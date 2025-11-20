use std::error::Error;
use std::process::Command;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::convert::TryInto;

use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, ResourceExt};
use futures::{TryStreamExt, future::join_all};
use reqwest::Client;
use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Semaphore;
use tokio::task;
use tracing::debug;
use time::OffsetDateTime;

use crate::model::AppEvent;

/// Refresh token and return (token_string, fetched_at, ttl).
/// Uses the SDK get_token and reads expires_on (OffsetDateTime) when available.
pub async fn refresh_token(credential: Arc<DeveloperToolsCredential>) -> Result<(String, Instant, Duration), Box<dyn Error>> {
    debug!("Refreshing token via SDK");
    let token_response = credential.get_token(&["https://management.azure.com/.default"], None).await?;
    let token_str = token_response.token.secret().to_string();

    // expires_on is an OffsetDateTime in azure-core v0.29.1
    let expires_on: OffsetDateTime = token_response.expires_on;
    let now = OffsetDateTime::now_utc();
    let secs_i128 = (expires_on - now).whole_seconds().max(1); // i128
    // convert i128 -> u64 safely
    let ttl_secs: u64 = secs_i128.try_into().unwrap_or(55 * 60);
    let ttl = Duration::from_secs(ttl_secs);
    let fetched_at = Instant::now();
    debug!("Token refreshed, ttl={:?}", ttl);
    Ok((token_str, fetched_at, ttl))
}

/// Get token then discover vaults in ARM (parallel per-subscription).
/// Returns optional token info (token_str,fetched_at,ttl) and vault list.
pub async fn get_token_then_discover(credential: Arc<DeveloperToolsCredential>) -> Result<(Option<(String, Instant, Duration)>, Vec<(String, String)>), Box<dyn Error>> {
    // Acquire token
    let (token_str, fetched_at, ttl) = refresh_token(credential.clone()).await?;
    let client = Client::new();
    let subs_url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    let sub_resp = client.get(subs_url).bearer_auth(&token_str).send().await?;
    let subs: Value = sub_resp.json().await?;
    let mut vaults: Vec<(String, String)> = Vec::new();

    if let Some(arr) = subs["value"].as_array() {
        // Build per-subscription futures
        let mut futures = Vec::new();
        for sub in arr {
            if let Some(sub_id) = sub["subscriptionId"].as_str() {
                let client_clone = client.clone();
                let bearer_clone = token_str.clone();
                let sub_id = sub_id.to_string();
                futures.push(async move {
                    let url = format!("https://management.azure.com/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2025-05-01", sub_id);
                    let resp = client_clone.get(&url).bearer_auth(bearer_clone).send().await.ok()?;
                    let data: Value = resp.json().await.ok()?;
                    let mut list = Vec::new();
                    if let Some(v) = data["value"].as_array() {
                        for item in v {
                            if let (Some(name), Some(uri)) = (item["name"].as_str(), item["properties"]["vaultUri"].as_str()) {
                                list.push((name.to_string(), uri.to_string()));
                            }
                        }
                    }
                    Some(list)
                });
            }
        }

        let results = join_all(futures).await;
        for opt in results.into_iter().flatten() {
            vaults.extend(opt);
        }
    }

    // Fallback to az CLI executed in blocking thread if no vaults found
    if vaults.is_empty() {
        debug!("No vaults from ARM; attempting az CLI fallback");
        if let Ok(out) = task::spawn_blocking(|| {
            Command::new("az").args(["keyvault", "list", "-o", "json"]).output()
        }).await? {
            if out.status.success() {
                let data: Value = serde_json::from_slice(&out.stdout)?;
                if let Some(arr) = data.as_array() {
                    for item in arr {
                        if let (Some(name), Some(uri)) = (item["name"].as_str(), item["properties"]["vaultUri"].as_str()) {
                            vaults.push((name.to_string(), uri.to_string()));
                        }
                    }
                }
            } else {
                debug!("az CLI returned non-zero status");
            }
        } else {
            debug!("az CLI fallback spawn failed");
        }
    }

    Ok((Some((token_str, fetched_at, ttl)), vaults))
}

/// Incrementally list secrets and send updates for the given vault back to UI.
/// Also sends CacheVaultSecrets for silent caching.
pub async fn list_secrets_incremental(client: Arc<SecretClient>, tx: UnboundedSender<AppEvent>, vault_name: String) -> Result<(), Box<dyn Error>> {
    debug!("Starting incremental list for vault '{}'", vault_name);
    let mut pager = client.list_secret_properties(None)?.into_stream();
    let mut names = Vec::new();
    const BATCH: usize = 20;
    while let Some(item) = pager.try_next().await? {
        if let Ok(rid) = item.resource_id() {
            names.push(rid.name);
        }
        if names.len() % BATCH == 0 {
            let mut sorted = names.clone();
            sorted.sort();
            let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), sorted.clone()));
            let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names.clone()));
        }
    }
    names.sort();
    let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), names.clone()));
    let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names));
    debug!("Completed incremental list for vault '{}'", vault_name);
    Ok(())
}

/// List secrets fully and update cache (used after write/delete to ensure cache is fresh).
pub async fn list_secrets_and_cache(client: Arc<SecretClient>, tx: UnboundedSender<AppEvent>, vault_name: String) -> Result<(), Box<dyn Error>> {
    debug!("Starting full list+cache for vault '{}'", vault_name);
    let mut pager = client.list_secret_properties(None)?.into_stream();
    let mut names = Vec::new();
    while let Some(item) = pager.try_next().await? {
        if let Ok(rid) = item.resource_id() {
            names.push(rid.name);
        }
    }
    names.sort();
    let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names.clone()));
    let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), names));
    debug!("Completed full list+cache for vault '{}'", vault_name);
    Ok(())
}

/// Preload secrets for all vaults using bounded concurrency and populate cache silently.
pub async fn preload_all_vaults(credential: Arc<DeveloperToolsCredential>, tx: UnboundedSender<AppEvent>, vaults: Vec<(String, String)>, sem: Arc<Semaphore>) {
    debug!("preload_all_vaults: starting, {} vaults", vaults.len());
    let client_cred = credential;
    let mut handles = Vec::new();
    for (name, uri) in vaults.into_iter() {
        let tx2 = tx.clone();
        let permit = sem.clone();
        let name_clone = name.clone();
        let uri_clone = uri.clone();
        let cred = client_cred.clone();
        let handle = tokio::spawn(async move {
            let _p = permit.acquire_owned().await.expect("semaphore");
            debug!("Preloading vault '{}' (uri={})", name_clone, uri_clone);
            match SecretClient::new(&uri_clone, cred.clone(), None) {
                Ok(client) => {
                    let client_arc = Arc::new(client);
                    if let Err(e) = list_secrets_and_cache(client_arc, tx2.clone(), name_clone.clone()).await {
                        debug!("Preload failed for {}: {}", name_clone, e);
                    } else {
                        debug!("Preload succeeded for {}", name_clone);
                    }
                }
                Err(e) => {
                    debug!("Failed to create client for {}: {}", name_clone, e);
                }
            }
        });
        handles.push(handle);
    }
    for h in handles {
        let _ = h.await;
    }
    debug!("preload_all_vaults: done");
}
