use std::convert::TryInto;
use std::error::Error;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
use futures::{TryStreamExt, future::join_all};
use reqwest::Client;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task;
use tracing::debug;

use crate::model::AppEvent;

/// Refresh token and return (token_string, fetched_at, ttl).
/// Uses the SDK get_token and reads expires_on (OffsetDateTime) when available.
pub async fn refresh_token(
    credential: Arc<DeveloperToolsCredential>,
) -> Result<(String, Instant, Duration), Box<dyn Error>> {
    debug!("Refreshing token via SDK");
    let token_response = credential
        .get_token(&["https://management.azure.com/.default"], None)
        .await?;
    let token_str = token_response.token.secret().to_string();

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
pub async fn get_token_then_discover(
    credential: Arc<DeveloperToolsCredential>,
) -> Result<(Option<(String, Instant, Duration)>, Vec<(String, String)>), Box<dyn Error>> {
    // Acquire token
    let (token_str, fetched_at, ttl) = refresh_token(credential.clone()).await?;
    let client = Client::new();
    // Delegate to internal discovery with real Azure URL
    let base_url = "https://management.azure.com";
    let vaults = discover_resources(&client, &token_str, base_url).await?;

    // Fallback to az CLI executed in blocking thread if no vaults found
    if vaults.is_empty() {
        debug!("No vaults from ARM; attempting az CLI fallback");
        if let Ok(out) = task::spawn_blocking(|| {
            Command::new("az")
                .args(["keyvault", "list", "-o", "json"])
                .output()
        })
        .await?
        {
            if out.status.success() {
                let data: Value = serde_json::from_slice(&out.stdout)?;
                if let Some(arr) = data.as_array() {
                    let mut extra_vaults = Vec::new();
                    for item in arr {
                        if let (Some(name), Some(uri)) = (
                            item["name"].as_str(),
                            item["properties"]["vaultUri"].as_str(),
                        ) {
                            extra_vaults.push((name.to_string(), uri.to_string()));
                        }
                    }
                    // Return a combination of found vaults (though likely only one source will yield results)
                    // The original logic replaced the empty vector, here we can extend or just return if discover_resources failed to find anything.
                    // Since vaults is empty here, we can just return the CLI results.
                    return Ok((Some((token_str, fetched_at, ttl)), extra_vaults));
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

/// Internal discovery logic that can be pointed to a mock server
async fn discover_resources(
    client: &Client,
    token_str: &str,
    base_url: &str,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let mut subs_url = Some(format!("{}/subscriptions?api-version=2020-01-01", base_url));
    let mut subscriptions = Vec::new();
    let mut vaults: Vec<(String, String)> = Vec::new();

    while let Some(url) = subs_url {
        let resp = client.get(&url).bearer_auth(token_str).send().await?;
        let page: Value = resp.json().await?;

        if let Some(arr) = page["value"].as_array() {
            for sub in arr {
                if let Some(sub_id) = sub["subscriptionId"].as_str() {
                    subscriptions.push(sub_id.to_string());
                }
            }
        }

        subs_url = page["nextLink"].as_str().map(|s| s.to_string());
    }

    let mut futures = Vec::new();
    for sub_id in subscriptions {
        let client_clone = client.clone();
        let bearer_clone = token_str.to_string();
        // We need to pass the base_url into the future, but we can't easily capture it if it's a reference unless we clone a String
        let base_url_owned = base_url.to_string();

        futures.push(async move {
            let mut vaults_list = Vec::new();
            let mut next_link = Some(format!(
                "{}/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2025-05-01",
                base_url_owned, sub_id
            ));

            while let Some(url) = next_link {
                let resp = client_clone
                    .get(&url)
                    .bearer_auth(&bearer_clone)
                    .send()
                    .await
                    .ok()?;
                let page: Value = resp.json().await.ok()?;

                if let Some(v) = page["value"].as_array() {
                    for item in v {
                        if let (Some(name), Some(uri)) = (
                            item["name"].as_str(),
                            item["properties"]["vaultUri"].as_str(),
                        ) {
                            vaults_list.push((name.to_string(), uri.to_string()));
                        }
                    }
                }
                next_link = page["nextLink"].as_str().map(|s| s.to_string());
            }
            Some(vaults_list)
        });
    }

    let results = join_all(futures).await;
    for opt in results.into_iter().flatten() {
        vaults.extend(opt);
    }

    Ok(vaults)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_pagination_logic() {
        let mock_server = MockServer::start().await;
        let client = Client::new();

        // 1. Mock Subscriptions (Page 1) -> Returns sub1, has nextLink
        let sub_page1 = serde_json::json!({
            "value": [{"subscriptionId": "sub1"}],
            "nextLink": format!("{}/subscriptions_page2", mock_server.uri())
        });
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sub_page1))
            .mount(&mock_server)
            .await;

        // 2. Mock Subscriptions (Page 2) -> Returns sub2, no nextLink
        let sub_page2 = serde_json::json!({
            "value": [{"subscriptionId": "sub2"}]
        });
        Mock::given(method("GET"))
            .and(path("/subscriptions_page2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sub_page2))
            .mount(&mock_server)
            .await;

        // 3. Mock Vaults for sub1 (Page 1) -> Returns vault1, has nextLink
        // The URL format in code is {base}/subscriptions/{sub}/providers/...
        // We match by regex or precise path. precise path is easiest since we know the structure.
        let v_sub1_p1 = serde_json::json!({
            "value": [{"name": "vault1", "properties": {"vaultUri": "https://vault1.vault.azure.net/"}}],
            "nextLink": format!("{}/sub1_vaults_p2", mock_server.uri())
        });
        Mock::given(method("GET"))
            .and(path(
                "/subscriptions/sub1/providers/Microsoft.KeyVault/vaults",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(v_sub1_p1))
            .mount(&mock_server)
            .await;

        // 4. Mock Vaults for sub1 (Page 2) -> Returns vault2
        let v_sub1_p2 = serde_json::json!({
            "value": [{"name": "vault2", "properties": {"vaultUri": "https://vault2.vault.azure.net/"}}]
        });
        Mock::given(method("GET"))
            .and(path("/sub1_vaults_p2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(v_sub1_p2))
            .mount(&mock_server)
            .await;

        // 5. Mock Vaults for sub2 -> Returns vault3, no pagination
        let v_sub2 = serde_json::json!({
            "value": [{"name": "vault3", "properties": {"vaultUri": "https://vault3.vault.azure.net/"}}]
        });
        Mock::given(method("GET"))
            .and(path(
                "/subscriptions/sub2/providers/Microsoft.KeyVault/vaults",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(v_sub2))
            .mount(&mock_server)
            .await;

        // Run discovery
        let res = discover_resources(&client, "fake_token", &mock_server.uri()).await;
        assert!(res.is_ok());
        let mut vaults = res.unwrap();
        // Sort for deterministic comparison
        vaults.sort();

        let expected = vec![
            (
                "vault1".to_string(),
                "https://vault1.vault.azure.net/".to_string(),
            ),
            (
                "vault2".to_string(),
                "https://vault2.vault.azure.net/".to_string(),
            ),
            (
                "vault3".to_string(),
                "https://vault3.vault.azure.net/".to_string(),
            ),
        ];

        // Check finding all 3 (2 from sub1 pagination, 1 from sub2)
        // Note: vector comparison might need sorting.
        assert_eq!(vaults.len(), 3);
        // We can check contains since order depends on async execution
        for e in expected {
            assert!(vaults.contains(&e), "Missing {:?}", e);
        }
    }
}

/// Incrementally list secrets and send updates for the given vault back to UI.
/// Also sends CacheVaultSecrets for silent caching.
pub async fn list_secrets_incremental(
    client: Arc<SecretClient>,
    tx: UnboundedSender<AppEvent>,
    vault_name: String,
) -> Result<(), Box<dyn Error>> {
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
            let _ = tx.send(AppEvent::CacheVaultSecrets(
                vault_name.clone(),
                names.clone(),
            ));
        }
    }
    names.sort();
    let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), names.clone()));
    let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names));
    debug!("Completed incremental list for vault '{}'", vault_name);
    Ok(())
}

/// List secrets fully and update cache (used after write/delete to ensure cache is fresh).
pub async fn list_secrets_and_cache(
    client: Arc<SecretClient>,
    tx: UnboundedSender<AppEvent>,
    vault_name: String,
) -> Result<(), Box<dyn Error>> {
    debug!("Starting full list+cache for vault '{}'", vault_name);
    let mut pager = client.list_secret_properties(None)?.into_stream();
    let mut names = Vec::new();
    while let Some(item) = pager.try_next().await? {
        if let Ok(rid) = item.resource_id() {
            names.push(rid.name);
        }
    }
    names.sort();
    let _ = tx.send(AppEvent::CacheVaultSecrets(
        vault_name.clone(),
        names.clone(),
    ));
    let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), names));
    debug!("Completed full list+cache for vault '{}'", vault_name);
    Ok(())
}

/// Preload secrets for all vaults using bounded concurrency and populate cache silently.
pub async fn preload_all_vaults(
    credential: Arc<DeveloperToolsCredential>,
    tx: UnboundedSender<AppEvent>,
    vaults: Vec<(String, String)>,
    sem: Arc<Semaphore>,
) {
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
                    if let Err(e) =
                        list_secrets_and_cache(client_arc, tx2.clone(), name_clone.clone()).await
                    {
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
