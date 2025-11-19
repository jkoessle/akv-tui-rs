use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::convert::TryInto;

use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};
use crossterm::event::KeyCode;
use ratatui::widgets::ListState;
use throbber_widgets_tui::ThrobberState;
use tokio::sync::mpsc::UnboundedSender;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

use crate::model::{AppEvent, AppScreen, Modal, AddInputMode, TokenCache, VaultCacheEntry};
use crate::azure::list_secrets_and_cache;

pub struct App {
    pub screen: AppScreen,
    pub credential: Arc<DeveloperToolsCredential>,
    pub current_vault: Option<(String, String)>, // (name, uri)
    pub secrets: Vec<String>,
    pub displayed_secrets: Vec<String>,
    pub selected: usize,
    pub list_state: ListState,
    pub message: Option<String>,
    pub modal: Option<Modal>,
    pub search_mode: bool,
    pub search_query: String,
    pub throbber_state: ThrobberState,
    pub loading: bool,
    pub vaults: Vec<(String, String)>,
    pub vault_selected: usize,
    pub token_cache: Option<TokenCache>,                 // in-memory token cache (token string stored but not used directly)
    pub vault_secret_cache: HashMap<String, VaultCacheEntry>, // in-memory per-vault cache
    pub welcome_shown_at: Instant,
}

impl App {
    pub fn new(credential: Arc<DeveloperToolsCredential>) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            screen: AppScreen::Welcome,
            credential,
            current_vault: None,
            secrets: Vec::new(),
            displayed_secrets: Vec::new(),
            selected: 0,
            list_state,
            message: None,
            modal: None,
            search_mode: false,
            search_query: String::new(),
            throbber_state: ThrobberState::default(),
            loading: false,
            vaults: Vec::new(),
            vault_selected: 0,
            token_cache: None,
            vault_secret_cache: HashMap::new(),
            welcome_shown_at: Instant::now(),
        }
    }

    pub fn selected_name(&self) -> Option<String> {
        self.displayed_secrets.get(self.selected).cloned()
    }

    pub fn token_should_refresh(&self) -> bool {
        match &self.token_cache {
            None => true,
            Some(tc) => {
                let ttl_secs = tc.ttl.as_secs().max(1);
                // compute 10% of TTL (at least 1s), then cap at 120s
                let ten_percent = ttl_secs / 10;
                let threshold_secs = std::cmp::min(120, std::cmp::max(1, ten_percent as u64));
                let threshold = Duration::from_secs(threshold_secs);
                let expires_at = tc.fetched_at + tc.ttl;
                Instant::now() + threshold >= expires_at
            }
        }
    }
}

/// Apply fuzzy search to produce displayed_secrets
pub fn apply_search(app: &mut App) {
    if app.search_query.is_empty() {
        app.displayed_secrets = app.secrets.clone();
    } else {
        let matcher = SkimMatcherV2::default();
        let mut results: Vec<(i64, &String)> = app
            .secrets
            .iter()
            .filter_map(|s| matcher.fuzzy_match(s, &app.search_query).map(|score| (score, s)))
            .collect();
        results.sort_by(|a, b| b.0.cmp(&a.0));
        app.displayed_secrets = results.into_iter().map(|(_, s)| s.clone()).collect();
    }
    app.selected = 0;
    app.list_state.select(Some(0));
}

/// Handle modal keys; background tasks clone tx to avoid move errors.
pub async fn handle_modal_key(app: &mut App, code: KeyCode, tx: &UnboundedSender<AppEvent>) -> Result<bool, Box<dyn Error>> {
    if app.modal.is_none() { return Ok(false); }
    match &mut app.modal {
        Some(Modal::Add { name, value, input_mode }) => {
            match code {
                KeyCode::Esc => { app.modal = None; }
                KeyCode::Tab => { *input_mode = if *input_mode == AddInputMode::Name { AddInputMode::Value } else { AddInputMode::Name }; }
                KeyCode::Backspace => { match input_mode { AddInputMode::Name => { name.pop(); }, AddInputMode::Value => { value.pop(); }, } }
                KeyCode::Enter => {
                    if name.is_empty() {
                        app.message = Some("Name cannot be empty".into());
                    } else if app.current_vault.is_none() {
                        app.message = Some("No vault selected".into());
                    } else {
                        let secret_name = name.clone();
                        let secret_value = value.clone();
                        let (vault_name, vault_uri) = app.current_vault.as_ref().unwrap().clone();
                        app.modal = None;
                        app.loading = true;
                        app.message = Some("Creating secret...".into());
                        let tx2 = tx.clone();
                        let client = SecretClient::new(&vault_uri, app.credential.clone(), None)?;
                        let client_arc = Arc::new(client);
                        tokio::spawn(async move {
                            let params = SetSecretParameters { value: Some(secret_value.into()), ..Default::default() };
                            match params.try_into() {
                                Ok(p) => {
                                    match client_arc.set_secret(&secret_name, p, None).await {
                                        Ok(resp) => {
                                            let _ = resp.into_body();
                                            let _ = tx2.send(AppEvent::Message(format!("Secret '{}' created/updated", secret_name)));
                                        }
                                        Err(e) => {
                                            let _ = tx2.send(AppEvent::Message(format!("Failed to set secret: {}", e)));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx2.send(AppEvent::Message(format!("Failed to prepare secret params: {}", e)));
                                }
                            }
                            // refresh and cache
                            let _ = list_secrets_and_cache(client_arc.clone(), tx2.clone(), vault_name.clone()).await;
                        });
                    }
                }
                KeyCode::Char(c) => {
                    match input_mode {
                        AddInputMode::Name => name.push(c),
                        AddInputMode::Value => value.push(c),
                    }
                }
                _ => {}
            }
            Ok(true)
        }
        Some(Modal::Edit { name, value }) => {
            match code {
                KeyCode::Esc => { app.modal = None; }
                KeyCode::Backspace => { value.pop(); }
                KeyCode::Enter => {
                    if app.current_vault.is_none() {
                        app.message = Some("No vault selected".into());
                    } else {
                        let (vault_name, vault_uri) = app.current_vault.as_ref().unwrap().clone();
                        let client = SecretClient::new(&vault_uri, app.credential.clone(), None)?;
                        let client_arc = Arc::new(client);
                        let name_clone = name.clone();
                        let value_clone = value.clone();
                        app.modal = None;
                        app.loading = true;
                        app.message = Some("Updating secret...".into());
                        let tx2 = tx.clone();
                        tokio::spawn(async move {
                            let params = SetSecretParameters { value: Some(value_clone.into()), ..Default::default() };
                            match params.try_into() {
                                Ok(p) => {
                                    match client_arc.set_secret(&name_clone, p, None).await {
                                        Ok(resp) => {
                                            let _ = resp.into_body();
                                            let _ = tx2.send(AppEvent::Message(format!("Secret '{}' updated", name_clone)));
                                        }
                                        Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to update secret: {}", e))); }
                                    }
                                }
                                Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to prepare secret params: {}", e))); }
                            }
                            let _ = list_secrets_and_cache(client_arc.clone(), tx2.clone(), vault_name.clone()).await;
                        });
                    }
                }
                KeyCode::Char(c) => { value.push(c); }
                _ => {}
            }
            Ok(true)
        }
        Some(Modal::ConfirmDelete { name }) => {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some((vault_name, vault_uri)) = &app.current_vault {
                        let client = SecretClient::new(vault_uri, app.credential.clone(), None)?;
                        let client_arc = Arc::new(client);
                        let name_clone = name.clone();
                        let vault_name = vault_name.clone();
                        app.modal = None;
                        app.loading = true;
                        app.message = Some("Deleting secret...".into());
                        let tx2 = tx.clone();
                        tokio::spawn(async move {
                            match client_arc.delete_secret(&name_clone, None).await {
                                Ok(_) => { let _ = tx2.send(AppEvent::Message(format!("Deleted '{}'. (soft-delete)", name_clone))); }
                                Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to delete: {}", e))); }
                            }
                            let _ = list_secrets_and_cache(client_arc.clone(), tx2.clone(), vault_name.clone()).await;
                        });
                    } else {
                        app.message = Some("No vault selected".into());
                        app.modal = None;
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') => { app.modal = None; }
                _ => {}
            }
            Ok(true)
        }
        None => Ok(false),
    }
}
