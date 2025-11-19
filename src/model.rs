use std::time::Instant;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Modal {
    Add { name: String, value: String, input_mode: AddInputMode },
    Edit { name: String, value: String },
    ConfirmDelete { name: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum AddInputMode { Name, Value }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppScreen {
    Welcome,
    VaultSelection,
    Secrets,
}

#[derive(Debug)]
pub enum AppEvent {
    VaultsLoaded(Vec<(String, String)>),
    SecretsUpdated(String, Vec<String>), // vault_name, secrets
    CacheVaultSecrets(String, Vec<String>), // vault_name -> cached secrets (silent)
    OpenEdit(String, String),
    Message(String),
    TokenCached(String, Instant, Duration), // token, fetched_at, ttl
}

#[derive(Debug, Clone)]
pub struct VaultCacheEntry {
    pub secrets: Vec<String>,
    pub refreshed_at: Instant,
}

#[derive(Debug, Clone)]
pub struct TokenCache {
    pub _token: String, // leading underscore to avoid "never read" warning
    pub fetched_at: Instant,
    pub ttl: Duration,
}
