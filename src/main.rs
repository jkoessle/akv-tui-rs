use std::error::Error;
use std::process::Command;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::convert::TryInto;

use azure_core::credentials::TokenCredential;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent};
use crossterm::{execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{Frame, backend::CrosstermBackend, Terminal};
use ratatui::layout::{Constraint, Direction, Layout, Rect, Alignment};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, ListState};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters, ResourceExt};
use futures::TryStreamExt;

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use clipboard::{ClipboardContext, ClipboardProvider};
use serde_json::Value;
use reqwest::Client;
use throbber_widgets_tui::{Throbber, ThrobberState, WhichUse, BRAILLE_SIX};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
enum Modal {
    Add { name: String, value: String, input_mode: AddInputMode },
    Edit { name: String, value: String },
    ConfirmDelete { name: String },
}

#[derive(Debug, Clone, PartialEq)]
enum AddInputMode { Name, Value }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppScreen {
    VaultSelection,
    Secrets,
}

#[derive(Debug)]
enum AppEvent {
    VaultsLoaded(Vec<(String, String)>),
    SecretsRefreshed(Vec<String>),
    OpenEdit(String, String),
    Message(String),
}

struct App {
    screen: AppScreen,
    credential: Arc<DeveloperToolsCredential>,
    client: Option<Arc<SecretClient>>,
    current_vault: Option<(String, String)>,
    secrets: Vec<String>,
    displayed_secrets: Vec<String>,
    selected: usize,
    list_state: ListState,
    message: Option<String>,
    modal: Option<Modal>,
    search_mode: bool,
    search_query: String,
    throbber_state: ThrobberState,
    loading: bool,
    vaults: Vec<(String, String)>,
    vault_selected: usize,
}

impl App {
    fn new(credential: Arc<DeveloperToolsCredential>) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            screen: AppScreen::VaultSelection,
            credential,
            client: None,
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
        }
    }

    fn selected_name(&self) -> Option<String> {
        self.displayed_secrets.get(self.selected).cloned()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Credential
    let credential = DeveloperToolsCredential::new(None)?;
    let mut app = App::new(credential.clone());

    // Terminal setup
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    crossterm::terminal::enable_raw_mode()?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Channel for background tasks -> UI
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

    // Start initial vault discovery in background
    {
        let tx = tx.clone();
        let cred = credential.clone();
        tokio::spawn(async move {
            match list_vaults(&cred).await {
                Ok(v) => { let _ = tx.send(AppEvent::VaultsLoaded(v)); }
                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Vault discovery failed: {}", e))); }
            }
        });
        app.loading = true;
    }

    let tick_rate = Duration::from_millis(120);
    let mut last_tick = Instant::now();

    loop {
        // Tick update: advance throbber if loading and redraw
        let tick_elapsed = last_tick.elapsed() >= tick_rate;
        if tick_elapsed {
            if app.loading {
                app.throbber_state.calc_next();
            }
            // draw the UI each tick so throbber animates
            terminal.draw(|f| draw_ui(f, &mut app)).ok();
            last_tick = Instant::now();
        }

        // Drain events from background tasks
        while let Ok(ev) = rx.try_recv() {
            match ev {
                AppEvent::VaultsLoaded(v) => {
                    app.vaults = v;
                    app.loading = false;
                    app.message = Some(format!("Discovered {} vault(s). Use ↑/↓ and Enter to select.", app.vaults.len()));
                    if app.vaults.is_empty() {
                        app.message = Some("No vaults found (press 'v' to retry).".into());
                    }
                }
                AppEvent::SecretsRefreshed(s) => {
                    app.secrets = s.clone();
                    apply_search(&mut app);
                    app.loading = false;
                    app.message = Some("Secrets refreshed".into());
                }
                AppEvent::OpenEdit(name, value) => {
                    app.modal = Some(Modal::Edit { name, value });
                    app.loading = false;
                }
                AppEvent::Message(msg) => {
                    app.loading = false;
                    app.message = Some(msg);
                }
            }
        }

        // Input handling
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                CEvent::Key(KeyEvent { code, .. }) => {
                    // If a modal is active, handle modal keys first
                    if let Some(_) = &app.modal {
                        if handle_modal_key(&mut app, code, &tx).await? { continue; }
                    }

                    // Search mode handling
                    if app.search_mode {
                        match code {
                            KeyCode::Esc => {
                                app.search_mode = false;
                                app.search_query.clear();
                                apply_search(&mut app);
                            }
                            KeyCode::Enter => { app.search_mode = false; }
                            KeyCode::Backspace => { app.search_query.pop(); apply_search(&mut app); }
                            KeyCode::Char(c) => { app.search_query.push(c); apply_search(&mut app); }
                            _ => {}
                        }
                        continue;
                    }

                    // Global quit
                    if code == KeyCode::Char('q') || code == KeyCode::Esc {
                        break;
                    }

                    // Screen specific handling
                    match app.screen {
                        AppScreen::VaultSelection => match code {
                            KeyCode::Down | KeyCode::Char('j') => {
                                if !app.vaults.is_empty() {
                                    app.vault_selected = (app.vault_selected + 1).min(app.vaults.len() - 1);
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if app.vault_selected > 0 { app.vault_selected -= 1; }
                            }
                            KeyCode::Enter => {
                                if let Some((name, url)) = app.vaults.get(app.vault_selected).cloned() {
                                    let client = SecretClient::new(&url, app.credential.clone(), None)?;
                                    app.client = Some(Arc::new(client));
                                    app.current_vault = Some((name.clone(), url));
                                    app.screen = AppScreen::Secrets;
                                    app.loading = true;
                                    let tx = tx.clone();
                                    let client_arc = app.client.as_ref().unwrap().clone();
                                    tokio::spawn(async move {
                                        match list_secrets(client_arc).await {
                                            Ok(s) => { let _ = tx.send(AppEvent::SecretsRefreshed(s)); }
                                            Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to list secrets: {}", e))); }
                                        }
                                    });
                                }
                            }
                            KeyCode::Char('v') => {
                                // re-trigger vault discovery
                                app.loading = true;
                                let tx = tx.clone();
                                let cred = app.credential.clone();
                                tokio::spawn(async move {
                                    match list_vaults(&cred).await {
                                        Ok(v) => { let _ = tx.send(AppEvent::VaultsLoaded(v)); }
                                        Err(e) => { let _ = tx.send(AppEvent::Message(format!("Vault discovery failed: {}", e))); }
                                    }
                                });
                            }
                            _ => {}
                        },
                        AppScreen::Secrets => match code {
                            KeyCode::Char('j') | KeyCode::Down => {
                                if !app.displayed_secrets.is_empty() {
                                    app.selected = (app.selected + 1).min(app.displayed_secrets.len() - 1);
                                    app.list_state.select(Some(app.selected));
                                }
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                if !app.displayed_secrets.is_empty() {
                                    if app.selected > 0 { app.selected -= 1; }
                                    app.list_state.select(Some(app.selected));
                                }
                            }
                            KeyCode::Char('v') => {
                                // back to vault selection
                                app.screen = AppScreen::VaultSelection;
                                app.loading = true;
                                let tx = tx.clone();
                                let cred = app.credential.clone();
                                tokio::spawn(async move {
                                    match list_vaults(&cred).await {
                                        Ok(v) => { let _ = tx.send(AppEvent::VaultsLoaded(v)); }
                                        Err(e) => { let _ = tx.send(AppEvent::Message(format!("Vault discovery failed: {}", e))); }
                                    }
                                });
                            }
                            KeyCode::Char('r') => {
                                if app.client.is_none() {
                                    app.message = Some("No vault selected".into());
                                } else {
                                    app.loading = true;
                                    let tx = tx.clone();
                                    let client = app.client.as_ref().unwrap().clone();
                                    tokio::spawn(async move {
                                        match list_secrets(client).await {
                                            Ok(s) => { let _ = tx.send(AppEvent::SecretsRefreshed(s)); }
                                            Err(e) => { let _ = tx.send(AppEvent::Message(format!("Refresh error: {}", e))); }
                                        }
                                    });
                                }
                            }
                            KeyCode::Char('a') => {
                                app.modal = Some(Modal::Add { name: String::new(), value: String::new(), input_mode: AddInputMode::Name });
                            }
                            KeyCode::Char('d') => {
                                if let Some(name) = app.selected_name() {
                                    app.modal = Some(Modal::ConfirmDelete { name });
                                }
                            }
                            KeyCode::Char('/') => {
                                app.search_mode = true;
                                app.search_query.clear();
                            }
                            KeyCode::Char('e') => {
                                if let Some(name) = app.selected_name() {
                                    if let Some(client) = &app.client {
                                        app.loading = true;
                                        let name_clone = name.clone();
                                        let client_cloned = client.clone();
                                        let tx = tx.clone();
                                        tokio::spawn(async move {
                                            match client_cloned.get_secret(&name_clone, None).await {
                                                Ok(resp) => {
                                                    if let Ok(secret) = resp.into_body() {
                                                        let val = secret.value.unwrap_or_default();
                                                        let _ = tx.send(AppEvent::OpenEdit(name_clone, val));
                                                    } else {
                                                        let _ = tx.send(AppEvent::Message("Failed to parse secret for edit".into()));
                                                    }
                                                }
                                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to get secret for edit: {}", e))); }
                                            }
                                        });
                                    } else {
                                        app.message = Some("No vault selected".into());
                                    }
                                }
                            }
                            KeyCode::Enter => {
                                if let Some(name) = app.selected_name() {
                                    if let Some(client) = &app.client {
                                        app.loading = true;
                                        let name_clone = name.clone();
                                        let client_cloned = client.clone();
                                        let tx = tx.clone();
                                        tokio::spawn(async move {
                                            match client_cloned.get_secret(&name_clone, None).await {
                                                Ok(resp) => {
                                                    match resp.into_body() {
                                                        Ok(secret) => {
                                                            let value = secret.value.unwrap_or_default();
                                                            let ctx: Result<ClipboardContext, _> = ClipboardProvider::new();
                                                            match ctx {
                                                                Ok(mut ctx) => {
                                                                    if ctx.set_contents(value.clone()).is_ok() {
                                                                        let _ = tx.send(AppEvent::Message(format!("Secret '{}' copied to clipboard", name_clone)));
                                                                    } else {
                                                                        let _ = tx.send(AppEvent::Message("Clipboard error".into()));
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    let _ = tx.send(AppEvent::Message(format!("Clipboard init error: {}", e)));
                                                                }
                                                            }
                                                        }
                                                        Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to read secret value: {}", e))); }
                                                    }
                                                }
                                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to get secret: {}", e))); }
                                            }
                                        });
                                    } else {
                                        app.message = Some("No vault selected".into());
                                    }
                                }
                            }
                            _ => {}
                        },
                    }
                }
                _ => {}
            }
        }
    }

    // Cleanup
    crossterm::terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_ui(f: &mut Frame<'_>, app: &mut App) {
    match app.screen {
        AppScreen::VaultSelection => draw_vault_selection_screen(f, app),
        AppScreen::Secrets => draw_secrets_screen(f, app),
    }
}

fn draw_vault_selection_screen(f: &mut Frame<'_>, app: &App) {
    let size = f.area();
    let block = Block::default()
        .title("🔐 Select an Azure Key Vault")
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center);

    let inner = block.inner(size);

    let items: Vec<ListItem> = if app.vaults.is_empty() {
        vec![ListItem::new("No vaults found yet...")]
    } else {
        app.vaults.iter().map(|(n, _)| ListItem::new(n.clone())).collect()
    };

    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(app.vault_selected));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, inner, &mut list_state);

    if app.loading {
        let throbber = Throbber::default()
            .label(" Discovering vaults...")
            .style(Style::default().fg(Color::Yellow))
            .throbber_set(BRAILLE_SIX)
            .use_type(WhichUse::Spin);
        let spinner_area = Rect {
            x: inner.x + 2,
            y: inner.bottom() - 2,
            width: 28,
            height: 1,
        };
        let mut ts = app.throbber_state.clone();
        f.render_stateful_widget(throbber, spinner_area, &mut ts);
    }

    let footer = Paragraph::new(app.message.clone().unwrap_or_default())
        .block(Block::default().borders(Borders::ALL).title("Message"))
        .style(Style::default().fg(Color::Cyan));
    let footer_area = Rect {
        x: size.x,
        y: size.bottom() - 3,
        width: size.width,
        height: 3,
    };
    f.render_widget(footer, footer_area);
}

fn draw_secrets_screen(f: &mut Frame<'_>, app: &mut App) {
    let size = f.area();
    let outer_block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            "Azure Key Vault Manager",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(outer_block, size);
    let inner = Rect {
        x: size.x + 1,
        y: size.y + 1,
        width: size.width - 2,
        height: size.height - 2,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(0)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(inner);

    let vault_label = app.current_vault.as_ref().map(|(n, _)| format!(" (Vault: {})", n)).unwrap_or_default();
    let header_text = if app.search_mode {
        format!("🔍 Search: {}_", app.search_query)
    } else {
        format!("🔑 Azure Key Vault TUI{} — [q: quit] [v: vault] [/: search] [a: add] [e: edit] [d: delete] [r: refresh] [Enter: copy]", vault_label)
    };

    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("Header"));
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = app.displayed_secrets.iter().map(|s| ListItem::new(s.clone())).collect();
    let mut list_state = app.list_state.clone();
    if app.displayed_secrets.is_empty() {
        list_state.select(None);
    } else {
        list_state.select(Some(app.selected));
    }
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Secrets"))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, chunks[1], &mut list_state);
    app.list_state = list_state;

    let footer_style = Style::default().fg(Color::Cyan);
    let footer = Paragraph::new(app.message.clone().unwrap_or_default())
        .style(footer_style)
        .block(Block::default().borders(Borders::ALL).title("Message"));
    f.render_widget(footer, chunks[2]);

    if app.loading {
        let throbber = Throbber::default()
            .label(" Processing...")
            .style(Style::default().fg(Color::Yellow))
            .throbber_set(BRAILLE_SIX)
            .use_type(WhichUse::Spin);
        f.render_stateful_widget(throbber, chunks[3], &mut app.throbber_state);
    }

    // Modal rendering (Add / Edit / ConfirmDelete) stays on top if present
    if let Some(modal) = &app.modal {
        let area = Rect::new(size.width / 8, size.height / 6, size.width * 3 / 4, size.height * 2 / 3);
        match modal {
            Modal::Add { name, value, input_mode } => {
                let mode = if *input_mode == AddInputMode::Name { "(typing name)" } else { "(typing value)" };
                let text = format!("Add Secret {}\n\nName: {}\nValue: {}\n\nPress Enter to submit, Esc to cancel", mode, name, value);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Add Secret", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area);
            }
            Modal::Edit { name, value } => {
                let text = format!("Edit Secret\n\nName: {}\nValue: {}\n\nPress Enter to save, Esc to cancel", name, value);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Edit Secret", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area);
            }
            Modal::ConfirmDelete { name } => {
                let text = format!("Delete secret '{}' ?\n\nPress 'y' to confirm, Esc to cancel", name);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Confirm Delete", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area);
            }
        }
    }
}

async fn handle_modal_key(app: &mut App, code: KeyCode, tx: &mpsc::UnboundedSender<AppEvent>) -> Result<bool, Box<dyn Error>> {
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
                    } else if app.client.is_none() {
                        app.message = Some("No vault selected".into());
                    } else {
                        let secret_name = name.clone();
                        let secret_value = value.clone();
                        let client = app.client.as_ref().unwrap().clone();
                        app.modal = None;
                        app.loading = true;
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let params = SetSecretParameters { value: Some(secret_value.into()), ..Default::default() };
                            match params.try_into() {
                                Ok(p) => {
                                    match client.set_secret(&secret_name, p, None).await {
                                        Ok(resp) => {
                                            let _ = resp.into_body();
                                            let _ = tx.send(AppEvent::Message(format!("Secret '{}' created/updated", secret_name)));
                                        }
                                        Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to set secret: {}", e))); }
                                    }
                                }
                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to prepare secret params: {}", e))); }
                            }
                            // refresh
                            match list_secrets(client.clone()).await {
                                Ok(s) => { let _ = tx.send(AppEvent::SecretsRefreshed(s)); }
                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to refresh secrets: {}", e))); }
                            }
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
                    if app.client.is_none() {
                        app.message = Some("No vault selected".into());
                    } else {
                        let client = app.client.as_ref().unwrap().clone();
                        let name_clone = name.clone();
                        let value_clone = value.clone();
                        app.modal = None;
                        app.loading = true;
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let params = SetSecretParameters { value: Some(value_clone.into()), ..Default::default() };
                            match params.try_into() {
                                Ok(p) => {
                                    match client.set_secret(&name_clone, p, None).await {
                                        Ok(resp) => {
                                            let _ = resp.into_body();
                                            let _ = tx.send(AppEvent::Message(format!("Secret '{}' updated", name_clone)));
                                        }
                                        Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to update secret: {}", e))); }
                                    }
                                }
                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to prepare secret params: {}", e))); }
                            }
                            match list_secrets(client.clone()).await {
                                Ok(s) => { let _ = tx.send(AppEvent::SecretsRefreshed(s)); }
                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to refresh secrets: {}", e))); }
                            }
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
                    if let Some(client) = &app.client {
                        let client_cloned = client.clone();
                        let name_clone = name.clone();
                        app.modal = None;
                        app.loading = true;
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            match client_cloned.delete_secret(&name_clone, None).await {
                                Ok(_) => {
                                    let _ = tx.send(AppEvent::Message(format!("Deleted '{}'. (soft-delete)", name_clone)));
                                }
                                Err(e) => {
                                    let _ = tx.send(AppEvent::Message(format!("Failed to delete: {}", e)));
                                }
                            }
                            match list_secrets(client_cloned.clone()).await {
                                Ok(s) => { let _ = tx.send(AppEvent::SecretsRefreshed(s)); }
                                Err(e) => { let _ = tx.send(AppEvent::Message(format!("Failed to refresh after delete: {}", e))); }
                            }
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

async fn list_secrets(client: Arc<SecretClient>) -> Result<Vec<String>, Box<dyn Error>> {
    let mut pager = client.list_secret_properties(None)?.into_stream();
    let mut names = Vec::new();
    while let Some(item) = pager.try_next().await? {
        if let Ok(rid) = item.resource_id() {
            names.push(rid.name);
        }
    }
    names.sort();
    Ok(names)
}

fn apply_search(app: &mut App) {
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

async fn list_vaults(credential: &DeveloperToolsCredential) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    // Acquire token for ARM
    let token = credential.get_token(&["https://management.azure.com/.default"], None).await?;
    let bearer = token.token.secret();

    let client = Client::new();
    let subs_url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    let sub_resp = client.get(subs_url)
        .bearer_auth(bearer)
        .send()
        .await?;
    let subs: Value = sub_resp.json().await?;
    let mut vaults = Vec::new();

    if let Some(arr) = subs["value"].as_array() {
        for sub in arr {
            if let Some(sub_id) = sub["subscriptionId"].as_str() {
                let url = format!("https://management.azure.com/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2025-05-01", sub_id);
                if let Ok(resp) = client.get(&url).bearer_auth(bearer).send().await {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(v) = data["value"].as_array() {
                            for item in v {
                                if let (Some(name), Some(uri)) = (item["name"].as_str(), item["properties"]["vaultUri"].as_str()) {
                                    vaults.push((name.to_string(), uri.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback to az cli
    if vaults.is_empty() {
        if let Ok(out) = Command::new("az").args(["keyvault", "list", "-o", "json"]).output() {
            if out.status.success() {
                let data: Value = serde_json::from_slice(&out.stdout)?;
                if let Some(arr) = data.as_array() {
                    for item in arr {
                        if let (Some(name), Some(uri)) = (item["name"].as_str(), item["properties"]["vaultUri"].as_str()) {
                            vaults.push((name.to_string(), uri.to_string()));
                        }
                    }
                }
            }
        }
    }

    Ok(vaults)
}
