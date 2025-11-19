use ratatui::{Frame, layout::{Constraint, Direction, Layout, Rect, Alignment}, widgets::{Block, Borders, List, ListItem, Paragraph}, style::{Color, Modifier, Style}, text::Span};
use throbber_widgets_tui::{Throbber, WhichUse, BRAILLE_SIX};

use crate::model::{AppScreen, Modal, AddInputMode};
use crate::app::App;

/// Draw router
pub fn draw_ui(f: &mut Frame<'_>, app: &mut App) {
    match app.screen {
        AppScreen::Welcome => draw_welcome_screen(f),
        AppScreen::VaultSelection => draw_vault_selection_screen(f, app),
        AppScreen::Secrets => draw_secrets_screen(f, app),
    }
}

/// Welcome ASCII art screen (centered)
fn draw_welcome_screen(f: &mut Frame<'_>) {
    let area = f.area();
    let art = r#"
     e      888  /   Y88b      / 
    d8b     888 /     Y88b    /  
   /Y88b    888/\      Y88b  /   
  /  Y88b   888  \      Y888/    
 /____Y88b  888   \      Y8/     
/      Y88b 888    \      Y      
                                  "#;

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Azure KeyVault TUI")
        .title_alignment(Alignment::Center);

    let paragraph = Paragraph::new(art)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(block);

    // Draw centered box (use most of the screen)
    f.render_widget(paragraph, area);
}

fn draw_vault_selection_screen(f: &mut Frame<'_>, app: &App) {
    let area = f.area();
    let block = Block::default()
        .title("🔐 Select an Azure Key Vault")
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center);

    let inner = block.inner(area);

    let items: Vec<ListItem> = if app.vaults.is_empty() {
        vec![ListItem::new("No vaults found yet...")]
    } else {
        app.vaults.iter().map(|(n, _)| ListItem::new(n.clone())).collect()
    };

    let mut list_state = ratatui::widgets::ListState::default();
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
        x: area.x,
        y: area.bottom() - 3,
        width: area.width,
        height: 3,
    };
    f.render_widget(footer, footer_area);
}

fn draw_secrets_screen(f: &mut Frame<'_>, app: &mut App) {
    let area = f.area();
    let outer_block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            "Azure Key Vault Manager",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(outer_block, area);
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width - 2,
        height: area.height - 2,
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

    if let Some(modal) = &app.modal {
        let area_modal = Rect::new(area.width / 8, area.height / 6, area.width * 3 / 4, area.height * 2 / 3);
        match modal {
            Modal::Add { name, value, input_mode } => {
                let mode = if *input_mode == AddInputMode::Name { "(typing name)" } else { "(typing value)" };
                let text = format!("Add Secret {}\n\nName: {}\nValue: {}\n\nPress Enter to submit, Esc to cancel", mode, name, value);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Add Secret", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area_modal);
            }
            Modal::Edit { name, value } => {
                let text = format!("Edit Secret\n\nName: {}\nValue: {}\n\nPress Enter to save, Esc to cancel", name, value);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Edit Secret", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area_modal);
            }
            Modal::ConfirmDelete { name } => {
                let text = format!("Delete secret '{}' ?\n\nPress 'y' to confirm, Esc to cancel", name);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Confirm Delete", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area_modal);
            }
        }
    }
}
