# Architecture

This document provides an overview of the akv-tui-rs architecture and design decisions.

## Overview

akv-tui-rs is a terminal user interface application built with Rust that provides an intuitive way to manage Azure Key Vault secrets. The application follows a modular architecture with clear separation of concerns.

## Technology Stack

- **Language**: Rust (Edition 2024)
- **TUI Framework**: [ratatui](https://github.com/ratatui-org/ratatui) - Terminal UI framework
- **Terminal Backend**: [crossterm](https://github.com/crossterm-rs/crossterm) - Cross-platform terminal manipulation
- **Azure SDK**: [azure-sdk-for-rust](https://github.com/Azure/azure-sdk-for-rust) - Azure Key Vault integration
- **Async Runtime**: [tokio](https://tokio.rs/) - Asynchronous runtime
- **Fuzzy Matching**: [fuzzy-matcher](https://github.com/lotabout/fuzzy-matcher) - Fuzzy search functionality

## Architecture Components

### 1. Application Layer (`src/app.rs`)

The application layer manages the core state and business logic:

- **State Management**: Tracks current view, selected vault, secrets list, search state
- **Event Handling**: Processes user input and keyboard events
- **Caching**: Implements token and secret caching for performance
- **Navigation**: Manages transitions between vault selection and secret management views

### 2. UI Layer (`src/ui.rs`)

The UI layer handles all terminal rendering:

- **View Rendering**: Draws vault selection and secret management screens
- **Component Rendering**: Modals, lists, search bars, status messages
- **Layout Management**: Responsive terminal layout using ratatui's layout system
- **Styling**: Consistent color scheme and visual hierarchy

### 3. Azure Integration Layer (`src/azure.rs`)

The Azure integration layer handles all Azure Key Vault API interactions:

- **Authentication**: Uses Azure CLI credentials via `azure_identity`
- **Vault Discovery**: Lists accessible Key Vaults in the subscription
- **Secret Operations**: CRUD operations for secrets
- **Token Management**: Handles Azure AD token acquisition and caching

### 4. Data Models (`src/models.rs`)

Defines the core data structures:

- **Vault**: Represents an Azure Key Vault
- **Secret**: Represents a Key Vault secret
- **Application State**: Enumerates possible application states

## Data Flow

```
User Input → Event Handler → State Update → UI Render
                ↓
         Azure API Call (if needed)
                ↓
         Cache Update → State Update → UI Render
```

## Key Design Decisions

### Asynchronous Architecture

The application uses Tokio for async/await support, allowing non-blocking Azure API calls while maintaining a responsive UI.

### Caching Strategy

- **Token Caching**: Azure AD tokens are cached to reduce authentication overhead
- **Secret Caching**: Secrets are cached per vault to minimize API calls
- **Cache Invalidation**: Manual refresh option (`r` key) to update cached data

### Error Handling

- User-friendly error messages displayed in the UI
- Detailed error logging when debug mode is enabled
- Graceful degradation when API calls fail

### Security Considerations

- Secrets are only held in memory temporarily
- Clipboard integration for secure secret copying
- No persistent storage of secret values
- Relies on Azure CLI authentication (no credential storage)

## Performance Optimizations

1. **Lazy Loading**: Secrets are only fetched when a vault is selected
2. **Fuzzy Search**: Client-side fuzzy matching for instant search results
3. **Efficient Rendering**: Only re-renders UI when state changes
4. **Token Reuse**: Caches Azure AD tokens to avoid repeated authentication

## Future Considerations

- Support for certificate and key management (currently secrets only)
- Multi-vault operations
- Secret versioning support
- Export/import functionality
- Configuration file support

## Building and Testing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and testing guidelines.
