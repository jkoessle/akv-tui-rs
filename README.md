<p align="center">
  <img src="assets/banner.png" alt="akv-tui banner" width="100%"/>
</p>

# Azure Key Vault TUI

**A fast, intuitive terminal user interface for managing Azure Key Vault secrets**

Manage your Azure Key Vault secrets directly from your terminal with a powerful TUI built in Rust. Features fuzzy search, clipboard integration, and cross-platform support for Linux, macOS, and Windows.

[![Release-plz](https://github.com/jkoessle/akv-tui-rs/actions/workflows/release.yml/badge.svg)](https://github.com/jkoessle/akv-tui-rs/actions/workflows/release.yml)
[![Crates.io](https://img.shields.io/crates/v/akv-tui-rs.svg)](https://crates.io/crates/akv-tui-rs)
[![Downloads](https://img.shields.io/crates/d/akv-tui-rs.svg)](https://crates.io/crates/akv-tui-rs)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

## Why akv-tui-rs?

- **⚡ Fast & Efficient**: Built with Rust for maximum performance and minimal resource usage
- **🔍 Fuzzy Search**: Quickly find secrets with intelligent fuzzy matching
- **📋 Clipboard Integration**: Copy secret values with a single keypress
- **💾 Smart Caching**: Reduces API calls and improves response times
- **🖥️ Cross-Platform**: Works seamlessly on Linux, macOS, and Windows
- **🎯 Intuitive**: Vim-style keybindings and clean interface for productivity

## Use Cases

- **DevOps Engineers**: Quickly retrieve secrets during deployment and troubleshooting
- **Developers**: Access API keys, connection strings, and credentials without leaving the terminal
- **Security Teams**: Audit and manage secrets across multiple Azure Key Vaults

## Features

- **Vault Discovery**: Automatically discovers accessible Key Vaults in your Azure subscription.
- **Secret Management**:
    - List secrets with fuzzy search.
    - View secret values.
    - Add new secrets.
    - Edit existing secrets.
    - Delete secrets (soft-delete).
- **Clipboard Integration**: Copy secret values to clipboard with a single keypress.
- **Caching**: Caches secrets and tokens for improved performance and reduced API calls.
- **Cross-Platform**: Runs on Linux, macOS, and Windows.

## Installation

### Option 1: One-line Installer (Recommended)
For Linux and macOS users, you can install the latest release with a single command:

```sh
curl -fsSL https://raw.githubusercontent.com/jkoessle/akv-tui-rs/main/install.sh | sh
```

### Option 2: Cargo
If you have Rust installed, you can install via Cargo:

```sh
cargo install akv-tui-rs
```

### Option 3: Manual Download
You can download the pre-built binary for your platform from the [Releases](https://github.com/jkoessle/akv-tui-rs/releases) page.

### Build from Source

#### Prerequisites (Linux)
On Linux, you might need to install XCB development libraries:
```bash
sudo apt-get install libxcb-shape0-dev libxcb-xfixes0-dev
```

#### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/jkoessle/akv-tui-rs.git
   cd akv-tui-rs
   ```
2. Run directly:
   ```bash
   cargo run
   ```
3. Or install globally:
   ```bash
   cargo install --path .
   ```

## Usage

1. **Authenticate**: Run `az login` in your terminal if you haven't already.
2. **Start the Tool**: Run `akv` (or `cargo run`).
3. **Select Vault**: Use arrow keys or `j`/`k` to select a vault from the list and press `Enter`.
4. **Manage Secrets**:
    - **Navigation**: `j`/`k` or `Up`/`Down` to navigate the list.
    - **Search**: Press `/` to enter search mode. Type to filter secrets. `Esc` to clear/exit search.
    - **Copy Value**: Press `Enter` on a selected secret to copy its value to the clipboard.
    - **Add Secret**: Press `a` to add a new secret.
    - **Edit Secret**: Press `e` to edit the selected secret.
    - **Delete Secret**: Press `d` to delete the selected secret.
    - **Refresh**: Press `r` to refresh the secret list for the current vault.
    - **Switch Vault**: Press `v` to go back to the vault selection screen.
    - **Quit**: Press `q` or `Esc` to exit.

### Keybindings Summary

| Key | Action |
| --- | --- |
| `j` / `↓` | Move selection down |
| `k` / `↑` | Move selection up |
| `Enter` | Select vault / Copy secret value |
| `/` | Enter search mode |
| `a` | Add new secret |
| `e` | Edit selected secret |
| `d` | Delete selected secret |
| `r` | Refresh secrets |
| `v` | Back to vault selection |
| `q` | Quit application |

## Configuration

- **Debug Logging**: Run with `--debug` to enable logging to `azure_tui.log` in the current directory.
  ```bash
  cargo run -- --debug
  ```

## Troubleshooting

### Authentication Issues
- Ensure you're logged in with Azure CLI: `az login`
- Verify you have appropriate permissions on the Key Vault (Get, List permissions for secrets)
- Check your Azure subscription is active: `az account show`

### Build Issues on Linux
If you encounter linking errors related to XCB libraries:
```bash
sudo apt-get install libxcb-shape0-dev libxcb-xfixes0-dev
```

### Clipboard Not Working
- **Linux**: Ensure `xclip` or `xsel` is installed
- **macOS**: Clipboard should work out of the box
- **Windows**: Clipboard should work out of the box

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Related Projects

- [Azure CLI](https://github.com/Azure/azure-cli) - Official Azure command-line interface
- [ratatui](https://github.com/ratatui-org/ratatui) - The TUI framework powering this tool
- [azure-sdk-for-rust](https://github.com/Azure/azure-sdk-for-rust) - Azure SDK for Rust

## License

This project is licensed under the [Apache License 2.0](LICENSE).
