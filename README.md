<p align="center">
  <img src="assets/banner.png" alt="akv-tui banner" width="600"><br>
  <br>
  <a href="https://github.com/jkoessle/akv-tui-rs/actions/workflows/release.yml">
    <img src="https://github.com/jkoessle/akv-tui-rs/actions/workflows/release.yml/badge.svg"></a>
  <a href="https://crates.io/crates/akv-tui-rs">
    <img src="https://img.shields.io/crates/v/akv-tui-rs.svg"></a>
  <a href="https://crates.io/crates/akv-tui-rs">
    <img src="https://img.shields.io/crates/d/akv-tui-rs.svg"></a>
  <a href="https://github.com/jkoessle/akv-tui-rs/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"></a>
  <br>
  <br>
  A fast, intuitive terminal user interface for managing Azure Key Vault secrets with fuzzy search, clipboard integration, and cross-platform support.
</p>

<img src="assets/demo.gif" alt="akv-tui demo"/>

## Quick Start

### Install

`akv-tui-rs` runs on Linux, macOS, and Windows. It can be installed from cargo, precompiled binaries, or source.

For example, to install from `cargo`:

```shell
cargo install akv-tui-rs --locked
```

<details>

<summary>All installation methods</summary>

### Cargo

[![Crates.io](https://img.shields.io/crates/v/akv-tui-rs)](https://crates.io/crates/akv-tui-rs)

```shell
cargo install akv-tui-rs --locked
```

### One-line Installer (Linux/macOS)

```shell
curl -fsSL https://raw.githubusercontent.com/jkoessle/akv-tui-rs/main/install.sh | sh
```

### Manual Download

Download the pre-built binary for your platform from the [Releases](https://github.com/jkoessle/akv-tui-rs/releases) page.

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

</details>

### Run

To run `akv-tui-rs` with default settings, use the following command:

```shell
akv
```

> ⓘ Note:
>
> You must be authenticated with Azure CLI (`az login`) before running the tool.

## Features

- **⚡ Fast & Efficient**: Built with Rust for maximum performance and minimal resource usage
- **🔍 Fuzzy Search**: Quickly find secrets with intelligent fuzzy matching
- **📋 Clipboard Integration**: Copy secret values with a single keypress
- **💾 Smart Caching**: Reduces API calls and improves response times
- **🖥️ Cross-Platform**: Works seamlessly on Linux, macOS, and Windows
- **🎯 Intuitive**: Vim-style keybindings and clean interface for productivity

### Secret Management

- **Vault Discovery**: Automatically discovers accessible Key Vaults in your Azure subscription
- **List Secrets**: Browse all secrets with fuzzy search filtering
- **View Values**: Securely view secret values
- **Add Secrets**: Create new secrets directly from the TUI
- **Edit Secrets**: Update existing secret values
- **Delete Secrets**: Soft-delete secrets when no longer needed

## Usage

1. **Authenticate**: Run `az login` in your terminal if you haven't already
2. **Start the Tool**: Run `akv`
3. **Select Vault**: Use arrow keys or `j`/`k` to select a vault from the list and press `Enter`
4. **Manage Secrets**: Use the keybindings below to interact with secrets

### Keybindings

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

**Debug Logging**: Run with `--debug` to enable logging to `azure_tui.log` in the current directory:

```bash
akv --debug
```

## Use Cases

- **DevOps Engineers**: Quickly retrieve secrets during deployment and troubleshooting
- **Developers**: Access API keys, connection strings, and credentials without leaving the terminal
- **Security Teams**: Audit and manage secrets across multiple Azure Key Vaults

## Troubleshooting

<details>

<summary>Common issues and solutions</summary>

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

</details>

## Acknowledgements

`akv-tui-rs` is made possible by [ratatui](https://github.com/ratatui-org/ratatui), [crossterm](https://github.com/crossterm-rs/crossterm), and the [Azure SDK for Rust](https://github.com/Azure/azure-sdk-for-rust).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Related Projects

- [Azure CLI](https://github.com/Azure/azure-cli) - Official Azure command-line interface
- [ratatui](https://github.com/ratatui-org/ratatui) - The TUI framework powering this tool
- [azure-sdk-for-rust](https://github.com/Azure/azure-sdk-for-rust) - Azure SDK for Rust

## License

This project is licensed under the [Apache License 2.0](LICENSE).

---

*This project was built with the assistance of [Antigravity](https://antigravity.google) and LLMs.*
