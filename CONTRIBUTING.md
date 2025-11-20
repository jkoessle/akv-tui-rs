# Contributing to akv-tui-rs

Thank you for your interest in contributing to akv-tui-rs! This document provides guidelines for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Rust version, Azure CLI version)
- Relevant logs (use `--debug` flag)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please open an issue with:
- A clear description of the enhancement
- Use cases and benefits
- Any implementation ideas you have

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes**:
   - Follow Rust best practices and idioms
   - Run `cargo fmt` to format your code
   - Run `cargo clippy` to check for common mistakes
   - Add tests if applicable
3. **Test your changes**:
   - Run `cargo test` to ensure all tests pass
   - Test manually with `cargo run`
4. **Commit your changes**:
   - Write clear, descriptive commit messages
   - Reference any related issues
5. **Submit a pull request**:
   - Provide a clear description of the changes
   - Link to any related issues

## Development Setup

### Prerequisites

- Rust (latest stable version)
- Azure CLI (`az`)
- An Azure subscription with Key Vault access

### Linux-specific Requirements

```bash
sudo apt-get install libxcb-shape0-dev libxcb-xfixes0-dev
```

### Building

```bash
git clone https://github.com/jkoessle/akv-tui-rs.git
cd akv-tui-rs
cargo build
```

### Running

```bash
cargo run
```

### Testing

```bash
cargo test
```

### Debugging

```bash
cargo run -- --debug
```

This will create an `azure_tui.log` file with detailed logging information.

## Project Structure

- `src/main.rs` - Application entry point
- `src/app.rs` - Core application logic and state management
- `src/ui.rs` - Terminal UI rendering
- `src/azure.rs` - Azure Key Vault API integration
- `src/models.rs` - Data models

## Coding Guidelines

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and concise
- Handle errors appropriately (avoid unwrap in production code)

## Questions?

Feel free to open an issue for any questions about contributing!

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
