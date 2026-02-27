# CLAUDE.md — WezTerm Development Guide

## Project Overview

WezTerm is a GPU-accelerated cross-platform terminal emulator and multiplexer written in Rust.
This is a fork at `git@github.com:alarmz/wezterm.git`, based on the upstream [wezterm/wezterm](https://github.com/wezterm/wezterm).

## Quick Reference

### Build Commands

```sh
cargo build                        # Build all workspace members (debug)
cargo build -p wezterm-gui         # Build only the GUI binary
cargo build --release              # Release build
cargo check                        # Type-check without codegen (fastest iteration)
cargo check -p wezterm-gui         # Type-check a single crate
```

### Testing

```sh
cargo test --all                   # Run all tests
cargo nextest run                  # Fast parallel tests (preferred)
cargo test -p wezterm-term         # Test a specific crate
```

### Formatting & Linting

```sh
cargo fmt --all                    # Format all code
cargo fmt --all -- --check         # Check formatting without modifying
```

Formatting config (`.rustfmt.toml`): edition 2018, `imports_granularity = "Module"`, `tab_spaces = 4`.

## Workspace Structure

### Core Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `wezterm` | `wezterm/` | Main CLI binary with subcommands |
| `wezterm-gui` | `wezterm-gui/` | GUI application, rendering, input handling |
| `wezterm-term` | `term/` | Core terminal emulator model (escape sequences, screen) |
| `config` | `config/` | Configuration system (Lua-based, `.wezterm.lua`) |
| `mux` | `mux/` | Multiplexer model (tabs, panes, domains, windows) |
| `window` | `window/` | Cross-platform window management |
| `portable-pty` | `pty/` | Cross-platform PTY management |
| `termwiz` | `termwiz/` | Terminal UI library and utilities |
| `wezterm-ssh` | `wezterm-ssh/` | SSH integration |
| `wezterm-font` | `wezterm-font/` | Font configuration, shaping, rasterization |
| `wezterm-mux-server` | `wezterm-mux-server/` | Multiplexer server binary |

### Key Directories

- **`wezterm-gui/src/termwindow/`** — Main window implementation (rendering, clipboard, input)
- **`wezterm-gui/src/commands.rs`** — Command definitions and default keybindings
- **`wezterm-gui/src/inputmap.rs`** — Input/key mapping
- **`window/src/os/`** — Platform-specific window/clipboard code:
  - `windows/` — Windows implementation
  - `macos/` — macOS implementation
  - `x11/` — X11 implementation
  - `wayland/` — Wayland implementation
- **`config/src/keyassignment.rs`** — `KeyAssignment` enum (all possible key actions)
- **`config/src/config.rs`** — Main configuration struct
- **`lua-api-crates/`** — Lua API modules exposed to user config
- **`deps/`** — Vendored C/C++ dependencies (Cairo, FreeType, HarfBuzz, Fontconfig)
- **`docs/`** — Documentation site source (mkdocs)

## Architecture Notes

### Rendering Pipeline

- Primary renderer: **wgpu** (WebGPU) with WGSL shaders
- Fallback: **glium** (OpenGL) with GLSL shaders
- Shader files: `wezterm-gui/src/termwindow/shader.wgsl`, `glyph-vertex.glsl`, `glyph-frag.glsl`

### Configuration

- Users configure via `~/.wezterm.lua` (Lua 5.4, via `mlua`)
- Config struct: `config/src/config.rs` (`Configuration`)
- Key assignments: `config/src/keyassignment.rs` (`KeyAssignment` enum)

### Key Binding System

Default keybindings are defined in `wezterm-gui/src/commands.rs` via `CommandDef`.

The `permute_keys()` function (commands.rs) automatically generates variants:
- Every `SUPER` binding also generates `CTRL+SHIFT` equivalent
- Shift-key permutations for upper/lowercase forms

Platform-specific bindings use `#[cfg(target_os = "...")]` within CommandDef keys.

Binding registration: `wezterm-gui/src/inputmap.rs` (`InputMap::new()`)

### Clipboard & Paste

Smart paste logic in `wezterm-gui/src/termwindow/clipboard.rs`:
- `paste_from_clipboard()` — tries text first, falls back to image (saves locally, pastes path)
- `paste_image_to_ssh_upload()` — uploads image via SFTP/SCP to remote, pastes remote path

Platform clipboard implementations:
- Windows: `clipboard_win` crate, DIB→PNG conversion for images
- macOS: `NSPasteboard` (PNG preferred, TIFF fallback)
- X11: Selection protocol with `ConvertSelection`
- Wayland: Data device protocol, MIME types (`text/plain;charset=utf-8`, `image/png`)

### Multiplexing

Window → Tab → Pane hierarchy. Domain types: Local, SSH (RemoteSshDomain), TLS, Exec, WSL.

## Platform-Specific Notes

### Windows
- Copies `conpty.dll`, `OpenConsole.exe` to output dir at build time
- Static OpenSSL linking
- DIB format clipboard images need conversion to PNG

### macOS
- Uses `SUPER` modifier = Cmd key
- Native `NSPasteboard` for clipboard
- `Ctrl+V` preserved as terminal "verbatim insert"

### Linux
- X11 and Wayland both supported (`wayland` feature enabled by default)
- Clipboard image requires `xclip`/`xsel` (X11) or `wl-paste` (Wayland)
- `SUPER` modifier = Meta/Win key (often captured by window manager)

## Conventions

- **Edition**: Rust 2018
- **Imports**: Grouped by module (`imports_granularity = "Module"`)
- **Indentation**: 4 spaces
- **Error handling**: `anyhow` for application errors
- **Async**: Mix of `smol` and `tokio`; GUI uses `promise::spawn`
- **Tests**: Use `k9` assertions; include comments explaining test intent
- **Documentation**: Update `docs/changelog.md` and relevant docs for behavior changes

## CI/CD

- GitHub Actions (`.github/workflows/`) — multiple platform builds
- Cirrus CI (`.cirrus.yml`) — Ubuntu, ARM, Fedora builds
- Tests and formatting checked automatically on push
