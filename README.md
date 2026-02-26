# Wez's Terminal

[中文版 README](README.zh.md)

<img height="128" alt="WezTerm Icon" src="https://raw.githubusercontent.com/wezterm/wezterm/main/assets/icon/wezterm-icon.svg" align="left"> *A GPU-accelerated cross-platform terminal emulator and multiplexer written by <a href="https://github.com/wez">@wez</a> and implemented in <a href="https://www.rust-lang.org/">Rust</a>*

User facing docs and guide at: https://wezterm.org/

![Screenshot](docs/screenshots/two.png)

*Screenshot of wezterm on macOS, running vim*

## Highlight: Clipboard Image Paste over SSH

**Paste screenshots directly into your remote SSH session with a single keystroke.**

When you're working on a remote server via SSH and need to share a screenshot
or image with a CLI tool (such as [Claude Code](https://docs.anthropic.com/en/docs/claude-code)),
WezTerm can read the image from your local Windows clipboard, convert it to
PNG, upload it to the remote server via SFTP or SCP, and paste the remote file
path into the terminal — all in one action.

### Quick Setup

Add this to your `~/.wezterm.lua`:

```lua
local wezterm = require 'wezterm'

return {
  keys = {
    {
      key = 'v',
      mods = 'CTRL',
      action = wezterm.action.PasteImageToSshUpload,
    },
  },
}
```

### How It Works

1. Copy or screenshot an image to your clipboard
2. Press `Ctrl+V` (or your configured key) in an SSH pane
3. WezTerm automatically:
   - Reads the image from the Windows clipboard
   - Converts it to PNG format
   - Uploads it to the remote server via SFTP (or SCP as fallback)
   - Pastes the remote file path (e.g. `/tmp/wezterm-paste-1709012345.png`)

This is especially useful with AI coding assistants like Claude Code that can
read images from file paths but cannot access your local clipboard over SSH.

See the full documentation:
[PasteImageToSshUpload](https://wezterm.org/config/lua/keyassignment/PasteImageToSshUpload.html)

## Installation

https://wezterm.org/installation

## Getting help

This is a spare time project, so please bear with me.  There are a couple of channels for support:

* You can use the [GitHub issue tracker](https://github.com/wezterm/wezterm/issues) to see if someone else has a similar issue, or to file a new one.
* Start or join a thread in our [GitHub Discussions](https://github.com/wezterm/wezterm/discussions); if you have general
  questions or want to chat with other wezterm users, you're welcome here!
* There is a [Matrix room via Element.io](https://app.element.io/#/room/#wezterm:matrix.org)
  for (potentially!) real time discussions.

The GitHub Discussions and Element/Gitter rooms are better suited for questions
than bug reports, but don't be afraid to use whichever you are most comfortable
using and we'll work it out.

## Supporting the Project

If you use and like WezTerm, please consider sponsoring it: your support helps
to cover the fees required to maintain the project and to validate the time
spent working on it!

[Read more about sponsoring](https://wezterm.org/sponsor.html).

* [![Sponsor WezTerm](https://img.shields.io/github/sponsors/wez?label=Sponsor%20WezTerm&logo=github&style=for-the-badge)](https://github.com/sponsors/wez)
* [Patreon](https://patreon.com/WezFurlong)
* [Ko-Fi](https://ko-fi.com/wezfurlong)
* [Liberapay](https://liberapay.com/wez)
