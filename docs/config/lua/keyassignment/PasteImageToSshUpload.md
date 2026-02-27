# `PasteImageToSshUpload`

*Since: nightly builds only*

Reads an image from the clipboard, uploads it to the remote server via SFTP
(or SCP as fallback), and pastes the remote file path into the current pane.

On Windows, the clipboard image is read as DIB format and converted to PNG.
On Linux (X11 and Wayland), the clipboard image is read directly as PNG via
the `image/png` MIME type.
On macOS, the clipboard image is read as PNG (`public.png`) if available,
otherwise as TIFF (`public.tiff`) and converted to PNG.

This action is designed for use when connected to a remote host via an SSH
domain and you want to share a screenshot or clipboard image with a remote
application (such as Claude Code) that can read images from file paths.

The remote path is determined by
[ssh_image_paste_remote_path](../config/ssh_image_paste_remote_path.md).

The feature can be disabled via
[ssh_image_paste_enabled](../config/ssh_image_paste_enabled.md).

**Requirements:**
* Windows, Linux (X11/Wayland), or macOS
* The current pane must be connected via SSH (either an SSH domain or a
  detected `ssh` process)
* The clipboard must contain image data
* On Linux/FreeBSD: `xclip` or `xsel` (X11), or `wl-paste` from
  `wl-clipboard` (Wayland) must be installed. WezTerm checks for these
  tools at startup and shows a warning notification if they are missing.

**Upload methods:**
* **SFTP** — used when the pane belongs to a `RemoteSshDomain`
* **SCP** — used as fallback when SSH is detected via process inspection.
  SCP uses `BatchMode=yes`, so passwordless authentication (SSH key or agent)
  is required.

**Error handling:** If any step fails (no image in clipboard, not an SSH pane,
SFTP/SCP write error), a toast notification is shown with the error message.

```lua
local wezterm = require 'wezterm'
local act = wezterm.action

config.keys = {
  {
    key = 'V',
    mods = 'CTRL|SHIFT',
    action = act.PasteImageToSshUpload,
  },
}
```
