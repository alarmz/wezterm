# `PasteImageToSshUpload`

*Since: nightly builds only*

Reads an image from the Windows clipboard, converts it to PNG format, uploads
it to the remote server via SFTP, and pastes the remote file path into the
current pane.

This action is designed for use when connected to a remote host via an SSH
domain and you want to share a screenshot or clipboard image with a remote
application (such as Claude Code) that can read images from file paths.

The remote path is determined by
[ssh_image_paste_remote_path](../config/ssh_image_paste_remote_path.md).

The feature can be disabled via
[ssh_image_paste_enabled](../config/ssh_image_paste_enabled.md).

**Requirements:**
* Windows only (other platforms will show a toast notification)
* The current pane must be in an SSH domain (not a local pane)
* The clipboard must contain image data

**Error handling:** If any step fails (no image in clipboard, not an SSH pane,
SFTP write error), a toast notification is shown with the error message.

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
