---
tags:
  - clipboard
---
# `image_paste_local_path = "/tmp/wezterm-paste-{timestamp}.png"`

*Since: nightly builds only*

Specifies the local file path template used when pasting clipboard images
via the `PasteFrom` action's image fallback. When the clipboard contains an
image but no text, `PasteFrom` (triggered by Cmd+V on macOS or
Ctrl+Shift+V on other platforms) will save the image to this path and paste
the resulting file path into the terminal.

The `{timestamp}` placeholder is replaced with the current Unix timestamp
in seconds, ensuring unique file names for each paste operation.

```lua
config.image_paste_local_path = '/tmp/wezterm-paste-{timestamp}.png'
```
