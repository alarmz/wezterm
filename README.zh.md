# Wez's Terminal

[English README](README.md)

<img height="128" alt="WezTerm Icon" src="https://raw.githubusercontent.com/wezterm/wezterm/main/assets/icon/wezterm-icon.svg" align="left"> *由 <a href="https://github.com/wez">@wez</a> 開發、以 <a href="https://www.rust-lang.org/">Rust</a> 實作的 GPU 加速跨平台終端模擬器與多工器*

使用者文件與指南: https://wezterm.org/

![Screenshot](docs/screenshots/two.png)

*WezTerm 在 macOS 上執行 vim 的截圖*

## 亮點功能: SSH 剪貼簿圖片貼上

**一鍵將截圖貼入遠端 SSH 工作階段。**

當你透過 SSH 連線到遠端伺服器，需要將截圖或圖片分享給 CLI 工具（例如
[Claude Code](https://docs.anthropic.com/en/docs/claude-code)）時，WezTerm 可以
自動從本機 Windows 剪貼簿讀取圖片、轉換為 PNG 格式、透過 SFTP 或 SCP 上傳到遠端
伺服器，並將遠端檔案路徑貼入終端 — 一個按鍵全部搞定。

### 快速設定

在 `~/.wezterm.lua` 加入以下設定:

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

### 運作方式

1. 複製或截取一張圖片到剪貼簿
2. 在 SSH 分頁中按下 `Ctrl+V`（或你設定的快捷鍵）
3. WezTerm 自動執行以下步驟:
   - 從 Windows 剪貼簿讀取圖片
   - 轉換為 PNG 格式
   - 透過 SFTP（或 SCP 備援）上傳到遠端伺服器
   - 將遠端檔案路徑（例如 `/tmp/wezterm-paste-1709012345.png`）貼入終端

這對使用 AI 程式助手（如 Claude Code）特別實用 — 它們可以從檔案路徑讀取圖片，
但無法透過 SSH 存取你的本機剪貼簿。

### 進階設定

```lua
return {
  -- 自訂遠端儲存路徑（{timestamp} 會替換為 Unix 時間戳）
  ssh_image_paste_remote_path = '/tmp/wezterm-paste-{timestamp}.png',

  -- 停用此功能
  -- ssh_image_paste_enabled = false,
}
```

### 上傳方式

| 方式 | 使用時機 |
|------|---------|
| **SFTP** | 當分頁屬於 WezTerm 的 SSH Domain 時使用 |
| **SCP** | 當透過程序檢測到 `ssh` 連線時作為備援（需要 SSH Key 免密碼認證） |

### 需求

* 目前僅支援 Windows
* 分頁必須透過 SSH 連線（SSH Domain 或偵測到的 `ssh` 程序）
* 剪貼簿中必須有圖片資料

完整文件:
[PasteImageToSshUpload](https://wezterm.org/config/lua/keyassignment/PasteImageToSshUpload.html)

## 安裝

https://wezterm.org/installation

## 取得協助

* 使用 [GitHub Issue Tracker](https://github.com/wezterm/wezterm/issues) 回報問題或搜尋已知問題
* 在 [GitHub Discussions](https://github.com/wezterm/wezterm/discussions) 發起或參與討論
* 加入 [Matrix 聊天室 (Element.io)](https://app.element.io/#/room/#wezterm:matrix.org) 即時交流

## 贊助專案

如果你喜歡 WezTerm，歡迎贊助支持！你的贊助有助於維護專案並肯定開發者投入的時間。

[了解更多贊助方式](https://wezterm.org/sponsor.html)

* [![Sponsor WezTerm](https://img.shields.io/github/sponsors/wez?label=Sponsor%20WezTerm&logo=github&style=for-the-badge)](https://github.com/sponsors/wez)
* [Patreon](https://patreon.com/WezFurlong)
* [Ko-Fi](https://ko-fi.com/wezfurlong)
* [Liberapay](https://liberapay.com/wez)
