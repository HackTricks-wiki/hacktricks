# Discord 缓存取证（Chromium 磁盘缓存）

{{#include ../../../banners/hacktricks-training.md}}

本页概述如何对 Discord Desktop 缓存 artifacts 进行初步检查，以查找本地缓存的媒体、webhook endpoints 和活动关联信息。Discord 桌面客户端使用 Electron，Electron 会将磁盘缓存等会话数据存储在 `sessionData` 下。<sup>[[3]](#references)[[4]](#references)</sup>

## 检查位置（Windows/macOS/Linux）

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

这些是所引用 parser 使用的默认路径；Electron 允许应用覆盖 `sessionData`，因此在获取数据时应确认实际的 profile 路径。<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` 这种布局符合 Chromium 的 blockfile 磁盘缓存后端；在未验证后端前，不要将其标记为 Simple Cache，因为 Chromium 文档说明存在不同的缓存实现。<sup>[[5]](#references)</sup>

`Cache_Data` 中的关键磁盘结构：
- `index`：用于定位条目的 Blockfile 缓存索引。
- `data_#`：固定大小的块文件，可能包含缓存元数据、HTTP headers 和响应数据。
- `f_######`：用于存储大于块文件限制的数据的独立文件；这些文件包含存储的数据，不含块文件 headers。

删除消息、频道或服务器，并不能保证已缓存在本地的字节也会被移除，但 Chromium 可能随时逐出或重新创建缓存文件。将残留 artifacts 视为偶然留存的证据；文件修改时间只能作为粗略的本地写入信号，必须与其他遥测数据进行关联。<sup>[[5]](#references)[[6]](#references)</sup>

## 可以恢复的内容

根据已获取且尚未被逐出的数据，初步检查可能恢复缓存的附件、媒体、URL 和文件哈希；仅凭缓存无法证明某项内容已被 exfiltrated。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL 所引用的附件和缩略图。
- 图片、GIF 和视频（例如 `.jpg`、`.png`、`.gif`、`.webp`、`.mp4` 和 `.webm`）。
- Webhook URL，例如 `https://discord.com/api/webhooks/...`。<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API 调用，例如 `https://discord.com/api/vX/...`。<sup>[[2]](#references)</sup>
- 恢复媒体的 SHA-256 哈希，可用于与已知数据集或情报 feed 比较。<sup>[[1]](#references)[[2]](#references)</sup>

## 快速初步检查（手动）

- 使用 grep 搜索高信号 artifacts。这些模式与所引用 parser 的 URL 表达式一致，是初步筛选条件，并非穷尽性 indicators。<sup>[[2]](#references)</sup>
  - Webhook endpoints：
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - 附件/CDN URL：
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API 调用：
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 按修改时间对缓存条目排序，以构建粗略的时间序列；mtime 是文件系统信号，本身无法确定 Discord 对象何时被获取或发送。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## 解析 f_* 条目（HTTP body + headers）

在 blockfile 布局中，`f_######` 文件是独立的数据流，无法保证其以完整的 HTTP 响应开头。如果获取的文件确实包含序列化的 HTTP headers，后跟 `\r\n\r\n`，则可在第一个分隔符处分割并检查：<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type：用于推断媒体类型
- Content-Location 或 X-Original-URL：原始远程 URL，可用于预览/关联
- Content-Encoding：可能是 gzip/deflate/br（Brotli）。

随后可通过分割 headers 和 body 提取媒体，并根据 `Content-Encoding` 选择性解压；所引用的 parser 支持 Brotli、gzip 和 deflate。当 `Content-Type` 缺失时，使用 magic-byte 嗅探会有帮助，但这仍是一种启发式方法。<sup>[[2]](#references)</sup>

## 自动化 DFIR：Discord Forensic Suite（CLI/GUI）

- 仓库：[Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser)。<sup>[[1]](#references)</sup>
- 功能：递归扫描 Discord 的缓存文件夹，查找 webhook/API/附件 URL，解析 `f_*` bodies，可选择 carve 媒体，并输出 HTML 和 CSV 报告，以及可选的带 SHA-256 哈希的时间顺序 timeline。<sup>[[1]](#references)[[2]](#references)</sup>

CLI 使用示例：

```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
  --cache "$env:APPDATA\discord\Cache\Cache_Data" `
  --outdir "C:\IR\discord-cache" `
  --output discord_cache_report `
  --format both `
  --timeline `
  --extra `
  --carve `
  --verbose
```

CLI 定义了以下选项和输出名称：<sup>[[2]](#references)</sup>
- --cache：Discord Cache_Data 目录的路径
- --format html|csv|both
- --timeline：按修改时间生成有序 CSV 时间线
- --extra：同时扫描同级目录中的 Code Cache 和 GPUCache
- --carve：使用可识别的媒体签名（图像/视频）从原始缓存字节中 carving 媒体文件
- 输出：`<output>.html`、`<output>.csv`、可选的 `<output>_timeline.csv`，以及包含提取或 carving 文件的 `<output>_media` 文件夹。

## 分析人员提示

- 将 `f_*` 和 `data_*` 文件的修改时间（mtime）与用户或攻击者活动时间段及独立遥测数据相关联；mtime 并非确定的事件时间戳。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 对恢复的媒体计算哈希（SHA-256），并与已知恶意文件或数据外泄数据集进行比对。<sup>[[1]](#references)[[2]](#references)</sup>
- 将提取出的 webhook URL 视为凭据。不要仅为测试其是否有效而调用它们；应安全地保管这些 URL，协调吊销或轮换，并利用相关网络遥测进行追溯搜寻。<sup>[[7]](#references)</sup>
- 服务端删除并不保证本地缓存字节已被销毁。如果可以进行取证采集，应在缓存被清除或重新创建前，收集整个 `Cache` 目录及相关的同级缓存目录（`Code Cache`、`GPUCache`）。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord 取证套件（CLI/GUI）](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord 取证套件 CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord 如何无缝将数百万用户升级到 64 位架构](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [磁盘缓存](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [将 Discord 用作 C2 以及留下的缓存证据](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – 执行 Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
