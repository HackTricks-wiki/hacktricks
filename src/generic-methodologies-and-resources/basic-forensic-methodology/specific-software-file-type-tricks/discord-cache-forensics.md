# Discord Cache Forensics（Chromium Disk Cache）

本页总结如何对 Discord Desktop cache artifacts 进行 triage，以查找本地缓存的 media、webhook endpoints 以及 activity correlation。Discord 的 desktop client 使用 Electron，而 Electron 会将 disk cache 等 session data 存储在 `sessionData` 下。<sup>[[3]](#references)[[4]](#references)</sup>

## 查找位置（Windows/macOS/Linux）

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

这些是所引用 parser 使用的默认路径；Electron 允许 application 覆盖 `sessionData`，因此在 acquisition 期间应确认实际的 profile path。<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` 布局与 Chromium 的 blockfile disk-cache backend 匹配；不要在未验证 backend 的情况下将其标记为 Simple Cache，因为 Chromium 记录了不同的 cache implementations。<sup>[[5]](#references)</sup>

`Cache_Data` 内的关键 on-disk structures：
- `index`：用于定位 entries 的 Blockfile cache index。
- `data_#`：固定大小的 block files，可包含 cache metadata、HTTP headers 以及 response data。
- `f_######`：用于存储大于 block-file limit 的 data 的独立 files；这些 files 包含存储的数据，但不含 block-file headers。

删除 messages、channels 或 servers，并不保证已经在本地缓存的 bytes 被移除，但 Chromium 可能随时 evict 或重新创建 cache files。应将幸存的 artifacts 视为 opportunistic evidence，并且只能将 file modification times 作为粗略的 local-write signals，必须与其他 telemetry 进行 correlation。<sup>[[5]](#references)[[6]](#references)</sup>

## 可以恢复的内容

根据已 fetched 且尚未被 evicted 的内容，triage 可能恢复 cached attachments、media、URLs 以及 file hashes；单独的 cache 无法证明某个 item 已被 exfiltrated。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URLs 引用的 attachments 和 thumbnails。
- Images、GIFs 和 videos（例如 `.jpg`、`.png`、`.gif`、`.webp`、`.mp4` 和 `.webm`）。
- Webhook URLs，例如 `https://discord.com/api/webhooks/...`。<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls，例如 `https://discord.com/api/vX/...`。<sup>[[2]](#references)</sup>
- 恢复 media 的 SHA-256 hashes，用于与已知 datasets 或 intelligence feeds 进行 comparison。<sup>[[1]](#references)[[2]](#references)</sup>

## 快速 triage（手动）

- Grep cache 以查找高信号 artifacts。这些 patterns 与所引用 parser 的 URL expressions 相对应，是 triage filters，并非 exhaustive indicators。<sup>[[2]](#references)</sup>
- Webhook endpoints：
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs：
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls：
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 按 modified time 对 cached entries 排序，以构建粗略 sequence；mtime 是 filesystem signal，其本身无法确定某个 Discord object 何时被 fetched 或 sent。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## 解析 f_* entries（HTTP body + headers）

在 blockfile layout 中，`f_######` files 是独立的 data streams，并不保证以完整的 HTTP response 开始。如果 acquired file 确实包含 serialized HTTP headers，且其后跟随 `\r\n\r\n`，则在第一个 delimiter 处分割并进行检查：<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type：用于推断 media type
- Content-Location 或 X-Original-URL：用于 preview/correlation 的原始 remote URL
- Content-Encoding：可能为 gzip/deflate/br（Brotli）。

之后可以通过分离 headers 和 body 来提取 media，并根据 `Content-Encoding` 选择性地进行 decompress；所引用 parser 支持 Brotli、gzip 和 deflate。当 `Content-Type` 不存在时，magic-byte sniffing 很有用，但仍属于 heuristic。<sup>[[2]](#references)</sup>

## Automated DFIR：Discord Forensic Suite（CLI/GUI）

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser)。<sup>[[1]](#references)</sup>
- Function：递归扫描 Discord 的 cache folder，查找 webhook/API/attachment URLs，解析 `f_*` bodies，可选择性地 carve media，并输出 HTML 和 CSV reports，以及可选的带 SHA-256 hashes 的 chronological timeline。<sup>[[1]](#references)[[2]](#references)</sup>

Example CLI usage:
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
- --cache: Discord Cache_Data 目录的路径
- --format html|csv|both
- --timeline: 输出按修改时间排序的 CSV 时间线
- --extra: 同时扫描同级的 Code Cache 和 GPUCache
- --carve: 使用已识别的媒体签名（图像/视频）从原始缓存字节中 carve 媒体文件
- Output: `<output>.html`、`<output>.csv`、可选的 `<output>_timeline.csv`，以及包含提取或 carve 文件的 `<output>_media` 文件夹。

## 分析人员提示

- 将 `f_*` 和 `data_*` 文件的修改时间（mtime）与用户或攻击者活动时间窗口及独立 telemetry 进行关联；mtime 并非确定性的事件时间戳。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 对恢复的媒体计算哈希（SHA-256），并与已知恶意或 exfiltration 数据集进行比较。<sup>[[1]](#references)[[2]](#references)</sup>
- 将提取出的 webhook URL 视为凭据。不要仅为测试其存活状态而调用它们；应安全地保留这些 URL，协调撤销或轮换，并使用相关网络 telemetry 进行 retro-hunting。<sup>[[7]](#references)</sup>
- 服务端删除并不能保证本地缓存字节已被销毁。如果可以进行 acquisition，应在缓存被驱逐或重建前，收集整个 `Cache` 目录及相关同级缓存（`Code Cache`、`GPUCache`）。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite（CLI/GUI）](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord 如何无缝地将数百万用户升级到 64 位架构](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [磁盘缓存](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord 作为 C2 以及遗留的缓存证据](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks - 执行 Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
