# Discord Cache Forensics（Chromium Disk Cache）

{{#include ../../../banners/hacktricks-training.md}}

本页面总结了如何对 Discord Desktop 的 cache artifacts 进行 triage，以查找本地缓存的媒体、webhook endpoints，并关联活动记录。Discord 的 desktop client 使用 Electron，而 Electron 会将 disk cache 等 session data 存储在 `sessionData` 下。<sup>[[3]](#references)[[4]](#references)</sup>

## 查找位置（Windows/macOS/Linux）

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

上述是 referenced parser 使用的默认路径；Electron 允许应用覆盖 `sessionData`，因此在 acquisition 期间应确认实际的 profile path。<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` 的布局与 Chromium 的 blockfile disk-cache backend 相匹配；在未验证 backend 前，不要将其标记为 Simple Cache，因为 Chromium 记录了不同的 cache implementations。<sup>[[5]](#references)</sup>

`Cache_Data` 中的关键磁盘结构：
- `index`：用于定位 entries 的 Blockfile cache index。
- `data_#`：固定大小的 block files，可包含 cache metadata、HTTP headers 和 response data。
- `f_######`：用于存储超过 block-file limit 的 data 的独立 files；这些 files 包含存储的数据，但不含 block-file headers。

删除 messages、channels 或 servers 并不能保证已经在本地缓存的 bytes 被移除，但 Chromium 可能随时 evict 或重新创建 cache files。将残留 artifacts 视为 opportunistic evidence，并且只能将 file modification times 作为粗略的本地写入信号，必须与其他 telemetry 进行关联。<sup>[[5]](#references)[[6]](#references)</sup>

## 可恢复的内容

根据已获取且尚未被 evict 的内容，triage 可能恢复 cached attachments、media、URLs 和 file hashes；单凭 cache 无法证明某个项目曾被 exfiltrated。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URLs 引用的 attachments 和 thumbnails。
- Images、GIFs 和 videos（例如 `.jpg`、`.png`、`.gif`、`.webp`、`.mp4` 和 `.webm`）。
- Webhook URLs，例如 `https://discord.com/api/webhooks/...`。<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls，例如 `https://discord.com/api/vX/...`。<sup>[[2]](#references)</sup>
- 恢复媒体的 SHA-256 hashes，可用于与已知 datasets 或 intelligence feeds 进行比较。<sup>[[1]](#references)[[2]](#references)</sup>

## 快速 triage（手动）

- Grep cache 以查找高信号 artifacts。这些 patterns 与 referenced parser 的 URL expressions 一致，是 triage filters，并非 exhaustive indicators。<sup>[[2]](#references)</sup>
- Webhook endpoints：
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs：
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls：
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 按 modified time 对 cached entries 排序，以构建粗略的 sequence；mtime 是 filesystem signal，本身不能确定 Discord object 被 fetched 或 sent 的时间。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## 解析 f_* entries（HTTP body + headers）

在 blockfile layout 中，`f_######` files 是独立的 data streams，并不保证以完整的 HTTP response 开始。如果 acquired file 确实包含 serialized HTTP headers，且后面跟随 `\r\n\r\n`，则在第一个 delimiter 处分割并检查：<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type：用于推断 media type
- Content-Location 或 X-Original-URL：用于 preview/correlation 的原始 remote URL
- Content-Encoding：可能是 gzip/deflate/br（Brotli）。

之后可以通过分离 headers 和 body，并根据 `Content-Encoding` 选择性地进行 decompress 来提取 media；referenced parser 支持 Brotli、gzip 和 deflate。当 `Content-Type` 缺失时，magic-byte sniffing 很有用，但仍属于 heuristic。<sup>[[2]](#references)</sup>

## Automated DFIR：Discord Forensic Suite（CLI/GUI）

- Repo：[Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser)。<sup>[[1]](#references)</sup>
- Function：递归扫描 Discord 的 cache folder，查找 webhook/API/attachment URLs，解析 `f_*` bodies，可选择性地 carve media，并输出 HTML 和 CSV reports，以及可选的 chronological timeline 和 SHA-256 hashes。<sup>[[1]](#references)[[2]](#references)</sup>

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
- --timeline: 输出按修改时间排序的 CSV timeline
- --extra: 同时扫描同级的 Code Cache 和 GPUCache
- --carve: 使用已识别的 media signatures（图像/视频）从原始 cache 字节中 carve media
- 输出：`<output>.html`、`<output>.csv`、可选的 `<output>_timeline.csv`，以及包含提取或 carve 文件的 `<output>_media` 文件夹。

## 分析人员提示

- 将 `f_*` 和 `data_*` 文件的修改时间（mtime）与用户或攻击者活动时间窗口及独立 telemetry 进行关联；mtime 并非确定的事件时间戳。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 对恢复的 media 计算 hash（SHA-256），并与已知恶意或 exfiltration 数据集进行比对。<sup>[[1]](#references)[[2]](#references)</sup>
- 将提取出的 webhook URLs 视为 credentials。不要仅为测试存活性而调用它们；应安全保存，协调撤销或轮换，并使用相关 network telemetry 进行 retro-hunting。<sup>[[7]](#references)</sup>
- 服务端删除并不保证本地缓存的字节已被销毁。如果可以进行 acquisition，应在缓存被清除或重新创建前，收集整个 `Cache` 目录及相关同级缓存（`Code Cache`、`GPUCache`）。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite（CLI/GUI）](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord 如何无缝地将数百万用户升级到 64 位架构](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [磁盘缓存](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord 作为 C2 以及遗留在缓存中的证据](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – 执行 Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
