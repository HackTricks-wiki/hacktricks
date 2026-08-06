# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

本页总结了如何对 Discord Desktop cache artifacts 进行 triage，以恢复 exfiltrated files、webhook endpoints 和 activity timelines。Discord Desktop 是 Electron/Chromium app，并在磁盘上使用 Chromium Simple Cache。

## 查找位置（Windows/macOS/Linux）

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 内部的关键 on-disk structures:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Binary cache block files，可包含多个 cached objects
- f_######: 以 standalone files 形式存储的 individual cached entries（通常包含较大的 bodies）

注意：在 Discord 中删除 messages/channels/servers 不会清除 local cache。Cached items 通常仍会保留，其 file timestamps 与用户 activity 对齐，因此可以用于重建 timeline。<sup>[[1]](#references)</sup>

## 可恢复的内容

- 通过 cdn.discordapp.com/media.discordapp.net 获取的 exfiltrated attachments 和 thumbnails
- Images、GIFs、videos（例如 .jpg、.png、.gif、.webp、.mp4、.webm）
- Webhook URLs（https://discord.com/api/webhooks/…）<sup>[[3]](#references)</sup>
- Discord API calls（https://discord.com/api/vX/…）
- 有助于关联 beaconing/exfil activity，并对 media 进行 hashing 以匹配 intel<sup>[[1]](#references)</sup>

## 快速 triage（手动）

- Grep cache 以查找 high-signal artifacts：
- Webhook endpoints：
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs：
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls：
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 按 modified time 对 cached entries 排序，以快速构建 timeline（mtime 反映 object 进入 cache 的时间）：
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## 解析 f_* entries（HTTP body + headers）

以 f_ 开头的 files 包含 HTTP response headers，后跟 body。Header block 通常以 \r\n\r\n 结束。实用的 response headers 包括：
- Content-Type: 用于推断 media type
- Content-Location 或 X-Original-URL: 用于获取 preview/correlation 所需的原始 remote URL
- Content-Encoding: 可能是 gzip/deflate/br（Brotli）

可以通过分离 headers 和 body，并根据 Content-Encoding 选择性地进行 decompress，来提取 media。当 Content-Type 缺失时，magic-byte sniffing 很有用。

## Automated DFIR：Discord Forensic Suite（CLI/GUI）

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: 递归扫描 Discord 的 cache folder，查找 webhook/API/attachment URLs，解析 f_* bodies，可选择性地 carve media，并输出包含 SHA-256 hashes 的 HTML + CSV timeline reports。<sup>[[2]](#references)</sup>

Example CLI usage:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
关键选项：
- --cache: Cache_Data 的路径
- --format html|csv|both
- --timeline: 输出按修改时间排序的 CSV 时间线
- --extra: 同时扫描同级的 Code Cache 和 GPUCache
- --carve: 从 regex 命中附近的原始字节中提取媒体文件（图片/视频）
- 输出：HTML 报告、CSV 报告、CSV 时间线，以及包含提取/恢复文件的媒体文件夹

## 分析师提示

- 将 f_* 和 data_* 文件的修改时间（mtime）与用户/攻击者活动时间窗口进行关联，以重建时间线。
- 对恢复的媒体文件计算哈希（SHA-256），并与已知恶意文件或数据外泄数据集进行比对。
- 提取的 webhook URL 可测试其存活状态或进行轮换；考虑将其加入 blocklist，并对代理流量进行 retro-hunting。
- Cache 在服务器端执行“擦除”后仍会保留。如果可以进行采集，请收集整个 Cache 目录及相关的同级缓存（Code Cache、GPUCache）。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
