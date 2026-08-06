# Discord Cache Forensics（Chromium Simple Cache）

{{#include ../../../banners/hacktricks-training.md}}

本页总结了如何对 Discord Desktop cache artifacts 进行 triage，以恢复 exfiltrated files、webhook endpoints 和 activity timelines。Discord Desktop 是一个 Electron/Chromium app，并在磁盘上使用 Chromium Simple Cache。

## 查找位置（Windows/macOS/Linux）

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 中的关键 on-disk structures:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Binary cache block files，可能包含多个 cached objects
- f_######: 以 standalone files 存储的 individual cached entries（通常包含更大的 bodies）

注意：在 Discord 中删除 messages/channels/servers 不会清除此 local cache。Cached items 通常仍会保留，其 file timestamps 与 user activity 对齐，从而能够重建 timeline。<sup>[[1]](#references)</sup>

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
- 按 modified time 对 cached entries 排序，以构建快速 timeline（mtime 反映 object 进入 cache 的时间）：
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## 解析 f_* entries（HTTP body + headers）

以 f_ 开头的 files 包含 HTTP response headers，后跟 body。Header block 通常以 \r\n\r\n 结束。Useful response headers 包括：
- Content-Type: 用于推断 media type
- Content-Location 或 X-Original-URL: 用于获取 original remote URL，以便进行 preview/correlation
- Content-Encoding: 可能为 gzip/deflate/br（Brotli）

可以通过分离 headers 和 body，并根据 Content-Encoding 进行可选解压来提取 media。当 Content-Type 缺失时，magic-byte sniffing 很有用。

## Automated DFIR：Discord Forensic Suite（CLI/GUI）

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Function: Recursively scans Discord 的 cache folder，查找 webhook/API/attachment URLs，解析 f_* bodies，可选地 carve media，并输出包含 SHA-256 hashes 的 HTML + CSV timeline reports。<sup>[[2]](#references)</sup>

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
Key options:
- --cache: Cache_Data 的路径
- --format html|csv|both
- --timeline: 输出按修改时间排序的 CSV timeline
- --extra: 同时扫描同级的 Code Cache 和 GPUCache
- --carve: 根据 regex hits 附近的原始字节提取 media（images/video）
- Output: HTML report、CSV report、CSV timeline，以及包含 carved/extracted files 的 media folder

## Analyst tips

- 将 f_* 和 data_* 文件的修改时间（mtime）与用户/attacker activity windows 进行关联，以重建 timeline。
- 对 recovered media 计算 hash（SHA-256），并与已知恶意数据集或 exfil datasets 进行比对。
- Extracted webhook URLs 可用于测试 liveness 或进行轮换；考虑将其加入 blocklists，并对 proxies 执行 retro-hunting。
- 即使在 server side 执行“wiping”后，Cache 仍会保留。如果可以进行 acquisition，请收集整个 Cache directory 以及相关的同级 caches（Code Cache、GPUCache）。<sup>[[1]](#references)</sup>

## References

- [1] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
