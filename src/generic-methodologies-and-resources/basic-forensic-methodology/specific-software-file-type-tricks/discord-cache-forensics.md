# Discord 缓存取证 (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

本页概述如何对 Discord Desktop 的缓存遗留物进行初步分析，以恢复被外发的文件、webhook 端点和活动时间线。Discord Desktop 是基于 Electron/Chromium 的应用，磁盘上使用 Chromium Simple Cache。

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 中的关键磁盘结构：
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

注意：在 Discord 中删除消息/频道/服务器并不会清除本地缓存。缓存项通常会保留，其文件时间戳与用户活动相符，可用于时间线重建。

## What can be recovered

- 通过 cdn.discordapp.com/media.discordapp.net 获取的被外发附件和缩略图
- 图片、GIF、视频（例如 .jpg, .png, .gif, .webp, .mp4, .webm）
- Webhook URL（https://discord.com/api/webhooks/…）
- Discord API 调用（https://discord.com/api/vX/…）
- 有助于关联 beaconing/exfil 活动并对媒体进行哈希以进行情报匹配

## Quick triage (manual)

- 在缓存中搜寻高价值痕迹：
- Webhook 端点：
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- 附件/CDN URL：
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API 调用：
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 按修改时间排序缓存条目以构建快速时间线（mtime 反映对象进入缓存的时间）：
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

以 f_ 开头的文件包含 HTTP 响应头，随后是 body。头部块通常以 \r\n\r\n 结尾。有用的响应头包括：
- Content-Type: 用于推断媒体类型
- Content-Location or X-Original-URL: 原始远程 URL，以便预览/关联
- Content-Encoding: 可能是 gzip/deflate/br (Brotli)

可以通过将头部与主体分离并根据 Content-Encoding 进行可选解压来提取媒体。当缺少 Content-Type 时，基于 magic-byte 的嗅探很有用。

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: 递归扫描 Discord 的缓存文件夹，查找 webhook/API/附件 URL，解析 f_* 主体，可选地 carve 出媒体，并输出带有 SHA‑256 哈希的 HTML + CSV 时间线报告。

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
- --cache: 指向 Cache_Data 的路径
- --format html|csv|both
- --timeline: 按修改时间 (mtime) 生成有序的 CSV 时间线
- --extra: 也会扫描相邻的 Code Cache 和 GPUCache
- --carve: 从靠近 regex 命中的原始字节中提取媒体（images/video）
- Output: HTML report、CSV report、CSV timeline，以及包含已 carve/提取文件的媒体文件夹

## Analyst tips

- 将 f_* 和 data_* 文件的修改时间 (mtime) 与用户/攻击者的活动时间窗口关联，以重建时间线。
- 对恢复的媒体进行哈希（SHA-256），并与已知恶意或 exfil 数据集进行比对。
- 提取出的 webhook URLs 可以用于检测是否存活或是否已被轮换；考虑将其加入阻断列表并添加到 retro-hunting 代理中。
- 即使在服务器端“wiping”之后，Cache 仍会保留。如果可能获取，应收集整个 Cache 目录及相关的相邻缓存（Code Cache、GPUCache）。

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
