# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

This page summarizes how to triage Discord Desktop cache artifacts to recover exfiltrated files, webhook endpoints, and activity timelines. Discord Desktop is an Electron/Chromium app and uses Chromium Simple Cache on disk.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Key on‑disk structures inside Cache_Data:
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

Note: Deleting messages/channels/servers in Discord does not purge this local cache. Cached items often remain and their file timestamps align with user activity, enabling timeline reconstruction.

## What can be recovered

- Exfiltrated attachments and thumbnails fetched via cdn.discordapp.com/media.discordapp.net
- Images, GIFs, videos (e.g., .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API calls (https://discord.com/api/vX/…)
- Helpful for correlating beaconing/exfil activity and hashing media for intel matching

## Quick triage (manual)

- Grep cache for high-signal artifacts:
  - Webhook endpoints:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Attachment/CDN URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
  - Discord API calls:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sort cached entries by modified time to build a quick timeline (mtime reflects when the object hit cache):
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Files starting with f_ contain HTTP response headers followed by the body. The header block typically ends with \r\n\r\n. Useful response headers include:
- Content-Type: To infer media type
- Content-Location or X-Original-URL: Original remote URL for preview/correlation
- Content-Encoding: May be gzip/deflate/br (Brotli)

Media can be extracted by splitting headers from body and optionally decompressing based on Content-Encoding. Magic-byte sniffing is useful when Content-Type is absent.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Recursively scans Discord’s cache folder, finds webhook/API/attachment URLs, parses f_* bodies, optionally carves media, and outputs HTML + CSV timeline reports with SHA‑256 hashes.

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
- --cache: Path to Cache_Data
- --format html|csv|both
- --timeline: Emit ordered CSV timeline (by modified time)
- --extra: Also scan sibling Code Cache and GPUCache
- --carve: Carve media from raw bytes near regex hits (images/video)
- Output: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## Analyst tips

- Correlate the modified time (mtime) of f_* and data_* files with user/attacker activity windows to reconstruct a timeline.
- Hash recovered media (SHA-256) and compare against known-bad or exfil datasets.
- Extracted webhook URLs can be tested for liveness or rotated; consider adding them to blocklists and retro-hunting proxies.
- Cache persists after “wiping” on the server side. If acquisition is possible, collect the entire Cache directory and related sibling caches (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}