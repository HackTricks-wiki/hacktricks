# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

This page summarizes how to triage Discord Desktop cache artifacts for locally cached media, webhook endpoints, and activity correlation. Discord's desktop client uses Electron, and Electron stores session data such as the disk cache under `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Where to look (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

These are the default paths used by the referenced parser; Electron allows an application to override `sessionData`, so confirm the actual profile path during acquisition.<sup>[[2]](#references)[[4]](#references)</sup>

The `index` + `data_#` + `f_######` layout matches Chromium's blockfile disk-cache backend; do not label it Simple Cache without verifying the backend, because Chromium documents distinct cache implementations.<sup>[[5]](#references)</sup>

Key on-disk structures inside `Cache_Data`:
- `index`: Blockfile cache index used to locate entries.
- `data_#`: Fixed-size block files that can contain cache metadata, HTTP headers, and response data.
- `f_######`: Separate files used for data larger than the block-file limit; these files contain the stored data without the block-file headers.

Deleting messages, channels, or servers does not guarantee removal of bytes already cached locally, but Chromium may evict or recreate cache files at any time. Treat surviving artifacts as opportunistic evidence, and use file modification times only as rough local-write signals that must be correlated with other telemetry.<sup>[[5]](#references)[[6]](#references)</sup>

## What can be recovered

Depending on what was fetched and not yet evicted, triage may recover cached attachments, media, URLs, and file hashes; the cache alone does not prove that an item was exfiltrated.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments and thumbnails referenced by Discord CDN URLs.
- Images, GIFs, and videos (for example, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4`, and `.webm`).
- Webhook URLs such as `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls such as `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hashes of recovered media for comparison with known datasets or intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Quick triage (manual)

- Grep cache for high-signal artifacts. These patterns mirror the referenced parser's URL expressions and are triage filters, not exhaustive indicators.<sup>[[2]](#references)</sup>
  - Webhook endpoints:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Attachment/CDN URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API calls:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sort cached entries by modified time to build a rough sequence; mtime is a filesystem signal and does not by itself establish when a Discord object was fetched or sent.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

In the blockfile layout, `f_######` files are separate data streams and are not guaranteed to begin with a complete HTTP response. If an acquired file does contain serialized HTTP headers followed by `\r\n\r\n`, split at the first delimiter and inspect:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: To infer media type
- Content-Location or X-Original-URL: Original remote URL for preview/correlation
- Content-Encoding: May be gzip/deflate/br (Brotli).

Media can then be extracted by splitting headers from the body and optionally decompressing according to `Content-Encoding`; the referenced parser handles Brotli, gzip, and deflate. Magic-byte sniffing is useful when `Content-Type` is absent, but remains a heuristic.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Recursively scans Discord's cache folder, finds webhook/API/attachment URLs, parses `f_*` bodies, optionally carves media, and outputs HTML and CSV reports plus an optional chronological timeline with SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

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

The CLI defines these options and output names:<sup>[[2]](#references)</sup>
- --cache: Path to the Discord Cache_Data directory
- --format html|csv|both
- --timeline: Emit ordered CSV timeline (by modified time)
- --extra: Also scan sibling Code Cache and GPUCache
- --carve: Carve media from raw cache bytes using recognized media signatures (images/video)
- Output: `<output>.html`, `<output>.csv`, optional `<output>_timeline.csv`, and an `<output>_media` folder with extracted or carved files.

## Analyst tips

- Correlate the modified time (mtime) of `f_*` and `data_*` files with user or attacker activity windows and independent telemetry; mtime is not a definitive event timestamp.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Hash recovered media (SHA-256) and compare against known-bad or exfiltration datasets.<sup>[[1]](#references)[[2]](#references)</sup>
- Treat extracted webhook URLs as credentials. Do not invoke them merely to test liveness; preserve them securely, coordinate revocation or rotation, and use related network telemetry for retro-hunting.<sup>[[7]](#references)</sup>
- Server-side deletion does not guarantee that local cached bytes have been destroyed. If acquisition is possible, collect the entire `Cache` directory and related sibling caches (`Code Cache`, `GPUCache`) before eviction or cache recreation.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [How Discord Seamlessly Upgraded Millions of Users to 64-Bit Architecture](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
