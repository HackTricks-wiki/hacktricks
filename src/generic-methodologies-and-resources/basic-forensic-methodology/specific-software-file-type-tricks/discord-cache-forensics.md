# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa jinsi ya kuchambua cache artifacts za Discord Desktop ili kupata tena faili zilizotolewa (exfiltrated), endpoints za webhook, na ratiba za shughuli. Discord Desktop ni app ya Electron/Chromium na hutumia Chromium Simple Cache kwenye diski.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Miundo muhimu kwenye diski ndani ya Cache_Data:
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

Kumbuka: Kufuta ujumbe/kanali/seva kwenye Discord hakufuta cache hii ya eneo. Vipengee vilivyo kwenye cache mara nyingi hubaki na timestamps za faili zinaendana na shughuli za mtumiaji, kuruhusu ujenzi wa ratiba.

## What can be recovered

- Viambatisho vilivyotolewa (exfiltrated) na thumbnails zilizopakuliwa kupitia cdn.discordapp.com/media.discordapp.net
- Picha, GIFs, video (mfano .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Miito ya Discord API (https://discord.com/api/vX/…)
- Inasaidia kuoanisha beaconing/exfil shughuli na kukusanya hash za media kwa kulinganisha na intel

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
Chaguzi kuu:
- --cache: Njia ya Cache_Data
- --format html|csv|both
- --timeline: Toa timeline ya CSV iliyopangwa (kwa wakati uliorekebishwa / mtime)
- --extra: Pia chunguza Code Cache na GPUCache zilizo jirani
- --carve: Chimba media kutoka bytes ghafi karibu na hits za regex (picha/video)
- Output: Ripoti ya HTML, ripoti ya CSV, timeline ya CSV, na folda ya media yenye mafaili yaliyochimbwa/yaliyotolewa

## Vidokezo vya mchambuzi

- Linganisha modified time (mtime) ya f_* na data_* files na dirisha za shughuli za mtumiaji/mshambuliaji ili kujenga upya timeline.
- Pata hash ya media iliyopatikana (SHA-256) na linganisha dhidi ya datasets zilijulikana kuwa mbaya au za exfil.
- URLs za webhook zilizotolewa zinaweza kujaribiwa kwa uhai (liveness) au kubadilishwa; zingatia kuziweka kwenye blocklists na retro-hunting proxies.
- Cache huendelea kuwepo baada ya “wiping” upande wa server. Ikiwa upatikane acquisition, kusanya directory nzima ya Cache na caches jirani zinazohusiana (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
