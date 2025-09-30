# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

This page summarizes how to triage Discord Desktop cache artifacts to recover exfiltrated files, webhook endpoints, and activity timelines. Discord Desktop is an Electron/Chromium app and uses Chromium Simple Cache on disk.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Key on‑disk structures inside Cache_Data:
- index: Simple Cache indeksdatabasis
- data_#: Binêre cache-bloklêers wat meerdere gecachte objeke kan bevat
- f_######: Individuele gecachte inskrywings gestoor as afsonderlike lêers (dikwels groter bodies)

Note: Deleting messages/channels/servers in Discord does not purge this local cache. Cached items often remain and their file timestamps align with user activity, enabling timeline reconstruction.

## What can be recovered

- Exfiltrated attachments and thumbnails fetched via cdn.discordapp.com/media.discordapp.net
- Images, GIFs, videos (e.g., .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API calls (https://discord.com/api/vX/…)
- Helpful for correlating beaconing/exfil activity and hashing media for intel matching

## Quick triage (manual)

- Grep die cache vir hoë-signaal artefakte:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sorteer gecachte inskrywings volgens wysigingstyd om 'n vinnige tydlyn te bou (mtime weerspieël wanneer die objek in die cache gekom het):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Files starting with f_ contain HTTP response headers followed by the body. The header block typically ends with \r\n\r\n. Useful response headers include:
- Content-Type: Om media-type af te lei
- Content-Location or X-Original-URL: Originêre remote URL vir preview/korrelasie
- Content-Encoding: Mag wees gzip/deflate/br (Brotli)

Media kan uitgehaal word deur headers van die body te skei en opsioneel te dekomprimeer gebaseer op Content-Encoding. Magic-byte sniffing is nuttig wanneer Content-Type afwesig is.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Rekursief skandeer Discord se cache-lêergids, vind webhook/API/attachment URLs, parseer f_* bodies, opsioneel carve media, en gee HTML + CSV tydlyn-verslae met SHA‑256 hashes uit.

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
- --cache: Pad na Cache_Data
- --format html|csv|both
- --timeline: Emit geordende CSV-tydlyn (op modified time)
- --extra: Skandeer ook suster Code Cache en GPUCache
- --carve: Onttrek media uit rou bytes naby regex-treffers (images/video)
- Output: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## Wenke vir ontleders

- Korreleer die modified time (mtime) van f_* en data_* lêers met gebruiker/aanvaller-aktiwiteitsvensters om 'n tydlyn te herbou.
- Bereken die SHA-256-hash van die herstelde media en vergelyk dit met known-bad of exfil datasets.
- Uittrekte webhook URLs kan getoets word vir lewensvatbaarheid of geroteer word; oorweeg om dit by blocklists en retro-hunting proxies te voeg.
- Die Cache bly voortbestaan nadat daar aan die bediener-kant "wiping" uitgevoer is. Indien verkryging moontlik is, versamel die hele Cache directory en verwante suster-caches (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
