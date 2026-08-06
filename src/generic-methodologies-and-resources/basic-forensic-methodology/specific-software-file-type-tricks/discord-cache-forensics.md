# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

यह पेज Discord Desktop cache artifacts को triage करने, exfiltrated files, webhook endpoints और activity timelines को recover करने का सारांश देता है। Discord Desktop एक Electron/Chromium app है और disk पर Chromium Simple Cache का उपयोग करता है।

## कहाँ देखें (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data के अंदर मुख्य on-disk structures:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Binary cache block files, जिनमें कई cached objects हो सकते हैं
- f_######: Individual cached entries, जो standalone files के रूप में stored होते हैं (अक्सर बड़े bodies)

ध्यान दें: Discord में messages/channels/servers delete करने से यह local cache purge नहीं होता। Cached items अक्सर मौजूद रहते हैं और उनके file timestamps user activity के साथ align होते हैं, जिससे timeline reconstruction संभव होता है।<sup>[[1]](#references)</sup>

## क्या recover किया जा सकता है

- cdn.discordapp.com/media.discord.net के माध्यम से fetched exfiltrated attachments और thumbnails
- Images, GIFs, videos (जैसे .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- Beaconing/exfil activity को correlate करने और intel matching के लिए media की hashing में उपयोगी<sup>[[1]](#references)</sup>

## Quick triage (manual)

- High-signal artifacts के लिए cache में Grep करें:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Quick timeline बनाने के लिए cached entries को modified time के अनुसार sort करें (mtime उस समय को दर्शाता है जब object cache में आया):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entries को parse करना (HTTP body + headers)

f_ से शुरू होने वाली files में HTTP response headers के बाद body होती है। Header block आम तौर पर \r\n\r\n पर समाप्त होता है। उपयोगी response headers में शामिल हैं:
- Content-Type: Media type का अनुमान लगाने के लिए
- Content-Location या X-Original-URL: Correlation/preview के लिए original remote URL
- Content-Encoding: gzip/deflate/br (Brotli) हो सकता है

Headers को body से split करके और Content-Encoding के आधार पर optionally decompress करके media extract की जा सकती है। जब Content-Type मौजूद न हो, तब magic-byte sniffing उपयोगी होती है।

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Function: Discord के cache folder को recursively scan करता है, webhook/API/attachment URLs खोजता है, f_* bodies को parse करता है, optionally media carve करता है, और SHA‑256 hashes के साथ HTML + CSV timeline reports output करता है।<sup>[[2]](#references)</sup>

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
मुख्य options:
- --cache: Cache_Data का path
- --format html|csv|both
- --timeline: ordered CSV timeline (modified time के अनुसार)
- --extra: sibling Code Cache और GPUCache को भी scan करें
- --carve: regex hits के पास raw bytes से media (images/video) carve करें
- Output: HTML report, CSV report, CSV timeline, और carved/extracted files वाला media folder

## Analyst tips

- timeline को reconstruct करने के लिए f_* और data_* files के modified time (mtime) को user/attacker activity windows के साथ correlate करें।
- Recovered media का hash (SHA-256) निकालें और known-bad या exfil datasets से compare करें।
- Extracted webhook URLs को liveness के लिए test या rotate किया जा सकता है; उन्हें blocklists में जोड़ने और proxies पर retro-hunting करने पर विचार करें।
- Server side पर “wiping” करने के बाद भी Cache बना रहता है। यदि acquisition संभव हो, तो पूरी Cache directory और संबंधित sibling caches (Code Cache, GPUCache) collect करें।<sup>[[1]](#references)</sup>

## References

- [1] [C2 के रूप में Discord और पीछे छूटे cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
