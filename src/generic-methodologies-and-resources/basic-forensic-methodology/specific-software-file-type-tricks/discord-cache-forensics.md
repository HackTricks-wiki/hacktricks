# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

This page summarizes how to triage Discord Desktop cache artifacts to recover exfiltrated files, webhook endpoints, and activity timelines. Discord Desktop is an Electron/Chromium app and uses Chromium Simple Cache on disk.

## कहाँ देखें (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data के अंदर महत्वपूर्ण ऑन‑डिस्क संरचनाएँ:
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

Note: Discord में messages/channels/servers को हटाने से यह लोकल cache purge नहीं होता। Cached items अक्सर रहती हैं और उनकी file timestamps उपयोगकर्ता की गतिविधि के अनुरूप होती हैं, जिससे timeline पुनर्निर्माण संभव होता है।

## क्या रिकवर किया जा सकता है

- cdn.discordapp.com/media.discordapp.net के माध्यम से फ़ेच की गई निकाली गई attachments और thumbnails
- छवियाँ, GIFs, वीडियो (उदा., .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API कॉल्स (https://discord.com/api/vX/…)
- beaconing/exfil activity को correlate करने और intel matching के लिए मीडिया का hashing करने में मददगार

## त्वरित ट्रायज (मैन्युअल)

- उच्च‑सिग्नल आर्टिफैक्ट के लिए cache में grep करें:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- एक त्वरित टाइमलाइन बनाने के लिए cached एंट्रीज़ को modified time के अनुसार सॉर्ट करें (mtime दर्शाता है कि ऑब्जेक्ट कब cache में आया था):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* एंट्रीज़ का पार्सिंग (HTTP body + headers)

f_ से शुरू होने वाली फ़ाइलों में HTTP response headers होते हैं और उसके बाद body होती है। हेडर ब्लॉक आमतौर पर \r\n\r\n पर समाप्त होता है। उपयोगी response headers में शामिल हैं:
- Content-Type: मीडिया प्रकार का अनुमान लगाने के लिए
- Content-Location or X-Original-URL: प्रीव्यू/कोरिलेशन के लिए मूल रिमोट URL
- Content-Encoding: gzip/deflate/br (Brotli) हो सकता है

मीडिया को headers और body को अलग करके निकाला जा सकता है और वैकल्पिक रूप से Content-Encoding के आधार पर डीकम्प्रेस किया जा सकता है। जब Content-Type अनुपस्थित हो तब magic-byte sniffing उपयोगी होता है।

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- कार्य: Discord के cache फ़ोल्डर को recursively स्कैन करता है, webhook/API/attachment URLs ढूंढता है, f_* बॉडीज़ को पार्स करता है, वैकल्पिक रूप से media carve करता है, और SHA‑256 हैश के साथ HTML + CSV टाइमलाइन रिपोर्ट्स आउटपुट करता है।

उदाहरण CLI उपयोग:
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
मुख्य विकल्प:
- --cache: Cache_Data का पथ
- --format html|csv|both
- --timeline: क्रमबद्ध CSV timeline जारी करें (modified time के अनुसार)
- --extra: संबंधित Code Cache और GPUCache भी स्कैन करें
- --carve: regex हिट्स के पास raw bytes से media carve करें (images/video)
- Output: HTML रिपोर्ट, CSV रिपोर्ट, CSV timeline, और carved/extracted फ़ाइलों के साथ एक मीडिया फ़ोल्डर

## विश्लेषक सुझाव

- f_* और data_* फ़ाइलों के modified time (mtime) को user/attacker की गतिविधि विंडो के साथ मिलाकर एक टाइमलाइन पुनर्निर्मित करें।
- recovered media का hash (SHA-256) निकालें और known-bad या exfil datasets के साथ तुलना करें।
- Extracted webhook URLs की liveness जाँचें या उन्हें rotate करें; इन्हें blocklists और retro-hunting proxies में जोड़ने पर विचार करें।
- Server side पर “wiping” के बाद भी Cache बरकरार रहता है। अगर acquisition संभव हो, तो पूरे Cache directory और संबंधित sibling caches (Code Cache, GPUCache) इकट्ठा करें।

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
