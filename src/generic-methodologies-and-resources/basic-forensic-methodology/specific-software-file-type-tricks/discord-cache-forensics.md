# Discord Cache Forensics (Chromium Disk Cache)

यह पेज locally cached media, webhook endpoints और activity correlation के लिए Discord Desktop cache artifacts की triage का सारांश देता है। Discord का desktop client Electron का उपयोग करता है, और Electron `sessionData` के अंतर्गत disk cache जैसे session data को store करता है।<sup>[[3]](#references)[[4]](#references)</sup>

## कहाँ देखें (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

ये referenced parser द्वारा उपयोग किए जाने वाले default paths हैं; Electron किसी application को `sessionData` override करने की अनुमति देता है, इसलिए acquisition के दौरान वास्तविक profile path की पुष्टि करें।<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` layout Chromium के blockfile disk-cache backend से मेल खाता है; backend की पुष्टि किए बिना इसे Simple Cache के रूप में label न करें, क्योंकि Chromium अलग-अलग cache implementations को document करता है।<sup>[[5]](#references)</sup>

`Cache_Data` के अंदर मौजूद on-disk structures:
- `index`: Entries का location पता लगाने के लिए उपयोग किया जाने वाला Blockfile cache index।
- `data_#`: Fixed-size block files, जिनमें cache metadata, HTTP headers और response data हो सकते हैं।
- `f_######`: Block-file limit से बड़े data के लिए उपयोग की जाने वाली अलग files; इन files में block-file headers के बिना stored data होता है।

Messages, channels या servers को delete करने से locally पहले से cached bytes के हटने की गारंटी नहीं होती, लेकिन Chromium किसी भी समय cache files को evict या recreate कर सकता है। बचे हुए artifacts को opportunistic evidence मानें, और file modification times का उपयोग केवल rough local-write signals के रूप में करें, जिन्हें अन्य telemetry के साथ correlate करना आवश्यक है।<sup>[[5]](#references)[[6]](#references)</sup>

## क्या recover किया जा सकता है

क्या fetch किया गया था और अभी तक evict नहीं हुआ है, इसके आधार पर triage से cached attachments, media, URLs और file hashes recover किए जा सकते हैं; केवल cache से यह साबित नहीं होता कि कोई item exfiltrate किया गया था।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URLs द्वारा referenced attachments और thumbnails।
- Images, GIFs और videos (उदाहरण के लिए, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` और `.webm`)।
- Webhook URLs जैसे `https://discord.com/api/webhooks/...`।<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls जैसे `https://discord.com/api/vX/...`।<sup>[[2]](#references)</sup>
- Recovered media के SHA-256 hashes, जिनका उपयोग known datasets या intelligence feeds के साथ comparison के लिए किया जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Quick triage (manual)

- High-signal artifacts के लिए cache में Grep करें। ये patterns referenced parser के URL expressions को mirror करते हैं और exhaustive indicators नहीं, बल्कि triage filters हैं।<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Rough sequence बनाने के लिए cached entries को modified time के अनुसार sort करें; mtime एक filesystem signal है और अपने-आप यह स्थापित नहीं करता कि कोई Discord object कब fetch या send किया गया था।<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## `f_*` entries को parse करना (HTTP body + headers)

Blockfile layout में `f_######` files अलग data streams होती हैं और इनके आरंभ में complete HTTP response होना guaranteed नहीं है। यदि acquired file में serialized HTTP headers के बाद `\r\n\r\n` मौजूद हो, तो पहले delimiter पर split करें और इसकी जाँच करें:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Media type का अनुमान लगाने के लिए
- Content-Location या X-Original-URL: Correlation/preview के लिए original remote URL
- Content-Encoding: gzip/deflate/br (Brotli) हो सकता है।

Headers को body से split करके और `Content-Encoding` के अनुसार optionally decompress करके media extract किया जा सकता है; referenced parser Brotli, gzip और deflate को handle करता है। जब `Content-Type` मौजूद न हो, तब magic-byte sniffing उपयोगी है, लेकिन यह heuristic ही रहता है।<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Discord के cache folder को recursively scan करता है, webhook/API/attachment URLs ढूँढता है, `f_*` bodies को parse करता है, optionally media carve करता है, और HTML तथा CSV reports के साथ SHA-256 hashes वाली optional chronological timeline output करता है।<sup>[[1]](#references)[[2]](#references)</sup>

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
CLI इन विकल्पों और output names को परिभाषित करता है:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data directory का path
- --format html|csv|both
- --timeline: क्रमबद्ध CSV timeline (modified time के अनुसार) जारी करता है
- --extra: sibling Code Cache और GPUCache को भी scan करता है
- --carve: पहचाने गए media signatures (images/video) का उपयोग करके raw cache bytes से media carve करता है
- Output: `<output>.html`, `<output>.csv`, वैकल्पिक `<output>_timeline.csv`, और extracted या carved files वाला `<output>_media` folder।

## Analyst tips

- `f_*` और `data_*` files के modified time (mtime) को user या attacker activity windows और independent telemetry के साथ correlate करें; mtime निश्चित event timestamp नहीं है।<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Recovered media का hash (SHA-256) बनाकर known-bad या exfiltration datasets से compare करें।<sup>[[1]](#references)[[2]](#references)</sup>
- Extracted webhook URLs को credentials की तरह treat करें। केवल liveness test करने के लिए उन्हें invoke न करें; उन्हें सुरक्षित रूप से preserve करें, revocation या rotation का coordination करें, और retro-hunting के लिए संबंधित network telemetry का उपयोग करें।<sup>[[7]](#references)</sup>
- Server-side deletion इस बात की guarantee नहीं देता कि local cached bytes नष्ट हो गए हैं। यदि acquisition संभव हो, तो eviction या cache recreation से पहले पूरी `Cache` directory और संबंधित sibling caches (`Code Cache`, `GPUCache`) collect करें।<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord ने लाखों users को 64-Bit Architecture में सहजता से upgrade कैसे किया](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as a C2 और पीछे छोड़े गए cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
