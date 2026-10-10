# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

यह पेज स्थानीय रूप से cached media, webhook endpoints और activity correlation के लिए Discord Desktop cache artifacts की triage का सारांश देता है। Discord का desktop client Electron का उपयोग करता है, और Electron session data जैसे disk cache को `sessionData` के अंतर्गत संग्रहित करता है।<sup>[[3]](#references)[[4]](#references)</sup>

## कहाँ देखें (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

ये संदर्भित parser द्वारा उपयोग किए जाने वाले default paths हैं; Electron किसी application को `sessionData` override करने देता है, इसलिए acquisition के दौरान वास्तविक profile path की पुष्टि करें।<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` लेआउट Chromium के blockfile disk-cache backend से मेल खाता है; backend की पुष्टि किए बिना इसे Simple Cache न कहें, क्योंकि Chromium अलग-अलग cache implementations का दस्तावेज़ देता है।<sup>[[5]](#references)</sup>

`Cache_Data` के भीतर मुख्य on-disk संरचनाएँ:
- `index`: Blockfile cache index, जिसका उपयोग entries ढूँढने के लिए किया जाता है।
- `data_#`: Fixed-size block files, जिनमें cache metadata, HTTP headers और response data हो सकते हैं।
- `f_######`: Block-file limit से बड़े data के लिए इस्तेमाल होने वाली अलग files; इन files में block-file headers के बिना संग्रहित data होता है।

Messages, channels या servers delete करने से पहले से locally cached bytes हटने की गारंटी नहीं मिलती, लेकिन Chromium किसी भी समय cache files को evict या recreate कर सकता है। बचे हुए artifacts को अवसरजन्य साक्ष्य मानें, और file modification times को केवल स्थानीय write के मोटे संकेत के रूप में इस्तेमाल करें, जिन्हें अन्य telemetry से correlate करना ज़रूरी है।<sup>[[5]](#references)[[6]](#references)</sup>

## क्या recover किया जा सकता है

क्या fetch किया गया था और अभी तक evict नहीं हुआ है, इसके आधार पर triage में cached attachments, media, URLs और file hashes recover किए जा सकते हैं; केवल cache से यह साबित नहीं होता कि कोई item exfiltrate किया गया था।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URLs द्वारा संदर्भित attachments और thumbnails।
- Images, GIFs और videos (उदाहरण के लिए, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` और `.webm`)।
- `https://discord.com/api/webhooks/...` जैसे webhook URLs।<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` जैसी Discord API calls।<sup>[[2]](#references)</sup>
- ज्ञात datasets या intelligence feeds से तुलना के लिए recovered media के SHA-256 hashes।<sup>[[1]](#references)[[2]](#references)</sup>

## त्वरित triage (मैन्युअल)

- High-signal artifacts के लिए cache में grep करें। ये patterns संदर्भित parser के URL expressions से मेल खाते हैं और triage filters हैं, exhaustive indicators नहीं।<sup>[[2]](#references)</sup>
  - Webhook endpoints:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Attachment/CDN URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API calls:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- मोटा sequence बनाने के लिए cached entries को modified time के अनुसार sort करें; mtime filesystem signal है और अपने आप यह निर्धारित नहीं करता कि Discord object कब fetch या send किया गया था।<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## `f_*` entries को parse करना (HTTP body + headers)

Blockfile लेआउट में, `f_######` files अलग data streams होती हैं और इनके शुरू में पूरा HTTP response होने की गारंटी नहीं होती। यदि acquired file में serialized HTTP headers के बाद `\r\n\r\n` मौजूद हो, तो पहले delimiter पर split करें और जाँचें:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Media type का अनुमान लगाने के लिए
- Content-Location या X-Original-URL: Preview/correlation के लिए मूल remote URL
- Content-Encoding: gzip/deflate/br (Brotli) हो सकता है।

Headers को body से split करके और `Content-Encoding` के अनुसार वैकल्पिक रूप से decompress करके media निकाला जा सकता है; संदर्भित parser Brotli, gzip और deflate संभालता है। `Content-Type` न होने पर magic-byte sniffing उपयोगी है, लेकिन यह एक heuristic है।<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Discord के cache folder को recursively scan करता है, webhook/API/attachment URLs ढूँढता है, `f_*` bodies parse करता है, वैकल्पिक रूप से media carve करता है, और HTML व CSV reports के साथ SHA-256 hashes वाली वैकल्पिक chronological timeline आउटपुट करता है।<sup>[[1]](#references)[[2]](#references)</sup>

CLI usage का उदाहरण:

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

CLI इन options और output names को परिभाषित करता है:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data directory का path
- --format html|csv|both
- --timeline: क्रमबद्ध CSV timeline (modified time के अनुसार) जनरेट करें
- --extra: साथ वाले Code Cache और GPUCache को भी scan करें
- --carve: पहचाने गए media signatures (images/video) का उपयोग करके raw cache bytes से media carve करें
- Output: `<output>.html`, `<output>.csv`, वैकल्पिक `<output>_timeline.csv`, और extracted या carved files वाला `<output>_media` folder।

## Analyst tips

- `f_*` और `data_*` files के modified time (mtime) का user या attacker activity windows और स्वतंत्र telemetry से मिलान करें; mtime किसी घटना का निश्चित timestamp नहीं होता।<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- बरामद media का hash (SHA-256) निकालें और उसकी तुलना ज्ञात malicious या exfiltration datasets से करें।<sup>[[1]](#references)[[2]](#references)</sup>
- निकाले गए webhook URLs को credentials मानें। केवल उनकी उपलब्धता जांचने के लिए उन्हें invoke न करें; उन्हें सुरक्षित रूप से संरक्षित करें, revocation या rotation के लिए समन्वय करें, और retro-hunting के लिए संबंधित network telemetry का उपयोग करें।<sup>[[7]](#references)</sup>
- Server-side deletion से यह सुनिश्चित नहीं होता कि स्थानीय cached bytes नष्ट हो गए हैं। यदि acquisition संभव हो, तो eviction या cache दोबारा बनाए जाने से पहले पूरी `Cache` directory और उससे संबंधित साथ वाले caches (`Code Cache`, `GPUCache`) एकत्र करें।<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord ने लाखों उपयोगकर्ताओं को 64-बिट आर्किटेक्चर पर निर्बाध रूप से कैसे अपग्रेड किया](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
