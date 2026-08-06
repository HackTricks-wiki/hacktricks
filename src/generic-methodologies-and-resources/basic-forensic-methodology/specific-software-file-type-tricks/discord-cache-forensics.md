# Uchunguzi wa Cache ya Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa jinsi ya kufanya uchambuzi wa awali wa artifacts za cache ya Discord Desktop ili kurejesha mafaili yaliyotolewa nje, webhook endpoints, na timelines za shughuli. Discord Desktop ni app ya Electron/Chromium na hutumia Chromium Simple Cache kwenye diski.

## Mahali pa kuangalia (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Miundo muhimu iliyo kwenye Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Binary cache block files zinazoweza kuwa na objects nyingi zilizohifadhiwa kwenye cache
- f_######: Cached entries binafsi zilizohifadhiwa kama mafaili standalone (mara nyingi zikiwa na bodies kubwa)

Kumbuka: Kufuta messages/channels/servers katika Discord hakufuti cache hii ya ndani. Items zilizohifadhiwa kwenye cache mara nyingi hubaki, na timestamps za mafaili yake huendana na shughuli za mtumiaji, hivyo kuwezesha uundaji upya wa timeline.<sup>[[1]](#references)</sup>

## Kinachoweza kurejeshwa

- Attachments zilizotolewa nje na thumbnails zilizopakuliwa kupitia cdn.discordapp.com/media.discordapp.net
- Images, GIFs, videos (kwa mfano, .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- Inasaidia kuhusianisha beaconing/exfil activity na kufanya hashing ya media kwa ajili ya intel matching<sup>[[1]](#references)</sup>

## Quick triage (manual)

- Tafuta artifacts zenye signal kubwa kwenye cache:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Panga entries zilizohifadhiwa kwenye cache kwa modified time ili kuunda timeline ya haraka (mtime huonyesha wakati object iliingia kwenye cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Kuchanganua entries za f_* (HTTP body + headers)

Mafaili yanayoanza na f_ yana HTTP response headers zikifuatiwa na body. Header block kwa kawaida huisha kwa \r\n\r\n. Response headers muhimu ni pamoja na:
- Content-Type: Kukadiria media type
- Content-Location au X-Original-URL: URL ya awali ya remote kwa preview/correlation
- Content-Encoding: Inaweza kuwa gzip/deflate/br (Brotli)

Media inaweza kutolewa kwa kutenganisha headers na body, na kwa hiari ku-decompress kulingana na Content-Encoding. Magic-byte sniffing ni muhimu wakati Content-Type haipo.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Function: Huchanganua kwa recursively folder ya cache ya Discord, hutafuta webhook/API/attachment URLs, huchanganua bodies za f_*, kwa hiari hucarve media, na hutoa HTML + CSV timeline reports zenye SHA‑256 hashes.<sup>[[2]](#references)</sup>

Mfano wa matumizi ya CLI:
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
Chaguo muhimu:
- --cache: Njia ya Cache_Data
- --format html|csv|both
- --timeline: Toa timeline ya CSV iliyopangwa (kwa muda wa marekebisho)
- --extra: Pia changanua Code Cache na GPUCache zilizo jirani
- --carve: Carve media kutoka kwa raw bytes karibu na regex hits (picha/video)
- Output: Ripoti ya HTML, ripoti ya CSV, timeline ya CSV, na folda ya media yenye faili zilizocarved/extracted

## Vidokezo kwa Analyst

- Linganisha muda wa marekebisho (mtime) wa faili za f_* na data_* na vipindi vya shughuli za mtumiaji/attacker ili kuunda upya timeline.
- Hash media iliyorejeshwa (SHA-256) na ulinganishe dhidi ya datasets zinazojulikana kuwa mbaya au za exfil.
- URL za webhook zilizotolewa zinaweza kupimwa kwa liveness au kuzungushwa; zingatia kuziongeza kwenye blocklists na kufanya retro-hunting kwenye proxies.
- Cache hudumu baada ya “wiping” upande wa server. Ikiwa acquisition inawezekana, kusanya directory yote ya Cache pamoja na sibling caches zinazohusiana (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Marejeo

- [1] [Discord kama C2 na ushahidi wa cache unaoachwa nyuma](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
