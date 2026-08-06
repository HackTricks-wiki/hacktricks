# Uchunguzi wa Discord Cache (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa jinsi ya kufanya triage ya artifacts za Discord Desktop cache ili kurejesha files zilizotolewa, webhook endpoints, na timelines za shughuli. Discord Desktop ni Electron/Chromium app na hutumia Chromium Simple Cache kwenye disk.

## Mahali pa kuangalia (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Miundo muhimu iliyo kwenye disk ndani ya Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Binary cache block files ambazo zinaweza kuwa na cached objects nyingi
- f_######: Cached entries za kibinafsi zilizohifadhiwa kama files zinazojitegemea (mara nyingi zikiwa na bodies kubwa)

Kumbuka: Kufuta messages/channels/servers kwenye Discord hakufuti local cache hii. Cached items mara nyingi hubaki, na timestamps za files huendana na user activity, hivyo kuwezesha kutengeneza upya timeline.<sup>[[1]](#references)</sup>

## Kinachoweza kurejeshwa

- Attachments zilizotolewa na thumbnails zilizofikiwa kupitia cdn.discordapp.com/media.discordapp.net
- Images, GIFs, videos (k.m., .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- Husaidia kuhusianisha beaconing/exfil activity na kufanya hashing ya media kwa ajili ya intel matching<sup>[[1]](#references)</sup>

## Quick triage (manual)

- Tumia Grep kwenye cache kutafuta artifacts zenye signal kubwa:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Panga entries za cache kulingana na modified time ili kujenga timeline ya haraka (mtime huonyesha wakati object iliingia kwenye cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Kuchambua f_* entries (HTTP body + headers)

Files zinazoanza na f_ huwa na HTTP response headers ikifuatiwa na body. Header block kwa kawaida huisha kwa \r\n\r\n. Response headers zenye manufaa ni pamoja na:
- Content-Type: Kukadiria media type
- Content-Location or X-Original-URL: Original remote URL kwa preview/correlation
- Content-Encoding: Inaweza kuwa gzip/deflate/br (Brotli)

Media inaweza kutolewa kwa kutenganisha headers na body na, kwa hiari, ku-decompress kulingana na Content-Encoding. Magic-byte sniffing ni muhimu wakati Content-Type haipo.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Huchanganua kwa kina Discord’s cache folder, hupata webhook/API/attachment URLs, huchanganua f_* bodies, inaweza kuchonga media kwa hiari, na hutoa HTML + CSV timeline reports zenye SHA‑256 hashes.<sup>[[2]](#references)</sup>

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
- --cache: Path to Cache_Data
- --format html|csv|both
- --timeline: Toa CSV timeline iliyopangwa (kwa modified time)
- --extra: Pia scan sibling Code Cache na GPUCache
- --carve: Carve media kutoka raw bytes karibu na regex hits (images/video)
- Output: HTML report, CSV report, CSV timeline, na media folder yenye mafaili yaliyocarve/extract

## Vidokezo vya Analyst

- Correlate modified time (mtime) ya mafaili ya f_* na data_* na vipindi vya user/attacker activity ili kuunda upya timeline.
- Hash recovered media (SHA-256) na ulinganishe dhidi ya known-bad au exfil datasets.
- Extracted webhook URLs zinaweza kutestwa kwa liveness au kuzungushwa; zingatia kuziongeza kwenye blocklists na kufanya retro-hunting kwenye proxies.
- Cache huendelea kuwepo baada ya “wiping” upande wa server. Ikiwa acquisition inawezekana, kusanya directory nzima ya Cache na sibling caches zinazohusiana (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## References

- [1] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
