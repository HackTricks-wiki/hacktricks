# Forensics ya Discord Cache (Chromium Disk Cache)

Ukurasa huu unatoa muhtasari wa jinsi ya kufanya triage ya artifacts za Discord Desktop cache kwa ajili ya media iliyohifadhiwa locally, webhook endpoints, na correlation ya shughuli. Discord desktop client hutumia Electron, na Electron huhifadhi session data kama vile disk cache chini ya `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Mahali pa kutafuta (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Hizi ndizo paths za default zinazotumiwa na parser iliyorejelewa; Electron inaruhusu application kubadilisha `sessionData`, kwa hiyo thibitisha profile path halisi wakati wa acquisition.<sup>[[2]](#references)[[4]](#references)</sup>

Mpangilio wa `index` + `data_#` + `f_######` unaendana na Chromium's blockfile disk-cache backend; usiite Simple Cache bila kuthibitisha backend, kwa sababu Chromium inaandika kuhusu cache implementations tofauti.<sup>[[5]](#references)</sup>

Miundo muhimu ya on-disk ndani ya `Cache_Data`:
- `index`: Blockfile cache index inayotumika kutafuta entries.
- `data_#`: Fixed-size block files zinazoweza kuwa na cache metadata, HTTP headers, na response data.
- `f_######`: Separate files zinazotumika kwa data kubwa kuliko kikomo cha block-file; files hizi huwa na data iliyohifadhiwa bila block-file headers.

Kufuta messages, channels, au servers hakuhakikishi kuondolewa kwa bytes ambazo tayari zimehifadhiwa locally, lakini Chromium inaweza ku-evict au kuunda upya cache files wakati wowote. Chukulia artifacts zinazoendelea kuwepo kama ushahidi wa fursa, na tumia file modification times kama signals za makadirio ya local-write pekee, ambazo lazima zi-correlate na telemetry nyingine.<sup>[[5]](#references)[[6]](#references)</sup>

## Kinachoweza kurecoveriwa

Kulingana na kilichofetchiwa na ambacho bado hakija-evictiwa, triage inaweza kurecover cached attachments, media, URLs, na file hashes; cache pekee haithibitishi kuwa item iliexfiltrate.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments na thumbnails zilizorejelewa na Discord CDN URLs.
- Images, GIFs, na videos (kwa mfano, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4`, na `.webm`).
- Webhook URLs kama `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls kama `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hashes za media iliyorecoveriwa kwa kulinganisha na known datasets au intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Quick triage (manual)

- Grep cache kwa artifacts zenye signal kubwa. Patterns hizi zinaakisi URL expressions za parser iliyorejelewa, na ni triage filters, si indicators kamili.<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Panga entries za cache kulingana na modified time ili kujenga sequence ya makadirio; mtime ni filesystem signal na peke yake haithibitishi wakati Discord object ilifetchiwa au kutumwa.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Kuchanganua entries za f_* (HTTP body + headers)

Katika blockfile layout, `f_######` files ni separate data streams na hazihakikishwi kuanza na complete HTTP response. Ikiwa file iliyopatikana ina serialized HTTP headers zikifuatwa na `\r\n\r\n`, igawanye kwenye delimiter ya kwanza na ichunguze:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Kukadiria media type
- Content-Location au X-Original-URL: Original remote URL kwa preview/correlation
- Content-Encoding: Inaweza kuwa gzip/deflate/br (Brotli).

Media inaweza kutolewa kwa kugawanya headers kutoka kwa body na kwa hiari ku-decompress kulingana na `Content-Encoding`; parser iliyorejelewa hushughulikia Brotli, gzip, na deflate. Magic-byte sniffing ni muhimu wakati `Content-Type` haipo, lakini bado ni heuristic.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Huchanganua recursively Discord's cache folder, hutafuta webhook/API/attachment URLs, huchanganua `f_*` bodies, inaweza ku-carve media kwa hiari, na hutoa HTML na CSV reports pamoja na chronological timeline ya hiari yenye SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

Mfano wa matumizi ya CLI:
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
CLI inafafanua chaguo hizi na majina ya output:<sup>[[2]](#references)</sup>
- --cache: Path ya Discord Cache_Data directory
- --format html|csv|both
- --timeline: Toa CSV timeline iliyopangwa (kwa modified time)
- --extra: Pia scan sibling Code Cache na GPUCache
- --carve: Carve media kutoka raw cache bytes kwa kutumia media signatures zinazotambuliwa (images/video)
- Output: `<output>.html`, `<output>.csv`, `<output>_timeline.csv` ya hiari, na folder ya `<output>_media` yenye mafaili yaliyotolewa au kuchongwa.

## Vidokezo kwa mchambuzi

- Linganisha modified time (mtime) ya mafaili ya `f_*` na `data_*` na vipindi vya shughuli za mtumiaji au attacker pamoja na telemetry huru; mtime si timestamp ya tukio yenye uhakika.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Tengeneza hash ya media iliyorejeshwa (SHA-256) na ulinganishe dhidi ya datasets zinazojulikana kuwa hatari au za exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Chukulia webhook URLs zilizotolewa kama credentials. Usiziinvoke kwa madhumuni ya kujaribu tu kama ziko hai; zihifadhi kwa usalama, ratibu revocation au rotation, na tumia telemetry ya mtandao inayohusiana kwa retro-hunting.<sup>[[7]](#references)</sup>
- Kufutwa kwa upande wa server hakuhakikishi kwamba cache bytes za ndani zimeharibiwa. Ikiwa acquisition inawezekana, kusanya directory nzima ya `Cache` na sibling caches zinazohusiana (`Code Cache`, `GPUCache`) kabla ya eviction au cache recreation.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Jinsi Discord Ilivyowasasisha Mamilioni ya Watumiaji Bila Usumbufu hadi kwa 64-Bit Architecture](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord kama C2 na ushahidi wa cache ulioachwa nyuma](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
