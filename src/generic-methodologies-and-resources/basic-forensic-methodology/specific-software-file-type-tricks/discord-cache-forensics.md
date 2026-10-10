# Uchunguzi wa Cache ya Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa jinsi ya kuchunguza awali mabaki ya cache ya Discord Desktop ili kupata media iliyohifadhiwa ndani ya kifaa, webhook endpoints, na kuoanisha shughuli. Client ya desktop ya Discord hutumia Electron, na Electron huhifadhi data ya session kama disk cache chini ya `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Mahali pa kutafuta (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Hizi ndizo njia chaguomsingi zinazotumiwa na parser iliyorejelewa; Electron huruhusu programu kubadilisha `sessionData`, kwa hiyo thibitisha njia halisi ya profile wakati wa ukusanyaji.<sup>[[2]](#references)[[4]](#references)</sup>

Muundo wa `index` + `data_#` + `f_######` unalingana na backend ya Chromium ya blockfile disk-cache; usiutambulishe kama Simple Cache bila kuthibitisha backend, kwa sababu Chromium inaeleza utekelezaji tofauti wa cache.<sup>[[5]](#references)</sup>

Miundo muhimu iliyo kwenye diski ndani ya `Cache_Data`:
- `index`: Index ya cache ya Blockfile inayotumiwa kupata entries.
- `data_#`: Faili za block zenye ukubwa usiobadilika ambazo zinaweza kuwa na metadata ya cache, HTTP headers, na data ya majibu.
- `f_######`: Faili tofauti zinazotumiwa kwa data iliyo kubwa kuliko kikomo cha block-file; faili hizi zina data iliyohifadhiwa bila block-file headers.

Kufuta ujumbe, channels, au servers hakuhakikishi kuondolewa kwa bytes ambazo tayari zimehifadhiwa kwenye cache ya kifaa, lakini Chromium inaweza kuondoa au kuunda upya faili za cache wakati wowote. Chukulia mabaki yaliyosalia kama ushahidi wa bahati; tumia nyakati za kubadilishwa kwa faili kama dalili za jumla tu za uandishi wa ndani, ambazo lazima zilinganishwe na telemetry nyingine.<sup>[[5]](#references)[[6]](#references)</sup>

## Kinachoweza kurejeshwa

Kulingana na kilichopakuliwa na ambacho bado hakijaondolewa kwenye cache, uchunguzi wa awali unaweza kurejesha attachments, media, URLs, na hashes za faili zilizohifadhiwa kwenye cache; cache pekee haithibitishi kwamba kitu kilichotolewa nje ya mfumo.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments na thumbnails zinazorejelewa na Discord CDN URLs.
- Picha, GIFs, na videos (kwa mfano, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4`, na `.webm`).
- Webhook URLs kama `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Miito ya Discord API kama `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hashes za media zilizorejeshwa kwa kulinganisha na datasets au feeds za taarifa za kiintelijensia zinazojulikana.<sup>[[1]](#references)[[2]](#references)</sup>

## Uchunguzi wa awali wa haraka (kwa mikono)

- Tafuta mabaki yenye viashiria muhimu kwenye cache. Miundo hii inafanana na URL expressions za parser iliyorejelewa; ni vichujio vya uchunguzi wa awali, si viashiria kamili.<sup>[[2]](#references)</sup>
  - Webhook endpoints:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Attachment/CDN URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Miito ya Discord API:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Panga entries za cache kwa muda wa kubadilishwa ili kuunda mfuatano wa takriban; mtime ni kiashiria cha mfumo wa faili na peke yake haibainishi wakati ambapo kitu cha Discord kilipakuliwa au kutumwa.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Kuchanganua entries za f_* (HTTP body + headers)

Katika muundo wa blockfile, faili za `f_######` ni data streams tofauti na hazihakikishiwi kuanza na HTTP response kamili. Ikiwa faili iliyokusanywa ina HTTP headers zilizofuatana na `\r\n\r\n`, tenganisha sehemu hizo kwenye delimiter ya kwanza kisha kagua:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Kukisia aina ya media
- Content-Location au X-Original-URL: URL asilia ya mbali kwa ajili ya preview/ulinganisho
- Content-Encoding: Inaweza kuwa gzip/deflate/br (Brotli).

Kisha media inaweza kutolewa kwa kutenganisha headers na body na, kwa hiari, ku-decompress kulingana na `Content-Encoding`; parser iliyorejelewa hushughulikia Brotli, gzip, na deflate. Kukagua magic-byte husaidia wakati `Content-Type` haipo, lakini bado ni mbinu ya kukisia.<sup>[[2]](#references)</sup>

## DFIR ya kiotomatiki: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Kazi: Huchanganua kwa kujirudia folda ya cache ya Discord, hupata webhook/API/attachment URLs, huchanganua bodies za `f_*`, inaweza kwa hiari kuchonga media, na hutoa ripoti za HTML na CSV pamoja na timeline ya hiari ya mpangilio wa muda iliyo na SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

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

CLI inafafanua chaguo hizi na majina ya matokeo:<sup>[[2]](#references)</sup>
- --cache: Njia ya kuelekea kwenye saraka ya Discord Cache_Data
- --format html|csv|both
- --timeline: Toa ratiba ya CSV iliyopangwa (kwa muda wa kurekebishwa)
- --extra: Changanua pia Code Cache na GPUCache zilizo kwenye saraka jirani
- --carve: Carve media kutoka kwenye baiti ghafi za cache kwa kutumia saini za media zinazotambulika (picha/video)
- Matokeo: `<output>.html`, `<output>.csv`, hiari ya `<output>_timeline.csv`, na folda ya `<output>_media` yenye faili zilizotolewa au carved.

## Vidokezo kwa wachambuzi

- Linganisha muda wa kurekebishwa (mtime) wa faili za `f_*` na `data_*` na vipindi vya shughuli za mtumiaji au mshambuliaji, pamoja na telemetry huru; mtime si muhuri wa muda wa tukio unaoweza kuthibitishwa.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Kokotoa hash za media iliyorejeshwa (SHA-256) na uzilinganishe na seti za data zinazojulikana kuwa hasidi au za uchujaji wa data.<sup>[[1]](#references)[[2]](#references)</sup>
- Chukulia URL za webhook zilizotolewa kama credentials. Usizitumie tu kupima kama bado zinafanya kazi; zihifadhi kwa usalama, ratibu kuzifuta au kuzibadilisha, na tumia telemetry ya mtandao inayohusiana kwa retro-hunting.<sup>[[7]](#references)</sup>
- Kufutwa kwa upande wa seva hakuhakikishi kwamba baiti zilizohifadhiwa kwenye cache ya ndani zimeangamizwa. Ikiwezekana kupata data, kusanya saraka nzima ya `Cache` na cache jirani zinazohusiana (`Code Cache`, `GPUCache`) kabla ya kuondolewa au cache kuundwa upya.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Kifurushi cha Uchunguzi wa KiForensiki cha Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI ya Kifurushi cha Uchunguzi wa KiForensiki cha Discord](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Jinsi Discord Ilivyowahamisha Bila Usumbufu Mamilioni ya Watumiaji kwenda kwenye Usanifu wa 64-Bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [programu | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache ya Diski](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord kama C2 na ushahidi wa cache ulioachwa nyuma](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Tekeleza Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
