# Discord Cache Forensics (Chromium Disk Cache)

Hierdie bladsy som op hoe om Discord Desktop-cache-artefakte vir plaaslik gekaste media, webhook-endpunte en aktiwiteitskorrelasie te triage. Discord se desktop-kliënt gebruik Electron, en Electron stoor sessiedata soos die disk cache onder `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Waar om te kyk (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Dit is die verstekpaaie wat deur die verwysde parser gebruik word; Electron laat ’n toepassing toe om `sessionData` te oorskryf, dus bevestig die werklike profielpad tydens verkryging.<sup>[[2]](#references)[[4]](#references)</sup>

Die `index` + `data_#` + `f_######`-uitleg stem ooreen met Chromium se blockfile disk-cache-backend; moenie dit Simple Cache noem sonder om die backend te verifieer nie, omdat Chromium onderskeid tref tussen verskillende cache-implementerings.<sup>[[5]](#references)</sup>

Belangrike on-disk-strukture binne `Cache_Data`:
- `index`: Blockfile-cache-indeks wat gebruik word om entries op te spoor.
- `data_#`: Bloklêers met vaste grootte wat cache-metadata, HTTP-headers en responsdata kan bevat.
- `f_######`: Afsonderlike lêers wat gebruik word vir data wat groter as die block-file-limiet is; hierdie lêers bevat die gestoorde data sonder die block-file-headers.

Die verwydering van boodskappe, kanale of servers waarborg nie dat grepe wat reeds plaaslik gekas is, verwyder is nie, maar Chromium kan cache-lêers enige tyd verwyder of herskep. Behandel oorblywende artefakte as opportunistiese bewyse, en gebruik lêerwysigingstye slegs as rowwe seine van plaaslike skryfaksies wat met ander telemetry gekorreleer moet word.<sup>[[5]](#references)[[6]](#references)</sup>

## Wat herwin kan word

Afhangend van wat gefetch is en nog nie verwyder is nie, kan triage gekaste aanhegsels, media, URLs en lêerhashes herwin; die cache alleen bewys nie dat ’n item uitgelek is nie.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Aanhegsels en thumbnails waarna deur Discord CDN-URLs verwys word.
- Beelde, GIFs en videos (byvoorbeeld `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` en `.webm`).
- Webhook-URLs soos `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API-oproepe soos `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-hashes van herwonne media vir vergelyking met bekende datasets of intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Vinnige triage (handmatig)

- Grep die cache vir artefakte met hoë seinwaarde. Hierdie patrone weerspieël die verwysde parser se URL-expressions en is triage-filters, nie volledige indicators nie.<sup>[[2]](#references)</sup>
- Webhook-endpunte:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Aanhegsel/CDN-URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API-oproepe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sorteer gekaste entries volgens wysigingstyd om ’n rowwe volgorde te bou; mtime is ’n lêerstelselsein en bepaal nie op sigself wanneer ’n Discord-object gefetch of gestuur is nie.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing van f_* entries (HTTP-body + headers)

In die blockfile-uitleg is `f_######`-lêers afsonderlike datastrome en daar word nie gewaarborg dat hulle met ’n volledige HTTP-respons begin nie. Indien ’n verkrygde lêer wel geserialiseerde HTTP-headers bevat, gevolg deur `\r\n\r\n`, verdeel dit by die eerste delimiter en inspekteer dit:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Om die mediatype af te lei
- Content-Location of X-Original-URL: Oorspronklike afgeleë URL vir preview/korrelasie
- Content-Encoding: Kan gzip/deflate/br (Brotli) wees.

Media kan daarna onttrek word deur headers van die body te skei en dit opsioneel volgens `Content-Encoding` te dekomprimeer; die verwysde parser hanteer Brotli, gzip en deflate. Magic-byte-sniffing is nuttig wanneer `Content-Type` ontbreek, maar bly ’n heuristiek.<sup>[[2]](#references)</sup>

## Geoutomatiseerde DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funksie: Skandeer Discord se cache-lêergids rekursief, vind webhook/API/aanhegsel-URLs, parseer `f_*`-bodies, carve opsioneel media, en lewer HTML- en CSV-verslae plus ’n opsionele chronologiese tydlyn met SHA-256-hashes.<sup>[[1]](#references)[[2]](#references)</sup>

Voorbeeld van CLI-gebruik:
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
Die CLI definieer hierdie opsies en uitvoername:<sup>[[2]](#references)</sup>
- --cache: Pad na die Discord Cache_Data-gids
- --format html|csv|both
- --timeline: Genereer ’n geordende CSV-tydlyn (volgens wysigingstyd)
- --extra: Skandeer ook naburige Code Cache en GPUCache
- --carve: Onttrek media uit rou cache-grepe deur herkende mediasignature (beelde/video) te gebruik
- Output: `<output>.html`, `<output>.csv`, opsionele `<output>_timeline.csv`, en ’n `<output>_media`-gids met onttrekte of uitgesnyde lêers.

## Ontlederwenke

- Korrelleer die wysigingstyd (mtime) van `f_*`- en `data_*`-lêers met gebruiker- of aanvalleraktiwiteitsvensters en onafhanklike telemetrie; mtime is nie ’n definitiewe gebeurtenistydstempel nie.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Bereken ’n hash van herwonne media (SHA-256) en vergelyk dit met bekende kwaadwillige of eksfiltrasiedatastelle.<sup>[[1]](#references)[[2]](#references)</sup>
- Behandel onttrekte webhook-URL's as geloofsbriewe. Moenie hulle bloot aanroep om lewendigheid te toets nie; bewaar hulle veilig, koördineer herroeping of rotasie, en gebruik verwante netwerktelemetrie vir retroaktiewe opsporing.<sup>[[7]](#references)</sup>
- Verwydering aan die bedienerkant waarborg nie dat plaaslik-gecachede grepe vernietig is nie. Indien verkryging moontlik is, versamel die volledige `Cache`-gids en verwante naburige caches (`Code Cache`, `GPUCache`) voordat dit verwyder word of die cache herskep word.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Hoe Discord miljoene gebruikers na 64-bis-argitektuur opgegradeer het sonder onderbreking](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Skyf-cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as ’n C2 en die gecachede bewyse wat agterbly](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Voer Webhook uit](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
