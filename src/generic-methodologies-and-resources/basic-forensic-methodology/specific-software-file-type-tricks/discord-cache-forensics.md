# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy som op hoe om Discord Desktop-cache-artefakte vir plaaslik gecachede media, webhook endpoints en aktiwiteitskorrelasie te triage. Discord se desktop-client gebruik Electron, en Electron stoor sessiedata soos die disk cache onder `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Waar om te kyk (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Dit is die verstekpaaie wat deur die verwysde parser gebruik word; Electron laat ’n toepassing toe om `sessionData` te override, dus moet die werklike profielpad tydens acquisition bevestig word.<sup>[[2]](#references)[[4]](#references)</sup>

Die `index` + `data_#` + `f_######`-uitleg stem ooreen met Chromium se blockfile disk-cache backend; moenie dit as Simple Cache benoem sonder om die backend te verifieer nie, omdat Chromium onderskeie cache-implementerings dokumenteer.<sup>[[5]](#references)</sup>

Belangrike on-disk-strukture binne `Cache_Data`:
- `index`: Blockfile-cache-indeks wat gebruik word om entries te lokaliseer.
- `data_#`: Bloklêers met vaste grootte wat cache-metadata, HTTP-headers en responsdata kan bevat.
- `f_######`: Afsonderlike lêers wat gebruik word vir data wat groter as die block-file-limiet is; hierdie lêers bevat die gestoorde data sonder die block-file-headers.

Die uitvee van messages, channels of servers waarborg nie dat grepe wat reeds plaaslik gecache is, verwyder word nie, maar Chromium kan cache-lêers enige tyd evict of herskep. Behandel oorblywende artefakte as opportunistiese evidence, en gebruik lêerwysigingstye slegs as rowwe seine van plaaslike writes wat met ander telemetry gekorreleer moet word.<sup>[[5]](#references)[[6]](#references)</sup>

## Wat herwin kan word

Afhangend van wat fetched is en nog nie evicted is nie, kan triage gecachede attachments, media, URLs en file hashes herwin; die cache alleen bewys nie dat ’n item geëksfiltreer is nie.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments en thumbnails waarna deur Discord CDN-URLs verwys word.
- Images, GIFs en videos (byvoorbeeld `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` en `.webm`).
- Webhook URLs soos `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls soos `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-hashes van herwinde media vir vergelyking met bekende datasets of intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Vinnige triage (manual)

- Grep die cache vir artefakte met ’n hoë seinwaarde. Hierdie patrone weerspieël die verwysde parser se URL-expressions en is triage-filters, nie volledige indicators nie.<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sorteer gecachede entries volgens wysigingstyd om ’n rowwe volgorde te bou; mtime is ’n filesystem-sein en bepaal nie op sy eie wanneer ’n Discord-object fetched of gestuur is nie.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing van f_* entries (HTTP body + headers)

In die blockfile-uitleg is `f_######`-lêers afsonderlike datastrome en dit word nie gewaarborg om met ’n volledige HTTP-respons te begin nie. Indien ’n acquired lêer wel geserialiseerde HTTP-headers bevat, gevolg deur `\r\n\r\n`, split by die eerste delimiter en ondersoek:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Om die mediat tipe af te lei
- Content-Location of X-Original-URL: Oorspronklike remote URL vir preview/korrelasie
- Content-Encoding: Kan gzip/deflate/br wees (Brotli).

Media kan dan onttrek word deur headers van die body te split en dit opsioneel volgens `Content-Encoding` te dekomprimeer; die verwysde parser hanteer Brotli, gzip en deflate. Magic-byte sniffing is nuttig wanneer `Content-Type` ontbreek, maar bly ’n heuristiek.<sup>[[2]](#references)</sup>

## Geoutomatiseerde DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funksie: Skandeer Discord se cache-folder rekursief, vind webhook/API/attachment-URLs, parse `f_*`-bodies, carve opsioneel media, en lewer HTML- en CSV-rapporte plus ’n opsionele chronologiese tydlyn met SHA-256-hashes.<sup>[[1]](#references)[[2]](#references)</sup>

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
- --carve: Carve media uit rou kasgrepe deur gebruik te maak van herkende mediasignatures (beelde/video)
- Output: `<output>.html`, `<output>.csv`, opsionele `<output>_timeline.csv`, en ’n `<output>_media`-gids met onttrekte of gecarve lêers.

## Ontlederwenke

- Korrelleer die wysigingstyd (mtime) van `f_*`- en `data_*`-lêers met gebruiker- of aanvalleraktiwiteitsvensters en onafhanklike telemetrie; mtime is nie ’n definitiewe gebeurtenistydstempel nie.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Hash herwonne media (SHA-256) en vergelyk dit met bekende-slegte of eksfiltrasiedatastelle.<sup>[[1]](#references)[[2]](#references)</sup>
- Behandel onttrekte webhook-URL’s as aanmeldbewyse. Moenie hulle bloot aanroep om beskikbaarheid te toets nie; bewaar hulle veilig, koördineer herroeping of rotasie, en gebruik verwante netwerktelemetrie vir retro-hunting.<sup>[[7]](#references)</sup>
- Uitwissing aan die bedienerkant waarborg nie dat plaaslik gekaste grepe vernietig is nie. Indien verkryging moontlik is, versamel die volledige `Cache`-gids en verwante naburige kaste (`Code Cache`, `GPUCache`) voordat dit verwyder word of die kas herskep word.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Hoe Discord miljoene gebruikers na 64-bis-argitektuur opgegradeer het](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [toepassing | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Skyfkas](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as ’n C2 en die gekaste bewyse wat agterbly](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Voer Webhook uit](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
