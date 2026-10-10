# Forensiese ondersoek van Discord-kas (Chromium-skyfkas)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy som op hoe om Discord Desktop-kasartefakte te triage vir plaaslik gekaste media, webhook-eindpunte en aktiwiteitskorrelasie. Discord se rekenaarkliënt gebruik Electron, en Electron stoor sessiedata soos die skyfkas onder `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Waar om te kyk (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Dit is die verstekpaaie wat deur die parser waarna verwys word, gebruik word; Electron laat ’n toepassing toe om `sessionData` te oorheers, dus bevestig die werklike profielpad tydens verkryging.<sup>[[2]](#references)[[4]](#references)</sup>

Die `index` + `data_#` + `f_######`-uitleg stem ooreen met Chromium se blockfile-skyfkas-backend; moenie dit as Simple Cache bestempel sonder om die backend te verifieer nie, aangesien Chromium onderskeid tref tussen verskillende kasimplementasies.<sup>[[5]](#references)</sup>

Belangrike datastrukture op skyf binne `Cache_Data`:
- `index`: Blockfile-kasindeks wat gebruik word om inskrywings op te spoor.
- `data_#`: Lêers met vaste grootte wat kasmetadata, HTTP-opskrifte en antwoorddata kan bevat.
- `f_######`: Afsonderlike lêers wat gebruik word vir data wat die blockfile-limiet oorskry; hierdie lêers bevat die gestoorde data sonder die blockfile-opskrifte.

Die uitvee van boodskappe, kanale of bedieners waarborg nie dat grepe wat reeds plaaslik gekas is, verwyder word nie, maar Chromium kan kaslêers enige tyd uitwerp of herskep. Beskou oorblywende artefakte as toevallige bewyse, en gebruik lêerwysigingstye slegs as rowwe aanduidings van plaaslike skryfbewerkings wat met ander telemetrie gekorreleer moet word.<sup>[[5]](#references)[[6]](#references)</sup>

## Wat kan herwin word

Afhangend van wat opgehaal is en nog nie uitgewerp is nie, kan triage gekaste aanhegsels, media, URL’s en lêerhashes oplewer; die kas alleen bewys nie dat ’n item uitgelek is nie.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Aanhegsels en duimnaels waarna Discord CDN-URL’s verwys.
- Beelde, GIF’s en video’s (byvoorbeeld `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` en `.webm`).
- Webhook-URL’s soos `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API-oproepe soos `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-hashes van herwonne media om met bekende datastelle of intelligensievoere te vergelyk.<sup>[[1]](#references)[[2]](#references)</sup>

## Vinnige triage (handmatig)

- Gebruik grep op die kas om artefakte met ’n sterk sein te vind. Hierdie patrone weerspieël die URL-uitdrukkings van die parser waarna verwys word, en is triage-filters, nie volledige aanwysers nie.<sup>[[2]](#references)</sup>
  - Webhook-eindpunte:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Aanhegsel-/CDN-URL’s:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API-oproepe:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sorteer gekaste inskrywings volgens wysigingstyd om ’n rowwe volgorde saam te stel; mtime is ’n lêerstelselaanwyser en bepaal nie op sigself wanneer ’n Discord-objek opgehaal of gestuur is nie.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Ontleding van f_*-inskrywings (HTTP-liggaam + opskrifte)

In die blockfile-uitleg is `f_######`-lêers afsonderlike datastrome en is dit nie gewaarborg om met ’n volledige HTTP-antwoord te begin nie. As ’n verkrygde lêer wel geserialiseerde HTTP-opskrifte bevat, gevolg deur `\r\n\r\n`, verdeel dit by die eerste skeidingsteken en ondersoek die volgende:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Om die mediatipe af te lei
- Content-Location of X-Original-URL: Oorspronklike afgeleë URL vir voorskou/korrelasie
- Content-Encoding: Kan gzip/deflate/br (Brotli) wees.

Media kan dan onttrek word deur die opskrifte van die liggaam te skei en dit opsioneel volgens `Content-Encoding` te dekomprimeer; die parser waarna verwys word, hanteer Brotli, gzip en deflate. Ondersoek van magiese grepe is nuttig wanneer `Content-Type` ontbreek, maar bly ’n heuristiek.<sup>[[2]](#references)</sup>

## Outomatiese DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funksie: Skandeer Discord se kaslêergids rekursief, vind webhook-/API-/aanhegsel-URL’s, ontleed `f_*`-liggame, kerf opsioneel media uit en lewer HTML- en CSV-verslae plus ’n opsionele chronologiese tydlyn met SHA-256-hashes.<sup>[[1]](#references)[[2]](#references)</sup>

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

Die CLI definieer die volgende opsies en uitvoerlêername:<sup>[[2]](#references)</sup>
- --cache: Pad na die Discord Cache_Data-gids
- --format html|csv|both
- --timeline: Skep ’n geordende CSV-tydlyn (volgens gewysigde tyd)
- --extra: Skandeer ook Code Cache en GPUCache in dieselfde gids
- --carve: Carve media uit rou kasgrepe met behulp van herkende mediasignature (beelde/video)
- Uitvoer: `<output>.html`, `<output>.csv`, opsionele `<output>_timeline.csv`, en ’n `<output>_media`-gids met onttrekte of uitgekerfde lêers.

## Wenke vir ontleders

- Vergelyk die gewysigde tyd (mtime) van `f_*`- en `data_*`-lêers met gebruikers- of aanvalleraktiwiteitsvensters en onafhanklike telemetrie; mtime is nie ’n definitiewe gebeurtenistydstempel nie.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Bereken die hashes (SHA-256) van herstelde media en vergelyk dit met bekende kwaadwillige of data-eksfiltrasiedatastelle.<sup>[[1]](#references)[[2]](#references)</sup>
- Behandel onttrekte webhook-URL’s as geloofsbriewe. Moenie hulle bloot aanroep om te toets of hulle werk nie; bewaar hulle veilig, koördineer herroeping of rotasie, en gebruik verwante netwerktelemetrie vir terugwerkende soektogte.<sup>[[7]](#references)</sup>
- Uitwissing aan die bedienerkant waarborg nie dat plaaslik gekaste grepe vernietig is nie. Indien verkryging moontlik is, versamel die hele `Cache`-gids en verwante gidse op dieselfde vlak (`Code Cache`, `GPUCache`) voordat hulle verwyder word of die kas herskep word.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensiese Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensiese Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Hoe Discord miljoene gebruikers na 64-bis-argitektuur opgegradeer het](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [toepassing | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Skyfkas](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as ’n C2 en die gekaste bewyse wat agtergebly het](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Voer webhook uit](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
