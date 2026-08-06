# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy som op hoe om Discord Desktop-cache-artefakte te triageer om geëksfiltreerde lêers, webhook-endpunte en aktiwiteitstydlyne te herwin. Discord Desktop is ’n Electron/Chromium-toepassing en gebruik Chromium Simple Cache op skyf.

## Waar om te kyk (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Belangrike on-skyf-strukture binne Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple Cache-indeksdatabasis
- data_#: Binêre cache-bloklêers wat veelvuldige gekaste objekte kan bevat
- f_######: Individuele gekaste inskrywings wat as selfstandige lêers gestoor word (dikwels groter liggame)

Nota: Die uitvee van boodskappe/kanale/bedieners in Discord verwyder nie hierdie plaaslike cache nie. Gekaste items bly dikwels bestaan, en hul lêertydstempels stem ooreen met gebruikersaktiwiteit, wat die rekonstruksie van ’n tydlyn moontlik maak.<sup>[[1]](#references)</sup>

## Wat herwin kan word

- Geëksfiltreerde aanhangsels en duimnaels wat via cdn.discordapp.com/media.discordapp.net verkry is
- Beelde, GIF’s, video’s (bv. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook-URL’s (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API-oproepe (https://discord.com/api/vX/…)
- Nuttig om beaconing-/exfil-aktiwiteit te korreleer en media te hash vir intel-ooreenstemming<sup>[[1]](#references)</sup>

## Vinnige triage (handmatig)

- Grep die cache vir artefakte met ’n hoë seinwaarde:
- Webhook-endpunte:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Aanhangsel-/CDN-URL’s:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API-oproepe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sorteer gekaste inskrywings volgens wysigingstyd om ’n vinnige tydlyn te bou (mtime weerspieël wanneer die objek in die cache beland het):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Ontleding van f_*-inskrywings (HTTP-liggaam + headers)

Lêers wat met f_ begin, bevat HTTP-response-headers gevolg deur die liggaam. Die header-blok eindig gewoonlik met \r\n\r\n. Nuttige response-headers sluit in:
- Content-Type: Om die mediatip af te lei
- Content-Location of X-Original-URL: Oorspronklike afgeleë URL vir voorskou/korrelasie
- Content-Encoding: Kan gzip/deflate/br (Brotli) wees

Media kan onttrek word deur headers van die liggaam te skei en dit opsioneel volgens Content-Encoding te dekomprimeer. Magic-byte-snuffeling is nuttig wanneer Content-Type ontbreek.

## Geoutomatiseerde DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Funksie: Skandeer Discord se cache-lêergids rekursief, vind webhook-/API-/aanhangsel-URL’s, ontleed f_*-liggame, carve opsioneel media, en lewer HTML + CSV-tydlynverslae met SHA-256-hashes.<sup>[[2]](#references)</sup>

Voorbeeld van CLI-gebruik:
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
Key options:
- --cache: Pad na Cache_Data
- --format html|csv|both
- --timeline: Genereer geordende CSV-tydlyn (volgens wysigingstyd)
- --extra: Skandeer ook naburige Code Cache en GPUCache
- --carve: Sny media uit rou grepe naby regex-treffers (beelde/video)
- Output: HTML-verslag, CSV-verslag, CSV-tydlyn en ’n media-lêergids met uitgesnyde/onttrekte lêers

## Wenke vir ontleders

- Korreleer die wysigingstyd (mtime) van f_*- en data_*-lêers met gebruiker-/aanvalleraktiwiteitsvensters om ’n tydlyn te rekonstrueer.
- Hash herwonne media (SHA-256) en vergelyk dit met bekende-slegte of exfil-datastelle.
- Onttrekte webhook-URL’s kan vir lewensvatbaarheid getoets of geroteer word; oorweeg dit om hulle by bloklyste te voeg en retro-jag op proxies uit te voer.
- Cache bly bestaan ná “uitvee” aan die bedienerkant. Indien verkryging moontlik is, versamel die volledige Cache-gids en verwante naburige caches (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Discord as ’n C2 en die gekaste bewys wat agterbly](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
