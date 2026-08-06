# Forensiese ondersoek van Discord Cache (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy som op hoe om Discord Desktop-cache-artefakte te triageer om geëksfiltreerde lêers, webhook-endpoints en aktiwiteitstydlyne te herwin. Discord Desktop is 'n Electron/Chromium-toepassing en gebruik Chromium Simple Cache op die skyf.

## Waar om te kyk (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Belangrike datastrukture op die skyf binne Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple Cache-indeksdatabasis
- data_#: Binêre cache-bloklêers wat verskeie cache-objekte kan bevat
- f_######: Individuele cache-inskrywings wat as selfstandige lêers gestoor word (dikwels groter bodies)

Nota: Die verwydering van boodskappe/kanale/servers in Discord vee nie hierdie plaaslike cache uit nie. Cache-items bly dikwels behoue, en hul lêertydstempels stem ooreen met gebruikeraktiwiteit, wat die rekonstruksie van 'n tydlyn moontlik maak.<sup>[[1]](#references)</sup>

## Wat herwin kan word

- Geëksfiltreerde aanhegsels en thumbnails wat via cdn.discordapp.com/media.discordapp.net verkry is
- Images, GIFs, videos (bv. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- Nuttig om beaconing-/exfil-aktiwiteit te korreleer en media vir intel matching te hasj<sup>[[1]](#references)</sup>

## Vinnige triage (manual)

- Grep die cache vir artefakte met 'n hoë seinwaarde:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sorteer cache-inskrywings volgens wysigingstyd om 'n vinnige tydlyn te bou (mtime weerspieël wanneer die objek die cache bereik het):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Ontleding van f_*-inskrywings (HTTP body + headers)

Lêers wat met f_ begin, bevat HTTP response headers gevolg deur die body. Die header-blok eindig tipies met \r\n\r\n. Nuttige response headers sluit in:
- Content-Type: Om die mediatype af te lei
- Content-Location of X-Original-URL: Oorspronklike remote URL vir preview/korrelasie
- Content-Encoding: Kan gzip/deflate/br (Brotli) wees

Media kan onttrek word deur headers van die body te skei en dit opsioneel te dekomprimeer volgens Content-Encoding. Magic-byte sniffing is nuttig wanneer Content-Type ontbreek.

## Geoutomatiseerde DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Funksie: Skandeer Discord se cache-lêer recursively, vind webhook/API/attachment URLs, ontleed f_*-bodies, carve opsioneel media, en lewer HTML + CSV-tydlynverslae met SHA-256-hashes.<sup>[[2]](#references)</sup>

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
Sleutelopsies:
- --cache: Pad na Cache_Data
- --format html|csv|both
- --timeline: Genereer 'n geordende CSV-tydlyn (volgens gewysigde tyd)
- --extra: Skandeer ook naburige Code Cache en GPUCache
- --carve: Carve media uit rou grepe naby regex-treffers (beelde/video)
- Uitset: HTML-verslag, CSV-verslag, CSV-tydlyn en 'n medialêergids met gecarvde/onttrekte lêers

## Wenke vir ontleders

- Korrelleer die gewysigde tyd (mtime) van f_* en data_*-lêers met gebruiker-/aanvalleraktiwiteitsvensters om 'n tydlyn te rekonstrueer.
- Hash herwonne media (SHA-256) en vergelyk dit met bekende kwaadwillige of geëksfiltreerde datastelle.
- Onttrekte webhook-URL's kan vir lewendigheid getoets of geroteer word; oorweeg dit om hulle by bloklyste te voeg en gevolmagtigdes met terugwerkende soektogte te ondersoek.
- Cache bly voortbestaan nadat dit aan die “bedienerkant” uitgevee is. Indien verkryging moontlik is, versamel die volledige Cache-gids en verwante naburige caches (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Discord as 'n C2 en die gekaste bewyse wat agtergebly het](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
