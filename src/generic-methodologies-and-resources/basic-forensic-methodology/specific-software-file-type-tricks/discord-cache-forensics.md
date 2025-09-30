# Forenzika Discord keša (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica sažima kako trijagovati cache artefakte Discord Desktop-a da bi se povratili exfiltrated fajlovi, webhook endpoints i vremenske linije aktivnosti. Discord Desktop je Electron/Chromium aplikacija i koristi Chromium Simple Cache na disku.

## Gde tražiti (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Ključne strukture na disku unutar Cache_Data:
- index: Simple Cache index baza podataka
- data_#: Binarne cache blok datoteke koje mogu da sadrže više keširanih objekata
- f_######: Pojedinačni keširani unosi sačuvani kao zasebne datoteke (često veći sadržaji)

Napomena: Brisanje poruka/kanala/servera u Discord-u ne čisti ovaj lokalni keš. Keširani elementi često ostaju i njihovi vremenski pečati datoteka usklađeni su sa korisničkom aktivnošću, što omogućava rekonstrukciju vremenske linije.

## Šta se može povratiti

- Exfiltrated attachments and thumbnails fetched via cdn.discordapp.com/media.discordapp.net
- Slike, GIF-ovi, video zapisi (npr. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL-ovi (https://discord.com/api/webhooks/…)
- Discord API pozivi (https://discord.com/api/vX/…)
- Korisno za korelaciju beaconing/exfil aktivnosti i heširanje medija za intel matching

## Brza trijaža (ručno)

- Grep cache za artefakte visokog značaja:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortirajte keširane unose po vremenu izmene da napravite brzu vremensku liniju (mtime odražava kada je objekat upao u keš):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsiranje f_* unosa (HTTP telo + zaglavlja)

Fajlovi koji počinju sa f_ sadrže HTTP response headers praćene telom. Header blok obično završava sa \r\n\r\n. Korisna response headers uključuju:
- Content-Type: Da bi se naslutio tip medija
- Content-Location or X-Original-URL: Originalna udaljena URL za pregled/korelaciju
- Content-Encoding: Može biti gzip/deflate/br (Brotli)

Mediji se mogu izvući odvajanjem zaglavlja od tela i opciono dekompresovanjem prema Content-Encoding. Magic-byte sniffing je koristan kada Content-Type nedostaje.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Rekurzivno skenira Discord-ov cache folder, pronalazi webhook/API/attachment URL-ove, parsira f_* tela, opciono carve-uje medije, i ispisuje HTML + CSV timeline izveštaje sa SHA‑256 heševima.

Example CLI usage:
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
Ključne opcije:
- --cache: Putanja do Cache_Data
- --format html|csv|both
- --timeline: Generiši poredani CSV timeline (po vremenu izmene)
- --extra: Takođe skeniraj srodne Code Cache i GPUCache
- --carve: Carve media from raw bytes near regex hits (images/video)
- Output: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## Saveti analitičara

- Povežite vreme izmene (modified time / mtime) f_* i data_* fajlova sa periodima aktivnosti korisnika/napadača da biste rekonstruisali timeline.
- Izračunajte SHA-256 heš za povraćene medije i uporedite sa known-bad ili exfil dataset-ovima.
- Extracted webhook URLs mogu se testirati za liveness ili rotirati; razmislite o njihovom dodavanju na blocklists i retro-hunting proxies.
- Cache ostaje prisutan nakon “wiping”-a na serverskoj strani. Ako je moguća akvizicija, prikupite ceo Cache direktorijum i povezane sibling cache-ove (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
