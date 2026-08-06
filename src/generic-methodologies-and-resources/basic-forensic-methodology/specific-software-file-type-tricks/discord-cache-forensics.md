# Forenzika Discord Cache (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica sažima kako izvršiti trijažu Discord Desktop cache artefakata radi oporavka exfiltrated fajlova, webhook endpointa i vremenskih linija aktivnosti. Discord Desktop je Electron/Chromium aplikacija i koristi Chromium Simple Cache na disku.

## Gde tražiti (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Ključne strukture na disku unutar Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple Cache index baza podataka
- data_#: Binarni cache blok fajlovi koji mogu sadržati više cache objekata
- f_######: Pojedinačni cache unosi sačuvani kao zasebni fajlovi (često veća tela)

Napomena: Brisanje poruka/kanala/servera u Discordu ne uklanja ovaj lokalni cache. Cache stavke često ostaju, a vremenske oznake njihovih fajlova usklađene su sa aktivnošću korisnika, što omogućava rekonstrukciju vremenske linije.<sup>[[1]](#references)</sup>

## Šta se može oporaviti

- Exfiltrated prilozi i thumbnails preuzeti sa cdn.discordapp.com/media.discordapp.net
- Slike, GIF-ovi, video-zapisi (npr. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL-ovi (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API pozivi (https://discord.com/api/vX/…)
- Korisno za korelaciju beaconing/exfil aktivnosti i hashovanje medija radi intel podudaranja<sup>[[1]](#references)</sup>

## Brza trijaža (ručno)

- Pretražite cache za artefakte visoke signalne vrednosti:
- Webhook endpointi:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL-ovi:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API pozivi:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortirajte cache unose prema vremenu izmene da biste napravili brzu vremensku liniju (mtime odražava trenutak kada je objekat dospeo u cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsiranje f_* unosa (HTTP telo + zaglavlja)

Fajlovi koji počinju sa f_ sadrže HTTP response zaglavlja, a zatim telo. Blok zaglavlja se obično završava sa \r\n\r\n. Korisna response zaglavlja uključuju:
- Content-Type: Za određivanje tipa medija
- Content-Location ili X-Original-URL: Originalni remote URL za preview/korelaciju
- Content-Encoding: Može biti gzip/deflate/br (Brotli)

Mediji se mogu izdvojiti razdvajanjem zaglavlja od tela i opcionim decompress-ovanjem na osnovu Content-Encoding vrednosti. Prepoznavanje pomoću magic byte vrednosti korisno je kada Content-Type nije prisutan.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Funkcija: Rekurzivno skenira Discord cache folder, pronalazi webhook/API/attachment URL-ove, parsira f_* tela, opciono izdvaja medije i generiše HTML + CSV izveštaje vremenske linije sa SHA‑256 hash vrednostima.<sup>[[2]](#references)</sup>

Primer korišćenja CLI-ja:
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
- --timeline: Generiše uređenu CSV vremensku liniju (prema vremenu izmene)
- --extra: Takođe skenira susedne Code Cache i GPUCache
- --carve: Izdvaja medije iz sirovih bajtova u blizini regex pogodaka (slike/video)
- Izlaz: HTML izveštaj, CSV izveštaj, CSV vremenska linija i fascikla sa izdvojenim/ekstrahovanim medijima

## Saveti za analitičare

- Povežite vreme izmene (mtime) datoteka f_* i data_* sa vremenskim okvirima aktivnosti korisnika/napadača da biste rekonstruisali vremensku liniju.
- Hešujte oporavljene medije (SHA-256) i uporedite ih sa poznatim zlonamernim skupovima podataka ili skupovima podataka za exfil.
- Ekstrahovani webhook URL-ovi mogu se testirati radi provere dostupnosti ili rotirati; razmotrite njihovo dodavanje na blocklists i retroaktivni lov kroz proxy-je.
- Cache opstaje nakon „brisanja“ na serverskoj strani. Ako je akvizicija moguća, prikupite ceo Cache direktorijum i povezane susedne keš-eve (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Reference

- [1] [Discord kao C2 i keširani tragovi koji ostaju za sobom](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
