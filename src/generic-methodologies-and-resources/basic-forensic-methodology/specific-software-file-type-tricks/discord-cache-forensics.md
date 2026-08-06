# Forenzika Discord Cache (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica sažima kako izvršiti trijažu Discord Desktop cache artefakata radi oporavka exfiltrated fajlova, webhook endpointa i vremenskih linija aktivnosti. Discord Desktop je Electron/Chromium aplikacija i koristi Chromium Simple Cache na disku.

## Gde tražiti (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Ključne strukture na disku unutar Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple Cache index baza podataka
- data_#: Binarni cache block fajlovi koji mogu sadržati više keširanih objekata
- f_######: Pojedinačni keširani unosi sačuvani kao standalone fajlovi (često sa većim sadržajem)

Napomena: Brisanje poruka/kanala/servera u Discordu ne uklanja ovaj lokalni cache. Keširane stavke često ostaju, a vremenske oznake njihovih fajlova odgovaraju aktivnosti korisnika, što omogućava rekonstrukciju vremenske linije.<sup>[[1]](#references)</sup>

## Šta se može oporaviti

- Exfiltrated attachmenti i thumbnails preuzeti sa cdn.discordapp.com/media.discordapp.net
- Slike, GIF-ovi, video-snimci (npr. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL-ovi (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API pozivi (https://discord.com/api/vX/…)
- Korisno za korelaciju beaconing/exfil aktivnosti i hashovanje medija radi intel matchinga<sup>[[1]](#references)</sup>

## Brza trijaža (ručno)

- Pretražite cache radi pronalaženja artefakata visoke vrednosti:
- Webhook endpointi:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL-ovi:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API pozivi:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortirajte keširane unose prema vremenu izmene da biste napravili brzu vremensku liniju (mtime odražava trenutak kada je objekat dospeo u cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsiranje f_* unosa (HTTP body + headers)

Fajlovi koji počinju sa f_ sadrže HTTP response headers nakon kojih sledi body. Blok zaglavlja se obično završava sa \r\n\r\n. Korisna response headers uključuju:
- Content-Type: Za određivanje tipa medija
- Content-Location ili X-Original-URL: Originalni remote URL za pregled/korelaciju
- Content-Encoding: Može biti gzip/deflate/br (Brotli)

Mediji se mogu izdvojiti razdvajanjem headers od body-ja i opcionim decompressing-om na osnovu Content-Encoding. Detekcija magic bytes je korisna kada Content-Type nije prisutan.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Funkcija: Rekurzivno skenira Discord-ov cache folder, pronalazi webhook/API/attachment URL-ove, parsira f_* body-je, opciono vrši carving medija i generiše HTML + CSV izveštaje vremenske linije sa SHA‑256 hash-evima.<sup>[[2]](#references)</sup>

Primer CLI upotrebe:
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
- --extra: Takođe skenira susedne Code Cache i GPUCache direktorijume
- --carve: Izdvaja medije iz sirovih bajtova u blizini regex podudaranja (slike/video)
- Izlaz: HTML izveštaj, CSV izveštaj, CSV vremenska linija i folder sa izdvojenim/ekstrahovanim medijima

## Saveti za analitičare

- Povežite vreme izmene (mtime) fajlova f_* i data_* sa periodima aktivnosti korisnika/napadača da biste rekonstruisali vremensku liniju.
- Hashujte pronađene medije (SHA-256) i uporedite ih sa poznatim malicioznim ili exfil skupovima podataka.
- Ekstrahovani webhook URL-ovi mogu se testirati radi provere dostupnosti ili rotirati; razmotrite njihovo dodavanje na blockliste i retroaktivni lov kroz proxy-je.
- Cache ostaje sačuvan nakon „brisanja“ na serverskoj strani. Ako je akvizicija moguća, prikupite ceo Cache direktorijum i povezane susedne cache-ove (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Reference

- [1] [Discord kao C2 i keširani tragovi koji ostaju iza njega](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
