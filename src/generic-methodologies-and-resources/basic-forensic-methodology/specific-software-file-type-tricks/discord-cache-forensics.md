# Forenzika Discord cache-a (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica sažima kako izvršiti trijažu Discord Desktop cache artefakata za lokalno keširane medije, webhook endpoint-e i korelaciju aktivnosti. Discord desktop klijent koristi Electron, a Electron skladišti podatke sesije, kao što je disk cache, u okviru `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Gde tražiti (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Ovo su podrazumevane putanje koje koristi navedeni parser; Electron omogućava aplikaciji da zameni `sessionData`, zato tokom akvizicije potvrdite stvarnu putanju profila.<sup>[[2]](#references)[[4]](#references)</sup>

Raspored `index` + `data_#` + `f_######` odgovara Chromium-ovom blockfile disk-cache backend-u; nemojte ga označavati kao Simple Cache bez provere backend-a, jer Chromium dokumentuje različite implementacije cache-a.<sup>[[5]](#references)</sup>

Ključne strukture na disku unutar `Cache_Data`:
- `index`: Blockfile cache indeks koji se koristi za pronalaženje unosa.
- `data_#`: Fajlovi blokova fiksne veličine koji mogu sadržati cache metapodatke, HTTP zaglavlja i podatke odgovora.
- `f_######`: Zasebni fajlovi koji se koriste za podatke veće od ograničenja block-file-a; ovi fajlovi sadrže sačuvane podatke bez block-file zaglavlja.

Brisanje poruka, kanala ili servera ne garantuje uklanjanje bajtova koji su već lokalno keširani, ali Chromium u svakom trenutku može izbaciti ili ponovo kreirati cache fajlove. Preživele artefakte tretirajte kao oportunističke dokaze, a vremena izmene fajlova koristite samo kao grube signale lokalnog upisa koji moraju biti korelisani sa drugom telemetrijom.<sup>[[5]](#references)[[6]](#references)</sup>

## Šta se može povratiti

U zavisnosti od toga šta je preuzeto i još nije izbačeno iz cache-a, trijažom se mogu povratiti keširani attachment-i, mediji, URL-ovi i hash-evi fajlova; sam cache ne dokazuje da je stavka eksfiltrirana.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachment-i i thumbnail-ovi na koje upućuju Discord CDN URL-ovi.
- Slike, GIF-ovi i video-zapisi (na primer, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` i `.webm`).
- Webhook URL-ovi kao što je `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API pozivi kao što je `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hash-evi povraćenih medija za poređenje sa poznatim skupovima podataka ili intelligence feed-ovima.<sup>[[1]](#references)[[2]](#references)</sup>

## Brza trijaža (ručna)

- Pretražite cache u potrazi za artefaktima visoke indikativnosti. Ovi obrasci odgovaraju izrazima za URL-ove u navedenom parser-u i predstavljaju filtere za trijažu, a ne iscrpne indikatore.<sup>[[2]](#references)</sup>
- Webhook endpoint-i:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL-ovi:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API pozivi:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortirajte keširane unose prema vremenu izmene da biste izgradili grubu sekvencu; mtime je signal sistema datoteka i sam po sebi ne utvrđuje kada je Discord objekat preuzet ili poslat.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsiranje f_* unosa (HTTP telo + zaglavlja)

U blockfile rasporedu, `f_######` fajlovi su zasebni tokovi podataka i nije garantovano da počinju potpunim HTTP odgovorom. Ako akvizirani fajl sadrži serijalizovana HTTP zaglavlja praćena sa `\r\n\r\n`, razdvojte ih na prvom delimiteru i pregledajte:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Za utvrđivanje tipa medija
- Content-Location ili X-Original-URL: Originalni udaljeni URL za pregled/korelaciju
- Content-Encoding: Može biti gzip/deflate/br (Brotli).

Mediji se zatim mogu ekstrahovati razdvajanjem zaglavlja od tela i opcionim dekompresovanjem u skladu sa `Content-Encoding`; navedeni parser obrađuje Brotli, gzip i deflate. Detekcija na osnovu magic-byte vrednosti korisna je kada `Content-Type` nije prisutan, ali i dalje predstavlja heuristiku.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funkcija: Rekurzivno skenira Discord cache folder, pronalazi webhook/API/attachment URL-ove, parsira `f_*` tela, opciono izdvaja medije i generiše HTML i CSV izveštaje, kao i opcionu hronološku vremensku liniju sa SHA-256 hash-evima.<sup>[[1]](#references)[[2]](#references)</sup>

Primer CLI upotrebe:
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
CLI definiše sledeće opcije i nazive izlaznih datoteka:<sup>[[2]](#references)</sup>
- --cache: Putanja do Discord Cache_Data direktorijuma
- --format html|csv|both
- --timeline: Generiše uređenu CSV vremensku liniju (prema vremenu izmene)
- --extra: Takođe skenira susedne Code Cache i GPUCache direktorijume
- --carve: Izdvaja media podatke iz sirovih bajtova cache-a koristeći prepoznate media potpise (slike/video)
- Output: `<output>.html`, `<output>.csv`, opciono `<output>_timeline.csv` i `<output>_media` folder sa ekstrahovanim ili izdvojenim datotekama.

## Saveti za analitičare

- Povežite vreme izmene (mtime) datoteka `f_*` i `data_*` sa periodima aktivnosti korisnika ili napadača i nezavisnom telemetrijom; mtime nije konačna vremenska oznaka događaja.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Izračunajte hash oporavljenih media datoteka (SHA-256) i uporedite ga sa poznatim zlonamernim ili exfiltration datasetovima.<sup>[[1]](#references)[[2]](#references)</sup>
- Tretirajte ekstrahovane webhook URL-ove kao credentials. Nemojte ih pozivati samo radi testiranja dostupnosti; bezbedno ih sačuvajte, koordinirajte revokaciju ili rotaciju i koristite povezanu network telemetriju za retro-hunting.<sup>[[7]](#references)</sup>
- Brisanje na serveru ne garantuje da su lokalni keširani bajtovi uništeni. Ako je acquisition moguć, prikupite ceo `Cache` direktorijum i povezane susedne cache-ove (`Code Cache`, `GPUCache`) pre eviction-a ili ponovnog kreiranja cache-a.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Kako je Discord neprimetno nadogradio milione korisnika na 64-bitnu arhitekturu](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord kao C2 i keširani dokazi koji ostaju iza njega](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
