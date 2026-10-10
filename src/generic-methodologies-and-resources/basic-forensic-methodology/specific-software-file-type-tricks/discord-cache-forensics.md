# Forenzika Discord Cache-a (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica sažima kako obaviti trijažu artefakata iz Discord Desktop cache-a radi pronalaženja lokalno keširanih medija, webhook endpoint-a i korelacije aktivnosti. Discord desktop klijent koristi Electron, a Electron čuva podatke sesije, kao što je disk cache, u direktorijumu `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Gde tražiti (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Ovo su podrazumevane putanje koje koristi navedeni parser; Electron aplikacijama omogućava da izmene `sessionData`, zato tokom preuzimanja podataka potvrdite stvarnu putanju profila.<sup>[[2]](#references)[[4]](#references)</sup>

Raspored `index` + `data_#` + `f_######` odgovara Chromium blockfile pozadinskom mehanizmu za disk cache; nemojte ga označiti kao Simple Cache bez provere pozadinskog mehanizma, jer Chromium dokumentuje različite implementacije cache-a.<sup>[[5]](#references)</sup>

Ključne strukture na disku unutar `Cache_Data`:
- `index`: Indeks Blockfile cache-a koji se koristi za pronalaženje unosa.
- `data_#`: Datoteke blokova fiksne veličine koje mogu sadržati metapodatke cache-a, HTTP zaglavlja i podatke odgovora.
- `f_######`: Odvojene datoteke koje se koriste za podatke veće od ograničenja veličine datoteka blokova; sadrže sačuvane podatke bez zaglavlja datoteka blokova.

Brisanje poruka, kanala ili servera ne garantuje uklanjanje bajtova koji su već lokalno keširani, ali Chromium može u bilo kom trenutku da izbaci ili ponovo kreira datoteke cache-a. Preostale artefakte tretirajte kao potencijalne dokaze, a vremena izmene datoteka koristite samo kao grube pokazatelje lokalnog upisa koje treba korelisati sa drugim telemetrijskim podacima.<sup>[[5]](#references)[[6]](#references)</sup>

## Šta se može oporaviti

U zavisnosti od toga šta je preuzeto, a još nije izbačeno iz cache-a, trijažom se mogu oporaviti keširani prilozi, mediji, URL-ovi i hash vrednosti datoteka; sam cache ne dokazuje da je neka stavka eksfiltrirana.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Prilozi i sličice na koje upućuju Discord CDN URL-ovi.
- Slike, GIF-ovi i video-snimci (na primer, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` i `.webm`).
- Webhook URL-ovi kao što je `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API pozivi kao što je `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hash vrednosti oporavljenih medija radi poređenja sa poznatim skupovima podataka ili obaveštajnim izvorima.<sup>[[1]](#references)[[2]](#references)</sup>

## Brza trijaža (ručno)

- Pretražite cache u potrazi za artefaktima visoke pouzdanosti. Ovi obrasci odgovaraju URL izrazima navedenog parsera i predstavljaju filtere za trijažu, a ne iscrpne indikatore.<sup>[[2]](#references)</sup>
  - Webhook endpoint-i:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL-ovi priloga/CDN-a:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API pozivi:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortirajte keširane unose prema vremenu izmene da biste napravili grubi redosled; mtime je signal iz sistema datoteka i sam po sebi ne utvrđuje kada je Discord objekat preuzet ili poslat.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsiranje unosa f_* (HTTP telo + zaglavlja)

U blockfile rasporedu, datoteke `f_######` predstavljaju odvojene tokove podataka i ne mora se očekivati da počinju kompletnim HTTP odgovorom. Ako preuzeta datoteka sadrži serijalizovana HTTP zaglavlja iza kojih sledi `\r\n\r\n`, podelite sadržaj na prvom graničniku i pregledajte:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Za procenu tipa medija
- Content-Location ili X-Original-URL: Originalni udaljeni URL za pregled/korelaciju
- Content-Encoding: Može biti gzip/deflate/br (Brotli).

Mediji se zatim mogu izdvojiti odvajanjem zaglavlja od tela i, po potrebi, dekompresijom prema `Content-Encoding`; navedeni parser podržava Brotli, gzip i deflate. Provera magic byte vrednosti korisna je kada `Content-Type` nedostaje, ali ostaje heuristička metoda.<sup>[[2]](#references)</sup>

## Automatizovani DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funkcija: Rekurzivno skenira Discord cache direktorijum, pronalazi webhook/API/attachment URL-ove, parsira tela `f_*` datoteka, po izboru izdvaja medije i pravi HTML i CSV izveštaje, kao i opcionu hronološku vremensku liniju sa SHA-256 hash vrednostima.<sup>[[1]](#references)[[2]](#references)</sup>

Primer upotrebe CLI-ja:

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

CLI definiše ove opcije i nazive izlaznih datoteka:<sup>[[2]](#references)</sup>
- --cache: Putanja do Discord direktorijuma Cache_Data
- --format html|csv|both
- --timeline: Generiše uređenu CSV vremensku liniju (prema vremenu izmene)
- --extra: Skenira i susedne direktorijume Code Cache i GPUCache
- --carve: Izdvaja medije iz sirovih bajtova keša pomoću prepoznatih potpisa medijskih datoteka (slike/video)
- Izlaz: `<output>.html`, `<output>.csv`, opcionalni `<output>_timeline.csv` i fascikla `<output>_media` sa izdvojenim ili izrezbarenim datotekama.

## Saveti za analitičare

- Uporedite vreme izmene (mtime) datoteka `f_*` i `data_*` sa periodima aktivnosti korisnika ili napadača i nezavisnom telemetrijom; mtime nije pouzdana vremenska oznaka događaja.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Izračunajte hash oporavljenih medija (SHA-256) i uporedite ga sa poznatim zlonamernim skupovima podataka ili skupovima podataka o eksfiltraciji.<sup>[[1]](#references)[[2]](#references)</sup>
- Tretirajte izdvojene URL-ove webhookova kao akreditive. Nemojte ih pozivati samo da biste proverili da li su aktivni; bezbedno ih sačuvajte, koordinirajte njihovo opozivanje ili rotaciju i koristite povezanu mrežnu telemetriju za retroaktivnu potragu.<sup>[[7]](#references)</sup>
- Brisanje na strani servera ne garantuje uništenje lokalno keširanih bajtova. Ako je moguće prikupljanje, pre uklanjanja ili ponovnog kreiranja keša prikupite ceo direktorijum `Cache` i povezane susedne keševe (`Code Cache`, `GPUCache`).<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Kako je Discord neprimetno nadogradio milione korisnika na 64-bitnu arhitekturu](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [Aplikacija | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Keš diska](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord kao C2 i keširani dokazi koji ostaju](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – izvršavanje Webhooka](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
