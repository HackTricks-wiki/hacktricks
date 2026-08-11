# Forensics cache Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona podsumowuje sposób przeprowadzania triage artefaktów cache Discord Desktop w celu znalezienia lokalnie cache'owanych mediów, endpointów webhooków i korelacji aktywności. Klient desktopowy Discord korzysta z Electron, a Electron przechowuje dane sesji, takie jak disk cache, w `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Gdzie szukać (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Są to domyślne ścieżki używane przez wskazany parser; Electron pozwala aplikacji nadpisać `sessionData`, dlatego podczas akwizycji należy potwierdzić rzeczywistą ścieżkę profilu.<sup>[[2]](#references)[[4]](#references)</sup>

Układ `index` + `data_#` + `f_######` odpowiada backendowi blockfile disk-cache Chromium; nie należy oznaczać go jako Simple Cache bez zweryfikowania backendu, ponieważ Chromium dokumentuje odrębne implementacje cache.<sup>[[5]](#references)</sup>

Kluczowe struktury na dysku wewnątrz `Cache_Data`:
- `index`: Indeks cache Blockfile używany do lokalizowania wpisów.
- `data_#`: Pliki bloków o stałym rozmiarze, które mogą zawierać metadane cache, nagłówki HTTP i dane odpowiedzi.
- `f_######`: Oddzielne pliki używane dla danych większych niż limit pliku blokowego; zawierają zapisane dane bez nagłówków pliku blokowego.

Usunięcie wiadomości, kanałów lub serwerów nie gwarantuje usunięcia bajtów, które zostały już lokalnie zapisane w cache, ale Chromium może w dowolnym momencie usuwać lub ponownie tworzyć pliki cache. Ocalałe artefakty należy traktować jako dowody opportunistic, a czasy modyfikacji plików wykorzystywać wyłącznie jako przybliżone sygnały lokalnego zapisu, które muszą zostać skorelowane z inną telemetrią.<sup>[[5]](#references)[[6]](#references)</sup>

## Co można odzyskać

W zależności od tego, co zostało pobrane i nie zostało jeszcze usunięte z cache, triage może ujawnić cache'owane załączniki, media, URL-e i hashe plików; sam cache nie dowodzi, że dany element został eksfiltrowany.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Załączniki i miniatury wskazywane przez URL-e Discord CDN.
- Obrazy, GIF-y i filmy (na przykład `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` i `.webm`).
- URL-e webhooków, takie jak `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Wywołania Discord API, takie jak `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hashe SHA-256 odzyskanych mediów do porównania ze znanymi datasetami lub feedami intelligence.<sup>[[1]](#references)[[2]](#references)</sup>

## Szybki triage (manualny)

- Przeszukaj cache pod kątem artefaktów o wysokiej wartości sygnałowej. Wzorce te odzwierciedlają wyrażenia URL używane przez wskazany parser i są filtrami triage, a nie wyczerpującymi wskaźnikami.<sup>[[2]](#references)</sup>
- Endpointy webhooków:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL-e załączników/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Wywołania Discord API:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Posortuj cache'owane wpisy według czasu modyfikacji, aby zbudować przybliżoną sekwencję; mtime jest sygnałem systemu plików i sam w sobie nie ustala, kiedy obiekt Discord został pobrany lub wysłany.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsowanie wpisów f_* (HTTP body + headers)

W układzie blockfile pliki `f_######` są oddzielnymi strumieniami danych i nie ma gwarancji, że zaczynają się od kompletnej odpowiedzi HTTP. Jeśli pozyskany plik zawiera serializowane nagłówki HTTP, po których występuje `\r\n\r\n`, podziel go przy pierwszym delimiterze i przeanalizuj:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Aby określić typ mediów
- Content-Location lub X-Original-URL: Oryginalny zdalny URL do podglądu/korelacji
- Content-Encoding: Może mieć wartość gzip/deflate/br (Brotli).

Media można następnie wyodrębnić, oddzielając nagłówki od body i opcjonalnie dekompresując je zgodnie z `Content-Encoding`; wskazany parser obsługuje Brotli, gzip i deflate. Rozpoznawanie na podstawie magic bytes jest przydatne, gdy `Content-Type` nie występuje, ale nadal pozostaje heurystyką.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funkcja: Rekurencyjnie skanuje folder cache Discord, wyszukuje URL-e webhooków/API/załączników, parsuje body `f_*`, opcjonalnie carves media oraz generuje raporty HTML i CSV, a także opcjonalną chronologiczną timeline z hashami SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Przykładowe użycie CLI:
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
CLI definiuje następujące opcje i nazwy wyników:<sup>[[2]](#references)</sup>
- --cache: Ścieżka do katalogu Discord Cache_Data
- --format html|csv|both
- --timeline: Generuje uporządkowaną oś czasu CSV (według czasu modyfikacji)
- --extra: Skanuje również sąsiednie katalogi Code Cache i GPUCache
- --carve: Wydobywa multimedia z surowych bajtów cache przy użyciu rozpoznanych sygnatur multimediów (obrazy/wideo)
- Wynik: `<output>.html`, `<output>.csv`, opcjonalnie `<output>_timeline.csv` oraz folder `<output>_media` z wyodrębnionymi lub wydobytymi plikami.

## Wskazówki dla analityków

- Koreluj czas modyfikacji (mtime) plików `f_*` i `data_*` z oknami aktywności użytkownika lub atakującego oraz niezależną telemetrią; mtime nie jest definitywnym znacznikiem czasu zdarzenia.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Obliczaj hash odzyskanych multimediów (SHA-256) i porównuj je ze znanymi szkodliwymi zbiorami danych lub zbiorami danych dotyczących exfiltracji.<sup>[[1]](#references)[[2]](#references)</sup>
- Traktuj wyodrębnione webhook URLs jak dane uwierzytelniające. Nie wywołuj ich wyłącznie w celu sprawdzenia dostępności; zabezpiecz je, skoordynuj ich unieważnienie lub rotację i wykorzystaj powiązaną telemetrię sieciową do retro-huntingu.<sup>[[7]](#references)</sup>
- Usunięcie po stronie serwera nie gwarantuje zniszczenia lokalnie zapisanych w cache bajtów. Jeśli pozyskanie jest możliwe, zbierz cały katalog `Cache` oraz powiązane sąsiednie cache (`Code Cache`, `GPUCache`) przed ich usunięciem lub ponownym utworzeniem cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Jak Discord płynnie zaktualizował miliony użytkowników do architektury 64-bitowej](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord jako C2 i pozostawione dowody w cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
