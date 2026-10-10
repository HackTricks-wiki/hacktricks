# Analiza cache Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona zawiera podsumowanie sposobu wstępnej analizy artefaktów cache Discord Desktop w celu znalezienia lokalnie buforowanych multimediów, endpointów webhooków i korelacji aktywności. Klient desktopowy Discorda korzysta z Electron, który przechowuje dane sesji, takie jak cache dyskowy, w `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Gdzie szukać (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Są to domyślne ścieżki używane przez parser, do którego odwołuje się ten dokument; Electron pozwala aplikacji zmienić `sessionData`, dlatego podczas pozyskiwania danych potwierdź rzeczywistą ścieżkę profilu.<sup>[[2]](#references)[[4]](#references)</sup>

Układ `index` + `data_#` + `f_######` odpowiada backendowi blockfile disk cache Chromium; nie klasyfikuj go jako Simple Cache bez sprawdzenia backendu, ponieważ Chromium dokumentuje odrębne implementacje cache.<sup>[[5]](#references)</sup>

Kluczowe struktury na dysku w `Cache_Data`:
- `index`: Indeks cache Blockfile używany do lokalizowania wpisów.
- `data_#`: Pliki bloków o stałym rozmiarze, które mogą zawierać metadane cache, nagłówki HTTP i dane odpowiedzi.
- `f_######`: Oddzielne pliki używane dla danych większych niż limit pliku bloków; zawierają zapisane dane bez nagłówków pliku bloków.

Usunięcie wiadomości, kanałów lub serwerów nie gwarantuje usunięcia bajtów, które zostały już lokalnie zbuforowane, ale Chromium może w dowolnej chwili usunąć lub ponownie utworzyć pliki cache. Traktuj zachowane artefakty jako dowody dostępne przypadkowo, a czas modyfikacji pliku wykorzystuj jedynie jako przybliżony sygnał lokalnego zapisu, który należy skorelować z innymi danymi telemetrycznymi.<sup>[[5]](#references)[[6]](#references)</sup>

## Co można odzyskać

W zależności od tego, co zostało pobrane i nie zostało jeszcze usunięte z cache, wstępna analiza może pozwolić odzyskać buforowane załączniki, multimedia, URL-e i hashe plików; sam cache nie dowodzi, że dany element został eksfiltrowany.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Załączniki i miniatury wskazywane przez URL-e CDN Discorda.
- Obrazy, GIF-y i filmy (na przykład `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` i `.webm`).
- URL-e webhooków, takie jak `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Wywołania API Discorda, takie jak `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hashe SHA-256 odzyskanych multimediów do porównania ze znanymi zbiorami danych lub źródłami informacji wywiadowczych.<sup>[[1]](#references)[[2]](#references)</sup>

## Szybka wstępna analiza (ręczna)

- Wyszukaj w cache artefakty o wysokiej wartości diagnostycznej. Te wzorce odpowiadają wyrażeniom URL używanym przez parser, do którego odwołuje się ten dokument; służą do filtrowania podczas wstępnej analizy i nie obejmują wszystkich wskaźników.<sup>[[2]](#references)</sup>
  - Endpointy webhooków:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL-e załączników/CDN:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Wywołania API Discorda:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Posortuj wpisy cache według czasu modyfikacji, aby uzyskać przybliżoną sekwencję; mtime jest sygnałem pochodzącym z systemu plików i sam w sobie nie określa, kiedy obiekt Discorda został pobrany lub wysłany.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analiza wpisów f_* (treść HTTP + nagłówki)

W układzie blockfile pliki `f_######` są oddzielnymi strumieniami danych i nie muszą zaczynać się od pełnej odpowiedzi HTTP. Jeśli pozyskany plik zawiera serializowane nagłówki HTTP, po których występuje `\r\n\r\n`, podziel go przy pierwszym separatorze i sprawdź:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Pozwala określić typ multimediów
- Content-Location lub X-Original-URL: Oryginalny zdalny URL do podglądu/korelacji
- Content-Encoding: Może mieć wartość gzip/deflate/br (Brotli).

Następnie można wyodrębnić multimedia, oddzielając nagłówki od treści i opcjonalnie dekompresując je zgodnie z `Content-Encoding`; parser, do którego odwołuje się ten dokument, obsługuje Brotli, gzip i deflate. Rozpoznawanie na podstawie sygnatur bajtowych jest przydatne, gdy brakuje `Content-Type`, ale nadal pozostaje metodą heurystyczną.<sup>[[2]](#references)</sup>

## Zautomatyzowane DFIR: Discord Forensic Suite (CLI/GUI)

- Repozytorium: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funkcja: Rekurencyjnie skanuje folder cache Discorda, wyszukuje URL-e webhooków/API/załączników, analizuje treść `f_*`, opcjonalnie odzyskuje multimedia i generuje raporty HTML oraz CSV, a także opcjonalną chronologiczną oś czasu z hashami SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

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

CLI definiuje następujące opcje i nazwy plików wyjściowych:<sup>[[2]](#references)</sup>
- --cache: Ścieżka do katalogu Discord Cache_Data
- --format html|csv|both
- --timeline: Generuje uporządkowaną oś czasu w formacie CSV (według czasu modyfikacji)
- --extra: Skanuje również sąsiednie katalogi Code Cache i GPUCache
- --carve: Odzyskuje pliki multimedialne z surowych bajtów cache przy użyciu rozpoznanych sygnatur plików multimedialnych (obrazy/wideo)
- Wynik: `<output>.html`, `<output>.csv`, opcjonalnie `<output>_timeline.csv` oraz folder `<output>_media` z wyodrębnionymi lub odzyskanymi plikami.

## Wskazówki dla analityków

- Porównaj czasy modyfikacji (mtime) plików `f_*` i `data_*` z okresami aktywności użytkownika lub atakującego oraz niezależną telemetrią; mtime nie jest rozstrzygającym znacznikiem czasu zdarzenia.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Oblicz skróty odzyskanych plików multimedialnych (SHA-256) i porównaj je ze znanymi złośliwymi zbiorami danych lub zbiorami dotyczącymi eksfiltracji.<sup>[[1]](#references)[[2]](#references)</sup>
- Traktuj wyodrębnione adresy URL webhooków jak dane uwierzytelniające. Nie wywołuj ich wyłącznie po to, by sprawdzić, czy działają; przechowuj je w bezpieczny sposób, skoordynuj ich unieważnienie lub rotację, a do retro-huntingu wykorzystaj powiązaną telemetrię sieciową.<sup>[[7]](#references)</sup>
- Usunięcie danych po stronie serwera nie gwarantuje zniszczenia lokalnych bajtów z cache. Jeśli pozyskanie danych jest możliwe, skopiuj cały katalog `Cache` oraz powiązane sąsiednie cache (`Code Cache`, `GPUCache`) przed ich usunięciem lub ponownym utworzeniem.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Jak Discord płynnie przeniósł miliony użytkowników na architekturę 64-bitową](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Pamięć podręczna dysku](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord jako C2 i pozostawione ślady w cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhooki Discord – wykonanie webhooka](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
