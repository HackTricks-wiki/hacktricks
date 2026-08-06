# Forensics cache Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona podsumowuje sposób przeprowadzania triage artefaktów cache Discord Desktop w celu odzyskania eksfiltrowanych plików, endpointów webhooków i osi czasu aktywności. Discord Desktop jest aplikacją Electron/Chromium i używa na dysku Chromium Simple Cache.

## Gdzie szukać (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Kluczowe struktury na dysku wewnątrz Cache_Data:<sup>[[1]](#references)</sup>
- index: baza danych indeksu Simple Cache
- data_#: binarne pliki bloków cache, które mogą zawierać wiele obiektów cache
- f_######: pojedyncze wpisy cache przechowywane jako niezależne pliki (często zawierające większe body)

Uwaga: usunięcie wiadomości/kanałów/serwerów w Discord nie usuwa tego lokalnego cache. Elementy cache często pozostają, a znaczniki czasu plików odpowiadają aktywności użytkownika, umożliwiając odtworzenie osi czasu.<sup>[[1]](#references)</sup>

## Co można odzyskać

- Eksfiltrowane załączniki i miniatury pobrane z cdn.discordapp.com/media.discordapp.net
- Obrazy, GIF-y, filmy (np. .jpg, .png, .gif, .webp, .mp4, .webm)
- URL-e webhooków (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Wywołania Discord API (https://discord.com/api/vX/…)
- Przydatne do korelowania beaconingu/aktywności eksfiltracyjnej i haszowania multimediów na potrzeby dopasowywania z danymi wywiadowczymi<sup>[[1]](#references)</sup>

## Szybki triage (manualny)

- Przeszukaj cache pod kątem artefaktów o wysokiej wartości sygnałowej:
- Endpointy webhooków:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL-e załączników/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Wywołania Discord API:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Posortuj wpisy cache według czasu modyfikacji, aby szybko utworzyć oś czasu (mtime odzwierciedla moment zapisania obiektu w cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsowanie wpisów f_* (body HTTP + nagłówki)

Pliki zaczynające się od f_ zawierają nagłówki odpowiedzi HTTP, a następnie body. Blok nagłówków zazwyczaj kończy się sekwencją \r\n\r\n. Przydatne nagłówki odpowiedzi obejmują:
- Content-Type: do określenia typu multimediów
- Content-Location lub X-Original-URL: oryginalny zdalny URL do podglądu/korelacji
- Content-Encoding: może mieć wartość gzip/deflate/br (Brotli)

Media można wyodrębnić, oddzielając nagłówki od body i opcjonalnie dekompresując dane na podstawie Content-Encoding. Wykrywanie magicznych bajtów jest przydatne, gdy Content-Type nie jest dostępny.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Funkcja: rekurencyjnie skanuje folder cache Discord, wyszukuje URL-e webhooków/API/załączników, parsuje body f_*, opcjonalnie odzyskuje media i generuje raporty osi czasu w formatach HTML + CSV z hashami SHA‑256.<sup>[[2]](#references)</sup>

Przykładowe użycie CLI:
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
Kluczowe opcje:
- --cache: Ścieżka do Cache_Data
- --format html|csv|both
- --timeline: Generuje uporządkowaną oś czasu CSV (według czasu modyfikacji)
- --extra: Skanuje również sąsiednie katalogi Code Cache i GPUCache
- --carve: Wydobywa multimedia z nieprzetworzonych bajtów w pobliżu trafień regex (obrazy/wideo)
- Wyjście: raport HTML, raport CSV, oś czasu CSV oraz folder multimediów z wydobytymi/wyodrębnionymi plikami

## Wskazówki dla analityków

- Skoreluj czas modyfikacji (mtime) plików f_* i data_* z oknami aktywności użytkownika/atakującego, aby odtworzyć oś czasu.
- Oblicz hash odzyskanych multimediów (SHA-256) i porównaj je ze znanymi złośliwymi zbiorami danych lub zbiorami danych exfil.
- Wyodrębnione adresy URL webhooków można sprawdzić pod kątem aktywności lub rotacji; rozważ dodanie ich do blocklist oraz przeprowadzenie retroaktywnego wyszukiwania w proxy.
- Cache pozostaje po stronie serwera nawet po „wyczyszczeniu”. Jeśli możliwe jest pozyskanie danych, zbierz cały katalog Cache oraz powiązane sąsiednie cache (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Referencje

- [1] [Discord jako C2 i pozostawione ślady w cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
