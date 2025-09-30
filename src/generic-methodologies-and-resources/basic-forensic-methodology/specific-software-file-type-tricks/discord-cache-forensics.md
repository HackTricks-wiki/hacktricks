# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

This page summarizes how to triage Discord Desktop cache artifacts to recover exfiltrated files, webhook endpoints, and activity timelines. Discord Desktop is an Electron/Chromium app and uses Chromium Simple Cache on disk.

## Gdzie szukać (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Kluczowe struktury na dysku w katalogu Cache_Data:
- index: baza indeksu Simple Cache
- data_#: binarne pliki bloków cache, mogące zawierać wiele obiektów w cache
- f_######: pojedyncze wpisy cache przechowywane jako oddzielne pliki (często większe treści)

Uwaga: Usuwanie wiadomości/kanałów/serwerów w Discord nie czyści tego lokalnego cache. Elementy w cache często pozostają, a znaczniki czasu plików odpowiadają aktywności użytkownika, co umożliwia rekonstrukcję osi czasu.

## Co można odzyskać

- Pliki wynikające z exfiltracji i miniatury pobrane z cdn.discordapp.com/media.discordapp.net
- Obrazy, GIFy, wideo (np. .jpg, .png, .gif, .webp, .mp4, .webm)
- URL-e webhooków (https://discord.com/api/webhooks/…)
- Wywołania API Discord (https://discord.com/api/vX/…)
- Przydatne do korelowania beaconingu/exfiltracji oraz hashowania mediów w celu dopasowań wywiadowczych

## Szybki triage (ręcznie)

- Przeszukaj cache pod kątem wyraźnych artefaktów:
- Endpointy webhooków:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL-e załączników/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Wywołania API Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortuj wpisy w cache według czasu modyfikacji, aby zbudować szybką oś czasu (mtime odzwierciedla moment zapisania obiektu w cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsowanie wpisów f_* (ciało HTTP + nagłówki)

Pliki zaczynające się od f_ zawierają nagłówki odpowiedzi HTTP, po których następuje ciało. Blok nagłówków zwykle kończy się sekwencją \r\n\r\n. Przydatne nagłówki odpowiedzi to:
- Content-Type: do wnioskowania typu mediów
- Content-Location or X-Original-URL: Oryginalny zdalny URL do podglądu/korelacji
- Content-Encoding: może być gzip/deflate/br (Brotli)

Media można wydobyć, rozdzielając nagłówki od ciała i opcjonalnie dekompresując na podstawie Content-Encoding. Sprawdzanie magicznych bajtów jest przydatne, gdy brakuje Content-Type.

## Zautomatyzowane DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Funkcja: Rekurencyjnie skanuje folder cache Discord, wyszukuje URL-e webhooków/API/załączników, parsuje ciała f_*, opcjonalnie wydobywa media (carving), i generuje raporty osi czasu w formacie HTML + CSV z hashami SHA‑256.

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
- --timeline: Wygeneruj uporządkowany CSV timeline (wg czasu modyfikacji)
- --extra: Skanuj także sąsiednie Code Cache i GPUCache
- --carve: Carve media z surowych bajtów w pobliżu trafień regex (obrazy/wideo)
- Output: raport HTML, raport CSV, CSV timeline oraz folder z mediami z carved/extracted plikami

## Wskazówki analityka

- Powiąż czas modyfikacji (mtime) plików f_* i data_* z oknami aktywności użytkownika/atakującego, aby odtworzyć oś czasu.
- Oblicz hash odzyskanych mediów (SHA-256) i porównaj z known-bad lub exfil datasets.
- Wyekstrahowane webhook URLs można testować pod kątem liveness lub rotować; rozważ dodanie ich do blocklists i retro-hunting proxies.
- Cache utrzymuje się po “wiping” po stronie serwera. Jeśli możliwe pozyskanie, zbierz cały katalog Cache oraz powiązane sibling caches (Code Cache, GPUCache).

## Źródła

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
