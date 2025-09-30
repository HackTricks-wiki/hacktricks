# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina riassume come eseguire il triage degli artifact della cache di Discord Desktop per recuperare file esfiltrati, endpoint di webhook e timeline delle attività. Discord Desktop è un'app Electron/Chromium e utilizza Chromium Simple Cache su disco.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Strutture chiave su disco all'interno di Cache_Data:
- index: database indice di Simple Cache
- data_#: file di blocco della cache binari che possono contenere più oggetti memorizzati nella cache
- f_######: singole voci della cache memorizzate come file autonomi (spesso contenuti di dimensione maggiore)

Nota: eliminare messaggi/canali/server in Discord non svuota questa cache locale. Gli elementi in cache spesso rimangono e i timestamp dei file corrispondono all'attività dell'utente, permettendo la ricostruzione della timeline.

## What can be recovered

- Allegati esfiltrati e miniature recuperate tramite cdn.discordapp.com/media.discordapp.net
- Immagini, GIF, video (es. .jpg, .png, .gif, .webp, .mp4, .webm)
- URL di webhook (https://discord.com/api/webhooks/…)
- Chiamate API di Discord (https://discord.com/api/vX/…)
- Utile per correlare attività di beaconing/esfiltrazione e per calcolare hash dei media per il matching con intel

## Quick triage (manual)

- Grep nella cache per artefatti ad alto segnale:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordina le voci della cache per tempo di modifica per costruire una timeline rapida (mtime riflette quando l'oggetto è stato aggiunto alla cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

I file che iniziano con f_ contengono header di risposta HTTP seguiti dal body. Il blocco degli header termina tipicamente con \r\n\r\n. Header di risposta utili includono:
- Content-Type: per inferire il tipo di media
- Content-Location or X-Original-URL: URL remoto originale per preview/correlazione
- Content-Encoding: può essere gzip/deflate/br (Brotli)

I media possono essere estratti separando gli header dal body e, opzionalmente, decomprimendo in base a Content-Encoding. Il magic-byte sniffing è utile quando Content-Type è assente.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: scansiona ricorsivamente la cartella della cache di Discord, trova URL di webhook/API/allegati, analizza i corpi f_*, opzionalmente estrae (carve) i media, e genera report timeline in HTML + CSV con hash SHA‑256.

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
Opzioni principali:
- --cache: Percorso alla directory Cache_Data
- --format html|csv|both
- --timeline: Genera una timeline CSV ordinata (per tempo di modifica)
- --extra: Scansiona anche le cache sorelle Code Cache e GPUCache
- --carve: Carve media dai raw bytes vicino ai match regex (images/video)
- Output: rapporto HTML, rapporto CSV, timeline CSV e una cartella media con file carved/estratti

## Suggerimenti per l'analista

- Correlare il tempo di modifica (mtime) dei file f_* e data_* con le finestre di attività dell'utente/attaccante per ricostruire una timeline.
- Calcolare l'hash (SHA-256) dei media recuperati e confrontarlo con dataset known-bad o di exfil.
- Le webhook URL estratte possono essere testate per la loro operatività o ruotate; considerare l'aggiunta a blocklists e retro-hunting proxies.
- La Cache persiste dopo il “wiping” lato server. Se l'acquisizione è possibile, raccogliere l'intera directory Cache e le cache correlate (Code Cache, GPUCache).

## Riferimenti

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
