# Analisi forense della cache di Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina riassume come eseguire il triage degli artifact della cache di Discord Desktop per recuperare file esfiltrati, endpoint webhook e timeline delle attività. Discord Desktop è un'app Electron/Chromium e utilizza Chromium Simple Cache sul disco.

## Dove cercare (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Strutture principali sul disco all'interno di Cache_Data:<sup>[[1]](#references)</sup>
- index: database dell'indice Simple Cache
- data_#: file binari dei blocchi della cache che possono contenere più oggetti memorizzati nella cache
- f_######: singole entry della cache memorizzate come file autonomi (spesso contenenti body più grandi)

Nota: l'eliminazione di messaggi/canali/server in Discord non esegue il purge della cache locale. Gli elementi memorizzati nella cache spesso rimangono e i timestamp dei file corrispondono all'attività dell'utente, consentendo la ricostruzione di una timeline.<sup>[[1]](#references)</sup>

## Cosa può essere recuperato

- Allegati esfiltrati e thumbnail recuperate tramite cdn.discordapp.com/media.discordapp.net
- Immagini, GIF, video (ad es., .jpg, .png, .gif, .webp, .mp4, .webm)
- URL webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Chiamate all'API di Discord (https://discord.com/api/vX/…)
- Utile per correlare attività di beaconing/esfiltrazione e per l'hashing dei media ai fini del matching con informazioni di intelligence<sup>[[1]](#references)</sup>

## Triage rapido (manuale)

- Eseguire il grep della cache per individuare gli artifact più significativi:
- Endpoint webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL degli allegati/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Chiamate all'API di Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordinare le entry memorizzate nella cache in base all'ora di modifica per creare una timeline rapida (mtime indica quando l'oggetto è entrato nella cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analisi delle entry f_* (body HTTP + headers)

I file che iniziano con f_ contengono gli HTTP response headers seguiti dal body. Il blocco degli header termina generalmente con \r\n\r\n. Gli response headers utili includono:
- Content-Type: per dedurre il tipo di media
- Content-Location o X-Original-URL: URL remoto originale per l'anteprima/la correlazione
- Content-Encoding: può essere gzip/deflate/br (Brotli)

I media possono essere estratti separando gli header dal body e, facoltativamente, eseguendo la decompressione in base a Content-Encoding. Il rilevamento dei magic byte è utile quando Content-Type è assente.

## DFIR automatizzato: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Funzione: esegue la scansione ricorsiva della cartella della cache di Discord, individua URL webhook/API/allegati, analizza i body f_*, può eseguire il carving dei media e produce report HTML + CSV della timeline con hash SHA‑256.<sup>[[2]](#references)</sup>

Esempio di utilizzo CLI:
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
- --cache: Percorso a Cache_Data
- --format html|csv|both
- --timeline: Genera una timeline CSV ordinata (in base all'ora di modifica)
- --extra: Esegue la scansione anche di Code Cache e GPUCache adiacenti
- --carve: Esegue il carving dei media dai raw bytes nelle vicinanze dei regex hit (immagini/video)
- Output: report HTML, report CSV, timeline CSV e una cartella media con i file sottoposti a carving/estratti

## Suggerimenti per l'analista

- Correla l'ora di modifica (mtime) dei file f_* e data_* con le finestre temporali dell'attività dell'utente/attacker per ricostruire una timeline.
- Calcola l'hash dei media recuperati (SHA-256) e confrontalo con dataset noti di file dannosi o esfiltrati.
- Gli URL dei webhook estratti possono essere testati per verificarne l'operatività o ruotati; valuta di aggiungerli alle blocklist e di eseguire retro-hunting sui proxy.
- La cache persiste dopo il “wiping” lato server. Se l'acquisizione è possibile, raccogli l'intera directory Cache e le relative cache adiacenti (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
