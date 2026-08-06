# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina riassume come eseguire il triage degli artefatti della cache di Discord Desktop per recuperare file esfiltrati, endpoint webhook e timeline delle attività. Discord Desktop è un'app Electron/Chromium e utilizza Chromium Simple Cache su disco.

## Dove cercare (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Strutture principali su disco all'interno di Cache_Data:<sup>[[1]](#references)</sup>
- index: database dell'indice Simple Cache
- data_#: file binari dei blocchi della cache che possono contenere più oggetti memorizzati nella cache
- f_######: singole voci della cache memorizzate come file autonomi (spesso contenenti body più grandi)

Nota: eliminare messaggi/canali/server in Discord non elimina questa cache locale. Gli elementi memorizzati nella cache spesso rimangono e i timestamp dei file corrispondono all'attività dell'utente, consentendo la ricostruzione di una timeline.<sup>[[1]](#references)</sup>

## Cosa può essere recuperato

- Allegati esfiltrati e miniature recuperate tramite cdn.discordapp.com/media.discordapp.net
- Immagini, GIF, video (ad es., .jpg, .png, .gif, .webp, .mp4, .webm)
- URL webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Chiamate API di Discord (https://discord.com/api/vX/…)
- Utile per correlare attività di beaconing/esfiltrazione e sottoporre gli elementi multimediali a hashing per il matching di intelligence<sup>[[1]](#references)</sup>

## Quick triage (manuale)

- Cercare nella cache gli artefatti ad alto valore informativo:
- Endpoint webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL degli allegati/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Chiamate API di Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordinare le voci della cache in base all'ora di modifica per creare rapidamente una timeline (mtime indica quando l'oggetto è entrato nella cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing delle voci f_* (HTTP body + headers)

I file che iniziano con f_ contengono gli header della risposta HTTP seguiti dal body. Il blocco degli header termina generalmente con \r\n\r\n. Gli header di risposta utili includono:
- Content-Type: per dedurre il tipo di media
- Content-Location o X-Original-URL: URL remoto originale per l'anteprima/la correlazione
- Content-Encoding: può essere gzip/deflate/br (Brotli)

I media possono essere estratti separando gli header dal body e, facoltativamente, decomprimendoli in base a Content-Encoding. Il rilevamento dei magic byte è utile quando Content-Type è assente.

## DFIR automatizzato: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Funzione: esegue la scansione ricorsiva della cartella della cache di Discord, trova URL webhook/API/allegati, analizza i body f_*, può eseguire il carving dei media e genera report HTML + CSV della timeline con hash SHA‑256.<sup>[[2]](#references)</sup>

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
- --cache: Path a Cache_Data
- --format html|csv|both
- --timeline: Genera una timeline CSV ordinata (in base al tempo di modifica)
- --extra: Esegue la scansione anche di Code Cache e GPUCache adiacenti
- --carve: Estrae media dai raw bytes vicini ai riscontri regex (immagini/video)
- Output: report HTML, report CSV, timeline CSV e una cartella media con i file estratti/carved

## Suggerimenti per l'analista

- Correla il tempo di modifica (mtime) dei file f_* e data_* con le finestre di attività dell'utente/attacker per ricostruire una timeline.
- Calcola l'hash dei media recuperati (SHA-256) e confrontalo con dataset noti di file malevoli o esfiltrati.
- Gli URL dei webhook estratti possono essere testati per verificarne la raggiungibilità o ruotati; valuta di aggiungerli alle blocklist e di eseguire retro-hunting sui proxy.
- La cache persiste dopo il “wiping” sul server side. Se l'acquisizione è possibile, raccogli l'intera directory Cache e le cache correlate adiacenti (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Discord come C2 e le tracce lasciate nella cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
