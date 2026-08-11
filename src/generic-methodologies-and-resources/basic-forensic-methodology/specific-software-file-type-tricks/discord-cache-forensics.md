# Forensics della cache di Discord (cache su disco di Chromium)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina riassume come eseguire il triage degli artefatti della cache di Discord Desktop per individuare media memorizzati localmente nella cache, endpoint webhook e correlazioni delle attività. Il client desktop di Discord usa Electron, ed Electron memorizza i dati di sessione, come la cache su disco, nella directory `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Dove cercare (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Questi sono i percorsi predefiniti usati dal parser indicato; Electron consente a un'applicazione di sovrascrivere `sessionData`, quindi è necessario confermare il percorso effettivo del profilo durante l'acquisizione.<sup>[[2]](#references)[[4]](#references)</sup>

La struttura `index` + `data_#` + `f_######` corrisponde al backend blockfile della cache su disco di Chromium; non definirla Simple Cache senza aver verificato il backend, perché Chromium documenta implementazioni della cache distinte.<sup>[[5]](#references)</sup>

Strutture principali su disco all'interno di `Cache_Data`:
- `index`: indice della cache Blockfile usato per individuare le entry.
- `data_#`: file a blocchi di dimensione fissa che possono contenere metadati della cache, header HTTP e dati delle risposte.
- `f_######`: file separati usati per dati più grandi del limite dei file a blocchi; questi file contengono i dati memorizzati senza gli header dei file a blocchi.

L'eliminazione di messaggi, canali o server non garantisce la rimozione dei byte già memorizzati localmente nella cache, ma Chromium può eseguire l'eviction o ricreare i file della cache in qualsiasi momento. Considera gli artefatti sopravvissuti come evidenze opportunistiche e usa gli orari di modifica dei file solo come indicatori approssimativi delle scritture locali, da correlare con altra telemetria.<sup>[[5]](#references)[[6]](#references)</sup>

## Cosa può essere recuperato

A seconda di ciò che è stato scaricato e non è ancora stato sottoposto a eviction, il triage può recuperare allegati, media, URL e hash di file memorizzati nella cache; la sola cache non dimostra che un elemento sia stato esfiltrato.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Allegati e miniature referenziati da URL del CDN di Discord.
- Immagini, GIF e video (ad esempio `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` e `.webm`).
- URL webhook come `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Chiamate all'API di Discord come `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hash SHA-256 dei media recuperati per il confronto con dataset noti o feed di intelligence.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rapido (manuale)

- Esegui Grep nella cache per individuare artefatti ad alto segnale. Questi pattern rispecchiano le espressioni degli URL del parser indicato e sono filtri di triage, non indicatori esaustivi.<sup>[[2]](#references)</sup>
- Endpoint webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL degli allegati/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Chiamate all'API di Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordina le entry memorizzate nella cache in base all'orario di modifica per costruire una sequenza approssimativa; mtime è un indicatore del filesystem e da solo non stabilisce quando un oggetto Discord è stato scaricato o inviato.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analisi delle entry f_* (body HTTP + header)

Nella struttura blockfile, i file `f_######` sono flussi di dati separati e non è garantito che inizino con una risposta HTTP completa. Se un file acquisito contiene header HTTP serializzati seguiti da `\r\n\r\n`, dividilo in corrispondenza del primo delimitatore ed esamina:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: per dedurre il tipo di media
- Content-Location o X-Original-URL: URL remoto originale per l'anteprima/correlazione
- Content-Encoding: può essere gzip/deflate/br (Brotli).

I media possono quindi essere estratti separando gli header dal body e, facoltativamente, decomprimendoli in base a `Content-Encoding`; il parser indicato gestisce Brotli, gzip e deflate. L'analisi dei magic byte è utile quando `Content-Type` è assente, ma rimane un'euristica.<sup>[[2]](#references)</sup>

## DFIR automatizzato: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funzione: esegue una scansione ricorsiva della cartella della cache di Discord, individua URL webhook/API/allegati, analizza i body `f_*`, esegue facoltativamente il carving dei media e produce report HTML e CSV, oltre a una timeline cronologica opzionale con hash SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Esempio di utilizzo della CLI:
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
La CLI definisce queste opzioni e questi nomi di output:<sup>[[2]](#references)</sup>
- --cache: Percorso alla directory Discord Cache_Data
- --format html|csv|both
- --timeline: Genera una timeline CSV ordinata (in base all'ora di modifica)
- --extra: Esegue la scansione anche delle directory Code Cache e GPUCache adiacenti
- --carve: Esegue il carving dei media dai byte grezzi della cache usando firme di media riconosciute (immagini/video)
- Output: `<output>.html`, `<output>.csv`, facoltativo `<output>_timeline.csv` e una directory `<output>_media` con file estratti o sottoposti a carving.

## Suggerimenti per l'analista

- Correla l'ora di modifica (mtime) dei file `f_*` e `data_*` con le finestre temporali dell'attività degli utenti o degli attacker e con telemetria indipendente; mtime non è un timestamp definitivo dell'evento.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calcola l'hash dei media recuperati (SHA-256) e confrontalo con dataset di elementi noti come dannosi o di exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Tratta gli URL dei webhook estratti come credenziali. Non invocarli soltanto per verificarne la disponibilità; conservali in modo sicuro, coordina la revoca o la rotazione e usa la telemetria di rete correlata per il retro-hunting.<sup>[[7]](#references)</sup>
- L'eliminazione server-side non garantisce che i byte memorizzati localmente nella cache siano stati distrutti. Se l'acquisizione è possibile, raccogli l'intera directory `Cache` e le cache adiacenti correlate (`Code Cache`, `GPUCache`) prima dell'eviction o della ricreazione della cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Come Discord ha aggiornato senza problemi milioni di utenti all'architettura a 64 bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache su disco](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord come C2 e le prove residue nella cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Esegui webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
