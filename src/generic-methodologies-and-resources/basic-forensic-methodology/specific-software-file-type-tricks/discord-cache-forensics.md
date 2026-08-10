# Forensics della cache di Discord (Chromium Disk Cache)

Questa pagina riepiloga come eseguire il triage degli artefatti della cache di Discord Desktop per individuare media memorizzati localmente, endpoint webhook e correlazioni con le attività. Il client desktop di Discord utilizza Electron, ed Electron memorizza i dati della sessione, come la disk cache, in `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Dove cercare (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Questi sono i percorsi predefiniti utilizzati dal parser indicato; Electron consente a un'applicazione di sovrascrivere `sessionData`, quindi confermare il percorso effettivo del profilo durante l'acquisizione.<sup>[[2]](#references)[[4]](#references)</sup>

La struttura `index` + `data_#` + `f_######` corrisponde al backend blockfile disk-cache di Chromium; non etichettarla come Simple Cache senza aver verificato il backend, poiché Chromium documenta implementazioni della cache distinte.<sup>[[5]](#references)</sup>

Strutture principali su disco all'interno di `Cache_Data`:
- `index`: indice della cache Blockfile utilizzato per individuare le entry.
- `data_#`: file a blocchi di dimensione fissa che possono contenere metadati della cache, header HTTP e dati delle risposte.
- `f_######`: file separati utilizzati per i dati più grandi del limite dei file a blocchi; questi file contengono i dati memorizzati senza gli header dei file a blocchi.

L'eliminazione di messaggi, canali o server non garantisce la rimozione dei byte già memorizzati localmente nella cache, ma Chromium può rimuovere o ricreare i file della cache in qualsiasi momento. Considerare gli artefatti sopravvissuti come prove opportunistiche e utilizzare gli orari di modifica dei file solo come indicazioni approssimative delle scritture locali, che devono essere correlate con altri dati telemetrici.<sup>[[5]](#references)[[6]](#references)</sup>

## Cosa può essere recuperato

A seconda di ciò che è stato scaricato e non è ancora stato rimosso dalla cache, il triage può recuperare allegati memorizzati nella cache, media, URL e hash dei file; la sola cache non dimostra che un elemento sia stato esfiltrato.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Allegati e miniature referenziati da URL della CDN di Discord.
- Immagini, GIF e video (ad esempio `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` e `.webm`).
- URL webhook come `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Chiamate alle API di Discord come `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hash SHA-256 dei media recuperati per il confronto con dataset noti o intelligence feed.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rapido (manuale)

- Eseguire il grep della cache alla ricerca di artefatti ad alto valore informativo. Questi pattern rispecchiano le espressioni URL del parser indicato e sono filtri di triage, non indicatori esaustivi.<sup>[[2]](#references)</sup>
- Endpoint webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL degli allegati/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Chiamate alle API di Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordinare le entry della cache in base all'orario di modifica per costruire una sequenza approssimativa; mtime è un segnale del filesystem e non stabilisce da solo quando un oggetto Discord è stato scaricato o inviato.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analisi delle entry f_* (HTTP body + headers)

Nella struttura blockfile, i file `f_######` sono flussi di dati separati e non è garantito che inizino con una risposta HTTP completa. Se un file acquisito contiene header HTTP serializzati seguiti da `\r\n\r\n`, dividerlo al primo delimitatore ed esaminare:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: per inferire il tipo di media
- Content-Location o X-Original-URL: URL remoto originale per l'anteprima/la correlazione
- Content-Encoding: può essere gzip/deflate/br (Brotli).

Il media può quindi essere estratto separando gli header dal body e, facoltativamente, decomprimendolo in base a `Content-Encoding`; il parser indicato gestisce Brotli, gzip e deflate. Il rilevamento dei magic byte è utile quando `Content-Type` è assente, ma rimane un'euristica.<sup>[[2]](#references)</sup>

## DFIR automatizzato: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funzione: esegue la scansione ricorsiva della cartella della cache di Discord, individua URL webhook/API/allegati, analizza i body `f_*`, esegue facoltativamente il carving dei media e produce report HTML e CSV, oltre a una timeline cronologica opzionale con hash SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Esempio di utilizzo CLI:
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
- --timeline: Genera una timeline CSV ordinata (in base all'orario di modifica)
- --extra: Esegue inoltre la scansione delle directory adiacenti Code Cache e GPUCache
- --carve: Estrae contenuti multimediali dai byte grezzi della cache utilizzando firme riconosciute dei media (immagini/video)
- Output: `<output>.html`, `<output>.csv`, `<output>_timeline.csv` opzionale e una cartella `<output>_media` con file estratti o recuperati tramite carving.

## Consigli per l'analista

- Correla l'orario di modifica (mtime) dei file `f_*` e `data_*` con le finestre di attività degli utenti o degli attacker e con la telemetria indipendente; mtime non è un timestamp definitivo dell'evento.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calcola l'hash dei contenuti multimediali recuperati (SHA-256) e confrontalo con dataset noti come dannosi o relativi all'esfiltrazione.<sup>[[1]](#references)[[2]](#references)</sup>
- Considera gli URL dei webhook estratti come credenziali. Non richiamarli semplicemente per verificarne la disponibilità; conservali in modo sicuro, coordina la revoca o la rotazione e utilizza la telemetria di rete correlata per il retro-hunting.<sup>[[7]](#references)</sup>
- L'eliminazione lato server non garantisce che i byte memorizzati localmente nella cache siano stati distrutti. Se l'acquisizione è possibile, raccogli l'intera directory `Cache` e le relative cache adiacenti (`Code Cache`, `GPUCache`) prima dell'eviction o della ricreazione della cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Come Discord ha aggiornato senza problemi milioni di utenti all'architettura a 64 bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache su disco](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord come C2 e le tracce memorizzate nella cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhook di Discord – Esegui webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
