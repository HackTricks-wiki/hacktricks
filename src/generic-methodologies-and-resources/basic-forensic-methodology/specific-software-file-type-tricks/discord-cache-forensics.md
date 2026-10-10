# Analisi forense della cache di Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina riassume come eseguire il triage degli artefatti della cache di Discord Desktop per individuare contenuti multimediali memorizzati localmente, endpoint webhook e correlazioni con le attività. Il client desktop di Discord usa Electron, che memorizza i dati di sessione, come la cache su disco, in `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Dove cercare (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Questi sono i percorsi predefiniti usati dal parser citato; Electron consente a un'applicazione di sovrascrivere `sessionData`, quindi durante l'acquisizione verifica il percorso effettivo del profilo.<sup>[[2]](#references)[[4]](#references)</sup>

La struttura `index` + `data_#` + `f_######` corrisponde al backend della cache su disco blockfile di Chromium; non definirla Simple Cache senza prima verificare il backend, perché Chromium documenta implementazioni della cache distinte.<sup>[[5]](#references)</sup>

Strutture chiave su disco all'interno di `Cache_Data`:
- `index`: indice della cache Blockfile usato per individuare le voci.
- `data_#`: file a blocchi di dimensione fissa che possono contenere metadati della cache, intestazioni HTTP e dati delle risposte.
- `f_######`: file separati usati per dati più grandi del limite dei file a blocchi; contengono i dati memorizzati senza le intestazioni dei file a blocchi.

L'eliminazione di messaggi, canali o server non garantisce la rimozione dei byte già memorizzati localmente nella cache, ma Chromium può espellere o ricreare i file della cache in qualsiasi momento. Considera gli artefatti residui come prove opportunistiche e usa gli orari di modifica dei file solo come indicazioni approssimative delle scritture locali, da correlare con altri dati telemetrici.<sup>[[5]](#references)[[6]](#references)</sup>

## Cosa si può recuperare

A seconda dei contenuti recuperati e non ancora espulsi, il triage può consentire di recuperare allegati, contenuti multimediali, URL e hash dei file memorizzati nella cache; la sola cache non dimostra che un elemento sia stato esfiltrato.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Allegati e miniature a cui fanno riferimento gli URL del CDN di Discord.
- Immagini, GIF e video (ad esempio, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` e `.webm`).
- URL webhook come `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Chiamate API di Discord come `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hash SHA-256 dei contenuti multimediali recuperati, da confrontare con dataset noti o feed di intelligence.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rapido (manuale)

- Usa grep sulla cache per cercare artefatti ad alto valore informativo. Questi pattern rispecchiano le espressioni URL del parser citato e sono filtri di triage, non indicatori esaustivi.<sup>[[2]](#references)</sup>
  - Endpoint webhook:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL di allegati/CDN:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Chiamate API di Discord:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordina le voci della cache per data di modifica per ricostruire una sequenza approssimativa; mtime è un'indicazione del filesystem e non stabilisce da solo quando un oggetto Discord è stato scaricato o inviato.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analisi delle voci f_* (corpo HTTP + intestazioni)

Nella struttura blockfile, i file `f_######` sono flussi di dati separati e non è garantito che inizino con una risposta HTTP completa. Se un file acquisito contiene intestazioni HTTP serializzate seguite da `\r\n\r\n`, dividi il contenuto in corrispondenza del primo delimitatore e controlla:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: per dedurre il tipo di contenuto multimediale
- Content-Location o X-Original-URL: URL remoto originale per l'anteprima e la correlazione
- Content-Encoding: può essere gzip/deflate/br (Brotli).

È quindi possibile estrarre i contenuti multimediali separando le intestazioni dal corpo e, facoltativamente, decomprimendo i dati in base a `Content-Encoding`; il parser citato gestisce Brotli, gzip e deflate. Il rilevamento tramite magic byte è utile quando `Content-Type` è assente, ma resta un'euristica.<sup>[[2]](#references)</sup>

## DFIR automatizzato: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funzione: esegue una scansione ricorsiva della cartella della cache di Discord, individua URL webhook/API/allegati, analizza i corpi `f_*`, può estrarre contenuti multimediali e genera report HTML e CSV, oltre a una cronologia opzionale con hash SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

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

La CLI definisce queste opzioni e nomi di output:<sup>[[2]](#references)</sup>
- --cache: Percorso della directory Discord Cache_Data
- --format html|csv|both
- --timeline: Genera una timeline CSV ordinata (per ora di modifica)
- --extra: Analizza anche le directory Code Cache e GPUCache adiacenti
- --carve: Estrae file multimediali dai byte della cache grezzi usando firme multimediali riconosciute (immagini/video)
- Output: `<output>.html`, `<output>.csv`, facoltativamente `<output>_timeline.csv` e una cartella `<output>_media` con i file estratti o recuperati.

## Suggerimenti per gli analisti

- Correlare l'ora di modifica (mtime) dei file `f_*` e `data_*` con le finestre di attività di utenti o attaccanti e con telemetria indipendente; mtime non è un timestamp definitivo degli eventi.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calcolare l'hash dei file multimediali recuperati (SHA-256) e confrontarlo con dataset noti di file dannosi o di esfiltrazione.<sup>[[1]](#references)[[2]](#references)</sup>
- Considerare gli URL dei webhook estratti come credenziali. Non invocarli solo per verificarne la disponibilità; conservarli in modo sicuro, coordinare la revoca o la rotazione e usare la telemetria di rete correlata per le ricerche retrospettive.<sup>[[7]](#references)</sup>
- L'eliminazione lato server non garantisce che i byte memorizzati localmente nella cache siano stati distrutti. Se è possibile acquisirli, raccogliere l'intera directory `Cache` e le cache adiacenti correlate (`Code Cache`, `GPUCache`) prima dell'eliminazione o della ricreazione della cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Suite forense Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI della suite forense Discord](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Come Discord ha aggiornato senza interruzioni milioni di utenti all'architettura a 64 bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache su disco](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord come C2 e le prove lasciate nella cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhook Discord – Esegui webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
