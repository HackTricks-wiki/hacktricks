# Discord-Cache-Forensik (Chromium Disk Cache)

Diese Seite fasst zusammen, wie Discord-Desktop-Cache-Artefakte auf lokal gecachte Medien, Webhook-Endpunkte und Aktivitätskorrelation untersucht werden können. Der Desktop-Client von Discord verwendet Electron, und Electron speichert Sitzungsdaten wie den Disk Cache unter `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Fundstellen (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Dies sind die Standardpfade, die vom referenzierten Parser verwendet werden. Electron erlaubt es einer Anwendung, `sessionData` zu überschreiben. Daher sollte der tatsächliche Profilpfad während der Acquisition bestätigt werden.<sup>[[2]](#references)[[4]](#references)</sup>

Das Layout aus `index` + `data_#` + `f_######` entspricht dem Blockfile-Disk-Cache-Backend von Chromium. Bezeichnen Sie es nicht als Simple Cache, ohne das Backend zu überprüfen, da Chromium verschiedene Cache-Implementierungen dokumentiert.<sup>[[5]](#references)</sup>

Wichtige On-Disk-Strukturen innerhalb von `Cache_Data`:
- `index`: Blockfile-Cache-Index zum Auffinden von Einträgen.
- `data_#`: Blockdateien fester Größe, die Cache-Metadaten, HTTP-Header und Response-Daten enthalten können.
- `f_######`: Separate Dateien für Daten, die größer als das Limit der Blockdateien sind; diese Dateien enthalten die gespeicherten Daten ohne die Blockdatei-Header.

Das Löschen von Nachrichten, Channels oder Servern garantiert nicht die Entfernung von Bytes, die bereits lokal gecacht wurden. Chromium kann Cache-Dateien jedoch jederzeit entfernen oder neu erstellen. Behandeln Sie vorhandene Artefakte als opportunistische Beweismittel und verwenden Sie Dateiänderungszeiten nur als grobe Signale für lokale Schreibvorgänge, die mit anderer Telemetrie korreliert werden müssen.<sup>[[5]](#references)[[6]](#references)</sup>

## Was wiederhergestellt werden kann

Je nachdem, welche Daten abgerufen und noch nicht entfernt wurden, können bei der Untersuchung gecachte Attachments, Medien, URLs und Datei-Hashes wiederhergestellt werden. Der Cache allein beweist nicht, dass ein Element exfiltriert wurde.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments und Thumbnails, auf die über Discord-CDN-URLs verwiesen wird.
- Bilder, GIFs und Videos (zum Beispiel `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` und `.webm`).
- Webhook-URLs wie `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord-API-Aufrufe wie `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-Hashes wiederhergestellter Medien zum Vergleich mit bekannten Datasets oder Intelligence Feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Schnelle Untersuchung (manuell)

- Durchsuchen Sie den Cache nach aussagekräftigen Artefakten. Diese Muster entsprechen den URL-Ausdrücken des referenzierten Parsers und dienen als Untersuchungsfilter, nicht als vollständige Indikatoren.<sup>[[2]](#references)</sup>
- Webhook-Endpunkte:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment-/CDN-URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord-API-Aufrufe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortieren Sie gecachte Einträge nach Änderungszeit, um eine grobe Abfolge zu erstellen. Die mtime ist ein Dateisystemsignal und belegt für sich allein nicht, wann ein Discord-Objekt abgerufen oder gesendet wurde.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsen von f_*-Einträgen (HTTP-Body + Header)

Im Blockfile-Layout sind `f_######`-Dateien separate Datenströme und beginnen nicht garantiert mit einer vollständigen HTTP-Response. Falls eine erworbene Datei serialisierte HTTP-Header gefolgt von `\r\n\r\n` enthält, teilen Sie sie am ersten Trenner auf und untersuchen Sie:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Zur Ableitung des Medientyps
- Content-Location oder X-Original-URL: Ursprüngliche Remote-URL für Preview/Korrelation
- Content-Encoding: Kann gzip/deflate/br (Brotli) sein.

Medien können anschließend durch das Trennen der Header vom Body und optionales Dekomprimieren gemäß `Content-Encoding` extrahiert werden. Der referenzierte Parser unterstützt Brotli, gzip und deflate. Die Erkennung anhand von Magic Bytes ist nützlich, wenn `Content-Type` fehlt, bleibt jedoch eine Heuristik.<sup>[[2]](#references)</sup>

## Automatisierte DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funktion: Durchsucht den Discord-Cache-Ordner rekursiv, findet Webhook-/API-/Attachment-URLs, parst `f_*`-Bodies, kann optional Medien carven und erstellt HTML- und CSV-Reports sowie optional eine chronologische Timeline mit SHA-256-Hashes.<sup>[[1]](#references)[[2]](#references)</sup>

Beispiel für die CLI-Nutzung:
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
Die CLI definiert diese Optionen und Ausgabenamen:<sup>[[2]](#references)</sup>
- --cache: Pfad zum Discord-Cache_Data-Verzeichnis
- --format html|csv|both
- --timeline: Gibt eine geordnete CSV-Zeitleiste aus (nach Änderungszeit)
- --extra: Durchsucht zusätzlich die benachbarten Verzeichnisse Code Cache und GPUCache
- --carve: Extrahiert Medien aus rohen Cache-Bytes anhand erkannter Mediensignaturen (Bilder/Videos)
- Ausgabe: `<output>.html`, `<output>.csv`, optional `<output>_timeline.csv` sowie ein `<output>_media`-Verzeichnis mit extrahierten oder ausgelesenen Dateien.

## Tipps für Analysten

- Korrelieren Sie die Änderungszeit (mtime) der Dateien `f_*` und `data_*` mit Aktivitätszeiträumen von Benutzern oder Angreifern sowie unabhängiger Telemetrie; mtime ist kein definitiver Ereigniszeitstempel.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Hashen Sie wiederhergestellte Medien (SHA-256) und vergleichen Sie sie mit bekannten schädlichen oder Exfiltrations-Datensätzen.<sup>[[1]](#references)[[2]](#references)</sup>
- Behandeln Sie extrahierte Webhook-URLs als Zugangsdaten. Rufen Sie sie nicht lediglich auf, um ihre Erreichbarkeit zu testen; bewahren Sie sie sicher auf, koordinieren Sie ihre Sperrung oder Rotation und verwenden Sie zugehörige Netzwerk-Telemetrie für Retro-Hunting.<sup>[[7]](#references)</sup>
- Eine serverseitige Löschung garantiert nicht, dass lokal zwischengespeicherte Bytes zerstört wurden. Wenn eine Sicherung möglich ist, sammeln Sie das gesamte Verzeichnis `Cache` sowie die zugehörigen benachbarten Caches (`Code Cache`, `GPUCache`), bevor sie entfernt oder der Cache neu erstellt wird.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Wie Discord nahtlos Millionen von Benutzern auf eine 64-Bit-Architektur aktualisierte](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Festplatten-Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord als C2 und die zurückgebliebenen Cache-Beweise](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord-Webhooks – Webhook ausführen](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
