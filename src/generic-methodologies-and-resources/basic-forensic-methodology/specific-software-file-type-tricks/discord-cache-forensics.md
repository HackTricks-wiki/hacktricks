# Discord-Cache-Forensik (Chromium-Disk-Cache)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite fasst zusammen, wie Artefakte aus dem Discord-Desktop-Cache auf lokal zwischengespeicherte Medien, Webhook-Endpunkte und Aktivitätskorrelation untersucht werden können. Der Discord-Desktop-Client verwendet Electron, und Electron speichert Sitzungsdaten wie den Disk-Cache unter `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Wo suchen (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Dies sind die Standardpfade des referenzierten Parsers. Electron ermöglicht es Anwendungen, `sessionData` zu überschreiben; bestätigen Sie daher bei der Erfassung den tatsächlichen Profilpfad.<sup>[[2]](#references)[[4]](#references)</sup>

Das Layout `index` + `data_#` + `f_######` entspricht dem Blockfile-Disk-Cache-Backend von Chromium. Bezeichnen Sie es nicht als Simple Cache, ohne das Backend zu überprüfen, da Chromium verschiedene Cache-Implementierungen dokumentiert.<sup>[[5]](#references)</sup>

Wichtige Strukturen auf dem Datenträger innerhalb von `Cache_Data`:
- `index`: Blockfile-Cache-Index zum Auffinden von Einträgen.
- `data_#`: Dateien mit fester Größe, die Cache-Metadaten, HTTP-Header und Antwortdaten enthalten können.
- `f_######`: Separate Dateien für Daten, die größer als das Blockdatei-Limit sind; diese Dateien enthalten die gespeicherten Daten ohne die Blockdatei-Header.

Das Löschen von Nachrichten, Channels oder Servern garantiert nicht, dass bereits lokal zwischengespeicherte Bytes entfernt werden. Chromium kann Cache-Dateien jedoch jederzeit entfernen oder neu erstellen. Betrachten Sie erhaltene Artefakte als opportunistische Beweise und verwenden Sie Dateiänderungszeiten nur als grobe Hinweise auf lokale Schreibvorgänge, die mit anderer Telemetrie korreliert werden müssen.<sup>[[5]](#references)[[6]](#references)</sup>

## Was wiederhergestellt werden kann

Je nachdem, was abgerufen und noch nicht entfernt wurde, können bei der Untersuchung zwischengespeicherte Anhänge, Medien, URLs und Datei-Hashes wiederhergestellt werden. Der Cache allein beweist nicht, dass ein Element exfiltriert wurde.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Anhänge und Thumbnails, auf die Discord-CDN-URLs verweisen.
- Bilder, GIFs und Videos (zum Beispiel `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` und `.webm`).
- Webhook-URLs wie `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord-API-Aufrufe wie `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-Hashes wiederhergestellter Medien zum Vergleich mit bekannten Datensätzen oder Intelligence-Feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Schnelle Triage (manuell)

- Durchsuchen Sie den Cache nach aussagekräftigen Artefakten. Diese Muster entsprechen den URL-Ausdrücken des referenzierten Parsers und dienen als Triage-Filter, nicht als vollständige Indikatoren.<sup>[[2]](#references)</sup>
  - Webhook-Endpunkte:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Anhangs-/CDN-URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord-API-Aufrufe:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortieren Sie zwischengespeicherte Einträge nach Änderungszeit, um eine grobe Abfolge zu erstellen. Die mtime ist ein Dateisystemsignal und belegt für sich genommen nicht, wann ein Discord-Objekt abgerufen oder gesendet wurde.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsen von f_*-Einträgen (HTTP-Body + Header)

Im Blockfile-Layout sind `f_######`-Dateien separate Datenströme und beginnen nicht zwingend mit einer vollständigen HTTP-Antwort. Falls eine erfasste Datei serialisierte HTTP-Header gefolgt von `\r\n\r\n` enthält, teilen Sie sie am ersten Trennzeichen auf und untersuchen Sie:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: zur Ermittlung des Medientyps
- Content-Location oder X-Original-URL: ursprüngliche Remote-URL für Vorschau/Korrelation
- Content-Encoding: kann gzip/deflate/br (Brotli) sein.

Medien können anschließend extrahiert werden, indem Header und Body getrennt und die Daten optional entsprechend `Content-Encoding` dekomprimiert werden. Der referenzierte Parser unterstützt Brotli, gzip und deflate. Die Erkennung anhand von Magic Bytes ist nützlich, wenn `Content-Type` fehlt, bleibt aber eine heuristische Methode.<sup>[[2]](#references)</sup>

## Automatisierte DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funktion: Durchsucht rekursiv den Discord-Cache-Ordner, findet Webhook-/API-/Anhangs-URLs, parst `f_*`-Bodies, kann optional Medien extrahieren und erstellt HTML- und CSV-Berichte sowie optional eine chronologische Zeitleiste mit SHA-256-Hashes.<sup>[[1]](#references)[[2]](#references)</sup>

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
- --cache: Pfad zum Discord-Cache-Verzeichnis Cache_Data
- --format html|csv|both
- --timeline: Gibt eine geordnete CSV-Zeitleiste aus (nach Änderungszeit)
- --extra: Durchsucht zusätzlich die benachbarten Verzeichnisse Code Cache und GPUCache
- --carve: Extrahiert Mediendateien aus rohen Cache-Bytes anhand erkannter Mediensignaturen (Bilder/Videos)
- Ausgabe: `<output>.html`, `<output>.csv`, optional `<output>_timeline.csv` und ein Verzeichnis `<output>_media` mit extrahierten oder herausgeschnittenen Dateien.

## Hinweise für Analysten

- Setzen Sie die Änderungszeit (mtime) von `f_*`- und `data_*`-Dateien mit Aktivitätszeiträumen von Benutzern oder Angreifern und unabhängigen Telemetriedaten in Beziehung; mtime ist kein definitiver Ereigniszeitstempel.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Erstellen Sie Hashes der wiederhergestellten Medien (SHA-256) und vergleichen Sie sie mit bekannten Schadsoftware- oder Exfiltrationsdatensätzen.<sup>[[1]](#references)[[2]](#references)</sup>
- Behandeln Sie extrahierte Webhook-URLs wie Zugangsdaten. Rufen Sie sie nicht einfach auf, um ihre Erreichbarkeit zu testen; bewahren Sie sie sicher auf, stimmen Sie deren Widerruf oder Rotation ab und verwenden Sie zugehörige Netzwerk-Telemetrie für die rückwirkende Suche.<sup>[[7]](#references)</sup>
- Eine serverseitige Löschung garantiert nicht, dass lokal zwischengespeicherte Bytes vernichtet wurden. Wenn eine Erfassung möglich ist, sammeln Sie das gesamte Verzeichnis `Cache` und die zugehörigen benachbarten Caches (`Code Cache`, `GPUCache`), bevor sie bereinigt oder neu erstellt werden.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Wie Discord Millionen von Benutzern nahtlos auf eine 64-Bit-Architektur aktualisierte](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Festplatten-Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord als C2 und die zurückgelassenen Cache-Artefakte](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord-Webhooks – Webhook ausführen](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
