# Discord-Cache-Forensik (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite fasst zusammen, wie Artefakte des Discord Desktop-Cache auf lokal zwischengespeicherte Medien, Webhook-Endpunkte und Aktivitätszusammenhänge untersucht werden können. Der Desktop-Client von Discord verwendet Electron, und Electron speichert Sitzungsdaten wie den Disk Cache unter `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Wo zu suchen ist (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Dies sind die Standardpfade, die vom referenzierten Parser verwendet werden. Electron ermöglicht es einer Anwendung, `sessionData` zu überschreiben; bestätige daher während der Sicherung den tatsächlichen Profilpfad.<sup>[[2]](#references)[[4]](#references)</sup>

Das Layout `index` + `data_#` + `f_######` entspricht dem Blockfile-Disk-Cache-Backend von Chromium. Bezeichne es nicht als Simple Cache, ohne das Backend zu überprüfen, da Chromium verschiedene Cache-Implementierungen dokumentiert.<sup>[[5]](#references)</sup>

Wichtige Strukturen auf dem Datenträger innerhalb von `Cache_Data`:
- `index`: Blockfile-Cache-Index zur Lokalisierung von Einträgen.
- `data_#`: Blockdateien mit fester Größe, die Cache-Metadaten, HTTP-Header und Antwortdaten enthalten können.
- `f_######`: Separate Dateien für Daten, die größer als das Limit der Blockdateien sind; diese Dateien enthalten die gespeicherten Daten ohne die Header der Blockdateien.

Das Löschen von Nachrichten, Channels oder Servern garantiert nicht, dass bereits lokal zwischengespeicherte Bytes entfernt werden. Chromium kann Cache-Dateien jedoch jederzeit auslagern oder neu erstellen. Behandle überlebende Artefakte als opportunistische Beweise und verwende Dateiänderungszeiten nur als grobe Signale für lokale Schreibvorgänge, die mit anderer Telemetrie korreliert werden müssen.<sup>[[5]](#references)[[6]](#references)</sup>

## Was wiederhergestellt werden kann

Je nachdem, was abgerufen und noch nicht ausgelagert wurde, können bei einer Triage zwischengespeicherte Anhänge, Medien, URLs und Datei-Hashes wiederhergestellt werden. Der Cache allein beweist nicht, dass ein Element exfiltriert wurde.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Anhänge und Thumbnails, auf die durch Discord CDN-URLs verwiesen wird.
- Bilder, GIFs und Videos (zum Beispiel `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` und `.webm`).
- Webhook-URLs wie `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API-Aufrufe wie `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-Hashes wiederhergestellter Medien zum Vergleich mit bekannten Datensätzen oder Intelligence-Feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Schnelle Triage (manuell)

- Durchsuche den Cache nach aussagekräftigen Artefakten. Diese Muster entsprechen den URL-Ausdrücken des referenzierten Parsers und sind Triage-Filter, keine erschöpfenden Indikatoren.<sup>[[2]](#references)</sup>
- Webhook-Endpunkte:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Anhang-/CDN-URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API-Aufrufe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortiere zwischengespeicherte Einträge nach Änderungszeit, um eine grobe Abfolge zu erstellen. Die mtime ist ein Dateisystemsignal und belegt für sich allein nicht, wann ein Discord-Objekt abgerufen oder gesendet wurde.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsen von f_*‑Einträgen (HTTP-Body + Header)

Im Blockfile-Layout sind `f_######`-Dateien separate Datenströme und beginnen nicht garantiert mit einer vollständigen HTTP-Antwort. Falls eine erfasste Datei serialisierte HTTP-Header gefolgt von `\r\n\r\n` enthält, teile sie am ersten Trennzeichen auf und untersuche sie:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Zur Ableitung des Medientyps
- Content-Location oder X-Original-URL: Ursprüngliche Remote-URL für Vorschau/Korrelation
- Content-Encoding: Kann gzip/deflate/br (Brotli) sein.

Medien können anschließend durch Trennen der Header vom Body und optionales Dekomprimieren entsprechend `Content-Encoding` extrahiert werden. Der referenzierte Parser verarbeitet Brotli, gzip und deflate. Die Erkennung anhand von Magic Bytes ist nützlich, wenn `Content-Type` fehlt, bleibt jedoch eine Heuristik.<sup>[[2]](#references)</sup>

## Automatisierte DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Funktion: Durchsucht den Discord-Cache-Ordner rekursiv, findet Webhook-/API-/Anhang-URLs, parst `f_*`-Bodies, extrahiert optional Medien und gibt HTML- und CSV-Berichte sowie optional eine chronologische Timeline mit SHA-256-Hashes aus.<sup>[[1]](#references)[[2]](#references)</sup>

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
- --timeline: Gibt eine geordnete CSV-Timeline aus (nach Änderungszeit)
- --extra: Durchsucht zusätzlich die benachbarten Verzeichnisse Code Cache und GPUCache
- --carve: Extrahiert Medien aus rohen Cache-Bytes mithilfe erkannter Mediensignaturen (Bilder/Videos)
- Ausgabe: `<output>.html`, `<output>.csv`, optional `<output>_timeline.csv` sowie ein Verzeichnis `<output>_media` mit extrahierten oder extrahierten Dateien.

## Analystentipps

- Korreliere die Änderungszeit (mtime) der Dateien `f_*` und `data_*` mit Aktivitätszeiträumen von Benutzern oder Angreifern sowie unabhängiger Telemetrie; mtime ist kein definitiver Ereigniszeitstempel.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Bilde Hashes der wiederhergestellten Medien (SHA-256) und vergleiche sie mit bekannten schädlichen oder Exfiltrations-Datensätzen.<sup>[[1]](#references)[[2]](#references)</sup>
- Behandle extrahierte Webhook-URLs als Zugangsdaten. Rufe sie nicht lediglich auf, um ihre Erreichbarkeit zu testen; sichere sie, koordiniere ihren Widerruf oder ihre Rotation und nutze zugehörige Netzwerk-Telemetrie für die nachträgliche Suche nach Aktivitäten.<sup>[[7]](#references)</sup>
- Eine serverseitige Löschung garantiert nicht, dass lokal zwischengespeicherte Bytes zerstört wurden. Wenn eine Erfassung möglich ist, sammle das gesamte Verzeichnis `Cache` sowie die zugehörigen benachbarten Caches (`Code Cache`, `GPUCache`), bevor sie entfernt oder neu erstellt werden.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Wie Discord Millionen von Benutzern nahtlos auf eine 64-Bit-Architektur aktualisierte](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Festplatten-Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord als C2 und die zurückgebliebenen Cache-Artefakte](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Webhook ausführen](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
