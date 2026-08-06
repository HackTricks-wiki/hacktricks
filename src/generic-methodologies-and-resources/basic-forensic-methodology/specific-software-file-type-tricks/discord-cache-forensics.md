# Discord-Cache-Forensik (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite fasst zusammen, wie Discord-Desktop-Cache-Artefakte untersucht werden können, um exfiltrierte Dateien, Webhook-Endpunkte und Aktivitätszeitlinien wiederherzustellen. Discord Desktop ist eine Electron/Chromium-App und verwendet den Chromium Simple Cache auf der Festplatte.

## Wo gesucht werden sollte (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Wichtige Strukturen auf der Festplatte innerhalb von Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple-Cache-Indexdatenbank
- data_#: Binäre Cache-Blockdateien, die mehrere gecachte Objekte enthalten können
- f_######: Einzelne gecachte Einträge, die als eigenständige Dateien gespeichert werden (oft größere Inhalte)

Hinweis: Das Löschen von Nachrichten/Kanälen/Servern in Discord leert diesen lokalen Cache nicht. Gecachte Elemente bleiben häufig erhalten, und ihre Dateizeitstempel stimmen mit der Benutzeraktivität überein, wodurch die Rekonstruktion einer Zeitlinie ermöglicht wird.<sup>[[1]](#references)</sup>

## Was wiederhergestellt werden kann

- Exfiltrierte Anhänge und Thumbnails, die über cdn.discordapp.com/media.discordapp.net abgerufen wurden
- Bilder, GIFs, Videos (z. B. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook-URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord-API-Aufrufe (https://discord.com/api/vX/…)
- Hilfreich für die Korrelation von Beaconing-/Exfil-Aktivitäten und das Hashing von Medien zum Abgleich mit Intel-Daten<sup>[[1]](#references)</sup>

## Schnelle Triage (manuell)

- Den Cache nach aussagekräftigen Artefakten durchsuchen:
- Webhook-Endpunkte:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment-/CDN-URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord-API-Aufrufe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Die gecachten Einträge nach Änderungszeit sortieren, um schnell eine Zeitlinie zu erstellen (mtime zeigt, wann das Objekt im Cache abgelegt wurde):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsen von f_*-Einträgen (HTTP-Body + Header)

Dateien, die mit f_ beginnen, enthalten HTTP-Response-Header gefolgt vom Body. Der Header-Block endet typischerweise mit \r\n\r\n. Nützliche Response-Header umfassen:
- Content-Type: Zum Ableiten des Medientyps
- Content-Location oder X-Original-URL: Ursprüngliche Remote-URL für Preview/Korrelation
- Content-Encoding: Kann gzip/deflate/br (Brotli) sein

Medien können extrahiert werden, indem die Header vom Body getrennt und sie optional anhand von Content-Encoding dekomprimiert werden. Magic-Byte-Sniffing ist hilfreich, wenn Content-Type fehlt.

## Automatisierte DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Funktion: Durchsucht den Discord-Cache-Ordner rekursiv, findet Webhook-/API-/Attachment-URLs, parst f_*-Bodies, kann optional Medien carven und erstellt HTML- sowie CSV-Zeitlinienberichte mit SHA-256-Hashes.<sup>[[2]](#references)</sup>

Beispiel für die CLI-Nutzung:
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
Wichtige Optionen:
- --cache: Pfad zu Cache_Data
- --format html|csv|both
- --timeline: Geordnete CSV-Timeline ausgeben (nach Änderungszeit)
- --extra: Zusätzlich benachbarte Code Cache und GPUCache durchsuchen
- --carve: Medien aus Raw-Bytes in der Nähe von Regex-Treffern extrahieren (Bilder/Videos)
- Ausgabe: HTML-Report, CSV-Report, CSV-Timeline und ein Medienverzeichnis mit extrahierten/gesicherten Dateien

## Tipps für Analysten

- Die Änderungszeit (mtime) von f_* und data_*-Dateien mit Aktivitätszeiträumen von Benutzern/Angreifern korrelieren, um eine Timeline zu rekonstruieren.
- Wiederhergestellte Medien hashen (SHA-256) und mit bekannten schädlichen Datensätzen oder Exfil-Datensätzen vergleichen.
- Extrahierte Webhook-URLs können auf Erreichbarkeit getestet oder rotiert werden; erwägen, sie zu Blocklists hinzuzufügen und Proxies rückwirkend zu durchsuchen.
- Der Cache bleibt nach dem „Löschen“ auf der Serverseite bestehen. Falls eine Acquisition möglich ist, das gesamte Cache-Verzeichnis sowie zugehörige benachbarte Caches (Code Cache, GPUCache) erfassen.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Discord als C2 und die zurückgelassenen Cache-Artefakte](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
