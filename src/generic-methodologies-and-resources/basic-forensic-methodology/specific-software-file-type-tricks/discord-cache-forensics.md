# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite fasst zusammen, wie Artefakte aus dem Discord-Desktop-Cache untersucht werden können, um exfiltrierte Dateien, Webhook-Endpunkte und Aktivitätszeitabläufe wiederherzustellen. Discord Desktop ist eine Electron/Chromium-App und verwendet den Chromium Simple Cache auf der Festplatte.

## Wo gesucht werden sollte (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Wichtige Strukturen auf der Festplatte innerhalb von Cache_Data:<sup>[[1]](#references)</sup>
- index: Simple-Cache-Indexdatenbank
- data_#: Binäre Cache-Blockdateien, die mehrere gecachte Objekte enthalten können
- f_######: Einzelne gecachte Einträge, die als eigenständige Dateien gespeichert werden (häufig größere Inhalte)

Hinweis: Das Löschen von Nachrichten/Kanälen/Servern in Discord entfernt diesen lokalen Cache nicht. Gecachte Elemente bleiben häufig erhalten, und ihre Dateizeitstempel stimmen mit der Benutzeraktivität überein, wodurch die Rekonstruktion eines Zeitablaufs ermöglicht wird.<sup>[[1]](#references)</sup>

## Was wiederhergestellt werden kann

- Exfiltrierte Anhänge und Thumbnails, die über cdn.discordapp.com/media.discord.net abgerufen wurden
- Bilder, GIFs, Videos (z. B. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook-URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord-API-Aufrufe (https://discord.com/api/vX/…)
- Nützlich für die Korrelation von Beaconing-/Exfil-Aktivitäten und das Hashen von Medien zum Abgleich mit Intelligence-Daten<sup>[[1]](#references)</sup>

## Schnelle Untersuchung (manuell)

- Den Cache nach aussagekräftigen Artefakten durchsuchen:
- Webhook-Endpunkte:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Anhang-/CDN-URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord-API-Aufrufe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Die gecachten Einträge nach Änderungszeit sortieren, um einen schnellen Zeitablauf zu erstellen (mtime zeigt, wann das Objekt im Cache abgelegt wurde):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsen von f_*-Einträgen (HTTP-Body + Header)

Dateien, die mit f_ beginnen, enthalten HTTP-Response-Header, gefolgt vom Body. Der Header-Block endet typischerweise mit \r\n\r\n. Nützliche Response-Header umfassen:
- Content-Type: Zum Ableiten des Medientyps
- Content-Location oder X-Original-URL: Ursprüngliche Remote-URL für Vorschau/Korrelation
- Content-Encoding: Kann gzip/deflate/br (Brotli) sein

Medien können extrahiert werden, indem die Header vom Body getrennt und die Daten optional anhand von Content-Encoding dekomprimiert werden. Die Erkennung anhand von Magic Bytes ist nützlich, wenn Content-Type fehlt.

## Automatisierte DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Funktion: Durchsucht den Discord-Cache-Ordner rekursiv, findet Webhook-/API-/Anhang-URLs, parst f_*-Bodies, kann optional Medien extrahieren und gibt HTML- und CSV-Zeitablaufberichte mit SHA-256-Hashes aus.<sup>[[2]](#references)</sup>

Beispiel für die CLI-Verwendung:
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
Schlüsseloptionen:
- --cache: Pfad zu Cache_Data
- --format html|csv|both
- --timeline: Geordnete CSV-Timeline ausgeben (nach Änderungszeit)
- --extra: Zusätzlich benachbarte Code Cache und GPUCache scannen
- --carve: Medien aus Raw-Bytes in der Nähe von Regex-Treffern extrahieren (Bilder/Videos)
- Ausgabe: HTML-Report, CSV-Report, CSV-Timeline sowie ein Medienverzeichnis mit extrahierten/gesicherten Dateien

## Analystentipps

- Die Änderungszeit (mtime) von f_* und data_* Dateien mit Aktivitätszeiträumen von Benutzern/Angreifern korrelieren, um eine Timeline zu rekonstruieren.
- Wiederhergestellte Medien hashen (SHA-256) und mit bekannten bösartigen Datensätzen oder Exfil-Datensätzen vergleichen.
- Extrahierte Webhook-URLs können auf Erreichbarkeit getestet oder rotiert werden; erwägen Sie, sie zu Blocklists hinzuzufügen und ein Retro-Hunting in Proxies durchzuführen.
- Der Cache bleibt nach dem „Löschen“ auf der Serverseite bestehen. Wenn eine Acquisition möglich ist, das gesamte Cache-Verzeichnis sowie zugehörige benachbarte Caches (Code Cache, GPUCache) erfassen.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Discord als C2 und die zurückbleibenden Cache-Artefakte](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
