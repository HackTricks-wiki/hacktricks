# Discord-Cache-Forensik (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite fasst zusammen, wie man den Cache-Ordner der Discord Desktop-App triagiert, um exfiltrierte Dateien, Webhook-Endpunkte und Aktivitäts-Timelines wiederherzustellen. Discord Desktop ist eine Electron/Chromium-App und verwendet Chromium Simple Cache auf der Festplatte.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Wichtige On‑Disk-Strukturen innerhalb von Cache_Data:
- index: Simple Cache index database
- data_#: Binäre Cache-Blockdateien, die mehrere gecachte Objekte enthalten können
- f_######: Einzelne gecachte Einträge, als einzelne Dateien gespeichert (oft größere Inhalte)

Hinweis: Das Löschen von Nachrichten/Channels/Servern in Discord entfernt diesen lokalen Cache nicht. Gepufferte Elemente bleiben häufig erhalten und ihre Dateizeitstempel korrelieren mit Benutzeraktivität, wodurch eine Timeline-Rekonstruktion möglich ist.

## What can be recovered

- Exfiltrierte Attachments und Thumbnails, die über cdn.discordapp.com/media.discordapp.net abgerufen wurden
- Bilder, GIFs, Videos (z. B. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API-Aufrufe (https://discord.com/api/vX/…)
- Nützlich zur Korrelation von Beaconing-/Exfil-Aktivität und zum Hashing von Medien für Intel-Abgleiche

## Quick triage (manual)

- Cache mit grep nach hochrelevanten Artefakten durchsuchen:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN-URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API-Aufrufe:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sortiere gecachte Einträge nach Änderungszeit, um eine schnelle Timeline zu erstellen (mtime spiegelt wider, wann das Objekt in den Cache geschrieben wurde):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Dateien, die mit f_ beginnen, enthalten HTTP-Response-Header gefolgt vom Body. Der Header-Block endet typischerweise mit \r\n\r\n. Nützliche Response-Header sind:
- Content-Type: Zur Ableitung des Medientyps
- Content-Location oder X-Original-URL: Originale Remote-URL zur Vorschau/Korrelation
- Content-Encoding: Kann gzip/deflate/br (Brotli) sein

Medien können extrahiert werden, indem Header und Body getrennt werden und ggf. entsprechend Content-Encoding dekomprimiert wird. Magic-Byte-Sniffing ist hilfreich, wenn Content-Type fehlt.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Funktion: Scannt rekursiv den Discord-Cache-Ordner, findet Webhook-/API-/Attachment-URLs, parst f_* Bodies, kann Medien carven und liefert HTML- + CSV-Timeline-Reports mit SHA‑256-Hashes.

Example CLI usage:
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
- --timeline: Gibt eine geordnete CSV-Timeline aus (nach modified time (mtime))
- --extra: Scannt außerdem benachbarte Caches (Code Cache und GPUCache)
- --carve: Carve media from raw bytes near regex hits (images/video)
- Output: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## Analystentipps

- Korrelieren Sie die modified time (mtime) von f_* und data_* Dateien mit den Aktivitätsfenstern von Benutzer/Angreifer, um eine Timeline zu rekonstruieren.
- Berechnen Sie SHA-256-Hashes der wiederhergestellten Medien und vergleichen Sie diese mit known-bad- oder exfil-Datensätzen.
- Extrahierte Webhook-URLs können auf Erreichbarkeit getestet oder erneuert werden; erwägen Sie, sie zu Blocklisten und retro-hunting Proxys hinzuzufügen.
- Der Cache bleibt nach “wiping” auf der Serverseite bestehen. Falls eine Akquisition möglich ist, erfassen Sie das gesamte Cache-Verzeichnis und die zugehörigen Sibling-Caches (Code Cache, GPUCache).

## Referenzen

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
