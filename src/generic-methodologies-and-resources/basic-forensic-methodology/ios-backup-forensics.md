# iOS Backup‑Forensik (Messaging‑zentrierte Triage)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite beschreibt praktische Schritte, um iOS‑Backups zu rekonstruieren und zu analysieren, um Hinweise auf 0‑click exploit delivery via Anhänge von Messaging‑Apps zu finden. Sie konzentriert sich darauf, Apples gehashte Backup‑Struktur in menschenlesbare Pfade umzuwandeln und anschließend Anhänge in gängigen Apps zu enumerieren und zu scannen.

Ziele:
- Lesbare Pfade aus Manifest.db rekonstruieren
- Messaging‑Datenbanken enumerieren (iMessage, WhatsApp, Signal, Telegram, Viber)
- Pfade zu Anhängen auflösen, eingebettete Objekte extrahieren (PDF/Bilder/Schriftarten) und diese an Struktur‑Detektoren übergeben


## Rekonstruktion eines iOS‑Backups

Unter MobileSync gespeicherte Backups verwenden gehashte Dateinamen, die nicht menschenlesbar sind. Die SQLite‑Datenbank Manifest.db ordnet jedes gespeicherte Objekt seinem logischen Pfad zu.

Überblick über das Vorgehen:
1) Manifest.db öffnen und die Dateieinträge lesen (domain, relativePath, flags, fileID/hash)
2) Die ursprüngliche Ordnerhierarchie basierend auf domain + relativePath rekonstruieren
3) Jedes gespeicherte Objekt zu seinem rekonstruierten Pfad kopieren oder per hardlink verknüpfen

Beispielworkflow mit einem Tool, das dies Ende‑zu‑Ende implementiert (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Hinweise:
- Verarbeite verschlüsselte Backups, indem du dem Extractor das Backup-Passwort bereitstellst
- Bewahre, wenn möglich, originale Zeitstempel/ACLs für Beweiszwecke

### Erfassung & Entschlüsselung des Backups (USB / Finder / libimobiledevice)

- Unter macOS/Finder setze "Encrypt local backup" und erstelle ein *frisches* verschlüsseltes Backup, damit keychain items vorhanden sind.
- Plattformübergreifend: `idevicebackup2` (libimobiledevice ≥1.4.0) unterstützt die Backup‑Protokolländerungen von iOS 17/18 und behebt frühere Restore-/Backup‑Handshake‑Fehler.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑gesteuerte Triage mit MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) arbeitet jetzt direkt mit verschlüsselten iTunes/Finder-Backups und automatisiert die Entschlüsselung sowie das IOC-Matching für Fälle kommerzieller Spyware.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Outputs land under `mvt-results/` (e.g., analytics_detected.json, safari_history_detected.json) and can be correlated with the attachment paths recovered below.

### Allgemeine Artefaktanalyse (iLEAPP)

Für Timeline-/Metadaten über Messaging hinaus führe iLEAPP direkt im Backup-Ordner aus (unterstützt iOS 11‑17 Schemata):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Aufzählung von Anhängen in Messaging-Apps

Nach der Rekonstruktion Anhänge beliebter Apps auflisten. Das genaue Schema variiert je nach App/Version, aber das Vorgehen ist ähnlich: die Messaging-Datenbank abfragen, Nachrichten mit Anhängen verknüpfen und Pfade auf der Festplatte auflösen.

### iMessage (sms.db)
Wichtige Tabellen: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Beispielabfragen:
```sql
-- List attachments with basic message linkage
SELECT
m.ROWID            AS message_rowid,
a.ROWID            AS attachment_rowid,
a.filename         AS attachment_path,
m.handle_id,
m.date,
m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
c.display_name,
a.filename AS attachment_path,
m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```
Attachment-Pfade können absolut sein oder relativ zum rekonstruierten Baum unter Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Typische Verknüpfung: message-Tabelle ↔ media/attachment-Tabelle (Benennung variiert je nach Version). Media-Zeilen abfragen, um die Pfade auf dem Datenträger zu erhalten. Neuere iOS-Builds geben weiterhin `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` preis.
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Pfade liegen üblicherweise unter `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` innerhalb des rekonstruierten Backups.

### Signal / Telegram / Viber
- Signal: die Nachrichten‑DB ist verschlüsselt; Anlagen, die auf der Festplatte zwischengespeichert sind (und Thumbnails), sind jedoch normalerweise durchsuchbar
- Telegram: Cache verbleibt unter `Library/Caches/` innerhalb der Sandbox; iOS 18‑Builds zeigen cache‑clearing bugs, sodass große verbliebene Medien‑Caches häufige Beweisquellen sind
- Viber: Viber.sqlite enthält Nachrichten-/Anhangtabellen mit Referenzen auf dem Datenträger

Tipp: Selbst wenn Metadaten verschlüsselt sind, fördert das Scannen der media/cache‑Verzeichnisse weiterhin bösartige Objekte zutage.


## Scannen von Anhängen auf strukturelle Exploits

Sobald Sie Pfade zu Anhängen haben, geben Sie diese in strukturelle Scanner ein, die Dateiformat‑Invarianten anstatt Signaturen validieren. Beispiel mit ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Erkennungen, die von strukturellen Regeln abgedeckt werden, umfassen:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): impossible JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata vs. stream component mismatches


## Validierung, Einschränkungen und Fehlalarme

- Zeitkonvertierungen: iMessage speichert Daten in Apple-Epochen/-Einheiten in einigen Versionen; bei der Berichterstattung entsprechend konvertieren
- Schema-Drift: App-SQLite-Schemata ändern sich im Laufe der Zeit; Tabellen- und Spaltennamen für jeden Geräte-Build bestätigen
- Rekursive Extraktion: PDFs können JBIG2-Streams und Fonts einbetten; innere Objekte extrahieren und scannen
- Fehlalarme: Strukturelle Heuristiken sind konservativ, können aber seltene, fehlerhafte, jedoch harmlose Medien als verdächtig markieren


## Quellen

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
