# iOS Backup Forensics (Messaging-zentrierte Triage)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite beschreibt praktische Schritte zur Rekonstruktion und Analyse von iOS-Backups auf Hinweise für die Zustellung von 0-click exploits über Anhänge in Messaging-Apps. Der Fokus liegt darauf, das gehashte Backup-Layout von Apple in lesbare Pfade umzuwandeln und anschließend Anhänge in verbreiteten Apps aufzulisten und zu scannen.

Ziele:
- Lesbare Pfade aus Manifest.db wiederherstellen
- Messaging-Datenbanken (iMessage, WhatsApp, Signal, Telegram, Viber) auflisten
- Pfade zu Anhängen auflösen, eingebettete Objekte (PDF/Bilder/Schriftarten) extrahieren und an strukturelle Detektoren übergeben


## Rekonstruktion eines iOS-Backups

Unter MobileSync gespeicherte Backups verwenden gehashte Dateinamen, die nicht lesbar sind. Die SQLite-Datenbank Manifest.db ordnet jedes gespeicherte Objekt seinem logischen Pfad zu.

Übergeordnetes Vorgehen:
1) Manifest.db öffnen und die Dateieinträge auslesen (domain, relativePath, flags, fileID/hash)
2) Die ursprüngliche Ordnerhierarchie auf Grundlage von domain + relativePath wiederherstellen
3) Jedes gespeicherte Objekt in seinen rekonstruierten Pfad kopieren oder hart verlinken

Beispiel-Workflow mit einem Tool, das diesen Vorgang durchgängig implementiert (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Hinweise:
- Verarbeite verschlüsselte Backups, indem du das Backup-Passwort an deinen Extraktor übergibst
- Bewahre nach Möglichkeit die ursprünglichen Zeitstempel/ACLs auf, um den Beweiswert zu erhalten

### Erfassen und Entschlüsseln des Backups (USB / Finder / libimobiledevice)

- Aktiviere unter macOS/Finder „Encrypt local backup“ und erstelle ein *neues* verschlüsseltes Backup, damit keychain-Elemente vorhanden sind.
- Plattformübergreifend versteht `idevicebackup2` (libimobiledevice ≥1.4.0) die Änderungen am iOS-17/18-Backup-Protokoll und behebt frühere Fehler beim Restore-/Backup-Handshake.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC-gesteuerte Triage mit MVT

Amnestys Mobile Verification Toolkit (mvt-ios) funktioniert jetzt direkt mit verschlüsselten iTunes/Finder-Backups und automatisiert die Entschlüsselung sowie den IOC-Abgleich für Fälle mit mercenary spyware.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Die Ergebnisse werden unter `mvt-results/` abgelegt (z. B. `analytics_detected.json`, `safari_history_detected.json`) und können mit den unten wiederhergestellten Anhangspfaden korreliert werden.

### Allgemeine Artektanalyse (iLEAPP)

Für eine Zeitleiste/Metadaten über Messaging hinaus führe iLEAPP direkt für den Backup-Ordner aus (unterstützt iOS-11‑17-Schemas):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Aufzählung von Anhängen in Messaging-Apps

Nach der Rekonstruktion werden Anhänge für beliebte Apps aufgezählt. Das genaue Schema variiert je nach App/Version, aber der Ansatz ist ähnlich: die Messaging-Datenbank abfragen, Nachrichten mit Anhängen verknüpfen und Pfade auf dem Datenträger auflösen.<sup>[[1]](#references)[[2]](#references)</sup>

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
Anhangspfade können absolut oder relativ zum rekonstruierten Verzeichnisbaum unter Library/SMS/Attachments/ sein.

### WhatsApp (ChatStorage.sqlite)
Häufige Verknüpfung: message table ↔ media/attachment table (die Benennung variiert je nach Version). Frage die media rows ab, um die Pfade auf der Festplatte zu ermitteln. Neuere iOS-Builds stellen weiterhin `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` bereit.
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
Pfade werden im rekonstruierten Backup normalerweise unter `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` aufgelöst.

### Signal / Telegram / Viber
- Signal: Die Nachrichten-DB ist verschlüsselt; auf der Festplatte zwischengespeicherte Anhänge (und Thumbnails) lassen sich jedoch normalerweise scannen
- Telegram: Der Cache verbleibt unter `Library/Caches/` innerhalb der Sandbox; iOS-18-Builds weisen Fehler beim Löschen des Caches auf, daher sind große, verbleibende Medien-Caches häufige Beweisquellen<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite enthält Nachrichten-/Anhangtabellen mit Verweisen auf der Festplatte

Tipp: Selbst wenn Metadaten verschlüsselt sind, lassen sich durch das Scannen der Medien-/Cache-Verzeichnisse weiterhin schädliche Objekte finden.


## Anhänge auf strukturelle Exploits scannen

Sobald du Pfade zu Anhängen hast, übergib sie strukturellen Detektoren, die Dateiformat-Invarianten anstelle von Signaturen validieren. Beispiel mit ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Durch strukturelle Regeln abgedeckte Erkennungen umfassen:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): unmögliche JBIG2-Dictionary-Zustände
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): übergroße Huffman-Table-Konstruktionen
- TrueType TRIANGULATION (CVE‑2023‑41990): nicht dokumentierte Bytecode-Opcodes
- DNG/TIFF CVE‑2025‑43300: Nichtübereinstimmungen zwischen Metadaten- und Stream-Komponenten


## Validierung, Einschränkungen und False Positives

- Zeitkonvertierungen: iMessage speichert Datumsangaben in einigen Versionen mit Apple-Epochen/-Einheiten; bei der Berichterstellung entsprechend konvertieren
- Schema Drift: SQLite-Schemas von Apps ändern sich im Laufe der Zeit; Tabellen-/Spaltennamen für den jeweiligen Device-Build bestätigen
- Rekursive Extraktion: PDFs können JBIG2-Streams und Fonts einbetten; innere Objekte extrahieren und scannen
- False Positives: Strukturelle Heuristiken sind konservativ, können aber seltene, fehlerhafte und dennoch harmlose Medien markieren<sup>[[1]](#references)[[2]](#references)</sup>


## Referenzen

- [1] [ELEGANTBOUNCER: Wenn Sie die Samples nicht bekommen können, die Bedrohung aber trotzdem erkennen müssen](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS-Backup-Workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 behebt die Cache-Bereinigung unter iOS 18.0.1 nicht (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
