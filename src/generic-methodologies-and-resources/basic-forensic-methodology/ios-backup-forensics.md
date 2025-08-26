# iOS-Backup-Forensik (Messaging‑zentrierte Triage)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite beschreibt praktische Schritte, um iOS-Backups zu rekonstruieren und zu analysieren, um Hinweise auf 0‑Click-Exploit‑Lieferungen über Messaging‑App‑Anhänge zu finden. Der Fokus liegt darauf, Apples gehashte Backup-Struktur in menschenlesbare Pfade zu überführen und anschließend Anhänge in gängigen Apps zu enumerieren und zu scannen.

Ziele:
- Lesbare Pfade aus Manifest.db rekonstruieren
- Messaging‑Datenbanken aufzählen (iMessage, WhatsApp, Signal, Telegram, Viber)
- Anhangspfade auflösen, eingebettete Objekte extrahieren (PDF/Bilder/Schriftarten) und sie an strukturelle Detektoren weiterleiten


## Rekonstruktion eines iOS-Backups

Backups, die unter MobileSync gespeichert sind, verwenden gehashte Dateinamen, die nicht menschenlesbar sind. Die Manifest.db SQLite‑Datenbank ordnet jedes gespeicherte Objekt seinem logischen Pfad zu.

Vorgehensweise im Überblick:
1) Öffne Manifest.db und lese die Dateieinträge (domain, relativePath, flags, fileID/hash)  
2) Erstelle die ursprüngliche Ordnerhierarchie basierend auf domain + relativePath wieder  
3) Kopiere oder erstelle Hardlinks für jedes gespeicherte Objekt an seinem rekonstruierten Pfad

Beispiel-Workflow mit einem Tool, das dies End-to-End umsetzt (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notizen:
- Verschlüsselte Backups behandeln, indem Sie das Backup-Passwort an Ihr Extractor übergeben
- Bewahren Sie nach Möglichkeit ursprüngliche Zeitstempel/ACLs zur Beweissicherung


## Aufzählung von Anhängen in Messaging-Apps

Nach der Rekonstruktion sollten Sie Anhänge beliebter Apps auflisten. Das genaue Schema variiert je nach App/Version, aber der Ansatz ist ähnlich: die Messaging-Datenbank abfragen, Nachrichten mit Anhängen verknüpfen und Pfade auf der Festplatte ermitteln.

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
Pfade zu Anhängen können absolut sein oder relativ zum rekonstruierten Verzeichnisbaum unter Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Häufige Verknüpfung: message table ↔ media/attachment table (Benennung variiert je nach Version). Abfragen der media‑Zeilen, um Pfade auf dem Datenträger zu erhalten.

Beispiel (generisch):
```sql
SELECT
m.Z_PK          AS message_pk,
mi.ZMEDIALOCALPATH AS media_path,
m.ZMESSAGEDATE  AS message_date
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Passen Sie Tabellen-/Spaltennamen an Ihre App-Version an (ZWAMESSAGE/ZWAMEDIAITEM sind in iOS-Builds häufig).

### Signal / Telegram / Viber
- Signal: die message DB ist verschlüsselt; Anhänge, die auf der Festplatte zwischengespeichert sind (und Thumbnails), sind jedoch normalerweise durchsuchbar
- Telegram: Cache‑Verzeichnisse (photo/video/document caches) untersuchen und, wenn möglich, den Chats zuordnen
- Viber: Viber.sqlite enthält message/attachment-Tabellen mit Verweisen auf der Festplatte

Tipp: Selbst wenn Metadaten verschlüsselt sind, fördert das Scannen der media/cache-Verzeichnisse weiterhin bösartige Objekte zutage.


## Scannen von Anhängen auf strukturelle Exploits

Sobald Sie Pfade zu Anhängen haben, geben Sie diese an strukturelle Detektoren, die Dateiformat‑Invarianten statt Signaturen validieren. Beispiel mit ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Von strukturellen Regeln abgedeckte Erkennungen umfassen:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): unmögliche JBIG2-Wörterbuchzustände
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): überdimensionierte Huffman-Tabellenaufbauten
- TrueType TRIANGULATION (CVE‑2023‑41990): undokumentierte Bytecode-Opcodes
- DNG/TIFF CVE‑2025‑43300: Unstimmigkeiten zwischen Metadaten und Stream-Komponenten


## Validierung, Vorbehalte und false positives

- Zeitkonversionen: iMessage speichert Datumsangaben in Apple-Epochen/-Einheiten in einigen Versionen; bei der Berichterstattung entsprechend umrechnen
- Schema-Drift: App SQLite-Schemata ändern sich im Laufe der Zeit; prüfen Sie die Tabellen-/Spaltennamen je nach Geräte-Build
- Rekursive Extraktion: PDFs können JBIG2-Streams und Fonts einbetten; innere Objekte extrahieren und scannen
- False positives: strukturelle Heuristiken sind konservativ, können aber seltene, fehlerhafte, aber harmlose Medien markieren


## Referenzen

- [ELEGANTBOUNCER: Wenn Sie die Samples nicht bekommen können, aber die Bedrohung trotzdem nachweisen müssen](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer-Projekt (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
