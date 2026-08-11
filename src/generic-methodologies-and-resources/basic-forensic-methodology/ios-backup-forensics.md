# iOS-Backup-Forensik (Messaging-zentrierte Triage)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite beschreibt praktische Schritte zur Rekonstruktion und Analyse von iOS-Backups auf Anzeichen für die Zustellung von 0-click-Exploits über Anhänge in Messaging-Apps. Der Schwerpunkt liegt darauf, Apples gehashte Backup-Struktur in menschenlesbare Pfade umzuwandeln und anschließend Anhänge in gängigen Apps aufzulisten und zu scannen.

Ziele:
- Lesbare Pfade aus Manifest.db wiederherstellen
- Messaging-Datenbanken (iMessage, WhatsApp, Signal, Telegram, Viber) auflisten
- Anhangspfade auflösen, eingebettete Objekte extrahieren, sofern unterstützt (PDF/Bilder/Schriftarten), und sie strukturellen Detektoren zuführen


## Rekonstruieren eines iOS-Backups

Backups unter MobileSync verwenden gehashte Dateinamen, die nicht menschenlesbar sind. Die SQLite-Datenbank Manifest.db ordnet jedes gespeicherte Objekt seinem logischen Pfad zu.<sup>[[1]](#references)[[2]](#references)</sup>

Vorgehensweise auf hoher Ebene:
1) Manifest.db öffnen und die Dateieinträge auslesen (Domain, relativePath, flags, fileID/Hash)
2) Die ursprüngliche Ordnerhierarchie anhand von Domain + relativePath wiederherstellen
3) Jedes gespeicherte Objekt in seinen rekonstruierten Pfad kopieren oder hart verknüpfen

Beispiel-Workflow mit einem Tool, das dies vollständig umsetzt (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Hinweise:
- Entschlüsseln Sie verschlüsselte Backups, bevor Sie sie an ein Rekonstruktions-Tool übergeben; ElegantBouncer erwartet ein entschlüsseltes Backup.<sup>[[2]](#references)[[3]](#references)</sup>
- Bewahren Sie nach Möglichkeit die ursprünglichen Zeitstempel/ACLs für den Beweiswert

### Erfassung und Entschlüsselung des Backups (USB / Finder / libimobiledevice)

- Aktivieren Sie in Finder/Apple Devices/iTunes die Option „Lokales Backup verschlüsseln“ und erstellen Sie ein neues Backup; verschlüsselte Backups können gespeicherte Passwörter und Health-Daten enthalten, die bei unverschlüsselten Backups fehlen.<sup>[[8]](#references)</sup>
- Plattformübergreifend: libimobiledevice 1.4.0 enthält Fehlerbehebungen für `idevicebackup2`.<sup>[[4]](#references)</sup> Aktivieren Sie die Verschlüsselung interaktiv und erzwingen Sie anschließend ein vollständiges Backup, indem Sie die dokumentierte Befehlsreihenfolge verwenden und das Zielverzeichnis zuletzt angeben.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### IOC-basierte Triage mit MVT

Amnesty’s Mobile Verification Toolkit kann einen Schlüssel aus verschlüsselten iTunes/Finder-Backups extrahieren und diese entschlüsseln. Anschließend kann es das entschlüsselte Backup mit einer STIX2-IOC-Datei scannen.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Mit `-o` werden JSON-Ergebnisse unter `/tmp/mvt-results/` gespeichert; IOC-Treffer verwenden das Suffix `_detected` und können mit den unten wiederhergestellten Pfaden der Anhänge abgeglichen werden.<sup>[[3]](#references)</sup>

### Allgemeine Artefaktanalyse (iLEAPP)

Für Zeitachsen/Metadaten über Messaging hinaus führen Sie iLEAPP für den Ordner mit dem raw Backup aus; sein Eingabetyp `itunes` akzeptiert iTunes-/Finder-Backups, und aktuelle Releases unterstützen iOS/iPadOS 11 bis zu den aktuellen Versionen.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Aufzählung von Anhängen in Messaging-Apps

Nach der Rekonstruktion werden Anhänge für beliebte Apps aufgezählt. Das genaue Schema variiert je nach App/Version, aber der Ansatz ist ähnlich: Die Messaging-Datenbank abfragen, Nachrichten mit Anhängen verknüpfen und Pfade auf dem Datenträger auflösen.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Wichtige Tabellen: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Pfade zu Anhängen können absolut oder relativ zum rekonstruierten Baum unter Library/SMS/Attachments sein.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Übliche Verknüpfung: Nachrichtentabelle ↔ Medien-/Anhangstabelle (Benennung variiert je nach Version). Frage die Medienzeilen ab, um die Pfade auf der Festplatte zu erhalten. Belkasoft identifiziert `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` als Speicherort der Mediendatei; die aktuelle Implementierung von ElegantBouncer verknüpft `ZWAMEDIAITEM.ZMESSAGE` mit `ZWAMESSAGE.Z_PK` und stellt `Message/` voran, wenn ein Pfad aufgelöst wird, der mit `Media/` beginnt.<sup>[[9]](#references)[[10]](#references)</sup>
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Für diesen ElegantBouncer-Rekonstruktionspfad wird ein mit `Media/` beginnender Medienpfad unter `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` aufgelöst; der Leitfaden von Belkasoft dokumentiert stattdessen einen Pfad `Messages/Media/`. Untersuchen Sie daher das Backup, bevor Sie eine der beiden Schreibweisen voraussetzen.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: Die Nachrichten-DB ist verschlüsselt; Anhänge, die auf dem Datenträger zwischengespeichert sind (ebenso wie Vorschaubilder), lassen sich jedoch normalerweise scannen.<sup>[[2]](#references)</sup>
- Telegram: Untersuchen Sie die Medien-/Cache-Verzeichnisse der App; Telegram dokumentierte einen Fehler bei der Cache-Bereinigung in der iOS-App 11.2 unter iOS 18.0.1, der in 11.3 als behoben markiert wurde. Prüfen Sie daher auf verbliebene Dateien.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite enthält Tabellen für Nachrichten/Anhänge mit Verweisen auf dem Datenträger.<sup>[[2]](#references)</sup>

Tipp: Selbst wenn Metadaten verschlüsselt sind, werden beim Scannen der Medien-/Cache-Verzeichnisse weiterhin bösartige Objekte sichtbar.<sup>[[2]](#references)</sup>


## Anhänge auf strukturelle Exploits scannen

Sobald Sie die Pfade der Anhänge haben, übergeben Sie sie an strukturelle Detektoren, die Dateiformat-Invarianten anstelle von Signaturen validieren. Beispiel mit ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Durch strukturelle Regeln abgedeckte Erkennungen umfassen:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): unmögliche JBIG2-Wörterbuchzustände
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): übergroße Huffman-Tabellenkonstruktionen
- TrueType TRIANGULATION (CVE‑2023‑41990): undokumentierte Bytecode-Opcode
- DNG/TIFF CVE‑2025‑43300: Nichtübereinstimmungen zwischen Metadaten- und Stream-Komponenten


## Validierung, Einschränkungen und False Positives

- Zeitkonvertierungen: iMessage speichert Datumsangaben in einigen Versionen mit Apple-Epochen/Einheiten; bei der Berichterstellung entsprechend konvertieren.<sup>[[2]](#references)</sup>
- Schema Drift: Die SQLite-Schemas von Apps ändern sich im Laufe der Zeit; Tabellen- und Spaltennamen für den jeweiligen Device-Build bestätigen
- Rekursive Extraktion: PDFs können JBIG2-Streams und Fonts einbetten; einen Parser verwenden, der innere Objekte extrahieren und scannen kann
- False Positives: Strukturelle Heuristiken sind konservativ, können jedoch seltene, fehlerhafte, aber harmlose Medien kennzeichnen.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Wenn Sie die Samples nicht erhalten können, die Bedrohung aber trotzdem erkennen müssen](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer-Projekt (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS-Backup-Workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 Release Notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 hat die Cache-Bereinigung unter iOS 18.0.1 beschädigt (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2-Handbuch](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP-Projekt (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Informationen zu verschlüsselten Backups auf Ihrem iPhone, iPad oder iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics mit Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp-Scanner und Pfadauflöser](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
