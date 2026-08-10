# iOS-Backup-Forensik (Messaging-zentrierte Triage)

Diese Seite beschreibt praktische Schritte zur Rekonstruktion und Analyse von iOS-Backups auf Hinweise zur Zustellung von 0-click exploits über Anhänge in Messaging-Apps. Der Schwerpunkt liegt darauf, Apples gehashte Backup-Struktur in menschenlesbare Pfade umzuwandeln und anschließend Anhänge in verbreiteten Apps aufzulisten und zu scannen.

Ziele:
- Lesbare Pfade aus Manifest.db rekonstruieren
- Messaging-Datenbanken auflisten (iMessage, WhatsApp, Signal, Telegram, Viber)
- Anhangspfade auflösen, eingebettete Objekte extrahieren, sofern unterstützt (PDF/Bilder/Fonts), und sie strukturellen Detektoren zuführen


## Rekonstruktion eines iOS-Backups

Unter MobileSync gespeicherte Backups verwenden gehashte Dateinamen, die nicht menschenlesbar sind. Die SQLite-Datenbank Manifest.db ordnet jedes gespeicherte Objekt seinem logischen Pfad zu.<sup>[[1]](#references)[[2]](#references)</sup>

Vorgehen auf hoher Ebene:
1) Manifest.db öffnen und die Dateieinträge auslesen (Domain, relativePath, Flags, fileID/Hash)
2) Die ursprüngliche Ordnerhierarchie basierend auf Domain + relativePath wiederherstellen
3) Jedes gespeicherte Objekt in seinen rekonstruierten Pfad kopieren oder hardlinken

Beispiel-Workflow mit einem Tool, das dies vollständig implementiert (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Hinweise:
- Entschlüssle verschlüsselte Backups, bevor du sie an ein Reconstruction-Tool übergibst; ElegantBouncer erwartet ein entschlüsseltes Backup.<sup>[[2]](#references)[[3]](#references)</sup>
- Bewahre nach Möglichkeit die ursprünglichen Zeitstempel/ACLs auf, um den Beweiswert zu erhalten

### Erfassen und Entschlüsseln des Backups (USB / Finder / libimobiledevice)

- Aktiviere in Finder/Apple Devices/iTunes die Option „Encrypt local backup“ und erstelle ein neues Backup; verschlüsselte Backups können gespeicherte Passwörter und Health-Daten enthalten, die unverschlüsselte Backups nicht enthalten.<sup>[[8]](#references)</sup>
- Plattformübergreifend: libimobiledevice 1.4.0 enthält Fixes für `idevicebackup2`.<sup>[[4]](#references)</sup> Aktiviere die Verschlüsselung interaktiv und erzwinge anschließend ein vollständiges Backup, indem du die dokumentierte Reihenfolge der Befehle verwendest und das Zielverzeichnis zuletzt angibst.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### IOC-gesteuerte Triage mit MVT

Amnestys Mobile Verification Toolkit kann einen Schlüssel aus verschlüsselten iTunes/Finder-Backups extrahieren und diese entschlüsseln. Anschließend kann es das entschlüsselte Backup mit einer STIX2-IOC-Datei scannen.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Mit `-o` werden JSON-Ergebnisse unter `/tmp/mvt-results/` geschrieben; IOC matches verwenden das Suffix `_detected` und können mit den unten wiederhergestellten Attachment-Pfaden korreliert werden.<sup>[[3]](#references)</sup>

### Allgemeines Artefakt-Parsing (iLEAPP)

Für Timeline-/Metadatenanalysen über Messaging hinaus kann iLEAPP auf den Ordner mit dem Raw-Backup angewendet werden; sein `itunes`-Eingabetyp akzeptiert iTunes-/Finder-Backups, und aktuelle Releases unterstützen iOS/iPadOS 11 bis zu den aktuellen Versionen.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Aufzählung von Anhängen in Messaging-Apps

Nach der Rekonstruktion werden Anhänge für beliebte Apps aufgelistet. Das genaue Schema variiert je nach App/Version, aber der Ansatz ist ähnlich: die Messaging-Datenbank abfragen, Nachrichten mit Anhängen verknüpfen und Pfade auf dem Datenträger auflösen.<sup>[[1]](#references)[[2]](#references)</sup>

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
Anhangspfade können absolut oder relativ zum rekonstruierten Baum unter Library/SMS/Attachments sein.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Übliche Verknüpfung: message table ↔ media/attachment table (die Benennung variiert je nach Version). Frage media rows ab, um die Pfade auf dem Datenträger zu ermitteln. Belkasoft identifiziert `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` als Speicherort der Mediendatei; die aktuelle Implementierung von ElegantBouncer verknüpft `ZWAMEDIAITEM.ZMESSAGE` mit `ZWAMESSAGE.Z_PK` und stellt `Message/` voran, wenn ein mit `Media/` beginnender Pfad aufgelöst wird.<sup>[[9]](#references)[[10]](#references)</sup>
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
Für diesen ElegantBouncer-Rekonstruktionspfad wird ein mit `Media/` beginnender Medienpfad unter `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` aufgelöst; der Leitfaden von Belkasoft dokumentiert dagegen einen `Messages/Media/`-Pfad. Untersuche daher das Backup, bevor du eine der beiden Schreibweisen annimmst.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: Die Nachrichten-Datenbank ist verschlüsselt; auf der Festplatte zwischengespeicherte Anhänge (und Thumbnails) lassen sich jedoch normalerweise scannen.<sup>[[2]](#references)</sup>
- Telegram: Untersuche die Medien-/Cache-Verzeichnisse der App; Telegram dokumentierte einen Fehler bei der Cache-Bereinigung in der iOS-App 11.2 unter iOS 18.0.1, der in Version 11.3 als behoben markiert wurde. Suche daher nach verbliebenen Dateien.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite enthält Tabellen für Nachrichten/Anhänge mit Verweisen auf Dateien auf der Festplatte.<sup>[[2]](#references)</sup>

Tipp: Selbst wenn Metadaten verschlüsselt sind, können beim Scannen der Medien-/Cache-Verzeichnisse weiterhin schädliche Objekte gefunden werden.<sup>[[2]](#references)</sup>


## Anhänge auf strukturelle Exploits scannen

Sobald du die Pfade der Anhänge hast, übergib sie strukturellen Detektoren, die Dateiformat-Invarianten anstelle von Signaturen validieren. Beispiel mit ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
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
- TrueType TRIANGULATION (CVE‑2023‑41990): undokumentierte Bytecode-OpCodes
- DNG/TIFF CVE‑2025‑43300: Nichtübereinstimmungen zwischen Metadaten- und Stream-Komponenten


## Validierung, Einschränkungen und Falschpositive

- Zeitumrechnungen: iMessage speichert Datumsangaben in einigen Versionen in Apple-Epochen/-Einheiten; bei der Berichterstattung entsprechend umrechnen.<sup>[[2]](#references)</sup>
- Schemaänderungen: Die SQLite-Schemas von Apps ändern sich im Laufe der Zeit; Tabellen- und Spaltennamen für den jeweiligen Device-Build bestätigen
- Rekursive Extraktion: PDFs können JBIG2-Streams und Fonts einbetten; einen Parser verwenden, der innere Objekte extrahieren und scannen kann
- Falschpositive: Strukturelle Heuristiken sind konservativ, können aber seltene, fehlerhafte und dennoch harmlose Medien erkennen.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Wenn Sie die Samples nicht erhalten können, die Bedrohung aber trotzdem erkennen müssen](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer-Projekt (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT-iOS-Backup-Workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Versionshinweise zu libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 hat die Cache-Bereinigung unter iOS 18.0.1 beschädigt (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2-Handbuch](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP-Projekt (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Informationen zu verschlüsselten Backups auf Ihrem iPhone, iPad oder iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS-WhatsApp-Forensik mit Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer-WhatsApp-Scanner und Pfadauflöser](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
