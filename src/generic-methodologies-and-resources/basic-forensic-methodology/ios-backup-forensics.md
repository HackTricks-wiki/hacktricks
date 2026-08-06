# iOS Backup Forensics (triage με επίκεντρο τα Messaging apps)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα περιγράφει πρακτικά βήματα για την ανακατασκευή και ανάλυση iOS backups, με στόχο τον εντοπισμό ενδείξεων παράδοσης 0-click exploit μέσω συνημμένων σε messaging apps. Εστιάζει στη μετατροπή της hashed διάταξης backup της Apple σε paths που είναι κατανοητά από τον άνθρωπο και, στη συνέχεια, στην απαρίθμηση και σάρωση συνημμένων σε common apps.

Στόχοι:
- Ανακατασκευή αναγνώσιμων paths από το Manifest.db
- Απαρίθμηση messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Επίλυση των paths των συνημμένων, εξαγωγή embedded objects (PDF/Images/Fonts) και τροφοδότησή τους σε structural detectors


## Ανακατασκευή ενός iOS backup

Τα backups που αποθηκεύονται στο MobileSync χρησιμοποιούν hashed filenames που δεν είναι αναγνώσιμα από τον άνθρωπο. Η SQLite database Manifest.db αντιστοιχίζει κάθε αποθηκευμένο object στο logical path του.

Διαδικασία υψηλού επιπέδου:
1) Άνοιγμα του Manifest.db και ανάγνωση των file records (domain, relativePath, flags, fileID/hash)
2) Αναδημιουργία της αρχικής folder hierarchy με βάση τα domain + relativePath
3) Αντιγραφή ή δημιουργία hardlink κάθε αποθηκευμένου object στο reconstructed path

Παράδειγμα workflow με ένα tool που υλοποιεί τη διαδικασία end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Σημειώσεις:
- Διαχειριστείτε τα encrypted backups παρέχοντας τον κωδικό πρόσβασης του backup στον extractor σας
- Διατηρήστε, όπου είναι δυνατόν, τα αρχικά timestamps/ACLs για αποδεικτική αξία

### Απόκτηση και αποκρυπτογράφηση του backup (USB / Finder / libimobiledevice)

- Σε macOS/Finder ενεργοποιήστε το "Encrypt local backup" και δημιουργήστε ένα *νέο* encrypted backup, ώστε να περιλαμβάνονται τα στοιχεία του keychain.
- Cross-platform: το `idevicebackup2` (libimobiledevice ≥1.4.0) υποστηρίζει τις αλλαγές στο backup protocol των iOS 17/18 και διορθώνει παλαιότερα σφάλματα handshake κατά το restore/backup.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage βάσει IOC με το MVT

Το Mobile Verification Toolkit (mvt-ios) της Amnesty λειτουργεί πλέον απευθείας με κρυπτογραφημένα iTunes/Finder backups, αυτοματοποιώντας την αποκρυπτογράφηση και την αντιστοίχιση IOC σε περιπτώσεις mercenary spyware.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Τα outputs αποθηκεύονται στο `mvt-results/` (π.χ. `analytics_detected.json`, `safari_history_detected.json`) και μπορούν να συσχετιστούν με τα attachment paths που ανακτήθηκαν παρακάτω.

### General artifact parsing (iLEAPP)

Για timeline/metadata πέρα από τα messaging, εκτελέστε το iLEAPP απευθείας στον backup folder (υποστηρίζει schemas iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Απαρίθμηση συνημμένων εφαρμογών ανταλλαγής μηνυμάτων

Μετά την ανακατασκευή, απαριθμήστε τα συνημμένα για δημοφιλείς εφαρμογές. Το ακριβές schema διαφέρει ανά εφαρμογή/έκδοση, αλλά η προσέγγιση είναι παρόμοια: εκτελέστε query στη βάση δεδομένων ανταλλαγής μηνυμάτων, συνδέστε τα messages με τα attachments και επιλύστε τα paths στον δίσκο.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Βασικοί πίνακες: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Παραδείγματα queries:
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
Οι διαδρομές των συνημμένων μπορεί να είναι απόλυτες ή σχετικές με το ανακατασκευασμένο δέντρο στο Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Συνηθισμένη σύνδεση: message table ↔ media/attachment table (η ονομασία διαφέρει ανά έκδοση). Εκτελέστε query στις γραμμές του media για να λάβετε τις paths στον δίσκο. Οι πρόσφατες εκδόσεις iOS εξακολουθούν να εκθέτουν το `ZMEDIALOCALPATH` στο `ZWAMEDIAITEM`.
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
Τα paths συνήθως επιλύονται κάτω από το `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` μέσα στο reconstructed backup.

### Signal / Telegram / Viber
- Signal: η message DB είναι encrypted· ωστόσο, τα attachments που έχουν γίνει cached στον δίσκο (καθώς και τα thumbnails) είναι συνήθως scan-able
- Telegram: το cache παραμένει κάτω από το `Library/Caches/` μέσα στο sandbox· τα iOS 18 builds παρουσιάζουν bugs εκκαθάρισης cache, επομένως τα μεγάλα residual media caches αποτελούν συχνές πηγές evidence<sup>[[5]](#references)</sup>
- Viber: το Viber.sqlite περιέχει πίνακες μηνυμάτων/attachments με references που δείχνουν στον δίσκο

Συμβουλή: ακόμη και όταν τα metadata είναι encrypted, το scanning των media/cache directories εξακολουθεί να εντοπίζει malicious objects.


## Scanning attachments για structural exploits

Μόλις αποκτήσετε τα paths των attachments, περάστε τα σε structural detectors που επικυρώνουν τα invariants του file format αντί για signatures. Παράδειγμα με ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Οι ανιχνεύσεις που καλύπτονται από structural rules περιλαμβάνουν:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): αδύνατες καταστάσεις λεξικών JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): υπερμεγέθεις κατασκευές πινάκων Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): μη τεκμηριωμένοι κωδικοί bytecode
- DNG/TIFF CVE‑2025‑43300: ασυμφωνίες μεταξύ μεταδεδομένων και στοιχείων stream


## Επικύρωση, επισημάνσεις και false positives

- Μετατροπές χρόνου: το iMessage αποθηκεύει ημερομηνίες σε Apple epochs/μονάδες σε ορισμένες εκδόσεις· πραγματοποιήστε την κατάλληλη μετατροπή κατά την αναφορά
- Schema drift: τα SQLite schemas των εφαρμογών αλλάζουν με την πάροδο του χρόνου· επιβεβαιώστε τα ονόματα των πινάκων/στηλών ανά build συσκευής
- Recursive extraction: τα PDF ενδέχεται να ενσωματώνουν streams JBIG2 και fonts· εξαγάγετε και σαρώστε τα εσωτερικά objects
- False positives: τα structural heuristics είναι συντηρητικά, αλλά ενδέχεται να επισημάνουν σπάνια, κατεστραμμένα αλλά καλοήθη media<sup>[[1]](#references)[[2]](#references)</sup>


## Αναφορές

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
