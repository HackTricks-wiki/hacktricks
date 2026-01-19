# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα περιγράφει πρακτικά βήματα για την ανακατασκευή και ανάλυση αντιγράφων iOS για ενδείξεις παράδοσης 0‑click exploit μέσω επισυναπτόμενων αρχείων εφαρμογών μηνυμάτων. Εστιάζει στη μετατροπή της hashed διάταξης αντιγράφων της Apple σε μονοπάτια αναγνώσιμα από άνθρωπο, και στη συνέχεια στην καταγραφή και σάρωση επισυναπτόμενων αρχείων σε κοινές εφαρμογές.

Goals:
- Ανακατασκευή αναγνώσιμων διαδρομών από Manifest.db
- Καταγραφή βάσεων δεδομένων μηνυμάτων (iMessage, WhatsApp, Signal, Telegram, Viber)
- Επίλυση διαδρομών επισυναπτόμενων, εξαγωγή ενσωματωμένων αντικειμένων (PDF/Images/Fonts) και παροχή τους σε structural detectors


## Reconstructing an iOS backup

Τα αντίγραφα που αποθηκεύονται κάτω από MobileSync χρησιμοποιούν ονόματα αρχείων με hash που δεν είναι αναγνώσιμα από άνθρωπο. Η βάση δεδομένων Manifest.db SQLite αντιστοιχίζει κάθε αποθηκευμένο αντικείμενο στη λογική του διαδρομή.

High‑level procedure:
1) Open Manifest.db and read the file records (domain, relativePath, flags, fileID/hash)
2) Recreate the original folder hierarchy based on domain + relativePath
3) Copy or hardlink each stored object to its reconstructed path

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Σημειώσεις:
- Διαχειριστείτε κρυπτογραφημένα αντίγραφα ασφαλείας παρέχοντας τον κωδικό του backup στον extractor σας
- Διατηρήστε τα αρχικά timestamps/ACLs όταν είναι δυνατόν για αποδεικτική αξία

### Απόκτηση & αποκρυπτογράφηση του αντιγράφου ασφαλείας (USB / Finder / libimobiledevice)

- Σε macOS/Finder ορίστε "Encrypt local backup" και δημιουργήστε ένα *fresh* κρυπτογραφημένο αντίγραφο ασφαλείας ώστε τα στοιχεία του Keychain να είναι παρόντα.
- Cross‑platform: `idevicebackup2` (libimobiledevice ≥1.4.0) υποστηρίζει τις αλλαγές του πρωτοκόλλου backup στο iOS 17/18 και διορθώνει προηγούμενα σφάλματα handshake κατά την επαναφορά/backup.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑κατευθυνόμενη διαλογή με MVT

Το Mobile Verification Toolkit (mvt-ios) της Amnesty πλέον λειτουργεί απευθείας σε κρυπτογραφημένα αντίγραφα ασφαλείας iTunes/Finder, αυτοματοποιώντας την αποκρυπτογράφηση και την αντιστοίχιση IOC για υποθέσεις mercenary spyware.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Τα αρχεία εξόδου τοποθετούνται κάτω από `mvt-results/` (π.χ., analytics_detected.json, safari_history_detected.json) και μπορούν να συσχετιστούν με τις διαδρομές συνημμένων που ανακτώνται παρακάτω.

### Γενική ανάλυση artifacts (iLEAPP)

Για timeline/metadata πέρα από τα μηνύματα, εκτελέστε το iLEAPP απευθείας στο φάκελο backup (υποστηρίζει iOS 11‑17 schemas):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Απαρίθμηση συνημμένων εφαρμογών μηνυμάτων

Μετά την ανακατασκευή, απαρίθμησε τα συνημμένα για δημοφιλείς εφαρμογές. Το ακριβές σχήμα διαφέρει ανά εφαρμογή/έκδοση, αλλά η προσέγγιση είναι παρόμοια: εκτέλεσε ερώτημα στη βάση δεδομένων των μηνυμάτων, σύνδεσε τα μηνύματα με τα συνημμένα και επίλυσε τις διαδρομές στο δίσκο.

### iMessage (sms.db)
Βασικοί πίνακες: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Παραδείγματα ερωτημάτων:
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
Οι διαδρομές συνημμένων μπορεί να είναι απόλυτες ή σχετικές σε σχέση με το ανακατασκευασμένο δέντρο κάτω από Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Συνήθης σύνδεση: message table ↔ media/attachment table (το όνομα διαφέρει ανά έκδοση). Εκτελέστε ερώτημα στις εγγραφές media για να βρείτε τις διαδρομές στο δίσκο. Οι πρόσφατες κατασκευές iOS εξακολουθούν να εκθέτουν το `ZMEDIALOCALPATH` στο `ZWAMEDIAITEM`.
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
Οι διαδρομές συνήθως επιλύονται κάτω από `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` μέσα στο ανασυσταμένο αντίγραφο ασφαλείας.

### Signal / Telegram / Viber
- Signal: Η βάση δεδομένων μηνυμάτων είναι κρυπτογραφημένη· ωστόσο, τα αρχεία συνημμένων που βρίσκονται στην cache στο δίσκο (και τα thumbnails) συνήθως μπορούν να σαρωθούν
- Telegram: η cache παραμένει υπό `Library/Caches/` μέσα στο sandbox· οι εκδόσεις iOS 18 εμφανίζουν σφάλματα εκκαθάρισης της cache, οπότε μεγάλα υπολείμματα cache μέσων αποτελούν συνηθισμένες πηγές αποδεικτικών στοιχείων
- Viber: Το Viber.sqlite περιέχει πίνακες μηνυμάτων/επισυνάψεων με αναφορές σε αρχεία στο δίσκο

Συμβουλή: ακόμη και όταν τα μεταδεδομένα είναι κρυπτογραφημένα, η σάρωση των καταλόγων media/cache αποκαλύπτει ακόμα κακόβουλα αντικείμενα.


## Σάρωση επισυνάψεων για δομικά exploits

Μόλις έχετε τις διαδρομές των επισυναπτόμενων, τροφοδοτήστε τις σε structural detectors που επικυρώνουν file‑format invariants αντί για signatures. Παράδειγμα με ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Οι ανιχνεύσεις που καλύπτονται από δομικούς κανόνες περιλαμβάνουν:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): αδύνατες καταστάσεις λεξικού JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): υπερβολικά μεγάλες κατασκευές πινάκων Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): μη τεκμηριωμένα bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: ασυμφωνίες μεταξύ μεταδεδομένων και στοιχείων ροής


## Validation, caveats, and false positives

- Time conversions: iMessage stores dates in Apple epochs/units on some versions; convert appropriately during reporting
- Schema drift: app SQLite schemas change over time; confirm table/column names per device build
- Recursive extraction: PDFs may embed JBIG2 streams and fonts; extract and scan inner objects
- False positives: structural heuristics are conservative but can flag rare malformed yet benign media


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
