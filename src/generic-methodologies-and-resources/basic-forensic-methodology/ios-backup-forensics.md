# iOS Backup Forensics (triage με επίκεντρο τα μηνύματα)

Αυτή η σελίδα περιγράφει πρακτικά βήματα για την ανακατασκευή και ανάλυση iOS backups, με σκοπό τον εντοπισμό ενδείξεων παράδοσης 0-click exploit μέσω attachments εφαρμογών messaging. Εστιάζει στη μετατροπή της hashed διάταξης backup της Apple σε paths αναγνώσιμα από τον άνθρωπο και, στη συνέχεια, στην απαρίθμηση και σάρωση attachments σε κοινές εφαρμογές.

Στόχοι:
- Ανακατασκευή αναγνώσιμων paths από το Manifest.db
- Απαρίθμηση databases εφαρμογών messaging (iMessage, WhatsApp, Signal, Telegram, Viber)
- Επίλυση paths attachments, εξαγωγή embedded objects όπου υποστηρίζεται (PDF/Images/Fonts) και προώθησή τους σε structural detectors


## Ανακατασκευή ενός iOS backup

Τα backups που αποθηκεύονται στο MobileSync χρησιμοποιούν hashed filenames που δεν είναι αναγνώσιμα από τον άνθρωπο. Η SQLite database Manifest.db αντιστοιχίζει κάθε αποθηκευμένο object στο logical path του.<sup>[[1]](#references)[[2]](#references)</sup>

Διαδικασία υψηλού επιπέδου:
1) Άνοιγμα του Manifest.db και ανάγνωση των file records (domain, relativePath, flags, fileID/hash)
2) Αναδημιουργία της αρχικής ιεραρχίας φακέλων με βάση τα domain + relativePath
3) Αντιγραφή ή δημιουργία hardlink για κάθε αποθηκευμένο object στο reconstructed path του

Παράδειγμα workflow με εργαλείο που υλοποιεί αυτή τη διαδικασία end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Σημειώσεις:
- Αποκρυπτογραφήστε τα κρυπτογραφημένα backups πριν τα περάσετε σε εργαλείο ανακατασκευής· το ElegantBouncer απαιτεί αποκρυπτογραφημένο backup.<sup>[[2]](#references)[[3]](#references)</sup>
- Διατηρήστε, όπου είναι δυνατό, τις αρχικές timestamps/ACLs για την αποδεικτική τους αξία

### Απόκτηση και αποκρυπτογράφηση του backup (USB / Finder / libimobiledevice)

- Στα Finder/Apple Devices/iTunes, ενεργοποιήστε το "Encrypt local backup" και δημιουργήστε ένα νέο backup· τα κρυπτογραφημένα backups μπορούν να περιλαμβάνουν αποθηκευμένους κωδικούς πρόσβασης και δεδομένα Health που παραλείπονται από τα μη κρυπτογραφημένα backups.<sup>[[8]](#references)</sup>
- Cross-platform: το libimobiledevice 1.4.0 περιλαμβάνει διορθώσεις για το `idevicebackup2`.<sup>[[4]](#references)</sup> Ενεργοποιήστε διαδραστικά την κρυπτογράφηση και, στη συνέχεια, επιβάλετε ένα πλήρες backup χρησιμοποιώντας τη documented σειρά εντολών, με τον κατάλογο προορισμού τελευταίο.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage με βάση τα IOC με το MVT

Το Mobile Verification Toolkit της Amnesty μπορεί να εξαγάγει ένα κλειδί από κρυπτογραφημένα backup iTunes/Finder και να τα αποκρυπτογραφήσει, και στη συνέχεια να σαρώσει το αποκρυπτογραφημένο backup με ένα αρχείο STIX2 IOC.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Με το `-o`, τα αποτελέσματα JSON γράφονται στο `/tmp/mvt-results/`. Οι αντιστοιχίσεις IOC χρησιμοποιούν το επίθημα `_detected` και μπορούν να συσχετιστούν με τις διαδρομές των συνημμένων που ανακτήθηκαν παρακάτω.<sup>[[3]](#references)</sup>

### Γενική ανάλυση artifacts (iLEAPP)

Για timeline/metadata πέρα από τα μηνύματα, εκτελέστε το iLEAPP στον φάκελο του raw backup. Ο τύπος εισόδου `itunes` δέχεται backups από iTunes/Finder και οι τρέχουσες εκδόσεις υποστηρίζουν iOS/iPadOS 11 έως τις τρέχουσες εκδόσεις.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Απαρίθμηση συνημμένων εφαρμογών messaging

Μετά την ανακατασκευή, απαριθμήστε τα συνημμένα για δημοφιλείς εφαρμογές. Το ακριβές schema διαφέρει ανά εφαρμογή/έκδοση, αλλά η προσέγγιση είναι παρόμοια: κάντε query στη βάση δεδομένων messaging, ενώστε τα μηνύματα με τα συνημμένα και επιλύστε τις διαδρομές στον δίσκο.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Βασικοί πίνακες: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Οι διαδρομές των συνημμένων μπορεί να είναι απόλυτες ή σχετικές με το ανακατασκευασμένο δέντρο στη διαδρομή Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Συνήθης σύνδεση: πίνακας message ↔ πίνακας media/attachment (η ονομασία διαφέρει ανάλογα με την έκδοση). Κάντε query στις γραμμές media για να λάβετε τις διαδρομές στον δίσκο. Το Belkasoft αναγνωρίζει το `ZMEDIALOCALPATH` στον `ZWAMEDIAITEM` ως τη θέση του αρχείου media. Η τρέχουσα υλοποίηση του ElegantBouncer συνδέει το `ZWAMEDIAITEM.ZMESSAGE` με το `ZWAMESSAGE.Z_PK` και προσθέτει το `Message/` ως πρόθεμα κατά την επίλυση μιας διαδρομής που ξεκινά με `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Για εκείνη τη διαδρομή ανακατασκευής του ElegantBouncer, ένα media path που ξεκινά με `Media/` επιλύεται κάτω από το `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`. Ο οδηγός της Belkasoft, αντίθετα, τεκμηριώνει μια διαδρομή `Messages/Media/`, επομένως ελέγξτε το backup πριν θεωρήσετε δεδομένη οποιαδήποτε από τις δύο γραφές.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: η message DB είναι κρυπτογραφημένη· ωστόσο, τα attachments που αποθηκεύονται προσωρινά στον δίσκο (καθώς και τα thumbnails) συνήθως μπορούν να σαρωθούν.<sup>[[2]](#references)</sup>
- Telegram: ελέγξτε τους media/cache directories της εφαρμογής· το Telegram τεκμηρίωσε ένα bug εκκαθάρισης cache στην iOS app 11.2 σε iOS 18.0.1, το οποίο επισημάνθηκε ως διορθωμένο στην 11.3, επομένως ελέγξτε για residual files.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: το Viber.sqlite περιέχει message/attachment tables με references σε αρχεία του δίσκου.<sup>[[2]](#references)</sup>

Συμβουλή: ακόμη και όταν τα metadata είναι κρυπτογραφημένα, η σάρωση των media/cache directories εξακολουθεί να εντοπίζει malicious objects.<sup>[[2]](#references)</sup>


## Σάρωση attachments για structural exploits

Μόλις αποκτήσετε τα attachment paths, τροφοδοτήστε τα σε structural detectors που επικυρώνουν τα invariants της μορφής αρχείου αντί για signatures. Παράδειγμα με ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Οι ανιχνεύσεις που καλύπτονται από structural rules περιλαμβάνουν:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): αδύνατες καταστάσεις λεξικών JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): κατασκευές πινάκων Huffman υπερβολικού μεγέθους
- TrueType TRIANGULATION (CVE‑2023‑41990): μη τεκμηριωμένοι κωδικοί λειτουργίας bytecode
- DNG/TIFF CVE‑2025‑43300: ασυμφωνίες μεταξύ στοιχείων metadata και stream


## Επικύρωση, επιφυλάξεις και false positives

- Μετατροπές χρόνου: το iMessage αποθηκεύει ημερομηνίες σε Apple epochs/units σε ορισμένες εκδόσεις· πραγματοποιήστε κατάλληλη μετατροπή κατά την αναφορά.<sup>[[2]](#references)</sup>
- Schema drift: τα SQLite schemas των εφαρμογών αλλάζουν με την πάροδο του χρόνου· επιβεβαιώστε τα ονόματα πινάκων/στηλών ανά build συσκευής
- Recursive extraction: τα PDF ενδέχεται να ενσωματώνουν streams JBIG2 και γραμματοσειρές· χρησιμοποιήστε parser που μπορεί να εξάγει και να σαρώνει εσωτερικά αντικείμενα
- False positives: τα structural heuristics είναι συντηρητικά, αλλά ενδέχεται να επισημάνουν σπάνια malformed, αλλά καλοήθη, media.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Όταν δεν μπορείτε να αποκτήσετε τα samples, αλλά πρέπει και πάλι να εντοπίσετε την απειλή](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Project ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Ροή εργασίας MVT iOS backup](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Σημειώσεις έκδοσης libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Η ενημέρωση 11.2 έχει προκαλέσει δυσλειτουργία στον καθαρισμό cache στο iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Εγχειρίδιο idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Project iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Σχετικά με τα encrypted backups στο iPhone, iPad ή iPod touch σας (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics με το Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [WhatsApp scanner και path resolver του ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
