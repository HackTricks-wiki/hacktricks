# Forensics αντιγράφων ασφαλείας iOS (διαλογή με επίκεντρο τα μηνύματα)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα περιγράφει πρακτικά βήματα για την ανακατασκευή και ανάλυση αντιγράφων ασφαλείας iOS, με στόχο τον εντοπισμό ενδείξεων παράδοσης 0-click exploit μέσω συνημμένων εφαρμογών messaging. Εστιάζει στη μετατροπή της hashed διάταξης αντιγράφων ασφαλείας της Apple σε paths αναγνώσιμα από τον άνθρωπο και, στη συνέχεια, στην απαρίθμηση και σάρωση συνημμένων σε κοινές εφαρμογές.

Στόχοι:
- Ανακατασκευή αναγνώσιμων paths από το Manifest.db
- Απαρίθμηση βάσεων δεδομένων messaging (iMessage, WhatsApp, Signal, Telegram, Viber)
- Επίλυση paths συνημμένων, εξαγωγή ενσωματωμένων αντικειμένων όπου υποστηρίζεται (PDF/Images/Fonts) και τροφοδότησή τους σε structural detectors


## Ανακατασκευή ενός αντιγράφου ασφαλείας iOS

Τα αντίγραφα ασφαλείας που αποθηκεύονται στο MobileSync χρησιμοποιούν hashed filenames, τα οποία δεν είναι αναγνώσιμα από τον άνθρωπο. Η βάση δεδομένων SQLite Manifest.db αντιστοιχίζει κάθε αποθηκευμένο αντικείμενο στο logical path του.<sup>[[1]](#references)[[2]](#references)</sup>

Διαδικασία υψηλού επιπέδου:
1) Άνοιγμα του Manifest.db και ανάγνωση των records αρχείων (domain, relativePath, flags, fileID/hash)
2) Αναδημιουργία της αρχικής ιεραρχίας φακέλων με βάση τα domain + relativePath
3) Αντιγραφή ή δημιουργία hardlink για κάθε αποθηκευμένο αντικείμενο στο reconstructed path του

Παράδειγμα workflow με εργαλείο που υλοποιεί τη διαδικασία end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Σημειώσεις:
- Αποκρυπτογραφήστε τα encrypted backups πριν τα περάσετε σε εργαλείο ανακατασκευής· το ElegantBouncer απαιτεί decrypted backup.<sup>[[2]](#references)[[3]](#references)</sup>
- Διατηρήστε τα αρχικά timestamps/ACLs όταν είναι δυνατό, για evidentiary value

### Απόκτηση και αποκρυπτογράφηση του backup (USB / Finder / libimobiledevice)

- Στο Finder/Apple Devices/iTunes, ενεργοποιήστε το "Encrypt local backup" και δημιουργήστε ένα νέο backup· τα encrypted backups μπορούν να περιλαμβάνουν αποθηκευμένους κωδικούς πρόσβασης και δεδομένα Health που παραλείπονται από τα unencrypted backups.<sup>[[8]](#references)</sup>
- Cross-platform: το libimobiledevice 1.4.0 περιλαμβάνει fixes για το `idevicebackup2`.<sup>[[4]](#references)</sup> Ενεργοποιήστε interactive encryption και, στη συνέχεια, εκτελέστε force ενός full backup χρησιμοποιώντας τη documented σειρά εντολών, με τον κατάλογο προορισμού τελευταίο.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage με βάση τα IOC με το MVT

Το Mobile Verification Toolkit της Amnesty μπορεί να εξαγάγει ένα κλειδί από και να αποκρυπτογραφήσει κρυπτογραφημένα αντίγραφα ασφαλείας iTunes/Finder και, στη συνέχεια, να σαρώσει το αποκρυπτογραφημένο αντίγραφο ασφαλείας με ένα αρχείο IOC STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Με την επιλογή `-o`, τα αποτελέσματα JSON εγγράφονται κάτω από το `/tmp/mvt-results/`; οι αντιστοιχίσεις IOC χρησιμοποιούν επίθημα `_detected` και μπορούν να συσχετιστούν με τις διαδρομές των συνημμένων που ανακτήθηκαν παρακάτω.<sup>[[3]](#references)</sup>

### Γενική ανάλυση artifact (iLEAPP)

Για timeline/metadata πέρα από το messaging, εκτέλεσε το iLEAPP στον φάκελο raw backup· ο τύπος εισόδου `itunes` δέχεται backups από iTunes/Finder και οι τρέχουσες εκδόσεις υποστηρίζουν iOS/iPadOS 11 έως τις τρέχουσες εκδόσεις.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Απαρίθμηση συνημμένων εφαρμογών messaging

Μετά την ανακατασκευή, απαριθμήστε τα συνημμένα για δημοφιλείς εφαρμογές. Το ακριβές schema διαφέρει ανά εφαρμογή/έκδοση, αλλά η προσέγγιση είναι παρόμοια: εκτελέστε query στη βάση δεδομένων messaging, κάντε join των μηνυμάτων με τα συνημμένα και επιλύστε τις διαδρομές στον δίσκο.<sup>[[1]](#references)[[2]](#references)</sup>

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
Οι διαδρομές των συνημμένων μπορεί να είναι απόλυτες ή σχετικές με το ανακατασκευασμένο δέντρο κάτω από το Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Συνήθης συσχέτιση: message table ↔ media/attachment table (η ονομασία διαφέρει ανά έκδοση). Εκτελέστε query στις γραμμές media για να λάβετε τις διαδρομές των αρχείων στο δίσκο. Το Belkasoft αναγνωρίζει το `ZMEDIALOCALPATH` στο `ZWAMEDIAITEM` ως τη θέση του αρχείου media· η τρέχουσα υλοποίηση του ElegantBouncer συνδέει το `ZWAMEDIAITEM.ZMESSAGE` με το `ZWAMESSAGE.Z_PK` και προσθέτει το `Message/` ως πρόθεμα κατά την επίλυση μιας διαδρομής που αρχίζει με `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Για εκείνη τη διαδρομή ανακατασκευής του ElegantBouncer, μια διαδρομή media που αρχίζει με `Media/` επιλύεται κάτω από το `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`. Ο οδηγός της Belkasoft, αντίθετα, τεκμηριώνει μια διαδρομή `Messages/Media/`, επομένως ελέγξτε το backup πριν θεωρήσετε δεδομένη κάποια από τις δύο γραφές.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: η message DB είναι κρυπτογραφημένη· ωστόσο, τα attachments που έχουν αποθηκευτεί προσωρινά στον δίσκο (καθώς και τα thumbnails) μπορούν συνήθως να σαρωθούν.<sup>[[2]](#references)</sup>
- Telegram: ελέγξτε τους media/cache directories της εφαρμογής· το Telegram τεκμηρίωσε ένα cache-cleanup bug στην iOS app 11.2 σε iOS 18.0.1, το οποίο σημειώνεται ως διορθωμένο στην 11.3, επομένως ελέγξτε για residual files.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: το Viber.sqlite περιέχει πίνακες μηνυμάτων/attachments με references σε αρχεία στον δίσκο.<sup>[[2]](#references)</sup>

Συμβουλή: ακόμη και όταν τα metadata είναι κρυπτογραφημένα, η σάρωση των media/cache directories εξακολουθεί να εντοπίζει κακόβουλα objects.<sup>[[2]](#references)</sup>


## Σάρωση attachments για structural exploits

Μόλις αποκτήσετε τα attachment paths, τροφοδοτήστε τα σε structural detectors που επικυρώνουν τα invariants της μορφής αρχείου αντί για signatures. Παράδειγμα με ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Οι ανιχνεύσεις που καλύπτονται από δομικούς κανόνες περιλαμβάνουν:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): αδύνατες καταστάσεις λεξικών JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): υπερμεγέθεις κατασκευές πινάκων Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): μη τεκμηριωμένοι opcodes bytecode
- DNG/TIFF CVE‑2025‑43300: ασυμφωνίες μεταξύ μεταδεδομένων και στοιχείων stream


## Επικύρωση, επιφυλάξεις και false positives

- Μετατροπές χρόνου: το iMessage αποθηκεύει ημερομηνίες σε epochs/μονάδες της Apple σε ορισμένες εκδόσεις· πραγματοποιήστε την κατάλληλη μετατροπή κατά την αναφορά.<sup>[[2]](#references)</sup>
- Απόκλιση schema: τα SQLite schemas των εφαρμογών αλλάζουν με την πάροδο του χρόνου· επιβεβαιώστε τα ονόματα πινάκων/στηλών για κάθε build συσκευής
- Αναδρομική εξαγωγή: τα PDF μπορεί να ενσωματώνουν streams JBIG2 και γραμματοσειρές· χρησιμοποιήστε parser που μπορεί να εξάγει και να σαρώνει εσωτερικά αντικείμενα
- False positives: οι δομικές heuristics είναι συντηρητικές, αλλά ενδέχεται να επισημάνουν σπάνια κατεστραμμένα αλλά benign αρχεία πολυμέσων.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Όταν δεν μπορείτε να αποκτήσετε τα δείγματα αλλά εξακολουθείτε να πρέπει να εντοπίσετε την απειλή](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Project ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Ροή εργασίας MVT για iOS backup](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Σημειώσεις έκδοσης libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Η ενημέρωση 11.2 έχει προκαλέσει δυσλειτουργία στον καθαρισμό cache στο iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Εγχειρίδιο idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Project iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Σχετικά με τα κρυπτογραφημένα backup στο iPhone, iPad ή iPod touch σας (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics με το Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [WhatsApp scanner και path resolver του ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
