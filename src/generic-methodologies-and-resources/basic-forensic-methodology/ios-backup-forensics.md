# iOS Ανάλυση Backup (Τριάρισμα εστιασμένο σε μηνύματα)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα περιγράφει πρακτικά βήματα για την ανακατασκευή και ανάλυση iOS backups για ενδείξεις παράδοσης 0‑click exploits μέσω συνημμένων σε messaging apps. Εστιάζει στην μετατροπή της κατακερματισμένης διάταξης backup της Apple σε διαδρομές αναγνώσιμες από άνθρωπο και στη συνέχεια στην απαρίθμηση και σάρωση συνημμένων σε κοινές εφαρμογές.

Στόχοι:
- Ανακατασκευή αναγνώσιμων διαδρομών από το Manifest.db
- Απαρίθμηση βάσεων δεδομένων μηνυμάτων (iMessage, WhatsApp, Signal, Telegram, Viber)
- Επίλυση διαδρομών συνημμένων, εξαγωγή ενσωματωμένων αντικειμένων (PDF/Images/Fonts) και τροφοδότηση τους σε structural detectors


## Ανακατασκευή backup iOS

Τα backups που αποθηκεύονται στο MobileSync χρησιμοποιούν κατακερματισμένα ονόματα αρχείων που δεν είναι αναγνώσιμα από άνθρωπο. Η βάση δεδομένων Manifest.db (SQLite) αντιστοιχίζει κάθε αποθηκευμένο αντικείμενο στην λογική του διαδρομή.

Γενική διαδικασία:
1) Ανοίξτε το Manifest.db και διαβάστε τις εγγραφές αρχείων (domain, relativePath, flags, fileID/hash)  
2) Αναδημιουργήστε την αρχική ιεραρχία φακέλων βάσει domain + relativePath  
3) Αντιγράψτε ή δημιουργήστε hardlink για κάθε αποθηκευμένο αντικείμενο στην επανακατασκευασμένη διαδρομή

Παράδειγμα ροής εργασίας με ένα εργαλείο που υλοποιεί όλη τη διαδικασία end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Σημειώσεις:
- Χειριστείτε τα encrypted backups παρέχοντας το backup password στον extractor σας
- Διατηρήστε τα original timestamps/ACLs όταν είναι δυνατόν, για την αξία τους ως αποδεικτικό υλικό


## Απαρίθμηση συνημμένων σε εφαρμογές μηνυμάτων

Μετά την ανακατασκευή, απαριθμήστε τα συνημμένα για δημοφιλείς εφαρμογές. Το ακριβές schema διαφέρει ανά app/version, αλλά η προσέγγιση είναι παρόμοια: query στη messaging database, κάντε join τα messages με τα attachments και επιλύστε τα paths στο δίσκο.

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Example queries:
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
Οι διαδρομές συνημμένων μπορεί να είναι απόλυτες ή σχετικές σε σχέση με το επανακατασκευασμένο δέντρο κάτω από Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Συνήθης συσχέτιση: message table ↔ media/attachment table (η ονοματολογία διαφέρει ανά έκδοση). Κάντε ερώτημα στις εγγραφές media για να αποκτήσετε τις διαδρομές στο δίσκο.

Παράδειγμα (γενικό):
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
Προσαρμόστε τα ονόματα πινάκων/στηλών στην έκδοση της εφαρμογής σας (ZWAMESSAGE/ZWAMEDIAITEM είναι συνηθισμένα σε iOS builds).

### Signal / Telegram / Viber
- Signal: η message DB είναι encrypted; ωστόσο, τα attachments που είναι cached on disk (και τα thumbnails) συνήθως είναι scan‑able
- Telegram: επιθεωρήστε τα cache directories (photo/video/document caches) και συσχετίστε τα με chats όταν είναι δυνατόν
- Viber: το Viber.sqlite περιέχει message/attachment tables με on‑disk references

Tip: ακόμα κι όταν τα metadata είναι encrypted, το σκανάρισμα των media/cache directories εξακολουθεί να αποκαλύπτει malicious objects.


## Σάρωση attachments για structural exploits

Μόλις αποκτήσετε attachment paths, περάστε τα σε structural detectors που επικυρώνουν file‑format invariants αντί για signatures. Παράδειγμα με ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Οι ανιχνεύσεις που καλύπτονται από κανόνες δομής περιλαμβάνουν:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): αδύνατες καταστάσεις λεξικού JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): υπερμεγέθεις κατασκευές πινάκων Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): μη τεκμηριωμένες bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: ασυμφωνίες μεταξύ metadata και stream component


## Επαλήθευση, προειδοποιήσεις και false positives

- Μετατροπές χρόνου: το iMessage αποθηκεύει ημερομηνίες σε Apple epochs/units σε κάποιες εκδόσεις· μετατρέψτε κατάλληλα κατά την αναφορά
- Schema drift: τα app SQLite schemas αλλάζουν με την πάροδο του χρόνου· επιβεβαιώστε τα ονόματα πινάκων/στηλών ανά build συσκευής
- Αναδρομική εξαγωγή: τα PDFs μπορεί να ενσωματώνουν JBIG2 streams και fonts· εξαγάγετε και σαρώστε τα εσωτερικά αντικείμενα
- False positives: οι δομικές ευριστικές μέθοδοι είναι συντηρητικές αλλά μπορεί να επισημάνουν σπάνια κακώς μορφοποιημένα αλλά ακίνδυνα μέσα


## Αναφορές

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
