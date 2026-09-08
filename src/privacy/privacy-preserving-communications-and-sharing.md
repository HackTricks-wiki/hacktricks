# Επικοινωνίες και κοινοποίηση με διατήρηση της ιδιωτικότητας

{{#include ../banners/hacktricks-training.md}}

Η end-to-end encryption προστατεύει το περιεχόμενο. Δεν αποκρύπτει αυτόματα τον λογαριασμό, τον αριθμό τηλεφώνου, το γράφημα επαφών, τη διεύθυνση IP, το push token, την προεπισκόπηση ειδοποιήσεων, τον χρονισμό, τα metadata αρχείων ή τη συμπεριφορά του παραλήπτη. Επιλέξτε ένα εργαλείο με βάση τα metadata που αφαιρεί και τους παρατηρητές που εισάγει.

## Σύγκριση μοντέλων επικοινωνίας

| Εργαλείο/μοντέλο | Χρήσιμη ιδιότητα | Υπολειπόμενοι παρατηρητές και περιορισμοί |
|---|---|---|
| Signal | Ώριμη E2EE· τα usernames μπορούν να ξεκινήσουν επικοινωνία χωρίς κοινοποίηση αριθμού· το sealed sender μειώνει τα metadata της υπηρεσίας | Απαιτείται αριθμός τηλεφώνου για την εγγραφή· η υπηρεσία, ο push provider, οι επαφές και τα endpoints διατηρούν ορισμένες παρατηρήσεις |
| SimpleX | Δεν υπάρχει καθολικό user identifier· queues ανά επαφή· προαιρετικό Tor transport | Χρονισμός/transport του relay, push service, προσκλήσεις και endpoints· νεότερο/μικρότερο οικοσύστημα |
| Briar | Άμεσος συγχρονισμός· Tor online· Bluetooth/Wi-Fi offline· δεν υπάρχει κεντρική αποθήκευση μηνυμάτων | Επαφές και endpoints· τοπικοί παρατηρητές ραδιοεπικοινωνιών· εστίαση σε Android· και οι δύο πλευρές πρέπει να είναι διαθέσιμες ή να χρησιμοποιούν Mailbox |
| OnionShare | Άμεσο file/receive/chat/site μέσω προσωρινού onion service· κανένας storage provider | Ο υπολογιστής του αποστολέα είναι η υπηρεσία· ο κάτοχος του link μαθαίνει την πρόσβαση· ο χρονισμός και τα endpoints παραμένουν |
| Κρυπτογραφημένο αρχείο `age` | Απλή κρυπτογράφηση με recipient key, ανεξάρτητη από το transport | Το transport βλέπει αποστολέα/παραλήπτη/χρονισμό/μέγεθος· τα filenames/metadata του archive και τα endpoints παραμένουν |
| Συνηθισμένο email + TLS | Κρυπτογράφηση του καναλιού μεταξύ servers | Και οι δύο mail providers μπορούν συνήθως να διαβάσουν το περιεχόμενο και να διατηρήσουν routing/account metadata |

## Signal: ιδιωτική επαφή χωρίς αποκάλυψη αριθμού

Τα usernames του Signal μπορούν να ξεκινήσουν ένα chat χωρίς να αποκαλύψουν τον αριθμό τηλεφώνου του χρήστη στη νέα επαφή, αλλά για την εγγραφή εξακολουθεί να απαιτείται αριθμός τηλεφώνου.<sup>[[1]](#references)</sup> Το Sealed sender είναι μια πρόσθετη προστασία metadata και όχι προστασία από κάθε συσχέτιση IP/χρονισμού.<sup>[[2]](#references)</sup>

### Ροή εργασίας

1. Εγκαταστήστε το Signal από το επίσημο app store/project και ενημερώστε πρώτα το OS.
2. Εγγραφείτε με έναν αριθμό που δικαιούστε νόμιμα να χρησιμοποιείτε. Μην χρησιμοποιείτε rented SMS activations, αριθμό άλλου προσώπου ή λογαριασμό provider που αποκτήθηκε με ψευδή στοιχεία ταυτότητας.
3. Στο **Settings → Privacy → Phone Number**, ορίστε ποιοι μπορούν να βλέπουν τον αριθμό και ποιοι μπορούν να βρίσκουν τον λογαριασμό μέσω αριθμού, σύμφωνα με το threat model.
4. Δημιουργήστε username για την αναζήτηση νέων επαφών. Μοιραστείτε το ακριβές link/QR μέσω ενός ήδη authenticated channel· τα usernames μπορούν να αλλάξουν και δεν είναι το profile name.
5. Απενεργοποιήστε το contact upload/permissions αν η ευκολία δεν αξίζει τη συσχέτιση και προσθέστε χειροκίνητα τις επαφές όπου το υποστηρίζει η πλατφόρμα.
6. Ανοίξτε τα στοιχεία της επαφής και συγκρίνετε το safety number/QR μέσω δεύτερου καναλιού ή αυτοπροσώπως, πριν από την αποστολή ευαίσθητου περιεχομένου.
7. Ελέγξτε τις linked devices, το registration lock/PIN, τα notification previews, το screen security, το call relaying, τις προεπιλογές disappearing messages και τη συμπεριφορά των backups.
8. Στείλτε ένα μη ευαίσθητο test message και πραγματοποιήστε μια κλήση. Ελέγξτε τα ίχνη στην οθόνη κλειδώματος, στο desktop, στο wearable και στις cloud notifications και στις δύο πλευρές.
9. Αντιμετωπίστε έναν αλλαγμένο safety number ή μια μη αναμενόμενη linked device ως περιστατικό προς διερεύνηση και όχι ως alert που απορρίπτεται αυτόματα.

Μην συνδυάζετε μια pseudonymous profile photo, bio, group membership ή schedule με ένα αναγνωρίσιμο Signal context.

## SimpleX: per-contact connections χωρίς καθολικό identifier

Το SimpleX δρομολογεί μηνύματα μέσω unidirectional queues και δεν εκχωρεί network-wide user identifier. Η δική του policy τεκμηριώνει επίσης transport sessions, προσωρινά δεδομένα server, τα tradeoffs των push notifications και την ευθύνη των endpoints.<sup>[[3]](#references)</sup>

### Ροή εργασίας

1. Κατεβάστε έναν maintained client από το επίσημο project/store και επαληθεύστε τον publisher. Χρησιμοποιήστε dedicated OS/app profile όταν οι ταυτότητες δεν πρέπει να αναμειγνύονται.
2. Δημιουργήστε ένα **local** profile με context-specific display name και image. Η διαγραφή της εφαρμογής χωρίς backup μπορεί να οδηγήσει σε απώλεια του profile και των connections.
3. Κατά την πρώτη εκκίνηση, επιλέξτε συνειδητά το notification mode. Το άμεσο mobile push μπορεί να εκθέσει πρόσθετα metadata στην υποδομή της Apple/Google.
4. Δημιουργήστε ένα one-time invitation link για μία επαφή. Μεταφέρετέ το μέσω authenticated channel· οποιοσδήποτε αποκτήσει ένα ενεργό invitation μπορεί να προσπαθήσει να το χρησιμοποιήσει.
5. Μετά τη σύνδεση, ανοίξτε τα στοιχεία της επαφής και συγκρίνετε τον security code αυτοπροσώπως ή μέσω ανεξάρτητου verified channel.<sup>[[4]](#references)</sup>
6. Χρησιμοποιήστε incognito per-group profile όπου υποστηρίζεται, αντί να ανακυκλώνετε το ίδιο profile σε άσχετες ομάδες.
7. Ρυθμίστε το υποστηριζόμενο Tor transport του client αν το τοπικό δίκτυο/server δεν πρέπει να βλέπει την direct IP. Επιβεβαιώστε τη σύνδεση μετά την αλλαγή· μην επιβάλλετε system proxy που δεν υποστηρίζεται.
8. Ελέγξτε τα delivery receipts, τα link previews, τις κλήσεις, τα automatic downloads και το database export/backup. Κάθε ένα από αυτά αλλάζει την έκθεση metadata ή endpoint.
9. Δοκιμάστε την ανάκτηση σε ένα εφεδρικό απομονωμένο device χωρίς να εκτελείτε duplicated live profile state· το project προειδοποιεί ότι ταυτόχρονα αντίγραφα μπορεί να διαταράξουν τις συνομιλίες.

Η απουσία global identifier δεν εμποδίζει μια επαφή να αναγνωρίσει τον χρήστη μέσω του περιεχομένου, της επαναχρησιμοποίησης profile, της παράδοσης invitation, του χρονισμού ή του social graph.

## Briar: άμεση και ανθεκτική σε διακοπές ανταλλαγή μηνυμάτων

Το Briar συγχρονίζει απευθείας μεταξύ devices, μέσω Tor όταν είναι online και μέσω Bluetooth/Wi-Fi κατά τη διάρκεια τοπικών διακοπών. Το επίσημο threat model υποθέτει μόνο περιορισμένη adversarial παρακολούθηση ραδιοεπικοινωνιών μικρής εμβέλειας, επομένως το τοπικό wireless δεν είναι αόρατο.<sup>[[5]](#references)</sup>

### Ροή εργασίας

1. Εγκαταστήστε το από την επίσημη Briar distribution και επαληθεύστε την πηγή του package. Χρησιμοποιήστε υποστηριζόμενο Android device με τρέχουσες security updates.
2. Δημιουργήστε local account με μοναδικό context nickname και ισχυρό password. Δεν υπάρχει password-reset path· ελέγξτε ότι το unlock secret μπορεί να ανακτηθεί.
3. Προσθέστε επαφές πρόσωπο με πρόσωπο, σαρώνοντας τα QR codes ο ένας του άλλου όπου είναι δυνατό. Έτσι γίνεται authentication της επαφής και αποφεύγεται η αποστολή link μέσω correlatable channel.
4. Στις ρυθμίσεις connectivity, ενεργοποιήστε μόνο τα απαραίτητα transports: Tor/Internet, Wi-Fi ή/και Bluetooth. Απενεργοποιήστε τα local radios όταν δεν απαιτούνται.
5. Για asynchronous delivery, αξιολογήστε το Briar Mailbox σε dedicated powered device· καταγράψτε το και προστατέψτε το φυσικά όπως έναν message server.
6. Στείλτε ένα benign test ενώ υπάρχει Internet και στη συνέχεια δοκιμάστε τη planned outage path με απενεργοποιημένο Internet, σε τοποθεσία όπου έχετε εξουσιοδότηση ως owner.
7. Ελέγξτε τα Android backups, τα notification previews, τα screenshots και το exported content. Το local encrypted storage εκτίθεται όταν το endpoint είναι unlocked/compromised.
8. Αφαιρέστε χαμένες επαφές/devices και αποσύρετε ολόκληρο το context αν έχει παραβιαστεί η φυσική κατοχή ή το account password.

## OnionShare: άμεση προσωρινή μεταφορά

Το OnionShare εκτελεί ένα onion service στον υπολογιστή του αποστολέα/παραλήπτη· τα αρχεία δεν ανεβαίνουν σε storage provider και η κίνηση είναι end-to-end encrypted μέσα στο Tor.<sup>[[6]](#references)</sup> Το πλήρες onion URL είναι bearer capability και πρέπει να προστατεύεται.

### GUI file-sharing workflow

1. Εγκαταστήστε το OnionShare από την επίσημη signed distribution και το Tor Browser στην πλευρά του παραλήπτη.
2. Τοποθετήστε **sanitized copies** των αρχείων σε dedicated staging directory. Μην υποδείξετε στο OnionShare έναν προσωπικό home directory.
3. Ανοίξτε το **Share Files**, προσθέστε μόνο τα staged files, αφήστε ενεργοποιημένη την προστασία private key/access και διατηρήστε ενεργοποιημένο το **Stop sharing after files have been sent** για έναν παραλήπτη.
4. Ξεκινήστε την κοινοποίηση και στείλτε το πλήρες onion URL μέσω ενός ήδη authenticated E2EE channel. Μην το επικολλήσετε σε email, issue trackers ή public chats.
5. Ο παραλήπτης ανοίγει το URL στο Tor Browser, επαληθεύει τα αναμενόμενα filenames/size με τον αποστολέα και πραγματοποιεί download.
6. Και οι δύο πλευρές συγκρίνουν ένα εκ των προτέρων συμφωνημένο ή ανεξάρτητα παραδομένο SHA-256 digest για integrity όταν το ίδιο το αρχείο αποτελεί το security boundary.
7. Επιβεβαιώστε ότι το OnionShare σταμάτησε μετά το download· διαφορετικά σταματήστε το χειροκίνητα και κλείστε την εφαρμογή.
8. Διαγράψτε το staged copy σύμφωνα με την πολιτική retention και ελέγξτε τις ρυθμίσεις history/log του OnionShare για μη σκόπιμη αποκάλυψη filename.

### CLI workflow

Το επίσημο CLI δέχεται αρχεία ως positional arguments και σταματά μετά το προεπιλεγμένο single completed share. Σε host με εγκατεστημένα το επίσημο CLI/Tor:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Παρέχετε το πλήρες URL με ασφάλεια. Μην προσθέτετε `--public`, `--no-autostop-sharing`, verbose καταγραφή ονομάτων αρχείων ή persistence, εκτός εάν το threat model απαιτεί ρητά την προκύπτουσα έκθεση.<sup>[[7]](#references)</sup>

Αντιμετωπίζετε τα ληφθέντα έγγραφα ως hostile. Ανοίγετέ τα σε disposable VM/Dangerzone-style renderer και όχι στον host που περιέχει την ταυτότητά σας.

## Κρυπτογράφηση ενός αρχείου ανεξάρτητα με `age`

Η encryption ανεξάρτητη από το transport είναι χρήσιμη όταν ένας storage/email provider ενδέχεται να δει το object. Δεν αποκρύπτει τον sender, τον recipient, το μέγεθος, τον χρόνο ή το filename, εκτός εάν αυτά αντιμετωπιστούν ξεχωριστά.

### Ρύθμιση recipient
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Επαληθεύστε τη δημόσια συμβολοσειρά παραλήπτη μέσω ενός δεύτερου καναλιού. Στη συνέχεια, ο αποστολέας εκτελεί:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Ο παραλήπτης αποκρυπτογραφεί σε μια νέα διαδρομή:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Η επίσημη CLI προειδοποιεί ότι το `-o` αντικαθιστά ένα υπάρχον output, επομένως χρησιμοποιήστε έναν νέο κατάλογο και επαληθεύστε το digest/περιεχόμενο πριν το μετακινήσετε.<sup>[[8]](#references)</sup> Ποτέ μην στέλνετε το αρχείο ταυτότητας μαζί με το ciphertext.

## Αναπαραγώγιμη pipeline απολύμανσης αρχείων

Η αφαίρεση metadata εξαρτάται από τη μορφή. Διατηρήστε ένα κρυπτογραφημένο πρωτότυπο όταν έχουν σημασία η αυθεντικότητα, η forensics ή η αλυσίδα επιτήρησης· εργαστείτε σε αντίγραφο.

### Παράδειγμα JPEG
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Αυτό ακολουθεί τις ασφαλέστερες οδηγίες του ExifTool για JPEG: η τυφλή αφαίρεση κάθε tag μπορεί επίσης να αφαιρέσει πληροφορίες χρώματος.<sup>[[9]](#references)</sup> Στη συνέχεια, ελέγξτε οπτικά τα pixels για πρόσωπα, αντανακλάσεις, οθόνες, τοπόσημα και μοναδικά μοτίβα φθοράς/θορύβου.

### Ροή εργασίας για Office/PDF

1. Διατηρήστε το επεξεργάσιμο πρωτότυπο κρυπτογραφημένο και offline, μακριά από το πλαίσιο δημοσίευσης.
2. Αφαιρέστε σχόλια, παρακολουθούμενες αλλαγές, κρυφές διαφάνειες/φύλλα, ενσωματωμένα αρχεία, προσωπικά πρότυπα και ιδιότητες εγγράφου στην εφαρμογή συγγραφής.
3. Εξαγάγετε ένα νέο PDF από ένα αποκλειστικό καθαρό προφίλ· μην κάνετε «εκτύπωση» σε cloud printer.
4. Ελέγξτε το τόσο με εργαλεία που γνωρίζουν τη μορφή όσο και με έναν disposable οπτικό renderer:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Αναζητήστε στο rendered output ονόματα, paths, διευθύνσεις email και κείμενο revision. Η rasterization μπορεί να αφαιρέσει ενεργές δομές, αλλά υποβαθμίζει την προσβασιμότητα/αναζήτηση και δεν αφαιρεί το ορατό περιεχόμενο ή το writing style.
6. Υπολογίστε το hash του τελικού artifact και μεταφέρετε **μόνο** αυτό το αντίγραφο μέσω του publication compartment.

## Privacy Pass: anonymous authorization for service designers

Το Privacy Pass διαχωρίζει το token **issuance** από το **redemption**. Ένα origin μπορεί να μάθει ότι ένας client διαθέτει token εγκεκριμένο από issuer, χωρίς να μάθει τη συγκεκριμένη αλληλεπίδραση issuance του client. Η επαναχρησιμοποίηση token, τα unique metadata, ο συγχρονισμός ή η collusion μπορούν να επαναφέρουν τη linkability.<sup>[[10]](#references)</sup>

Ασφαλές deployment pattern:

1. Ορίστε τη δήλωση που αποδεικνύει το token (για παράδειγμα, eligibility για rate-limit), όχι μια κρυφή global identity.
2. Χρησιμοποιήστε την standardized architecture και τα issuance protocols· μην υλοποιείτε blind-signature cryptography από την αρχή.
3. Διαχωρίστε τη διαχείριση issuer/attester και origin όπου το απαιτεί η επιθυμητή ιδιότητα.
4. Ελαχιστοποιήστε τα public/private token metadata και βεβαιωθείτε ότι τα anonymity sets είναι αρκετά μεγάλα.
5. Εκδώστε batches πριν από τη χρήση, όπου υποστηρίζεται, ώστε ο χρόνος issuance να μην αντιστοιχεί trivially στον χρόνο redemption.
6. Κάντε redeem κάθε token μόνο μία φορά, επικυρώστε το origin-bound challenge και διαγράψτε το state των expired token.
7. Βεβαιωθείτε ότι τα cookies, το IP logging και τα application accounts δεν ακυρώνουν σιωπηρά την ιδιότητα privacy του token.
8. Ελέγξτε αν τα logs του issuer και του origin μπορούν να συσχετίσουν ένα ελεγχόμενο event issuance και redemption μέσω timing, metadata ή unique errors.

Το Privacy Pass είναι application feature και όχι κάτι που μπορεί να προσθέσει ένας user σε έναν αυθαίρετο account.

## Communications verification checklist

- [ ] Το contact/invitation/key authenticated independently.
- [ ] Η έκθεση του phone number, username, profile, group και contact-upload είναι κατανοητή.
- [ ] Έχουν καταγραφεί οι direct IP, relay, Tor, push-provider και local-radio observers.
- [ ] Έγινε έλεγχος των notification previews, wearables, linked desktops και backups.
- [ ] Τα αρχεία έγιναν sanitized, κρυπτογραφήθηκαν όπου απαιτείται και ανοίχτηκαν σε disposable context.
- [ ] Το recovery λειτουργεί χωρίς bridging unrelated identities.
- [ ] Τα logs, το history και τα temporary share services έχουν κανόνα shutdown/retention.

## References

- [1] [Signal — Απόρρητο αριθμού τηλεφώνου και usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Πολιτική απορρήτου και όροι χρήσης](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Οδηγός privacy και security](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Πώς λειτουργεί](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Σχεδιασμός security](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Προηγμένη χρήση και CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — Επίσημο CLI και χρήση](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Ασφαλής αφαίρεση metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architecture του Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
