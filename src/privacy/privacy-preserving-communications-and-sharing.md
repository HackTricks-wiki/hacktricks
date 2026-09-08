# Επικοινωνίες και κοινή χρήση με προστασία ιδιωτικότητας

Η end-to-end κρυπτογράφηση προστατεύει το περιεχόμενο. Δεν αποκρύπτει αυτόματα τον λογαριασμό, τον αριθμό τηλεφώνου, το γράφημα επαφών, τη διεύθυνση IP, το push token, την προεπισκόπηση ειδοποιήσεων, τον χρονισμό, τα metadata αρχείων ή τη συμπεριφορά του παραλήπτη. Επιλέξτε ένα εργαλείο με βάση τα metadata που αφαιρεί και τους παρατηρητές που εισάγει.

## Σύγκριση μοντέλων επικοινωνίας

| Εργαλείο/μοντέλο | Χρήσιμη ιδιότητα | Υπολειπόμενοι παρατηρητές και περιορισμοί |
|---|---|---|
| Signal | Ώριμο E2EE· τα usernames μπορούν να ξεκινήσουν επαφή χωρίς κοινοποίηση αριθμού· το sealed sender μειώνει τα metadata της υπηρεσίας | Απαιτείται αριθμός τηλεφώνου για την εγγραφή· η υπηρεσία, ο πάροχος push, οι επαφές και τα endpoints διατηρούν ορισμένες παρατηρήσεις |
| SimpleX | Δεν υπάρχει καθολικό user identifier· ουρές ανά επαφή· προαιρετικό Tor transport | Χρονισμός/transport του relay, υπηρεσία push, προσκλήσεις και endpoints· νεότερο/μικρότερο οικοσύστημα |
| Briar | Άμεσος συγχρονισμός· Tor όταν υπάρχει σύνδεση· Bluetooth/Wi-Fi offline· δεν υπάρχει κεντρική αποθήκευση μηνυμάτων | Επαφές και endpoints· τοπικοί παρατηρητές ραδιοεπικοινωνίας· επικεντρώνεται στο Android· και οι δύο πλευρές πρέπει να είναι διαθέσιμες ή να χρησιμοποιείται Mailbox |
| OnionShare | Άμεση μεταφορά αρχείων/λήψη/chat/site μέσω προσωρινής onion service· κανένας πάροχος αποθήκευσης | Ο υπολογιστής του αποστολέα είναι η service· ο κάτοχος του link μαθαίνει την πρόσβαση· ο χρονισμός και τα endpoints παραμένουν |
| Κρυπτογραφημένο αρχείο `age` | Απλή κρυπτογράφηση με κλειδί παραλήπτη, ανεξάρτητη από το transport | Το transport βλέπει αποστολέα/παραλήπτη/χρονισμό/μέγεθος· τα filenames/metadata archive και τα endpoints παραμένουν |
| Συνηθισμένο email + TLS | Κρυπτογράφηση καναλιού μεταξύ mail servers | Και οι δύο mail providers μπορούν κανονικά να διαβάσουν το περιεχόμενο και να διατηρούν metadata δρομολόγησης/λογαριασμού |

## Signal: ιδιωτική επαφή χωρίς αποκάλυψη αριθμού

Τα usernames του Signal μπορούν να ξεκινήσουν μια συνομιλία χωρίς να αποκαλύψουν τον αριθμό τηλεφώνου του χρήστη στη νέα επαφή, αλλά για την εγγραφή εξακολουθεί να απαιτείται αριθμός τηλεφώνου.<sup>[[1]](#references)</sup> Το Sealed sender είναι μια σταδιακή προστασία metadata και όχι προστασία από κάθε συσχέτιση IP/χρονισμού.<sup>[[2]](#references)</sup>

### Ροή εργασίας

1. Εγκαταστήστε το Signal από το επίσημο app store/project και ενημερώστε πρώτα το OS.
2. Εγγραφείτε με έναν αριθμό που δικαιούστε νόμιμα να χρησιμοποιείτε. Μην χρησιμοποιείτε ενοικιαζόμενες SMS activations, τον αριθμό άλλου προσώπου ή λογαριασμό provider που αποκτήθηκε με ψευδή ταυτότητα.
3. Στο **Settings → Privacy → Phone Number**, ορίστε ποιοι μπορούν να βλέπουν τον αριθμό και ποιοι μπορούν να βρίσκουν τον λογαριασμό μέσω αριθμού, σύμφωνα με το threat model.
4. Δημιουργήστε ένα username για την αναζήτηση νέων επαφών. Μοιραστείτε το ακριβές link/QR μέσω ήδη authenticated καναλιού· τα usernames μπορούν να αλλάξουν και δεν είναι το όνομα του profile.
5. Απενεργοποιήστε το contact upload/permissions αν η ευκολία δεν αξίζει τη συσχέτιση και προσθέστε επαφές χειροκίνητα όπου το υποστηρίζει η πλατφόρμα.
6. Ανοίξτε τα στοιχεία της επαφής και συγκρίνετε το safety number/QR μέσω δεύτερου καναλιού ή αυτοπροσώπως πριν από ευαίσθητο περιεχόμενο.
7. Ελέγξτε τις linked devices, το registration lock/PIN, τις προεπισκοπήσεις ειδοποιήσεων, την ασφάλεια οθόνης, το call relaying, τις προεπιλογές disappearing messages και τη συμπεριφορά των backups.
8. Στείλτε ένα μη ευαίσθητο δοκιμαστικό μήνυμα και πραγματοποιήστε κλήση. Ελέγξτε τα ίχνη στην οθόνη κλειδώματος, στο desktop, στα wearables και στις cloud notifications και στις δύο πλευρές.
9. Αντιμετωπίστε έναν αλλαγμένο safety number ή μια απρόσμενη linked device ως συμβάν προς διερεύνηση και όχι ως alert που απορρίπτεται αυτόματα.

Μην συνδυάζετε μια pseudonymous φωτογραφία profile, bio, συμμετοχή σε group ή πρόγραμμα με ένα αναγνωριστικό Signal context.

## SimpleX: connections ανά επαφή χωρίς καθολικό identifier

Το SimpleX δρομολογεί μηνύματα μέσω unidirectional queues και δεν εκχωρεί network-wide user identifier. Η δική του policy τεκμηριώνει επίσης transport sessions, προσωρινά δεδομένα server, tradeoffs των push notifications και την ευθύνη των endpoints.<sup>[[3]](#references)</sup>

### Ροή εργασίας

1. Κατεβάστε έναν maintained client από το επίσημο project/store και επαληθεύστε τον publisher. Χρησιμοποιήστε dedicated OS/app profile όταν οι ταυτότητες δεν πρέπει να αναμειγνύονται.
2. Δημιουργήστε ένα **τοπικό** profile με display name και εικόνα ειδικά για το συγκεκριμένο context. Η διαγραφή της εφαρμογής χωρίς backup μπορεί να οδηγήσει σε απώλεια του profile και των connections.
3. Κατά την πρώτη εκκίνηση, επιλέξτε σκόπιμα τη λειτουργία ειδοποιήσεων. Το instant mobile push μπορεί να εκθέσει επιπλέον metadata στην υποδομή της Apple/Google.
4. Δημιουργήστε ένα one-time invitation link για μία επαφή. Μεταφέρετέ το μέσω authenticated καναλιού· όποιος αποκτήσει μια ενεργή πρόσκληση μπορεί να προσπαθήσει να τη χρησιμοποιήσει.
5. Μετά τη σύνδεση, ανοίξτε τα στοιχεία της επαφής και συγκρίνετε τον security code αυτοπροσώπως ή μέσω ανεξάρτητου verified καναλιού.<sup>[[4]](#references)</sup>
6. Χρησιμοποιήστε incognito per-group profile όπου υποστηρίζεται, αντί να ανακυκλώνετε το ίδιο profile σε άσχετα groups.
7. Ρυθμίστε το υποστηριζόμενο Tor transport του client αν το τοπικό δίκτυο/server δεν πρέπει να βλέπει την direct IP. Επιβεβαιώστε τη σύνδεση μετά την αλλαγή· μην επιβάλετε μη υποστηριζόμενο system proxy.
8. Ελέγξτε τα delivery receipts, τα link previews, τις calls, τα automatic downloads και το database export/backup. Κάθε στοιχείο αλλάζει τα metadata ή την έκθεση του endpoint.
9. Δοκιμάστε την ανάκτηση σε μια εφεδρική απομονωμένη συσκευή χωρίς να εκτελείτε duplicated live profile state· το project προειδοποιεί ότι ταυτόχρονα αντίγραφα μπορούν να διαταράξουν τις συνομιλίες.

Η απουσία global identifier δεν εμποδίζει μια επαφή να αναγνωρίσει τον χρήστη μέσω του περιεχομένου, της επαναχρησιμοποίησης profile, της παράδοσης πρόσκλησης, του χρονισμού ή του κοινωνικού γραφήματος.

## Briar: άμεση και ανθεκτική σε διακοπές ανταλλαγή μηνυμάτων

Το Briar συγχρονίζεται απευθείας μεταξύ συσκευών, μέσω Tor όταν υπάρχει σύνδεση και μέσω Bluetooth/Wi-Fi κατά τη διάρκεια τοπικών διακοπών. Το επίσημο threat model θεωρεί μόνο περιορισμένη adversarial παρακολούθηση ραδιοεπικοινωνίας μικρής εμβέλειας, επομένως το τοπικό wireless δεν είναι αόρατο.<sup>[[5]](#references)</sup>

### Ροή εργασίας

1. Εγκαταστήστε το από την επίσημη διανομή του Briar και επαληθεύστε την προέλευση του package. Χρησιμοποιήστε υποστηριζόμενη συσκευή Android με τις τρέχουσες security updates.
2. Δημιουργήστε local account με μοναδικό context nickname και ισχυρό password. Δεν υπάρχει password-reset path· δοκιμάστε ότι το unlock secret μπορεί να ανακτηθεί.
3. Προσθέστε επαφές πρόσωπο με πρόσωπο, σαρώνοντας τα QR codes ο ένας του άλλου όπου είναι δυνατό. Έτσι γίνεται authentication της επαφής και αποφεύγεται η αποστολή link μέσω correlatable καναλιού.
4. Στις ρυθμίσεις συνδεσιμότητας, ενεργοποιήστε μόνο τα απαραίτητα transports: Tor/Internet, Wi-Fi και/ή Bluetooth. Απενεργοποιήστε τα local radios όταν δεν απαιτούνται.
5. Για asynchronous delivery, αξιολογήστε το Briar Mailbox σε dedicated powered device· καταγράψτε το στο inventory και προστατέψτε το φυσικά όπως έναν message server.
6. Στείλτε ένα benign test ενώ υπάρχει διαθέσιμο Internet και έπειτα δοκιμάστε τη σχεδιασμένη διαδρομή διακοπής με απενεργοποιημένο Internet, σε τοποθεσία για την οποία έχετε authorization.
7. Ελέγξτε τα Android backups, τις προεπισκοπήσεις ειδοποιήσεων, τα screenshots και το exported content. Το local encrypted storage εκτίθεται όταν το endpoint ξεκλειδωθεί ή παραβιαστεί.
8. Αφαιρέστε χαμένες επαφές/συσκευές και αποσύρετε ολόκληρο το context αν παραβιαστεί η φυσική κατοχή ή το password του account.

## OnionShare: άμεση προσωρινή μεταφορά

Το OnionShare εκτελεί μια onion service στον υπολογιστή του αποστολέα/παραλήπτη· τα αρχεία δεν ανεβαίνουν σε storage provider και η κίνηση είναι end-to-end encrypted μέσα στο Tor.<sup>[[6]](#references)</sup> Το πλήρες onion URL είναι bearer capability και πρέπει να προστατεύεται.

### Ροή εργασίας κοινής χρήσης αρχείων μέσω GUI

1. Εγκαταστήστε το OnionShare από την επίσημη signed distribution και το Tor Browser στην πλευρά του παραλήπτη.
2. Τοποθετήστε **sanitized copies** των αρχείων σε dedicated staging directory. Μην υποδείξετε στο OnionShare έναν προσωπικό home directory.
3. Ανοίξτε το **Share Files**, προσθέστε μόνο τα staged files, αφήστε ενεργοποιημένη την προστασία private key/access και διατηρήστε ενεργοποιημένο το **Stop sharing after files have been sent** για έναν παραλήπτη.
4. Ξεκινήστε την κοινή χρήση και στείλτε το πλήρες onion URL μέσω ήδη authenticated E2EE καναλιού. Μην το επικολλήσετε σε email, issue trackers ή public chats.
5. Ο παραλήπτης ανοίγει το URL στο Tor Browser, επαληθεύει τα αναμενόμενα filenames/size με τον αποστολέα και πραγματοποιεί download.
6. Και οι δύο πλευρές συγκρίνουν ένα εκ των προτέρων συμφωνημένο ή ανεξάρτητα παραδοθέν SHA-256 digest για ακεραιότητα, όταν το ίδιο το αρχείο αποτελεί το security boundary.
7. Επιβεβαιώστε ότι το OnionShare σταμάτησε μετά το download· διαφορετικά σταματήστε το χειροκίνητα και κλείστε την εφαρμογή.
8. Διαγράψτε το staged copy σύμφωνα με την πολιτική retention και ελέγξτε τις ρυθμίσεις history/log του OnionShare για ακούσια αποκάλυψη filename.

### Ροή εργασίας CLI

Το επίσημο CLI δέχεται αρχεία ως positional arguments και σταματά μετά την προεπιλεγμένη ολοκλήρωση μίας μόνο κοινής χρήσης. Σε host με εγκατεστημένα το επίσημο CLI/Tor:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Παρέδωσε το πλήρες URL με ασφαλή τρόπο. Μην προσθέτεις `--public`, `--no-autostop-sharing`, verbose filename logging ή persistence, εκτός αν το threat model απαιτεί ρητά την προκύπτουσα έκθεση.<sup>[[7]](#references)</sup>

Αντιμετώπιζε τα έγγραφα που λαμβάνεις ως hostile. Άνοιγέ τα σε disposable VM/renderer τύπου Dangerzone και όχι στο host που συνδέεται με την ταυτότητά σου.

## Κρυπτογράφηση ενός αρχείου ανεξάρτητα με `age`

Η κρυπτογράφηση ανεξάρτητη από το transport είναι χρήσιμη όταν ένας storage/email provider ενδέχεται να δει το αντικείμενο. Δεν αποκρύπτει τον αποστολέα, τον παραλήπτη, το μέγεθος, τον χρόνο ή το filename, εκτός αν αυτά αντιμετωπιστούν ξεχωριστά.

### Ρύθμιση παραλήπτη
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Επαληθεύστε τη δημόσια συμβολοσειρά παραλήπτη μέσω δεύτερου καναλιού. Στη συνέχεια, ο αποστολέας εκτελεί:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Ο παραλήπτης αποκρυπτογραφεί σε μια νέα διαδρομή:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Η επίσημη CLI προειδοποιεί ότι το `-o` αντικαθιστά ένα υπάρχον output, επομένως χρησιμοποιήστε έναν νέο κατάλογο και επαληθεύστε το digest/περιεχόμενο πριν το μετακινήσετε.<sup>[[8]](#references)</sup> Μην στέλνετε ποτέ το identity file μαζί με το κρυπτοκείμενο.

## Αναπαραγώγιμο pipeline εκκαθάρισης αρχείων

Η αφαίρεση metadata εξαρτάται από τη μορφή. Διατηρήστε ένα κρυπτογραφημένο πρωτότυπο όταν έχει σημασία η αυθεντικότητα, η forensics ή η αλυσίδα φύλαξης· εργαστείτε σε ένα αντίγραφο.

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
Αυτό ακολουθεί τις ασφαλέστερες οδηγίες του ExifTool για JPEG: η άκριτη αφαίρεση κάθε tag μπορεί επίσης να αφαιρέσει πληροφορίες χρώματος.<sup>[[9]](#references)</sup> Στη συνέχεια, ελέγξτε οπτικά τα pixels για πρόσωπα, αντανακλάσεις, οθόνες, χαρακτηριστικά σημεία και μοναδικά μοτίβα φθοράς/θορύβου.

### Ροή εργασίας Office/PDF

1. Διατηρήστε το επεξεργάσιμο πρωτότυπο κρυπτογραφημένο και offline, μακριά από το πλαίσιο δημοσίευσης.
2. Αφαιρέστε σχόλια, καταγεγραμμένες αλλαγές, κρυφές διαφάνειες/φύλλα, ενσωματωμένα αρχεία, προσωπικά πρότυπα και ιδιότητες εγγράφου στην εφαρμογή συγγραφής.
3. Κάντε export ενός νέου PDF από ένα ξεχωριστό καθαρό profile· μην κάνετε «εκτύπωση» σε cloud printer.
4. Ελέγξτε το με εργαλεία που κατανοούν τη μορφή και με έναν disposable visual renderer:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Αναζητήστε στο rendered output ονόματα, paths, email addresses και κείμενο revision. Το rasterization μπορεί να αφαιρέσει ενεργές δομές, αλλά βλάπτει την accessibility/αναζήτηση και δεν αφαιρεί το ορατό περιεχόμενο ή το writing style.
6. Υπολογίστε το hash του τελικού artifact και μεταφέρετε **μόνο** αυτό το αντίγραφο μέσω του publication compartment.

## Privacy Pass: anonymous authorization for service designers

Το Privacy Pass διαχωρίζει την **έκδοση** token από την **εξαργύρωσή** τους. Ένα origin μπορεί να μάθει ότι ένας client διαθέτει token εγκεκριμένο από issuer, χωρίς να μάθει τη συγκεκριμένη αλληλεπίδραση έκδοσης του client. Η επαναχρησιμοποίηση token, τα μοναδικά metadata, το timing ή η collusion μπορούν να επαναφέρουν τη δυνατότητα συσχέτισης.<sup>[[10]](#references)</sup>

Ασφαλές deployment pattern:

1. Καθορίστε τη δήλωση που αποδεικνύει το token (για παράδειγμα, την καταλληλότητα για rate-limit), όχι μια κρυφή global identity.
2. Χρησιμοποιήστε την τυποποιημένη architecture και τα issuance protocols· μην υλοποιήσετε blind-signature cryptography από την αρχή.
3. Διαχωρίστε τη διαχείριση issuer/attester και origin, όπου η επιθυμητή ιδιότητα το απαιτεί.
4. Ελαχιστοποιήστε τα public/private token metadata και βεβαιωθείτε ότι τα anonymity sets είναι αρκετά μεγάλα.
5. Εκδώστε batches πριν από τη χρήση, όπου υποστηρίζεται, ώστε ο χρόνος έκδοσης να μην ταιριάζει trivially με τον χρόνο εξαργύρωσης.
6. Εξαργυρώστε κάθε token μία φορά, επικυρώστε το origin-bound challenge και διαγράψτε την κατάσταση των expired token.
7. Βεβαιωθείτε ότι τα cookies, το IP logging και τα application accounts δεν ακυρώνουν σιωπηρά την privacy property του token.
8. Ελέγξτε αν τα logs του issuer και του origin μπορούν να συνδέσουν ένα ελεγχόμενο event έκδοσης και εξαργύρωσης μέσω timing, metadata ή unique errors.

Το Privacy Pass είναι feature εφαρμογής και όχι κάτι που μπορεί να προσθέσει ένας user αυθαίρετα σε οποιοδήποτε account.

## Communications verification checklist

- [ ] Η επαφή/invitation/key έγινε authenticated ανεξάρτητα.
- [ ] Η έκθεση του phone number, του username, του profile, του group και του contact upload είναι κατανοητή.
- [ ] Έχουν καταγραφεί οι observers των direct IP, relay, Tor, push provider και local radio.
- [ ] Έγινε έλεγχος των notification previews, wearables, linked desktops και backups.
- [ ] Τα files καθαρίστηκαν, κρυπτογραφήθηκαν αν χρειαζόταν και ανοίχτηκαν σε disposable context.
- [ ] Το recovery λειτουργεί χωρίς bridging άσχετων identities.
- [ ] Τα logs, το history και τα temporary share services διαθέτουν κανόνα shutdown/retention.

## References

- [1] [Signal — Απόρρητο Phone Number και Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy και Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Οδηγός privacy και security](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Πώς λειτουργεί](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage και CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — official CLI και usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Ασφαλής αφαίρεση metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
