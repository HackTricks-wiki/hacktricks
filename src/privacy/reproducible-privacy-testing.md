# Επαναλήψιμος Έλεγχος Privacy

{{#include ../banners/hacktricks-training.md}}

Ένα privacy setup δεν έχει ολοκληρωθεί όταν συνδέεται. Έχει ολοκληρωθεί όταν το δηλωμένο όριό του έχει ελεγχθεί υπό κανονική χρήση, σε περίπτωση failure, recovery και teardown. Πραγματοποιείτε ελέγχους σε infrastructure που σας ανήκει ή που έχετε εξουσιοδότηση να επιθεωρήσετε· οι δημόσιοι ιστότοποι “leak test” γίνονται ένας ακόμη observer.

## Δημιουργία ενός μικρού εξουσιοδοτημένου test environment

Χρησιμοποιήστε τρεις ρόλους, ιδανικά σε ξεχωριστούς providers/networks:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Καταγράψτε πριν από κάθε test:

- το ID του test, την ώρα έναρξης/λήξης σε UTC, τον operator και την εξουσιοδότηση·
- τις εκδόσεις και το configuration hash του endpoint/OS/client·
- τις αναμενόμενες παρατηρήσεις για IPv4, IPv6, DNS, TLS, account, payment και φυσική πρόσβαση·
- ποια logs θα επιθεωρηθούν, καθώς και τα ρολόγια/ζώνες ώρας τους·
- τον κανόνα pass/fail και την ώρα teardown.

Μην κάνετε ποτέ test πρώτα με ευαίσθητη ταυτότητα. Χρησιμοποιήστε synthetic account και benign, μοναδικές canary values που ανήκουν στον tester.

## Test διαδρομής δικτύου

### 1. Καταγράψτε το baseline

Πριν ενεργοποιήσετε τη διαδρομή απορρήτου, καταγράψτε τις τοπικές διαδρομές και τους resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
Σε macOS χρησιμοποιήστε τις εντολές `route -n get default`, `netstat -rn -f inet6` και `scutil --dns`. Αποθηκεύστε τα αποτελέσματα μόνο στο ελεγχόμενο αποθετήριο evidence· ενδέχεται να περιέχουν local identifiers.

### 2. Σύνδεση και έλεγχος routing

Ενεργοποιήστε το VPN/Tor/workload namespace και, στη συνέχεια, ελέγξτε τη διαδρομή που επιλέχθηκε για controlled public addresses:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Αντικαταστήστε τις διευθύνσεις documentation με τις διευθύνσεις του test server. Επιβεβαιώστε ότι το επιλεγμένο interface/table αντιστοιχεί στον σχεδιασμό.

### 3. Παρατηρήστε και από τα δύο άκρα

Ορίστε το URL του endpoint που ελέγχετε και, στη συνέχεια, ζητήστε ένα μοναδικό benign path:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Χρησιμοποίησε ένα domain που ελέγχεται από τον tester, authenticated TLS και ένα μη ευαίσθητο path token. Έλεγξε το server log για:

- source address/ASN και το αναμενόμενο egress·
- IPv4 έναντι IPv6·
- τη συμπεριφορά των Host/SNI που είναι ορατή στο endpoint·
- το user agent και τα application headers·
- την ακριβή ώρα και την επαναχρησιμοποίηση του request.

Μην προσθέσεις `X-Forwarded-For`, μοναδικά debug headers ή cookies που περιέχουν στοιχεία ταυτότητας σε ένα υποτιθέμενα separated request.

### 4. Test DNS με ένα owned canary

Ρύθμισε ένα authoritative test zone του οποίου τα query logs ελέγχεις. Κάνε query για ένα μοναδικό random label μέσω του compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Ελέγξτε το authoritative log. Συνήθως βλέπει τον recursive resolver και όχι απαραίτητα τον client. Συγκρίνετε αυτόν τον resolver με τον προβλεπόμενο σχεδιασμό DNS του VPN/Tor/application. Δεν απαιτείται κάποιος τυχαίος public DNS leak site.

### 5. Test fail-closed behavior

Διατηρήστε ένα benign request loop που στοχεύει το owned endpoint και, στη συνέχεια, διακόψτε το privacy path. Το workload πρέπει να αποτύχει αντί να μεταβεί σε physical interface. Ελέγξτε και τις δύο address families και το DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Επανάλαβε κατά τη διάρκεια:

- crash της διεργασίας του tunnel·
- εναλλαγής από Wi-Fi σε Ethernet ή hotspot·
- αναστολής/επαναφοράς λειτουργίας·
- ανανέωσης DHCP·
- κατάστασης captive portal·
- επανασύνδεσης του provider/λήξης του key.

Για ένα Linux namespace/container, σταμάτησε το tunnel του και επαλήθευσε ότι δεν διαθέτει άλλη default route ή resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Τα ονόματα και οι εντολές διαφέρουν ανά deployment. Μην τα επικολλάτε σε απομακρυσμένο production host χωρίς δυνατότητα ανάκτησης μέσω console.

### 6. Επιθεώρηση τοπικών sockets και πακέτων

Με εξουσιοδότηση, ελέγξτε ποια διεργασία/διεπαφή επικοινωνεί πραγματικά:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Αντικαταστήστε το `TEST_SERVER_IP` με τη συγκεκριμένη διεύθυνση που σας ανήκει· αποφύγετε την ευρεία καταγραφή άσχετων χρηστών. Η φυσική διεπαφή θα πρέπει να βλέπει το tunnel/bridge peer, ενώ η clear destination traffic θα πρέπει να υπάρχει μόνο στο προβλεπόμενο layer.

## Tor and onion-service test

1. Στο Tor Browser, επισκεφθείτε τη σελίδα ελέγχου σύνδεσης του Tor Project και επιβεβαιώστε τη χρήση του Tor. Μην το θεωρήσετε απόδειξη ταυτότητας.<sup>[[1]](#references)</sup>
2. Επισκεφθείτε το HTTPS endpoint που σας ανήκει, χρησιμοποιώντας ένα μοναδικό canary, και επιβεβαιώστε ότι βλέπει έξοδο Tor, κανένα identifying cookie και το τυπικό browser context.
3. Επιλέξτε **New Identity**, επισκεφθείτε ξανά το endpoint με διαφορετικό canary και επαληθεύστε ότι το local state διαγράφηκε όπως αναμενόταν. Η αλλαγή του exit IP δεν είναι εγγυημένη ούτε αποτελεί τον σκοπό του New Identity.
4. Για μια onion service, αποκτήστε πρόσβαση μόνο μέσω Tor Browser. Επιβεβαιώστε ότι ο service host δεν διαθέτει public listener, χρησιμοποιώντας εξουσιοδοτημένο external scan, και ότι οι αποκρίσεις της εφαρμογής δεν περιέχουν public hostname/IP.
5. Επιθεωρήστε τα origin outbound DNS/HTTP, τα templates, τις error pages, τα email/webhooks και τα third-party assets. Οποιοδήποτε direct fetch μπορεί να αποκαλύψει το origin ή τον λογαριασμό του operator.
6. Αν είναι ενεργοποιημένο το client authorization, επιβεβαιώστε ότι ένα uncredentialed καθαρό Tor Browser δεν μπορεί να συνδεθεί και ότι ένα credentialed μπορεί.
7. Περιστρέψτε ένα test authorization key και επιβεβαιώστε ότι ο revoked client χάνει την πρόσβαση χωρίς να αλλάξει η onion identity.

## Browser-compartment test

Δημιουργήστε μια controlled page που καταγράφει μόνο τα πεδία που απαιτούνται για το test, με σύντομη περίοδο διατήρησης. Συγκρίνετε τα personal και privacy compartments για:

- cookies/local storage/service workers και cache·
- browser sync/login state·
- γλώσσα, time zone, διαστάσεις οθόνης/παραθύρου και fonts·
- WebRTC/network candidates·
- permissions και modifications που είναι ορατές σε extensions·
- TLS/HTTP user-agent data στον server.

Μην επιχειρήσετε να κάνετε το Tor Browser «πιο random». Η pass condition είναι η ομοιότητα με το τυπικό anonymity set του και η απουσία personal state, όχι η μέγιστη διαφορά από το personal browser.

Ελέγξτε τα copy/paste, drag/drop, το άνοιγμα downloaded files, τις προτάσεις password manager και τα identity-provider buttons. Αυτά αποτελούν συχνά bridges μεταξύ compartments.

## Operating-system isolation test

### Tails

1. Ξεκινήστε με ένα benign file/canary σε session χωρίς Persistent Storage.
2. Κάντε πλήρες shutdown, επανεκκινήστε και επιβεβαιώστε ότι έχει εξαφανιστεί.
3. Ενεργοποιήστε μόνο μία απαιτούμενη persistence category, επαναλάβετε και επιβεβαιώστε ότι δεν διατηρείται unrelated browser/application state.
4. Επαληθεύστε ότι το Unsafe Browser δεν μπορεί να χρησιμοποιηθεί μετά το portal login για sensitive activity και ότι οι Tor applications επανασυνδέονται κανονικά.

### Whonix/Qubes

1. Σταματήστε το Gateway/net qube και αποδείξτε ότι το Workstation/app qube δεν μπορεί να αποκτήσει πρόσβαση σε IPv4, IPv6 ή DNS.
2. Επιχειρήστε μόνο το ρητά configured inter-qube clipboard/file path και επιβεβαιώστε ότι απουσιάζουν άλλα shared-folder/device paths.
3. Ανοίξτε ένα benign test document σε disposable qube, κλείστε το και επιβεβαιώστε ότι το state του εξαφανίζεται.
4. Ελέγξτε ότι το vault qube δεν διαθέτει NetVM και δεν μπορεί να αποκτήσει ένα μέσω αλλαγής template/default.
5. Δημιουργήστε snapshot/restore ενός test VM και ελέγξτε αν επιστρέφει απροσδόκητα identity-bearing state.

## Communications metadata test

Για κάθε επιλεγμένο messenger:

1. Δημιουργήστε test-only participants σε controlled devices.
2. Καταγράψτε τι απαιτεί η εγγραφή: phone, app-store account, IP, push service, username ή invitation.
3. Στείλτε ένα benign message, ενώ επιθεωρείτε τα notification previews, linked desktops, wearables και backups.
4. Επαληθεύστε τους safety/security codes μέσω independent path.
5. Απενεργοποιήστε τα receipts/push ή ενεργοποιήστε τα Tor/local transports ένα-ένα και παρατηρήστε τις αλλαγές σε reliability/metadata.
6. Κάντε export ή restore ενός test backup και τεκμηριώστε ακριβώς ποιο profile, ποιες contacts και ποιο history περιέχει.
7. Απενεργοποιήστε ή ανακαλέστε ένα test device και επιβεβαιώστε ότι οι υπόλοιποι participants βλέπουν την αναμενόμενη αλλαγή key/device.

Μην κάνετε test επικοινωνώντας με άτομα που δεν εμπλέκονται ή δημιουργώντας abusive traffic.

## File-sanitization test

1. Κάντε hash και διατηρήστε το πρωτότυπο σε encrypted evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Δημιουργήστε ένα καθαρό αντίγραφο χρησιμοποιώντας τη διαδικασία που αφορά τη συγκεκριμένη μορφή στο [Επικοινωνίες και κοινοποίηση με προστασία απορρήτου](privacy-preserving-communications-and-sharing.md).
3. Συγκρίνετε τα αποθέματα μεταδεδομένων:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Κάντε render/open στο αντίγραφο σε disposable context. Ελέγξτε κρυφό περιεχόμενο, συνημμένα, links, forms, layers, thumbnails και visual identifiers.
5. Κάντε αναζήτηση μόνο στο staged αντίγραφο για γνωστές canary συμβολοσειρές author/email/path.
6. Υπολογίστε το hash του τελικού output και ζητήστε από δεύτερο άτομο να επαληθεύσει το ακριβές αρχείο που θα δημοσιευτεί.

Η απουσία από το output του ExifTool δεν αποτελεί απόδειξη ανωνυμίας· τα εσωτερικά του format, τα pixels, το prose και τα records διανομής παραμένουν.

## Payment privacy test

Χρησιμοποιήστε το μικρότερο επιτρεπόμενο ποσό ή ένα επίσημο test network/sandbox:

1. Καταγράψτε την αναμενόμενη view για τον payer, τον payee/merchant, τον issuer/exchange, το network/node, το public ledger και τον accountant/controller.
2. Δημιουργήστε ένα μοναδικό test invoice/merchant context χωρίς false identity.
3. Κάντε μία πληρωμή και, στη συνέχεια, συλλέξτε τη δική σας receipt, statement, merchant dashboard, wallet/node log και public-chain view όπου εφαρμόζεται.
4. Ελέγξτε αν το ποσό, το timestamp, το address/token, ο λογαριασμός, το IP/device, η παράδοση και η διαδρομή refund αντιστοιχούν στον πίνακα observers.
5. Για Bitcoin, ελέγξτε το address reuse, τα selected inputs, το change και το μεταγενέστερο consolidation στη view coin-control του wallet.
6. Για shielded protocols, επαληθεύστε το πραγματικό pool/path και τι αποκαλύπτει ένα viewing key· μην συμπεραίνετε privacy από το wallet branding.
7. Για e-cash/Taler, ελέγξτε το backup/recovery, το refund και το redemption με μικρή αξία· τεκμηριώστε τα records στα όρια mint/exchange/federation.
8. Ανακαλέστε μια virtual card/test credential και επιβεβαιώστε ότι η μεταγενέστερη authorization αποτυγχάνει, ενώ η νόμιμη διαχείριση refund παραμένει κατανοητή.
9. Κάντε reconcile και διατηρήστε τα απαιτούμενα tax/authorization evidence κρυπτογραφημένα.

Ποτέ μην δημιουργείτε circular transfers, threshold-splitting, fake purchases ή ύποπτα refunds ως “privacy test”.

## Authorized red-team accountability drill

Πριν από την άσκηση, εκτελέστε ένα tabletop και technical drill:

1. Ένας operator запускаρει ένα benign canary από κάθε εγκεκριμένο source path.
2. Το target SOC καταγράφει ό,τι εντοπίζει χωρίς να λαμβάνει την ταυτότητα του operator, αν προβλέπεται blind testing.
3. Ο exercise controller αντιστοιχίζει το source → engagement → operator από το escrowed map και το signed job record.
4. Ο controller στέλνει το emergency stop· ο operator και ο infrastructure owner επιδεικνύουν shutdown εντός του χρόνου που ορίζει το ROE.
5. Το provider abuse λαμβάνει το σωστό 24/7 contact και authorization reference.
6. Τα evidence δείχνουν το target, τον χρόνο, το tool/job και τον operator, χωρίς να διατηρούν περιττό payload content.
7. Δεύτερος operator επαληθεύει το credential revocation και το resource teardown.

Αποτύχετε στο readiness review αν το SOC μπορεί εύκολα να δει personal/home infrastructure **ή** αν ο controller δεν μπορεί να αποδώσει γρήγορα την πηγή και να τη σταματήσει.

## Test record template
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Έλεγχος σύνδεσης](https://check.torproject.org/)
- [2] [WireGuard — Δρομολόγηση και χώροι ονομάτων δικτύου](https://www.wireguard.com/netns/)
- [3] [ExifTool — Συχνές ερωτήσεις και καθοδήγηση μεταδεδομένων](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Τεχνικός οδηγός για δοκιμή και αξιολόγηση ασφάλειας πληροφοριών](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
