# Αναπαραγώγιμος Έλεγχος Privacy

Μια ρύθμιση privacy δεν ολοκληρώνεται όταν συνδέεται. Ολοκληρώνεται όταν το δηλωμένο όριό της έχει ελεγχθεί υπό κανονική χρήση, σε περίπτωση αστοχίας, κατά την ανάκτηση και κατά την κατάργηση. Πραγματοποιείτε ελέγχους σε υποδομές που σας ανήκουν ή τις οποίες έχετε εξουσιοδότηση να επιθεωρήσετε· οι δημόσιες τοποθεσίες “leak test” γίνονται ένας ακόμη παρατηρητής.

## Δημιουργήστε ένα μικρό εξουσιοδοτημένο περιβάλλον ελέγχου

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
- τις αναμενόμενες παρατηρήσεις για IPv4, IPv6, DNS, TLS, account, payment και τη φυσική υποδομή·
- ποια logs θα επιθεωρηθούν, καθώς και τα ρολόγια και τις time zones τους·
- τον κανόνα pass/fail και την ώρα teardown.

Μην κάνετε ποτέ πρώτα test σε ευαίσθητη ταυτότητα. Χρησιμοποιήστε synthetic account και benign, μοναδικές canary values που ανήκουν στον tester.

## Test διαδρομής δικτύου

### 1. Καταγράψτε το baseline

Πριν ενεργοποιήσετε τη διαδρομή ιδιωτικότητας, καταγράψτε τις τοπικές routes και τους resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
Στο macOS χρησιμοποιήστε `route -n get default`, `netstat -rn -f inet6` και `scutil --dns`. Αποθηκεύστε την έξοδο μόνο στο ελεγχόμενο evidence store· ενδέχεται να περιέχει local identifiers.

### 2. Σύνδεση και έλεγχος του routing

Ενεργοποιήστε το VPN/Tor/workload namespace και, στη συνέχεια, ελέγξτε το route που επιλέχθηκε για controlled public addresses:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Αντικαταστήστε τις διευθύνσεις τεκμηρίωσης με τις διευθύνσεις του test server. Επιβεβαιώστε ότι το επιλεγμένο interface/table αντιστοιχεί στον σχεδιασμό.

### 3. Παρατηρήστε και από τις δύο πλευρές

Ορίστε το URL του endpoint που ελέγχετε και, στη συνέχεια, ζητήστε ένα μοναδικό ακίνδυνο path:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Χρησιμοποίησε ένα πραγματικό domain που ελέγχεται από τον tester, authenticated TLS και ένα non-sensitive path token. Έλεγξε το server log για:

- source address/ASN και το expected egress·
- IPv4 έναντι IPv6·
- τη συμπεριφορά των Host/SNI που είναι ορατή στο endpoint·
- το user agent και τα application headers·
- την ακριβή ώρα και την επαναχρησιμοποίηση του request.

Μην προσθέτεις `X-Forwarded-For`, μοναδικά debug headers ή cookies που περιέχουν identity σε ένα supposedly separated request.

### 4. Έλεγχος DNS με ένα owned canary

Διαμόρφωσε ένα authoritative test zone του οποίου τα query logs ελέγχεις. Κάνε query για ένα μοναδικό τυχαίο label μέσω του compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Ελέγξτε το authoritative log. Συνήθως βλέπει τον recursive resolver και όχι απαραίτητα τον client. Συγκρίνετε αυτόν τον resolver με τον προβλεπόμενο σχεδιασμό DNS του VPN/Tor/application. Δεν απαιτείται ένας τυχαίος public DNS leak ιστότοπος.

### 5. Test fail-closed behavior

Διατηρήστε έναν benign request loop με προορισμό το owned endpoint και, στη συνέχεια, διακόψτε το privacy path. Το workload πρέπει να αποτύχει αντί να μεταβεί σε physical interface. Ελέγξτε και τις δύο address families και το DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Επαναλάβετε κατά τη διάρκεια:

- crash της διεργασίας του tunnel·
- εναλλαγής από Wi-Fi σε Ethernet ή hotspot·
- αναστολής λειτουργίας/αφύπνισης·
- ανανέωσης DHCP·
- κατάστασης captive-portal·
- επανασύνδεσης του provider/λήξης του key.

Για ένα Linux namespace/container, σταματήστε το tunnel του και επαληθεύστε ότι δεν διαθέτει άλλη default route ή resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Τα ονόματα και οι εντολές διαφέρουν ανά deployment. Μην τα επικολλάτε σε απομακρυσμένο production host χωρίς ανάκτηση μέσω console.

### 6. Inspect local sockets and packets

Με εξουσιοδότηση, ελέγξτε ποιο process/interface επικοινωνεί πραγματικά:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Αντικαταστήστε το `TEST_SERVER_IP` με τη ρητή διεύθυνση που σας ανήκει· αποφύγετε την ευρεία capture άσχετων χρηστών. Η physical interface θα πρέπει να βλέπει το tunnel/bridge peer, ενώ clear destination traffic θα πρέπει να υπάρχει μόνο στο προβλεπόμενο layer.

## Tor και onion-service test

1. Στο Tor Browser, επισκεφθείτε το connection check του Tor Project και επιβεβαιώστε τη χρήση του Tor. Μην το θεωρήσετε απόδειξη ταυτότητας.<sup>[[1]](#references)</sup>
2. Επισκεφθείτε το HTTPS endpoint που σας ανήκει, χρησιμοποιώντας ένα μοναδικό canary, και επιβεβαιώστε ότι βλέπει ένα Tor exit, κανένα identifying cookie και το standard browser context.
3. Επιλέξτε **New Identity**, επισκεφθείτε ξανά τη σελίδα με διαφορετικό canary και επαληθεύστε ότι το local state διαγράφηκε όπως αναμενόταν. Η αλλαγή του exit IP δεν είναι εγγυημένη ούτε αποτελεί τον σκοπό του New Identity.
4. Για ένα onion service, αποκτήστε πρόσβαση σε αυτό μόνο μέσω του Tor Browser. Επιβεβαιώστε ότι το service host δεν έχει public listener, χρησιμοποιώντας authorized external scan, και ότι οι application responses δεν περιέχουν public hostname/IP.
5. Επιθεωρήστε τα origin outbound DNS/HTTP, templates, error pages, email/webhooks και third-party assets. Οποιοδήποτε direct fetch μπορεί να αποκαλύψει το origin ή το operator account.
6. Αν είναι ενεργοποιημένο το client authorization, επιβεβαιώστε ότι ένα uncredentialed καθαρό Tor Browser δεν μπορεί να συνδεθεί και ότι ένα credentialed μπορεί.
7. Περιστρέψτε ένα test authorization key και επιβεβαιώστε ότι ο revoked client χάνει την πρόσβαση χωρίς αλλαγή του onion identity.

## Browser-compartment test

Δημιουργήστε μια controlled page που καταγράφει μόνο τα πεδία που απαιτούνται για το test, με σύντομη περίοδο retention. Συγκρίνετε τα personal και privacy compartments για:

- cookies/local storage/service workers και cache·
- browser sync/login state·
- language, time zone, screen/window dimensions και fonts·
- WebRTC/network candidates·
- permissions και extension-visible modifications·
- TLS/HTTP user-agent data στον server.

Μην προσπαθήσετε να κάνετε το Tor Browser «πιο random». Η προϋπόθεση επιτυχίας είναι η ομοιότητα με το standard anonymity set του και η απουσία personal state, όχι η μέγιστη διαφορά από το personal browser.

Δοκιμάστε copy/paste, drag/drop, άνοιγμα downloaded-file, password-manager suggestions και identity-provider buttons. Αυτά αποτελούν συχνές γέφυρες μεταξύ compartments.

## Operating-system isolation test

### Tails

1. Ξεκινήστε με ένα benign file/canary σε session χωρίς Persistent Storage.
2. Κάντε πλήρες shutdown, επανεκκινήστε και επιβεβαιώστε ότι έχει εξαφανιστεί.
3. Ενεργοποιήστε μόνο μία απαιτούμενη persistence category, επαναλάβετε και επιβεβαιώστε ότι το άσχετο browser/application state δεν διατηρείται.
4. Επαληθεύστε ότι το Unsafe Browser δεν μπορεί να χρησιμοποιηθεί μετά το portal login για sensitive activity και ότι οι Tor applications επανασυνδέονται κανονικά.

### Whonix/Qubes

1. Σταματήστε το Gateway/net qube και αποδείξτε ότι το Workstation/app qube δεν μπορεί να αποκτήσει πρόσβαση σε IPv4, IPv6 ή DNS.
2. Επιχειρήστε μόνο το ρητά configured inter-qube clipboard/file path και επιβεβαιώστε ότι τα άλλα shared-folder/device paths απουσιάζουν.
3. Ανοίξτε ένα benign test document σε disposable qube, κλείστε το και επιβεβαιώστε ότι το state του εξαφανίζεται.
4. Ελέγξτε ότι το vault qube δεν έχει NetVM και δεν μπορεί να αποκτήσει ένα μέσω αλλαγής template/default.
5. Εκτελέστε snapshot/restore σε ένα test VM και επιθεωρήστε αν identity-bearing state επιστρέφει απροσδόκητα.

## Communications metadata test

Για κάθε επιλεγμένο messenger:

1. Δημιουργήστε test-only participants σε controlled devices.
2. Καταγράψτε τι απαιτεί η registration: phone, app-store account, IP, push service, username ή invitation.
3. Στείλτε ένα benign message ενώ επιθεωρείτε notification previews, linked desktops, wearables και backups.
4. Επαληθεύστε τα safety/security codes μέσω independent path.
5. Απενεργοποιήστε receipts/push ή ενεργοποιήστε Tor/local transports ένα κάθε φορά και παρατηρήστε τις αλλαγές σε reliability/metadata.
6. Κάντε export ή restore ενός test backup και τεκμηριώστε ακριβώς ποιο profile, contacts και history περιέχει.
7. Χάστε/ανακαλέστε ένα test device και επιβεβαιώστε ότι οι υπόλοιποι participants βλέπουν την αναμενόμενη αλλαγή key/device.

Μην κάνετε test επικοινωνώντας με άσχετους ανθρώπους ή δημιουργώντας abusive traffic.

## File-sanitization test

1. Υπολογίστε το hash και διατηρήστε το original σε encrypted evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Δημιουργήστε ένα καθαρό αντίγραφο χρησιμοποιώντας τη διαδικασία ειδικά για τη μορφή στο [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Συγκρίνετε τα αποθέματα μεταδεδομένων:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Κάντε render/open το αντίγραφο σε disposable context. Ελέγξτε κρυφό περιεχόμενο, attachments, links, forms, layers, thumbnails και visual identifiers.
5. Κάντε αναζήτηση μόνο στο staged αντίγραφο για γνωστά canary author/email/path strings.
6. Κάντε hash στο τελικό output και ζητήστε από δεύτερο άτομο να επαληθεύσει το ακριβές file που θα δημοσιευτεί.

Η απουσία από το output του ExifTool δεν αποτελεί απόδειξη anonymity· τα format internals, τα pixels, η prose και τα distribution records παραμένουν.

## Payment privacy test

Χρησιμοποιήστε το μικρότερο επιτρεπόμενο ποσό ή ένα επίσημο test network/sandbox:

1. Καταγράψτε την αναμενόμενη view για τον payer, τον payee/merchant, τον issuer/exchange, το network/node, το public ledger και τον accountant/controller.
2. Δημιουργήστε ένα μοναδικό test invoice/merchant context χωρίς false identity.
3. Πληρώστε μία φορά και, στη συνέχεια, συλλέξτε τη **δική σας** receipt, statement, merchant dashboard, wallet/node log και public-chain view, όπου εφαρμόζεται.
4. Ελέγξτε αν το ποσό, το timestamp, το address/token, ο λογαριασμός, το IP/device, η παράδοση και η διαδρομή refund συμφωνούν με τον observer table.
5. Για το Bitcoin, ελέγξτε address reuse, selected inputs, change και μεταγενέστερη consolidation στο coin-control view του wallet.
6. Για shielded protocols, επαληθεύστε το πραγματικό pool/path και όσα αποκαλύπτει ένα viewing key· μην συμπεραίνετε privacy από το wallet branding.
7. Για e-cash/Taler, δοκιμάστε backup/recovery, refund και redemption με μικρή αξία· τεκμηριώστε τα boundary records του mint/exchange/federation.
8. Ανακαλέστε μια virtual card/test credential και επιβεβαιώστε ότι μεταγενέστερη authorization αποτυγχάνει, ενώ η νόμιμη διαχείριση refund παραμένει κατανοητή.
9. Κάντε reconcile και διατηρήστε τα απαιτούμενα tax/authorization evidence κρυπτογραφημένα.

Ποτέ μην δημιουργείτε circular transfers, threshold-splitting, fake purchases ή ύποπτα refunds ως «privacy test».

## Authorized red-team accountability drill

Πριν από την άσκηση, εκτελέστε tabletop και technical drill:

1. Ένας operator εκκινεί ένα benign canary από κάθε εγκεκριμένο source path.
2. Το target SOC καταγράφει όσα ανιχνεύει χωρίς να λάβει την ταυτότητα του operator, εάν προβλέπεται blind testing.
3. Ο exercise controller επιλύει το source → engagement → operator από το escrowed map και το signed job record.
4. Ο controller στέλνει το emergency stop· ο operator και ο infrastructure owner επιδεικνύουν shutdown εντός του χρόνου που ορίζει το ROE.
5. Το provider abuse λαμβάνει τη σωστή 24/7 contact και authorization reference.
6. Τα evidence δείχνουν το target, την ώρα, το tool/job και τον operator χωρίς να διατηρούν περιττό payload content.
7. Δεύτερος operator επαληθεύει το credential revocation και το resource teardown.

Απορρίψτε το readiness review αν το SOC μπορεί εύκολα να δει personal/home infrastructure **ή** αν ο controller δεν μπορεί να αποδώσει γρήγορα και να διακόψει το source.

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
- [2] [WireGuard — Δρομολόγηση και Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — Συχνές ερωτήσεις και οδηγίες μεταδεδομένων](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Τεχνικός οδηγός για τον έλεγχο και την αξιολόγηση ασφάλειας πληροφοριών](https://csrc.nist.gov/pubs/sp/800/115/final)
