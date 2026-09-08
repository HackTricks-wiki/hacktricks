# Privacy Operating Systems

Τα λειτουργικά συστήματα με έμφαση στο privacy μειώνουν τα λάθη στο routing και την persistence, αλλά κανένα δεν μπορεί να αντισταθμίσει συμπεριφορές που αποκαλύπτουν την ταυτότητα ή compromised hardware.

## Επιλέξτε το μοντέλο απομόνωσης

| System | Καταλληλότερο για | Persistence | Network enforcement | Κύριος συμβιβασμός |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Περιστασιακή anonymous περιήγηση στο web | Η κατάσταση του browser περιορίζεται συνήθως στη συνεδρία | Μόνο η κίνηση του browser | Οι άλλες εφαρμογές και το host παραμένουν εκτός Tor |
| **Tails** | Φορητές, amnesic συνεδρίες ενός σκοπού | Προαιρετικό κρυπτογραφημένο Persistent Storage | Η κίνηση στο Internet περνά υποχρεωτικά μέσω Tor | Τριβές σε reboot/workflow· εμπιστοσύνη σε firmware/hardware |
| **Whonix** | Persistent εφαρμογές που χρειάζονται υποχρεωτικό Tor routing | Persistent VMs | Διαχωρισμός Gateway/Workstation | Το host/hypervisor και η ανάμειξη ταυτοτήτων παραμένουν |
| **Qubes-Whonix** | Ισχυρός διαχωρισμός compartments για προχωρημένους χρήστες | Ανά qube | Dedicated network qubes και Whonix | Απαιτήσεις hardware και λειτουργική πολυπλοκότητα |

## Tails

Το Tails εκκινεί ανεξάρτητα από removable media, δρομολογεί την κίνηση στο Internet μέσω Tor και έχει σχεδιαστεί ώστε να αφήνει ελάχιστη τοπική κατάσταση. Οι ίδιες οι προειδοποιήσεις του τονίζουν ότι δεν μπορεί να προστατεύσει από compromised BIOS/firmware/hardware, αποκαλύψεις που προσδιορίζουν την ταυτότητα, metadata αρχείων ή έναν ισχυρό παρατηρητή που συσχετίζει και τα δύο άκρα.<sup>[[1]](#references)</sup>

### Single-purpose Tails workflow

1. Κατεβάστε το Tails από τον επίσημο ιστότοπο σε έναν αξιόπιστο, ενημερωμένο υπολογιστή και ακολουθήστε την επίσημη διαδικασία verification/install.
2. Χρησιμοποιήστε ένα υποστηριζόμενο USB drive μόνο για την εκκίνηση του Tails· μην το χρησιμοποιείτε επίσης ως γενικό drive μεταφοράς αρχείων.
3. Εκκινήστε σε hardware που ελέγχετε φυσικά. Ένα live OS δεν μπορεί να εξουδετερώσει ένα hardware keylogger ή malicious firmware.
4. Αφήστε το Persistent Storage απενεργοποιημένο, εκτός αν το workflow το χρειάζεται πραγματικά. Αν το ενεργοποιήσετε, αποθηκεύστε μόνιμα μόνο τις απαιτούμενες κατηγορίες και χρησιμοποιήστε ισχυρό passphrase.
5. Συνδεθείτε σε ένα νόμιμο δίκτυο. Αν ένα captive portal είναι αναπόφευκτο, χρησιμοποιήστε το Unsafe Browser του Tails μόνο για το portal, μην αποκαλύψετε περιττές πληροφορίες ταυτότητας, κλείστε το αμέσως και συνδεθείτε στο Tor πριν από οποιαδήποτε ευαίσθητη δραστηριότητα.<sup>[[2]](#references)</sup>
6. Ρυθμίστε ένα Tor bridge αν έχει σημασία η άμεση ορατότητα ή το blocking του Tor.
7. Εκτελέστε **μία contextual ταυτότητα/σκοπό ανά συνεδρία**. Το Tails συνιστά restart μεταξύ δραστηριοτήτων που δεν πρέπει να συνδεθούν μεταξύ τους.<sup>[[1]](#references)</sup>
8. Ελέγξτε και καθαρίστε τα αρχεία πριν από τη δημοσίευση. Μην ανοίγετε downloaded active documents σε εφαρμογή που θα μπορούσε να παρακάμψει το προβλεπόμενο context.
9. Κάντε πλήρες shutdown όταν τελειώσετε και διατηρήστε το USB σε φυσικά ασφαλές σημείο.

## Whonix

Το Whonix διαχωρίζει ένα Tor-routing **Gateway** από ένα **Workstation**, οι εφαρμογές του οποίου δεν μπορούν να μάθουν άμεσα την εξωτερική IP. Αυτό μειώνει ουσιαστικά τα λάθη σε proxy/DNS, αλλά το host, ο hypervisor, η συμπεριφορά και τα έγγραφα μπορούν ακόμη να αποκαλύψουν την ταυτότητα. Το Whonix προειδοποιεί ρητά να μην χρησιμοποιείται ένα workstation για πολλαπλές ταυτότητες ή να συνδυάζεται anonymous και non-anonymous δραστηριότητα.<sup>[[3]](#references)</sup>

### Compartment workflow

1. Επαληθεύστε το Whonix image και την πλατφόρμα virtualization από επίσημες πηγές.
2. Κάντε patch στο host, τον hypervisor, το Gateway και το Workstation πριν από τη χρήση.
3. Κλωνοποιήστε ένα νέο Workstation για κάθε ταυτότητα ή engagement· μην κλωνοποιείτε ποτέ ένα VM αφού έχει εισαχθεί state που συνδέεται με την ταυτότητα.
4. Κρατήστε προσωπικούς λογαριασμούς, shared folders του host, clipboard synchronization, USB devices και δεδομένα χρόνου/τοποθεσίας εκτός του Workstation.
5. Χρησιμοποιήστε snapshots για recovery, όχι ως υποκατάστατο των backups ή του διαχωρισμού ταυτοτήτων.
6. Επιβεβαιώστε ότι το Workstation δεν μπορεί να συνδεθεί στο Internet όταν το Gateway είναι σταματημένο.
7. Για ιδιαίτερα επικίνδυνα αρχεία, χρησιμοποιήστε disposable VM/qube και εξαγάγετε μόνο ένα sanitized αποτέλεσμα.

## Qubes OS και Qubes-Whonix

Το Qubes υλοποιεί την ασφάλεια μέσω compartmentalization με qubes που βασίζονται στο Xen. Ο σχεδιασμός του περιορίζει το ενδεχόμενο ένα compromise σε έναν domain να επηρεάσει αυτόματα άλλους, αλλά οι εφαρμογές μέσα στο **ίδιο** qube δεν είναι απομονωμένες μεταξύ τους.<sup>[[4]](#references)</sup> Τα Disposable qubes παρέχουν fresh state για untrusted sites, αρχεία και συσκευές.<sup>[[5]](#references)</sup>

Μια πρακτική διάταξη:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Κανόνες:

- Δώστε σε κάθε qube ένα επίπεδο εμπιστοσύνης και έναν σκοπό ταυτότητας.
- Διατηρείτε τα secrets σε ένα offline vault qube και χρησιμοποιείτε ρητές inter-qube λειτουργίες αντιγραφής/αρχείων.
- Ανοίγετε μη ζητηθέντα αρχεία και links σε disposables.
- Δρομολογείτε μόνο τα προβλεπόμενα qubes μέσω Whonix ή ενός dedicated VPN qube.
- Επισημαίνετε τα παράθυρα με σαφήνεια και διακόπτετε τα άσχετα qubes κατά την ευαίσθητη εργασία.
- Μην θεωρείτε ότι δύο qubes αποτρέπουν τη συσχέτιση, αν μοιράζονται accounts, περιεχόμενο, χρονοδιαγράμματα ή πληρωμές.

## Verification and maintenance

- Επαληθεύετε τις υπογραφές/checksums των installers μέσω των επίσημων οδηγιών.
- Κάνετε patch πρώτα στα templates και έπειτα επανεκκινείτε τα εξαρτώμενα qubes/VMs.
- Επιβεβαιώνετε τη συμπεριφορά network-deny, το DNS, το IPv6, το ρολόι, το clipboard, τους shared directories και την ανάθεση USB.
- Ελέγχετε το Persistent Storage και τα VM snapshots για παλιά δεδομένα που φέρουν στοιχεία ταυτότητας.
- Διατηρείτε κρυπτογραφημένα offline backups των seeds/keys και δοκιμάζετε την επαναφορά σε απομονωμένο περιβάλλον.
- Ανακατασκευάζετε ένα compartment μετά από πιθανή παραβίαση· η αλλαγή του egress IP του δεν επαρκεί.

## References

- [1] [Tails — Προειδοποιήσεις: Το Tails είναι ασφαλές, αλλά δεν είναι μαγικό](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Σύνδεση σε δίκτυο μέσω captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Περιορισμοί του Whonix και του Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Στόχοι σχεδιασμού ασφάλειας](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Πώς να χρησιμοποιείτε disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
