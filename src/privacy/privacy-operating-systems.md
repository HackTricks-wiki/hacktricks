# Λειτουργικά συστήματα προστασίας απορρήτου

{{#include ../banners/hacktricks-training.md}}

Τα λειτουργικά συστήματα που εστιάζουν στο απόρρητο μειώνουν τα λάθη δρομολόγησης και persistence, αλλά κανένα δεν μπορεί να αντισταθμίσει συμπεριφορές που αποκαλύπτουν την ταυτότητα ή παραβιασμένο hardware.

## Επιλέξτε το μοντέλο απομόνωσης

| Σύστημα | Καταλληλότερη χρήση | Persistence | Επιβολή δικτύου | Κύριος συμβιβασμός |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Περιστασιακή ανώνυμη περιήγηση στο web | Η κατάσταση του browser περιορίζεται συνήθως στη session | Μόνο η κίνηση του browser | Οι άλλες εφαρμογές και το host παραμένουν εκτός Tor |
| **Tails** | Φορητές, amnesic sessions μίας χρήσης | Προαιρετικό κρυπτογραφημένο Persistent Storage | Η κίνηση Internet περνά υποχρεωτικά μέσω Tor | Τριβές από τα reboots και τη ροή εργασίας· εμπιστοσύνη σε firmware/hardware |
| **Whonix** | Persistent εφαρμογές που χρειάζονται υποχρεωτική δρομολόγηση μέσω Tor | Persistent VMs | Διαχωρισμός Gateway/Workstation | Το host/hypervisor και η ανάμειξη ταυτοτήτων παραμένουν |
| **Qubes-Whonix** | Ισχυρός διαχωρισμός compartments για προχωρημένους χρήστες | Ανά qube | Αφιερωμένα network qubes και Whonix | Απαιτήσεις hardware και λειτουργική πολυπλοκότητα |

## Tails

Το Tails εκκινεί ανεξάρτητα από removable media, δρομολογεί την κίνηση Internet μέσω Tor και έχει σχεδιαστεί ώστε να αφήνει ελάχιστη τοπική κατάσταση. Οι δικές του προειδοποιήσεις τονίζουν ότι δεν μπορεί να προστατεύσει από παραβιασμένο BIOS/firmware/hardware, αποκαλύψεις ταυτότητας, metadata αρχείων ή έναν ισχυρό παρατηρητή που συσχετίζει και τα δύο άκρα.<sup>[[1]](#references)</sup>

### Ροή εργασίας Tails μίας χρήσης

1. Κατεβάστε το Tails από τον επίσημο ιστότοπο σε έναν αξιόπιστο και ενημερωμένο υπολογιστή και ακολουθήστε την επίσημη διαδικασία verification/install.
2. Χρησιμοποιήστε ένα υποστηριζόμενο USB drive μόνο για την εκκίνηση του Tails· μην το χρησιμοποιείτε επίσης ως γενικό drive μεταφοράς αρχείων.
3. Εκκινήστε σε hardware που ελέγχετε φυσικά. Ένα live OS δεν μπορεί να εξουδετερώσει hardware keylogger ή malicious firmware.
4. Διατηρήστε το Persistent Storage απενεργοποιημένο, εκτός αν η ροή εργασίας το χρειάζεται πραγματικά. Αν το ενεργοποιήσετε, αποθηκεύστε persistent μόνο τις απαιτούμενες κατηγορίες και χρησιμοποιήστε ισχυρό passphrase.
5. Συνδεθείτε σε νόμιμο δίκτυο. Αν ένα captive portal είναι αναπόφευκτο, χρησιμοποιήστε το Tails' Unsafe Browser μόνο για το portal, μην αποκαλύψετε περιττές πληροφορίες ταυτότητας, κλείστε το αμέσως και συνδεθείτε στο Tor πριν από οποιαδήποτε ευαίσθητη δραστηριότητα.<sup>[[2]](#references)</sup>
6. Διαμορφώστε ένα Tor bridge αν έχει σημασία η άμεση ορατότητα ή η παρεμπόδιση του Tor.
7. Εκτελέστε **μία contextual ταυτότητα/σκοπό ανά session**. Το Tails συνιστά επανεκκίνηση μεταξύ δραστηριοτήτων που δεν θα πρέπει να συνδεθούν μεταξύ τους.<sup>[[1]](#references)</sup>
8. Ελέγξτε και απολυμάνετε τα αρχεία πριν από τη δημοσίευση. Μην ανοίγετε ληφθέντα ενεργά έγγραφα σε εφαρμογή που θα μπορούσε να παρακάμψει το προβλεπόμενο context.
9. Τερματίστε πλήρως τη λειτουργία όταν ολοκληρώσετε και διατηρήστε το USB ασφαλές σε φυσικό επίπεδο.

## Whonix

Το Whonix διαχωρίζει ένα Tor-routing **Gateway** από ένα **Workstation**, οι εφαρμογές του οποίου δεν μπορούν να μάθουν άμεσα την εξωτερική IP. Αυτό μειώνει σημαντικά τα λάθη proxy/DNS, αλλά το host, ο hypervisor, η συμπεριφορά και τα έγγραφα μπορούν ακόμη να αποκαλύψουν την ταυτότητα. Το Whonix προειδοποιεί ρητά να μην χρησιμοποιείται ένα workstation για πολλές ταυτότητες ή να συνδυάζεται ανώνυμη και μη ανώνυμη δραστηριότητα.<sup>[[3]](#references)</sup>

### Ροή εργασίας με compartments

1. Επαληθεύστε το Whonix image και την πλατφόρμα virtualization από επίσημες πηγές.
2. Εφαρμόστε patches στο host, τον hypervisor, το Gateway και το Workstation πριν από τη χρήση.
3. Κλωνοποιήστε ένα νέο Workstation για κάθε ταυτότητα ή engagement· μην κλωνοποιείτε ποτέ ένα VM αφού έχει εισαχθεί κατάσταση που συνδέεται με την ταυτότητα.
4. Κρατήστε τους προσωπικούς λογαριασμούς, τους κοινόχρηστους φακέλους του host, τον συγχρονισμό clipboard, τις συσκευές USB και τα δεδομένα ώρας/τοποθεσίας εκτός του Workstation.
5. Χρησιμοποιήστε snapshots για recovery, όχι ως υποκατάστατο των backups ή του διαχωρισμού ταυτοτήτων.
6. Επιβεβαιώστε ότι το Workstation δεν μπορεί να έχει πρόσβαση στο Internet όταν το Gateway είναι σταματημένο.
7. Για ιδιαίτερα επικίνδυνα αρχεία, χρησιμοποιήστε disposable VM/qube και εξαγάγετε μόνο ένα απολυμασμένο αποτέλεσμα.

## Qubes OS και Qubes-Whonix

Το Qubes υλοποιεί την ασφάλεια μέσω compartmentalization με qubes που υποστηρίζονται από Xen. Ο σχεδιασμός του περιορίζει τη δυνατότητα μιας παραβίασης σε έναν domain να επηρεάσει αυτόματα άλλους, αλλά οι εφαρμογές μέσα στο **ίδιο** qube δεν είναι απομονωμένες μεταξύ τους.<sup>[[4]](#references)</sup> Τα Disposable qubes παρέχουν νέα κατάσταση για μη αξιόπιστους ιστότοπους, αρχεία και συσκευές.<sup>[[5]](#references)</sup>

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
- Δώστε σε κάθε qube ένα επίπεδο εμπιστοσύνης και έναν σκοπό ταυτότητας.
- Κρατήστε τα secrets σε ένα offline vault qube και χρησιμοποιείτε explicit inter-qube copy/file operations.
- Ανοίγετε μη ζητημένα αρχεία και links σε disposables.
- Δρομολογείτε μόνο τα qubes που προορίζονται γι’ αυτό μέσω Whonix ή ενός dedicated VPN qube.
- Επισημαίνετε τα παράθυρα με σαφήνεια και σταματάτε τα άσχετα qubes κατά τη διάρκεια ευαίσθητων εργασιών.
- Μην υποθέτετε ότι δύο qubes αποτρέπουν τη συσχέτιση, αν μοιράζονται accounts, περιεχόμενο, χρονοδιαγράμματα ή πληρωμές.

## Επαλήθευση και συντήρηση

- Επαληθεύετε τις υπογραφές/checksums του installer μέσω των επίσημων οδηγιών.
- Εφαρμόζετε patches πρώτα στα templates και έπειτα επανεκκινείτε τα dependent qubes/VMs.
- Επιβεβαιώνετε τη συμπεριφορά network-deny, τα DNS, το IPv6, το ρολόι, το clipboard, τους shared directories και την ανάθεση USB.
- Ελέγχετε το Persistent Storage και τα VM snapshots για παλιά δεδομένα που περιέχουν στοιχεία ταυτότητας.
- Διατηρείτε κρυπτογραφημένα offline backups των seeds/keys και δοκιμάζετε την αποκατάσταση σε isolated environment.
- Ανακατασκευάζετε ένα compartment μετά από υποψία compromise· η αλλαγή του egress IP δεν επαρκεί.

## References

- [1] [Tails — Προειδοποιήσεις: Το Tails είναι ασφαλές, αλλά όχι μαγικό](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Σύνδεση σε δίκτυο μέσω captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Περιορισμοί του Whonix και του Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Στόχοι σχεδιασμού ασφάλειας](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Πώς να χρησιμοποιείτε disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
