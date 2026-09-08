# Playbooks Επιχειρησιακής Ιδιωτικότητας

Αυτά τα playbooks συνδυάζουν τους ελέγχους από το υπόλοιπο αυτής της ενότητας. Αποτελούν αφετηρίες και όχι εγγυήσεις: ενημερώνετε το μοντέλο απειλών κάθε φορά που ένας νέος παρατηρητής, λογαριασμός, συσκευή, τοποθεσία, πληρωμή, αρχείο ή αντισυμβαλλόμενος εισέρχεται στη ροή εργασίας.

## Καθολικός προέλεγχος

1. Καταγράψτε τον νόμιμο στόχο και τι πρέπει να παραμείνει ιδιωτικό **από ποιον**.
2. Καταγράψτε τις ταυτότητες, συσκευές, δίκτυα, λογαριασμούς, μέσα πληρωμής, αντισυμβαλλομένους, φυσικές τοποθεσίες και δεδομένα με τα οποία θα αλληλεπιδράσει η δραστηριότητα.
3. Εντοπίστε τον ισχυρότερο πιθανό παρατηρητή και τη συνέπεια μιας αποτυχίας.
4. Επιβεβαιώστε την εξουσιοδότηση, την ισχύουσα νομοθεσία, τους όρους του παρόχου και την οργανωτική πολιτική.
5. Αποφασίστε τι πρέπει να παραμείνει εσωτερικά αποδιδόμενο για λόγους ασφάλειας, απόκρισης σε περιστατικά, λογιστικής και ελέγχου.
6. Επιλέξτε το μικρότερο λειτουργικό compartment· καθορίστε τις διαδρομές ανάκτησης και τερματισμού του πριν από τη χρήση.
7. Δοκιμάστε το compartment απέναντι σε μια ελεγχόμενη υπηρεσία, συμπεριλαμβανομένων των IP/DNS/IPv6, της ταυτότητας του browser, των metadata εγγράφων, της κατάστασης πληρωμής και της διαρροής ειδοποιήσεων.

Χρησιμοποιήστε το λεπτομερές μοντέλο στο [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Βασικό επίπεδο καθημερινής ιδιωτικότητας

Στόχος: μείωση της εμπορικής παρακολούθησης, της κατάληψης λογαριασμών και της περιττής έκθεσης, χωρίς προσπάθεια επίτευξης ανωνυμίας.

- Χρησιμοποιείτε ένα συντηρούμενο OS με πλήρη κρυπτογράφηση δίσκου, αυτόματες ενημερώσεις, κλείδωμα οθόνης και secure boot όπου είναι διαθέσιμο.
- Ρυθμίστε πρώτα τον password manager, το email ανάκτησης και το phishing-resistant MFA/security keys.
- Ελέγχετε τα δικαιώματα εφαρμογών, το ιστορικό τοποθεσίας, τα advertising identifiers, το cloud sync και τις συνδέσεις λογαριασμών τρίτων.
- Χρησιμοποιείτε έναν mainstream browser με λίγα extensions, προστασία από tracking, HTTPS και ξεχωριστά profiles για περιήγηση εργασίας/προσωπική/υψηλού κινδύνου.
- Χρησιμοποιείτε private relay aliases ή ξεχωριστές διευθύνσεις email ανά σχέση· μην χρησιμοποιείτε προσωπικό αριθμό τηλεφώνου όταν είναι απλώς προαιρετικός.
- Προτιμάτε end-to-end encrypted messaging για το περιεχόμενο, θυμώμενοι ότι οι συμμετέχοντες, ο χρόνος, οι ομάδες και τα endpoints παραμένουν metadata.
- Αφαιρείτε σκόπιμα τα metadata από τα αρχεία και ελέγχετε το exported αντίγραφο —όχι το πρωτότυπο— πριν από τη δημοσίευση.
- Χρησιμοποιείτε virtual-card ή wallet tokens για compartmentalization των credentials πληρωμής· μην τα αποκαλείτε anonymous.
- Δημιουργείτε αντίγραφα ασφαλείας του κρυπτογραφημένου υλικού ανάκτησης και δοκιμάζετε την επαναφορά.

## Ψευδωνυμική δημοσίευση

Στόχος: να αποτρέψετε τους περιστασιακούς αναγνώστες και τις πλατφόρμες από το να συνδέσουν εύκολα μια δημοσίευση με μια αστική ταυτότητα. Αυτό δεν αντιμετωπίζει μια ικανή στοχευμένη έρευνα.

1. Καθορίστε αν το platform, ο hosting provider, οι αναγνώστες, οι επαφές, το τοπικό δίκτυο, ο πάροχος πληρωμών ή η νομική διαδικασία ανήκουν στο μοντέλο απειλών.
2. Δημιουργήστε ένα dedicated endpoint/account context από ένα clean baseline. Απενεργοποιήστε το προσωπικό browser sync, τα cloud documents, το contact upload και τις προεπισκοπήσεις ειδοποιήσεων.
3. Δημιουργήστε τον ψευδωνυμικό λογαριασμό μέσω του επιλεγμένου network compartment. Μην επαναχρησιμοποιείτε usernames, avatars, recovery channels, writing boilerplate ή σύνδεση προσωπικού identity-provider.
4. Χρησιμοποιήστε Tor Browser όταν η unlinkability του προορισμού είναι σημαντικότερη από την ταχύτητα· μην προσθέτετε extensions, μην αλλάζετε υπερβολικά το μέγεθος/την παραμετροποίησή του και μην ανοίγετε downloaded documents ενώ είστε online σε μια συνηθισμένη desktop session.
5. Συντάσσετε με μια διαδικασία που δεν ενσωματώνει προσωπικά ονόματα templates, authors αναθεωρήσεων, printer paths, GPS/EXIF, thumbnails ή hidden layers. Κάντε export ένα αντίγραφο και ελέγξτε το με κατάλληλα metadata tools.
6. Ελέγξτε το περιεχόμενο για self-identifying facts: μοναδικές ημερομηνίες, λεπτομέρειες χώρου εργασίας, τοπικό καιρό/ζώνη ώρας, reflections, ήχο παρασκηνίου, γλωσσικές συνήθειες και επαναχρησιμοποίηση κειμένου από προηγούμενες δημοσιεύσεις.
7. Χρησιμοποιήστε ξεχωριστό reply channel. Θεωρήστε κάθε direct contact, attachment και link πιθανή προσπάθεια συσχέτισης ή phishing.
8. Αν εμπλέκονται χρήματα, χρησιμοποιήστε τη νόμιμη μέθοδο που εκθέτει μόνο τα απαραίτητα δεδομένα. Θεωρήστε ότι η πλατφόρμα και ο regulated intermediary μπορεί να γνωρίζουν τον payee, ακόμη και αν δεν τον γνωρίζουν οι αναγνώστες.
9. Δημοσιεύστε και, στη συνέχεια, ελέγξτε το δημόσιο αποτέλεσμα από διαφορετικό clean context. Καταγράψτε τι πρόσθεσε ή μετέτρεψε η πλατφόρμα.
10. Διατηρείτε προγραμματισμένη cadence μόνο αν δεν δημιουργεί σταθερό behavioral fingerprint· αποσύρετε το compartment αντί να το επαναχρησιμοποιήσετε σιωπηρά.

Για σοβαρή δημοσιογραφία, activism, domestic abuse ή κίνδυνο επιπέδου κράτους, ζητήστε εξατομικευμένη βοήθεια από έναν έμπειρο οργανισμό digital security· μια στατική checklist δεν μπορεί να μοντελοποιήσει την τοπική νομοθεσία ή έναν ενεργό αντίπαλο.

## Authorized red-team engagement

Στόχος: να διατηρούνται οι προσωπικές ταυτότητες των operators και τα οικιακά δίκτυά τους εκτός των telemetry των targets, διατηρώντας παράλληλα την εξουσιοδότηση, τον έλεγχο και την απόκριση σε περιστατικά.

### Πριν από το start window

- Ολοκληρώστε το infrastructure annex του ROE, τα targets/exclusions, τα source ranges, τις ημερομηνίες, το emergency stop και τις άδειες τρίτων/παρόχων.
- Διαθέστε dedicated operator profile ή VM, engagement secrets, evidence store, cloud project, domains και budget.
- Προτιμήστε client-provided egress ή ένα organization-controlled fixed bastion. Δοκιμάστε τη συμπεριφορά full-tunnel IPv4/IPv6/DNS και την πολιτική fail-closed.
- Αποθηκεύστε την αντιστοίχιση operator προς public infrastructure με τον exercise controller ή τον συμφωνημένο escrow contact.
- Καθορίστε rate limits, destination allowlists και ξεχωριστή έγκριση για destructive, wireless, physical, phishing ή credential-collection actions.
- Χρησιμοποιήστε organization-controlled payment rail και καταγράψτε εσωτερικά τις εγκρίσεις.

### Κατά τη διάρκεια του engagement

- Ξεκινήστε από το εγκεκριμένο endpoint και tunnel· επαληθεύστε το observed egress πριν από assessment traffic.
- Κρατήστε προσωπικούς λογαριασμούς, συσκευές, αριθμούς τηλεφώνου, repositories, SSH/GPG keys και cloud sync εκτός του compartment.
- Καταγράψτε operator/job, start/stop, source, scoped destination και configuration change χωρίς συλλογή περιττού client content.
- Σταματήστε σε περίπτωση ασάφειας του scope, μη αναμενόμενων third-party systems, ειδοποίησης provider abuse, επίπτωσης στην ασφάλεια, απώλειας εξοπλισμού ή απώλειας επικοινωνίας με τον controller.
- Ποτέ μην αυτοσχεδιάζετε χρησιμοποιώντας το Wi-Fi ενός γείτονα, κλεμμένα credentials, μη εγκεκριμένο SIM/account ή hardware κρυμμένο σε χώρο εκδήλωσης.

### Μετά το τέλος του engagement

- Σταματήστε τα jobs και το C2· ανακτήστε τις εγκεκριμένες drop devices· ανακαλέστε tokens, credentials και certificates.
- Συμφωνήστε infrastructure, domains, source addresses, expenses, data και provider cases με το inventory.
- Επιστρέψτε/διαγράψτε/διατηρήστε τα client data σύμφωνα με το contract, διατηρήστε τα ελάχιστα απαιτούμενα audit evidence και ζητήστε από δεύτερο operator να επαληθεύσει τον τερματισμό.

Δείτε το [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) για τον πλήρη οδηγό build και teardown.

## Νόμιμη ιδιωτική αγορά ή δωρεά

Στόχος: ελαχιστοποίηση της αποκάλυψης προς τον merchant ή το κοινό, με παράλληλη τήρηση των υποχρεώσεων προς τον issuer, τη λογιστική, τη φορολογία και τις κυρώσεις.

1. Καταγράψτε ποιος δεν πρέπει να μάθει τι: το κοινό, ο merchant, ο payment intermediary, ο employer/family account delegate, η υπηρεσία παράδοσης ή ένας blockchain observer.
2. Ελέγξτε τους τοπικούς κανόνες, τον recipient/counterparty, τους όρους του παρόχου, τα cash limits και τις ανάγκες τήρησης αρχείων.
3. Επιλέξτε το rail:
- μετρητά για αποδεκτές νόμιμες τοπικές πληρωμές χωρίς record του payment network·
- regulated virtual/merchant-specific card για online credential separation·
- cryptocurrency μόνο αφού αναλύσετε τα acquisition, ledger, wallet backend, network, counterparty και later-spend links.
4. Χρησιμοποιήστε αληθή απαιτούμενα στοιχεία και παραλείψτε μόνο προαιρετικές πληροφορίες loyalty/marketing. Μην χρησιμοποιείτε την ταυτότητα/διεύθυνση άλλου προσώπου και μην διαχωρίζετε μια συναλλαγή γύρω από ένα threshold.
5. Διαχωρίστε το merchant browser/account context και αποφύγετε άσχετο social login, loyalty ή προσωπικά recovery channels.
6. Επιβεβαιώστε τι εμφανίζεται σε statements, receipts, notifications, shipping και public donor lists.
7. Αποθηκεύστε τα απαιτούμενα receipt/tax/authorization evidence κρυπτογραφημένα· ανακαλέστε τα disposable payment credentials μετά το refund window.

Δείτε τα [Private Digital Payments](private-digital-payments.md) και [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Ταξίδια και μη έμπιστα δίκτυα

Στόχος: προστασία δεδομένων και λογαριασμών σε δίκτυα που δεν διαχειρίζεται ο χρήστης —όχι απόκρυψη μη εξουσιοδοτημένης δραστηριότητας.

- Ενημερώστε τις συσκευές και κατεβάστε τα απαραίτητα credentials/maps πριν από το ταξίδι.
- Ελαχιστοποιήστε τα αποθηκευμένα δεδομένα· χρησιμοποιήστε full-disk encryption, ισχυρό unlock, σχεδιασμό remote recovery και διαδικασίες powered-off border/physical-risk κατάλληλες για τη νομική συμβουλή.
- Επαληθεύστε το venue SSID/captive portal. Προτιμήστε personal hotspot όπου είναι κατάλληλο, αλλά θυμηθείτε τα cellular subscriber και location records.
- Χρησιμοποιήστε full/forced approved VPN για organizational data· επαληθεύστε ότι οι tethered devices το μοιράζονται και δοκιμάστε τη συμπεριφορά IPv6/DNS.
- Χρησιμοποιήστε travel router για client isolation και επαναλήψιμη πολιτική, όχι ως εγγύηση ανωνυμίας.
- Αντιμετωπίστε το public USB charging, τους borrowed computers, τους public printers και τα shared meeting-room systems ως ξεχωριστές απειλές.
- Θεωρήστε ότι η φυσική παρουσία, τα radio identifiers, το portal login, οι κάμερες και τα payment/location records μπορούν να συσχετίσουν την επίσκεψη.

Οι λεπτομέρειες σύγκρισης και ρύθμισης βρίσκονται στο [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Απόκριση σε αποτυχία και έκθεση

Όταν ένα compartment διαρρεύσει ή ενδέχεται να συνδεθεί:

1. Σταματήστε τη δραστηριότητα αν η συνέχιση αυξάνει τη ζημιά· χρησιμοποιήστε το engagement emergency stop όπου εφαρμόζεται.
2. Διατηρήστε τα απαραίτητα evidence χωρίς να διαδώσετε ευαίσθητα δεδομένα. Καταγράψτε την ακριβή ώρα, την observed indicator και τα affected assets.
3. Ειδοποιήστε τον κατάλληλο owner/controller/security contact. Μην αποκρύψετε ένα περιστατικό για να διατηρήσετε μια αφήγηση ιδιωτικότητας.
4. Ανακαλέστε sessions, tokens, payment credentials και infrastructure access· κάντε rotation των secrets από known-clean endpoint.
5. Καθορίστε ποια edges συνέδεσαν τα στοιχεία: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty ή physical presence.
6. Θεωρήστε ολόκληρο το affected compartment burned. Μην αλλάξετε απλώς το username ή το exit IP.
7. Εκπληρώστε τις υποχρεώσεις notification για breach, provider, client, financial και legal θέματα.
8. Κάντε rebuild μόνο αφού αλλάξετε τη διαδικασία που προκάλεσε τη σύνδεση· τεκμηριώστε το control και δοκιμάστε το.

## Περιοδικός έλεγχος

- [ ] Το μοντέλο απειλών και οι νομικές/παροχικές παραδοχές ελέγχθηκαν σύμφωνα με χρονολογημένο πρόγραμμα.
- [ ] Έγινε inventory των συσκευών, λογαριασμών, aliases, domains, network paths και payment credentials.
- [ ] Οι διαδρομές ανάκτησης δεν διασχίζουν απροσδόκητα compartments.
- [ ] Η συμπεριφορά full-tunnel, DNS, IPv6 και fail-closed δοκιμάστηκε.
- [ ] Τα δημόσια αρχεία και profiles ελέγχθηκαν για metadata/content reuse.
- [ ] Τα wallet nodes/backends και οι παραδοχές των crypto protocols παραμένουν ενημερωμένα.
- [ ] Τα logs και τα receipts είναι ελάχιστα, κρυπτογραφημένα, ελεγχόμενης πρόσβασης και εντός περιόδου διατήρησης.
- [ ] Τα παλιά compartments και η engagement infrastructure αποσύρθηκαν πλήρως.
