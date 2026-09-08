# Threat Modeling & Identity Separation

{{#include ../banners/hacktricks-training.md}}

Η πιο συνηθισμένη αποτυχία ανωνυμίας δεν είναι η προβληματική κρυπτογραφία. Είναι η **συσχέτιση**: ένα αναγνωριστικό, ένα μοτίβο χρονισμού, μια συσκευή, ένας λογαριασμός, μια πληρωμή, ένα αρχείο ή μια ανθρώπινη συνήθεια συνδέει δύο περιβάλλοντα που υποτίθεται ότι θα παρέμεναν ξεχωριστά.

## Δημιουργήστε ένα privacy threat model

Το πλάνο ασφαλείας έξι ερωτήσεων του EFF αποτελεί ισχυρή βάση: τι πρέπει να προστατευτεί, από ποιον, ο αντίκτυπος και η πιθανότητα αποτυχίας, η διαθέσιμη προσπάθεια και οι σύμμαχοι που μπορούν να βοηθήσουν.<sup>[[1]](#references)</sup> Κάντε το λειτουργικό με έναν μικρό πίνακα:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Έρευνα για έναν πελάτη | ISP | Μεταδεδομένα προορισμού/χρονισμού | Αρχείο οικιακού συνδρομητή | Tor Browser | Η χρήση του Tor είναι ορατή· end-to-end συσχέτιση |
| Ψευδώνυμος λογαριασμός | Platform | IP, browser, δεδομένα ανάκτησης | Επαναχρησιμοποιημένο τηλέφωνο/email/φωτογραφία | Αφιερωμένο context και alias | Συσχέτιση μέσω γραφής/κοινωνικού γραφήματος |
| Online αγορά | Merchant | Λογαριασμός, παράδοση, tokenized card | Διεύθυνση και ιστορικό λογαριασμού | Guest checkout, ελάχιστα πεδία, virtual card | Ο εκδότης και ο μεταφορέας διατηρούν αρχεία |
| Red-team traffic | Target/client | IP προέλευσης και συμπεριφορά | Αρχεία provider/engagement | Αφιερωμένο εξουσιοδοτημένο egress | Σκόπιμα αποδοτέο σε περίπτωση escalation |

Επανεξετάζετε τον πίνακα κάθε φορά που αλλάζει η τοποθεσία, ο provider, η συσκευή, ο counterpart ή οι συνέπειες.

## Σχεδιάστε το linkability graph

Αντιμετωπίστε κάθε ταυτότητα ως ξεχωριστό node. Προσθέστε ένα edge για κάθε κοινό χαρακτηριστικό:

- email ή διεύθυνση ανάκτησης·
- αριθμός τηλεφώνου ή upload βιβλίου επαφών·
- username, avatar, φωτογραφία, bio ή στυλ γραφής/code·
- password, passkey-sync account ή ερώτηση ανάκτησης·
- συσκευή, advertising ID, browser profile, cookies, γραμματοσειρές ή extensions·
- IP address, ζώνη ώρας, γλώσσα, πρόγραμμα ή ταυτόχρονη online παρουσία·
- bank card, exchange account, wallet cluster, διεύθυνση αποστολής ή loyalty program·
- πεδία author εγγράφων, τοποθεσία EXIF, σημάδια εκτυπωτή ή owner cloud-share·
- συνάδελφος, συμμετοχή σε group και social graph.

Ένα edge δεν είναι αυτόματα καταστροφικό, αλλά σας δείχνει ποιος observer μπορεί να κάνει τη σύνδεση. Το EFF προειδοποιεί συγκεκριμένα ότι οι αριθμοί τηλεφώνου, οι διευθύνσεις email και οι επαναχρησιμοποιημένες φωτογραφίες μπορούν να συνδέσουν profiles.<sup>[[2]](#references)</sup>

## Δημιουργήστε ένα compartment βήμα προς βήμα

1. **Ονομάστε το context και τις απαγορευμένες συνδέσεις.** Παράδειγμα: `client-red-2026`, με απαγόρευση σύνδεσης με προσωπικό email, home browser profiles, προσωπικές μεθόδους πληρωμής και άσχετους clients.
2. **Επιλέξτε το όριο απομόνωσης.** Με αυξανόμενη ισχύ: ξεχωριστό browser profile → ξεχωριστός OS account → ξεχωριστό VM/qube → αφιερωμένη συσκευή. Ένα ξεχωριστό tab ή private window δεν αποτελεί security boundary.
3. **Δημιουργήστε fresh identifiers μέσα σε αυτό το boundary.** Χρησιμοποιήστε context-specific email/alias, username, password-manager vault ή collection και authentication keys. Μην προσθέσετε προσωπικό recovery channel αν η unlinkability από τον provider είναι σημαντική.
4. **Επιλέξτε μία network policy.** Αποφασίστε αν το context θα χρησιμοποιεί πάντα client VPN, engagement VPS, trusted VPN ή Tor. Επιβάλετε fail-closed routing όπου είναι δυνατό.
5. **Επιλέξτε μία payment policy.** Η μέθοδος πληρωμής πρέπει να αντιστοιχεί στο observer model· μια virtual card μπορεί να αποκρύψει το PAN από έναν merchant, αλλά εξακολουθεί να ταυτοποιεί τον πελάτη στον issuer.
6. **Ορίστε κανόνες μεταφοράς δεδομένων.** Προτιμήστε στενά εστιασμένες και σκόπιμες μεταφορές. Αντιμετωπίστε το clipboard, τους shared folders, τις USB devices, το cloud sync, τους printers και τα screenshots ως πιθανά bridges.
7. **Καταγράψτε τις ημερομηνίες δημιουργίας και teardown.** Καθορίστε ποια στοιχεία πρέπει να διατηρηθούν για contracts/tax/compliance και ποια transient δεδομένα πρέπει να λήξουν.
8. **Ελέγξτε για συνδέσεις πριν από τη χρήση.** Επιθεωρήστε τις ρυθμίσεις λογαριασμού, τα recovery fields, το public profile, τα IP/DNS, την κατάσταση του browser, τα metadata αρχείων και τα provider dashboards.

{% hint style="warning" %}
Μην επινοείτε στοιχεία ταυτότητας όπου μια υπηρεσία ή ο νόμος απαιτεί ακριβή ταυτοποίηση. Ένα privacy compartment αφορά την ελαχιστοποίηση και τον διαχωρισμό δεδομένων, όχι identity fraud ή την παράκαμψη του customer due diligence.
{% endhint %}

## Endpoint και account baseline

- Χρησιμοποιείτε υποστηριζόμενο hardware και εγκαθιστάτε άμεσα OS, browser, wallet και firmware updates.
- Ενεργοποιήστε device encryption και χρησιμοποιήστε ισχυρό device passcode. Η encryption at rest βοηθά όταν μια απενεργοποιημένη συσκευή χαθεί ή κατασχεθεί, αλλά όχι όταν malware ή μια ξεκλείδωτη session μπορεί να διαβάσει δεδομένα.<sup>[[3]](#references)</sup>
- Χρησιμοποιείτε μοναδικά, τυχαία παραγόμενα passwords σε password manager.
- Προτιμήστε phishing-resistant authentication, όπως WebAuthn/passkeys ή hardware security keys, όπου το threat model επιτρέπει το recovery/sync model τους. Το NIST σημειώνει ότι τα OTPs που εισάγονται χειροκίνητα δεν είναι phishing-resistant, επειδή ένας impostor μπορεί να τα προωθήσει.<sup>[[4]](#references)</sup>
- Διατηρείτε τα recovery codes offline και ξεχωριστά από το endpoint. Ελέγξτε αν ένας synced passkey account συνδέει ταυτότητες που πρέπει να παραμείνουν ξεχωριστές.
- Απενεργοποιήστε τις μη απαραίτητες permissions για location, contacts, microphone, camera, Bluetooth, advertising-ID και background λειτουργίες.
- Μην ενσωματώνετε personal cloud sync, browser sync, password-manager accounts ή app stores σε context υψηλού διαχωρισμού.

## Browser privacy

Το browser fingerprinting χρησιμοποιεί παρατηρήσιμες ρυθμίσεις, συσκευή, περιβάλλον και συμπεριφορά για να ταυτοποιήσει ή να συσχετίσει έναν χρήστη. Η διαγραφή cookies ή η αλλαγή IP addresses δεν το εξουδετερώνει αξιόπιστα, και το W3C θεωρεί απίθανη την πλήρη τεχνική εξάλειψή του με ευρέως αναπτυγμένα μέσα.<sup>[[5]](#references)</sup>

Για συνηθισμένο privacy:

1. Χρησιμοποιήστε maintained browser με HTTPS-only mode και ισχυρό tracking protection.
2. Αποκλείστε third-party tracking και κάντε partition το state όπου υποστηρίζεται.
3. Χρησιμοποιήστε ξεχωριστά browser profiles για πραγματικά ξεχωριστά contexts.
4. Απενεργοποιήστε τις μη απαραίτητες permissions και διαγράφετε τα site data βάσει καθορισμένου προγράμματος.
5. Αποφύγετε τη σύνδεση σε identity-rich accounts ενώ κάνετε άσχετη ευαίσθητη έρευνα.

Για web anonymity, χρησιμοποιήστε **Tor Browser στην standard configuration**. Μην κάνετε proxy έναν normal browser μέσω Tor: το Tor Project προειδοποιεί ότι οι ordinary browsers μπορεί να κάνουν leak μέσω DNS/WebRTC, persistent state, fonts, plugins και διαφορών στο fingerprint.<sup>[[6]](#references)</sup> Αποφύγετε επιπλέον extensions, ασυνήθιστα μεγέθη παραθύρων, custom fonts και preferences που κάνουν τον browser να ξεχωρίζει.<sup>[[7]](#references)</sup>

## Communications και metadata

Τα metadata περιλαμβάνουν sender, recipient, χρόνο, τοποθεσία και άλλο context, ακόμη και όταν το περιεχόμενο του μηνύματος είναι encrypted.<sup>[[8]](#references)</sup>

- Προτιμήστε end-to-end-encrypted tools με ελαχιστοποιημένα server-side metadata και open protocols/clients όπου είναι πρακτικό.
- Επαληθεύστε τις ευαίσθητες επαφές χρησιμοποιώντας ανεξάρτητο channel ή αυτοπροσώπως. Τα Signal safety numbers έχουν σχεδιαστεί για αυτόν τον έλεγχο.<sup>[[9]](#references)</sup>
- Τα Signal usernames μπορούν να ξεκινήσουν επικοινωνία χωρίς κοινοποίηση αριθμού τηλεφώνου, αλλά για την εγγραφή εξακολουθεί να απαιτείται αριθμός τηλεφώνου· ρυθμίστε σκόπιμα την ορατότητα/δυνατότητα εντοπισμού του αριθμού τηλεφώνου.<sup>[[9]](#references)</sup>
- Τα disappearing messages μειώνουν τα διατηρούμενα αντίγραφα· οι recipients μπορούν ακόμη να φωτογραφίσουν, να αντιγράψουν, να προωθήσουν ή να αρχειοθετήσουν το περιεχόμενο.
- Το email συνήθως εκθέτει routing metadata. Ακόμη και privacy-focused providers δεν μπορούν να κάνουν ένα μήνυμα end-to-end encrypted όταν η άλλη πλευρά χρησιμοποιεί ordinary email, εκτός αν και τα δύο μέρη χρησιμοποιούν συμβατή μέθοδο E2EE. Η Proton, για παράδειγμα, τεκμηριώνει ότι τα ordinary mail προς άλλους providers χρησιμοποιούν TLS και παραμένουν αναγνώσιμα από τον receiving provider.<sup>[[10]](#references)</sup>
- Διατηρείτε ξεχωριστά address books και μην ανεβάζετε προσωπικές επαφές σε pseudonymous account.

## Αρχεία, φωτογραφίες και authorship

Το Tails προειδοποιεί ότι οι φωτογραφίες μπορεί να περιέχουν δεδομένα κάμερας και τοποθεσίας, ενώ τα office documents μπορεί να περιέχουν πεδία author και χρόνου δημιουργίας.<sup>[[11]](#references)</sup>

Πριν από την κοινοποίηση:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Στη συνέχεια ανοίξτε ξανά το καθαρισμένο αντίγραφο σε isolated viewer και ελέγξτε:

- τις ιδιότητες του εγγράφου, τα σχόλια, τις tracked changes, τα κρυφά φύλλα/διαφάνειες, τις μικρογραφίες και τα συνημμένα·
- τα EXIF/XMP/IPTC, το GPS, τις χρονικές σημάνσεις, τα ονόματα συσκευών/λογισμικού και τα μοναδικά IDs·
- ορατές αντανακλάσεις, τοπόσημα, περιεχόμενο οθονών, φωνές, πρόσωπα και ήχους παρασκηνίου·
- το όνομα αρχείου, τις διαδρομές αρχείων σε archives, τον owner του cloud-share, το signing certificate και το revision history.

Ο καθαρισμός μπορεί να καταστρέψει αποδεικτικά στοιχεία ή την αυθεντικότητα. Διατηρήστε ένα κρυπτογραφημένο πρωτότυπο όταν έχει σημασία η chain of custody ή η μεταγενέστερη επαλήθευση. Η stylometry και το coding style μπορούν επίσης να συνδέσουν την πατρότητα· η αφαίρεση metadata δεν αλλάζει το ανθρώπινο στυλ.

## Common failure patterns

- Σύνδεση σε προσωπικό account μέσω μιας «anonymous» σύνδεσης.
- Επαναχρησιμοποίηση recovery phone, avatar, username, public key, wallet ή donation address.
- Ταυτόχρονη λειτουργία δύο identities από συσχετιζόμενα contexts.
- Αντιγραφή κειμένου/αρχείων μέσω προσωπικού cloud clipboard ή shared folder.
- Εγκατάσταση distinctive Tor Browser extensions ή αλλαγή πολλών defaults.
- Εμπιστοσύνη σε έναν ισχυρισμό «no logs» χωρίς κατανόηση του τι καταγράφεται, για πόσο καιρό και από ποιους subcontractors.
- Υπόθεση ότι ένα secondary phone είναι anonymous ενώ μετακινείται μαζί με ένα personal phone. Η EFF σημειώνει ότι η cellular location και η κοινή μετακίνηση μπορούν να συσχετίσουν τις συσκευές.<sup>[[3]](#references)</sup>
- Αντιμετώπιση της κρυπτογράφησης ως διαγραφής· τα endpoints και οι παραλήπτες μπορεί να διατηρούν plaintext.

## Verification checklist

- [ ] Το context δεν περιέχει personal recovery address, phone, sync account ή reused media, εκτός αν αυτό έχει γίνει σκόπιμα αποδεκτό.
- [ ] Η προβλεπόμενη network path είναι ενεργή και fails closed.
- [ ] Η time zone, το locale, τα extensions και τα permissions του browser/device συμφωνούν με το plan.
- [ ] Δεν υπάρχουν ανοιχτά personal accounts στο compartment.
- [ ] Τα αρχεία έχουν ελεγχθεί και υποστεί sanitization· τα originals διαχειρίζονται ξεχωριστά.
- [ ] Οι contacts έχουν authenticated μέσω δεύτερου channel.
- [ ] Τα metadata που είναι ορατά στον provider και η περίοδος retention είναι κατανοητά.
- [ ] Οι διαδικασίες teardown, διατήρησης evidence και account recovery είναι τεκμηριωμένες.

## References

- [1] [EFF Surveillance Self-Defense — Το πλάνο ασφάλειάς σας](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Προστασία στα social networks](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Συμμετοχή σε διαμαρτυρία](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication και διαχείριση authenticators](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Μετριασμός του browser fingerprinting σε Web Specifications](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Χρήση του Tor με άλλους browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins και add-ons στο Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Γιατί έχουν σημασία τα communication metadata](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Απόρρητο αριθμού τηλεφώνου και usernames: βαθύτερη ανάλυση](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Τι είναι encrypted μέσα στο Proton Mail;](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Προειδοποιήσεις: Το Tails είναι ασφαλές, αλλά όχι μαγικό](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
