# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

Το **Gatekeeper** είναι μια δυνατότητα ασφαλείας που αναπτύχθηκε για τα λειτουργικά συστήματα Mac και έχει σχεδιαστεί ώστε να διασφαλίζει ότι οι χρήστες **εκτελούν μόνο αξιόπιστο λογισμικό** στα συστήματά τους. Λειτουργεί **επικυρώνοντας το λογισμικό** που ένας χρήστης κατεβάζει και προσπαθεί να ανοίξει από **πηγές εκτός του App Store**, όπως μια εφαρμογή, ένα plug-in ή ένα πακέτο εγκατάστασης.

Ο βασικός μηχανισμός του Gatekeeper βασίζεται στη διαδικασία **επαλήθευσης**. Ελέγχει αν το λογισμικό είναι **υπογεγραμμένο από αναγνωρισμένο developer**, επιβεβαιώνοντας την αυθεντικότητα του λογισμικού. Επιπλέον, ελέγχει αν το λογισμικό είναι **notarised από την Apple**, επιβεβαιώνοντας ότι δεν περιέχει γνωστό κακόβουλο περιεχόμενο και ότι δεν έχει τροποποιηθεί μετά το notarisation.

Επιπρόσθετα, το Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια των χρηστών, **ζητώντας από τους χρήστες να εγκρίνουν το άνοιγμα** του downloaded λογισμικού την πρώτη φορά. Αυτή η δικλείδα ασφαλείας βοηθά στην αποτροπή της ακούσιας εκτέλεσης δυνητικά επιβλαβούς executable code, την οποία οι χρήστες μπορεί να έχουν θεωρήσει λανθασμένα ως ακίνδυνο data file.

### Application Signatures

Οι application signatures, γνωστές και ως code signatures, αποτελούν κρίσιμο στοιχείο της υποδομής ασφαλείας της Apple. Χρησιμοποιούνται για την **επαλήθευση της ταυτότητας του author του λογισμικού** (του developer) και για να διασφαλιστεί ότι ο κώδικας δεν έχει τροποποιηθεί από την τελευταία φορά που υπογράφηκε.

Δείτε πώς λειτουργεί:

1. **Signing the Application:** Όταν ένας developer είναι έτοιμος να διανείμει την εφαρμογή του, **υπογράφει την εφαρμογή χρησιμοποιώντας ένα private key**. Αυτό το private key σχετίζεται με ένα **certificate που εκδίδει η Apple στον developer** όταν εγγράφεται στο Apple Developer Program. Η διαδικασία υπογραφής περιλαμβάνει τη δημιουργία ενός cryptographic hash για όλα τα τμήματα της εφαρμογής και την κρυπτογράφηση αυτού του hash με το private key του developer.
2. **Distributing the Application:** Η signed εφαρμογή διανέμεται στη συνέχεια στους χρήστες μαζί με το certificate του developer, το οποίο περιέχει το αντίστοιχο public key.
3. **Verifying the Application:** Όταν ένας χρήστης κατεβάζει και προσπαθεί να εκτελέσει την εφαρμογή, το λειτουργικό σύστημα του Mac χρησιμοποιεί το public key από το certificate του developer για να αποκρυπτογραφήσει το hash. Στη συνέχεια υπολογίζει ξανά το hash με βάση την τρέχουσα κατάσταση της εφαρμογής και το συγκρίνει με το decrypted hash. Αν ταιριάζουν, αυτό σημαίνει ότι **η εφαρμογή δεν έχει τροποποιηθεί** από τότε που την υπέγραψε ο developer και το σύστημα επιτρέπει την εκτέλεσή της.

Οι application signatures αποτελούν ουσιώδες μέρος της τεχνολογίας Gatekeeper της Apple. Όταν ένας χρήστης προσπαθεί να **ανοίξει μια εφαρμογή που έχει κατεβάσει από το διαδίκτυο**, το Gatekeeper επαληθεύει την application signature. Αν έχει υπογραφεί με certificate που έχει εκδοθεί από την Apple σε γνωστό developer και ο κώδικας δεν έχει τροποποιηθεί, το Gatekeeper επιτρέπει την εκτέλεση της εφαρμογής. Διαφορετικά, αποκλείει την εφαρμογή και ειδοποιεί τον χρήστη.

Από το macOS Catalina και έπειτα, το **Gatekeeper ελέγχει επίσης αν η εφαρμογή έχει notarized** από την Apple, προσθέτοντας ένα επιπλέον επίπεδο ασφάλειας. Η διαδικασία notarization ελέγχει την εφαρμογή για γνωστά security issues και malicious code και, αν αυτοί οι έλεγχοι ολοκληρωθούν επιτυχώς, η Apple προσθέτει ένα ticket στην εφαρμογή, το οποίο μπορεί να επαληθεύσει το Gatekeeper.

#### Check Signatures

Όταν ελέγχετε κάποιο **malware sample**, θα πρέπει πάντα να **ελέγχετε τη signature** του binary, καθώς ο **developer** που το υπέγραψε μπορεί να **σχετίζεται** ήδη με **malware.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

Η διαδικασία notarization της Apple λειτουργεί ως ένα επιπλέον μέτρο προστασίας για την προστασία των χρηστών από δυνητικά επιβλαβές λογισμικό. Περιλαμβάνει την **υποβολή της εφαρμογής από τον developer για εξέταση** από την **Apple's Notary Service**, η οποία δεν πρέπει να συγχέεται με το App Review. Αυτή η υπηρεσία είναι ένα **automated system** που εξετάζει το υποβληθέν λογισμικό για την ύπαρξη **malicious content** και τυχόν προβλημάτων με το code-signing.

Εάν το λογισμικό **περάσει** αυτόν τον έλεγχο χωρίς να εντοπιστούν προβλήματα, η Notary Service δημιουργεί ένα notarization ticket. Στη συνέχεια, ο developer πρέπει να **επισυνάψει αυτό το ticket στο λογισμικό**, μια διαδικασία γνωστή ως 'stapling'. Επιπλέον, το notarization ticket δημοσιεύεται online, όπου μπορεί να αποκτήσει πρόσβαση το Gatekeeper, η τεχνολογία ασφάλειας της Apple.

Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του notarization ticket - είτε είναι stapled στο executable είτε βρεθεί online - **ενημερώνει το Gatekeeper ότι το λογισμικό έχει υποβληθεί σε notarization από την Apple**. Ως αποτέλεσμα, το Gatekeeper εμφανίζει ένα περιγραφικό μήνυμα στο αρχικό launch dialog, indicando ότι το λογισμικό έχει ελεγχθεί από την Apple για malicious content. Με αυτόν τον τρόπο ενισχύεται η εμπιστοσύνη των χρηστών στην ασφάλεια του λογισμικού που εγκαθιστούν ή εκτελούν στα συστήματά τους.

### spctl & syspolicyd

> [!CAUTION]
> Σημειώστε ότι από την έκδοση Sequoia και έπειτα, το **`spctl`** δεν επιτρέπει πλέον την τροποποίηση της διαμόρφωσης του Gatekeeper.

Το **`spctl`** είναι το CLI tool για την απαρίθμηση και την αλληλεπίδραση με το Gatekeeper (μέσω του daemon `syspolicyd` και μηνυμάτων XPC). Για παράδειγμα, είναι δυνατό να δείτε το **status** του GateKeeper με:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Σημειώστε ότι οι έλεγχοι υπογραφής του GateKeeper εκτελούνται μόνο σε **αρχεία με το χαρακτηριστικό Quarantine**, όχι σε κάθε αρχείο.

Το GateKeeper ελέγχει αν, σύμφωνα με τις **προτιμήσεις & την υπογραφή**, μπορεί να εκτελεστεί ένα binary:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

Το **`syspolicyd`** είναι ο κύριος daemon που είναι υπεύθυνος για την επιβολή του Gatekeeper. Διατηρεί μια βάση δεδομένων στη διεύθυνση `/var/db/SystemPolicy` και μπορείτε να βρείτε τον κώδικα που υποστηρίζει τη [βάση δεδομένων εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) και το [SQL template εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Σημειώστε ότι η βάση δεδομένων δεν περιορίζεται από το SIP και είναι εγγράψιμη από τον root, ενώ η βάση δεδομένων `/var/db/.SystemPolicy-default` χρησιμοποιείται ως αρχικό αντίγραφο ασφαλείας σε περίπτωση που η άλλη καταστραφεί.

Επιπλέον, τα bundles **`/var/db/gke.bundle`** και **`/var/db/gkopaque.bundle`** περιέχουν αρχεία με κανόνες που εισάγονται στη βάση δεδομένων. Μπορείτε να ελέγξετε αυτήν τη βάση δεδομένων ως root με:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** εκθέτει επίσης έναν XPC server με διαφορετικές λειτουργίες όπως `assess`, `update`, `record` και `cancel`, οι οποίες είναι επίσης προσβάσιμες μέσω των **`Security.framework`'s `SecAssessment*`** APIs, ενώ το **`spctl`** επικοινωνεί στην πραγματικότητα με το **`syspolicyd`** μέσω XPC.

Παρατηρήστε ότι ο πρώτος κανόνας τελείωνε σε "**App Store**" και ο δεύτερος σε "**Developer ID**", καθώς και ότι στην προηγούμενη εικόνα ήταν **ενεργοποιημένη η εκτέλεση εφαρμογών από το App Store και από αναγνωρισμένους developers**.\
Αν **τροποποιήσετε** αυτή τη ρύθμιση σε App Store, οι κανόνες "**Notarized Developer ID**" θα εξαφανιστούν**.

Υπάρχουν επίσης χιλιάδες κανόνες **τύπου GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Αυτά είναι hashes από:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ή μπορείτε να εμφανίσετε τις προηγούμενες πληροφορίες με:
```bash
sudo spctl --list
```
Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα **απενεργοποιήσουν πλήρως** αυτούς τους ελέγχους υπογραφών:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Όταν ενεργοποιηθεί πλήρως, θα εμφανιστεί μια νέα επιλογή:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να **ελέγξετε αν μια εφαρμογή θα επιτρέπεται από το GateKeeper** με:
```bash
spctl --assess -v /Applications/App.app
```
Είναι δυνατό να προστεθούν νέοι κανόνες στο GateKeeper για να επιτραπεί η εκτέλεση συγκεκριμένων εφαρμογών με:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Όσον αφορά τα **kernel extensions**, ο φάκελος `/var/db/SystemPolicyConfiguration` περιέχει αρχεία με λίστες των kexts που επιτρέπεται να φορτωθούν. Επιπλέον, το `spctl` διαθέτει το entitlement `com.apple.private.iokit.nvram-csr`, επειδή μπορεί να προσθέτει νέα pre-approved kernel extensions, τα οποία πρέπει να αποθηκεύονται επίσης στο NVRAM, σε ένα key `kext-allowed-teams`.

#### Διαχείριση του Gatekeeper σε macOS 15 (Sequoia) και νεότερες εκδόσεις

- Η εδώ και πολλά χρόνια παράκαμψη μέσω Finder **Ctrl+Open / Δεξί κλικ → Άνοιγμα** έχει αφαιρεθεί. Οι χρήστες πρέπει πλέον να επιτρέπουν ρητά μια blocked εφαρμογή από τις **Ρυθμίσεις συστήματος → Απόρρητο και ασφάλεια → Άνοιγμα ούτως ή άλλως**, αφού εμφανιστεί για πρώτη φορά το dialog αποκλεισμού.<sup>[[4]](#references)</sup>
- Οι εντολές `spctl --master-disable/--global-disable` δεν γίνονται πλέον αποδεκτές. Το `spctl` είναι ουσιαστικά read-only για assessment και label management, ενώ η επιβολή της policy διαμορφώνεται μέσω του UI ή του MDM.

Από το macOS 15 Sequoia και έπειτα, οι end users δεν μπορούν πλέον να αλλάζουν την policy του Gatekeeper από το `spctl`. Η διαχείριση πραγματοποιείται μέσω των Ρυθμίσεων συστήματος ή με ανάπτυξη ενός MDM configuration profile με το payload `com.apple.systempolicy.control`. Παράδειγμα τμήματος profile για την allowlist του App Store και των identified developers (αλλά όχι του "Anywhere"):

<details>
<summary>MDM profile για την allowlist του App Store και των identified developers</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Αρχεία Quarantine

Κατά τη **λήψη** μιας εφαρμογής ή ενός αρχείου, συγκεκριμένες **εφαρμογές** του macOS, όπως web browsers ή email clients, **προσθέτουν ένα extended file attribute**, γνωστό συνήθως ως "**quarantine flag**", στο αρχείο που λήφθηκε. Αυτό το attribute λειτουργεί ως μέτρο ασφαλείας για να **σημάνει το αρχείο** ως προερχόμενο από μη αξιόπιστη πηγή (το διαδίκτυο) και ως πιθανώς επικίνδυνο. Ωστόσο, δεν προσθέτουν όλες οι εφαρμογές αυτό το attribute· για παράδειγμα, τα συνηθισμένα BitTorrent client software συνήθως παρακάμπτουν αυτή τη διαδικασία.

**Η παρουσία ενός quarantine flag ενεργοποιεί το security feature Gatekeeper του macOS όταν ένας χρήστης επιχειρεί να εκτελέσει το αρχείο**.

Σε περίπτωση που το **quarantine flag δεν υπάρχει** (όπως με αρχεία που λαμβάνονται μέσω ορισμένων BitTorrent clients), οι **έλεγχοι του Gatekeeper ενδέχεται να μην εκτελεστούν**. Επομένως, οι χρήστες θα πρέπει να είναι προσεκτικοί όταν ανοίγουν αρχεία που έχουν ληφθεί από λιγότερο ασφαλείς ή άγνωστες πηγές.

> [!NOTE] > Η **επαλήθευση** της **εγκυρότητας** των code signatures είναι μια διαδικασία με **υψηλές απαιτήσεις πόρων**, η οποία περιλαμβάνει τη δημιουργία κρυπτογραφικών **hashes** του κώδικα και όλων των bundled resources του. Επιπλέον, ο έλεγχος της εγκυρότητας των certificates περιλαμβάνει έναν **online έλεγχο** στους servers της Apple, προκειμένου να διαπιστωθεί αν το certificate έχει ανακληθεί μετά την έκδοσή του. Για αυτούς τους λόγους, ένας πλήρης έλεγχος code signature και notarization είναι **ανέφικτο να εκτελείται κάθε φορά που εκκινείται μια εφαρμογή**.
>
> Επομένως, αυτοί οι έλεγχοι **εκτελούνται μόνο κατά την εκτέλεση εφαρμογών με το quarantined attribute.**

> [!WARNING]
> Αυτό το attribute πρέπει να **ορίζεται από την εφαρμογή που δημιουργεί/λαμβάνει** το αρχείο.
>
> Ωστόσο, τα αρχεία που βρίσκονται σε sandbox θα έχουν αυτό το attribute ορισμένο για κάθε αρχείο που δημιουργούν. Επίσης, οι non sandboxed εφαρμογές μπορούν να το ορίσουν οι ίδιες ή να καθορίσουν το key [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) στο **Info.plist**, γεγονός που θα κάνει το σύστημα να ορίσει το `com.apple.quarantine` extended attribute στα αρχεία που δημιουργούνται,

Επιπλέον, όλα τα αρχεία που δημιουργούνται από μια διεργασία η οποία καλεί το **`qtn_proc_apply_to_self`** τίθενται σε quarantine. Εναλλακτικά, το API **`qtn_file_apply_to_path`** προσθέτει το quarantine attribute σε μια καθορισμένη διαδρομή αρχείου.

Μπορείτε να **ελέγξετε την κατάστασή του και να το ενεργοποιήσετε/απενεργοποιήσετε** (απαιτούνται δικαιώματα root) με:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Μπορείτε επίσης να **διαπιστώσετε αν ένα αρχείο έχει το quarantine extended attribute** με:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Ελέγξτε την **τιμή** των **extended** **attributes** και βρείτε την εφαρμογή που έγραψε το quarantine attr με:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Στην πραγματικότητα, μια διεργασία «θα μπορούσε να ορίσει quarantine flags στα αρχεία που δημιουργεί» (ήδη δοκίμασα να εφαρμόσω το flag USER_APPROVED σε ένα αρχείο που δημιουργήθηκε, αλλά δεν εφαρμόζεται):

<details>

<summary>Πηγαίος κώδικας για την εφαρμογή quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Και **αφαιρέστε** αυτό το attribute με:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Και βρείτε όλα τα αρχεία σε καραντίνα με:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Οι πληροφορίες του Quarantine αποθηκεύονται επίσης σε μια κεντρική βάση δεδομένων που διαχειρίζεται το LaunchServices στο **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, επιτρέποντας στο GUI να λαμβάνει δεδομένα σχετικά με την προέλευση του αρχείου. Επιπλέον, αυτή μπορεί να παρακαμφθεί από εφαρμογές που ενδέχεται να ενδιαφέρονται να αποκρύψουν την προέλευσή τους. Αυτό μπορεί επίσης να γίνει μέσω των LaunchServices APIs.

#### **libquarantine.dylib**

Αυτή η library εξάγει διάφορες functions που επιτρέπουν τον χειρισμό των πεδίων extended attribute.

Τα APIs `qtn_file_*` αφορούν τις πολιτικές file quarantine, ενώ τα APIs `qtn_proc_*` εφαρμόζονται σε processes (αρχεία που δημιουργούνται από το process). Οι μη εξαγόμενες functions `__qtn_syscall_quarantine*` είναι αυτές που εφαρμόζουν τις policies και καλούν το `mac_syscall` με πρώτο όρισμα το "Quarantine", το οποίο στέλνει τα requests στο `Quarantine.kext`.

#### **Quarantine.kext**

Το kernel extension είναι διαθέσιμο μόνο μέσω του **kernel cache στο σύστημα**. Ωστόσο, _μπορείτε να κατεβάσετε το **Kernel Debug Kit από το** [**https://developer.apple.com/**](https://developer.apple.com/), το οποίο περιέχει μια symbolicated έκδοση του extension.

Αυτό το Kext χρησιμοποιεί hooks μέσω του MACF σε αρκετές calls, ώστε να παγιδεύει όλα τα file lifecycle events: δημιουργία, άνοιγμα, μετονομασία, δημιουργία hard link... ακόμη και το `setxattr`, για να αποτρέπει τον ορισμό του extended attribute `com.apple.quarantine`.

Χρησιμοποιεί επίσης μερικά MIBs:

- `security.mac.qtn.sandbox_enforce`: Επιβολή του Quarantine μαζί με το Sandbox
- `security.mac.qtn.user_approved_exec`: Τα processes σε Quarantine μπορούν να εκτελούν μόνο εγκεκριμένα αρχεία

#### Provenance xattr (Ventura και νεότερα)

Το macOS 13 Ventura εισήγαγε έναν ξεχωριστό μηχανισμό provenance, ο οποίος συμπληρώνεται την πρώτη φορά που επιτρέπεται σε μια quarantined εφαρμογή να εκτελεστεί.<sup>[[2]](#references)</sup> Δημιουργούνται δύο artefacts:

- Το xattr `com.apple.provenance` στον κατάλογο του `.app` bundle (δυαδική τιμή σταθερού μεγέθους που περιέχει ένα primary key και flags).
- Μια γραμμή στον πίνακα `provenance_tracking` μέσα στη βάση δεδομένων ExecPolicy στο `/var/db/SystemPolicyConfiguration/ExecPolicy/`, η οποία αποθηκεύει το cdhash και τα metadata της εφαρμογής.

Πρακτική χρήση:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

Το XProtect είναι μια ενσωματωμένη λειτουργία **anti-malware** στο macOS. Το XProtect **ελέγχει κάθε εφαρμογή κατά την πρώτη εκκίνησή της ή όταν τροποποιείται, συγκρίνοντάς την με τη βάση δεδομένων του** με γνωστό malware και μη ασφαλείς τύπους αρχείων. Όταν κατεβάζετε ένα αρχείο μέσω συγκεκριμένων εφαρμογών, όπως το Safari, το Mail ή τα Messages, το XProtect σαρώνει αυτόματα το αρχείο. Αν αντιστοιχεί σε γνωστό malware της βάσης δεδομένων του, το XProtect θα **εμποδίσει την εκτέλεση του αρχείου** και θα σας ειδοποιήσει για την απειλή.

Η βάση δεδομένων του XProtect **ενημερώνεται τακτικά** από την Apple με νέους ορισμούς malware, και αυτές οι ενημερώσεις κατεβαίνουν και εγκαθίστανται αυτόματα στο Mac σας. Έτσι διασφαλίζεται ότι το XProtect είναι πάντα ενημερωμένο με τις πιο πρόσφατες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι το **XProtect δεν είναι μια ολοκληρωμένη λύση antivirus**. Ελέγχει μόνο μια συγκεκριμένη λίστα γνωστών απειλών και δεν πραγματοποιεί σάρωση on-access, όπως τα περισσότερα λογισμικά antivirus.

Μπορείτε να λάβετε πληροφορίες σχετικά με την πιο πρόσφατη ενημέρωση του XProtect εκτελώντας:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
Το XProtect βρίσκεται σε τοποθεσία προστατευμένη από το SIP στη διεύθυνση **/Library/Apple/System/Library/CoreServices/XProtect.bundle** και μέσα στο bundle μπορείτε να βρείτε πληροφορίες που χρησιμοποιεί το XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει σε code με αυτά τα cdhashes να χρησιμοποιεί legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα plugins και extensions που δεν επιτρέπεται να φορτωθούν μέσω BundleID και TeamID ή που απαιτούν μια ελάχιστη έκδοση.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules για τον εντοπισμό malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση δεδομένων SQLite3 με hashes blocked applications και TeamIDs.

Σημειώστε ότι υπάρχει ένα ακόμη App στη διεύθυνση **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, το οποίο σχετίζεται με το XProtect αλλά δεν συμμετέχει στη διαδικασία του Gatekeeper.

> XProtect Remediator: Σε σύγχρονες εκδόσεις του macOS, η Apple παρέχει on-demand scanners (XProtect Remediator), τα οποία εκτελούνται περιοδικά μέσω launchd για τον εντοπισμό και την αποκατάσταση οικογενειών malware. Μπορείτε να παρατηρήσετε αυτά τα scans στα unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Δεν είναι Gatekeeper

> [!CAUTION]
> Σημειώστε ότι το Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή· μόνο το _**AppleMobileFileIntegrity**_ θα **επαληθεύσει τις υπογραφές του executable code** όταν εκτελείτε μια εφαρμογή που έχει ήδη εκτελεστεί και επαληθευτεί από το Gatekeeper.

Επομένως, παλαιότερα ήταν δυνατό να εκτελέσετε μια εφαρμογή ώστε να αποθηκευτεί σε cache από το Gatekeeper και στη συνέχεια να **τροποποιήσετε μη-executable αρχεία της εφαρμογής** (όπως αρχεία Electron asar ή NIB). Αν δεν υπήρχαν άλλα protections, η εφαρμογή **εκτελούνταν** με τις **malicious** προσθήκες.

Ωστόσο, πλέον αυτό δεν είναι δυνατό, επειδή το macOS **εμποδίζει την τροποποίηση αρχείων** μέσα στα application bundles. Επομένως, αν δοκιμάσετε το attack [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), θα διαπιστώσετε ότι δεν είναι πλέον δυνατό να το εκμεταλλευτείτε, επειδή, αφού εκτελέσετε την εφαρμογή ώστε να αποθηκευτεί σε cache από το Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το bundle. Επίσης, αν αλλάξετε, για παράδειγμα, το όνομα του καταλόγου Contents σε NotCon (όπως υποδεικνύεται στο exploit) και στη συνέχεια εκτελέσετε το κύριο binary της εφαρμογής ώστε να αποθηκευτεί σε cache από το Gatekeeper, θα προκληθεί σφάλμα και δεν θα εκτελεστεί.

## Παρακάμψεις του Gatekeeper

Οποιοσδήποτε τρόπος παράκαμψης του Gatekeeper (να καταφέρετε να κάνει ο χρήστης download κάποιου στοιχείου και να το εκτελέσει ενώ το Gatekeeper θα έπρεπε να το απαγορεύσει) θεωρείται vulnerability στο macOS. Αυτά είναι ορισμένα CVEs που αποδόθηκαν σε techniques οι οποίες επέτρεπαν την παράκαμψη του Gatekeeper στο παρελθόν:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι, αν χρησιμοποιηθεί το **Archive Utility** για extraction, αρχεία με **paths που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το extended attribute com.apple.quarantine. Αυτή η κατάσταση επιτρέπει κατά λάθος σε αυτά τα αρχεία να **παρακάμπτουν τους ελέγχους ασφαλείας του Gatekeeper**.<sup>[[5]](#references)</sup>

Ελέγξτε την [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) για περισσότερες πληροφορίες.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν μια εφαρμογή δημιουργείται με το **Automator**, οι πληροφορίες σχετικά με το τι χρειάζεται για να εκτελεστεί βρίσκονται στο `application.app/Contents/document.wflow` και όχι στο executable. Το executable είναι απλώς ένα generic Automator binary που ονομάζεται **Automator Application Stub**.

Επομένως, θα μπορούσατε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` **να δείχνει με symbolic link σε ένα άλλο Automator Application Stub μέσα στο system** και αυτό θα εκτελούσε ό,τι βρίσκεται στο `document.wflow` (το script σας) **χωρίς να ενεργοποιήσει το Gatekeeper**, επειδή το πραγματικό executable δεν διαθέτει το quarantine xattr.<sup>[[6]](#references)</sup>

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Ελέγξτε την [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) για περισσότερες πληροφορίες.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτό το bypass δημιουργήθηκε ένα zip file με μια εφαρμογή, ξεκινώντας τη συμπίεση από το `application.app/Contents` αντί για το `application.app`. Επομένως, το **quarantine attr** εφαρμοζόταν σε όλα τα **αρχεία του `application.app/Contents`**, αλλά **όχι στο `application.app`**, το οποίο έλεγχε το Gatekeeper. Έτσι, το Gatekeeper παρακαμπτόταν, επειδή όταν γινόταν trigger το `application.app` **δεν είχε το quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Δείτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Παρόλο που τα components είναι διαφορετικά, η εκμετάλλευση αυτής της ευπάθειας είναι πολύ παρόμοια με την προηγούμενη. Σε αυτήν την περίπτωση, θα δημιουργήσουμε ένα Apple Archive από το **`application.app/Contents`**, ώστε το **`application.app`** να μην αποκτήσει το quarantine attr κατά την αποσυμπίεσή του από το **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Δείτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) για περισσότερες πληροφορίες.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Το ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να αποτρέψει οποιονδήποτε από την εγγραφή μιας ιδιότητας σε ένα αρχείο:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Επιπλέον, η μορφή αρχείων **AppleDouble** αντιγράφει ένα αρχείο μαζί με τα ACE του.<sup>[[9]](#references)</sup>

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατό να δούμε ότι η αναπαράσταση κειμένου του ACL που είναι αποθηκευμένη μέσα στο xattr με την ονομασία **`com.apple.acl.text`** πρόκειται να οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Επομένως, αν συμπιέζατε μια εφαρμογή σε ένα αρχείο zip με τη μορφή αρχείων **AppleDouble**, με ένα ACL που εμποδίζει την εγγραφή άλλων xattr σε αυτήν... το quarantine xattr δεν ορίστηκε στην εφαρμογή:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.<sup>[[9]](#references)</sup>

Σημειώστε ότι αυτό θα μπορούσε επίσης να γίνει exploit μέσω του AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ανακαλύφθηκε ότι το **Google Chrome δεν όριζε το quarantine attribute** στα ληφθέντα αρχεία εξαιτίας ορισμένων εσωτερικών προβλημάτων του macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Οι μορφές αρχείων AppleDouble αποθηκεύουν τα attributes ενός αρχείου σε ξεχωριστό αρχείο που ξεκινά με `._`, γεγονός που βοηθά στην αντιγραφή των attributes αρχείων **μεταξύ υπολογιστών macOS**. Ωστόσο, παρατηρήθηκε ότι μετά την αποσυμπίεση ενός αρχείου AppleDouble, στο αρχείο που ξεκινά με `._` **δεν αποδιδόταν το quarantine attribute**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Έχοντας τη δυνατότητα να δημιουργήσουμε ένα αρχείο στο οποίο δεν θα έχει οριστεί το quarantine attribute, ήταν **δυνατή η παράκαμψη του Gatekeeper.** Το τέχνασμα ήταν να **δημιουργήσουμε ένα αρχείο εφαρμογής DMG** χρησιμοποιώντας τη σύμβαση ονοματοδοσίας AppleDouble (ξεκινώντας το με `._`) και να δημιουργήσουμε ένα **ορατό αρχείο ως sym link** προς αυτό το κρυφό αρχείο, χωρίς το quarantine attribute.\
Όταν **εκτελεστεί το αρχείο dmg**, καθώς δεν διαθέτει quarantine attribute, θα **παρακάμψει το Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Ένα Gatekeeper bypass που διορθώθηκε στο macOS Sonoma 14.0 επέτρεπε σε ειδικά διαμορφωμένες εφαρμογές να εκτελούνται χωρίς προειδοποίηση. Οι λεπτομέρειες δημοσιοποιήθηκαν μετά την επιδιόρθωση και το ζήτημα είχε γίνει αντικείμενο ενεργής εκμετάλλευσης στο wild πριν από τη διόρθωση. Βεβαιωθείτε ότι είναι εγκατεστημένο το Sonoma 14.0 ή νεότερο.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Ένα Gatekeeper bypass στο macOS 14.4 (που κυκλοφόρησε τον Μάρτιο του 2024), το οποίο προέκυπτε από τον τρόπο με τον οποίο το `libarchive` χειριζόταν κακόβουλα ZIP, επέτρεπε σε εφαρμογές να αποφεύγουν το assessment. Κάντε update στην έκδοση 14.4 ή νεότερη, όπου η Apple αντιμετώπισε το ζήτημα.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Ένα **Automator Quick Action workflow** ενσωματωμένο σε μια εφαρμογή που είχε γίνει download μπορούσε να ενεργοποιηθεί χωρίς assessment από το Gatekeeper, επειδή τα workflows αντιμετωπίζονταν ως δεδομένα και εκτελούνταν από τον Automator helper εκτός της κανονικής διαδρομής του prompt για notarization. Επομένως, ένα ειδικά διαμορφωμένο `.app` που περιείχε ένα Quick Action το οποίο εκτελεί ένα shell script (π.χ. μέσα στο `Contents/PlugIns/*.workflow/Contents/document.wflow`) μπορούσε να εκτελεστεί αμέσως κατά την εκκίνηση. Η Apple πρόσθεσε ένα επιπλέον consent dialog και διόρθωσε τη διαδρομή του assessment στα Ventura **13.7**, Sonoma **14.7** και Sequoia **15**.<sup>[[3]](#references)</sup>

### Third‑party unarchivers με εσφαλμένη μεταβίβαση του quarantine (2023–2024)

Αρκετά vulnerabilities σε δημοφιλή extraction tools (π.χ. το The Unarchiver) προκαλούσαν την απώλεια του `com.apple.quarantine` xattr από αρχεία που εξάγονταν από archives, επιτρέποντας ευκαιρίες για Gatekeeper bypass. Να βασίζεστε πάντα στο macOS Archive Utility ή σε patched tools κατά το testing και να επικυρώνετε τα xattrs μετά την εξαγωγή.

### uchg (από αυτήν την [ομιλία](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Δημιουργήστε έναν κατάλογο που περιέχει μια εφαρμογή.
- Προσθέστε το uchg στην εφαρμογή.
- Συμπιέστε την εφαρμογή σε ένα αρχείο tar.gz.
- Στείλτε το αρχείο tar.gz σε ένα victim.
- Το victim ανοίγει το αρχείο tar.gz και εκτελεί την εφαρμογή.
- Το Gatekeeper δεν ελέγχει την εφαρμογή.<sup>[[12]](#references)</sup>

### Αποτροπή του Quarantine xattr

Σε ένα bundle ".app", αν δεν προστεθεί σε αυτό το quarantine xattr, κατά την εκτέλεσή του **το Gatekeeper δεν θα ενεργοποιηθεί**.

## Αναφορές

- [1] [Apple Platform Security: Σχετικά με το περιεχόμενο ασφάλειας του macOS Sonoma 14.4 (περιλαμβάνει το CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Πώς το macOS παρακολουθεί πλέον την προέλευση των εφαρμογών](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Σχετικά με το περιεχόμενο ασφάλειας του macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: Το macOS 15 Sequoia καταργεί το Gatekeeper bypass μέσω Control‑click “Open”](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Η ανακάλυψη του CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Παράκαμψη του macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Η Jamf Threat Labs εντοπίζει vulnerability του Safari που επιτρέπει Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Η Jamf Threat Labs εντοπίζει vulnerability του macOS Archive Utility που επιτρέπει Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Η αχίλλειος πτέρνα του Gatekeeper: Αποκάλυψη vulnerability του macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ανακάλυψη ενός Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Εντοπισμός και αναφορά ενός Gatekeeper bypass exploit με τη βοήθεια του Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Παράκαμψη των Μηχανισμών Ασφάλειας και Privacy του macOS — Από το Gatekeeper στο System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Σχετικά με το περιεχόμενο ασφάλειας του macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)

{{#include ../../../banners/hacktricks-training.md}}
