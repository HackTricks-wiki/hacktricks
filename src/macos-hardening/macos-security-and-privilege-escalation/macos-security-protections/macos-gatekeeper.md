# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

Το **Gatekeeper** είναι μια δυνατότητα ασφαλείας που αναπτύχθηκε για τα λειτουργικά συστήματα Mac και έχει σχεδιαστεί ώστε να διασφαλίζει ότι οι χρήστες **εκτελούν μόνο αξιόπιστο software** στα συστήματά τους. Λειτουργεί **επικυρώνοντας το software** που κατεβάζει και προσπαθεί να ανοίξει ένας χρήστης από **πηγές εκτός του App Store**, όπως μια εφαρμογή, ένα plug-in ή ένα installer package.

Ο βασικός μηχανισμός του Gatekeeper βασίζεται στη διαδικασία **verification**. Ελέγχει αν το downloaded software είναι **υπογεγραμμένο από αναγνωρισμένο developer**, διασφαλίζοντας την αυθεντικότητά του. Επιπλέον, διαπιστώνει αν το software έχει **notarised από την Apple**, επιβεβαιώνοντας ότι δεν περιέχει γνωστό κακόβουλο περιεχόμενο και ότι δεν έχει τροποποιηθεί μετά το notarisation.

Επιπλέον, το Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια του χρήστη ζητώντας από τους χρήστες να **εγκρίνουν το άνοιγμα** του downloaded software την πρώτη φορά. Αυτή η προστασία βοηθά στην αποτροπή της ακούσιας εκτέλεσης δυνητικά επιβλαβούς executable code, το οποίο μπορεί να έχει θεωρηθεί εσφαλμένα harmless data file.

### Signatures Εφαρμογών

Οι signatures εφαρμογών, γνωστές επίσης ως code signatures, αποτελούν κρίσιμο στοιχείο της υποδομής ασφαλείας της Apple. Χρησιμοποιούνται για την **επαλήθευση της ταυτότητας του author του software** (του developer) και για τη διασφάλιση ότι ο κώδικας δεν έχει τροποποιηθεί από την τελευταία φορά που υπογράφηκε.

Δείτε πώς λειτουργεί:

1. **Signing της Εφαρμογής:** Όταν ένας developer είναι έτοιμος να διανείμει την εφαρμογή του, **υπογράφει την εφαρμογή χρησιμοποιώντας ένα private key**. Αυτό το private key συνδέεται με ένα **certificate που εκδίδει η Apple στον developer** όταν εγγράφεται στο Apple Developer Program. Η διαδικασία signing περιλαμβάνει τη δημιουργία ενός cryptographic hash όλων των τμημάτων της εφαρμογής και την κρυπτογράφηση αυτού του hash με το private key του developer.
2. **Διανομή της Εφαρμογής:** Η signed εφαρμογή διανέμεται στη συνέχεια στους χρήστες μαζί με το certificate του developer, το οποίο περιέχει το αντίστοιχο public key.
3. **Verification της Εφαρμογής:** Όταν ένας χρήστης κατεβάζει και προσπαθεί να εκτελέσει την εφαρμογή, το Mac operating system χρησιμοποιεί το public key από το certificate του developer για να αποκρυπτογραφήσει το hash. Στη συνέχεια υπολογίζει ξανά το hash με βάση την τρέχουσα κατάσταση της εφαρμογής και το συγκρίνει με το decrypted hash. Αν ταιριάζουν, σημαίνει ότι **η εφαρμογή δεν έχει τροποποιηθεί** από τότε που την υπέγραψε ο developer και το σύστημα επιτρέπει στην εφαρμογή να εκτελεστεί.

Οι application signatures αποτελούν βασικό μέρος της τεχνολογίας Gatekeeper της Apple. Όταν ένας χρήστης προσπαθεί να **ανοίξει μια εφαρμογή που κατέβασε από το internet**, το Gatekeeper επαληθεύει την application signature. Αν έχει υπογραφεί με certificate που έχει εκδοθεί από την Apple σε γνωστό developer και ο κώδικας δεν έχει τροποποιηθεί, το Gatekeeper επιτρέπει στην εφαρμογή να εκτελεστεί. Διαφορετικά, μπλοκάρει την εφαρμογή και ειδοποιεί τον χρήστη.

Από το macOS Catalina και έπειτα, το **Gatekeeper ελέγχει επίσης αν η εφαρμογή έχει notarized** από την Apple, προσθέτοντας ένα επιπλέον επίπεδο ασφάλειας. Η διαδικασία notarization ελέγχει την εφαρμογή για γνωστά security issues και malicious code και, αν αυτοί οι έλεγχοι ολοκληρωθούν επιτυχώς, η Apple προσθέτει ένα ticket στην εφαρμογή, το οποίο μπορεί να επαληθεύσει το Gatekeeper.

#### Έλεγχος Signatures

Κατά τον έλεγχο κάποιου **malware sample**, θα πρέπει πάντα να **ελέγχετε τη signature** του binary, καθώς ο **developer** που το υπέγραψε μπορεί να **σχετίζεται** ήδη με **malware.**
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

Η διαδικασία notarization της Apple λειτουργεί ως πρόσθετη προστασία για την προστασία των χρηστών από δυνητικά επιβλαβές λογισμικό. Περιλαμβάνει την **υποβολή της εφαρμογής από τον developer για εξέταση** από την **Apple's Notary Service**, η οποία δεν πρέπει να συγχέεται με το App Review. Αυτή η υπηρεσία είναι ένα **automated system** που ελέγχει το υποβληθέν λογισμικό για την ύπαρξη **malicious content** και τυχόν προβλημάτων με το code-signing.

Αν το λογισμικό **περάσει** αυτόν τον έλεγχο χωρίς να εντοπιστούν προβλήματα, η Notary Service δημιουργεί ένα notarization ticket. Στη συνέχεια, ο developer πρέπει να **επισυνάψει αυτό το ticket στο λογισμικό του**, μια διαδικασία που είναι γνωστή ως 'stapling.' Επιπλέον, το notarization ticket δημοσιεύεται online, όπου μπορεί να έχει πρόσβαση το Gatekeeper, η τεχνολογία ασφαλείας της Apple.

Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του notarization ticket - είτε είναι stapled στο executable είτε βρίσκεται online - **ενημερώνει το Gatekeeper ότι το λογισμικό έχει υποβληθεί σε notarization από την Apple**. Ως αποτέλεσμα, το Gatekeeper εμφανίζει ένα περιγραφικό μήνυμα στο αρχικό παράθυρο διαλόγου εκκίνησης, indicando ότι το λογισμικό έχει ελεγχθεί από την Apple για malicious content. Με αυτόν τον τρόπο ενισχύεται η εμπιστοσύνη των χρηστών στην ασφάλεια του λογισμικού που εγκαθιστούν ή εκτελούν στα συστήματά τους.

### spctl & syspolicyd

> [!CAUTION]
> Σημειώστε ότι από την έκδοση Sequoia και έπειτα, το **`spctl`** δεν επιτρέπει πλέον την τροποποίηση της διαμόρφωσης του Gatekeeper.

Το **`spctl`** είναι το CLI tool για την απαρίθμηση και την αλληλεπίδραση με το Gatekeeper (μέσω του daemon `syspolicyd` και μηνυμάτων XPC). Για παράδειγμα, είναι δυνατό να εμφανιστεί το **status** του GateKeeper με:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Σημειώστε ότι οι έλεγχοι υπογραφής του GateKeeper εκτελούνται μόνο σε **αρχεία με το χαρακτηριστικό Quarantine**, όχι σε κάθε αρχείο.

Το GateKeeper ελέγχει αν, σύμφωνα με τις **προτιμήσεις και την υπογραφή**, μπορεί να εκτελεστεί ένα binary:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

Το **`syspolicyd`** είναι το κύριο daemon που είναι υπεύθυνο για την επιβολή του Gatekeeper. Διατηρεί μια βάση δεδομένων στη διεύθυνση `/var/db/SystemPolicy` και μπορείτε να βρείτε τον κώδικα υποστήριξης για τη [βάση δεδομένων εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), καθώς και το [SQL template εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Σημειώστε ότι η βάση δεδομένων δεν περιορίζεται από το SIP και είναι εγγράψιμη από τον root, ενώ η βάση δεδομένων `/var/db/.SystemPolicy-default` χρησιμοποιείται ως αρχικό backup σε περίπτωση που η άλλη καταστραφεί.

Επιπλέον, τα bundles **`/var/db/gke.bundle`** και **`/var/db/gkopaque.bundle`** περιέχουν αρχεία με rules που εισάγονται στη βάση δεδομένων. Μπορείτε να ελέγξετε αυτήν τη βάση δεδομένων ως root με:
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
Το **`syspolicyd`** εκθέτει επίσης έναν XPC server με διαφορετικές λειτουργίες όπως `assess`, `update`, `record` και `cancel`, οι οποίες είναι επίσης προσβάσιμες μέσω των APIs **`Security.framework`'s `SecAssessment*`** και το **`spctl`** επικοινωνεί στην πραγματικότητα με το **`syspolicyd`** μέσω XPC.

Σημειώστε ότι ο πρώτος κανόνας τελείωνε σε "**App Store**" και ο δεύτερος σε "**Developer ID**", και ότι στην προηγούμενη εικόνα ήταν **ενεργοποιημένη η εκτέλεση εφαρμογών από το App Store και από ταυτοποιημένους developers**.\
Αν **τροποποιήσετε** αυτήν τη ρύθμιση σε App Store, οι κανόνες "**Notarized Developer ID" θα εξαφανιστούν**.

Υπάρχουν επίσης χιλιάδες κανόνες **τύπου GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Αυτοί είναι οι hashes από:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Εναλλακτικά, μπορείτε να εμφανίσετε τις προηγούμενες πληροφορίες με:
```bash
sudo spctl --list
```
Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα **απενεργοποιήσουν πλήρως** αυτούς τους ελέγχους υπογραφής:
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

Είναι δυνατό να **ελέγξετε αν ένα App θα επιτρέπεται από το GateKeeper** με:
```bash
spctl --assess -v /Applications/App.app
```
Στο macOS 14 και νεότερα, το **`syspolicy_check`** είναι ένας χρήσιμος έλεγχος υψηλότερου επιπέδου πριν από τη διανομή ενός bundle εφαρμογής. Παράγει πιο αξιοποιήσιμα διαγνωστικά trusted-execution από ένα απλό αποτέλεσμα του `spctl`, αν και η Apple εξακολουθεί να συνιστά τον έλεγχο της πραγματικής διαδρομής λήψης/αποσυμπίεσης/πρώτης εκκίνησης, επειδή αυτή ελέγχει επίσης τη διάδοση του quarantine.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
Είναι δυνατή η προσθήκη νέων κανόνων στο GateKeeper για να επιτραπεί η εκτέλεση συγκεκριμένων εφαρμογών με:
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
Όσον αφορά τα **kernel extensions**, ο φάκελος `/var/db/SystemPolicyConfiguration` περιέχει αρχεία με λίστες των kexts που επιτρέπεται να φορτωθούν. Επιπλέον, το `spctl` διαθέτει το entitlement `com.apple.private.iokit.nvram-csr`, επειδή μπορεί να προσθέτει νέα pre-approved kernel extensions, τα οποία πρέπει επίσης να αποθηκεύονται στο NVRAM σε ένα key `kext-allowed-teams`.

#### Διαχείριση του Gatekeeper στο macOS 15 (Sequoia) και νεότερες εκδόσεις

- Το παλιό bypass του Finder **Ctrl+Open / Δεξί κλικ → Open** έχει καταργηθεί· οι χρήστες πρέπει να επιτρέπουν ρητά μια blocked εφαρμογή από τις **System Settings → Privacy & Security → Open Anyway**, μετά το πρώτο block dialog.<sup>[[4]](#references)</sup>
- Τα `spctl --master-disable/--global-disable` δεν γίνονται πλέον αποδεκτά ως unattended policy changes. Οι λειτουργίες που τροποποιούν τη rule database ή την global assessment state έχουν deprecated, επομένως χρησιμοποιήστε το `spctl` για assessment και ρυθμίστε το enforcement μέσω του UI ή του MDM.

Από το macOS 15 Sequoia, οι end users δεν μπορούν πλέον να αλλάζουν το Gatekeeper policy από το `spctl`. Η διαχείριση πραγματοποιείται μέσω των System Settings ή με ανάπτυξη ενός MDM configuration profile με το payload `com.apple.systempolicy.control`. Παράδειγμα profile snippet για την αποδοχή του App Store και identified developers (αλλά όχι του "Anywhere"):

<details>
<summary>MDM profile για την αποδοχή του App Store και identified developers</summary>
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

Κατά τη **λήψη** μιας εφαρμογής ή ενός αρχείου, συγκεκριμένες **εφαρμογές** του macOS, όπως web browsers ή email clients, **επισυνάπτουν ένα εκτεταμένο χαρακτηριστικό αρχείου**, γνωστό συνήθως ως "**quarantine flag**", στο αρχείο που λήφθηκε. Αυτό το χαρακτηριστικό λειτουργεί ως μέτρο ασφαλείας για να **σημάνει το αρχείο** ως προερχόμενο από μη αξιόπιστη πηγή (το διαδίκτυο) και ως δυνητικά επικίνδυνο. Ωστόσο, δεν επισυνάπτουν όλες οι εφαρμογές αυτό το χαρακτηριστικό· για παράδειγμα, τα συνηθισμένα BitTorrent client software συνήθως παρακάμπτουν αυτή τη διαδικασία.

**Η παρουσία ενός quarantine flag ενεργοποιεί το χαρακτηριστικό ασφαλείας Gatekeeper του macOS όταν ένας χρήστης προσπαθεί να εκτελέσει το αρχείο**.

Σε περίπτωση που το **quarantine flag δεν υπάρχει** (όπως με αρχεία που λαμβάνονται μέσω ορισμένων BitTorrent clients), οι **έλεγχοι του Gatekeeper ενδέχεται να μην πραγματοποιηθούν**. Επομένως, οι χρήστες θα πρέπει να είναι προσεκτικοί όταν ανοίγουν αρχεία που έχουν ληφθεί από λιγότερο ασφαλείς ή άγνωστες πηγές.

> [!NOTE] > Η **επαλήθευση** της **εγκυρότητας** των code signatures είναι μια **υπολογιστικά απαιτητική** διαδικασία που περιλαμβάνει τη δημιουργία κρυπτογραφικών **hashes** του κώδικα και όλων των bundled resources του. Επιπλέον, ο έλεγχος της εγκυρότητας των certificates περιλαμβάνει έναν **online έλεγχο** στους servers της Apple, προκειμένου να διαπιστωθεί αν έχουν ανακληθεί μετά την έκδοσή τους. Για αυτούς τους λόγους, ένας πλήρης έλεγχος code signature και notarization είναι **ανέφικτο να εκτελείται κάθε φορά που εκκινείται μια εφαρμογή**.
>
> Επομένως, αυτοί οι έλεγχοι **εκτελούνται μόνο κατά την εκτέλεση εφαρμογών με το quarantined attribute.**

> [!WARNING]
> Αυτό το attribute πρέπει να **οριστεί από την εφαρμογή που δημιουργεί/κατεβάζει** το αρχείο.
>
> Ωστόσο, τα αρχεία που είναι sandboxed θα έχουν αυτό το attribute ορισμένο σε κάθε αρχείο που δημιουργούν. Επιπλέον, οι non sandboxed εφαρμογές μπορούν να το ορίσουν οι ίδιες ή να καθορίσουν το key [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) στο **Info.plist**, γεγονός που θα κάνει το σύστημα να ορίσει το extended attribute `com.apple.quarantine` στα αρχεία που δημιουργούνται,

Επιπλέον, όλα τα αρχεία που δημιουργούνται από μια διεργασία η οποία καλεί το **`qtn_proc_apply_to_self`** τίθενται σε quarantine. Εναλλακτικά, το API **`qtn_file_apply_to_path`** προσθέτει το quarantine attribute σε μια καθορισμένη διαδρομή αρχείου.

Είναι δυνατό να **ελεγχθεί η κατάστασή του και να ενεργοποιηθεί/απενεργοποιηθεί** (απαιτείται root) με:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Μπορείτε επίσης να **ελέγξετε αν ένα αρχείο έχει το extended attribute quarantine** με:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Ελέγξτε την **τιμή** των **extended** **attributes** και εντοπίστε την εφαρμογή που έγραψε το quarantine attr με:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Στην πραγματικότητα, μια διεργασία «θα μπορούσε να ορίσει quarantine flags στα αρχεία που δημιουργεί» (ήδη προσπάθησα να εφαρμόσω το flag USER_APPROVED σε ένα δημιουργημένο αρχείο, αλλά δεν εφαρμόζεται):

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

Και **αφαιρέστε** αυτή την ιδιότητα με:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Και βρείτε όλα τα αρχεία σε καραντίνα με:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Οι πληροφορίες καραντίνας αποθηκεύονται επίσης σε μια κεντρική database που διαχειρίζεται το LaunchServices στο **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, η οποία επιτρέπει στο GUI να λαμβάνει δεδομένα σχετικά με την προέλευση των αρχείων. Επιπλέον, αυτή μπορεί να overwritten από applications που ενδέχεται να ενδιαφέρονται να αποκρύψουν την προέλευσή τους. Αυτό μπορεί επίσης να γίνει μέσω των LaunchServices APIS.

#### **libquarantine.dylib**

Αυτή η library εξάγει αρκετές functions που επιτρέπουν τον χειρισμό των πεδίων extended attribute.

Τα `qtn_file_*` APIs αφορούν quarantine policies αρχείων, ενώ τα `qtn_proc_*` APIs εφαρμόζονται σε processes (αρχεία που δημιουργούνται από το process). Οι μη εξαγόμενες functions `__qtn_syscall_quarantine*` είναι αυτές που εφαρμόζουν τις policies και καλούν το `mac_syscall` με το "Quarantine" ως πρώτο όρισμα, το οποίο στέλνει τα requests στο `Quarantine.kext`.

#### **Quarantine.kext**

Το kernel extension είναι διαθέσιμο μόνο μέσω του **kernel cache στο σύστημα**· ωστόσο, _μπορείτε να κατεβάσετε το **Kernel Debug Kit από το** [**https://developer.apple.com/**](https://developer.apple.com/), το οποίο περιέχει μια symbolicated έκδοση του extension.

Αυτό το Kext χρησιμοποιεί hooks μέσω του MACF σε αρκετές calls, προκειμένου να κάνει traps σε όλα τα file lifecycle events: Creation, opening, renaming, hard-linkning... ακόμη και στο `setxattr`, ώστε να αποτρέπει τον ορισμό του extended attribute `com.apple.quarantine`.

Χρησιμοποιεί επίσης μερικά MIBs:

- `security.mac.qtn.sandbox_enforce`: Επιβολή του quarantine μαζί με το Sandbox
- `security.mac.qtn.user_approved_exec`: Τα Querantined procs μπορούν να εκτελούν μόνο approved files

#### Provenance xattr (Ventura και νεότερα)

Το macOS 13 Ventura εισήγαγε έναν ξεχωριστό μηχανισμό provenance, ο οποίος συμπληρώνεται την πρώτη φορά που επιτρέπεται να εκτελεστεί ένα quarantined app.<sup>[[2]](#references)</sup> Δημιουργούνται δύο artefacts:

- Το `com.apple.provenance` xattr στον κατάλογο του `.app` bundle (binary value σταθερού μεγέθους που περιέχει ένα primary key και flags).
- Μια row στον πίνακα `provenance_tracking` μέσα στη database ExecPolicy στη διεύθυνση `/var/db/SystemPolicyConfiguration/ExecPolicy/`, η οποία αποθηκεύει το cdhash και τα metadata του app.

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

Το XProtect είναι μια ενσωματωμένη λειτουργία **anti-malware** στο macOS. Το XProtect **ελέγχει κάθε εφαρμογή κατά την πρώτη εκκίνησή της ή όταν τροποποιείται, συγκρίνοντάς την με τη βάση δεδομένων του** που περιέχει γνωστό malware και μη ασφαλείς τύπους αρχείων. Όταν κατεβάζετε ένα αρχείο μέσω συγκεκριμένων εφαρμογών, όπως τα Safari, Mail ή Messages, το XProtect σαρώνει αυτόματα το αρχείο. Αν αντιστοιχεί σε γνωστό malware της βάσης δεδομένων του, το XProtect θα **εμποδίσει την εκτέλεση του αρχείου** και θα σας ειδοποιήσει για την απειλή.

Η βάση δεδομένων του XProtect **ενημερώνεται τακτικά** από την Apple με νέους ορισμούς malware, και αυτές οι ενημερώσεις κατεβαίνουν και εγκαθίστανται αυτόματα στο Mac σας. Αυτό διασφαλίζει ότι το XProtect είναι πάντα ενημερωμένο με τις πιο πρόσφατες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι **το XProtect δεν είναι μια ολοκληρωμένη λύση antivirus**. Ελέγχει μόνο μια συγκεκριμένη λίστα γνωστών απειλών και δεν πραγματοποιεί σάρωση on-access όπως τα περισσότερα λογισμικά antivirus.

Μπορείτε να λάβετε πληροφορίες σχετικά με την πιο πρόσφατη ενημέρωση του XProtect εκτελώντας:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
Το XProtect βρίσκεται στη SIP protected τοποθεσία **/Library/Apple/System/Library/CoreServices/XProtect.bundle** και μέσα στο bundle μπορείτε να βρείτε πληροφορίες που χρησιμοποιεί το XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει σε κώδικα με αυτά τα cdhashes να χρησιμοποιεί legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα plugins και extensions που δεν επιτρέπεται να φορτωθούν μέσω BundleID και TeamID ή που απαιτούν μια ελάχιστη έκδοση.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules για τον εντοπισμό malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση δεδομένων SQLite3 με hashes αποκλεισμένων εφαρμογών και TeamIDs.

Σημειώστε ότι υπάρχει ένα ακόμη App στο **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, το οποίο σχετίζεται με το XProtect, αλλά δεν συμμετέχει στη διαδικασία του Gatekeeper.

> XProtect Remediator: Σε σύγχρονα macOS, η Apple παρέχει on-demand scanners (XProtect Remediator), οι οποίοι εκτελούνται περιοδικά μέσω launchd για τον εντοπισμό και την αποκατάσταση οικογενειών malware. Μπορείτε να παρατηρήσετε αυτά τα scans στα unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Δεν είναι το Gatekeeper

> [!CAUTION]
> Σημειώστε ότι το Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή· μόνο το _**AppleMobileFileIntegrity**_ θα **επαληθεύσει τις υπογραφές του executable code** όταν εκτελείτε μια εφαρμογή που έχει ήδη εκτελεστεί και επαληθευτεί από το Gatekeeper.

Επομένως, παλαιότερα ήταν δυνατό να εκτελέσετε μια εφαρμογή ώστε να αποθηκευτεί σε cache από το Gatekeeper και στη συνέχεια να **τροποποιήσετε αρχεία της εφαρμογής που δεν είναι executables** (όπως αρχεία Electron asar ή NIB). Αν δεν υπήρχαν άλλες protections, η εφαρμογή **εκτελούνταν** με τις **malicious** προσθήκες.

Ωστόσο, πλέον αυτό δεν είναι δυνατό, επειδή το macOS **αποτρέπει την τροποποίηση αρχείων** μέσα σε application bundles. Επομένως, αν δοκιμάσετε το [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, θα διαπιστώσετε ότι δεν είναι πλέον δυνατό να το εκμεταλλευτείτε, επειδή αφού εκτελέσετε την εφαρμογή ώστε να αποθηκευτεί σε cache από το Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το bundle. Και αν αλλάξετε, για παράδειγμα, το όνομα του Contents directory σε NotCon (όπως υποδεικνύεται στο exploit) και στη συνέχεια εκτελέσετε το main binary της εφαρμογής ώστε να αποθηκευτεί σε cache από το Gatekeeper, θα προκληθεί error και δεν θα εκτελεστεί.

## Gatekeeper Bypasses

Οποιοσδήποτε τρόπος παράκαμψης του Gatekeeper (να καταφέρετε να κάνετε τον χρήστη να κατεβάσει κάτι και να το εκτελέσει ενώ το Gatekeeper θα έπρεπε να το αποτρέψει) θεωρείται vulnerability στο macOS. Αυτά είναι ορισμένα CVEs που αντιστοιχούν σε techniques οι οποίες επέτρεπαν στο παρελθόν την παράκαμψη του Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι, όταν το **Archive Utility** χρησιμοποιείται για extraction, αρχεία με **paths που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το extended attribute com.apple.quarantine. Αυτή η κατάσταση επιτρέπει ακούσια σε αυτά τα αρχεία να **παρακάμπτουν τους ελέγχους ασφαλείας του Gatekeeper**.<sup>[[5]](#references)</sup>

Ανατρέξτε στο [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) για περισσότερες πληροφορίες.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν μια εφαρμογή δημιουργείται με το **Automator**, οι πληροφορίες σχετικά με όσα χρειάζεται για να εκτελεστεί βρίσκονται μέσα στο `application.app/Contents/document.wflow` και όχι στο executable. Το executable είναι απλώς ένα generic Automator binary που ονομάζεται **Automator Application Stub**.

Επομένως, θα μπορούσατε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` να **δείχνει μέσω symbolic link σε ένα άλλο Automator Application Stub μέσα στο σύστημα** και αυτό θα εκτελούσε ό,τι υπάρχει στο `document.wflow` (το script σας) **χωρίς να ενεργοποιήσει το Gatekeeper**, επειδή το actual executable δεν διαθέτει το quarantine xattr.<sup>[[6]](#references)</sup>

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Ανατρέξτε στο [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) για περισσότερες πληροφορίες.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτό το bypass δημιουργήθηκε ένα zip file με μια εφαρμογή, ξεκινώντας τη συμπίεση από το `application.app/Contents` αντί για το `application.app`. Επομένως, το **quarantine attr** εφαρμόστηκε σε όλα τα **αρχεία από το `application.app/Contents`**, αλλά **όχι στο `application.app`**, το οποίο έλεγχε το Gatekeeper. Έτσι, το Gatekeeper παρακάμφθηκε, επειδή όταν ενεργοποιήθηκε το `application.app` **δεν είχε το quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Ελέγξτε την [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Ακόμη και αν τα components είναι διαφορετικά, η εκμετάλλευση αυτού του vulnerability είναι πολύ παρόμοια με την προηγούμενη. Σε αυτή την περίπτωση, θα δημιουργήσουμε ένα Apple Archive από το **`application.app/Contents`**, έτσι ώστε το **`application.app`** να μην αποκτήσει το quarantine attr κατά την αποσυμπίεση από το **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Ελέγξτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) για περισσότερες πληροφορίες.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Το ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να αποτρέψει οποιονδήποτε από την εγγραφή ενός attribute σε ένα αρχείο:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Επιπλέον, η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο μαζί με τα ACEs του.<sup>[[9]](#references)</sup>

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατό να δούμε ότι η αναπαράσταση ACL σε μορφή κειμένου, αποθηκευμένη μέσα στο xattr που ονομάζεται **`com.apple.acl.text`**, πρόκειται να οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Επομένως, αν συμπιέζατε μια εφαρμογή σε αρχείο zip με τη μορφή αρχείου **AppleDouble**, με ένα ACL που εμποδίζει την εγγραφή άλλων xattrs σε αυτήν... το quarantine xattr δεν οριζόταν στην εφαρμογή:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.<sup>[[9]](#references)</sup>

Σημειώστε ότι αυτό θα μπορούσε επίσης να γίνει exploit με το AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ανακαλύφθηκε ότι το **Google Chrome δεν όριζε το quarantine attribute** στα downloaded αρχεία λόγω ορισμένων εσωτερικών προβλημάτων του macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Το AppleDouble αποθηκεύει τα attributes ενός αρχείου σε ξεχωριστό αρχείο, το όνομα του οποίου ξεκινά με `._`· αυτό βοηθά στην αντιγραφή των attributes **μεταξύ υπολογιστών macOS**. Ωστόσο, μετά την αποσυμπίεση ενός αρχείου AppleDouble, στο αρχείο που ξεκινούσε με `._` **δεν είχε δοθεί το quarantine attribute**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Έχοντας τη δυνατότητα να δημιουργήσετε ένα αρχείο που δεν θα έχει ορισμένο το quarantine attribute, ήταν **δυνατό να παρακαμφθεί το Gatekeeper.** Το trick ήταν να **δημιουργήσετε ένα DMG file application** χρησιμοποιώντας τη σύμβαση ονομασίας AppleDouble (ξεκινώντας το με `._`) και να δημιουργήσετε ένα **ορατό αρχείο ως sym link προς αυτό το κρυφό** αρχείο, χωρίς το quarantine attribute.\
Όταν **εκτελείται το dmg file**, καθώς δεν διαθέτει quarantine attribute, θα **παρακάμψει το Gatekeeper**.
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

Η Apple διόρθωσε ένα σφάλμα λογικής του LaunchServices στο macOS Sonoma 14.0 μέσω βελτιωμένων ελέγχων. Η δημόσια advisory αναφέρει μόνο ότι μια εφαρμογή μπορούσε να παρακάμψει το Gatekeeper, επομένως μην συμπεραίνετε συγκεκριμένη μορφή carrier ή αλυσίδα exploitation μόνο από την καταχώριση CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Ένα Gatekeeper bypass στο macOS 14.4 (κυκλοφόρησε τον Μάρτιο του 2024), το οποίο προέκυπτε από τον τρόπο με τον οποίο το `libarchive` χειριζόταν κακόβουλα ZIP, επέτρεπε σε εφαρμογές να αποφεύγουν το assessment. Κάντε update στην έκδοση 14.4 ή νεότερη, όπου η Apple αντιμετώπισε το ζήτημα.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Ένα **Automator Quick Action workflow** ενσωματωμένο σε μια downloaded εφαρμογή μπορούσε να ενεργοποιηθεί χωρίς Gatekeeper assessment, επειδή τα workflows αντιμετωπίζονταν ως δεδομένα και εκτελούνταν από το Automator helper εκτός της κανονικής διαδρομής του notarization prompt. Ένα crafted `.app` που περιείχε ένα Quick Action το οποίο εκτελεί shell script (π.χ. μέσα στο `Contents/PlugIns/*.workflow/Contents/document.wflow`) μπορούσε επομένως να εκτελεστεί αμέσως κατά το launch. Η Apple πρόσθεσε ένα επιπλέον consent dialog και διόρθωσε τη διαδρομή assessment στα Ventura **13.7**, Sonoma **14.7** και Sequoia **15**.<sup>[[3]](#references)</sup>

### Αποτυχίες propagation του quarantine στα όρια extraction και copy

Μια μελέτη του 2024 εντόπισε κενά στο propagation στις δοκιμασμένες εκδόσεις των iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) και 7z Utility (DMG/ZIP/7Z)· παρατήρησε επίσης ότι το attribute χανόταν κατά τις host-to-guest αντιγραφές του VMware Tools. Αρκετοί vendors ανακοίνωσαν στη συνέχεια fixes, επομένως αντιμετωπίστε αυτά τα ονόματα ως leads για **version-specific retesting** και όχι ως μόνιμη λίστα ευάλωτου software. Το ίδιο πρόβλημα trust boundary ισχύει και για native Unix workflows: τα `curl`/`scp` δεν προσθέτουν quarantine, ενώ τα command-line `tar`/`unzip` δεν το κληρονομούν αυτόματα από ένα carrier archive.<sup>[[15]](#references)</sup>

Για offensive testing, συγκρίνετε το carrier και την τελική εφαρμογή μετά από **κάθε** μετάβαση μέσω browser, mail client, archive, disk-image, cloud-sync, shared-folder και VM-copy. Μια ρητή απόρριψη από το `spctl` δεν διορθώνει ένα missing xattr: χωρίς quarantine, η κανονική διαδρομή του Gatekeeper κατά το πρώτο άνοιγμα μπορεί να μην ζητήσει ποτέ αυτό το assessment.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (από αυτή την [ομιλία](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Δημιουργήστε έναν κατάλογο που περιέχει μια εφαρμογή.
- Προσθέστε το uchg στην εφαρμογή.
- Συμπιέστε την εφαρμογή σε αρχείο tar.gz.
- Στείλτε το αρχείο tar.gz σε ένα θύμα.
- Το θύμα ανοίγει το αρχείο tar.gz και εκτελεί την εφαρμογή.
- Το Gatekeeper δεν ελέγχει την εφαρμογή.<sup>[[12]](#references)</sup>

### Αποτροπή του Quarantine xattr

Σε ένα bundle ".app", αν δεν προστεθεί σε αυτό το quarantine xattr, κατά την εκτέλεσή του **το Gatekeeper δεν θα ενεργοποιηθεί**.

Δείτε το [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) για primitives που βασίζονται σε filesystem, flags, ACL και AppleDouble και μπορούν να αποτρέψουν ή να απορρίψουν extended attributes.



## References

- [1] [Apple Platform Security: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.4 (περιλαμβάνει το CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Πώς το macOS παρακολουθεί πλέον την προέλευση των εφαρμογών](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: Το macOS 15 Sequoia καταργεί το bypass του Gatekeeper μέσω Control-click “Open”](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Η ανακάλυψη του CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Παράκαμψη του macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs: Εντοπίζει ευπάθεια του Safari που επιτρέπει bypass του Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs: Εντοπίζει ευπάθεια του macOS Archive Utility που επιτρέπει bypass του Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Η αχίλλειος πτέρνα του Gatekeeper: Αποκαλύπτοντας μια ευπάθεια του macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ανακάλυψη bypass του Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Εντοπισμός και αναφορά exploit για bypass του Gatekeeper με τη βοήθεια του Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Παράκαμψη των μηχανισμών ασφάλειας και ιδιωτικότητας του macOS — Από το Gatekeeper στο System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Δοκιμή ενός notarised product](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Bypass του Gatekeeper — Αποκαλύπτοντας αδυναμίες σε έναν μηχανισμό ασφαλείας του macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
