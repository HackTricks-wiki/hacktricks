# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

**Gatekeeper** είναι μια λειτουργία ασφαλείας που έχει αναπτυχθεί για τα λειτουργικά συστήματα Mac, σχεδιασμένη να διασφαλίσει ότι οι χρήστες **εκτελούν μόνο αξιόπιστο λογισμικό** στα συστήματά τους. Λειτουργεί με το να **επικυρώνει το λογισμικό** που κατεβάζει ο χρήστης και προσπαθεί να ανοίξει από **πηγές εκτός του App Store**, όπως μια εφαρμογή, ένα πρόσθετο ή ένα πακέτο εγκατάστασης.

Ο βασικός μηχανισμός του Gatekeeper έγκειται στη διαδικασία **επικύρωσης**. Ελέγχει αν το κατεβασμένο λογισμικό είναι **υπογεγραμμένο από έναν αναγνωρισμένο προγραμματιστή**, διασφαλίζοντας την αυθεντικότητα του λογισμικού. Επιπλέον, διαπιστώνει αν το λογισμικό είναι **νοταρισμένο από την Apple**, επιβεβαιώνοντας ότι είναι απαλλαγμένο από γνωστό κακόβουλο περιεχόμενο και δεν έχει παραποιηθεί μετά τη νοταρίσματος.

Επιπλέον, το Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια του χρήστη, **ζητώντας από τους χρήστες να εγκρίνουν το άνοιγμα** του κατεβασμένου λογισμικού για πρώτη φορά. Αυτό το μέτρο προστασίας βοηθά στην αποφυγή της εκτέλεσης δυνητικά επιβλαβούς εκτελέσιμου κώδικα που μπορεί να έχουν μπερδέψει οι χρήστες με ένα αβλαβές αρχείο δεδομένων.

### Υπογραφές Εφαρμογών

Οι υπογραφές εφαρμογών, γνωστές και ως υπογραφές κώδικα, είναι ένα κρίσιμο στοιχείο της υποδομής ασφαλείας της Apple. Χρησιμοποιούνται για να **επικυρώσουν την ταυτότητα του συγγραφέα του λογισμικού** (του προγραμματιστή) και για να διασφαλίσουν ότι ο κώδικας δεν έχει παραποιηθεί από την τελευταία φορά που υπογράφηκε.

Ακολουθεί πώς λειτουργεί:

1. **Υπογραφή της Εφαρμογής:** Όταν ένας προγραμματιστής είναι έτοιμος να διανείμει την εφαρμογή του, **υπογράφει την εφαρμογή χρησιμοποιώντας ένα ιδιωτικό κλειδί**. Αυτό το ιδιωτικό κλειδί σχετίζεται με ένα **πιστοποιητικό που εκδίδει η Apple στον προγραμματιστή** όταν εγγραφεί στο Πρόγραμμα Προγραμματιστών της Apple. Η διαδικασία υπογραφής περιλαμβάνει τη δημιουργία ενός κρυπτογραφικού κατακερματισμού όλων των μερών της εφαρμογής και την κρυπτογράφηση αυτού του κατακερματισμού με το ιδιωτικό κλειδί του προγραμματιστή.
2. **Διανομή της Εφαρμογής:** Η υπογεγραμμένη εφαρμογή διανέμεται στους χρήστες μαζί με το πιστοποιητικό του προγραμματιστή, το οποίο περιέχει το αντίστοιχο δημόσιο κλειδί.
3. **Επικύρωση της Εφαρμογής:** Όταν ένας χρήστης κατεβάσει και προσπαθήσει να εκτελέσει την εφαρμογή, το λειτουργικό σύστημα Mac χρησιμοποιεί το δημόσιο κλειδί από το πιστοποιητικό του προγραμματιστή για να αποκρυπτογραφήσει τον κατακερματισμό. Στη συνέχεια, υπολογίζει ξανά τον κατακερματισμό με βάση την τρέχουσα κατάσταση της εφαρμογής και τον συγκρίνει με τον αποκρυπτογραφημένο κατακερματισμό. Αν ταιριάζουν, σημαίνει ότι **η εφαρμογή δεν έχει τροποποιηθεί** από την υπογραφή του προγραμματιστή και το σύστημα επιτρέπει την εκτέλεση της εφαρμογής.

Οι υπογραφές εφαρμογών είναι ένα ουσιαστικό μέρος της τεχνολογίας Gatekeeper της Apple. Όταν ένας χρήστης προσπαθεί να **ανοίξει μια εφαρμογή που έχει κατεβάσει από το διαδίκτυο**, το Gatekeeper επαληθεύει την υπογραφή της εφαρμογής. Αν είναι υπογεγραμμένη με πιστοποιητικό που έχει εκδώσει η Apple σε έναν γνωστό προγραμματιστή και ο κώδικας δεν έχει παραποιηθεί, το Gatekeeper επιτρέπει την εκτέλεση της εφαρμογής. Διαφορετικά, αποκλείει την εφαρμογή και ειδοποιεί τον χρήστη.

Από το macOS Catalina και μετά, **το Gatekeeper ελέγχει επίσης αν η εφαρμογή έχει νοταριστεί** από την Apple, προσθέτοντας μια επιπλέον στρώση ασφάλειας. Η διαδικασία νοταρίσματος ελέγχει την εφαρμογή για γνωστά ζητήματα ασφαλείας και κακόβουλο κώδικα, και αν αυτές οι έλεγχοι περάσουν, η Apple προσθέτει ένα εισιτήριο στην εφαρμογή που μπορεί να επαληθεύσει το Gatekeeper.

#### Έλεγχος Υπογραφών

Όταν ελέγχετε κάποιο **δείγμα κακόβουλου λογισμικού**, θα πρέπει πάντα να **ελέγχετε την υπογραφή** του δυαδικού, καθώς ο **προγραμματιστής** που το υπέγραψε μπορεί ήδη να είναι **σχετικός** με **κακόβουλο λογισμικό.**
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

Η διαδικασία notarization της Apple λειτουργεί ως επιπλέον προστασία για να προστατεύσει τους χρήστες από δυνητικά επιβλαβές λογισμικό. Περιλαμβάνει την **υποβολή της εφαρμογής από τον προγραμματιστή για εξέταση** από την **Υπηρεσία Notary της Apple**, η οποία δεν πρέπει να συγχέεται με την Εξέταση Εφαρμογών. Αυτή η υπηρεσία είναι ένα **αυτοματοποιημένο σύστημα** που εξετάζει το υποβληθέν λογισμικό για την παρουσία **κακόβουλου περιεχομένου** και τυχόν πιθανών προβλημάτων με την υπογραφή κώδικα.

Εάν το λογισμικό **περάσει** αυτή την επιθεώρηση χωρίς να εγείρει ανησυχίες, η Υπηρεσία Notary δημιουργεί ένα εισιτήριο notarization. Ο προγραμματιστής είναι υποχρεωμένος να **συνδέσει αυτό το εισιτήριο με το λογισμικό του**, μια διαδικασία που ονομάζεται 'stapling.' Επιπλέον, το εισιτήριο notarization δημοσιεύεται επίσης online όπου ο Gatekeeper, η τεχνολογία ασφαλείας της Apple, μπορεί να έχει πρόσβαση σε αυτό.

Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του εισιτηρίου notarization - είτε είναι συνδεδεμένο με το εκτελέσιμο είτε βρίσκεται online - **ενημερώνει τον Gatekeeper ότι το λογισμικό έχει πιστοποιηθεί από την Apple**. Ως αποτέλεσμα, ο Gatekeeper εμφανίζει ένα περιγραφικό μήνυμα στο αρχικό παράθυρο εκκίνησης, υποδεικνύοντας ότι το λογισμικό έχει υποβληθεί σε ελέγχους για κακόβουλο περιεχόμενο από την Apple. Αυτή η διαδικασία ενισχύει την εμπιστοσύνη των χρηστών στην ασφάλεια του λογισμικού που εγκαθιστούν ή εκτελούν στα συστήματά τους.

### spctl & syspolicyd

> [!CAUTION]
> Σημειώστε ότι από την έκδοση Sequoia, **`spctl`** δεν επιτρέπει πλέον την τροποποίηση της διαμόρφωσης του Gatekeeper.

**`spctl`** είναι το εργαλείο CLI για την καταμέτρηση και την αλληλεπίδραση με τον Gatekeeper (με τον daemon `syspolicyd` μέσω μηνυμάτων XPC). Για παράδειγμα, είναι δυνατή η προβολή της **κατάστασης** του GateKeeper με:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Σημειώστε ότι οι έλεγχοι υπογραφής του GateKeeper εκτελούνται μόνο για **αρχεία με το χαρακτηριστικό Quarantine**, όχι για κάθε αρχείο.

Ο GateKeeper θα ελέγξει αν σύμφωνα με τις **προτιμήσεις & την υπογραφή** μπορεί να εκτελεστεί ένα δυαδικό αρχείο:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** είναι ο κύριος δαίμονας που είναι υπεύθυνος για την επιβολή του Gatekeeper. Διατηρεί μια βάση δεδομένων που βρίσκεται στο `/var/db/SystemPolicy` και είναι δυνατή η εύρεση του κώδικα για την υποστήριξη της [βάσης δεδομένων εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) και του [SQL template εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Σημειώστε ότι η βάση δεδομένων δεν περιορίζεται από το SIP και είναι εγγράψιμη από τον root και η βάση δεδομένων `/var/db/.SystemPolicy-default` χρησιμοποιείται ως αρχικό αντίγραφο ασφαλείας σε περίπτωση που η άλλη καταστραφεί.

Επιπλέον, τα πακέτα **`/var/db/gke.bundle`** και **`/var/db/gkopaque.bundle`** περιέχουν αρχεία με κανόνες που εισάγονται στη βάση δεδομένων. Μπορείτε να ελέγξετε αυτή τη βάση δεδομένων ως root με:
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
**`syspolicyd`** εκθέτει επίσης έναν XPC διακομιστή με διάφορες λειτουργίες όπως `assess`, `update`, `record` και `cancel` που είναι επίσης προσβάσιμες χρησιμοποιώντας τις APIs **`SecAssessment*`** του **`Security.framework`** και το **`spctl`** στην πραγματικότητα επικοινωνεί με το **`syspolicyd`** μέσω XPC.

Σημειώστε πώς ο πρώτος κανόνας τελείωσε σε "**App Store**" και ο δεύτερος σε "**Developer ID**" και ότι στην προηγούμενη εικόνα ήταν **ενεργοποιημένο να εκτελεί εφαρμογές από το App Store και αναγνωρισμένους προγραμματιστές**.\
Αν **τροποποιήσετε** αυτή τη ρύθμιση σε App Store, οι κανόνες "**Notarized Developer ID" θα εξαφανιστούν**.

Υπάρχουν επίσης χιλιάδες κανόνες **τύπου GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Αυτοί είναι οι κατακερματισμοί που προέρχονται από:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ή μπορείτε να παραθέσετε τις προηγούμενες πληροφορίες με:
```bash
sudo spctl --list
```
Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα **απενεργοποιήσουν** εντελώς αυτούς τους ελέγχους υπογραφής:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Όταν είναι πλήρως ενεργοποιημένο, μια νέα επιλογή θα εμφανιστεί:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατόν να **ελέγξετε αν μια εφαρμογή θα επιτραπεί από το GateKeeper** με:
```bash
spctl --assess -v /Applications/App.app
```
Είναι δυνατόν να προσθέσετε νέους κανόνες στο GateKeeper για να επιτρέψετε την εκτέλεση ορισμένων εφαρμογών με:
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
Σχετικά με **kernel extensions**, ο φάκελος `/var/db/SystemPolicyConfiguration` περιέχει αρχεία με λίστες kexts που επιτρέπεται να φορτωθούν. Επιπλέον, το `spctl` έχει την εξουσία `com.apple.private.iokit.nvram-csr` επειδή είναι ικανό να προσθέτει νέες προεγκεκριμένες kernel extensions που πρέπει επίσης να αποθηκευτούν στη NVRAM σε ένα κλειδί `kext-allowed-teams`.

#### Διαχείριση του Gatekeeper σε macOS 15 (Sequoia) και μεταγενέστερες εκδόσεις

Από το macOS 15 Sequoia, οι τελικοί χρήστες δεν μπορούν πλέον να αλλάξουν την πολιτική του Gatekeeper από το `spctl`. Η διαχείριση γίνεται μέσω των Ρυθμίσεων Συστήματος ή με την ανάπτυξη ενός προφίλ διαμόρφωσης MDM με το payload `com.apple.systempolicy.control`. Παράδειγμα αποσπάσματος προφίλ για να επιτραπεί το App Store και οι αναγνωρισμένοι προγραμματιστές (αλλά όχι "Οπουδήποτε"):
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
### Quarantine Files

Upon **downloading** an application or file, specific macOS **applications** such as web browsers or email clients **attach an extended file attribute**, commonly known as the "**quarantine flag**," to the downloaded file. This attribute acts as a security measure to **mark the file** as coming from an untrusted source (the internet), and potentially carrying risks. However, not all applications attach this attribute, for instance, common BitTorrent client software usually bypasses this process.

**Η παρουσία της σημαίας καραντίνας σηματοδοτεί τη λειτουργία ασφαλείας Gatekeeper του macOS όταν ένας χρήστης προσπαθεί να εκτελέσει το αρχείο**.

In the case where the **quarantine flag is not present** (as with files downloaded via some BitTorrent clients), Gatekeeper's **checks may not be performed**. Thus, users should exercise caution when opening files downloaded from less secure or unknown sources.

> [!NOTE] > **Έλεγχος** της **έγκυρης** υπογραφής κώδικα είναι μια **χρονικά απαιτητική** διαδικασία που περιλαμβάνει τη δημιουργία κρυπτογραφικών **hashes** του κώδικα και όλων των πόρων που περιλαμβάνονται. Furthermore, checking certificate validity involves doing an **online check** to Apple's servers to see if it has been revoked after it was issued. For these reasons, a full code signature and notarization check is **impractical to run every time an app is launched**.
>
> Therefore, these checks are **only run when executing apps with the quarantined attribute.**

> [!WARNING]
> This attribute must be **set by the application creating/downloading** the file.
>
> However, files that are sandboxed will have this attribute set to every file they create. And non sandboxed apps can set it themselves, or specify the [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key in the **Info.plist** which will make the system set the `com.apple.quarantine` extended attribute on the files created,

Moreover, all files created by a process calling **`qtn_proc_apply_to_self`** are quarantined. Or the API **`qtn_file_apply_to_path`** adds the quarantine attribute to a specified file path.

It's possible to **check it's status and enable/disable** (root required) with:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Μπορείτε επίσης να **βρείτε αν ένα αρχείο έχει την επεκτάσιμη ιδιότητα καραντίνας** με:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Ελέγξτε την **τιμή** των **εκτεταμένων** **χαρακτηριστικών** και βρείτε την εφαρμογή που έγραψε το χαρακτηριστικό καραντίνας με:
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
Στην πραγματικότητα, μια διαδικασία "θα μπορούσε να ορίσει σημαίες καραντίνας στα αρχεία που δημιουργεί" (έχω ήδη προσπαθήσει να εφαρμόσω τη σημαία USER_APPROVED σε ένα δημιουργημένο αρχείο, αλλά δεν θα την εφαρμόσει):

<details>

<summary>Κώδικας Πηγής εφαρμογής σημαίων καραντίνας</summary>
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

Και **αφαιρέστε** αυτό το χαρακτηριστικό με:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Και βρείτε όλα τα καραντινιασμένα αρχεία με:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

Αυτή η βιβλιοθήκη εξάγει πολλές συναρτήσεις που επιτρέπουν την επεξεργασία των πεδίων εκτεταμένων χαρακτηριστικών.

Οι APIs `qtn_file_*` ασχολούνται με τις πολιτικές καραντίνας αρχείων, οι APIs `qtn_proc_*` εφαρμόζονται σε διαδικασίες (αρχεία που δημιουργούνται από τη διαδικασία). Οι μη εξαγόμενες συναρτήσεις `__qtn_syscall_quarantine*` είναι αυτές που εφαρμόζουν τις πολιτικές που καλούν το `mac_syscall` με "Quarantine" ως πρώτο επιχείρημα, το οποίο στέλνει τα αιτήματα στο `Quarantine.kext`.

#### **Quarantine.kext**

Η επέκταση πυρήνα είναι διαθέσιμη μόνο μέσω της **κρυφής μνήμης πυρήνα στο σύστημα**; ωστόσο, μπορείτε να κατεβάσετε το **Kernel Debug Kit από** [**https://developer.apple.com/**](https://developer.apple.com/), το οποίο θα περιέχει μια συμβολική έκδοση της επέκτασης.

Αυτό το Kext θα συνδέσει μέσω MACF πολλές κλήσεις προκειμένου να παγιδεύσει όλα τα γεγονότα κύκλου ζωής αρχείων: Δημιουργία, άνοιγμα, μετονομασία, σκληρή σύνδεση... ακόμη και `setxattr` για να αποτρέψει την ρύθμιση του εκτεταμένου χαρακτηριστικού `com.apple.quarantine`.

Χρησιμοποιεί επίσης μερικά MIBs:

- `security.mac.qtn.sandbox_enforce`: Επιβολή καραντίνας μαζί με Sandbox
- `security.mac.qtn.user_approved_exec`: Οι διαδικασίες που είναι σε καραντίνα μπορούν να εκτελούν μόνο εγκεκριμένα αρχεία

#### Provenance xattr (Ventura και αργότερα)

Το macOS 13 Ventura εισήγαγε έναν ξεχωριστό μηχανισμό προέλευσης που συμπληρώνεται την πρώτη φορά που επιτρέπεται σε μια εφαρμογή σε καραντίνα να εκτελείται. Δημιουργούνται δύο αντικείμενα:

- Το `com.apple.provenance` xattr στον φάκελο `.app` (σταθερού μεγέθους δυαδική τιμή που περιέχει ένα κύριο κλειδί και σημαίες).
- Μια γραμμή στον πίνακα `provenance_tracking` μέσα στη βάση δεδομένων ExecPolicy στο `/var/db/SystemPolicyConfiguration/ExecPolicy/` που αποθηκεύει το cdhash και τα μεταδεδομένα της εφαρμογής.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect είναι μια ενσωματωμένη **αντι-malware** δυνατότητα στο macOS. XProtect **ελέγχει οποιαδήποτε εφαρμογή όταν εκκινείται για πρώτη φορά ή τροποποιείται σε σχέση με τη βάση δεδομένων** του για γνωστά malware και επικίνδυνους τύπους αρχείων. Όταν κατεβάζετε ένα αρχείο μέσω ορισμένων εφαρμογών, όπως το Safari, το Mail ή τα Messages, το XProtect σαρώνει αυτόματα το αρχείο. Εάν ταιριάζει με οποιοδήποτε γνωστό malware στη βάση δεδομένων του, το XProtect θα **αποτρέψει την εκτέλεση του αρχείου** και θα σας ειδοποιήσει για την απειλή.

Η βάση δεδομένων του XProtect **ενημερώνεται τακτικά** από την Apple με νέες ορισμούς malware, και αυτές οι ενημερώσεις κατεβαίνουν και εγκαθίστανται αυτόματα στον Mac σας. Αυτό διασφαλίζει ότι το XProtect είναι πάντα ενημερωμένο με τις τελευταίες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι **το XProtect δεν είναι μια πλήρης λύση antivirus**. Ελέγχει μόνο για μια συγκεκριμένη λίστα γνωστών απειλών και δεν εκτελεί σάρωση κατά την πρόσβαση όπως οι περισσότερες λύσεις antivirus.

Μπορείτε να λάβετε πληροφορίες σχετικά με την τελευταία ενημέρωση του XProtect εκτελώντας:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect βρίσκεται σε προστατευμένη τοποθεσία SIP στο **/Library/Apple/System/Library/CoreServices/XProtect.bundle** και μέσα στο bundle μπορείτε να βρείτε πληροφορίες που χρησιμοποιεί το XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει στον κώδικα με αυτούς τους cdhashes να χρησιμοποιεί κληρονομημένα δικαιώματα.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα με plugins και επεκτάσεις που δεν επιτρέπεται να φορτωθούν μέσω BundleID και TeamID ή που υποδεικνύουν μια ελάχιστη έκδοση.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Κανόνες Yara για την ανίχνευση κακόβουλου λογισμικού.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση δεδομένων SQLite3 με hashes αποκλεισμένων εφαρμογών και TeamIDs.

Σημειώστε ότι υπάρχει μια άλλη εφαρμογή στο **`/Library/Apple/System/Library/CoreServices/XProtect.app`** που σχετίζεται με το XProtect και δεν εμπλέκεται στη διαδικασία του Gatekeeper.

> XProtect Remediator: Στο σύγχρονο macOS, η Apple παρέχει σαρωτές κατ' απαίτηση (XProtect Remediator) που εκτελούνται περιοδικά μέσω του launchd για να ανιχνεύσουν και να αποκαταστήσουν οικογένειες κακόβουλου λογισμικού. Μπορείτε να παρακολουθήσετε αυτές τις σαρώσεις στα ενοποιημένα αρχεία καταγραφής:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Όχι Gatekeeper

> [!CAUTION]
> Σημειώστε ότι ο Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή, μόνο το _**AppleMobileFileIntegrity**_ (AMFI) θα **επαληθεύσει τις υπογραφές εκτελέσιμου κώδικα** όταν εκτελείτε μια εφαρμογή που έχει ήδη εκτελεστεί και επαληθευτεί από τον Gatekeeper.

Επομένως, προηγουμένως ήταν δυνατό να εκτελέσετε μια εφαρμογή για να την αποθηκεύσετε στη μνήμη cache με τον Gatekeeper, στη συνέχεια **να τροποποιήσετε μη εκτελέσιμα αρχεία της εφαρμογής** (όπως τα αρχεία Electron asar ή NIB) και αν δεν υπήρχαν άλλες προστασίες, η εφαρμογή θα **εκτελούνταν** με τις **κακόβουλες** προσθήκες.

Ωστόσο, τώρα αυτό δεν είναι δυνατό γιατί το macOS **αποτρέπει την τροποποίηση αρχείων** μέσα σε bundles εφαρμογών. Έτσι, αν προσπαθήσετε την επίθεση [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), θα διαπιστώσετε ότι δεν είναι πλέον δυνατό να την εκμεταλλευτείτε γιατί μετά την εκτέλεση της εφαρμογής για να την αποθηκεύσετε στη μνήμη cache με τον Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το bundle. Και αν αλλάξετε για παράδειγμα το όνομα του καταλόγου Contents σε NotCon (όπως υποδεικνύεται στην εκμετάλλευση), και στη συνέχεια εκτελέσετε το κύριο δυαδικό της εφαρμογής για να το αποθηκεύσετε στη μνήμη cache με τον Gatekeeper, θα προκαλέσει σφάλμα και δεν θα εκτελεστεί.

## Παράκαμψη Gatekeeper

Οποιοσδήποτε τρόπος για να παρακάμψετε τον Gatekeeper (να καταφέρετε να κάνετε τον χρήστη να κατεβάσει κάτι και να το εκτελέσει όταν ο Gatekeeper θα έπρεπε να το αποτρέψει) θεωρείται ευπάθεια στο macOS. Αυτές είναι μερικές CVEs που έχουν ανατεθεί σε τεχνικές που επέτρεπαν την παράκαμψη του Gatekeeper στο παρελθόν:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι αν χρησιμοποιηθεί το **Archive Utility** για εξαγωγή, αρχεία με **διαδρομές που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το εκτεταμένο χαρακτηριστικό com.apple.quarantine. Αυτή η κατάσταση επιτρέπει ακούσια σε αυτά τα αρχεία να **παρακάμψουν τους** ελέγχους ασφαλείας του Gatekeeper.

Ελέγξτε την [**αρχική αναφορά**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) για περισσότερες πληροφορίες.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν μια εφαρμογή δημιουργείται με το **Automator**, οι πληροφορίες σχετικά με το τι χρειάζεται για να εκτελεστεί βρίσκονται μέσα στο `application.app/Contents/document.wflow` και όχι στο εκτελέσιμο. Το εκτελέσιμο είναι απλώς ένα γενικό δυαδικό αρχείο Automator που ονομάζεται **Automator Application Stub**.

Επομένως, θα μπορούσατε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` **να δείχνει με έναν συμβολικό σύνδεσμο σε άλλο Automator Application Stub μέσα στο σύστημα** και θα εκτελέσει ό,τι είναι μέσα στο `document.wflow` (το σενάριό σας) **χωρίς να ενεργοποιήσει τον Gatekeeper** γιατί το πραγματικό εκτελέσιμο δεν έχει το χαρακτηριστικό καραντίνας xattr.

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Ελέγξτε την [**αρχική αναφορά**](https://ronmasas.com/posts/bypass-macos-gatekeeper) για περισσότερες πληροφορίες.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτή την παράκαμψη δημιουργήθηκε ένα zip αρχείο με μια εφαρμογή που άρχισε να συμπιέζεται από το `application.app/Contents` αντί από το `application.app`. Επομένως, το **χαρακτηριστικό καραντίνας** εφαρμόστηκε σε όλα τα **αρχεία από το `application.app/Contents`** αλλά **όχι στο `application.app`**, το οποίο ήταν αυτό που έλεγχε ο Gatekeeper, έτσι ο Gatekeeper παρακάμφθηκε γιατί όταν ενεργοποιήθηκε το `application.app` **δεν είχε το χαρακτηριστικό καραντίνας.**
```bash
zip -r test.app/Contents test.zip
```
Ελέγξτε την [**πρωτότυπη αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Ακόμα και αν τα συστατικά είναι διαφορετικά, η εκμετάλλευση αυτής της ευπάθειας είναι πολύ παρόμοια με την προηγούμενη. Σε αυτή την περίπτωση θα δημιουργήσουμε ένα Apple Archive από **`application.app/Contents`** έτσι ώστε το **`application.app` να μην αποκτήσει την ιδιότητα καραντίνας** όταν αποσυμπιεστεί από το **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Δείτε την [**πρωτότυπη αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) για περισσότερες πληροφορίες.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Η ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να αποτρέψει οποιονδήποτε από το να γράψει ένα χαρακτηριστικό σε ένα αρχείο:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Επιπλέον, η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο συμπεριλαμβανομένων των ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατόν να δει κανείς ότι η κείμενη αναπαράσταση ACL που αποθηκεύεται μέσα στο xattr που ονομάζεται **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπίεσες μια εφαρμογή σε ένα αρχείο zip με μορφή αρχείου **AppleDouble** με ένα ACL που αποτρέπει την εγγραφή άλλων xattrs σε αυτό... το xattr καραντίνας δεν ορίστηκε στην εφαρμογή:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Δείτε την [**πρωτότυπη αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Σημειώστε ότι αυτό θα μπορούσε επίσης να εκμεταλλευτεί με AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ανακαλύφθηκε ότι **το Google Chrome δεν ρύθμιζε το χαρακτηριστικό καραντίνας** για τα κατεβασμένα αρχεία λόγω κάποιων εσωτερικών προβλημάτων του macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Οι μορφές αρχείων AppleDouble αποθηκεύουν τα χαρακτηριστικά ενός αρχείου σε ένα ξεχωριστό αρχείο που ξεκινά με `._`, αυτό βοηθά στην αντιγραφή των χαρακτηριστικών των αρχείων **σε μηχανές macOS**. Ωστόσο, παρατηρήθηκε ότι μετά την αποσυμπίεση ενός αρχείου AppleDouble, το αρχείο που ξεκινά με `._` **δεν έλαβε το χαρακτηριστικό καραντίνας**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Η δυνατότητα δημιουργίας ενός αρχείου που δεν θα έχει οριστεί το χαρακτηριστικό καραντίνας, ήταν **δυνατό να παρακαμφθεί ο Gatekeeper.** Το κόλπο ήταν να **δημιουργηθεί μια εφαρμογή DMG** χρησιμοποιώντας τη σύμβαση ονοματοδοσίας AppleDouble (να ξεκινά με `._`) και να δημιουργηθεί ένα **ορατό αρχείο ως συμβολικός σύνδεσμος σε αυτό το κρυφό** αρχείο χωρίς το χαρακτηριστικό καραντίνας.\
Όταν **εκτελείται το αρχείο dmg**, καθώς δεν έχει χαρακτηριστικό καραντίνας, θα **παρακαμφθεί ο Gatekeeper.**
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

Μια παράκαμψη του Gatekeeper που διορθώθηκε στο macOS Sonoma 14.0 επέτρεψε σε κακόβουλες εφαρμογές να εκτελούνται χωρίς προειδοποίηση. Οι λεπτομέρειες αποκαλύφθηκαν δημόσια μετά την επιδιόρθωση και το ζήτημα εκμεταλλεύτηκε ενεργά στον έξω κόσμο πριν από τη διόρθωση. Βεβαιωθείτε ότι είναι εγκατεστημένο το Sonoma 14.0 ή νεότερη έκδοση.

### [CVE-2024-27853]

Μια παράκαμψη του Gatekeeper στο macOS 14.4 (που κυκλοφόρησε τον Μάρτιο του 2024) που προήλθε από την επεξεργασία κακόβουλων ZIP από το `libarchive` επέτρεψε στις εφαρμογές να αποφύγουν την αξιολόγηση. Ενημερώστε σε 14.4 ή νεότερη έκδοση όπου η Apple διόρθωσε το ζήτημα.

### Εξωτερικοί αποσυμπιεστές που διαδίδουν λανθασμένα την καραντίνα (2023–2024)

Πολλές ευπάθειες σε δημοφιλή εργαλεία εξαγωγής (π.χ., The Unarchiver) προκάλεσαν τα αρχεία που εξάγονται από αρχεία να μην έχουν το xattr `com.apple.quarantine`, επιτρέποντας ευκαιρίες παράκαμψης του Gatekeeper. Πάντα να βασίζεστε στο macOS Archive Utility ή σε διορθωμένα εργαλεία κατά τη διάρκεια των δοκιμών και να επικυρώνετε τα xattrs μετά την εξαγωγή.

### uchg (από αυτή την [ομιλία](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Δημιουργήστε έναν φάκελο που περιέχει μια εφαρμογή.
- Προσθέστε uchg στην εφαρμογή.
- Συμπιέστε την εφαρμογή σε αρχείο tar.gz.
- Στείλτε το αρχείο tar.gz σε ένα θύμα.
- Το θύμα ανοίγει το αρχείο tar.gz και εκτελεί την εφαρμογή.
- Ο Gatekeeper δεν ελέγχει την εφαρμογή.

### Αποτροπή xattr καραντίνας

Σε ένα ".app" πακέτο, αν το xattr καραντίνας δεν προστεθεί σε αυτό, κατά την εκτέλεση του **ο Gatekeeper δεν θα ενεργοποιηθεί**.


## Αναφορές

- Apple Platform Security: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.4 (περιλαμβάνει το CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Πώς το macOS παρακολουθεί τώρα την προέλευση των εφαρμογών – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)

{{#include ../../../banners/hacktricks-training.md}}
