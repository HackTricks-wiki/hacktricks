# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** είναι μια λειτουργία ασφαλείας που αναπτύχθηκε για τα λειτουργικά συστήματα Mac, σχεδιασμένη να διασφαλίζει ότι οι χρήστες **τρέχουν μόνο αξιόπιστο λογισμικό** στα συστήματά τους. Λειτουργεί κάνοντας **επικύρωση του λογισμικού** που ο χρήστης κατεβάζει και προσπαθεί να ανοίξει από **πηγές εκτός του App Store**, όπως μια εφαρμογή, ένα plugin ή ένα installer package.

Ο κύριος μηχανισμός του Gatekeeper έγκειται στη διαδικασία **επαλήθευσης**. Ελέγχει εάν το κατεβασμένο λογισμικό είναι **υπογεγραμμένο από αναγνωρισμένο developer**, διασφαλίζοντας την αυθεντικότητα του λογισμικού. Επιπλέον, επιβεβαιώνει εάν το λογισμικό έχει **notarised by Apple**, επιβεβαιώνοντας ότι δεν περιέχει γνωστό κακόβουλο περιεχόμενο και ότι δεν έχει αλλοιωθεί μετά την notarisation.

Επιπρόσθετα, ο Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια του χρήστη ζητώντας από τον χρήστη να **επιβεβαιώσει το άνοιγμα** του λογισμικού που κατεβάστηκε την πρώτη φορά που θα προσπαθήσει να το ανοίξει. Αυτή η προστασία βοηθά στην αποφυγή απρόσεκτης εκτέλεσης δυνητικά επικίνδυνου εκτελέσιμου κώδικα που ο χρήστης μπορεί να είχε παρερμηνεύσει ως ένα αβλαβές αρχείο δεδομένων.

### Application Signatures

Application signatures, also known as code signatures, are a critical component of Apple's security infrastructure. They're used to **verify the identity of the software author** (the developer) and to ensure that the code hasn't been tampered with since it was last signed.

Here's how it works:

1. **Signing the Application:** When a developer is ready to distribute their application, they **sign the application using a private key**. This private key is associated with a **certificate that Apple issues to the developer** when they enrol in the Apple Developer Program. The signing process involves creating a cryptographic hash of all parts of the app and encrypting this hash with the developer's private key.
2. **Distributing the Application:** The signed application is then distributed to users along with the developer's certificate, which contains the corresponding public key.
3. **Verifying the Application:** When a user downloads and attempts to run the application, their Mac operating system uses the public key from the developer's certificate to decrypt the hash. It then recalculates the hash based on the current state of the application and compares this with the decrypted hash. If they match, it means **the application hasn't been modified** since the developer signed it, and the system permits the application to run.

Application signatures are an essential part of Apple's Gatekeeper technology. When a user attempts to **open an application downloaded from the internet**, Gatekeeper verifies the application signature. If it's signed with a certificate issued by Apple to a known developer and the code hasn't been tampered with, Gatekeeper permits the application to run. Otherwise, it blocks the application and alerts the user.

Starting from macOS Catalina, **Gatekeeper also checks whether the application has been notarized** by Apple, adding an extra layer of security. The notarization process checks the application for known security issues and malicious code, and if these checks pass, Apple adds a ticket to the application that Gatekeeper can verify.

#### Check Signatures

When checking some **malware sample** you should always **check the signature** of the binary as the **developer** that signed it may be already **related** with **malware.**
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
### Νοταριοποίηση

Η διαδικασία νοταριοποίησης της Apple λειτουργεί ως ένα επιπλέον μέτρο ασφαλείας για την προστασία των χρηστών από ενδεχομένως επιβλαβές λογισμικό. Περιλαμβάνει τον **προγραμματιστή που υποβάλλει την εφαρμογή του για έλεγχο** από την **Apple's Notary Service**, κάτι που δεν πρέπει να συγχέεται με το App Review. Αυτή η υπηρεσία είναι ένα **αυτοματοποιημένο σύστημα** που εξετάζει το υποβληθέν λογισμικό για την παρουσία **κακόβουλου περιεχομένου** και τυχόν προβλήματα με το code-signing.

Εάν το λογισμικό **περάσει** αυτόν τον έλεγχο χωρίς να προκύψουν ανησυχίες, το Notary Service δημιουργεί ένα notarization ticket. Ο προγραμματιστής στη συνέχεια πρέπει να **επισυνάψει αυτό το εισητήριο στο λογισμικό του**, μια διαδικασία γνωστή ως 'stapling'. Επιπλέον, το notarization ticket δημοσιεύεται επίσης στο διαδίκτυο, όπου το Gatekeeper, η τεχνολογία ασφαλείας της Apple, μπορεί να έχει πρόσβαση.

Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του notarization ticket — είτε 'stapled' στο εκτελέσιμο είτε διαθέσιμο στο διαδίκτυο — **ενημερώνει το Gatekeeper ότι το λογισμικό έχει νοταριοποιηθεί από την Apple**. Ως αποτέλεσμα, το Gatekeeper εμφανίζει ένα περιγραφικό μήνυμα στο αρχικό παράθυρο εκκίνησης, υποδεικνύοντας ότι το λογισμικό έχει υποβληθεί σε ελέγχους για κακόβουλο περιεχόμενο από την Apple. Αυτή η διαδικασία ενισχύει έτσι την εμπιστοσύνη του χρήστη στην ασφάλεια του λογισμικού που εγκαθιστά ή εκτελεί στο σύστημά του.

### spctl & syspolicyd

> [!CAUTION]
> Σημειώστε ότι από την έκδοση Sequoia, **`spctl`** δεν επιτρέπει πλέον την τροποποίηση της διαμόρφωσης του Gatekeeper.

**`spctl`** είναι το CLI εργαλείο για την απαρίθμηση και την αλληλεπίδραση με το Gatekeeper (με το daemon `syspolicyd` μέσω μηνυμάτων XPC). Για παράδειγμα, είναι δυνατό να δείτε την **κατάσταση** του GateKeeper με:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Σημειώστε ότι οι έλεγχοι υπογραφής του GateKeeper εκτελούνται μόνο σε **files with the Quarantine attribute**, όχι σε κάθε αρχείο.

GateKeeper will check if according to the **προτιμήσεις & την υπογραφή** ένα binary μπορεί να εκτελεστεί:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** είναι το κύριο daemon υπεύθυνο για την επιβολή του Gatekeeper. Διατηρεί μια βάση δεδομένων στο `/var/db/SystemPolicy` και είναι δυνατό να βρείτε τον κώδικα που την υποστηρίζει στη [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) και το [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Σημειώστε ότι η βάση δεδομένων δεν περιορίζεται από το SIP και είναι εγγράψιμη από root και η βάση `/var/db/.SystemPolicy-default` χρησιμοποιείται ως αρχικό αντίγραφο ασφαλείας σε περίπτωση που η άλλη καταστραφεί.

Επιπλέον, τα bundles **`/var/db/gke.bundle`** και **`/var/db/gkopaque.bundle`** περιέχουν αρχεία με κανόνες που εισάγονται στη βάση δεδομένων. Μπορείτε να ελέγξετε αυτή τη βάση δεδομένων ως root με:
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
**`syspolicyd`** εκθέτει επίσης έναν XPC server με διαφορετικές ενέργειες όπως `assess`, `update`, `record` και `cancel` που είναι επίσης προσβάσιμες μέσω των **`Security.framework`'s `SecAssessment*`** APIs και το **`spctl`** στην πραγματικότητα μιλάει στο **`syspolicyd`** μέσω XPC.

Σημειώστε πώς ο πρώτος κανόνας τελείωνε σε "**App Store**" και ο δεύτερος σε "**Developer ID**" και ότι στην προηγούμενη εικόνα ήταν **ενεργοποιημένο ώστε να εκτελεί εφαρμογές από το App Store και από αναγνωρισμένους προγραμματιστές**.\
Αν **τροποποιήσετε** αυτή τη ρύθμιση σε App Store, οι **κανόνες "Notarized Developer ID" θα εξαφανιστούν**.

Υπάρχουν επίσης χιλιάδες κανόνες **τύπου GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Αυτά είναι hashes που προέρχονται από:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Εναλλακτικά, μπορείτε να απαριθμήσετε τις προηγούμενες πληροφορίες με:
```bash
sudo spctl --list
```
Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα **disable** εντελώς αυτούς τους ελέγχους υπογραφών:
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

Μπορείτε να **ελέγξετε αν μια App θα επιτραπεί από το GateKeeper** με:
```bash
spctl --assess -v /Applications/App.app
```
Είναι δυνατό να προστεθούν νέοι κανόνες στο GateKeeper για να επιτραπεί η εκτέλεση ορισμένων εφαρμογών με:
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
Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### Διαχείριση Gatekeeper στο macOS 15 (Sequoia) και μεταγενέστερα

- Η μακροχρόνια παράκαμψη του Finder **Ctrl+Open / Right‑click → Open** έχει αφαιρεθεί· οι χρήστες πρέπει να επιτρέψουν ρητά μια αποκλεισμένη εφαρμογή από **System Settings → Privacy & Security → Open Anyway** μετά τον πρώτο διάλογο αποκλεισμού.
- Τα `spctl --master-disable/--global-disable` δεν γίνονται πλέον αποδεκτά· το `spctl` είναι ουσιαστικά μόνο για ανάγνωση για την αξιολόγηση και τη διαχείριση ετικετών, ενώ η επιβολή πολιτικής ρυθμίζεται μέσω UI ή MDM.

Ξεκινώντας από το macOS 15 Sequoia, οι τελικοί χρήστες δεν μπορούν πλέον να αλλάζουν την πολιτική του Gatekeeper από το `spctl`. Η διαχείριση γίνεται μέσω System Settings ή με ανάπτυξη ενός MDM configuration profile με το payload `com.apple.systempolicy.control`. Παράδειγμα αποσπάσματος profile για να επιτρέπεται το App Store και identified developers (αλλά όχι "Anywhere"):

<details>
<summary>MDM profile για να επιτρέπει το App Store και identified developers</summary>
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

### Αρχεία Καραντίνας

Κατά το **κατέβασμα** μιας εφαρμογής ή αρχείου, ορισμένες macOS **εφαρμογές**, όπως web browsers ή email clients, **προσθέτουν ένα επεκταμένο χαρακτηριστικό αρχείου**, γνωστό κοινώς ως "**quarantine flag**", στο ληφθέν αρχείο. Αυτό το χαρακτηριστικό λειτουργεί ως μέτρο ασφαλείας για να **σημειώσει το αρχείο** ότι προέρχεται από μη αξιόπιστη πηγή (το internet) και ενδέχεται να εμπεριέχει κινδύνους. Ωστόσο, όχι όλες οι εφαρμογές προσθέτουν αυτό το χαρακτηριστικό — για παράδειγμα, κοινά BitTorrent client προγράμματα συνήθως παρακάμπτουν αυτή τη διαδικασία.

**Η παρουσία του quarantine flag ειδοποιεί τη λειτουργία ασφαλείας Gatekeeper του macOS όταν ο χρήστης προσπαθεί να εκτελέσει το αρχείο.**

Σε περίπτωση που το **quarantine flag δεν υπάρχει** (όπως συμβαίνει με αρχεία που έχουν ληφθεί μέσω ορισμένων BitTorrent clients), οι **έλεγχοι του Gatekeeper μπορεί να μη γίνουν**. Συνεπώς, οι χρήστες θα πρέπει να είναι προσεκτικοί όταν ανοίγουν αρχεία που έχουν ληφθεί από λιγότερο ασφαλείς ή άγνωστες πηγές.

> [!NOTE] > **Ο έλεγχος** της **ισχύος** των υπογραφών κώδικα είναι μια **δυσβάσταχτη** διαδικασία που περιλαμβάνει τη δημιουργία κρυπτογραφικών **hashes** του κώδικα και όλων των συσκευασμένων πόρων του. Επιπλέον, ο έλεγχος της εγκυρότητας του πιστοποιητικού περιλαμβάνει έναν **online έλεγχο** προς τους servers της Apple για να διαπιστωθεί αν έχει ανακληθεί μετά την έκδοσή του. Για αυτούς τους λόγους, ένας πλήρης έλεγχος υπογραφής κώδικα και notarization είναι **ανέφικτο να εκτελείται κάθε φορά που ξεκινά μια εφαρμογή**.
>
> Επομένως, αυτοί οι έλεγχοι **εκτελούνται μόνο όταν εκτελούνται εφαρμογές που έχουν το χαρακτηριστικό quarantine.**

> [!WARNING]
> Αυτό το χαρακτηριστικό πρέπει να **ορίζεται από την εφαρμογή που δημιουργεί/κατεβάζει** το αρχείο.
>
> Ωστόσο, αρχεία που είναι sandboxed θα έχουν αυτό το χαρακτηριστικό για κάθε αρχείο που δημιουργούν. Και εφαρμογές που δεν είναι sandboxed μπορούν να το ορίσουν μόνες τους, ή να καθορίσουν το κλειδί [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) στο **Info.plist**, το οποίο θα κάνει το σύστημα να θέτει το επεκταμένο χαρακτηριστικό `com.apple.quarantine` στα αρχεία που δημιουργούνται.

Επιπλέον, όλα τα αρχεία που δημιουργούνται από μια διεργασία που καλεί την **`qtn_proc_apply_to_self`** είναι σε καραντίνα. Ή το API **`qtn_file_apply_to_path`** προσθέτει το χαρακτηριστικό καραντίνας σε μια καθορισμένη διαδρομή αρχείου.

Είναι δυνατόν να **ελεγχθεί η κατάστασή του και να ενεργοποιηθεί/απενεργοποιηθεί** (απαιτείται root) με:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Μπορείτε επίσης να **ελέγξετε αν ένα αρχείο έχει το quarantine extended attribute** με:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Ελέγξτε την **τιμή** των **επεκταμένων** **χαρακτηριστικών** και βρείτε την εφαρμογή που έγραψε την quarantine attr με:
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
Στην πραγματικότητα μια διεργασία "μπορεί να ορίσει σημαίες καραντίνας στα αρχεία που δημιουργεί" (Προσπάθησα ήδη να εφαρμόσω τη σημαία USER_APPROVED σε ένα δημιουργημένο αρχείο αλλά δεν εφαρμόζεται):

<details>

<summary>Πηγαίος κώδικας — εφαρμογή σημαίων καραντίνας</summary>
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

Και **αφαίρεσε** αυτήν την ιδιότητα με:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Και βρες όλα τα αρχεία σε καραντίνα με:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

This library exports several functions that allow to manipulate the extended attribute fields.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

This Kext will hook via MACF several calls in order to traps all file lifecycle events: Creation, opening, renaming, hard-linkning... even `setxattr` to prevent it from setting the `com.apple.quarantine` extended attribute.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura introduced a separate provenance mechanism which is populated the first time a quarantined app is allowed to run. Two artefacts are created:

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

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

Το XProtect είναι μια ενσωματωμένη δυνατότητα **anti-malware** στο macOS. Το XProtect **ελέγχει κάθε εφαρμογή όταν ξεκινάει για πρώτη φορά ή όταν τροποποιείται σε σχέση με τη βάση δεδομένων του** γνωστών malware και μη ασφαλών τύπων αρχείων. Όταν κάνετε λήψη αρχείου μέσω συγκεκριμένων εφαρμογών, όπως Safari, Mail ή Messages, το XProtect σαρώνει αυτόματα το αρχείο. Εάν ταιριάζει με κάποιο γνωστό malware στη βάση δεδομένων του, το XProtect θα **αποτρέψει την εκτέλεση του αρχείου** και θα σας ειδοποιήσει για την απειλή.

Η βάση δεδομένων του XProtect **ενημερώνεται τακτικά** από την Apple με νέους ορισμούς malware, και αυτές οι ενημερώσεις κατεβαίνουν και εγκαθίστανται αυτόματα στον Mac σας. Αυτό εξασφαλίζει ότι το XProtect είναι πάντα ενημερωμένο με τις πιο πρόσφατες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι το XProtect **δεν είναι μια πλήρης antivirus λύση**. Ελέγχει μόνο μια συγκεκριμένη λίστα γνωστών απειλών και δεν εκτελεί on-access scanning όπως τα περισσότερα antivirus προγράμματα.

Μπορείτε να λάβετε πληροφορίες για την πιο πρόσφατη ενημέρωση του XProtect τρέχοντας:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect βρίσκεται σε προστατευμένη από SIP τοποθεσία στο **/Library/Apple/System/Library/CoreServices/XProtect.bundle** και μέσα στο bundle μπορείτε να βρείτε πληροφορίες που χρησιμοποιεί το XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει σε κώδικα με αυτά τα cdhashes να χρησιμοποιεί legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα plugins και extensions που απαγορεύεται να φορτωθούν μέσω BundleID και TeamID ή που υποδεικνύει ελάχιστη έκδοση.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Κανόνες Yara για την ανίχνευση malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση SQLite3 με hashes μπλοκαρισμένων εφαρμογών και TeamIDs.

Σημειώστε ότι υπάρχει μια άλλη εφαρμογή στο **`/Library/Apple/System/Library/CoreServices/XProtect.app`** σχετιζόμενη με το XProtect που δεν εμπλέκεται στη διαδικασία του Gatekeeper.

> XProtect Remediator: Σε σύγχρονο macOS, η Apple παρέχει on-demand scanners (XProtect Remediator) που εκτελούνται περιοδικά μέσω launchd για να εντοπίσουν και να αποκαταστήσουν οικογένειες malware. Μπορείτε να παρατηρήσετε αυτές τις σαρώσεις στα unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Δεν είναι Gatekeeper

> [!CAUTION]
> Σημειώστε ότι ο Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή — μόνο το _**AppleMobileFileIntegrity**_ (AMFI) θα **επαληθεύει τις υπογραφές εκτελέσιμου κώδικα** όταν εκτελείτε μια εφαρμογή που έχει ήδη εκτελεστεί και επαληθευτεί από τον Gatekeeper.

Συνεπώς, παλαιότερα ήταν δυνατό να εκτελέσετε μια εφαρμογή για να την cache-άρετε με τον Gatekeeper, και μετά να **τροποποιήσετε μη-εκτελέσιμα αρχεία της εφαρμογής** (όπως Electron asar ή αρχεία NIB) και αν δεν υπήρχαν άλλες προστασίες, η εφαρμογή θα **εκτελούνταν** με τις **κακόβουλες** προσθήκες.

Ωστόσο, τώρα αυτό δεν είναι δυνατό επειδή το macOS **αποτρέπει την τροποποίηση αρχείων** μέσα σε bundles εφαρμογών. Έτσι, αν δοκιμάσετε την επίθεση [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), θα διαπιστώσετε ότι δεν είναι πλέον δυνατό να την καταχραστείτε γιατί μετά την εκτέλεση της εφαρμογής για να την cache-άρετε με τον Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το bundle. Και αν αλλάξετε, για παράδειγμα, το όνομα του φακέλου Contents σε NotCon (όπως υποδεικνύεται στο exploit), και στη συνέχεια εκτελέσετε το κύριο δυαδικό της εφαρμογής για να το cache-άρετε με τον Gatekeeper, θα προκαλέσει σφάλμα και δεν θα εκτελεστεί.

## Gatekeeper Bypasses

Οποιοσδήποτε τρόπος παράκαμψης του Gatekeeper (κατάφερνε να κάνει τον χρήστη να κατεβάσει κάτι και να το εκτελέσει όταν ο Gatekeeper θα έπρεπε να το απαγορεύσει) θεωρείται ευπάθεια στο macOS. Ακολουθούν μερικά CVE που αποδόθηκαν σε τεχνικές που επέτρεψαν την παράκαμψη του Gatekeeper στο παρελθόν:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι αν χρησιμοποιηθεί το **Archive Utility** για εξαγωγή, αρχεία με **διαδρομές που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το extended attribute com.apple.quarantine. Αυτή η κατάσταση επιτρέπει άθελά τους σε αυτά τα αρχεία να **παρακάμψουν τους ελέγχους ασφάλειας του Gatekeeper**.

Δείτε την [**πρωτότυπη αναφορά**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) για περισσότερες πληροφορίες.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν μια εφαρμογή δημιουργείται με **Automator**, οι πληροφορίες για το τι χρειάζεται να εκτελέσει βρίσκονται μέσα στο `application.app/Contents/document.wflow` και όχι στο εκτελέσιμο. Το εκτελέσιμο είναι απλώς ένα γενικό δυαδικό Automator που ονομάζεται **Automator Application Stub**.

Επομένως, μπορούσατε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` να **δείχνει με symbolic link σε άλλο Automator Application Stub μέσα στο σύστημα** και αυτό θα εκτελούσε ό,τι υπάρχει μέσα στο `document.wflow` (το script σας) **χωρίς να ενεργοποιήσει τον Gatekeeper** επειδή το πραγματικό εκτελέσιμο δεν έχει το quarantine xattr.

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Δείτε την [**πρωτότυπη αναφορά**](https://ronmasas.com/posts/bypass-macos-gatekeeper) για περισσότερες πληροφορίες.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτή την παράκαμψη δημιουργήθηκε ένα zip αρχείο όπου η συμπίεση της εφαρμογής ξεκινούσε από το `application.app/Contents` αντί για το `application.app`. Επομένως, το **quarantine attr** εφαρμόστηκε σε όλα τα **αρχεία από το `application.app/Contents`** αλλά **όχι στο `application.app`**, το οποίο ελέγχε ο Gatekeeper, οπότε ο Gatekeeper παρακάμφθηκε επειδή όταν ενεργοποιήθηκε το `application.app` **δεν είχε το quarantine attribute.**
```bash
zip -r test.app/Contents test.zip
```
Ελέγξτε το [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Ακόμα κι αν τα συστατικά είναι διαφορετικά, η εκμετάλλευση αυτής της ευπάθειας είναι πολύ παρόμοια με την προηγούμενη. Σε αυτή την περίπτωση θα δημιουργήσουμε ένα Apple Archive από **`application.app/Contents`**, οπότε **`application.app` won't get the quarantine attr** όταν αποσυμπιεστεί από **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) for more information.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Η ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να εμποδίσει οποιονδήποτε να γράψει μια ιδιότητα σε ένα αρχείο:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Επιπλέον, η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο συμπεριλαμβανομένων των ACEs.

Στον [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) μπορεί κανείς να δει ότι η αναπαράσταση κειμένου της ACL που αποθηκεύεται στο xattr με όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπιέσατε μια εφαρμογή σε ένα zip αρχείο με τη μορφή αρχείου **AppleDouble** με μια ACL που αποτρέπει άλλα xattr από το να εγγραφούν σε αυτή... το quarantine xattr δεν ορίστηκε στην εφαρμογή:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Δείτε το [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Σημειώστε ότι αυτό θα μπορούσε επίσης να εκμεταλλευτεί με AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Διαπιστώθηκε ότι **Google Chrome wasn't setting the quarantine attribute** στα ληφθέντα αρχεία λόγω κάποιων εσωτερικών προβλημάτων του macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Οι μορφές αρχείων AppleDouble αποθηκεύουν τα χαρακτηριστικά ενός αρχείου σε ξεχωριστό αρχείο που αρχίζει με `._`, αυτό βοηθά στην αντιγραφή των χαρακτηριστικών αρχείων **across macOS machines**. Ωστόσο, παρατηρήθηκε ότι μετά την αποσυμπίεση ενός αρχείου AppleDouble, το αρχείο που αρχίζει με `._` **wasn't given the quarantine attribute**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Η δυνατότητα να δημιουργήσεις ένα αρχείο που δεν θα έχει ορισμένο το quarantine attribute έκανε **possible to bypass Gatekeeper.** Το κόλπο ήταν να **create a DMG file application** χρησιμοποιώντας την AppleDouble name convention (start it with `._`) και να δημιουργήσεις ένα **visible file as a sym link to this hidden** αρχείο χωρίς το quarantine attribute.\
Όταν το **dmg file is executed**, επειδή δεν έχει quarantine attribute, θα **bypass Gatekeeper**.
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

Μια παράκαμψη του Gatekeeper που διορθώθηκε στο macOS Sonoma 14.0 επέτρεπε σε κατασκευασμένες εφαρμογές να εκτελεστούν χωρίς εμφάνιση προτροπής. Οι λεπτομέρειες αποκαλύφθηκαν δημόσια μετά την επιδιόρθωση και το πρόβλημα εκμεταλλεύτηκε ενεργά στο φυσικό περιβάλλον πριν τη διόρθωση. Βεβαιωθείτε ότι έχετε εγκατεστημένο το Sonoma 14.0 ή νεότερο.

### [CVE-2024-27853]

Μια παράκαμψη του Gatekeeper στο macOS 14.4 (κυκλοφόρησε Μάρτιος 2024) που προέκυψε από τον τρόπο που το `libarchive` χειρίζεται κακόβουλα ZIPs επέτρεπε σε εφαρμογές να αποφύγουν την αξιολόγηση. Αναβαθμίστε σε 14.4 ή νεότερο όπου η Apple διόρθωσε το ζήτημα.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Μια **Automator Quick Action workflow** ενσωματωμένη σε μια ληφθείσα εφαρμογή θα μπορούσε να ενεργοποιηθεί χωρίς αξιολόγηση από τον Gatekeeper, επειδή οι workflows αντιμετωπίζονταν ως δεδομένα και εκτελούνταν από το Automator helper εκτός της κανονικής ροής του notarization prompt. Μια κατασκευασμένη `.app` που πακετάρει ένα Quick Action που εκτελεί ένα shell script (π.χ. μέσα στο `Contents/PlugIns/*.workflow/Contents/document.wflow`) μπορούσε έτσι να εκτελεστεί αμέσως κατά την εκκίνηση. Η Apple πρόσθεσε ένα επιπλέον διάλογο συγκατάθεσης και διόρθωσε τη ροή αξιολόγησης σε Ventura **13.7**, Sonoma **14.7**, και Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Πολλές ευπάθειες σε δημοφιλή εργαλεία εξαγωγής (π.χ., The Unarchiver) προκάλεσαν ώστε τα αρχεία που εξάγονται από αρχεία να μην αποκτούν το `com.apple.quarantine` xattr, δίνοντας ευκαιρίες παράκαμψης του Gatekeeper. Εμπιστευτείτε πάντα το macOS Archive Utility ή εργαλεία με διορθώσεις όταν δοκιμάζετε, και επαληθεύετε τα xattrs μετά την εξαγωγή.

### uchg (από αυτή την [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Δημιουργήστε έναν φάκελο που περιέχει ένα app.
- Προσθέστε το uchg στο app.
- Συμπιέστε το app σε αρχείο tar.gz.
- Στείλτε το αρχείο tar.gz σε ένα θύμα.
- Το θύμα ανοίγει το tar.gz και τρέχει το app.
- Ο Gatekeeper δεν ελέγχει το app.

### Αποτροπή quarantine xattr

Σε ένα bundle ".app", εάν το quarantine xattr δεν προστεθεί σε αυτό, κατά την εκτέλεσή του ο **Gatekeeper δεν θα ενεργοποιηθεί**.


## Αναφορές

- Apple Platform Security: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.4 (περιλαμβάνει CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Πώς το macOS τώρα παρακολουθεί την προέλευση των εφαρμογών – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
