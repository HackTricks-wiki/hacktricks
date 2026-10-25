# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

Το **Gatekeeper** είναι μια λειτουργία ασφαλείας που αναπτύχθηκε για τα λειτουργικά συστήματα Mac και έχει σχεδιαστεί για να διασφαλίζει ότι οι χρήστες **εκτελούν μόνο αξιόπιστο λογισμικό** στα συστήματά τους. Λειτουργεί **επικυρώνοντας το λογισμικό** που κατεβάζει και προσπαθεί να ανοίξει ένας χρήστης από **πηγές εκτός του App Store**, όπως μια εφαρμογή, ένα plug-in ή ένα πακέτο εγκατάστασης.

Ο βασικός μηχανισμός του Gatekeeper είναι η διαδικασία **επαλήθευσης**. Ελέγχει αν το λογισμικό που κατέβηκε είναι **υπογεγραμμένο από αναγνωρισμένο developer**, διασφαλίζοντας την αυθεντικότητά του. Επιπλέον, εξακριβώνει αν το λογισμικό έχει **επικυρωθεί από την Apple**, επιβεβαιώνοντας ότι δεν περιέχει γνωστό κακόβουλο περιεχόμενο και ότι δεν έχει αλλοιωθεί μετά την επικύρωσή του.

Επιπλέον, το Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια του χρήστη **ζητώντας από τους χρήστες να εγκρίνουν το άνοιγμα** του λογισμικού που κατέβασαν την πρώτη φορά. Αυτή η δικλείδα ασφαλείας βοηθά να αποτραπεί η ακούσια εκτέλεση δυνητικά επιβλαβούς εκτελέσιμου κώδικα, τον οποίο οι χρήστες μπορεί να εκλάβουν λανθασμένα ως ακίνδυνο αρχείο δεδομένων.

### Υπογραφές εφαρμογών

Οι υπογραφές εφαρμογών, γνωστές και ως υπογραφές κώδικα, αποτελούν κρίσιμο στοιχείο της υποδομής ασφαλείας της Apple. Χρησιμοποιούνται για **την επαλήθευση της ταυτότητας του δημιουργού του λογισμικού** (του developer) και για να διασφαλιστεί ότι ο κώδικας δεν έχει αλλοιωθεί από την τελευταία φορά που υπογράφηκε.

Δείτε πώς λειτουργεί:

1. **Υπογραφή της εφαρμογής:** Όταν ένας developer είναι έτοιμος να διανείμει την εφαρμογή του, **την υπογράφει χρησιμοποιώντας ένα ιδιωτικό κλειδί**. Αυτό το ιδιωτικό κλειδί σχετίζεται με ένα **πιστοποιητικό που εκδίδει η Apple στον developer** όταν εγγράφεται στο Apple Developer Program. Η διαδικασία υπογραφής περιλαμβάνει τη δημιουργία ενός κρυπτογραφικού hash για όλα τα μέρη της εφαρμογής και την κρυπτογράφηση αυτού του hash με το ιδιωτικό κλειδί του developer.
2. **Διανομή της εφαρμογής:** Στη συνέχεια, η υπογεγραμμένη εφαρμογή διανέμεται στους χρήστες μαζί με το πιστοποιητικό του developer, το οποίο περιέχει το αντίστοιχο δημόσιο κλειδί.
3. **Επαλήθευση της εφαρμογής:** Όταν ένας χρήστης κατεβάζει και προσπαθεί να εκτελέσει την εφαρμογή, το λειτουργικό σύστημα του Mac χρησιμοποιεί το δημόσιο κλειδί από το πιστοποιητικό του developer για να αποκρυπτογραφήσει το hash. Έπειτα, υπολογίζει ξανά το hash με βάση την τρέχουσα κατάσταση της εφαρμογής και το συγκρίνει με το αποκρυπτογραφημένο hash. Αν ταιριάζουν, αυτό σημαίνει ότι **η εφαρμογή δεν έχει τροποποιηθεί** από τότε που την υπέγραψε ο developer και το σύστημα επιτρέπει την εκτέλεσή της.

Οι υπογραφές εφαρμογών αποτελούν ουσιώδες μέρος της τεχνολογίας Gatekeeper της Apple. Όταν ένας χρήστης προσπαθεί να **ανοίξει μια εφαρμογή που κατέβασε από το διαδίκτυο**, το Gatekeeper επαληθεύει την υπογραφή της. Αν έχει υπογραφεί με πιστοποιητικό που έχει εκδώσει η Apple σε γνωστό developer και ο κώδικας δεν έχει αλλοιωθεί, το Gatekeeper επιτρέπει την εκτέλεσή της. Διαφορετικά, αποκλείει την εφαρμογή και ειδοποιεί τον χρήστη.

Από το macOS Catalina και μετά, **το Gatekeeper ελέγχει επίσης αν η εφαρμογή έχει επικυρωθεί από την Apple**, προσθέτοντας ένα επιπλέον επίπεδο ασφαλείας. Η διαδικασία επικύρωσης ελέγχει την εφαρμογή για γνωστά ζητήματα ασφαλείας και κακόβουλο κώδικα. Αν περάσει αυτούς τους ελέγχους, η Apple προσθέτει στην εφαρμογή ένα ticket, το οποίο μπορεί να επαληθεύσει το Gatekeeper.

#### Έλεγχος υπογραφών

Όταν εξετάζετε ένα **δείγμα malware**, θα πρέπει πάντα να **ελέγχετε την υπογραφή** του binary, καθώς ο **developer** που το υπέγραψε μπορεί να **σχετίζεται** ήδη με **malware**.

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

### Συμβολαιογραφική επικύρωση

Η διαδικασία συμβολαιογραφικής επικύρωσης της Apple λειτουργεί ως πρόσθετη δικλίδα ασφαλείας για την προστασία των χρηστών από δυνητικά επιβλαβές λογισμικό. Περιλαμβάνει την **υποβολή της εφαρμογής από τον developer για έλεγχο** από την **Υπηρεσία Συμβολαιογραφικής Επικύρωσης της Apple**, η οποία δεν πρέπει να συγχέεται με το App Review. Η υπηρεσία αυτή είναι ένα **αυτοματοποιημένο σύστημα** που εξετάζει το υποβληθέν λογισμικό για την παρουσία **κακόβουλου περιεχομένου** και τυχόν προβλήματα με την υπογραφή κώδικα.

Αν το λογισμικό **περάσει** αυτόν τον έλεγχο χωρίς να εντοπιστούν προβλήματα, η Υπηρεσία Συμβολαιογραφικής Επικύρωσης δημιουργεί ένα ticket επικύρωσης. Στη συνέχεια, ο developer πρέπει να **επισυνάψει αυτό το ticket στο λογισμικό του**, σε μια διαδικασία γνωστή ως «stapling». Επιπλέον, το ticket επικύρωσης δημοσιεύεται και online, όπου μπορεί να έχει πρόσβαση το Gatekeeper, η τεχνολογία ασφάλειας της Apple.

Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του ticket επικύρωσης —είτε είναι stapled στο εκτελέσιμο αρχείο είτε βρίσκεται online— **ενημερώνει το Gatekeeper ότι το λογισμικό έχει λάβει συμβολαιογραφική επικύρωση από την Apple**. Ως αποτέλεσμα, το Gatekeeper εμφανίζει ένα επεξηγηματικό μήνυμα στο παράθυρο διαλόγου της αρχικής εκκίνησης, το οποίο υποδεικνύει ότι η Apple έχει ελέγξει το λογισμικό για κακόβουλο περιεχόμενο. Έτσι, η διαδικασία ενισχύει την εμπιστοσύνη των χρηστών στην ασφάλεια του λογισμικού που εγκαθιστούν ή εκτελούν στα συστήματά τους.

### spctl & syspolicyd

> [!CAUTION]
> Σημειώστε ότι από την έκδοση Sequoia, το **`spctl`** δεν επιτρέπει πλέον την τροποποίηση της διαμόρφωσης του Gatekeeper.

Το **`spctl`** είναι το εργαλείο CLI για την απαρίθμηση και την αλληλεπίδραση με το Gatekeeper (με τον daemon `syspolicyd` μέσω μηνυμάτων XPC). Για παράδειγμα, είναι δυνατό να δείτε την **κατάσταση** του GateKeeper με:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Σημειώστε ότι οι έλεγχοι υπογραφής του GateKeeper πραγματοποιούνται μόνο σε **αρχεία με το χαρακτηριστικό Quarantine**, όχι σε όλα τα αρχεία.

Το GateKeeper ελέγχει αν, σύμφωνα με τις **προτιμήσεις και την υπογραφή**, μπορεί να εκτελεστεί ένα binary:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

Το **`syspolicyd`** είναι ο κύριος daemon που είναι υπεύθυνος για την επιβολή του Gatekeeper. Διατηρεί μια βάση δεδομένων στη θέση `/var/db/SystemPolicy` και μπορείτε να βρείτε τον κώδικα που υποστηρίζει τη [βάση δεδομένων εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) και το [πρότυπο SQL εδώ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Σημειώστε ότι η βάση δεδομένων δεν υπόκειται σε περιορισμούς από το SIP και είναι εγγράψιμη από τον root, ενώ η βάση δεδομένων `/var/db/.SystemPolicy-default` χρησιμοποιείται ως αρχικό αντίγραφο ασφαλείας, σε περίπτωση που η άλλη καταστραφεί.

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

**Το `syspolicyd`** εκθέτει επίσης έναν XPC server με διαφορετικές λειτουργίες, όπως `assess`, `update`, `record` και `cancel`, οι οποίες είναι επίσης προσβάσιμες μέσω των API **`SecAssessment*` του `Security.framework`**. Το **`spctl`** επικοινωνεί στην πραγματικότητα με το **`syspolicyd`** μέσω XPC.

Σημειώστε ότι ο πρώτος κανόνας τελείωνε σε «**App Store**» και ο δεύτερος σε «**Developer ID**», ενώ στην προηγούμενη εικόνα ήταν **ενεργοποιημένη η εκτέλεση εφαρμογών από το App Store και από αναγνωρισμένους developers**.\
Αν **τροποποιήσετε** αυτήν τη ρύθμιση σε App Store, οι κανόνες «**Notarized Developer ID**» θα εξαφανιστούν.

Υπάρχουν επίσης χιλιάδες κανόνες **τύπου GKE** :

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

Ή μπορείτε να παραθέσετε τις προηγούμενες πληροφορίες με:

```bash
sudo spctl --list
```

Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα **απενεργοποιήσουν** πλήρως αυτούς τους ελέγχους υπογραφής:

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

Μπορείτε να **ελέγξετε αν μια εφαρμογή θα επιτραπεί από το GateKeeper** με:

```bash
spctl --assess -v /Applications/App.app
```

Στο macOS 14 και νεότερες εκδόσεις, το **`syspolicy_check`** είναι ένας χρήσιμος έλεγχος υψηλότερου επιπέδου πριν από τη διανομή ενός bundle εφαρμογής. Παρέχει πιο αξιοποιήσιμα διαγνωστικά για την αξιόπιστη εκτέλεση από ένα απλό αποτέλεσμα του `spctl`, αν και η Apple εξακολουθεί να συνιστά τη δοκιμή της πραγματικής διαδικασίας λήψης/αποσυμπίεσης/πρώτης εκκίνησης, επειδή έτσι ελέγχεται και η διάδοση του quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Είναι δυνατή η προσθήκη νέων κανόνων στο GateKeeper για να επιτρέπεται η εκτέλεση συγκεκριμένων εφαρμογών με:

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

Σχετικά με τις **επεκτάσεις πυρήνα**, ο φάκελος `/var/db/SystemPolicyConfiguration` περιέχει αρχεία με λίστες kext που επιτρέπεται να φορτωθούν. Επιπλέον, το `spctl` διαθέτει το entitlement `com.apple.private.iokit.nvram-csr`, επειδή μπορεί να προσθέτει νέες προεγκεκριμένες επεκτάσεις πυρήνα, οι οποίες πρέπει επίσης να αποθηκεύονται στο NVRAM με το κλειδί `kext-allowed-teams`.

#### Διαχείριση του Gatekeeper στο macOS 15 (Sequoia) και νεότερο

- Το παλιό παράκαμψης Finder **Ctrl+Open / Δεξί κλικ → Άνοιγμα** έχει καταργηθεί· οι χρήστες πρέπει να επιτρέψουν ρητά μια αποκλεισμένη εφαρμογή από τις **Ρυθμίσεις συστήματος → Απόρρητο και ασφάλεια → Άνοιγμα ούτως ή άλλως**, αφού εμφανιστεί για πρώτη φορά το παράθυρο αποκλεισμού.<sup>[[4]](#references)</sup>
- Οι εντολές `spctl --master-disable/--global-disable` δεν γίνονται πλέον αποδεκτές ως μη επιτηρούμενες αλλαγές πολιτικής. Οι ενέργειες που τροποποιούν τη βάση δεδομένων κανόνων ή την καθολική κατάσταση αξιολόγησης έχουν καταργηθεί· χρησιμοποιήστε το `spctl` για αξιολόγηση και ρυθμίστε την επιβολή μέσω του UI ή του MDM.

Από το macOS 15 Sequoia και μετά, οι τελικοί χρήστες δεν μπορούν πλέον να αλλάζουν την πολιτική του Gatekeeper μέσω του `spctl`. Η διαχείριση γίνεται μέσω των Ρυθμίσεων συστήματος ή με ανάπτυξη ενός προφίλ διαμόρφωσης MDM με το payload `com.apple.systempolicy.control`. Παράδειγμα αποσπάσματος προφίλ που επιτρέπει το App Store και τους αναγνωρισμένους προγραμματιστές (αλλά όχι την επιλογή «Οπουδήποτε»):

<details>
<summary>Προφίλ MDM για να επιτρέπεται το App Store και οι αναγνωρισμένοι προγραμματιστές</summary>

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

Κατά τη **λήψη** μιας εφαρμογής ή ενός αρχείου, συγκεκριμένες **εφαρμογές** του macOS, όπως τα προγράμματα περιήγησης ή οι εφαρμογές email, **επισυνάπτουν ένα εκτεταμένο χαρακτηριστικό αρχείου**, γνωστό συνήθως ως "**quarantine flag**", στο αρχείο που λήφθηκε. Αυτό το χαρακτηριστικό λειτουργεί ως μέτρο ασφαλείας για να **επισημάνει το αρχείο** ως προερχόμενο από μη έμπιστη πηγή (το διαδίκτυο) και ως πιθανώς επικίνδυνο. Ωστόσο, δεν επισυνάπτουν όλες οι εφαρμογές αυτό το χαρακτηριστικό· για παράδειγμα, τα συνήθη προγράμματα-πελάτες BitTorrent συνήθως παρακάμπτουν αυτήν τη διαδικασία.

**Η παρουσία ενός quarantine flag ειδοποιεί τη λειτουργία ασφαλείας Gatekeeper του macOS όταν ένας χρήστης επιχειρεί να εκτελέσει το αρχείο**.

Αν **δεν υπάρχει quarantine flag** (όπως συμβαίνει με αρχεία που λαμβάνονται μέσω ορισμένων προγραμμάτων-πελατών BitTorrent), οι **έλεγχοι** του Gatekeeper ενδέχεται **να μην εκτελεστούν**. Επομένως, οι χρήστες πρέπει να είναι προσεκτικοί όταν ανοίγουν αρχεία που έχουν ληφθεί από λιγότερο ασφαλείς ή άγνωστες πηγές.

> [!NOTE] > **Ο έλεγχος** της **εγκυρότητας** των υπογραφών κώδικα είναι μια διαδικασία που απαιτεί **πολλούς πόρους** και περιλαμβάνει τη δημιουργία κρυπτογραφικών **hashes** του κώδικα και όλων των πόρων που περιέχει. Επιπλέον, ο έλεγχος της εγκυρότητας του πιστοποιητικού περιλαμβάνει έναν **έλεγχο μέσω διαδικτύου** στους διακομιστές της Apple, για να διαπιστωθεί αν το πιστοποιητικό έχει ανακληθεί μετά την έκδοσή του. Για αυτούς τους λόγους, δεν είναι **πρακτικό να εκτελείται κάθε φορά που εκκινείται μια εφαρμογή** πλήρης έλεγχος υπογραφής κώδικα και notarization.
>
> Επομένως, αυτοί οι έλεγχοι **εκτελούνται μόνο κατά την εκτέλεση εφαρμογών με το χαρακτηριστικό quarantine**.

> [!WARNING]
> Αυτό το χαρακτηριστικό πρέπει να **οριστεί από την εφαρμογή που δημιουργεί/λαμβάνει** το αρχείο.
>
> Ωστόσο, τα αρχεία που δημιουργούνται από εφαρμογές σε sandbox θα έχουν αυτό το χαρακτηριστικό. Οι εφαρμογές που δεν βρίσκονται σε sandbox μπορούν να το ορίσουν οι ίδιες ή να καθορίσουν το κλειδί [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) στο **Info.plist**, ώστε το σύστημα να ορίσει το εκτεταμένο χαρακτηριστικό `com.apple.quarantine` στα αρχεία που δημιουργούνται.

Επιπλέον, όλα τα αρχεία που δημιουργούνται από μια διεργασία που καλεί τη **`qtn_proc_apply_to_self`** τίθενται σε quarantine. Εναλλακτικά, το API **`qtn_file_apply_to_path`** προσθέτει το χαρακτηριστικό quarantine σε μια καθορισμένη διαδρομή αρχείου.

Μπορείτε να **ελέγξετε την κατάστασή του και να το ενεργοποιήσετε/απενεργοποιήσετε** (απαιτούνται δικαιώματα root) με:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Μπορείτε επίσης να **διαπιστώσετε αν ένα αρχείο έχει το εκτεταμένο attribute quarantine** με:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Ελέγξτε την **τιμή** των **εκτεταμένων** **attributes** και εντοπίστε την εφαρμογή που έγραψε το quarantine attr με:

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

Στην πραγματικότητα, μια διεργασία «θα μπορούσε να ορίζει quarantine flags στα αρχεία που δημιουργεί» (δοκίμασα ήδη να εφαρμόσω το flag USER_APPROVED σε ένα αρχείο που δημιουργήθηκε, αλλά δεν εφαρμόζεται):

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

Και εντοπίστε όλα τα αρχεία που βρίσκονται σε καραντίνα με:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Οι πληροφορίες καραντίνας αποθηκεύονται επίσης σε μια κεντρική βάση δεδομένων, την οποία διαχειρίζεται το LaunchServices στο **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** και η οποία επιτρέπει στο GUI να λαμβάνει δεδομένα σχετικά με την προέλευση των αρχείων. Επιπλέον, οι εφαρμογές που ενδέχεται να θέλουν να αποκρύψουν την προέλευσή τους μπορούν να τις αντικαταστήσουν. Αυτό μπορεί επίσης να γίνει μέσω των APIs του LaunchServices.

#### **libquarantine.dylib**

Αυτή η βιβλιοθήκη εξάγει διάφορες συναρτήσεις που επιτρέπουν τον χειρισμό των πεδίων extended attribute.

Τα APIs `qtn_file_*` αφορούν τις πολιτικές καραντίνας αρχείων, ενώ τα APIs `qtn_proc_*` εφαρμόζονται σε διεργασίες (στα αρχεία που δημιουργεί η διεργασία). Οι μη εξαγόμενες συναρτήσεις `__qtn_syscall_quarantine*` εφαρμόζουν τις πολιτικές και καλούν το `mac_syscall` με πρώτο όρισμα το "Quarantine", στέλνοντας έτσι τα αιτήματα στο `Quarantine.kext`.

#### **Quarantine.kext**

Το kernel extension διατίθεται μόνο μέσω του **kernel cache στο σύστημα**. Ωστόσο, μπορείτε να κατεβάσετε το **Kernel Debug Kit από** [**https://developer.apple.com/**](https://developer.apple.com/), το οποίο περιλαμβάνει μια έκδοση του extension με σύμβολα.

Αυτό το Kext χρησιμοποιεί hooks μέσω του MACF σε διάφορες κλήσεις, ώστε να παγιδεύει όλα τα συμβάντα του κύκλου ζωής των αρχείων: δημιουργία, άνοιγμα, μετονομασία, δημιουργία hard link... ακόμη και το `setxattr`, ώστε να εμποδίζει τον ορισμό του extended attribute `com.apple.quarantine`.

Χρησιμοποιεί επίσης μερικά MIB:

- `security.mac.qtn.sandbox_enforce`: Επιβολή της καραντίνας μαζί με το Sandbox
- `security.mac.qtn.user_approved_exec`: Οι διεργασίες σε καραντίνα μπορούν να εκτελούν μόνο εγκεκριμένα αρχεία

#### Provenance xattr (Ventura και νεότερες εκδόσεις)

Το macOS 13 Ventura εισήγαγε έναν ξεχωριστό μηχανισμό provenance, ο οποίος συμπληρώνεται την πρώτη φορά που επιτρέπεται η εκτέλεση μιας εφαρμογής σε καραντίνα.<sup>[[2]](#references)</sup> Δημιουργούνται δύο τεχνουργήματα:

- Το xattr `com.apple.provenance` στον κατάλογο του bundle `.app` (δυαδική τιμή σταθερού μεγέθους που περιέχει ένα primary key και flags).
- Μια εγγραφή στον πίνακα `provenance_tracking` μέσα στη βάση δεδομένων ExecPolicy στο `/var/db/SystemPolicyConfiguration/ExecPolicy/`, η οποία αποθηκεύει το cdhash και τα metadata της εφαρμογής.

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

Το XProtect είναι μια ενσωματωμένη λειτουργία **anti-malware** στο macOS. Το XProtect **ελέγχει κάθε εφαρμογή κατά την πρώτη εκκίνησή της ή όταν τροποποιείται, συγκρίνοντάς την με τη βάση δεδομένων του** με γνωστό malware και μη ασφαλείς τύπους αρχείων. Όταν κατεβάζετε ένα αρχείο μέσω συγκεκριμένων εφαρμογών, όπως το Safari, το Mail ή τα Messages, το XProtect σαρώνει αυτόματα το αρχείο. Αν αντιστοιχεί σε κάποιο γνωστό malware στη βάση δεδομένων του, το XProtect **θα εμποδίσει την εκτέλεση του αρχείου** και θα σας ειδοποιήσει για την απειλή.

Η βάση δεδομένων του XProtect **ενημερώνεται τακτικά** από την Apple με νέους ορισμούς malware, και αυτές οι ενημερώσεις λαμβάνονται και εγκαθίστανται αυτόματα στο Mac σας. Έτσι, το XProtect παραμένει πάντα ενημερωμένο για τις πιο πρόσφατες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι **το XProtect δεν είναι μια ολοκληρωμένη λύση antivirus**. Ελέγχει μόνο μια συγκεκριμένη λίστα γνωστών απειλών και δεν πραγματοποιεί σάρωση κατά την πρόσβαση, όπως τα περισσότερα προγράμματα antivirus.

Μπορείτε να λάβετε πληροφορίες για την πιο πρόσφατη ενημέρωση του XProtect εκτελώντας:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

Το XProtect βρίσκεται σε προστατευμένη από το SIP τοποθεσία: **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Μέσα στο bundle μπορείτε να βρείτε πληροφορίες που χρησιμοποιεί το XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει σε κώδικα με αυτά τα cdhashes να χρησιμοποιεί legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα προσθέτων και επεκτάσεων που δεν επιτρέπεται να φορτωθούν, βάσει BundleID και TeamID, ή που πρέπει να έχουν μια ελάχιστη έκδοση.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Κανόνες Yara για τον εντοπισμό malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση δεδομένων SQLite3 με hashes αποκλεισμένων εφαρμογών και TeamIDs.

Σημειώστε ότι υπάρχει και μια άλλη εφαρμογή στο **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, η οποία σχετίζεται με το XProtect αλλά δεν συμμετέχει στη διαδικασία του Gatekeeper.

> XProtect Remediator: Στις σύγχρονες εκδόσεις του macOS, η Apple παρέχει σαρωτές κατ' απαίτηση (XProtect Remediator) που εκτελούνται περιοδικά μέσω του launchd για να εντοπίζουν και να αντιμετωπίζουν οικογένειες malware. Μπορείτε να παρατηρήσετε αυτές τις σαρώσεις στα unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Όχι Gatekeeper

> [!CAUTION]
> Σημειώστε ότι το Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή. Το _**AppleMobileFileIntegrity**_ (AMFI) απλώς **επαληθεύει τις υπογραφές του εκτελέσιμου κώδικα** όταν εκτελείτε μια εφαρμογή που έχει ήδη εκτελεστεί και επαληθευτεί από το Gatekeeper.

Επομένως, παλαιότερα ήταν δυνατό να εκτελέσετε μια εφαρμογή, ώστε να αποθηκευτεί στην cache του Gatekeeper, και έπειτα να **τροποποιήσετε μη εκτελέσιμα αρχεία της εφαρμογής** (όπως αρχεία Electron asar ή NIB). Αν δεν υπήρχαν άλλες προστασίες, η εφαρμογή **εκτελούνταν** με τις **κακόβουλες** προσθήκες.

Ωστόσο, αυτό δεν είναι πλέον δυνατό, επειδή το macOS **αποτρέπει την τροποποίηση αρχείων** μέσα στα bundles εφαρμογών. Επομένως, αν δοκιμάσετε την επίθεση [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), θα διαπιστώσετε ότι δεν μπορείτε πλέον να την καταχραστείτε, επειδή αφού εκτελέσετε την εφαρμογή ώστε να αποθηκευτεί στην cache του Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το bundle. Και αν, για παράδειγμα, αλλάξετε το όνομα του καταλόγου Contents σε NotCon (όπως υποδεικνύεται στο exploit) και έπειτα εκτελέσετε το κύριο binary της εφαρμογής ώστε να αποθηκευτεί στην cache του Gatekeeper, θα προκληθεί σφάλμα και δεν θα εκτελεστεί.

## Παρακάμψεις του Gatekeeper

Κάθε τρόπος παράκαμψης του Gatekeeper (να καταφέρετε να κατεβάσει ο χρήστης κάτι και να το εκτελέσει, ενώ το Gatekeeper θα έπρεπε να το εμποδίσει) θεωρείται ευπάθεια στο macOS. Ακολουθούν ορισμένα CVE που αποδόθηκαν σε τεχνικές οι οποίες επέτρεπαν την παράκαμψη του Gatekeeper στο παρελθόν:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι όταν χρησιμοποιείται το **Archive Utility** για αποσυμπίεση, τα αρχεία με **διαδρομές που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το extended attribute com.apple.quarantine. Αυτό επιτρέπει ακούσια σε αυτά τα αρχεία να **παρακάμπτουν** τους ελέγχους ασφαλείας του Gatekeeper.<sup>[[5]](#references)</sup>

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν δημιουργείται μια εφαρμογή με το **Automator**, οι πληροφορίες σχετικά με το τι πρέπει να εκτελέσει βρίσκονται στο `application.app/Contents/document.wflow` και όχι στο εκτελέσιμο αρχείο. Το εκτελέσιμο αρχείο είναι απλώς ένα γενικό binary του Automator με το όνομα **Automator Application Stub**.

Επομένως, θα μπορούσατε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` να **δείχνει με συμβολικό σύνδεσμο σε ένα άλλο Automator Application Stub μέσα στο σύστημα**, και έτσι θα εκτελούσε ό,τι περιέχεται στο `document.wflow` (το script σας) **χωρίς να ενεργοποιηθεί το Gatekeeper**, επειδή το πραγματικό εκτελέσιμο αρχείο δεν έχει το quarantine xattr.<sup>[[6]](#references)</sup>

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτήν την παράκαμψη, δημιουργήθηκε ένα zip αρχείο με μια εφαρμογή, ξεκινώντας τη συμπίεση από το `application.app/Contents` αντί από το `application.app`. Έτσι, το **quarantine attr** εφαρμόστηκε σε **όλα τα αρχεία του `application.app/Contents`**, αλλά **όχι στο `application.app`**, το οποίο έλεγχε το Gatekeeper. Συνεπώς, το Gatekeeper παρακάμφθηκε, επειδή όταν ενεργοποιήθηκε το `application.app`, **δεν είχε το quarantine attribute.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Δείτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Ακόμα κι αν τα components είναι διαφορετικά, το exploitation αυτής της ευπάθειας μοιάζει πολύ με το προηγούμενο. Σε αυτή την περίπτωση, θα δημιουργήσουμε ένα Apple Archive από το **`application.app/Contents`**, ώστε το **`application.app`** να μην αποκτήσει το quarantine attr κατά την αποσυμπίεση από το **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Δείτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) για περισσότερες πληροφορίες.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Το ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να εμποδίσει οποιονδήποτε να γράψει ένα attribute σε ένα αρχείο:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Επιπλέον, η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο μαζί με τα ACE του.<sup>[[9]](#references)</sup>

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) μπορούμε να δούμε ότι η αναπαράσταση κειμένου ACL που είναι αποθηκευμένη μέσα στο xattr με όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Επομένως, αν συμπιέσετε μια εφαρμογή σε αρχείο zip με τη μορφή **AppleDouble** και με ACL που εμποδίζει την εγγραφή άλλων xattr σε αυτήν... το xattr quarantine δεν ορίστηκε στην εφαρμογή:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.<sup>[[9]](#references)</sup> Δείτε την [αναπαραγωγή AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) για τα βήματα δημιουργίας και επικύρωσης του sidecar.

Σημειώστε ότι θα μπορούσε να γίνει εκμετάλλευση και μέσω του AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ανακαλύφθηκε ότι το **Google Chrome δεν όριζε το quarantine attribute** στα ληφθέντα αρχεία, λόγω ορισμένων εσωτερικών προβλημάτων του macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Το AppleDouble αποθηκεύει τα attributes ενός αρχείου σε ξεχωριστό αρχείο, το όνομα του οποίου ξεκινά με `._`· έτσι διευκολύνεται η αντιγραφή των attributes των αρχείων **μεταξύ μηχανημάτων macOS**. Ωστόσο, μετά την αποσυμπίεση ενός αρχείου AppleDouble, στο αρχείο που ξεκινά με `._` **δεν αποδιδόταν το quarantine attribute**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Έχοντας τη δυνατότητα να δημιουργήσουμε ένα αρχείο χωρίς να οριστεί το quarantine attribute, ήταν **δυνατό να παρακαμφθεί το Gatekeeper.** Το κόλπο ήταν να **δημιουργήσουμε ένα αρχείο εφαρμογής DMG** χρησιμοποιώντας τη σύμβαση ονομασίας AppleDouble (ξεκινώντας το με `._`) και να δημιουργήσουμε ένα **ορατό αρχείο ως symlink προς αυτό το κρυφό** αρχείο, χωρίς το quarantine attribute.\
Όταν **εκτελείται το αρχείο DMG**, επειδή δεν έχει quarantine attribute, θα **παρακάμψει το Gatekeeper**.

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

Η Apple διόρθωσε ένα λογικό σφάλμα του LaunchServices στο macOS Sonoma 14.0 μέσω βελτιωμένων ελέγχων. Η δημόσια ανακοίνωση αναφέρει μόνο ότι μια εφαρμογή μπορούσε να παρακάμψει το Gatekeeper, επομένως μην συμπεραίνετε συγκεκριμένη μορφή φορέα ή αλυσίδα εκμετάλλευσης μόνο από την καταχώριση του CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Μια παράκαμψη του Gatekeeper στο macOS 14.4 (κυκλοφόρησε τον Μάρτιο του 2024), η οποία προέκυψε από τον τρόπο με τον οποίο το `libarchive` χειριζόταν κακόβουλα ZIP, επέτρεπε σε εφαρμογές να αποφεύγουν την αξιολόγηση. Ενημερώστε στην έκδοση 14.4 ή νεότερη, όπου η Apple διόρθωσε το πρόβλημα.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Ένα **Automator Quick Action workflow** ενσωματωμένο σε εφαρμογή που είχε ληφθεί μπορούσε να ενεργοποιηθεί χωρίς αξιολόγηση από το Gatekeeper, επειδή τα workflows αντιμετωπίζονταν ως δεδομένα και εκτελούνταν από το βοηθητικό πρόγραμμα Automator, εκτός της κανονικής ροής προτροπής notarization. Συνεπώς, ένα ειδικά διαμορφωμένο `.app` που περιείχε Quick Action και εκτελούσε ένα shell script (π.χ. μέσα στο `Contents/PlugIns/*.workflow/Contents/document.wflow`) μπορούσε να εκτελεστεί αμέσως κατά την εκκίνηση. Η Apple πρόσθεσε ένα επιπλέον παράθυρο διαλόγου συναίνεσης και διόρθωσε τη ροή αξιολόγησης στα Ventura **13.7**, Sonoma **14.7** και Sequoia **15**.<sup>[[3]](#references)</sup>

### Αστοχίες διάδοσης του quarantine κατά την εξαγωγή και την αντιγραφή

Μια μελέτη του 2024 εντόπισε κενά διάδοσης στις δοκιμασμένες εκδόσεις των iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) και 7z Utility (DMG/ZIP/7Z). Παρατήρησε επίσης ότι το χαρακτηριστικό χανόταν κατά τις αντιγραφές από host σε guest μέσω VMware Tools. Αρκετοί προμηθευτές ανακοίνωσαν στη συνέχεια διορθώσεις, επομένως θεωρήστε αυτά τα ονόματα ενδείξεις για **επανέλεγχο ανά έκδοση**, όχι ως μόνιμη λίστα ευάλωτου λογισμικού. Το ίδιο πρόβλημα ορίων εμπιστοσύνης ισχύει και για εγγενείς ροές εργασίας Unix: τα `curl`/`scp` δεν προσθέτουν quarantine, ενώ τα εργαλεία γραμμής εντολών `tar`/`unzip` δεν το κληρονομούν αυτόματα από ένα αρχείο-φορέα.<sup>[[15]](#references)</sup>

Για δοκιμές offensive security, συγκρίνετε τον φορέα και την τελική εφαρμογή μετά από **κάθε** μετάβαση μέσω browser, mail client, εργαλείου αρχειοθέτησης, disk image, cloud sync, shared folder και αντιγραφής VM. Μια ρητή απόρριψη από το `spctl` δεν διορθώνει ένα xattr που λείπει: χωρίς quarantine, η κανονική διαδικασία Gatekeeper κατά το πρώτο άνοιγμα ενδέχεται να μην ζητήσει ποτέ αυτή την αξιολόγηση.<sup>[[15]](#references)</sup>

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

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Δημιουργήστε έναν κατάλογο που να περιέχει μια εφαρμογή.
- Προσθέστε το uchg στην εφαρμογή.
- Συμπιέστε την εφαρμογή σε αρχείο tar.gz.
- Στείλτε το αρχείο tar.gz σε ένα θύμα.
- Το θύμα ανοίγει το αρχείο tar.gz και εκτελεί την εφαρμογή.
- Το Gatekeeper δεν ελέγχει την εφαρμογή.<sup>[[12]](#references)</sup>

### Αποτροπή του Quarantine xattr

Σε ένα bundle «.app», αν δεν προστεθεί το quarantine xattr, κατά την εκτέλεσή του **δεν θα ενεργοποιηθεί το Gatekeeper**.

Δείτε το [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) για primitives βασισμένα σε filesystem, flags, ACL και AppleDouble, τα οποία μπορούν να αποτρέψουν ή να απορρίψουν extended attributes.





## References

- [1] [Apple Platform Security: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.4 (περιλαμβάνει το CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Πώς το macOS παρακολουθεί πλέον την προέλευση των εφαρμογών](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: Το macOS 15 Sequoia καταργεί την παράκαμψη του Gatekeeper μέσω Control‑click «Open»](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Η ανακάλυψη του CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Παράκαμψη του macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Η Jamf Threat Labs εντοπίζει ευπάθεια στο Safari που επιτρέπει την παράκαμψη του Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Η Jamf Threat Labs εντοπίζει ευπάθεια στο macOS Archive Utility που επιτρέπει την παράκαμψη του Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Η αχίλλειος πτέρνα του Gatekeeper: Ανακάλυψη ευπάθειας στο macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ανακάλυψη παράκαμψης του Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Εντοπισμός και αναφορά exploit παράκαμψης του Gatekeeper με τη βοήθεια του Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Παράκαμψη των μηχανισμών ασφάλειας και απορρήτου του macOS — Από το Gatekeeper έως το System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Δοκιμή ενός προϊόντος με notarisation](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Παράκαμψη του Gatekeeper — Αποκάλυψη αδυναμιών σε έναν μηχανισμό ασφαλείας του macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
