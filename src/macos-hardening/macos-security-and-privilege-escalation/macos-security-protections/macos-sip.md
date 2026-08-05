# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Βασικές πληροφορίες**

Το **System Integrity Protection (SIP)** στο macOS είναι ένας μηχανισμός σχεδιασμένος να αποτρέπει ακόμη και τους πιο προνομιούχους χρήστες από την πραγματοποίηση μη εξουσιοδοτημένων αλλαγών σε βασικούς φακέλους του συστήματος. Αυτή η λειτουργία διαδραματίζει κρίσιμο ρόλο στη διατήρηση της ακεραιότητας του συστήματος, περιορίζοντας ενέργειες όπως η προσθήκη, η τροποποίηση ή η διαγραφή αρχείων σε προστατευμένες περιοχές. Οι κύριοι φάκελοι που προστατεύονται από το SIP περιλαμβάνουν:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Οι κανόνες που διέπουν τη συμπεριφορά του SIP ορίζονται στο αρχείο ρυθμίσεων που βρίσκεται στη διεύθυνση **`/System/Library/Sandbox/rootless.conf`**. Σε αυτό το αρχείο, οι διαδρομές που έχουν ως πρόθεμα έναν αστερίσκο (\*) υποδεικνύονται ως εξαιρέσεις από τους αυστηρούς περιορισμούς του SIP.

Δείτε το παρακάτω παράδειγμα:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Αυτό το απόσπασμα υποδεικνύει ότι, ενώ το SIP προστατεύει γενικά τον κατάλογο **`/usr`**, υπάρχουν συγκεκριμένοι υποκατάλογοι (`/usr/libexec/cups`, `/usr/local` και `/usr/share/man`) στους οποίους επιτρέπονται τροποποιήσεις, όπως υποδεικνύεται από τον αστερίσκο (\*) πριν από τις διαδρομές τους.

Για να επαληθεύσετε αν ένας κατάλογος ή ένα αρχείο προστατεύεται από το SIP, μπορείτε να χρησιμοποιήσετε την εντολή **`ls -lOd`** για να ελέγξετε αν υπάρχει η σημαία **`restricted`** ή **`sunlnk`**. Για παράδειγμα:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Σε αυτήν την περίπτωση, το flag **`sunlnk`** υποδεικνύει ότι ο ίδιος ο κατάλογος `/usr/libexec/cups` **δεν μπορεί να διαγραφεί**, παρόλο που μπορούν να δημιουργηθούν, να τροποποιηθούν ή να διαγραφούν αρχεία μέσα σε αυτόν.

Από την άλλη πλευρά:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Εδώ, το **`restricted`** flag υποδεικνύει ότι ο κατάλογος `/usr/libexec` προστατεύεται από το SIP. Σε έναν κατάλογο που προστατεύεται από το SIP, δεν είναι δυνατή η δημιουργία, τροποποίηση ή διαγραφή αρχείων.

Επιπλέον, αν ένα αρχείο περιέχει το extended **attribute** **`com.apple.rootless`**, τότε και αυτό το αρχείο θα **προστατεύεται από το SIP**.

> [!TIP]
> Σημειώστε ότι το **Sandbox** hook **`hook_vnode_check_setextattr`** αποτρέπει κάθε προσπάθεια τροποποίησης του extended attribute **`com.apple.rootless`.**

Το **SIP περιορίζει επίσης άλλες ενέργειες του root**, όπως:

- Η φόρτωση μη έμπιστων kernel extensions
- Η λήψη task-ports για διεργασίες υπογεγραμμένες από την Apple
- Η τροποποίηση μεταβλητών NVRAM
- Η ενεργοποίηση του kernel debugging

Οι επιλογές διατηρούνται σε μεταβλητή nvram ως bitflag (`csr-active-config` στο Intel, ενώ το `lp-sip0` διαβάζεται από το booted Device Tree στο ARM). Μπορείτε να βρείτε τα flags στον πηγαίο κώδικα του XNU, στο `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Κατάσταση SIP

Μπορείτε να ελέγξετε αν το SIP είναι ενεργοποιημένο στο σύστημά σας με την ακόλουθη εντολή:
```bash
csrutil status
```
Εάν χρειάζεται να απενεργοποιήσετε το SIP, πρέπει να επανεκκινήσετε τον υπολογιστή σας σε recovery mode (πατώντας Command+R κατά την εκκίνηση) και, στη συνέχεια, να εκτελέσετε την ακόλουθη εντολή:
```bash
csrutil disable
```
Εάν θέλετε να διατηρήσετε το SIP ενεργοποιημένο, αλλά να καταργήσετε τις protections του debugging, μπορείτε να το κάνετε με:
```bash
csrutil enable --without debug
```
### Άλλοι Περιορισμοί

- **Απαγορεύει τη φόρτωση unsigned kernel extensions** (kexts), διασφαλίζοντας ότι μόνο επαληθευμένες επεκτάσεις αλληλεπιδρούν με τον kernel του συστήματος.
- **Αποτρέπει το debugging** των system processes του macOS, προστατεύοντας τα βασικά στοιχεία του συστήματος από μη εξουσιοδοτημένη πρόσβαση και τροποποίηση.
- **Εμποδίζει εργαλεία** όπως το dtrace να επιθεωρούν system processes, προστατεύοντας περαιτέρω την ακεραιότητα της λειτουργίας του συστήματος.

[**Μάθετε περισσότερα σχετικά με τις πληροφορίες του SIP σε αυτή την ομιλία**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **Entitlements που σχετίζονται με το SIP**

- `com.apple.rootless.xpc.bootstrap`: Έλεγχος του launchd
- `com.apple.rootless.install[.heritable]`: Πρόσβαση στο file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Διαχείριση του UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Δυνατότητες ρύθμισης XPC
- `com.apple.rootless.xpc.effective-root`: Root μέσω launchd XPC
- `com.apple.rootless.restricted-block-devices`: Πρόσβαση σε raw block devices
- `com.apple.rootless.internal.installer-equivalent`: Απεριόριστη πρόσβαση στο filesystem
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Πλήρης πρόσβαση στο NVRAM
- `com.apple.rootless.storage.label`: Τροποποίηση αρχείων που περιορίζονται από το com.apple.rootless xattr με το αντίστοιχο label
- `com.apple.rootless.volume.VM.label`: Διατήρηση του VM swap στο volume

## SIP Bypasses

Η παράκαμψη του SIP επιτρέπει σε έναν attacker να:

- **Αποκτήσει πρόσβαση σε User Data**: Να διαβάσει ευαίσθητα user data, όπως mail, messages και το ιστορικό του Safari, από όλους τους user accounts.
- **TCC Bypass**: Να χειριστεί απευθείας τη βάση δεδομένων TCC (Transparency, Consent, and Control), ώστε να παραχωρήσει μη εξουσιοδοτημένη πρόσβαση στην webcam, το microphone και άλλους πόρους.
- **Εγκαταστήσει Persistence**: Να τοποθετήσει malware σε τοποθεσίες που προστατεύονται από το SIP, καθιστώντας το ανθεκτικό στην αφαίρεση, ακόμη και με root privileges. Αυτό περιλαμβάνει επίσης την πιθανότητα παραποίησης του Malware Removal Tool (MRT).
- **Φορτώσει Kernel Extensions**: Παρότι υπάρχουν πρόσθετες δικλίδες ασφαλείας, η παράκαμψη του SIP απλοποιεί τη διαδικασία φόρτωσης unsigned kernel extensions.

### Installer Packages

**Τα installer packages που έχουν υπογραφεί με certificate της Apple** μπορούν να παρακάμψουν τις προστασίες της. Αυτό σημαίνει ότι ακόμη και packages που έχουν υπογραφεί από standard developers θα αποκλείονται, αν επιχειρήσουν να τροποποιήσουν directories που προστατεύονται από το SIP.

### Ανύπαρκτο αρχείο SIP

Ένα πιθανό loophole είναι ότι, αν ένα αρχείο καθορίζεται στο **`rootless.conf` αλλά δεν υπάρχει αυτή τη στιγμή**, μπορεί να δημιουργηθεί. Το malware θα μπορούσε να το εκμεταλλευτεί για να **εγκαταστήσει persistence** στο σύστημα. Για παράδειγμα, ένα malicious πρόγραμμα θα μπορούσε να δημιουργήσει ένα αρχείο .plist στο `/System/Library/LaunchDaemons`, αν αυτό αναφέρεται στο `rootless.conf` αλλά δεν υπάρχει.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει την παράκαμψη του SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Ανακαλύφθηκε ότι ήταν δυνατή η **αντικατάσταση του installer package αφού το σύστημα είχε επαληθεύσει την code** signature του και, στη συνέχεια, το σύστημα εγκαθιστούσε το malicious package αντί για το αρχικό. Καθώς αυτές οι ενέργειες εκτελούνταν από το **`system_installd`**, ήταν δυνατή η παράκαμψη του SIP.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Αν ένα package εγκαθίστατο από mounted image ή external drive, ο **installer** **εκτελούσε** το binary από **εκείνο το file system** (αντί από μια τοποθεσία που προστατεύεται από το SIP), με αποτέλεσμα το **`system_installd`** να εκτελεί ένα arbitrary binary.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Researchers από αυτή την ανάρτηση**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ανακάλυψαν μια ευπάθεια στον μηχανισμό System Integrity Protection (SIP) του macOS, η οποία ονομάστηκε ευπάθεια «Shrootless». Η ευπάθεια αυτή αφορά τον daemon **`system_installd`**, ο οποίος διαθέτει το entitlement **`com.apple.rootless.install.heritable`**, επιτρέποντας σε οποιαδήποτε child processes του να παρακάμπτουν τους file system restrictions του SIP.<sup>[4]</sup>

Ο daemon **`system_installd`** εγκαθιστά packages που έχουν υπογραφεί από την **Apple**.

Οι researchers διαπίστωσαν ότι, κατά την εγκατάσταση ενός Apple-signed package (αρχείο .pkg), το **`system_installd`** **εκτελεί** όλα τα **post-install** scripts που περιλαμβάνονται στο package. Αυτά τα scripts εκτελούνται από το default shell, το **`zsh`**, το οποίο **εκτελεί** αυτόματα commands από το αρχείο **`/etc/zshenv`**, αν αυτό υπάρχει, ακόμη και σε non-interactive mode. Αυτή η συμπεριφορά θα μπορούσε να αξιοποιηθεί από attackers: δημιουργώντας ένα malicious αρχείο `/etc/zshenv` και περιμένοντας το **`system_installd` να καλέσει το `zsh`**, θα μπορούσαν να εκτελέσουν arbitrary operations στη συσκευή.<sup>[4]</sup>

Επιπλέον, ανακαλύφθηκε ότι το **`/etc/zshenv` θα μπορούσε να χρησιμοποιηθεί ως general attack technique**, όχι μόνο για SIP bypass. Κάθε user profile διαθέτει ένα αρχείο `~/.zshenv`, το οποίο συμπεριφέρεται με τον ίδιο τρόπο όπως το `/etc/zshenv`, αλλά δεν απαιτεί root permissions. Αυτό το αρχείο θα μπορούσε να χρησιμοποιηθεί ως persistence mechanism, ενεργοποιούμενο κάθε φορά που ξεκινά το `zsh`, ή ως privilege escalation mechanism. Αν ένας admin user αποκτήσει root μέσω `sudo -s` ή `sudo <command>`, θα ενεργοποιηθεί το αρχείο `~/.zshenv`, με αποτέλεσμα την effective elevation σε root.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Στο [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) ανακαλύφθηκε ότι η ίδια process **`system_installd`** μπορούσε ακόμη να γίνει abuse, επειδή τοποθετούσε το **post-install script μέσα σε έναν φάκελο με random όνομα, προστατευμένο από το SIP, μέσα στο `/tmp`**. Το ζήτημα είναι ότι το **`/tmp` από μόνο του δεν προστατεύεται από το SIP**, επομένως ήταν δυνατή η **προσάρτηση** ενός **virtual image σε αυτό**, στη συνέχεια ο **installer** τοποθετούσε εκεί το **post-install script**, γινόταν **unmount** του virtual image, **αναδημιουργούνταν** όλοι οι **φάκελοι** και προστίθετο το **post-installation** script μαζί με το **payload** προς εκτέλεση.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Εντοπίστηκε μια ευπάθεια όπου το **`fsck_cs`** παραπλανήθηκε ώστε να καταστρέψει ένα κρίσιμο αρχείο, λόγω της δυνατότητάς του να ακολουθεί **symbolic links**. Συγκεκριμένα, οι attackers δημιούργησαν ένα link από το _`/dev/diskX`_ προς το αρχείο `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Η εκτέλεση του **`fsck_cs`** στο _`/dev/diskX`_ οδήγησε στην καταστροφή του `Info.plist`. Η ακεραιότητα αυτού του αρχείου είναι κρίσιμη για το SIP (System Integrity Protection) του operating system, το οποίο ελέγχει τη φόρτωση των kernel extensions. Μετά την καταστροφή του, η ικανότητα του SIP να διαχειρίζεται τις kernel exclusions υποβαθμίζεται.<sup>[6]</sup>

Οι commands για την εκμετάλλευση αυτής της ευπάθειας είναι:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Η εκμετάλλευση αυτής της ευπάθειας έχει σοβαρές επιπτώσεις. Το αρχείο `Info.plist`, το οποίο κανονικά είναι υπεύθυνο για τη διαχείριση των δικαιωμάτων των kernel extensions, καθίσταται αναποτελεσματικό. Αυτό περιλαμβάνει την αδυναμία blacklist συγκεκριμένων extensions, όπως το `AppleHWAccess.kext`. Κατά συνέπεια, καθώς ο μηχανισμός ελέγχου του SIP βρίσκεται εκτός λειτουργίας, αυτό το extension μπορεί να φορτωθεί, παρέχοντας μη εξουσιοδοτημένη πρόσβαση ανάγνωσης και εγγραφής στη RAM του συστήματος.<sup>[6]</sup>

#### [Mount πάνω από φακέλους που προστατεύονται από το SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Ήταν δυνατή η προσάρτηση ενός νέου file system πάνω από **φακέλους που προστατεύονται από το SIP, ώστε να παρακαμφθεί η προστασία**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Το σύστημα έχει ρυθμιστεί να εκκινεί από ένα ενσωματωμένο installer disk image μέσα στο `Install macOS Sierra.app` για την αναβάθμιση του OS, χρησιμοποιώντας το utility `bless`. Η εντολή που χρησιμοποιείται είναι η εξής:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Η ασφάλεια αυτής της διαδικασίας μπορεί να παραβιαστεί εάν ένας attacker τροποποιήσει το upgrade image (`InstallESD.dmg`) πριν από την εκκίνηση. Η στρατηγική περιλαμβάνει την αντικατάσταση ενός dynamic loader (dyld) με μια malicious έκδοση (`libBaseIA.dylib`). Αυτή η αντικατάσταση έχει ως αποτέλεσμα την εκτέλεση του κώδικα του attacker κατά την εκκίνηση του installer.<sup>[7]</sup>

Ο κώδικας του attacker αποκτά τον έλεγχο κατά τη διαδικασία του upgrade, εκμεταλλευόμενος την εμπιστοσύνη του συστήματος προς τον installer. Η επίθεση προχωρά με την τροποποίηση του image `InstallESD.dmg` μέσω method swizzling, στοχεύοντας συγκεκριμένα τη μέθοδο `extractBootBits`. Αυτό επιτρέπει την εισαγωγή malicious κώδικα πριν χρησιμοποιηθεί το disk image.<sup>[7]</sup>

Επιπλέον, μέσα στο `InstallESD.dmg` υπάρχει ένα `BaseSystem.dmg`, το οποίο λειτουργεί ως το root file system του κώδικα του upgrade. Η εισαγωγή μιας dynamic library σε αυτό επιτρέπει στον malicious κώδικα να εκτελείται μέσα σε μια process με δυνατότητα τροποποίησης αρχείων σε επίπεδο OS, αυξάνοντας σημαντικά την πιθανότητα compromise του συστήματος.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Σε αυτή την ομιλία από το [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), παρουσιάζεται πώς το **`systemmigrationd`** (το οποίο μπορεί να κάνει bypass το SIP) εκτελεί ένα **bash** και ένα **perl** script, τα οποία μπορούν να γίνουν abuse μέσω των env variables **`BASH_ENV`** και **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Όπως [**περιγράφεται αναλυτικά σε αυτή την ανάρτηση**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), ένα `postinstall` script από τα packages του `InstallAssistant.pkg` εκτελούνταν:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
και ήταν δυνατό να δημιουργηθεί ένα symlink στο `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, το οποίο θα επέτρεπε σε έναν χρήστη να **καταργήσει τους περιορισμούς οποιουδήποτε αρχείου, παρακάμπτοντας την προστασία SIP**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Το entitlement **`com.apple.rootless.install`** επιτρέπει την παράκαμψη του SIP

Το entitlement `com.apple.rootless.install` είναι γνωστό ότι παρακάμπτει το System Integrity Protection (SIP) στο macOS. Αυτό αναφέρθηκε χαρακτηριστικά σε σχέση με το [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

Σε αυτήν τη συγκεκριμένη περίπτωση, η system XPC service που βρίσκεται στο `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` διαθέτει αυτό το entitlement. Αυτό επιτρέπει στη σχετική διεργασία να παρακάμπτει τους περιορισμούς του SIP. Επιπλέον, αυτή η service παρέχει χαρακτηριστικά μια μέθοδο που επιτρέπει τη μετακίνηση αρχείων χωρίς την επιβολή μέτρων ασφαλείας.<sup>[10]</sup>

## Sealed System Snapshots

Τα Sealed System Snapshots είναι μια δυνατότητα που εισήγαγε η Apple στο **macOS Big Sur (macOS 11)** ως μέρος του μηχανισμού **System Integrity Protection (SIP)**, για την παροχή ενός επιπλέον επιπέδου ασφάλειας και σταθερότητας του συστήματος. Πρόκειται ουσιαστικά για read-only εκδόσεις του system volume.

Ακολουθεί μια πιο αναλυτική περιγραφή:

1. **Immutable System**: Τα Sealed System Snapshots καθιστούν το system volume του macOS "immutable", δηλαδή δεν μπορεί να τροποποιηθεί. Αυτό αποτρέπει μη εξουσιοδοτημένες ή τυχαίες αλλαγές στο σύστημα, οι οποίες θα μπορούσαν να θέσουν σε κίνδυνο την ασφάλεια ή τη σταθερότητα του συστήματος.
2. **System Software Updates**: Όταν εγκαθιστάτε updates ή upgrades του macOS, το macOS δημιουργεί ένα νέο system snapshot. Στη συνέχεια, το startup volume του macOS χρησιμοποιεί το **APFS (Apple File System)** για να μεταβεί σε αυτό το νέο snapshot. Η συνολική διαδικασία εφαρμογής των updates γίνεται ασφαλέστερη και πιο αξιόπιστη, καθώς το σύστημα μπορεί πάντα να επανέλθει στο προηγούμενο snapshot αν κάτι πάει στραβά κατά τη διάρκεια του update.
3. **Data Separation**: Σε συνδυασμό με την έννοια του διαχωρισμού των Data και System volumes, η οποία εισήχθη στο macOS Catalina, η δυνατότητα Sealed System Snapshot διασφαλίζει ότι όλα τα δεδομένα και οι ρυθμίσεις σας αποθηκεύονται σε ξεχωριστό "**Data**" volume. Αυτός ο διαχωρισμός καθιστά τα δεδομένα σας ανεξάρτητα από το σύστημα, απλοποιεί τη διαδικασία των system updates και ενισχύει την ασφάλεια του συστήματος.

Να θυμάστε ότι αυτά τα snapshots διαχειρίζονται αυτόματα από το macOS και δεν καταλαμβάνουν επιπλέον χώρο στον δίσκο σας, χάρη στις δυνατότητες κοινής χρήσης χώρου του APFS. Είναι επίσης σημαντικό να σημειωθεί ότι αυτά τα snapshots διαφέρουν από τα **Time Machine snapshots**, τα οποία είναι backups ολόκληρου του συστήματος, προσβάσιμα από τον χρήστη.

### Check Snapshots

Η εντολή **`diskutil apfs list`** εμφανίζει τις **λεπτομέρειες των APFS volumes** και τη διάταξή τους:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
|   Encrypted:                 No
</code></pre>

Στην προηγούμενη έξοδο είναι δυνατό να δούμε ότι οι **τοποθεσίες στις οποίες έχει πρόσβαση ο χρήστης** είναι mounted στο `/System/Volumes/Data`.

Επιπλέον, το **snapshot του macOS System volume** είναι mounted στο `/` και είναι **sealed** (κρυπτογραφικά υπογεγραμμένο από το OS). Επομένως, αν παρακαμφθεί το SIP και τροποποιηθεί, το **OS δεν θα εκκινεί πλέον**.

Είναι επίσης δυνατό να **επαληθευτεί ότι το seal είναι ενεργοποιημένο** εκτελώντας:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Επιπλέον, ο δίσκος του snapshot είναι επίσης προσαρτημένος ως **μόνο για ανάγνωση**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Αναφορές

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Η Microsoft εντοπίζει νέα ευπάθεια στο macOS, το Shrootless, που θα μπορούσε να παρακάμψει το System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Η fruitless rootless ασφάλεια της Apple παραβιάστηκε με κώδικα που χωράει σε ένα tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Παράκαμψη του System Integrity Protection της Apple - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Η Apple μετριάζει τις ευπάθειες στα Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: Το POC για το SIP-Bypass χωράει ακόμη και σε tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
