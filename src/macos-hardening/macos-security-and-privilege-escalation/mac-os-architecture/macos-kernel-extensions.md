# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Οι επεκτάσεις πυρήνα (Kexts) είναι **πακέτα** με κατάληξη **`.kext`** που **φορτώνονται απευθείας στον χώρο του πυρήνα macOS**, παρέχοντας επιπλέον λειτουργικότητα στο κύριο λειτουργικό σύστημα.

### Deprecation status & DriverKit / System Extensions
Αρχής γενομένης από **macOS Catalina (10.15)**, η Apple χαρακτήρισε τις περισσότερες κληρονομημένες KPI ως *παρωχημένες* και εισήγαγε τα **System Extensions & DriverKit** frameworks που εκτελούνται σε **user-space**. Από **macOS Big Sur (11)**, το λειτουργικό σύστημα θα *αρνείται να φορτώσει* τρίτες επεκτάσεις kext που βασίζονται σε παρωχημένες KPI εκτός αν η μηχανή εκκινείται σε **Reduced Security** mode. Σε Apple Silicon, η ενεργοποίηση των kext απαιτεί επιπλέον από τον χρήστη να:

1. Επανεκκινήσει σε **Recovery** → *Startup Security Utility*.
2. Επιλέξει **Reduced Security** και να τσεκάρει **“Allow user management of kernel extensions from identified developers”**.
3. Επανεκκινήσει και να εγκρίνει την kext από **System Settings → Privacy & Security**.

Οι οδηγοί χρήστη που έχουν γραφτεί με DriverKit/System Extensions μειώνουν δραματικά την **επιφάνεια επίθεσης** επειδή οι κρασάρισμα ή η διαφθορά μνήμης περιορίζονται σε μια διαδικασία sandboxed αντί για τον χώρο του πυρήνα.

> 📝 Από το macOS Sequoia (15), η Apple έχει αφαιρέσει εντελώς πολλές κληρονομημένες KPI δικτύωσης και USB – η μόνη συμβατή λύση για τους προμηθευτές είναι να μεταναστεύσουν σε System Extensions.

### Requirements

Προφανώς, αυτό είναι τόσο ισχυρό που είναι **περίπλοκο να φορτωθεί μια επέκταση πυρήνα**. Αυτές είναι οι **απαιτήσεις** που πρέπει να πληροί μια επέκταση πυρήνα για να φορτωθεί:

- Όταν **μπαίνετε σε λειτουργία ανάκτησης**, οι επεκτάσεις πυρήνα **πρέπει να επιτρέπεται** να φορτωθούν:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Η επέκταση πυρήνα πρέπει να είναι **υπογεγραμμένη με πιστοποιητικό υπογραφής κώδικα πυρήνα**, το οποίο μπορεί να **χορηγηθεί μόνο από την Apple**. Ποιος θα εξετάσει λεπτομερώς την εταιρεία και τους λόγους για τους οποίους είναι απαραίτητο.
- Η επέκταση πυρήνα πρέπει επίσης να είναι **notarized**, η Apple θα μπορεί να την ελέγξει για κακόβουλο λογισμικό.
- Στη συνέχεια, ο χρήστης **root** είναι αυτός που μπορεί να **φορτώσει την επέκταση πυρήνα** και τα αρχεία μέσα στο πακέτο πρέπει να **ανήκουν στον root**.
- Κατά τη διαδικασία φόρτωσης, το πακέτο πρέπει να είναι προετοιμασμένο σε μια **προστατευμένη τοποθεσία μη root**: `/Library/StagedExtensions` (απαιτεί την χορήγηση `com.apple.rootless.storage.KernelExtensionManagement`).
- Τέλος, όταν προσπαθεί να το φορτώσει, ο χρήστης θα [**λάβει ένα αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) και, αν γίνει αποδεκτό, ο υπολογιστής πρέπει να **επανεκκινήσει** για να το φορτώσει.

### Loading process

Στο Catalina ήταν έτσι: Είναι ενδιαφέρον να σημειωθεί ότι η **διαδικασία επαλήθευσης** συμβαίνει σε **userland**. Ωστόσο, μόνο οι εφαρμογές με την **`com.apple.private.security.kext-management`** χορήγηση μπορούν να **ζητήσουν από τον πυρήνα να φορτώσει μια επέκταση**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **ξεκινά** τη **διαδικασία επαλήθευσης** για τη φόρτωση μιας επέκτασης
- Θα επικοινωνήσει με **`kextd`** στέλνοντας χρησιμοποιώντας μια **Mach service**.
2. **`kextd`** θα ελέγξει διάφορα πράγματα, όπως την **υπογραφή**
- Θα επικοινωνήσει με **`syspolicyd`** για να **ελέγξει** αν η επέκταση μπορεί να **φορτωθεί**.
3. **`syspolicyd`** θα **ζητήσει** από τον **χρήστη** αν η επέκταση δεν έχει φορτωθεί προηγουμένως.
- **`syspolicyd`** θα αναφέρει το αποτέλεσμα στο **`kextd`**
4. **`kextd`** θα είναι τελικά σε θέση να **πείσει τον πυρήνα να φορτώσει** την επέκταση

Αν **`kextd`** δεν είναι διαθέσιμο, **`kextutil`** μπορεί να εκτελέσει τους ίδιους ελέγχους.

### Enumeration & management (loaded kexts)

`kextstat` ήταν το ιστορικό εργαλείο αλλά είναι **παρωχημένο** στις πρόσφατες εκδόσεις macOS. Η σύγχρονη διεπαφή είναι **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Η παλαιότερη σύνταξη είναι ακόμα διαθέσιμη για αναφορά:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` μπορεί επίσης να χρησιμοποιηθεί για **να εξάγει το περιεχόμενο μιας Συλλογής Πυρήνα (KC)** ή να επαληθεύσει ότι ένα kext επιλύει όλες τις εξαρτήσεις συμβόλων:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Αν και οι επεκτάσεις πυρήνα αναμένονται να βρίσκονται στο `/System/Library/Extensions/`, αν πάτε σε αυτόν τον φάκελο **δεν θα βρείτε κανένα δυαδικό αρχείο**. Αυτό οφείλεται στο **kernelcache** και για να αναστρέψετε ένα `.kext` πρέπει να βρείτε έναν τρόπο να το αποκτήσετε.

Το **kernelcache** είναι μια **προ-συγκεντρωμένη και προ-συνδεδεμένη έκδοση του πυρήνα XNU**, μαζί με βασικούς **οδηγούς** και **επικεφαλίδες πυρήνα**. Αποθηκεύεται σε **συμπιεσμένη** μορφή και αποσυμπιέζεται στη μνήμη κατά τη διάρκεια της διαδικασίας εκκίνησης. Το kernelcache διευκολύνει έναν **ταχύτερο χρόνο εκκίνησης** έχοντας μια έτοιμη προς εκτέλεση έκδοση του πυρήνα και κρίσιμων οδηγών διαθέσιμων, μειώνοντας τον χρόνο και τους πόρους που θα δαπανώνταν διαφορετικά για τη δυναμική φόρτωση και σύνδεση αυτών των στοιχείων κατά την εκκίνηση.

### Τοπικό Kernelcache

Στο iOS βρίσκεται στο **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** στο macOS μπορείτε να το βρείτε με: **`find / -name "kernelcache" 2>/dev/null`** \
Στην περίπτωσή μου στο macOS το βρήκα στο:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Η μορφή αρχείου IMG4 είναι μια μορφή κοντέινερ που χρησιμοποιείται από την Apple στα iOS και macOS συστήματα για την ασφαλή **αποθήκευση και επαλήθευση των στοιχείων firmware** (όπως το **kernelcache**). Η μορφή IMG4 περιλαμβάνει μια κεφαλίδα και αρκετές ετικέτες που περι encapsulate διάφορα κομμάτια δεδομένων, συμπεριλαμβανομένου του πραγματικού payload (όπως ένας πυρήνας ή bootloader), μια υπογραφή και ένα σύνολο ιδιοτήτων manifest. Η μορφή υποστηρίζει κρυπτογραφική επαλήθευση, επιτρέποντας στη συσκευή να επιβεβαιώσει την αυθεντικότητα και την ακεραιότητα του στοιχείου firmware πριν το εκτελέσει.

Συνήθως αποτελείται από τα εξής στοιχεία:

- **Payload (IM4P)**:
- Συχνά συμπιεσμένο (LZFSE4, LZSS, …)
- Προαιρετικά κρυπτογραφημένο
- **Manifest (IM4M)**:
- Περιέχει Υπογραφή
- Πρόσθετο λεξικό Κλειδιού/Τιμής
- **Restore Info (IM4R)**:
- Γνωστό και ως APNonce
- Αποτρέπει την επανάληψη ορισμένων ενημερώσεων
- ΠΡΟΑΙΡΕΤΙΚΟ: Συνήθως αυτό δεν βρίσκεται

Αποσυμπιέστε το Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Λήψη

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Στο [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) είναι δυνατή η εύρεση όλων των εργαλείων αποσφαλμάτωσης πυρήνα. Μπορείτε να το κατεβάσετε, να το τοποθετήσετε, να το ανοίξετε με το εργαλείο [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), να αποκτήσετε πρόσβαση στον φάκελο **`.kext`** και να **εξαγάγετε** το περιεχόμενο.

Ελέγξτε το για σύμβολα με:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Κάποιες φορές η Apple κυκλοφορεί **kernelcache** με **symbols**. Μπορείτε να κατεβάσετε κάποιες εκδόσεις firmware με symbols ακολουθώντας τους συνδέσμους σε αυτές τις σελίδες. Οι εκδόσεις firmware θα περιέχουν το **kernelcache** μεταξύ άλλων αρχείων.

Για να **extract** τα αρχεία, ξεκινήστε αλλάζοντας την επέκταση από `.ipsw` σε `.zip` και **unzip** το.

Αφού εξαγάγετε το firmware, θα λάβετε ένα αρχείο όπως: **`kernelcache.release.iphone14`**. Είναι σε μορφή **IMG4**, μπορείτε να εξαγάγετε τις ενδιαφέρουσες πληροφορίες με:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Εξέταση του kernelcache

Ελέγξτε αν το kernelcache έχει σύμβολα με
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Με αυτό μπορούμε τώρα να **εξάγουμε όλες τις επεκτάσεις** ή την **μία που σας ενδιαφέρει:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Πρόσφατες ευπάθειες & τεχνικές εκμετάλλευσης

| Έτος | CVE | Περίληψη |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Λάθος λογικής στο **`storagekitd`** επέτρεψε σε έναν *root* επιτιθέμενο να καταχωρήσει ένα κακόβουλο πακέτο συστήματος αρχείων που τελικά φόρτωσε ένα **μη υπογεγραμμένο kext**, **παρακάμπτοντας την Προστασία Ακεραιότητας Συστήματος (SIP)** και επιτρέποντας μόνιμα rootkits. Διορθώθηκε στο macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Ο daemon εγκατάστασης με την εξουσία `com.apple.rootless.install` μπορούσε να καταχραστεί για να εκτελέσει αυθαίρετα σενάρια μετά την εγκατάσταση, να απενεργοποιήσει το SIP και να φορτώσει αυθαίρετα kexts.  |

**Σημαντικά σημεία για τους red-teamers**

1. **Αναζητήστε εξουσιοδοτημένους daemons (`codesign -dvv /path/bin | grep entitlements`) που αλληλεπιδρούν με το Disk Arbitration, τον Installer ή τη Διαχείριση Kext.**
2. **Η κατάχρηση του SIP παρακάμπτει σχεδόν πάντα τη δυνατότητα φόρτωσης ενός kext → εκτέλεση κώδικα πυρήνα**.

**Αμυντικές συμβουλές**

*Διατηρήστε το SIP ενεργοποιημένο*, παρακολουθήστε για κλήσεις `kmutil load`/`kmutil create -n aux` που προέρχονται από μη Apple δυαδικά και ειδοποιήστε για οποιαδήποτε εγγραφή στο `/Library/Extensions`. Τα γεγονότα Ασφάλειας Τερματικού `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` παρέχουν σχεδόν άμεση ορατότητα.

## Αποσφαλμάτωση πυρήνα macOS & kexts

Η προτεινόμενη ροή εργασίας της Apple είναι να κατασκευάσει ένα **Kernel Debug Kit (KDK)** που ταιριάζει με την τρέχουσα έκδοση και στη συνέχεια να συνδεθεί με το **LLDB** μέσω μιας συνεδρίας δικτύου **KDP (Kernel Debugging Protocol)**.

### Τοπική αποσφαλμάτωση ενός πανικού με μία εντολή
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging from another Mac

1. Κατεβάστε + εγκαταστήστε την ακριβή έκδοση **KDK** για τη στοχευμένη μηχανή.
2. Συνδέστε τη στοχευμένη Mac και τη μηχανή φιλοξενίας με ένα **USB-C ή Thunderbolt καλώδιο**.
3. Στη **στοχευμένη**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Στον **φιλοξενούμενο**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Σύνδεση του LLDB σε ένα συγκεκριμένο φορτωμένο kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP μόνο εκθέτει μια **μόνο για ανάγνωση** διεπαφή. Για δυναμική οργάνωση θα χρειαστεί να διορθώσετε το δυαδικό αρχείο στον δίσκο, να εκμεταλλευτείτε το **hooking συναρτήσεων πυρήνα** (π.χ. `mach_override`) ή να μεταφέρετε τον οδηγό σε έναν **hypervisor** για πλήρη ανάγνωση/γραφή.

## Αναφορές

- DriverKit Security – Οδηγός Ασφαλείας Πλατφόρμας Apple
- Microsoft Security Blog – *Ανάλυση CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
