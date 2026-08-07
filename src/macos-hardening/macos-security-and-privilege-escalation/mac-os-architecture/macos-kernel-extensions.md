# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα Kernel extensions (Kexts) είναι **packages** με επέκταση **`.kext`**, τα οποία **φορτώνονται απευθείας στον χώρο του macOS kernel**, παρέχοντας πρόσθετη λειτουργικότητα στο κύριο λειτουργικό σύστημα.

### Κατάσταση deprecation & DriverKit / System Extensions
Ξεκινώντας με το **macOS Catalina (10.15)**, η Apple χαρακτήρισε τα περισσότερα legacy KPIs ως *deprecated* και εισήγαγε τα frameworks **System Extensions & DriverKit**, τα οποία εκτελούνται σε **user-space**. Από το **macOS Big Sur (11)**, το λειτουργικό σύστημα θα *αρνείται να φορτώσει* third-party kexts που βασίζονται σε deprecated KPIs, εκτός αν το μηχάνημα έχει εκκινηθεί σε λειτουργία **Reduced Security**. Σε Apple Silicon, η ενεργοποίηση των kexts απαιτεί επιπλέον από τον χρήστη:

1. Επανεκκίνηση σε **Recovery** → *Startup Security Utility*.
2. Επιλογή **Reduced Security** και ενεργοποίηση της επιλογής **“Allow user management of kernel extensions from identified developers”**.
3. Επανεκκίνηση και έγκριση του kext από το **System Settings → Privacy & Security**.

Οι user-land drivers που έχουν γραφτεί με DriverKit/System Extensions **μειώνουν σημαντικά το attack surface**, επειδή τα crashes ή η memory corruption περιορίζονται σε μια sandboxed process αντί για τον kernel space.<sup>[[1]](#references)</sup>

> 📝 Από το macOS Sequoia (15), η Apple έχει αφαιρέσει πλήρως αρκετά legacy networking και USB KPIs – η μόνη forward-compatible λύση για τους vendors είναι η μετάβαση σε System Extensions.

### Απαιτήσεις

Προφανώς, αυτό είναι τόσο ισχυρό ώστε να είναι **περίπλοκη η φόρτωση ενός kernel extension**. Αυτές είναι οι **απαιτήσεις** που πρέπει να πληροί ένα kernel extension για να φορτωθεί:

- Κατά την **είσοδο σε recovery mode**, τα kernel **extensions πρέπει να επιτρέπεται** να φορτώνονται:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Το kernel extension πρέπει να είναι **υπογεγραμμένο με kernel code signing certificate**, το οποίο μπορεί να **χορηγηθεί μόνο από την Apple**. Η Apple θα εξετάσει λεπτομερώς την εταιρεία και τους λόγους για τους οποίους απαιτείται.
- Το kernel extension πρέπει επίσης να είναι **notarized**, ώστε η Apple να μπορεί να το ελέγξει για malware.
- Στη συνέχεια, ο χρήστης **root** είναι αυτός που μπορεί να **φορτώσει το kernel extension** και τα files μέσα στο package πρέπει να **ανήκουν στον root**.
- Κατά τη διαδικασία upload, το package πρέπει να προετοιμαστεί σε μια **protected non-root τοποθεσία**: `/Library/StagedExtensions` (απαιτεί το grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Τέλος, κατά την προσπάθεια φόρτωσής του, ο χρήστης θα [**λάβει αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) και, αν το αποδεχτεί, ο υπολογιστής πρέπει να **επανεκκινηθεί** για να φορτωθεί.

### Διαδικασία φόρτωσης

Στο Catalina η διαδικασία ήταν η εξής: Είναι ενδιαφέρον να σημειωθεί ότι η διαδικασία **verification** πραγματοποιείται σε **userland**. Ωστόσο, μόνο applications με το grant **`com.apple.private.security.kext-management`** μπορούν να **ζητήσουν από τον kernel να φορτώσει ένα extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. Το **`kextutil`** cli **ξεκινά** τη διαδικασία **verification** για τη φόρτωση ενός extension
- Θα επικοινωνήσει με το **`kextd`** στέλνοντας δεδομένα μέσω μιας **Mach service**.
2. Το **`kextd`** θα ελέγξει διάφορα στοιχεία, όπως το **signature**
- Θα επικοινωνήσει με το **`syspolicyd`** για να **ελέγξει** αν το extension μπορεί να **φορτωθεί**.
3. Το **`syspolicyd`** θα **ζητήσει επιβεβαίωση από τον** **χρήστη** αν το extension δεν έχει φορτωθεί προηγουμένως.
- Το **`syspolicyd`** θα αναφέρει το αποτέλεσμα στο **`kextd`**
4. Το **`kextd`** θα μπορεί τελικά να **ζητήσει από τον kernel να φορτώσει** το extension

Αν το **`kextd`** δεν είναι διαθέσιμο, το **`kextutil`** μπορεί να εκτελέσει τους ίδιους ελέγχους.

### Enumeration & management (loaded kexts)

Το `kextstat` ήταν το ιστορικό tool, αλλά είναι **deprecated** στις πρόσφατες εκδόσεις του macOS. Το σύγχρονο interface είναι το **`kmutil`**:
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
Το `kmutil inspect` μπορεί επίσης να αξιοποιηθεί για την **εξαγωγή των περιεχομένων μιας Kernel Collection (KC)** ή για την επαλήθευση ότι ένα kext επιλύει όλες τις εξαρτήσεις συμβόλων:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Παρόλο που αναμένεται τα kernel extensions να βρίσκονται στο `/System/Library/Extensions/`, αν μεταβείτε σε αυτόν τον φάκελο **δεν θα βρείτε κανένα binary**. Αυτό συμβαίνει λόγω του **kernelcache** και, για να κάνετε reverse engineering σε ένα `.kext`, πρέπει να βρείτε έναν τρόπο να το αποκτήσετε.

Το **kernelcache** είναι μια **pre-compiled και pre-linked έκδοση του XNU kernel**, μαζί με απαραίτητους **drivers** συσκευών και **kernel extensions**. Αποθηκεύεται σε **compressed** μορφή και αποσυμπιέζεται στη μνήμη κατά τη διαδικασία boot. Το kernelcache διευκολύνει ένα **ταχύτερο boot time**, παρέχοντας μια έτοιμη προς εκτέλεση έκδοση του kernel και των κρίσιμων drivers, μειώνοντας τον χρόνο και τους πόρους που διαφορετικά θα απαιτούνταν για το δυναμικό loading και linking αυτών των components κατά το boot.

Τα κύρια οφέλη του kernelcache είναι η **ταχύτητα loading** και το γεγονός ότι όλα τα modules είναι prelinked (χωρίς impediment κατά το load time). Επίσης, αφού όλα τα modules έχουν γίνει prelinked, το KXLD μπορεί να αφαιρεθεί από τη μνήμη, επομένως το **XNU δεν μπορεί να φορτώσει νέα KEXTs.**

> [!TIP]
> Το tool [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) κάνει decrypt τα AEA (Apple Encrypted Archive / AEA asset) containers της Apple — το encrypted container format που χρησιμοποιεί η Apple για OTA assets και ορισμένα IPSW pieces — και μπορεί να παράγει το underlying `.dmg`/asset archive, το οποίο μπορείτε στη συνέχεια να κάνετε extract με τα παρεχόμενα aastuff tools.


### Local Kerlnelcache

Στο iOS βρίσκεται στο **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. Στο macOS μπορείτε να το βρείτε με: **`find / -name "kernelcache" 2>/dev/null`** \
Στη δική μου περίπτωση, στο macOS το βρήκα στο:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Βρείτε επίσης εδώ το [**kernelcache της version 14 με symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Το IMG4 file format είναι ένα container format που χρησιμοποιείται από την Apple στις iOS και macOS συσκευές της για την ασφαλή **αποθήκευση και επαλήθευση firmware** components (όπως το **kernelcache**). Το IMG4 format περιλαμβάνει ένα header και αρκετά tags, τα οποία encapsulate διαφορετικά τμήματα δεδομένων, συμπεριλαμβανομένου του actual payload (όπως ένας kernel ή bootloader), ενός signature και ενός συνόλου manifest properties. Το format υποστηρίζει cryptographic verification, επιτρέποντας στη συσκευή να επιβεβαιώσει την αυθεντικότητα και την ακεραιότητα του firmware component πριν από την εκτέλεσή του.

Συνήθως αποτελείται από τα ακόλουθα components:

- **Payload (IM4P)**:
- Συχνά compressed (LZFSE4, LZSS, …)
- Προαιρετικά encrypted
- **Manifest (IM4M)**:
- Περιέχει Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- Γνωστό και ως APNonce
- Αποτρέπει το replay ορισμένων updates
- OPTIONAL: Συνήθως δεν εντοπίζεται

Κάντε decompress το Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Σύμβολα του `Disarm` για τον kernel

Το **`Disarm`** επιτρέπει τη συμβολοποίηση συναρτήσεων από το kernelcache χρησιμοποιώντας matchers. Αυτοί οι matchers είναι απλοί κανόνες μοτίβων (γραμμές κειμένου) που告诉 στο disarm πώς να αναγνωρίζει και να εκτελεί αυτόματα symbolicate σε συναρτήσεις, ορίσματα και συμβολοσειρές panic/log μέσα σε ένα binary.

Βασικά, υποδεικνύετε τη συμβολοσειρά που χρησιμοποιεί μια συνάρτηση και το disarm θα τη βρει και θα κάνει **symbolicate**.

Μπορείτε να βρείτε ορισμένα `xnu.matchers` στο [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), στην ενότητα **`Matchers`**. Μπορείτε επίσης να δημιουργήσετε τους δικούς σας matchers.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Λήψη

Ένα **IPSW (iPhone/iPad Software)** είναι η μορφή πακέτου firmware της Apple που χρησιμοποιείται για επαναφορές συσκευών, updates και πλήρη firmware bundles. Μεταξύ άλλων, περιέχει το **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Στο [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) είναι δυνατός ο εντοπισμός όλων των kernel debug kits. Μπορείτε να το κατεβάσετε, να το κάνετε mount, να το ανοίξετε με το εργαλείο [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), να αποκτήσετε πρόσβαση στον φάκελο **`.kext`** και να το **εξαγάγετε**.

Ελέγξτε το για symbols με:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Μερικές φορές η Apple κυκλοφορεί **kernelcache** με **symbols**. Μπορείτε να κατεβάσετε ορισμένα firmwares με symbols ακολουθώντας τους συνδέσμους σε αυτές τις σελίδες. Τα firmwares θα περιέχουν το **kernelcache**, μεταξύ άλλων αρχείων.

Για να **extract** το kernel cache, μπορείτε να εκτελέσετε:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Μια άλλη επιλογή για να **εξαγάγετε** τα αρχεία είναι να ξεκινήσετε αλλάζοντας την επέκταση από `.ipsw` σε `.zip` και να κάνετε **unzip**.

Μετά την εξαγωγή του firmware, θα λάβετε ένα αρχείο όπως το: **`kernelcache.release.iphone14`**. Είναι σε μορφή **IMG4** και μπορείτε να εξαγάγετε τις χρήσιμες πληροφορίες με:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Έλεγχος του kernelcache

Ελέγξτε αν το kernelcache διαθέτει symbols με
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Με αυτό μπορούμε πλέον να **εξαγάγουμε όλες τις επεκτάσεις** ή **εκείνη που σας ενδιαφέρει:**
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
## Πρόσφατα vulnerabilities & τεχνικές exploitation

| Έτος | CVE | Περίληψη |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Ένα λογικό σφάλμα στο **`storagekitd`** επέτρεπε σε έναν *root* attacker να καταχωρίσει ένα κακόβουλο file-system bundle, το οποίο τελικά φόρτωνε ένα **unsigned kext**, **παρακάμπτοντας το System Integrity Protection (SIP)** και επιτρέποντας persistent rootkits. Διορθώθηκε στα macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Ένας installation daemon με το entitlement `com.apple.rootless.install` μπορούσε να γίνει αντικείμενο abuse για την εκτέλεση arbitrary post-install scripts, την απενεργοποίηση του SIP και τη φόρτωση arbitrary kexts. <sup>[[3]](#references)</sup> |

**Βασικά συμπεράσματα για red-teamers**

1. **Αναζητήστε entitled daemons (`codesign -dvv /path/bin | grep entitlements`) που αλληλεπιδρούν με τα Disk Arbitration, Installer ή Kext Management.**
2. **Η εκμετάλλευση SIP bypasses σχεδόν πάντα παρέχει τη δυνατότητα φόρτωσης ενός kext → kernel code execution**.

**Συμβουλές άμυνας**

*Διατηρήστε το SIP ενεργοποιημένο*, παρακολουθείτε invocations των `kmutil load`/`kmutil create -n aux` που προέρχονται από non-Apple binaries και δημιουργήστε alert για κάθε εγγραφή στο `/Library/Extensions`. Τα Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` παρέχουν σχεδόν real-time ορατότητα.

## Debugging του macOS kernel & των kexts

Η προτεινόμενη από την Apple διαδικασία είναι να δημιουργήσετε ένα **Kernel Debug Kit (KDK)** που αντιστοιχεί στο running build και, στη συνέχεια, να συνδεθείτε με το **LLDB** μέσω μιας network session **KDP (Kernel Debugging Protocol)**.

### One-shot local debugging ενός panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging από άλλο Mac

1. Κατεβάστε και εγκαταστήστε την ακριβή έκδοση **KDK** για το μηχάνημα-στόχο.
2. Συνδέστε το Mac-στόχο και το Mac-host με καλώδιο **USB-C ή Thunderbolt**.
3. Στο **target**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Στον **host**:
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
> ℹ️ Το KDP εκθέτει μόνο ένα **read-only** interface. Για dynamic instrumentation θα χρειαστεί να κάνετε patch στο binary που βρίσκεται στον δίσκο, να αξιοποιήσετε **kernel function hooking** (π.χ. `mach_override`) ή να μεταφέρετε τον driver σε έναν **hypervisor** για πλήρες read/write.

## Αναφορές

- [1] [Ασφάλεια του DriverKit για macOS - Οδηγός Apple Platform Security](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Ανάλυση του CVE-2024-44243, ενός bypass του macOS System Integrity Protection μέσω kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Η Microsoft εντοπίζει νέα ευπάθεια στο macOS, το Shrootless, που θα μπορούσε να παρακάμψει το System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
