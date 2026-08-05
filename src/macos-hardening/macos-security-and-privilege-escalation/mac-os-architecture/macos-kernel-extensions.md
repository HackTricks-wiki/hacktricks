# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα Kernel extensions (Kexts) είναι **packages** με επέκταση **`.kext`**, τα οποία **φορτώνονται απευθείας στον χώρο του kernel του macOS**, παρέχοντας πρόσθετη λειτουργικότητα στο κύριο λειτουργικό σύστημα.

### Κατάσταση κατάργησης & DriverKit / System Extensions
Ξεκινώντας με το **macOS Catalina (10.15)**, η Apple χαρακτήρισε τα περισσότερα παλαιά KPI ως *deprecated* και εισήγαγε τα frameworks **System Extensions & DriverKit**, τα οποία εκτελούνται σε **user-space**. Από το **macOS Big Sur (11)**, το λειτουργικό σύστημα θα *αρνείται να φορτώσει* third-party kexts που βασίζονται σε deprecated KPIs, εκτός αν το μηχάνημα έχει εκκινηθεί σε λειτουργία **Reduced Security**. Σε Apple Silicon, η ενεργοποίηση των kexts απαιτεί επιπλέον από τον χρήστη:

1. Επανεκκίνηση σε **Recovery** → *Startup Security Utility*.
2. Επιλογή του **Reduced Security** και ενεργοποίηση του **“Allow user management of kernel extensions from identified developers”**.
3. Επανεκκίνηση και έγκριση του kext από τις **System Settings → Privacy & Security**.

Οι user-land drivers που έχουν γραφτεί με DriverKit/System Extensions **μειώνουν σημαντικά την attack surface**, επειδή τα crashes ή η καταστροφή μνήμης περιορίζονται σε μια διεργασία με sandbox αντί για τον χώρο του kernel.<sup>[[1]](#references)</sup>

> 📝 Από το macOS Sequoia (15), η Apple έχει αφαιρέσει πλήρως αρκετά παλαιά networking και USB KPIs – η μόνη λύση με forward compatibility για τους vendors είναι η μετάβαση σε System Extensions.

### Απαιτήσεις

Προφανώς, αυτό είναι τόσο ισχυρό, ώστε η **φόρτωση ενός kernel extension** να είναι **περίπλοκη**. Αυτές είναι οι **απαιτήσεις** που πρέπει να πληροί ένα kernel extension για να φορτωθεί:

- Κατά την **είσοδο σε recovery mode**, πρέπει να επιτρέπεται η φόρτωση των kernel **extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Το kernel extension πρέπει να είναι **υπογεγραμμένο με πιστοποιητικό kernel code signing**, το οποίο μπορεί να **χορηγηθεί μόνο από την Apple**. Η Apple θα εξετάσει λεπτομερώς την εταιρεία και τους λόγους για τους οποίους απαιτείται.
- Το kernel extension πρέπει επίσης να είναι **notarized** και η Apple θα μπορεί να το ελέγξει για malware.
- Στη συνέχεια, ο χρήστης **root** είναι αυτός που μπορεί να **φορτώσει το kernel extension** και τα αρχεία μέσα στο package πρέπει να **ανήκουν στον root**.
- Κατά τη διαδικασία upload, το package πρέπει να προετοιμαστεί σε μια **προστατευμένη τοποθεσία που δεν ανήκει στον root**: `/Library/StagedExtensions` (απαιτεί το grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Τέλος, κατά την προσπάθεια φόρτωσής του, ο χρήστης θα [**λάβει ένα αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) και, αν το αποδεχτεί, ο υπολογιστής πρέπει να **επανεκκινηθεί** για να φορτωθεί.

### Διαδικασία φόρτωσης

Στο Catalina η διαδικασία ήταν η εξής: Είναι ενδιαφέρον να σημειωθεί ότι η διαδικασία **επαλήθευσης** πραγματοποιείται σε **userland**. Ωστόσο, μόνο εφαρμογές με το grant **`com.apple.private.security.kext-management`** μπορούν να **ζητήσουν από τον kernel να φορτώσει ένα extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. Το **`kextutil`** cli **ξεκινά** τη διαδικασία **επαλήθευσης** για τη φόρτωση ενός extension
- Θα επικοινωνήσει με το **`kextd`** στέλνοντας δεδομένα μέσω μιας **Mach service**.
2. Το **`kextd`** θα ελέγξει διάφορα στοιχεία, όπως την **υπογραφή**
- Θα επικοινωνήσει με το **`syspolicyd`** για να **ελέγξει** αν επιτρέπεται να **φορτωθεί** το extension.
3. Το **`syspolicyd`** θα **ζητήσει επιβεβαίωση από τον** **χρήστη** αν το extension δεν έχει φορτωθεί προηγουμένως.
- Το **`syspolicyd`** θα αναφέρει το αποτέλεσμα στο **`kextd`**
4. Το **`kextd`** θα μπορεί τελικά να **ζητήσει από τον kernel να φορτώσει** το extension

Αν το **`kextd`** δεν είναι διαθέσιμο, το **`kextutil`** μπορεί να εκτελέσει τους ίδιους ελέγχους.

### Enumeration & management (loaded kexts)

Το `kextstat` ήταν το ιστορικό εργαλείο, αλλά είναι **deprecated** στις πρόσφατες εκδόσεις του macOS. Η σύγχρονη διεπαφή είναι το **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Η παλαιότερη σύνταξη παραμένει διαθέσιμη για αναφορά:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
Το `kmutil inspect` μπορεί επίσης να αξιοποιηθεί για **την απόρριψη των περιεχομένων ενός Kernel Collection (KC)** ή για την επαλήθευση ότι ένα kext επιλύει όλες τις εξαρτήσεις συμβόλων:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Παρόλο που αναμένεται οι kernel extensions να βρίσκονται στο `/System/Library/Extensions/`, αν μεταβείτε σε αυτόν τον φάκελο **δεν θα βρείτε κανένα binary**. Αυτό οφείλεται στο **kernelcache** και, για να κάνετε reverse engineering σε ένα `.kext`, πρέπει να βρείτε έναν τρόπο να το αποκτήσετε.

Το **kernelcache** είναι μια **προμεταγλωττισμένη και προ-συνδεδεμένη έκδοση του XNU kernel**, μαζί με απαραίτητα **drivers** συσκευών και **kernel extensions**. Αποθηκεύεται σε **συμπιεσμένη** μορφή και αποσυμπιέζεται στη μνήμη κατά τη διαδικασία εκκίνησης. Το kernelcache επιτρέπει **ταχύτερο χρόνο εκκίνησης**, καθώς παρέχει μια έτοιμη προς εκτέλεση έκδοση του kernel και των κρίσιμων drivers, μειώνοντας τον χρόνο και τους πόρους που διαφορετικά θα απαιτούνταν για τη δυναμική φόρτωση και σύνδεση αυτών των στοιχείων κατά την εκκίνηση.

Τα κύρια οφέλη του kernelcache είναι η **ταχύτητα φόρτωσης** και το γεγονός ότι όλα τα modules είναι prelinked (χωρίς επιβάρυνση κατά τον χρόνο φόρτωσης). Και αφού όλα τα modules έχουν γίνει prelinked, το KXLD μπορεί να αφαιρεθεί από τη μνήμη, επομένως το **XNU δεν μπορεί να φορτώσει νέα KEXTs.**

> [!TIP]
> Το εργαλείο [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) αποκρυπτογραφεί τα containers AEA (Apple Encrypted Archive / AEA asset) της Apple — τη μορφή encrypted container που χρησιμοποιεί η Apple για OTA assets και ορισμένα τμήματα IPSW — και μπορεί να παραγάγει το υποκείμενο .dmg/asset archive, το οποίο μπορείτε στη συνέχεια να εξαγάγετε με τα παρεχόμενα εργαλεία aastuff.


### Τοπικό Kerlnelcache

Στο iOS βρίσκεται στο **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. Στο macOS μπορείτε να το βρείτε με: **`find / -name "kernelcache" 2>/dev/null`** \
Στην περίπτωσή μου, στο macOS το βρήκα εδώ:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Βρείτε επίσης εδώ το [**kernelcache της έκδοσης 14 με symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) συμπιεσμένο

Η μορφή αρχείων IMG4 είναι μια μορφή container που χρησιμοποιείται από την Apple στις συσκευές iOS και macOS για την ασφαλή **αποθήκευση και επαλήθευση στοιχείων firmware** (όπως το **kernelcache**). Η μορφή IMG4 περιλαμβάνει ένα header και αρκετά tags που ενσωματώνουν διαφορετικά τμήματα δεδομένων, συμπεριλαμβανομένου του πραγματικού payload (όπως έναν kernel ή bootloader), μιας υπογραφής και ενός συνόλου ιδιοτήτων manifest. Η μορφή υποστηρίζει cryptographic verification, επιτρέποντας στη συσκευή να επιβεβαιώνει την αυθεντικότητα και την ακεραιότητα του firmware component πριν από την εκτέλεσή του.

Συνήθως αποτελείται από τα ακόλουθα components:

- **Payload (IM4P)**:
- Συχνά συμπιεσμένο (LZFSE4, LZSS, …)
- Προαιρετικά encrypted
- **Manifest (IM4M)**:
- Περιέχει Signature
- Πρόσθετο Key/Value dictionary
- **Restore Info (IM4R)**:
- Επίσης γνωστό ως APNonce
- Αποτρέπει το replay ορισμένων updates
- OPTIONAL: Συνήθως δεν βρίσκεται

Αποσυμπιέστε το Kernelcache:
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
#### Απενεργοποίηση συμβόλων για τον kernel

Το **`Disarm`** επιτρέπει το symbolication συναρτήσεων από το kernelcache χρησιμοποιώντας matchers. Αυτοί οι matchers είναι απλοί κανόνες μοτίβων (γραμμές κειμένου) που λένε στο disarm πώς να αναγνωρίζει και να εκτελεί αυτόματο symbolication συναρτήσεων, arguments και συμβολοσειρών panic/log μέσα σε ένα binary.

Βασικά, υποδεικνύετε τη συμβολοσειρά που χρησιμοποιεί μια συνάρτηση και το disarm θα τη βρει και θα εκτελέσει **symbolication**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Μεταβείτε στο /tmp/extracted όπου το disarm εξήγαγε τα filesets
disarm -e filesets kernelcache.release.d23 # Να κάνετε πάντα extract στο /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Σημειώστε ότι το xnu.matchers είναι στην πραγματικότητα ένα αρχείο με τα matchers
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Εγκατάσταση του ipsw tool
brew install blacktop/tap/ipsw

# Εξαγωγή μόνο του kernelcache από το IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Θα πρέπει να λάβετε κάτι σαν:
#   out/Firmware/kernelcache.release.iPhoneXX
#   ή ένα IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Αν λάβετε ένα IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Λίστα όλων των extensions
kextex -l kernelcache.release.iphone14.e
## Εξαγωγή του com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Εξαγωγή όλων
kextex_all kernelcache.release.iphone14.e

# Έλεγχος του extension για symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Δημιουργία ενός symbolication bundle για το πιο πρόσφατο panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # λήψη backtrace σε kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Εντοπισμός της διεύθυνσης φόρτωσης του kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
