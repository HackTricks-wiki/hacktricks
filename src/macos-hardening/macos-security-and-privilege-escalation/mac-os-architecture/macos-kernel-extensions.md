# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) είναι **πακέτα** με επέκταση **`.kext`** που **φορτώνονται απευθείας στον χώρο πυρήνα του macOS**, παρέχοντας επιπλέον λειτουργικότητα στο κύριο λειτουργικό σύστημα.

### Deprecation status & DriverKit / System Extensions
Από το **macOS Catalina (10.15)** η Apple χαρακτήρισε τις περισσότερες legacy KPIs ως *deprecated* και εισήγαγε τα frameworks **System Extensions & DriverKit** που εκτελούνται σε **user-space**. Από το **macOS Big Sur (11)** το λειτουργικό σύστημα θα *αρνηθεί να φορτώσει* third-party kexts που βασίζονται σε deprecated KPIs εκτός αν η μηχανή εκκινήσει σε **Reduced Security** mode. Σε Apple Silicon, η ενεργοποίηση kexts απαιτεί επιπλέον από τον χρήστη να:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

Τα user-land drivers γραμμένα με DriverKit/System Extensions μειώνουν δραστικά την **επιφάνεια επίθεσης**, επειδή crashes ή memory corruption περιορίζονται σε μια sandboxed process αντί για τον χώρο του πυρήνα.

> 📝 Από το macOS Sequoia (15) η Apple έχει αφαιρέσει εντελώς αρκετά legacy networking και USB KPIs – η μόνη forward-compatible λύση για vendors είναι να μεταβούν σε System Extensions.

### Requirements

Προφανώς, αυτό είναι τόσο ισχυρό που είναι **περίπλοκο να φορτωθεί μια kernel extension**. Αυτά είναι τα **προαπαιτούμενα** που πρέπει να πληροί μια kernel extension για να φορτωθεί:

- Όταν **εισέρχεστε σε recovery mode**, οι kernel **extensions πρέπει να επιτρέπεται** να φορτωθούν:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Η kernel extension πρέπει να είναι **υπογεγραμμένη με kernel code signing certificate**, το οποίο μπορεί να παραχωρηθεί μόνο από Apple. Η Apple θα ελέγξει με λεπτομέρεια την εταιρεία και τους λόγους για τους οποίους είναι απαραίτητο.
- Η kernel extension πρέπει επίσης να είναι **notarized**, έτσι ώστε η Apple να μπορεί να την ελέγξει για malware.
- Στη συνέχεια, ο χρήστης **root** είναι αυτός που μπορεί να **φορτώσει την kernel extension** και τα αρχεία μέσα στο πακέτο πρέπει να **ανήκουν στον root**.
- Κατά τη διάρκεια της διαδικασίας upload, το πακέτο πρέπει να προετοιμαστεί σε μια **προστατευμένη τοποθεσία μη-root**: `/Library/StagedExtensions` (απαιτεί το `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Τέλος, κατά την προσπάθεια φόρτωσης, ο χρήστης θα [**λάβει αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) και, αν γίνει αποδεκτό, ο υπολογιστής πρέπει να **επανεκκινηθεί** για να το φορτώσει.

### Loading process

Στην Catalina ήταν ως εξής: Είναι ενδιαφέρον να σημειωθεί ότι η διαδικασία **επαλήθευσης** συμβαίνει στο **userland**. Ωστόσο, μόνο εφαρμογές με το **`com.apple.private.security.kext-management`** grant μπορούν να **ζητήσουν από τον kernel να φορτώσει μια extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **ξεκινάει** τη διαδικασία **επαλήθευσης** για τη φόρτωση μιας extension
- Θα επικοινωνήσει με **`kextd`** χρησιμοποιώντας μια **Mach service**.
2. **`kextd`** θα ελέγξει διάφορα πράγματα, όπως την **υπογραφή**
- Θα επικοινωνήσει με **`syspolicyd`** για να **ελέγξει** αν η extension μπορεί να **φορτωθεί**.
3. **`syspolicyd`** θα **εμφανίσει προτροπή** στον **χρήστη** αν η extension δεν έχει φορτωθεί προηγουμένως.
- **`syspolicyd`** θα αναφέρει το αποτέλεσμα στο **`kextd`**
4. **`kextd`** τελικά θα μπορεί να **πει στον kernel να φορτώσει** την extension

Αν το **`kextd`** δεν είναι διαθέσιμο, το **`kextutil`** μπορεί να εκτελέσει τους ίδιους ελέγχους.

### Enumeration & management (loaded kexts)

`kextstat` ήταν το ιστορικό εργαλείο αλλά είναι **deprecated** σε πρόσφατες εκδόσεις του macOS. Η σύγχρονη διεπαφή είναι **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Η παλαιότερη σύνταξη εξακολουθεί να είναι διαθέσιμη για αναφορά:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` μπορεί επίσης να χρησιμοποιηθεί για **dump the contents of a Kernel Collection (KC)** ή να επαληθεύσει ότι ένα kext επιλύει όλες τις εξαρτήσεις συμβόλων:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Παρόλο που οι kernel extensions αναμένονται στο `/System/Library/Extensions/`, αν μπεις σε αυτόν τον φάκελο **δεν θα βρεις κανένα binary**. Αυτό οφείλεται στο **kernelcache** και για να κάνεις reverse σε ένα `.kext` πρέπει να βρεις τρόπο να το αποκτήσεις.

Η **kernelcache** είναι μια **προ-μεταγλωττισμένη και προ-συνδεδεμένη έκδοση του XNU kernel**, μαζί με τους απαραίτητους device **drivers** και **kernel extensions**. Αποθηκεύεται σε **συμπιεσμένη** μορφή και αποσυμπιέζεται στη μνήμη κατά τη διάρκεια της διαδικασίας εκκίνησης. Η kernelcache διευκολύνει ένα **ταχύτερο χρόνο εκκίνησης** έχοντας μια έτοιμη προς εκτέλεση έκδοση του kernel και κρίσιμους drivers διαθέσιμους, μειώνοντας τον χρόνο και τους πόρους που διαφορετικά θα δαπανούνταν για τη δυναμική φόρτωση και σύνδεση αυτών των συστατικών κατά την εκκίνηση.

Τα κύρια οφέλη του kernelcache είναι η **ταχύτητα φόρτωσης** και το ότι όλα τα modules είναι προ-linked (χωρίς καθυστέρηση φόρτωσης). Επιπλέον, μόλις όλα τα modules έχουν προ-linked, το KXLD μπορεί να αφαιρεθεί από τη μνήμη ώστε **το XNU να μην μπορεί να φορτώσει νέα KEXTs.**

> [!TIP]
> Το εργαλείο [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) αποκρυπτογραφεί τα Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — τη κρυπτογραφημένη μορφή container που χρησιμοποιεί η Apple για OTA assets και κάποια κομμάτια IPSW — και μπορεί να παράξει το υποκείμενο .dmg/asset archive που μπορείς στη συνέχεια να εξάγεις με τα παρεχόμενα εργαλεία aastuff.

### Local Kerlnelcache

Στο iOS βρίσκεται στο **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. Στο macOS μπορείς να το βρεις με: **`find / -name "kernelcache" 2>/dev/null`** \
Στη δική μου περίπτωση στο macOS το βρήκα σε:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Η μορφή αρχείου IMG4 είναι ένα container format που χρησιμοποιεί η Apple στις συσκευές iOS και macOS για την ασφαλή **αποθήκευση και επαλήθευση firmware** συστατικών (όπως το **kernelcache**). Η μορφή IMG4 περιλαμβάνει μια κεφαλίδα και διάφορα tags που ενθυλακώνουν διαφορετικά κομμάτια δεδομένων, συμπεριλαμβανομένου του πραγματικού payload (όπως ένα kernel ή bootloader), μιας υπογραφής, και ενός συνόλου manifest properties. Η μορφή υποστηρίζει κρυπτογραφική επαλήθευση, επιτρέποντας στη συσκευή να επιβεβαιώσει την αυθεντικότητα και την ακεραιότητα του firmware πριν το εκτελέσει.

It's usually composed of the following components:

- **Payload (IM4P)**:
- Συνήθως συμπιεσμένο (LZFSE4, LZSS, …)
- Προαιρετικά κρυπτογραφημένο
- **Manifest (IM4M)**:
- Περιέχει Signature
- Επιπρόσθετο Key/Value dictionary
- **Restore Info (IM4R)**:
- Επίσης γνωστό ως APNonce
- Αποτρέπει το replay ορισμένων ενημερώσεων
- OPTIONAL: Συνήθως αυτό δεν βρίσκεται

Decompress the Kernelcache:
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
#### Disarm σύμβολα για τον kernel

**`Disarm`** επιτρέπει να symbolicate συναρτήσεις από το kernelcache χρησιμοποιώντας matchers. Αυτοί οι matchers είναι απλώς απλοί κανόνες μοτίβου (γραμμές κειμένου) που λένε στο disarm πώς να αναγνωρίσει και να auto-symbolicate συναρτήσεις, ορίσματα και panic/log strings μέσα σε ένα binary.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Μεταβείτε στο /tmp/extracted όπου το disarm εξήγαγε τα filesets
disarm -e filesets kernelcache.release.d23 # Πάντα εξάγετε στο /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Σημείωση ότι το xnu.matchers είναι στην πραγματικότητα ένα αρχείο με τους matchers
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
# Εγκατάσταση του εργαλείου ipsw
brew install blacktop/tap/ipsw

# Εξαγωγή μόνο του kernelcache από το IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Θα πρέπει να λάβετε κάτι σαν:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

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
# Λίστα όλων των επεκτάσεων
kextex -l kernelcache.release.iphone14.e
## Εξαγωγή com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Εξαγωγή όλων
kextex_all kernelcache.release.iphone14.e

# Έλεγχος της επέκτασης για σύμβολα
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
# Δημιουργήστε ένα πακέτο συμβολοποίησης για το πιο πρόσφατο panic
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
(lldb) bt  # λάβετε backtrace σε kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Εντοπισμός διεύθυνσης φόρτωσης του kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Σύνδεση
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
