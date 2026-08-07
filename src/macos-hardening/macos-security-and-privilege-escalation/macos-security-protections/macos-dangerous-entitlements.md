# Επικίνδυνα Entitlements και TCC perms στο macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε third-parties· μόνο η Apple μπορεί να τα εκχωρήσει... Ή, αν χρησιμοποιείτε enterprise certificate, θα μπορούσατε στην πραγματικότητα να δημιουργήσετε τα δικά σας entitlements που ξεκινούν με **`com.apple`** και να παρακάμψετε protections που βασίζονται σε αυτό.

## Υψηλό

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει την **παράκαμψη του SIP**. Δείτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει την **παράκαμψη του SIP**. Δείτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (προηγουμένως ονομαζόταν `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει τη λήψη του **task port για οποιοδήποτε** process, εκτός από τον kernel. Δείτε [**εδώ για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλα processes με το entitlement **`com.apple.security.cs.debugger`** να αποκτήσουν το task port του process που εκτελείται από το binary με αυτό το entitlement και να κάνουν **inject code σε αυτό**. Δείτε [**εδώ για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με το Debugging Tool Entitlement μπορούν να καλέσουν τη `task_for_pid()` για να ανακτήσουν ένα έγκυρο task port για unsigned και third-party apps με ενεργοποιημένο το entitlement `Get Task Allow` και την τιμή `true`. Ωστόσο, ακόμη και με το debugging tool entitlement, ένας debugger **δεν μπορεί να αποκτήσει τα task ports** processes που **δεν έχουν το entitlement `Get Task Allow`** και επομένως προστατεύονται από το System Integrity Protection. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει τη **φόρτωση frameworks, plug-ins ή libraries χωρίς να είναι υπογεγραμμένα είτε από την Apple είτε με το ίδιο Team ID** με το main executable, επομένως ένας attacker θα μπορούσε να εκμεταλλευτεί κάποιο arbitrary library load για να κάνει inject code. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με το **`com.apple.security.cs.disable-library-validation`**, αλλά **αντί να απενεργοποιεί άμεσα** το library validation, επιτρέπει στο process να **καλέσει ένα `csops` system call για να το απενεργοποιήσει** κατά το runtime.

Το όνομα του entitlement είναι hardcoded στο XNU, δίπλα στη λειτουργία `csops` που το χρησιμοποιεί:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Ο handler του kernel για το `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) δείχνει ακριβώς πόσο περιορισμένο είναι το primitive:<sup>[[2]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Άρα η λειτουργία:

- Είναι **macOS-only** (`ENOTSUP` σε κάθε άλλη πλατφόρμα).
- Λειτουργεί μόνο στο **ίδιο το process** (`forself == 1`) — δεν μπορείτε να αφαιρέσετε το library validation από άλλη διεργασία μέσω αυτής.
- Απαιτεί το process να **κατέχει πράγματι το entitlement** και αρνείται να εκτελεστεί αν το process έχει τη σημαία `CS_INSTALLER` ή εκτελείται κάτω από ένα subsystem root path.
- Αφαιρεί τα **`CS_REQUIRE_LV | CS_FORCED_LV`** από τα code-signing flags του process.

Το σχόλιο του XNU εξηγεί την προβλεπόμενη περίπτωση χρήσης, καθώς και γιατί είναι ενδιαφέρον για έναν attacker:

> Αυτή η επιλογή χρησιμοποιείται για την αφαίρεση του library validation από ένα running process. Χρησιμοποιείται σε plugin architectures όταν ένα πρόγραμμα χρειάζεται να φορτώσει untrusted libraries. [...] Μόλις ένα process φορτώσει την untrusted library, η μελλοντική εξάρτηση από το library validation δεν θα είναι αποτελεσματική.

Με άλλα λόγια, **κάθε binary που διαθέτει αυτό το entitlement είναι στόχος για dylib injection**: εκτελέστε κώδικα μέσα σε αυτό (ή πείστε το να φορτώσει το plug-in σας) αφού έχει αφαιρέσει το `CS_REQUIRE_LV`, και αποκτάτε τις δυνατότητες που έχει το host process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει τη **χρήση μεταβλητών περιβάλλοντος DYLD**, οι οποίες θα μπορούσαν να χρησιμοποιηθούν για την εισαγωγή libraries και κώδικα. Δείτε [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ή `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **και** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν την **τροποποίηση** της βάσης δεδομένων **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** και **`system.install.apple-software.standar-user`**

Αυτά τα entitlements επιτρέπουν την **εγκατάσταση software χωρίς να ζητείται άδεια** από τον χρήστη, κάτι που μπορεί να βοηθήσει σε μια **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement που απαιτείται για να ζητηθεί από τον **kernel η φόρτωση ενός kernel extension**.

### **`com.apple.private.icloud-account-access`**

Με το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατή η επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Τα **iMovie** και **Garageband** διέθεταν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για τη **λήψη iCloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν γνωρίζω τι επιτρέπει να γίνει αυτό

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Σε [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για την** ενημέρωση του SSV-protected περιεχομένου μετά από reboot. Αν γνωρίζετε πώς λειτουργεί, στείλτε ένα PR παρακαλώ!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Σε [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για την** ενημέρωση του SSV-protected περιεχομένου μετά από reboot. Αν γνωρίζετε πώς λειτουργεί, στείλτε ένα PR παρακαλώ!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Αυτό το entitlement παραθέτει τις ομάδες **keychain** στις οποίες έχει πρόσβαση η εφαρμογή:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Παρέχει δικαιώματα **Full Disk Access**, μία από τις υψηλότερου επιπέδου άδειες TCC που μπορείτε να έχετε.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει events σε άλλες εφαρμογές που χρησιμοποιούνται συνήθως για **αυτοματοποίηση εργασιών**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τα δικαιώματα που έχουν παραχωρηθεί σε αυτές.

Για παράδειγμα, μπορεί να τις κάνει να ζητήσουν από τον χρήστη τον κωδικό πρόσβασής του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ή κάνοντάς τα να εκτελούν **αυθαίρετες ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων, την **εγγραφή στη βάση δεδομένων TCC του χρήστη**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει την **αλλαγή** του attribute **`NFSHomeDirectory`** ενός χρήστη, γεγονός που αλλάζει τη διαδρομή του home folder του και επομένως επιτρέπει την **παράκαμψη του TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα στα app bundles (μέσα στο app.app), κάτι που **απαγορεύεται από προεπιλογή**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να ελέγξετε ποιοι έχουν αυτή την πρόσβαση από _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Η διεργασία θα μπορεί να κάνει **abuse των δυνατοτήτων προσβασιμότητας του macOS**, πράγμα που σημαίνει, για παράδειγμα, ότι θα μπορεί να πατάει keystrokes. Επομένως, θα μπορούσε να ζητήσει πρόσβαση για τον έλεγχο μιας εφαρμογής όπως το Finder και να εγκρίνει το dialog με αυτή την άδεια.

## Entitlements που σχετίζονται με το Trustcache/CDhash

Υπάρχουν ορισμένα entitlements που θα μπορούσαν να χρησιμοποιηθούν για την παράκαμψη των προστασιών Trustcache/CDhash, οι οποίες εμποδίζουν την εκτέλεση downgraded εκδόσεων των Apple binaries.

## Μέτριο

### `com.apple.security.cs.allow-jit`

Αυτό το entitlement επιτρέπει τη **δημιουργία μνήμης που είναι writable και executable**, με τη μεταβίβαση του flag `MAP_JIT` στη system function `mmap()`. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτό το entitlement επιτρέπει το **override ή patch C code**, τη χρήση του long-deprecated **`NSCreateObjectFileImageFromMemory`** (το οποίο είναι fundamentally insecure) ή τη χρήση του framework **DVDPlayback**. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Η συμπερίληψη αυτού του entitlement εκθέτει την εφαρμογή σας σε common vulnerabilities σε memory-unsafe code languages. Εξετάστε προσεκτικά αν η εφαρμογή σας χρειάζεται αυτή την εξαίρεση.

### `com.apple.security.cs.disable-executable-page-protection`

Αυτό το entitlement επιτρέπει την **τροποποίηση sections των δικών του executable files** στον δίσκο, ώστε να πραγματοποιείται forceful exit. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Το Disable Executable Memory Protection Entitlement είναι ένα extreme entitlement που αφαιρεί μια θεμελιώδη security protection από την εφαρμογή σας, καθιστώντας δυνατό για έναν attacker να ξαναγράψει τον executable code της εφαρμογής σας χωρίς detection. Προτιμήστε narrower entitlements, αν είναι δυνατό.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτό το entitlement επιτρέπει την προσάρτηση ενός nullfs file system (απαγορεύεται από προεπιλογή). Εργαλείο: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτό το blogpost, αυτή η άδεια TCC βρίσκεται συνήθως στη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέπει στη διεργασία να **ζητήσει όλα τα TCC permissions**.

### **`kTCCServicePostEvent`**

Επιτρέπει την **εισαγωγή συνθετικών συμβάντων πληκτρολογίου και ποντικιού** σε όλο το σύστημα μέσω της `CGEventPost()`. Μια διεργασία με αυτό το permission μπορεί να προσομοιώσει πατήματα πλήκτρων, κλικ του ποντικιού και συμβάντα κύλισης σε οποιαδήποτε εφαρμογή — παρέχοντας ουσιαστικά **remote control** της επιφάνειας εργασίας.

Αυτό είναι ιδιαίτερα επικίνδυνο σε συνδυασμό με τα `kTCCServiceAccessibility` ή `kTCCServiceListenEvent`, καθώς επιτρέπει τόσο την ανάγνωση ΟΣΟ ΚΑΙ την εισαγωγή input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Επιτρέπει την **intercepting όλων των συμβάντων πληκτρολογίου και ποντικιού** σε όλο το σύστημα (input monitoring / keylogging). Μια διεργασία μπορεί να καταχωρίσει ένα `CGEventTap` για να καταγράφει κάθε πληκτρολόγηση σε οποιαδήποτε εφαρμογή, συμπεριλαμβανομένων κωδικών πρόσβασης, αριθμών πιστωτικών καρτών και ιδιωτικών μηνυμάτων.

Για λεπτομερείς exploitation techniques, δείτε:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Επιτρέπει την **ανάγνωση του display buffer** — τη λήψη screenshots και την καταγραφή video της οθόνης οποιασδήποτε εφαρμογής, συμπεριλαμβανομένων secure text fields. Σε συνδυασμό με OCR, αυτό μπορεί να εξάγει αυτόματα κωδικούς πρόσβασης και ευαίσθητα δεδομένα από την οθόνη.

> [!WARNING]
> Από το macOS Sonoma, το screen capture εμφανίζει μια μόνιμη ένδειξη στη menu bar. Σε παλαιότερες εκδόσεις, το screen recording μπορεί να πραγματοποιείται εντελώς αθόρυβα.

### **`kTCCServiceCamera`**

Επιτρέπει τη **λήψη φωτογραφιών και video** από την ενσωματωμένη κάμερα ή συνδεδεμένες κάμερες USB. Το code injection σε ένα camera-entitled binary επιτρέπει την αθόρυβη οπτική παρακολούθηση.

### **`kTCCServiceMicrophone`**

Επιτρέπει την **καταγραφή ήχου** από όλες τις συσκευές εισόδου. Background daemons με πρόσβαση στο μικρόφωνο παρέχουν persistent ambient audio surveillance χωρίς ορατό παράθυρο εφαρμογής.

### **`kTCCServiceLocation`**

Επιτρέπει την αναζήτηση της **φυσικής τοποθεσίας** της συσκευής μέσω τριγωνοποίησης Wi-Fi ή Bluetooth beacons. Η συνεχής παρακολούθηση αποκαλύπτει διευθύνσεις κατοικίας/εργασίας, μοτίβα μετακινήσεων και καθημερινές συνήθειες.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Πρόσβαση στις **Επαφές** (ονόματα, email, τηλέφωνα — χρήσιμα για spear-phishing), στο **Ημερολόγιο** (προγράμματα συναντήσεων, λίστες συμμετεχόντων) και στις **Φωτογραφίες** (προσωπικές φωτογραφίες, screenshots που ενδέχεται να περιέχουν credentials, metadata τοποθεσίας).

Για πλήρεις credential theft exploitation techniques μέσω TCC permissions, δείτε:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Οι **προσωρινές εξαιρέσεις του Sandbox** αποδυναμώνουν το App Sandbox, επιτρέποντας επικοινωνία με system-wide Mach/XPC services που κανονικά αποκλείονται από το sandbox. Αυτό είναι το **primary sandbox escape primitive** — μια compromised sandboxed app μπορεί να χρησιμοποιήσει mach-lookup exceptions για να προσεγγίσει privileged daemons και να εκμεταλλευτεί τα XPC interfaces τους.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Για λεπτομερή αλυσίδα exploitation: sandboxed app → mach-lookup exception → ευάλωτο daemon → sandbox escape, δείτε:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Τα **DriverKit entitlements** επιτρέπουν σε user-space driver binaries να επικοινωνούν απευθείας με τον kernel μέσω διεπαφών IOKit. Τα DriverKit binaries διαχειρίζονται hardware: USB, Thunderbolt, PCIe, HID devices, audio και networking.

Η παραβίαση ενός DriverKit binary επιτρέπει:
- **Kernel attack surface** μέσω κακοσχηματισμένων κλήσεων `IOConnectCallMethod`
- **USB device spoofing** (προσομοίωση πληκτρολογίου για HID injection)
- **DMA attacks** μέσω διεπαφών PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Για λεπτομερή exploitation του IOKit/DriverKit, δείτε:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Αναφορές

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [The Nightmare of Apple's OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
