# Επικίνδυνα Entitlements του macOS & δικαιώματα TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε third-parties, μόνο η Apple μπορεί να τα εκχωρήσει... Ή, αν χρησιμοποιείτε enterprise certificate, θα μπορούσατε να δημιουργήσετε τα δικά σας entitlements που ξεκινούν με **`com.apple`** και να παρακάμψετε protections που βασίζονται σε αυτό.

## Υψηλό

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει την **παράκαμψη του SIP**. Δείτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει την **παράκαμψη του SIP**. Δείτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (παλαιότερα ονομαζόταν `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει τη λήψη του **task port για οποιαδήποτε** process, εκτός από τον kernel. Δείτε [**εδώ για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλες processes με το entitlement **`com.apple.security.cs.debugger`** να αποκτήσουν το task port της process που εκτελείται από το binary με αυτό το entitlement και να κάνουν **inject code σε αυτήν**. Δείτε [**εδώ για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με το Debugging Tool Entitlement μπορούν να καλέσουν τη `task_for_pid()` για να ανακτήσουν ένα έγκυρο task port για unsigned και third-party apps με ενεργοποιημένο το entitlement `Get Task Allow` σε `true`. Ωστόσο, ακόμη και με το debugging tool entitlement, ένας debugger **δεν μπορεί να αποκτήσει τα task ports** processes που **δεν διαθέτουν το `Get Task Allow` entitlement** και επομένως προστατεύονται από το System Integrity Protection. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει τη **φόρτωση frameworks, plug-ins ή libraries χωρίς να είναι είτε signed από την Apple είτε signed με το ίδιο Team ID** όπως το κύριο executable, επομένως ένας attacker θα μπορούσε να καταχραστεί κάποια αυθαίρετη φόρτωση library για να κάνει inject code. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με το **`com.apple.security.cs.disable-library-validation`**, αλλά **αντί να απενεργοποιεί άμεσα** το library validation, επιτρέπει στη process να **καλέσει ένα `csops` system call για να το απενεργοποιήσει** κατά το runtime.

Το όνομα του entitlement είναι hardcoded στο XNU, δίπλα στο `csops` operation που το χρησιμοποιεί:<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Ο kernel handler για το `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) δείχνει ακριβώς πόσο περιορισμένο είναι το primitive:<sup>[[3]](#references)</sup>
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

- Είναι **μόνο για macOS** (`ENOTSUP` σε κάθε άλλη πλατφόρμα).
- Λειτουργεί μόνο στο **ίδιο το process** (`forself == 1`) — δεν μπορείτε να αφαιρέσετε το library validation από άλλο process μέσω αυτής.
- Απαιτεί το process να **διαθέτει πράγματι το entitlement** και απορρίπτει την ενέργεια αν το process έχει το flag `CS_INSTALLER` ή εκτελείται κάτω από ένα subsystem root path.
- Αφαιρεί τα **`CS_REQUIRE_LV | CS_FORCED_LV`** από τα code-signing flags του process.

Το σχόλιο του XNU εξηγεί την προβλεπόμενη περίπτωση χρήσης, καθώς και γιατί είναι ενδιαφέρον για έναν attacker:

> Αυτή η επιλογή χρησιμοποιείται για την αφαίρεση του library validation από ένα process που εκτελείται. Χρησιμοποιείται σε plugin architectures όταν ένα πρόγραμμα χρειάζεται να φορτώσει untrusted libraries. [...] Μόλις ένα process φορτώσει την untrusted library, η μελλοντική εξάρτηση από το library validation δεν θα είναι αποτελεσματική.

Με άλλα λόγια, **κάθε binary που διαθέτει αυτό το entitlement είναι στόχος για dylib-injection**: εκτελέστε code μέσα σε αυτό (ή πείστε το να φορτώσει το plug-in σας) αφού έχει αφαιρέσει το `CS_REQUIRE_LV`, και αποκτάτε ό,τι μπορεί να κάνει αξιόπιστα το host process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει τη **χρήση DYLD environment variables**, οι οποίες μπορούν να χρησιμοποιηθούν για την εισαγωγή libraries και code. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ή `com.apple.rootless.storage`.`TCC`

[**Σύμφωνα με αυτό το blog**](https://objective-see.org/blog/blog_0x4C.html) **και** [**αυτό το blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν την **τροποποίηση** της βάσης δεδομένων **TCC**.

### **`system.install.apple-software`** και **`system.install.apple-software.standar-user`**

Αυτά τα entitlements επιτρέπουν την **εγκατάσταση software χωρίς να ζητούνται δικαιώματα** από τον user, κάτι που μπορεί να βοηθήσει σε **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement που απαιτείται για να ζητηθεί από τον **kernel η φόρτωση ενός kernel extension**.

### **`com.apple.private.icloud-account-access`**

Με το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατή η επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Το **iMovie** και το **Garageband** διέθεταν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για την **απόκτηση iCloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν γνωρίζω τι επιτρέπει να γίνει

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Σε [**αυτή την αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για την** ενημέρωση των περιεχομένων που προστατεύονται από το SSV μετά από reboot. Αν γνωρίζετε πώς λειτουργεί, παρακαλώ στείλτε ένα PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Σε [**αυτή την αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για την** ενημέρωση των περιεχομένων που προστατεύονται από το SSV μετά από reboot. Αν γνωρίζετε πώς λειτουργεί, παρακαλώ στείλτε ένα PR!

### `keychain-access-groups`

Αυτό το entitlement παραθέτει τις ομάδες του **keychain** στις οποίες έχει πρόσβαση η εφαρμογή:
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

Παρέχει δικαιώματα **Full Disk Access**, μία από τις υψηλότερες άδειες TCC που μπορείτε να έχετε.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει events σε άλλες εφαρμογές που χρησιμοποιούνται συνήθως για **automating tasks**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τα δικαιώματα που έχουν εκχωρηθεί σε αυτές.

Για παράδειγμα, μπορεί να τις κάνει να ζητήσουν από τον χρήστη τον κωδικό πρόσβασής του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ή να τους κάνει να εκτελούν **αυθαίρετες ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων δικαιωμάτων, την **εγγραφή στη βάση δεδομένων TCC του χρήστη**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει την **αλλαγή** του χαρακτηριστικού **`NFSHomeDirectory`** ενός χρήστη, γεγονός που αλλάζει τη διαδρομή του προσωπικού του φακέλου και επομένως επιτρέπει την **παράκαμψη του TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα σε app bundle (μέσα στο app.app), κάτι που **απαγορεύεται από προεπιλογή**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να ελέγξετε ποιος έχει αυτή την πρόσβαση στις _Ρυθμίσεις συστήματος_ > _Απόρρητο και ασφάλεια_ > _Διαχείριση εφαρμογών._

### `kTCCServiceAccessibility`

Η διεργασία θα μπορεί να **καταχραστεί τις δυνατότητες προσβασιμότητας του macOS**, πράγμα που σημαίνει, για παράδειγμα, ότι θα μπορεί να προσομοιώνει πατήματα πλήκτρων. Έτσι, θα μπορούσε να ζητήσει πρόσβαση για τον έλεγχο μιας εφαρμογής όπως το Finder και να εγκρίνει το παράθυρο διαλόγου με αυτό το δικαίωμα.

## Entitlements που σχετίζονται με Trustcache/CDhash

Υπάρχουν ορισμένα entitlements που θα μπορούσαν να χρησιμοποιηθούν για την παράκαμψη των προστασιών Trustcache/CDhash, οι οποίες εμποδίζουν την εκτέλεση υποβαθμισμένων εκδόσεων των binaries της Apple.

## Medium

### `com.apple.security.cs.allow-jit`

Αυτό το entitlement επιτρέπει τη **δημιουργία μνήμης που είναι εγγράψιμη και εκτελέσιμη** μέσω της μεταβίβασης του flag `MAP_JIT` στη system function `mmap()`. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτό το entitlement επιτρέπει την **παράκαμψη ή επιδιόρθωση κώδικα C**, τη χρήση του από καιρό deprecated **`NSCreateObjectFileImageFromMemory`** (το οποίο είναι θεμελιωδώς insecure) ή τη χρήση του framework **DVDPlayback**. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Η συμπερίληψη αυτού του entitlement εκθέτει την εφαρμογή σας σε κοινές ευπάθειες γλωσσών προγραμματισμού με μη ασφαλή διαχείριση μνήμης. Εξετάστε προσεκτικά αν η εφαρμογή σας χρειάζεται αυτή την εξαίρεση.

### `com.apple.security.cs.disable-executable-page-protection`

Αυτό το entitlement επιτρέπει την **τροποποίηση sections των δικών του executable files** στον δίσκο, ώστε να προκαλείται εξαναγκασμένος τερματισμός. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Το Disable Executable Memory Protection Entitlement είναι ένα extreme entitlement που αφαιρεί μια θεμελιώδη προστασία ασφαλείας από την εφαρμογή σας, καθιστώντας δυνατή την επανεγγραφή του executable code της εφαρμογής σας από έναν attacker χωρίς ανίχνευση. Προτιμήστε στενότερα entitlements, αν είναι δυνατό.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτό το entitlement επιτρέπει την προσάρτηση ενός nullfs file system (απαγορεύεται από προεπιλογή). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτό το blogpost, αυτό το TCC permission συνήθως βρίσκεται με τη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέπει στη διεργασία να **ζητήσει όλα τα TCC permissions**.

### **`kTCCServicePostEvent`**

Επιτρέπει την **εισαγωγή συνθετικών συμβάντων πληκτρολογίου και ποντικιού** σε όλο το σύστημα μέσω της `CGEventPost()`. Μια διεργασία με αυτό το permission μπορεί να προσομοιώσει πατήματα πλήκτρων, κλικ ποντικιού και συμβάντα κύλισης σε οποιαδήποτε εφαρμογή — παρέχοντας ουσιαστικά **απομακρυσμένο έλεγχο** της επιφάνειας εργασίας.

Αυτό είναι ιδιαίτερα επικίνδυνο σε συνδυασμό με τα `kTCCServiceAccessibility` ή `kTCCServiceListenEvent`, καθώς επιτρέπει τόσο την ανάγνωση ΟΣΟ ΚΑΙ την εισαγωγή input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Επιτρέπει την **intercepting όλων των συμβάντων πληκτρολογίου και ποντικιού** σε επίπεδο συστήματος (input monitoring / keylogging). Μια διεργασία μπορεί να καταχωρίσει ένα `CGEventTap` για να καταγράφει κάθε πλήκτρο που πληκτρολογείται σε οποιαδήποτε εφαρμογή, συμπεριλαμβανομένων κωδικών πρόσβασης, αριθμών πιστωτικών καρτών και ιδιωτικών μηνυμάτων.

Για λεπτομερείς exploitation techniques, δείτε:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Επιτρέπει την **ανάγνωση του display buffer** — τη λήψη screenshots και την καταγραφή video της οθόνης οποιασδήποτε εφαρμογής, συμπεριλαμβανομένων secure text fields. Σε συνδυασμό με OCR, αυτό μπορεί να εξάγει αυτόματα κωδικούς πρόσβασης και ευαίσθητα δεδομένα από την οθόνη.

> [!WARNING]
> Από το macOS Sonoma, το screen capture εμφανίζει μια μόνιμη ένδειξη στη menu bar. Σε παλαιότερες εκδόσεις, το screen recording μπορεί να πραγματοποιείται εντελώς αθόρυβα.

### **`kTCCServiceCamera`**

Επιτρέπει τη **λήψη φωτογραφιών και video** από την ενσωματωμένη κάμερα ή συνδεδεμένες USB cameras. Το code injection σε binary με camera entitlement επιτρέπει αθόρυπη οπτική παρακολούθηση.

### **`kTCCServiceMicrophone`**

Επιτρέπει την **καταγραφή ήχου** από όλες τις συσκευές εισόδου. Background daemons με πρόσβαση στο μικρόφωνο παρέχουν επίμονη ambient audio surveillance χωρίς ορατό παράθυρο εφαρμογής.

### **`kTCCServiceLocation`**

Επιτρέπει την αναζήτηση της **φυσικής τοποθεσίας** της συσκευής μέσω Wi-Fi triangulation ή Bluetooth beacons. Η συνεχής παρακολούθηση αποκαλύπτει διευθύνσεις κατοικίας/εργασίας, μοτίβα μετακινήσεων και καθημερινές συνήθειες.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Πρόσβαση στις **Contacts** (ονόματα, emails, τηλέφωνα — χρήσιμα για spear-phishing), στο **Calendar** (προγράμματα συναντήσεων, λίστες συμμετεχόντων) και στις **Photos** (προσωπικές φωτογραφίες, screenshots που μπορεί να περιέχουν credentials, metadata τοποθεσίας).

Για complete credential theft exploitation techniques μέσω TCC permissions, δείτε:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Οι **temporary exceptions του Sandbox** αποδυναμώνουν το App Sandbox, επιτρέποντας επικοινωνία με system-wide Mach/XPC services που το Sandbox κανονικά αποκλείει. Αυτό είναι το **primary sandbox escape primitive** — μια compromised sandboxed εφαρμογή μπορεί να χρησιμοποιήσει mach-lookup exceptions για να προσεγγίσει privileged daemons και να εκμεταλλευτεί τα XPC interfaces τους.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Για λεπτομερή exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, δείτε:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Τα **DriverKit entitlements** επιτρέπουν σε user-space driver binaries να επικοινωνούν απευθείας με τον kernel μέσω interfaces του IOKit. Τα DriverKit binaries διαχειρίζονται hardware: USB, Thunderbolt, PCIe, HID devices, audio και networking.

Η παραβίαση ενός DriverKit binary επιτρέπει:
- **Kernel attack surface** μέσω malformed κλήσεων `IOConnectCallMethod`
- **USB device spoofing** (emulate keyboard για HID injection)
- **DMA attacks** μέσω PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Για λεπτομερείς τεχνικές exploitation του IOKit/DriverKit, δείτε:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Αναφορές

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
