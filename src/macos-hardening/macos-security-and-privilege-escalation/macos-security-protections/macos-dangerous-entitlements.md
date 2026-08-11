# Επικίνδυνα Entitlements και δικαιώματα TCC στο macOS

{{#include ../../../banners/hacktricks-training.md}}

Τα Entitlements δηλώνουν δυνατότητες και εξαιρέσεις ασφαλείας που το λειτουργικό σύστημα παραχωρεί σε υπογεγραμμένο κώδικα. Οι παρακάτω καταχωρίσεις εστιάζουν σε εκείνες που είναι ιδιαίτερα χρήσιμες κατά τη διάρκεια offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε third-parties· μόνο η Apple μπορεί να τα παραχωρήσει... Ή, αν χρησιμοποιείτε enterprise certificate, θα μπορούσατε στην πραγματικότητα να δημιουργήσετε τα δικά σας entitlements που ξεκινούν με **`com.apple`** και να παρακάμψετε προστασίες που βασίζονται σε αυτό.

## Υψηλή

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει σε μια διεργασία να **παρακάμπτει το SIP**. Δείτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει σε μια διεργασία να **παρακάμπτει το SIP**. Δείτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει σε μια διεργασία να λάβει το **task port οποιασδήποτε** διεργασίας, εκτός από τον kernel. Δείτε [**εδώ για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλες διεργασίες με το entitlement **`com.apple.security.cs.debugger`** να λάβουν το task port της διεργασίας που εκτελείται από το binary με αυτό το entitlement και να **κάνουν inject κώδικα σε αυτήν**. Δείτε [**εδώ για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με το Debugging Tool Entitlement μπορούν να καλέσουν τη `task_for_pid()` για να ανακτήσουν ένα έγκυρο task port για unsigned και third-party apps με ενεργοποιημένο το entitlement `Get Task Allow` σε `true`. Ωστόσο, ακόμη και με το debugging tool entitlement, ένας debugger **δεν μπορεί να λάβει τα task ports** διεργασιών που **δεν διαθέτουν το entitlement `Get Task Allow`** και, επομένως, προστατεύονται από το System Integrity Protection. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει σε μια εφαρμογή να **φορτώνει frameworks, plug-ins ή libraries χωρίς να απαιτείται να έχουν υπογραφεί από την Apple ή με το ίδιο Team ID** με το κύριο executable, επομένως ένας attacker θα μπορούσε να εκμεταλλευτεί ένα arbitrary library load για να κάνει inject κώδικα. Δείτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με το **`com.apple.security.cs.disable-library-validation`**, αλλά **αντί να απενεργοποιεί άμεσα** το library validation, επιτρέπει στη διεργασία να **καλέσει ένα `csops` system call για να το απενεργοποιήσει** κατά το runtime.

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
- Λειτουργεί μόνο στο **ίδιο το process** (`forself == 1`) — δεν μπορείτε να αφαιρέσετε το library validation από άλλο process με αυτήν.
- Απαιτεί το process να **κατέχει πράγματι το entitlement** και αποτυγχάνει αν το process έχει τη σημαία `CS_INSTALLER` ή εκτελείται κάτω από ένα subsystem root path.
- Αφαιρεί τα **`CS_REQUIRE_LV | CS_FORCED_LV`** από τα code-signing flags του process.

Το σχόλιο του XNU εξηγεί την προβλεπόμενη περίπτωση χρήσης, καθώς και γιατί είναι ενδιαφέρον για έναν attacker:

> Αυτή η επιλογή χρησιμοποιείται για την αφαίρεση του library validation από ένα running process. Χρησιμοποιείται σε plugin architectures όταν ένα πρόγραμμα χρειάζεται να φορτώσει untrusted libraries. [...] Μόλις ένα process φορτώσει το untrusted library, η μελλοντική εξάρτηση από το library validation δεν θα είναι αποτελεσματική.

Με άλλα λόγια, **κάθε binary που περιέχει αυτό το entitlement είναι dylib-injection target**: αν καταφέρετε να εκτελέσετε code μέσα σε αυτό (ή να το πείσετε να φορτώσει το plug-in σας) αφού έχει αφαιρέσει το `CS_REQUIRE_LV`, αποκτάτε ό,τι δυνατότητες έχει το host process ως trusted process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει τη **χρήση των DYLD environment variables**, οι οποίες μπορούν να χρησιμοποιηθούν για την έγχυση libraries και code. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ή `com.apple.rootless.storage`.`TCC`

[**Σύμφωνα με αυτό το blog**](https://objective-see.org/blog/blog_0x4C.html) **και** [**αυτό το blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν σε ένα process να **τροποποιεί** τη βάση δεδομένων του **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** και **`system.install.apple-software.standar-user`**

Αυτά τα entitlements επιτρέπουν σε ένα process να **εγκαθιστά software χωρίς να ζητά άδεια από τον χρήστη**, κάτι που μπορεί να είναι χρήσιμο για **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement που απαιτείται για να ζητηθεί από τον **kernel η φόρτωση ενός kernel extension**.

### **`com.apple.private.icloud-account-access`**

Το entitlement **`com.apple.private.icloud-account-access`** καθιστά δυνατή την επικοινωνία με την **`com.apple.iCloudHelper`** XPC service, η οποία θα **παρέχει iCloud tokens**.

Τα **iMovie** και **Garageband** είχαν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για τη **λήψη icloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν γνωρίζω τι επιτρέπει να γίνει αυτό

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Αυτή η αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) αναφέρει ότι αυτό το entitlement θα μπορούσε να χρησιμοποιηθεί για την ενημέρωση περιεχομένου που προστατεύεται από το SSV μετά από reboot. Αν γνωρίζετε πώς, παρακαλώ στείλτε ένα PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Η ίδια αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) αναφέρει ότι η δημιουργία ενός sealed snapshot θα μπορούσε να χρησιμοποιηθεί για την ενημέρωση περιεχομένου που προστατεύεται από το SSV μετά από reboot. Αν γνωρίζετε πώς, παρακαλώ στείλτε ένα PR!<sup>[[9]](#references)</sup>

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

Παρέχει δικαιώματα **Full Disk Access**, ένα από τα υψηλότερα δικαιώματα TCC που μπορείτε να έχετε.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει events σε άλλες εφαρμογές που χρησιμοποιούνται συνήθως για **automating tasks**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τα δικαιώματα που έχουν παραχωρηθεί σε αυτές.

Για παράδειγμα, μπορεί να τις κάνει να ζητήσουν από τον χρήστη τον κωδικό πρόσβασής του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ή να τα αναγκάσουν να εκτελέσουν **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων, να **write the users TCC database**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει την **change** του χαρακτηριστικού **`NFSHomeDirectory`** ενός χρήστη, γεγονός που αλλάζει τη διαδρομή του αρχικού φακέλου του και επομένως επιτρέπει την **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα σε app bundle (μέσα στο app.app), κάτι που είναι **disallowed by default**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να ελέγξετε ποιος έχει αυτήν την πρόσβαση στις _Ρυθμίσεις συστήματος_ > _Απόρρητο και ασφάλεια_ > _Διαχείριση εφαρμογών._

### `kTCCServiceAccessibility`

Η διεργασία θα μπορεί να **abuse the macOS accessibility features**, πράγμα που σημαίνει, για παράδειγμα, ότι θα μπορεί να πατάει πλήκτρα. Επομένως, θα μπορούσε να ζητήσει πρόσβαση για τον έλεγχο μιας εφαρμογής όπως το Finder και να εγκρίνει το παράθυρο διαλόγου με αυτήν την άδεια.

## Entitlements που σχετίζονται με Trustcache/CDhash

Υπάρχουν ορισμένα entitlements που θα μπορούσαν να χρησιμοποιηθούν για την παράκαμψη των προστασιών Trustcache/CDhash, οι οποίες αποτρέπουν την εκτέλεση downgraded εκδόσεων των Apple binaries.

## Μεσαίο

### `com.apple.security.cs.allow-jit`

Αυτό το entitlement επιτρέπει σε μια διεργασία να **create memory that is writable and executable**, περνώντας το flag `MAP_JIT` στη system function `mmap()`. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτό το entitlement επιτρέπει την **override or patch C code**, τη χρήση του long-deprecated **`NSCreateObjectFileImageFromMemory`** (το οποίο είναι fundamentally insecure) ή τη χρήση του framework **DVDPlayback**. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Η συμπερίληψη αυτού του entitlement εκθέτει την εφαρμογή σας σε common vulnerabilities σε memory-unsafe code languages. Εξετάστε προσεκτικά αν η εφαρμογή σας χρειάζεται αυτήν την εξαίρεση.

### `com.apple.security.cs.disable-executable-page-protection`

Αυτό το entitlement επιτρέπει την **modify sections of its own executable files** στον δίσκο, ώστε να προκαλεί forceful exit. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Το Disable Executable Memory Protection Entitlement είναι ένα extreme entitlement που αφαιρεί μια θεμελιώδη security protection από την εφαρμογή σας, καθιστώντας δυνατή την επανεγγραφή του executable code της εφαρμογής σας από έναν attacker χωρίς detection. Προτιμήστε narrower entitlements, εάν είναι δυνατό.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτό το entitlement επιτρέπει την προσάρτηση ενός nullfs file system (forbidden by default). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτό το blogpost, αυτή η TCC permission συνήθως βρίσκεται στη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέπει στη **διεργασία να ζητήσει όλα τα TCC permissions**.

### **`kTCCServicePostEvent`**

Επιτρέπει την **εισαγωγή συνθετικών συμβάντων πληκτρολογίου και ποντικιού** σε ολόκληρο το σύστημα μέσω της `CGEventPost()`. Μια διεργασία με αυτό το permission μπορεί να προσομοιώσει πατήματα πλήκτρων, κλικ του ποντικιού και συμβάντα κύλισης σε οποιαδήποτε εφαρμογή — παρέχοντας ουσιαστικά **απομακρυσμένο έλεγχο** της επιφάνειας εργασίας.

Αυτό είναι ιδιαίτερα επικίνδυνο σε συνδυασμό με τα `kTCCServiceAccessibility` ή `kTCCServiceListenEvent`, καθώς επιτρέπει τόσο την ανάγνωση ΟΣΟ ΚΑΙ την εισαγωγή δεδομένων εισόδου.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Επιτρέπει την **intercepting όλων των συμβάντων πληκτρολογίου και ποντικιού** σε επίπεδο συστήματος (input monitoring / keylogging). Μια διεργασία μπορεί να καταχωρίσει ένα `CGEventTap` για να καταγράφει κάθε πλήκτρο που πατιέται σε οποιαδήποτε εφαρμογή, συμπεριλαμβανομένων κωδικών πρόσβασης, αριθμών πιστωτικών καρτών και ιδιωτικών μηνυμάτων.

Για λεπτομερείς τεχνικές exploitation, δείτε:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Επιτρέπει την **ανάγνωση του buffer της οθόνης** — τη λήψη screenshots και την καταγραφή video της οθόνης οποιασδήποτε εφαρμογής, συμπεριλαμβανομένων ασφαλών πεδίων κειμένου. Σε συνδυασμό με OCR, μπορεί να εξάγει αυτόματα κωδικούς πρόσβασης και ευαίσθητα δεδομένα από την οθόνη.

> [!WARNING]
> Από το macOS Sonoma, το screen capture εμφανίζει μόνιμη ένδειξη στη γραμμή μενού. Σε παλαιότερες εκδόσεις, η καταγραφή οθόνης μπορεί να πραγματοποιείται εντελώς αθόρυβα.

### **`kTCCServiceCamera`**

Επιτρέπει τη **λήψη φωτογραφιών και video** από την ενσωματωμένη κάμερα ή συνδεδεμένες κάμερες USB. Το code injection σε binary με camera entitlement επιτρέπει την αθόρυβη οπτική παρακολούθηση.

### **`kTCCServiceMicrophone`**

Επιτρέπει την **καταγραφή ήχου** από όλες τις συσκευές εισόδου. Background daemons με πρόσβαση στο μικρόφωνο παρέχουν επίμονη παρακολούθηση του περιβάλλοντος μέσω ήχου, χωρίς ορατό παράθυρο εφαρμογής.

### **`kTCCServiceLocation`**

Επιτρέπει την αναζήτηση της **φυσικής τοποθεσίας** της συσκευής μέσω τριγωνισμού Wi-Fi ή Bluetooth beacons. Η συνεχής παρακολούθηση αποκαλύπτει διευθύνσεις κατοικίας/εργασίας, μοτίβα μετακινήσεων και καθημερινές συνήθειες.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Πρόσβαση στις **Επαφές** (ονόματα, email, τηλέφωνα — χρήσιμα για spear-phishing), στο **Ημερολόγιο** (προγράμματα συναντήσεων, λίστες συμμετεχόντων) και στις **Φωτογραφίες** (προσωπικές φωτογραφίες, screenshots που ενδέχεται να περιέχουν credentials, metadata τοποθεσίας).

Για πλήρεις τεχνικές credential theft exploitation μέσω TCC permissions, δείτε:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements Sandbox & Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Οι **προσωρινές εξαιρέσεις του Sandbox** αποδυναμώνουν το App Sandbox, επιτρέποντας την επικοινωνία με system-wide Mach/XPC services που κανονικά αποκλείονται από το sandbox. Αυτό είναι το **κύριο primitive διαφυγής από το sandbox** — μια παραβιασμένη εφαρμογή εντός sandbox μπορεί να χρησιμοποιήσει mach-lookup exceptions για να προσεγγίσει privileged daemons και να εκμεταλλευτεί τα XPC interfaces τους.
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

Τα **DriverKit entitlements** επιτρέπουν σε binaries οδηγών user-space να επικοινωνούν απευθείας με τον kernel μέσω interfaces του IOKit. Τα binaries του DriverKit διαχειρίζονται hardware: USB, Thunderbolt, PCIe, HID devices, audio και networking.

Η παραβίαση ενός binary του DriverKit επιτρέπει:
- **Kernel attack surface** μέσω malformed κλήσεων `IOConnectCallMethod`
- **USB device spoofing** (emulate keyboard για HID injection)
- **DMA attacks** μέσω interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Για λεπτομερή exploitation του IOKit/DriverKit, δείτε:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (λειτουργίες `CS_OPS_*` και `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler των `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement εργαλείου debugging (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement απενεργοποίησης του Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement που επιτρέπει μεταβλητές περιβάλλοντος DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Παράκαμψη του TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Αναπαραγωγή μουσικής και παράκαμψη του TCC, γνωστό και ως CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Ο εφιάλτης του OTA Update της Apple: Παράκαμψη της επαλήθευσης υπογραφής και Pwning του Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement που επιτρέπει την εκτέλεση κώδικα μεταγλωττισμένου με JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement που επιτρέπει unsigned executable memory](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement απενεργοποίησης της προστασίας executable memory](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
