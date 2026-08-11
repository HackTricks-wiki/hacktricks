# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Τα Entitlements δηλώνουν δυνατότητες και εξαιρέσεις ασφαλείας που το λειτουργικό σύστημα εκχωρεί σε signed code. Οι παρακάτω καταχωρίσεις επικεντρώνονται σε εκείνες που είναι ιδιαίτερα χρήσιμες κατά τη διάρκεια offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε third-parties· μόνο η Apple μπορεί να τα εκχωρήσει... Ωστόσο, αν χρησιμοποιείτε enterprise certificate, θα μπορούσατε στην πραγματικότητα να δημιουργήσετε τα δικά σας entitlements που ξεκινούν με **`com.apple`** και να παρακάμψετε protections που βασίζονται σε αυτό.

## High

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει σε μια διεργασία να **παρακάμπτει το SIP**. Δείτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει σε μια διεργασία να **παρακάμπτει το SIP**. Δείτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει σε μια διεργασία να αποκτήσει το **task port οποιασδήποτε** διεργασίας εκτός από τον kernel. Δείτε [**αυτό για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλες διεργασίες με το entitlement **`com.apple.security.cs.debugger`** να αποκτήσουν το task port της διεργασίας που εκτελείται από το binary με αυτό το entitlement και να κάνουν **inject code σε αυτή**. Δείτε [**αυτό για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με το Debugging Tool Entitlement μπορούν να καλέσουν τη `task_for_pid()` για να ανακτήσουν ένα έγκυρο task port για unsigned και third-party apps με ενεργοποιημένο το entitlement `Get Task Allow` σε `true`. Ωστόσο, ακόμη και με το debugging tool entitlement, ένας debugger **δεν μπορεί να αποκτήσει τα task ports** διεργασιών που **δεν διαθέτουν το `Get Task Allow` entitlement** και, επομένως, προστατεύονται από το System Integrity Protection. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει σε μια εφαρμογή να **φορτώνει frameworks, plug-ins ή libraries χωρίς να απαιτείται να έχουν υπογραφεί από την Apple ή με το ίδιο Team ID** με το κύριο executable, επομένως ένας attacker θα μπορούσε να εκμεταλλευτεί ένα arbitrary library load για να κάνει inject code. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με το **`com.apple.security.cs.disable-library-validation`**, αλλά **αντί να απενεργοποιεί άμεσα** το library validation, επιτρέπει στη διεργασία να **καλέσει ένα `csops` system call για να το απενεργοποιήσει** κατά το runtime.

Το όνομα του entitlement είναι hardcoded στο XNU, δίπλα στην operation του `csops` που το χρησιμοποιεί:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Ο handler του `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) δείχνει ακριβώς πόσο περιορισμένο είναι το primitive:<sup>[[2]](#references)</sup>
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
So η λειτουργία:

- Είναι **macOS-only** (`ENOTSUP` σε κάθε άλλη πλατφόρμα).
- Λειτουργεί μόνο στο **ίδιο το process** (`forself == 1`) — δεν μπορείτε να αφαιρέσετε το library validation από άλλο process με αυτήν.
- Απαιτεί το process να **κατέχει πράγματι το entitlement** και αποτυγχάνει αν το process έχει τη σημαία `CS_INSTALLER` ή εκτελείται κάτω από ένα subsystem root path.
- Αφαιρεί τα **`CS_REQUIRE_LV | CS_FORCED_LV`** από τα code-signing flags του process.

Το σχόλιο του XNU εξηγεί την προβλεπόμενη χρήση, καθώς και γιατί αυτό είναι ενδιαφέρον για έναν attacker:

> Αυτή η επιλογή χρησιμοποιείται για την αφαίρεση του library validation από ένα running process. Χρησιμοποιείται σε plugin architectures όταν ένα πρόγραμμα χρειάζεται να φορτώσει untrusted libraries. [...] Μόλις ένα process φορτώσει την untrusted library, η μελλοντική εξάρτηση από το library validation δεν θα είναι αποτελεσματική.

Με άλλα λόγια, **κάθε binary που διαθέτει αυτό το entitlement είναι στόχος για dylib-injection**: εκτελέστε code μέσα σε αυτό (ή πείστε το να φορτώσει το plugin σας) αφού έχει αφαιρέσει το `CS_REQUIRE_LV`, και κληρονομείτε ό,τι επιτρέπεται να κάνει το host process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει τη **χρήση DYLD environment variables**, οι οποίες μπορούν να χρησιμοποιηθούν για την εισαγωγή libraries και code. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ή `com.apple.rootless.storage`.`TCC`

[**Σύμφωνα με αυτό το blog**](https://objective-see.org/blog/blog_0x4C.html) **και** [**αυτό το blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν σε ένα process να **τροποποιεί** τη βάση δεδομένων του **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** και **`system.install.apple-software.standard-user`**

Αυτά τα δικαιώματα του Authorization Services διέπουν την εγκατάσταση software που παρέχεται από την Apple. Ένα process με δικαίωμα απόκτησής τους μπορεί να παρακάμψει τη συνήθη ροή authorization, κάτι που μπορεί να βοηθήσει σε **privilege escalation**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement που απαιτείται για να ζητηθεί από τον **kernel η φόρτωση ενός kernel extension**.

### **`com.apple.private.icloud-account-access`**

Το entitlement **`com.apple.private.icloud-account-access`** επιτρέπει την επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Τα **iMovie** και **Garageband** διέθεταν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για την **απόκτηση icloud tokens** από αυτό το entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν γνωρίζω τι επιτρέπει να γίνει

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Αυτή η αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) αναφέρει ότι αυτό το entitlement θα μπορούσε να χρησιμοποιηθεί για την ενημέρωση SSV-protected contents μετά από reboot. Αν γνωρίζετε πώς, στείλτε ένα PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Η ίδια αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) αναφέρει ότι η δημιουργία ενός sealed snapshot θα μπορούσε να χρησιμοποιηθεί για την ενημέρωση SSV-protected contents μετά από reboot. Αν γνωρίζετε πώς, στείλτε ένα PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Αυτό το entitlement καθορίζει τις ομάδες **keychain** στις οποίες έχει πρόσβαση η εφαρμογή:
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

Παρέχει δικαιώματα **Full Disk Access**, μία από τις υψηλότερες permissions του TCC που μπορείτε να έχετε.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει events σε άλλες εφαρμογές που χρησιμοποιούνται συνήθως για **automating tasks**. Ελέγχοντας άλλες εφαρμογές, μπορεί να κάνει abuse των permissions που έχουν παραχωρηθεί σε αυτές.

Όπως το να τις κάνει να ζητήσουν από τον χρήστη τον κωδικό πρόσβασής του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ή να τα κάνει να εκτελούν **αυθαίρετες ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων, να **γράφει στη βάση δεδομένων TCC των χρηστών**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει την **αλλαγή** του χαρακτηριστικού **`NFSHomeDirectory`** ενός χρήστη, κάτι που αλλάζει τη διαδρομή του home folder του και επομένως επιτρέπει την **παράκαμψη του TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα σε app bundle (μέσα στο app.app), κάτι που **απαγορεύεται από προεπιλογή**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να ελέγξετε ποιος έχει αυτή την πρόσβαση στις _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Η διεργασία θα μπορεί να **καταχραστεί τις δυνατότητες προσβασιμότητας του macOS**, πράγμα που σημαίνει, για παράδειγμα, ότι θα μπορεί να πατάει πλήκτρα. Έτσι, θα μπορούσε να ζητήσει πρόσβαση για τον έλεγχο μιας εφαρμογής όπως το Finder και να εγκρίνει το παράθυρο διαλόγου με αυτή την άδεια.

## Entitlements που σχετίζονται με Trustcache/CDhash

Υπάρχουν ορισμένα entitlements που θα μπορούσαν να χρησιμοποιηθούν για την παράκαμψη των προστασιών Trustcache/CDhash, οι οποίες εμποδίζουν την εκτέλεση downgraded εκδόσεων των binaries της Apple.

## Μεσαίο

### `com.apple.security.cs.allow-jit`

Αυτό το entitlement επιτρέπει σε μια διεργασία να **δημιουργεί μνήμη που είναι εγγράψιμη και εκτελέσιμη**, περνώντας το flag `MAP_JIT` στη system function `mmap()`. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτό το entitlement επιτρέπει την **παράκαμψη ή επιδιόρθωση κώδικα C**, τη χρήση του εδώ και πολύ καιρό deprecated **`NSCreateObjectFileImageFromMemory`** (το οποίο είναι θεμελιωδώς insecure) ή τη χρήση του framework **DVDPlayback**. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Η συμπερίληψη αυτού του entitlement εκθέτει την εφαρμογή σας σε συνηθισμένες ευπάθειες σε γλώσσες προγραμματισμού με μη ασφαλή διαχείριση μνήμης. Εξετάστε προσεκτικά αν η εφαρμογή σας χρειάζεται αυτή την εξαίρεση.

### `com.apple.security.cs.disable-executable-page-protection`

Αυτό το entitlement επιτρέπει την **τροποποίηση τμημάτων των δικών του εκτελέσιμων αρχείων** στον δίσκο, ώστε να προκαλείται εξαναγκασμένη έξοδος. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Το Disable Executable Memory Protection Entitlement είναι ένα ακραίο entitlement που αφαιρεί μια θεμελιώδη προστασία ασφαλείας από την εφαρμογή σας, καθιστώντας εφικτό για έναν attacker να ξαναγράψει τον εκτελέσιμο κώδικα της εφαρμογής σας χωρίς ανίχνευση. Προτιμήστε στενότερα entitlements, αν είναι δυνατό.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτό το entitlement επιτρέπει την προσάρτηση ενός file system nullfs (απαγορεύεται από προεπιλογή). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτή την ανάρτηση σε blog, αυτή η άδεια TCC συνήθως βρίσκεται στη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέπει στη διεργασία να **ζητήσει όλα τα TCC permissions**.

### **`kTCCServicePostEvent`**

Επιτρέπει την **εισαγωγή συνθετικών συμβάντων πληκτρολογίου και ποντικιού** σε ολόκληρο το σύστημα μέσω της `CGEventPost()`. Μια διεργασία με αυτό το permission μπορεί να προσομοιώσει πατήματα πλήκτρων, κλικ του ποντικιού και συμβάντα κύλισης σε οποιαδήποτε εφαρμογή — παρέχοντας ουσιαστικά **απομακρυσμένο έλεγχο** της επιφάνειας εργασίας.

Αυτό είναι ιδιαίτερα επικίνδυνο σε συνδυασμό με τα `kTCCServiceAccessibility` ή `kTCCServiceListenEvent`, καθώς επιτρέπει τόσο την ανάγνωση όσο ΚΑΙ την εισαγωγή input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Επιτρέπει την **αναχαίτιση όλων των συμβάντων πληκτρολογίου και ποντικιού** σε επίπεδο συστήματος (input monitoring / keylogging). Μια διεργασία μπορεί να καταχωρίσει ένα `CGEventTap` για να καταγράφει κάθε πάτημα πλήκτρου που πληκτρολογείται σε οποιαδήποτε εφαρμογή, συμπεριλαμβανομένων κωδικών πρόσβασης, αριθμών πιστωτικών καρτών και ιδιωτικών μηνυμάτων.

Για λεπτομερείς τεχνικές exploitation, δείτε:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Επιτρέπει την **ανάγνωση του buffer οθόνης** — τη λήψη screenshots και την καταγραφή video της οθόνης οποιασδήποτε εφαρμογής, συμπεριλαμβανομένων ασφαλών πεδίων κειμένου. Σε συνδυασμό με OCR, αυτό μπορεί να εξάγει αυτόματα κωδικούς πρόσβασης και ευαίσθητα δεδομένα από την οθόνη.

> [!WARNING]
> Από το macOS Sonoma, η καταγραφή οθόνης εμφανίζει μια μόνιμη ένδειξη στη menu bar. Σε παλαιότερες εκδόσεις, η καταγραφή οθόνης μπορεί να πραγματοποιείται εντελώς αθόρυβα.

### **`kTCCServiceCamera`**

Επιτρέπει τη **λήψη φωτογραφιών και video** από την ενσωματωμένη κάμερα ή συνδεδεμένες USB κάμερες. Το code injection σε binary με camera entitlement επιτρέπει αθόρυφη οπτική παρακολούθηση.

### **`kTCCServiceMicrophone`**

Επιτρέπει την **καταγραφή ήχου** από όλες τις συσκευές εισόδου. Background daemons με πρόσβαση στο μικρόφωνο παρέχουν επίμονη παρακολούθηση ήχου του περιβάλλοντος χωρίς ορατό παράθυρο εφαρμογής.

### **`kTCCServiceLocation`**

Επιτρέπει την αναζήτηση της **φυσικής τοποθεσίας** της συσκευής μέσω τριγωνισμού Wi-Fi ή Bluetooth beacons. Η συνεχής παρακολούθηση αποκαλύπτει διευθύνσεις κατοικίας/εργασίας, μοτίβα μετακινήσεων και καθημερινές συνήθειες.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Πρόσβαση στις **Επαφές** (ονόματα, email, τηλέφωνα — χρήσιμα για spear-phishing), στο **Ημερολόγιο** (προγράμματα συναντήσεων, λίστες συμμετεχόντων) και στις **Φωτογραφίες** (προσωπικές φωτογραφίες, screenshots που μπορεί να περιέχουν credentials, metadata τοποθεσίας).

Για πλήρεις τεχνικές exploitation credential theft μέσω TCC permissions, δείτε:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Οι **προσωρινές εξαιρέσεις του Sandbox** αποδυναμώνουν το App Sandbox, επιτρέποντας επικοινωνία με system-wide Mach/XPC services που κανονικά αποκλείονται από το sandbox. Αυτό είναι το **primary sandbox escape primitive** — μια compromised sandboxed εφαρμογή μπορεί να χρησιμοποιήσει mach-lookup exceptions για να προσεγγίσει privileged daemons και να εκμεταλλευτεί τα XPC interfaces τους.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Για λεπτομερή αλυσίδα exploitation: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, δείτε:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Τα **DriverKit entitlements** επιτρέπουν σε user-space driver binaries να επικοινωνούν απευθείας με τον kernel μέσω διεπαφών IOKit. Τα DriverKit binaries διαχειρίζονται hardware: USB, Thunderbolt, PCIe, HID devices, audio και networking.

Η παραβίαση ενός DriverKit binary επιτρέπει:
- **Kernel attack surface** μέσω κακόβουλα διαμορφωμένων κλήσεων `IOConnectCallMethod`
- **USB device spoofing** (προσομοίωση πληκτρολογίου για HID injection)
- **DMA attacks** μέσω διεπαφών PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Για λεπτομερείς τεχνικές exploitation των IOKit/DriverKit, δείτε:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (λειτουργίες `CS_OPS_*` και `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler των `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement εργαλείου debugging (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement απενεργοποίησης του Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement允许 μεταβλητών περιβάλλοντος DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Παράκαμψη του TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Αναπαραγωγή μουσικής και παράκαμψη του TCC, γνωστό και ως CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: «Ό,τι συμβαίνει στο Mac σου, παραμένει στο iCloud της Apple?!» - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Ο εφιάλτης του OTA Update της Apple: Παράκαμψη της επαλήθευσης υπογραφής και pwning του kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement允许 εκτέλεσης JIT-compiled code (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement允许 μη υπογεγραμμένης executable μνήμης](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement απενεργοποίησης της προστασίας executable μνήμης](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Οδηγός προγραμματισμού Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
