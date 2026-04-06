# macOS Επικίνδυνα Entitlements & TCC δικαιώματα

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε τρίτους, μόνο η Apple μπορεί να τα χορηγήσει... Ή αν χρησιμοποιείτε ένα εταιρικό πιστοποιητικό θα μπορούσατε πραγματικά να δημιουργήσετε τα δικά σας entitlements που ξεκινούν με **`com.apple`** και να παρακάμψετε προστασίες βασισμένες σε αυτό.

## Υψηλό

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει να **παρακαμφθεί το SIP**. Δείτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει να **παρακαμφθεί το SIP**. Δείτε[ αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει την απόκτηση του **task port για οποιαδήποτε** διεργασία, εκτός από τον kernel. Δείτε [**αυτό για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλες διεργασίες με το **`com.apple.security.cs.debugger`** entitlement να αποκτήσουν το task port της διεργασίας που τρέχει το δυαδικό με αυτό το entitlement και να **ενέσουν κώδικα σε αυτό**. Δείτε [**αυτό για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Εφαρμογές με το Debugging Tool Entitlement μπορούν να καλέσουν `task_for_pid()` για να ανακτήσουν ένα έγκυρο task port για unsigned και τρίτες εφαρμογές με το entitlement `Get Task Allow` ορισμένο σε `true`. Ωστόσο, ακόμα και με το debugging tool entitlement, ένας debugger **δεν μπορεί να πάρει τα task ports** διεργασιών που **δεν έχουν το entitlement `Get Task Allow`**, και που επομένως προστατεύονται από το System Integrity Protection. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει να **φορτωθούν frameworks, plug-ins, ή βιβλιοθήκες χωρίς να είναι είτε υπογεγραμμένα από την Apple είτε υπογεγραμμένα με το ίδιο Team ID** όπως το κύριο εκτελέσιμο, οπότε ένας επιτιθέμενος θα μπορούσε να καταχραστεί κάποιο αυθαίρετο φόρτωμα βιβλιοθήκης για να εγχύσει κώδικα. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με **`com.apple.security.cs.disable-library-validation`** αλλά **αντί** να **απενεργοποιεί άμεσα** την επαλήθευση βιβλιοθηκών, επιτρέπει στη διεργασία να **καλέσει ένα system call `csops` για να την απενεργοποιήσει**.\
Δείτε [**αυτό για περισσότερες πληροφορίες**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει τη **χρήση των DYLD environment variables** που μπορούν να χρησιμοποιηθούν για εισαγωγή βιβλιοθηκών και κώδικα. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**Σύμφωνα με αυτό το blog**](https://objective-see.org/blog/blog_0x4C.html) **και** [**αυτό το blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν να **τροποποιηθεί** η βάση δεδομένων **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Αυτά τα entitlements επιτρέπουν να **εγκαταστήσετε λογισμικό χωρίς να ζητήσετε άδειες** από τον χρήστη, κάτι που μπορεί να βοηθήσει σε ένα **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement απαραίτητο για να ζητηθεί από τον **kernel να φορτώσει ένα kernel extension**.

### **`com.apple.private.icloud-account-access`**

Με το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατό να επικοινωνήσει κανείς με την XPC υπηρεσία **`com.apple.iCloudHelper`** η οποία θα **παρέχει iCloud tokens**.

**iMovie** και **Garageband** είχαν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για να **αποκτήσετε iCloud tokens** από αυτό το entitlement δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν ξέρω τι επιτρέπει να κάνει αυτό

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Στην [**αυτή η αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για** την ενημέρωση των περιεχομένων που προστατεύονται από SSV μετά από επανεκκίνηση. Αν ξέρετε πώς, στείλτε ένα PR παρακαλώ!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Στην [**αυτή η αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για** την ενημέρωση των περιεχομένων που προστατεύονται από SSV μετά από επανεκκίνηση. Αν ξέρετε πώς, στείλτε ένα PR παρακαλώ!

### `keychain-access-groups`

Αυτό το entitlement απαριθμεί τις ομάδες **keychain** στις οποίες η εφαρμογή έχει πρόσβαση:
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

Παρέχει δικαιώματα **Full Disk Access**, ένα από τα υψηλότερα δικαιώματα του TCC που μπορείτε να έχετε.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει συμβάντα σε άλλες εφαρμογές που χρησιμοποιούνται συνήθως για **αυτοματισμό εργασιών**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τα δικαιώματα που έχουν χορηγηθεί σε αυτές.

Όπως να τις κάνει να ζητήσουν από τον χρήστη τον κωδικό του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ή να τους κάνει να εκτελέσουν **αυθαίρετες ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων δικαιωμάτων, να **γράψει τη βάση δεδομένων TCC του χρήστη**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει να **αλλάξει** το χαρακτηριστικό **`NFSHomeDirectory`** ενός χρήστη, το οποίο αλλάζει τη διαδρομή του φακέλου χρήστη και επομένως επιτρέπει να **παρακαμφθεί το TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων εντός του bundle μιας εφαρμογής (εντός app.app), κάτι που **απαγορεύεται από προεπιλογή**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατόν να ελέγξετε ποιος έχει αυτήν την πρόσβαση στις _Ρυθμίσεις Συστήματος_ > _Απόρρητο & Ασφάλεια_ > _Διαχείριση Εφαρμογών_.

### `kTCCServiceAccessibility`

Η διαδικασία θα μπορεί να **κακοχρησιμοποιήσει τις δυνατότητες προσβασιμότητας του macOS**, πράγμα που σημαίνει ότι, για παράδειγμα, θα μπορεί να πατάει πλήκτρα. Έτσι θα μπορούσε να ζητήσει πρόσβαση για να ελέγξει μια εφαρμογή όπως το Finder και να εγκρίνει τον διάλογο με αυτή την άδεια.

## Trustcache/CDhash related entitlements

Υπάρχουν κάποιες entitlements που μπορούν να χρησιμοποιηθούν για να παρακαμφθούν οι προστασίες Trustcache/CDhash, οι οποίες αποτρέπουν την εκτέλεση υποβαθμισμένων εκδόσεων των Apple binaries.

## Medium

### `com.apple.security.cs.allow-jit`

Αυτό το entitlement επιτρέπει να **δημιουργηθεί μνήμη που είναι εγγράψιμη και εκτελέσιμη** περνώντας τη σημαία `MAP_JIT` στη συνάρτηση συστήματος `mmap()`. Δείτε [**περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτό το entitlement επιτρέπει να **αντικαταστήσει ή να τροποποιήσει κώδικα C**, να χρησιμοποιήσει την εδώ και καιρό απαρχαιωμένη **`NSCreateObjectFileImageFromMemory`** (η οποία είναι θεμελιωδώς ανασφαλής), ή να χρησιμοποιήσει το framework **DVDPlayback**. Δείτε [**περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Η συμπερίληψη αυτού του entitlement εκθέτει την εφαρμογή σας σε κοινές ευπάθειες σε γλώσσες με μη ασφαλή διαχείριση μνήμης. Εξετάστε προσεκτικά αν η εφαρμογή σας χρειάζεται αυτήν την εξαίρεση.

### `com.apple.security.cs.disable-executable-page-protection`

Αυτό το entitlement επιτρέπει να **τροποποιήσει τμήματα των δικών του εκτελέσιμων αρχείων** στο δίσκο για να εξαναγκάσει έξοδο. Δείτε [**περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Το Disable Executable Memory Protection Entitlement είναι ένα ακραίο entitlement που αφαιρεί μια θεμελιώδη προστασία ασφαλείας από την εφαρμογή σας, καθιστώντας δυνατή για έναν επιτιθέμενο την επανεγγραφή του εκτελέσιμου κώδικα της εφαρμογής σας χωρίς ανίχνευση. Προτιμήστε πιο στενά entitlements αν είναι δυνατό.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτό το entitlement επιτρέπει το mount ενός nullfs file system (απαγορευμένο από προεπιλογή). Εργαλείο: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτό το blogpost, αυτή η άδεια TCC συνήθως βρίσκεται με τη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέπει στη διεργασία να **ζητήσει όλες τις άδειες TCC**.

### **`kTCCServicePostEvent`**

Επιτρέπει την **έγχυση συνθετικών γεγονότων πληκτρολογίου και ποντικιού** σε όλο το σύστημα μέσω του `CGEventPost()`. Μια διεργασία με αυτή την άδεια μπορεί να προσομοιώσει πατήματα πλήκτρων, κλικ ποντικιού και γεγονότα κύλισης σε οποιαδήποτε εφαρμογή — παρέχοντας στην ουσία **απομακρυσμένο έλεγχο** της επιφάνειας εργασίας.

Αυτό είναι ιδιαίτερα επικίνδυνο σε συνδυασμό με `kTCCServiceAccessibility` ή `kTCCServiceListenEvent`, καθώς επιτρέπει τόσο την ανάγνωση όσο και την έγχυση εισόδων.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Επιτρέπει **την υποκλοπή όλων των πληκτρολογήσεων και κινήσεων ποντικιού** σε ολόκληρο το σύστημα (input monitoring / keylogging). Μια διεργασία μπορεί να εγγράψει ένα `CGEventTap` για να καταγράψει κάθε πάτημα πλήκτρου που εισάγεται σε οποιαδήποτε εφαρμογή, συμπεριλαμβανομένων κωδικών πρόσβασης, αριθμών πιστωτικών καρτών και ιδιωτικών μηνυμάτων.

Για αναλυτικές τεχνικές εκμετάλλευσης δείτε:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Επιτρέπει **την ανάγνωση του buffer της οθόνης** — τη λήψη screenshots και την εγγραφή βίντεο οθόνης οποιασδήποτε εφαρμογής, συμπεριλαμβανομένων ασφαλών πεδίων κειμένου. Σε συνδυασμό με OCR, αυτό μπορεί να εξαγάγει αυτόματα κωδικούς πρόσβασης και ευαίσθητα δεδομένα από την οθόνη.

> [!WARNING]
> Από το macOS Sonoma, το screen capture εμφανίζει έναν μόνιμο δείκτη στη γραμμή μενού. Σε παλαιότερες εκδόσεις, η εγγραφή οθόνης μπορεί να είναι εντελώς αθόρυβη.

### **`kTCCServiceCamera`**

Επιτρέπει **τη λήψη φωτογραφιών και βίντεο** από την ενσωματωμένη κάμερα ή συνδεδεμένες USB κάμερες. Η εισαγωγή κώδικα σε ένα binary με δικαίωμα κάμερας επιτρέπει σιωπηρή οπτική παρακολούθηση.

### **`kTCCServiceMicrophone`**

Επιτρέπει **την εγγραφή ήχου** από όλες τις συσκευές εισόδου. Δαίμονες στο παρασκήνιο με πρόσβαση στο μικρόφωνο παρέχουν μόνιμη ηχητική παρακολούθηση περιβάλλοντος χωρίς ορατό παράθυρο εφαρμογής.

### **`kTCCServiceLocation`**

Επιτρέπει την ερώτηση της **φυσικής τοποθεσίας** της συσκευής μέσω τριγωνοποίησης Wi‑Fi ή σημάτων Bluetooth. Η συνεχής παρακολούθηση αποκαλύπτει διευθύνσεις κατοικίας/εργασίας, μοτίβα ταξιδιών και καθημερινές ρουτίνες.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Πρόσβαση σε **Contacts** (ονόματα, emails, τηλέφωνα — χρήσιμο για spear-phishing), **Calendar** (προγράμματα συναντήσεων, λίστες συμμετεχόντων) και **Photos** (προσωπικές φωτογραφίες, screenshots που μπορεί να περιέχουν διαπιστευτήρια, metadata τοποθεσίας).

Για πλήρεις τεχνικές εκμετάλλευσης κλοπής διαπιστευτηρίων μέσω των δικαιωμάτων TCC, δείτε:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Οι **Sandbox temporary exceptions** αποδυναμώνουν το App Sandbox επιτρέποντας επικοινωνία με system-wide Mach/XPC services που το sandbox κανονικά μπλοκάρει. Αυτό είναι το **primary sandbox escape primitive** — μια συμβιβασμένη sandboxed app μπορεί να χρησιμοποιήσει mach-lookup exceptions για να φτάσει privileged daemons και να εκμεταλλευτεί τις XPC διεπαφές τους.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Για λεπτομερή αλυσίδα εκμετάλλευσης: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, δείτε:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** επιτρέπουν στα user-space driver binaries να επικοινωνούν απευθείας με τον kernel μέσω των IOKit interfaces. Τα DriverKit binaries διαχειρίζονται hardware: USB, Thunderbolt, PCIe, HID devices, audio, και networking.

Ο συμβιβασμός ενός DriverKit binary επιτρέπει:
- **Kernel attack surface** via malformed `IOConnectCallMethod` calls
- **USB device spoofing** (emulate keyboard for HID injection)
- **DMA attacks** through PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Για αναλυτική IOKit/DriverKit exploitation, δείτε:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
