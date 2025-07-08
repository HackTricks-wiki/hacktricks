# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε τρίτους, μόνο η Apple μπορεί να τα χορηγήσει.

## Υψηλό

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει να **παρακαμφθεί το SIP**. Δείτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει να **παρακαμφθεί το SIP**. Δείτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (προηγουμένως ονομαζόταν `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει να αποκτηθεί το **task port για οποιαδήποτε** διαδικασία, εκτός από τον πυρήνα. Δείτε [**αυτό για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλες διαδικασίες με το entitlement **`com.apple.security.cs.debugger`** να αποκτούν το task port της διαδικασίας που εκτελείται από το δυαδικό αρχείο με αυτό το entitlement και **να εισάγουν κώδικα σε αυτό**. Δείτε [**αυτό για περισσότερες πληροφορίες**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με το Entitlement Εργαλείου Αποσφαλμάτωσης μπορούν να καλέσουν `task_for_pid()` για να ανακτήσουν ένα έγκυρο task port για μη υπογεγραμμένες και τρίτες εφαρμογές με το entitlement `Get Task Allow` ρυθμισμένο σε `true`. Ωστόσο, ακόμη και με το entitlement εργαλείου αποσφαλμάτωσης, ένας αποσφαλματωτής **δεν μπορεί να αποκτήσει τα task ports** διαδικασιών που **δεν έχουν το entitlement `Get Task Allow`**, και που είναι επομένως προστατευμένες από την Προστασία Ακεραιότητας Συστήματος. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει να **φορτώνονται frameworks, plug-ins ή βιβλιοθήκες χωρίς να είναι είτε υπογεγραμμένα από την Apple είτε υπογεγραμμένα με το ίδιο Team ID** με το κύριο εκτελέσιμο, έτσι ώστε ένας επιτιθέμενος να μπορούσε να εκμεταλλευτεί κάποια αυθαίρετη φόρτωση βιβλιοθήκης για να εισάγει κώδικα. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με το **`com.apple.security.cs.disable-library-validation`** αλλά **αντί** να **απενεργοποιεί άμεσα** την επικύρωση βιβλιοθηκών, επιτρέπει στη διαδικασία να **καλέσει μια κλήση συστήματος `csops` για να την απενεργοποιήσει**.\
Δείτε [**αυτό για περισσότερες πληροφορίες**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει να **χρησιμοποιούνται μεταβλητές περιβάλλοντος DYLD** που θα μπορούσαν να χρησιμοποιηθούν για να εισάγουν βιβλιοθήκες και κώδικα. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ή `com.apple.rootless.storage`.`TCC`

[**Σύμφωνα με αυτό το blog**](https://objective-see.org/blog/blog_0x4C.html) **και** [**αυτό το blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν να **τροποποιηθεί** η βάση δεδομένων **TCC**.

### **`system.install.apple-software`** και **`system.install.apple-software.standar-user`**

Αυτά τα entitlements επιτρέπουν να **εγκαθίστανται λογισμικά χωρίς να ζητούν άδειες** από τον χρήστη, κάτι που μπορεί να είναι χρήσιμο για μια **κλιμάκωση προνομίων**.

### `com.apple.private.security.kext-management`

Entitlement που απαιτείται για να ζητήσει από τον **πυρήνα να φορτώσει μια επέκταση πυρήνα**.

### **`com.apple.private.icloud-account-access`**

Το entitlement **`com.apple.private.icloud-account-access`** επιτρέπει την επικοινωνία με την υπηρεσία XPC **`com.apple.iCloudHelper`** που θα **παρέχει tokens iCloud**.

Το **iMovie** και το **Garageband** είχαν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με την εκμετάλλευση για **να αποκτήσετε tokens icloud** από αυτό το entitlement, δείτε την ομιλία: [**#OBTS v5.0: "Τι συμβαίνει στον υπολογιστή σας, παραμένει στο iCloud της Apple;!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν ξέρω τι επιτρέπει να κάνετε

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Στο [**αυτό το αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για** να ενημερώσει τα περιεχόμενα που προστατεύονται από SSV μετά από επανεκκίνηση. Αν ξέρετε πώς, στείλτε μια PR παρακαλώ!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Στο [**αυτό το αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι αυτό θα μπορούσε να χρησιμοποιηθεί για** να ενημερώσει τα περιεχόμενα που προστατεύονται από SSV μετά από επανεκκίνηση. Αν ξέρετε πώς, στείλτε μια PR παρακαλώ!

### `keychain-access-groups`

Αυτό το entitlement καταγράφει τις ομάδες **keychain** στις οποίες η εφαρμογή έχει πρόσβαση:
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

Δίνει δικαιώματα **Πλήρους Πρόσβασης Δίσκου**, μία από τις υψηλότερες άδειες TCC που μπορείτε να έχετε.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει γεγονότα σε άλλες εφαρμογές που χρησιμοποιούνται συνήθως για **αυτοματοποίηση εργασιών**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τις άδειες που έχουν παραχωρηθεί σε αυτές τις άλλες εφαρμογές.

Όπως να τις κάνει να ζητούν από τον χρήστη τον κωδικό του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ή να τους κάνει να εκτελούν **τυχαίες ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων αδειών, να **γράψει τη βάση δεδομένων TCC των χρηστών**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει να **αλλάξει** την **`NFSHomeDirectory`** ιδιότητα ενός χρήστη που αλλάζει τη διαδρομή του φακέλου του και επομένως επιτρέπει να **παρακαμφθεί το TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα σε πακέτα εφαρμογών (μέσα στο app.app), κάτι που είναι **απαγορευμένο από προεπιλογή**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατόν να ελεγχθεί ποιος έχει αυτή την πρόσβαση στο _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Η διαδικασία θα μπορεί να **καταχραστεί τις δυνατότητες προσβασιμότητας του macOS**, που σημαίνει ότι για παράδειγμα θα μπορεί να πατάει πλήκτρα. Έτσι θα μπορούσε να ζητήσει πρόσβαση για να ελέγξει μια εφαρμογή όπως το Finder και να εγκρίνει το διάλογο με αυτή την άδεια.

## Medium

### `com.apple.security.cs.allow-jit`

Αυτή η άδεια επιτρέπει να **δημιουργήσει μνήμη που είναι εγ writable και εκτελέσιμη** περνώντας τη σημαία `MAP_JIT` στη συνάρτηση συστήματος `mmap()`. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτή η άδεια επιτρέπει να **υπερκαλύψει ή να διορθώσει C κώδικα**, να χρησιμοποιήσει τη μακροχρόνια αποσυρμένη **`NSCreateObjectFileImageFromMemory`** (η οποία είναι θεμελιωδώς ανασφαλής), ή να χρησιμοποιήσει το **DVDPlayback** framework. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Η συμπερίληψη αυτής της άδειας εκθέτει την εφαρμογή σας σε κοινές ευπάθειες σε γλώσσες κώδικα που είναι ανασφαλείς στη μνήμη. Σκεφτείτε προσεκτικά αν η εφαρμογή σας χρειάζεται αυτή την εξαίρεση.

### `com.apple.security.cs.disable-executable-page-protection`

Αυτή η άδεια επιτρέπει να **τροποποιήσει τμήματα των εκτελέσιμων αρχείων της** στο δίσκο για να εξαναγκάσει την έξοδο. Δείτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Η Άδεια Απενεργοποίησης Προστασίας Εκτελέσιμης Μνήμης είναι μια ακραία άδεια που αφαιρεί μια θεμελιώδη προστασία ασφαλείας από την εφαρμογή σας, καθιστώντας δυνατή την αναγραφή του εκτελέσιμου κώδικα της εφαρμογής σας χωρίς ανίχνευση. Προτιμήστε στενότερες άδειες αν είναι δυνατόν.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτή η άδεια επιτρέπει να τοποθετήσει ένα σύστημα αρχείων nullfs (απαγορευμένο από προεπιλογή). Εργαλείο: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτή την ανάρτηση στο blog, αυτή η άδεια TCC συνήθως βρίσκεται με τη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέψτε στη διαδικασία να **ζητήσει όλες τις άδειες TCC**.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}

</details>




{{#include /banners/hacktricks-training.md}}
