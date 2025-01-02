# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Το macOS Sandbox (αρχικά ονομαζόταν Seatbelt) **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο προφίλ Sandbox** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο σε αναμενόμενους πόρους**.

Οποιαδήποτε εφαρμογή με την **εξουσιοδότηση** **`com.apple.security.app-sandbox`** θα εκτελείται μέσα στο sandbox. **Οι δυαδικοί κώδικες της Apple** εκτελούνται συνήθως μέσα σε ένα Sandbox, και όλες οι εφαρμογές από το **App Store έχουν αυτή την εξουσιοδότηση**. Έτσι, πολλές εφαρμογές θα εκτελούνται μέσα στο sandbox.

Για να ελέγξει τι μπορεί ή δεν μπορεί να κάνει μια διαδικασία, το **Sandbox έχει hooks** σε σχεδόν οποιαδήποτε λειτουργία μπορεί να προσπαθήσει μια διαδικασία (συμπεριλαμβανομένων των περισσότερων syscalls) χρησιμοποιώντας **MACF**. Ωστόσο, **ανάλογα** με τις **εξουσιοδοτήσεις** της εφαρμογής, το Sandbox μπορεί να είναι πιο επιεικής με τη διαδικασία.

Ορισμένα σημαντικά στοιχεία του Sandbox είναι:

- Η **επέκταση πυρήνα** `/System/Library/Extensions/Sandbox.kext`
- Το **ιδιωτικό πλαίσιο** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Ένας **daemon** που εκτελείται στο userland `/usr/libexec/sandboxd`
- Οι **κοντέινερ** `~/Library/Containers`

### Containers

Κάθε sandboxed εφαρμογή θα έχει το δικό της κοντέινερ στο `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Μέσα σε κάθε φάκελο bundle id μπορείτε να βρείτε το **plist** και τον **φάκελο Δεδομένων** της εφαρμογής με μια δομή που μιμείται τον φάκελο Home:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Σημειώστε ότι ακόμη και αν τα symlinks είναι εκεί για να "ξεφύγουν" από το Sandbox και να αποκτήσουν πρόσβαση σε άλλους φακέλους, η εφαρμογή πρέπει να **έχει άδειες** για να τους προσπελάσει. Αυτές οι άδειες βρίσκονται μέσα στο **`.plist`** στο `RedirectablePaths`.

Το **`SandboxProfileData`** είναι το συμπιεσμένο προφίλ sandbox CFData που έχει διαφύγει σε B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Ό,τι δημιουργείται/τροποποιείται από μια εφαρμογή που είναι σε Sandbox θα αποκτήσει το **quarantine attribute**. Αυτό θα αποτρέψει έναν χώρο sandbox ενεργοποιώντας τον Gatekeeper αν η εφαρμογή sandbox προσπαθήσει να εκτελέσει κάτι με **`open`**.

## Sandbox Profiles

Τα Sandbox profiles είναι αρχεία ρυθμίσεων που υποδεικνύουν τι θα είναι **επιτρεπτό/απαγορευμένο** σε αυτό το **Sandbox**. Χρησιμοποιεί τη **Sandbox Profile Language (SBPL)**, η οποία χρησιμοποιεί τη γλώσσα προγραμματισμού [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>). 

Εδώ μπορείτε να βρείτε ένα παράδειγμα:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Ελέγξτε αυτήν την [**έρευνα**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **για να δείτε περισσότερες ενέργειες που θα μπορούσαν να επιτραπούν ή να απορριφθούν.**
>
> Σημειώστε ότι στην συμπιεσμένη έκδοση ενός προφίλ, τα ονόματα των λειτουργιών αντικαθίστανται από τις καταχωρίσεις τους σε έναν πίνακα που είναι γνωστός από το dylib και το kext, καθιστώντας την συμπιεσμένη έκδοση πιο σύντομη και πιο δύσκολη στην ανάγνωση.

Σημαντικές **υπηρεσίες συστήματος** εκτελούνται επίσης μέσα στο δικό τους προσαρμοσμένο **sandbox** όπως η υπηρεσία `mdnsresponder`. Μπορείτε να δείτε αυτά τα προσαρμοσμένα **προφίλ sandbox** μέσα σε:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Άλλα προφίλ sandbox μπορούν να ελεγχθούν στο [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Οι εφαρμογές του **App Store** χρησιμοποιούν το **προφίλ** **`/System/Library/Sandbox/Profiles/application.sb`**. Μπορείτε να ελέγξετε σε αυτό το προφίλ πώς οι εξουσιοδοτήσεις όπως **`com.apple.security.network.server`** επιτρέπουν σε μια διαδικασία να χρησιμοποιεί το δίκτυο.

Το SIP είναι ένα προφίλ Sandbox που ονομάζεται platform_profile στο /System/Library/Sandbox/rootless.conf

### Παραδείγματα Προφίλ Sandbox

Για να ξεκινήσετε μια εφαρμογή με ένα **συγκεκριμένο προφίλ sandbox** μπορείτε να χρησιμοποιήσετε:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> Σημειώστε ότι το **λογισμικό** που έχει αναπτυχθεί από την **Apple** που τρέχει σε **Windows** **δεν έχει επιπλέον μέτρα ασφαλείας**, όπως η απομόνωση εφαρμογών.

Παραδείγματα παρακάμψεων:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (μπορούν να γράψουν αρχεία εκτός της απομόνωσης των οποίων το όνομα ξεκινά με `~$`).

### Ιχνηλάτηση Απομόνωσης

#### Μέσω προφίλ

Είναι δυνατόν να ιχνηλατηθούν όλοι οι έλεγχοι που εκτελεί η απομόνωση κάθε φορά που ελέγχεται μια ενέργεια. Για αυτό, απλώς δημιουργήστε το παρακάτω προφίλ:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Και στη συνέχεια απλώς εκτελέστε κάτι χρησιμοποιώντας αυτό το προφίλ:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Στο `/tmp/trace.out` θα μπορείτε να δείτε κάθε έλεγχο sandbox που εκτελέστηκε κάθε φορά που κλήθηκε (οπότε, πολλά διπλότυπα).

Είναι επίσης δυνατό να παρακολουθήσετε το sandbox χρησιμοποιώντας την παράμετρο **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Μέσω API

Η συνάρτηση `sandbox_set_trace_path` που εξάγεται από το `libsystem_sandbox.dylib` επιτρέπει να καθορίσετε ένα όνομα αρχείου καταγραφής όπου θα γράφονται οι έλεγχοι sandbox.\
Είναι επίσης δυνατό να κάνετε κάτι παρόμοιο καλώντας `sandbox_vtrace_enable()` και στη συνέχεια να αποκτήσετε τα σφάλματα καταγραφής από το buffer καλώντας `sandbox_vtrace_report()`.

### Επιθεώρηση Sandbox

Το `libsandbox.dylib` εξάγει μια συνάρτηση που ονομάζεται sandbox_inspect_pid η οποία δίνει μια λίστα της κατάστασης του sandbox μιας διαδικασίας (συμπεριλαμβανομένων των επεκτάσεων). Ωστόσο, μόνο οι δυαδικοί κωδικοί της πλατφόρμας μπορούν να χρησιμοποιήσουν αυτή τη συνάρτηση.

### Προφίλ Sandbox MacOS & iOS

Το MacOS αποθηκεύει τα προφίλ sandbox του συστήματος σε δύο τοποθεσίες: **/usr/share/sandbox/** και **/System/Library/Sandbox/Profiles**.

Και αν μια εφαρμογή τρίτου μέρους φέρει την _**com.apple.security.app-sandbox**_ εξουσιοδότηση, το σύστημα εφαρμόζει το προφίλ **/System/Library/Sandbox/Profiles/application.sb** σε αυτή τη διαδικασία.

Στο iOS, το προεπιλεγμένο προφίλ ονομάζεται **container** και δεν έχουμε την κειμενική αναπαράσταση SBPL. Στη μνήμη, αυτό το sandbox αναπαρίσταται ως δυαδικό δέντρο Allow/Deny για κάθε άδεια από το sandbox.

### Προσαρμοσμένο SBPL σε εφαρμογές App Store

Θα μπορούσε να είναι δυνατό για τις εταιρείες να κάνουν τις εφαρμογές τους να εκτελούνται **με προσαρμοσμένα προφίλ Sandbox** (αντί με το προεπιλεγμένο). Πρέπει να χρησιμοποιήσουν την εξουσιοδότηση **`com.apple.security.temporary-exception.sbpl`** η οποία πρέπει να εγκριθεί από την Apple.

Είναι δυνατό να ελέγξετε τον ορισμό αυτής της εξουσιοδότησης στο **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Αυτό θα **eval την αλφαβητική σειρά μετά από αυτή την εξουσιοδότηση** ως προφίλ Sandbox.

### Συγκέντρωση & αποσυμπίεση ενός προφίλ Sandbox

Το **`sandbox-exec`** εργαλείο χρησιμοποιεί τις συναρτήσεις `sandbox_compile_*` από το `libsandbox.dylib`. Οι κύριες συναρτήσεις που εξάγονται είναι: `sandbox_compile_file` (αναμένει μια διαδρομή αρχείου, παράμετρος `-f`), `sandbox_compile_string` (αναμένει μια αλφαβητική σειρά, παράμετρος `-p`), `sandbox_compile_name` (αναμένει ένα όνομα κοντέινερ, παράμετρος `-n`), `sandbox_compile_entitlements` (αναμένει plist εξουσιοδοτήσεων).

Αυτή η αντίστροφη και [**ανοιχτού κώδικα έκδοση του εργαλείου sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) επιτρέπει στο **`sandbox-exec`** να γράφει σε ένα αρχείο το συγκεντρωμένο προφίλ sandbox.

Επιπλέον, για να περιορίσει μια διαδικασία μέσα σε ένα κοντέινερ, μπορεί να καλέσει `sandbox_spawnattrs_set[container/profilename]` και να περάσει ένα κοντέινερ ή προϋπάρχον προφίλ.

## Debug & Παράκαμψη Sandbox

Στο macOS, σε αντίθεση με το iOS όπου οι διαδικασίες είναι sandboxed από την αρχή από τον πυρήνα, **οι διαδικασίες πρέπει να επιλέξουν να μπουν στο sandbox μόνες τους**. Αυτό σημαίνει ότι στο macOS, μια διαδικασία δεν περιορίζεται από το sandbox μέχρι να αποφασίσει ενεργά να εισέλθει σε αυτό, αν και οι εφαρμογές του App Store είναι πάντα sandboxed.

Οι διαδικασίες είναι αυτόματα Sandboxed από το userland όταν ξεκινούν αν έχουν την εξουσιοδότηση: `com.apple.security.app-sandbox`. Για μια λεπτομερή εξήγηση αυτής της διαδικασίας, ελέγξτε:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Επεκτάσεις Sandbox**

Οι επεκτάσεις επιτρέπουν να δοθούν περαιτέρω προνόμια σε ένα αντικείμενο και δίνονται καλώντας μία από τις συναρτήσεις:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Οι επεκτάσεις αποθηκεύονται στη δεύτερη υποδοχή ετικέτας MACF που είναι προσβάσιμη από τα διαπιστευτήρια της διαδικασίας. Το ακόλουθο **`sbtool`** μπορεί να έχει πρόσβαση σε αυτές τις πληροφορίες.

Σημειώστε ότι οι επεκτάσεις συνήθως χορηγούνται από επιτρεπόμενες διαδικασίες, για παράδειγμα, το `tccd` θα χορηγήσει το token επέκτασης του `com.apple.tcc.kTCCServicePhotos` όταν μια διαδικασία προσπαθήσει να αποκτήσει πρόσβαση στις φωτογραφίες και επιτρεπόταν σε ένα μήνυμα XPC. Στη συνέχεια, η διαδικασία θα χρειαστεί να καταναλώσει το token επέκτασης ώστε να προστεθεί σε αυτήν.\
Σημειώστε ότι τα tokens επεκτάσεων είναι μακροχρόνια δεκαεξαδικά που κωδικοποιούν τις χορηγούμενες άδειες. Ωστόσο, δεν έχουν τον επιτρεπόμενο PID σκληρά κωδικοποιημένο, πράγμα που σημαίνει ότι οποιαδήποτε διαδικασία με πρόσβαση στο token μπορεί να είναι **καταναλωμένη από πολλές διαδικασίες**.

Σημειώστε ότι οι επεκτάσεις σχετίζονται πολύ και με τις εξουσιοδοτήσεις, οπότε η κατοχή ορισμένων εξουσιοδοτήσεων μπορεί αυτόματα να χορηγήσει ορισμένες επεκτάσεις.

### **Έλεγχος Προνομίων PID**

[**Σύμφωνα με αυτό**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), οι συναρτήσεις **`sandbox_check`** (είναι μια `__mac_syscall`), μπορούν να ελέγξουν **αν μια ενέργεια επιτρέπεται ή όχι** από το sandbox σε έναν συγκεκριμένο PID, audit token ή μοναδικό ID.

Το [**εργαλείο sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (βρείτε το [συγκεντρωμένο εδώ](https://newosxbook.com/articles/hitsb.html)) μπορεί να ελέγξει αν ένας PID μπορεί να εκτελέσει ορισμένες ενέργειες:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Είναι επίσης δυνατή η αναστολή και η αποαναστολή του sandbox χρησιμοποιώντας τις συναρτήσεις `sandbox_suspend` και `sandbox_unsuspend` από το `libsystem_sandbox.dylib`.

Σημειώστε ότι για να καλέσετε τη συνάρτηση αναστολής ελέγχονται ορισμένα δικαιώματα προκειμένου να εξουσιοδοτηθεί ο καλών να την καλέσει όπως:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Αυτή η κλήση συστήματος (#381) αναμένει ένα string ως πρώτο επιχείρημα που θα υποδείξει το module που θα εκτελεστεί, και στη συνέχεια έναν κωδικό ως δεύτερο επιχείρημα που θα υποδείξει τη συνάρτηση που θα εκτελεστεί. Στη συνέχεια, το τρίτο επιχείρημα θα εξαρτάται από τη συνάρτηση που εκτελείται.

Η κλήση συνάρτησης `___sandbox_ms` περιτυλίγει το `mac_syscall` υποδεικνύοντας στο πρώτο επιχείρημα `"Sandbox"` ακριβώς όπως το `___sandbox_msp` είναι μια περιτύλιξη του `mac_set_proc` (#387). Στη συνέχεια, μερικοί από τους υποστηριζόμενους κωδικούς από το `___sandbox_ms` μπορούν να βρεθούν σε αυτόν τον πίνακα:

- **set_profile (#0)**: Εφαρμόστε ένα συμπιεσμένο ή ονομασμένο προφίλ σε μια διαδικασία.
- **platform_policy (#1)**: Επιβάλλετε ελέγχους πολιτικής συγκεκριμένης πλατφόρμας (διαφέρει μεταξύ macOS και iOS).
- **check_sandbox (#2)**: Εκτελέστε έναν χειροκίνητο έλεγχο μιας συγκεκριμένης λειτουργίας sandbox.
- **note (#3)**: Προσθέτει μια σημείωση σε ένα Sandbox
- **container (#4)**: Συνδέστε μια σημείωση σε ένα sandbox, συνήθως για αποσφαλμάτωση ή αναγνώριση.
- **extension_issue (#5)**: Δημιουργήστε μια νέα επέκταση για μια διαδικασία.
- **extension_consume (#6)**: Καταναλώστε μια δεδομένη επέκταση.
- **extension_release (#7)**: Απελευθερώστε τη μνήμη που σχετίζεται με μια καταναλωθείσα επέκταση.
- **extension_update_file (#8)**: Τροποποιήστε τις παραμέτρους μιας υπάρχουσας επέκτασης αρχείου εντός του sandbox.
- **extension_twiddle (#9)**: Ρυθμίστε ή τροποποιήστε μια υπάρχουσα επέκταση αρχείου (π.χ., TextEdit, rtf, rtfd).
- **suspend (#10)**: Αναστείλετε προσωρινά όλους τους ελέγχους sandbox (απαιτεί κατάλληλα δικαιώματα).
- **unsuspend (#11)**: Επαναφέρετε όλους τους προηγουμένως ανασταλμένους ελέγχους sandbox.
- **passthrough_access (#12)**: Επιτρέψτε άμεση πρόσβαση passthrough σε μια πηγή, παρακάμπτοντας τους ελέγχους sandbox.
- **set_container_path (#13)**: (μόνο iOS) Ορίστε μια διαδρομή container για μια ομάδα εφαρμογών ή ID υπογραφής.
- **container_map (#14)**: (μόνο iOS) Ανακτήστε μια διαδρομή container από το `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Ορίστε μεταδεδομένα λειτουργίας χρήστη στο sandbox.
- **inspect (#16)**: Παρέχετε πληροφορίες αποσφαλμάτωσης σχετικά με μια διαδικασία που είναι sandboxed.
- **dump (#18)**: (macOS 11) Εκτυπώστε το τρέχον προφίλ ενός sandbox για ανάλυση.
- **vtrace (#19)**: Παρακολουθήστε τις λειτουργίες sandbox για παρακολούθηση ή αποσφαλμάτωση.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Απενεργοποιήστε τα ονομασμένα προφίλ (π.χ., `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Εκτελέστε πολλές λειτουργίες `sandbox_check` σε μία μόνο κλήση.
- **reference_retain_by_audit_token (#28)**: Δημιουργήστε μια αναφορά για ένα audit token για χρήση σε ελέγχους sandbox.
- **reference_release (#29)**: Απελευθερώστε μια προηγουμένως διατηρημένη αναφορά audit token.
- **rootless_allows_task_for_pid (#30)**: Επαληθεύστε εάν επιτρέπεται το `task_for_pid` (παρόμοιο με τους ελέγχους `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Εφαρμόστε ένα αρχείο manifest System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Ελέγξτε το αρχείο manifest SIP πριν από την εκτέλεση.
- **rootless_protected_volume (#33)**: (macOS) Εφαρμόστε SIP προστασίες σε έναν δίσκο ή διαμέρισμα.
- **rootless_mkdir_protected (#34)**: Εφαρμόστε SIP/DataVault προστασία σε μια διαδικασία δημιουργίας καταλόγου.

## Sandbox.kext

Σημειώστε ότι στο iOS η επέκταση πυρήνα περιέχει **σκληρά κωδικοποιημένα όλα τα προφίλ** μέσα στο τμήμα `__TEXT.__const` για να αποφευχθεί η τροποποίησή τους. Ακολουθούν ορισμένες ενδιαφέρουσες συναρτήσεις από την επέκταση πυρήνα:

- **`hook_policy_init`**: Συνδέει το `mpo_policy_init` και καλείται μετά το `mac_policy_register`. Εκτελεί τις περισσότερες από τις αρχικοποιήσεις του Sandbox. Επίσης, αρχικοποιεί το SIP.
- **`hook_policy_initbsd`**: Ρυθμίζει τη διεπαφή sysctl καταχωρώντας `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` και `security.mac.sandbox.debug_mode` (αν έχει εκκινήσει με `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Καλείται από το `mac_syscall` με "Sandbox" ως πρώτο επιχείρημα και κωδικό που υποδεικνύει τη λειτουργία στο δεύτερο. Χρησιμοποιείται ένα switch για να βρεθεί ο κωδικός που θα εκτελεστεί σύμφωνα με τον ζητούμενο κωδικό.

### MACF Hooks

**`Sandbox.kext`** χρησιμοποιεί περισσότερους από εκατό hooks μέσω MACF. Οι περισσότεροι από τους hooks θα ελέγξουν απλώς ορισμένες τυπικές περιπτώσεις που επιτρέπουν την εκτέλεση της ενέργειας, αν όχι, θα καλέσουν **`cred_sb_evalutate`** με τα **διαπιστευτήρια** από το MACF και έναν αριθμό που αντιστοιχεί στην **λειτουργία** που θα εκτελεστεί και ένα **buffer** για την έξοδο.

Ένα καλό παράδειγμα αυτού είναι η συνάρτηση **`_mpo_file_check_mmap`** που έχει συνδεθεί με **`mmap`** και η οποία θα αρχίσει να ελέγχει αν η νέα μνήμη θα είναι εγγράψιμη (και αν όχι θα επιτρέψει την εκτέλεση), στη συνέχεια θα ελέγξει αν χρησιμοποιείται για την κοινή μνήμη dyld και αν ναι θα επιτρέψει την εκτέλεση, και τελικά θα καλέσει **`sb_evaluate_internal`** (ή μία από τις περιτυλίξεις της) για να εκτελέσει περαιτέρω ελέγχους επιτρεπόμενης πρόσβασης.

Επιπλέον, από τους εκατοντάδες hooks που χρησιμοποιεί το Sandbox, υπάρχουν 3 που είναι ιδιαίτερα ενδιαφέροντα:

- `mpo_proc_check_for`: Εφαρμόζει το προφίλ αν χρειάζεται και αν δεν έχει εφαρμοστεί προηγουμένως
- `mpo_vnode_check_exec`: Καλείται όταν μια διαδικασία φορτώνει το σχετικό δυαδικό, στη συνέχεια εκτελείται έλεγχος προφίλ και επίσης έλεγχος που απαγορεύει τις εκτελέσεις SUID/SGID.
- `mpo_cred_label_update_execve`: Αυτό καλείται όταν ανατίθεται η ετικέτα. Αυτό είναι το πιο μακρύ καθώς καλείται όταν το δυαδικό έχει φορτωθεί πλήρως αλλά δεν έχει εκτελεστεί ακόμη. Θα εκτελέσει ενέργειες όπως η δημιουργία του αντικειμένου sandbox, η σύνδεση της δομής sandbox στα διαπιστευτήρια kauth, η αφαίρεση πρόσβασης σε mach ports...

Σημειώστε ότι **`_cred_sb_evalutate`** είναι μια περιτύλιξη πάνω από **`sb_evaluate_internal`** και αυτή η συνάρτηση παίρνει τα διαπιστευτήρια που περνιούνται και στη συνέχεια εκτελεί την αξιολόγηση χρησιμοποιώντας τη συνάρτηση **`eval`** που συνήθως αξιολογεί το **προφίλ πλατφόρμας** που εφαρμόζεται από προεπιλογή σε όλες τις διαδικασίες και στη συνέχεια το **συγκεκριμένο προφίλ διαδικασίας**. Σημειώστε ότι το προφίλ πλατφόρμας είναι ένα από τα κύρια συστατικά του **SIP** στο macOS.

## Sandboxd

Το Sandbox έχει επίσης έναν daemon χρήστη που εκτελεί την υπηρεσία XPC Mach `com.apple.sandboxd` και δεσμεύει την ειδική θύρα 14 (`HOST_SEATBELT_PORT`) την οποία χρησιμοποιεί η επέκταση πυρήνα για να επικοινωνήσει μαζί της. Εκθέτει ορισμένες συναρτήσεις χρησιμοποιώντας MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
