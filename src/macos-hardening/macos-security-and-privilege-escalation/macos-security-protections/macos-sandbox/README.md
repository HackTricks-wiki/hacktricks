# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το MacOS Sandbox (αρχικά ονομαζόμενο Seatbelt) **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο Sandbox profile** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο στους αναμενόμενους πόρους**.

Κάθε εφαρμογή με το **entitlement** **`com.apple.security.app-sandbox`** θα εκτελείται μέσα στο sandbox. Τα **Apple binaries** συνήθως εκτελούνται μέσα σε Sandbox, ενώ όλες οι εφαρμογές από το **App Store έχουν αυτό το entitlement**. Επομένως, αρκετές εφαρμογές θα εκτελούνται μέσα στο sandbox.<sup>[[4]](#references)</sup>

Για να ελέγχει τι μπορεί ή δεν μπορεί να κάνει μια διεργασία, το **Sandbox διαθέτει hooks** σχεδόν σε κάθε λειτουργία που μπορεί να επιχειρήσει μια διεργασία (συμπεριλαμβανομένων των περισσότερων syscalls), χρησιμοποιώντας το **MACF**. Ωστόσο, **ανάλογα** με τα **entitlements** της εφαρμογής, το Sandbox μπορεί να είναι πιο permissive απέναντι στη διεργασία.

Μερικά σημαντικά στοιχεία του Sandbox είναι:

- Το **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- Το **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Ένας **daemon** που εκτελείται σε userland `/usr/libexec/sandboxd`
- Τα **containers** `~/Library/Containers`

### Containers

Κάθε εφαρμογή που εκτελείται σε sandbox θα έχει το δικό της container στο `~/Library/Containers/{CFBundleIdentifier}` :
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
Μέσα σε κάθε φάκελο bundle id μπορείτε να βρείτε το **plist** και τον **Data directory** της App, με μια δομή που μιμείται τον φάκελο Home:
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
> Σημειώστε ότι, ακόμη και αν υπάρχουν symlinks για να γίνει «διαφυγή» από το Sandbox και να αποκτηθεί πρόσβαση σε άλλους φακέλους, το App πρέπει να **έχει δικαιώματα** πρόσβασης σε αυτούς. Αυτά τα δικαιώματα βρίσκονται μέσα στο **`.plist`**, στο `RedirectablePaths`.

Το **`SandboxProfileData`** είναι το μεταγλωττισμένο sandbox profile CFData, κωδικοποιημένο σε B64.
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
> Ό,τι δημιουργείται ή τροποποιείται από μια εφαρμογή που εκτελείται σε Sandbox λαμβάνει το **quarantine attribute**. Αυτό μπορεί να αποτρέψει ένα sandbox escape, ενεργοποιώντας το Gatekeeper, αν η εφαρμογή που εκτελείται σε Sandbox προσπαθήσει να εκτελέσει κάτι με το **`open`**.

## Προφίλ Sandbox

Τα προφίλ Sandbox είναι αρχεία διαμόρφωσης που υποδεικνύουν τι θα **επιτρέπεται/απαγορεύεται** σε αυτό το **Sandbox**. Χρησιμοποιούν τη **Sandbox Profile Language (SBPL)**, η οποία χρησιμοποιεί τη γλώσσα προγραμματισμού [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Εδώ μπορείτε να βρείτε ένα παράδειγμα:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> Ελέγξτε αυτή την [**έρευνα**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **για να δείτε περισσότερες ενέργειες που θα μπορούσαν να επιτρέπονται ή να απορρίπτονται.**<sup>[[5]](#references)</sup>
>
> Σημειώστε ότι στη μεταγλωττισμένη έκδοση ενός profile, τα ονόματα των λειτουργιών αντικαθίστανται από τις καταχωρίσεις τους σε έναν πίνακα γνωστό στο dylib και το kext, καθιστώντας τη μεταγλωττισμένη έκδοση μικρότερη και δυσκολότερη στην ανάγνωση.

Σημαντικές **υπηρεσίες συστήματος** εκτελούνται επίσης μέσα στο δικό τους προσαρμοσμένο **sandbox**, όπως η υπηρεσία `mdnsresponder`. Μπορείτε να δείτε αυτά τα προσαρμοσμένα **sandbox profiles** μέσα στους εξής καταλόγους:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Άλλα sandbox profiles μπορούν να ελεγχθούν στο [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- Στο iOS, το platform profile βρίσκεται μέσα στο sandbox `.kext`, στο `_platform_profile_data`, μέσα στο binary.

Οι εφαρμογές του **App Store** χρησιμοποιούν το **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Σε αυτό το profile μπορείτε να δείτε πώς entitlements όπως το **`com.apple.security.network.server`** επιτρέπουν σε μια διεργασία να χρησιμοποιεί το δίκτυο.

Στη συνέχεια, ορισμένες **Apple daemon services** χρησιμοποιούν διαφορετικά profiles που βρίσκονται στα `/System/Library/Sandbox/Profiles/*.sb` ή `/usr/share/sandbox/*.sb`. Αυτά τα sandboxes εφαρμόζονται στην κύρια συνάρτηση που καλεί το API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

Το **SIP** είναι ένα Sandbox profile με την ονομασία platform_profile στο `/System/Library/Sandbox/rootless.conf`.

### Παραδείγματα Sandbox Profiles

Για να εκκινήσετε μια εφαρμογή με ένα **συγκεκριμένο sandbox profile**, μπορείτε να χρησιμοποιήσετε:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> Σημειώστε ότι το **λογισμικό** που έχει δημιουργηθεί από την **Apple** και εκτελείται σε **Windows** **δεν διαθέτει πρόσθετες προφυλάξεις ασφαλείας**, όπως application sandboxing.

Παραδείγματα Bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (μπορούν να γράφουν αρχεία εκτός του Sandbox, το όνομα των οποίων ξεκινά με `~$`).<sup>[[7]](#references)</sup>

### Ιχνηλάτηση Sandbox

#### Μέσω profile

Είναι δυνατή η ιχνηλάτηση όλων των ελέγχων που εκτελεί το Sandbox κάθε φορά που ελέγχεται μια ενέργεια. Για αυτό, δημιουργήστε απλώς το ακόλουθο profile:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Και μετά απλώς εκτέλεσε κάτι χρησιμοποιώντας αυτό το προφίλ:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Στο `/tmp/trace.out` θα μπορείτε να δείτε κάθε sandbox check που εκτελείται κάθε φορά που καλείται (επομένως, πολλές διπλότυπες καταχωρίσεις).

Είναι επίσης δυνατή η καταγραφή του sandbox με την παράμετρο **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Μέσω API

Η συνάρτηση `sandbox_set_trace_path` που εξάγεται από το `libsystem_sandbox.dylib` επιτρέπει τον καθορισμό ενός ονόματος αρχείου trace, στο οποίο θα καταγράφονται οι sandbox checks.\
Είναι επίσης δυνατό να γίνει κάτι παρόμοιο με την κλήση της `sandbox_vtrace_enable()` και, στη συνέχεια, τη λήψη των error logs από το buffer μέσω της `sandbox_vtrace_report()`.

### Έλεγχος Sandbox

Το `libsandbox.dylib` εξάγει μια συνάρτηση που ονομάζεται sandbox_inspect_pid και παρέχει μια λίστα με την κατάσταση του sandbox μιας διεργασίας (συμπεριλαμβανομένων των extensions). Ωστόσο, μόνο platform binaries μπορούν να χρησιμοποιήσουν αυτήν τη συνάρτηση.

### Προφίλ Sandbox MacOS & iOS

Το MacOS αποθηκεύει τα system sandbox profiles σε δύο τοποθεσίες: **/usr/share/sandbox/** και **/System/Library/Sandbox/Profiles**.

Και αν μια εφαρμογή τρίτου μέρους διαθέτει το entitlement _**com.apple.security.app-sandbox**_, το σύστημα εφαρμόζει το προφίλ **/System/Library/Sandbox/Profiles/application.sb** σε αυτήν τη διεργασία.

Στο iOS, το default profile ονομάζεται **container** και δεν διαθέτουμε την αναπαράσταση κειμένου SBPL. Στη μνήμη, αυτό το sandbox αναπαρίσταται ως δυαδικό δέντρο Allow/Deny για κάθε permission του sandbox.

### Custom SBPL σε εφαρμογές του App Store

Θα ήταν δυνατό για εταιρείες να κάνουν τις εφαρμογές τους να εκτελούνται **με custom Sandbox profiles** (αντί για το default profile). Πρέπει να χρησιμοποιήσουν το entitlement **`com.apple.security.temporary-exception.sbpl`**, το οποίο πρέπει να εγκριθεί από την Apple.

Είναι δυνατός ο έλεγχος του ορισμού αυτού του entitlement στο **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Αυτό θα κάνει **eval το string μετά από αυτό το entitlement** ως Sandbox profile.

### Compile & decompile ενός Sandbox Profile

Το εργαλείο **`sandbox-exec`** χρησιμοποιεί τις functions `sandbox_compile_*` από το `libsandbox.dylib`. Οι κύριες exported functions είναι: `sandbox_compile_file` (δέχεται file path, παράμετρος `-f`), `sandbox_compile_string` (δέχεται string, παράμετρος `-p`), `sandbox_compile_name` (δέχεται όνομα container, παράμετρος `-n`), `sandbox_compile_entitlements` (δέχεται entitlements plist).

Αυτή η reverse-engineered και [**open sourced έκδοση του εργαλείου sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) επιτρέπει στο **`sandbox-exec`** να γράψει σε ένα file το compiled sandbox profile.

Επιπλέον, για να περιορίσει ένα process μέσα σε ένα container, μπορεί να καλέσει το `sandbox_spawnattrs_set[container/profilename]` και να περάσει ένα container ή ένα pre-existing profile.

## Debug & Bypass του Sandbox

Στο macOS, σε αντίθεση με το iOS όπου τα processes γίνονται sandboxed εξαρχής από τον kernel, τα **processes πρέπει να κάνουν opt-in στο Sandbox από μόνα τους**. Αυτό σημαίνει ότι στο macOS ένα process δεν περιορίζεται από το Sandbox μέχρι να αποφασίσει ενεργά να εισέλθει σε αυτό, παρόλο που τα App Store apps είναι πάντα sandboxed.

Τα processes γίνονται αυτόματα Sandboxed από το userland κατά την εκκίνησή τους, εάν διαθέτουν το entitlement: `com.apple.security.app-sandbox`. Για λεπτομερή εξήγηση αυτής της διαδικασίας, έλεγξε:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Τα Extensions επιτρέπουν την παροχή πρόσθετων privileges σε ένα object και καλούν μία από τις functions:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Τα extensions αποθηκεύονται στο δεύτερο MACF label slot, το οποίο είναι προσβάσιμο από τα process credentials. Το ακόλουθο **`sbtool`** μπορεί να έχει πρόσβαση σε αυτές τις πληροφορίες.

Σημείωσε ότι τα extensions συνήθως παρέχονται από allowed processes· για παράδειγμα, το `tccd` θα παρέχει το extension token του `com.apple.tcc.kTCCServicePhotos` όταν ένα process προσπαθήσει να αποκτήσει πρόσβαση στις photos και λάβει έγκριση σε ένα XPC message. Στη συνέχεια, το process πρέπει να καταναλώσει το extension token, ώστε αυτό να προστεθεί σε αυτό.\
Σημείωσε ότι τα extension tokens είναι μεγάλα δεκαεξαδικά strings που κωδικοποιούν τα granted permissions. Ωστόσο, δεν έχουν hardcoded το allowed PID, πράγμα που σημαίνει ότι οποιοδήποτε process με πρόσβαση στο token μπορεί να **καταναλωθεί από multiple processes**.

Σημείωσε επίσης ότι τα extensions σχετίζονται σε μεγάλο βαθμό και με τα entitlements, επομένως η κατοχή συγκεκριμένων entitlements μπορεί να παρέχει αυτόματα συγκεκριμένα extensions.

### **Έλεγχος Privileges ενός PID**

[**Σύμφωνα με αυτό**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), οι **`sandbox_check`** functions (είναι ένα `__mac_syscall`) μπορούν να ελέγξουν **αν μια operation επιτρέπεται ή όχι** από το Sandbox σε ένα συγκεκριμένο PID, audit token ή unique ID.<sup>[[8]](#references)</sup>

Το [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (βρες το [compiled εδώ](https://newosxbook.com/articles/hitsb.html)) μπορεί να ελέγξει αν ένα PID μπορεί να εκτελέσει συγκεκριμένες actions:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Είναι επίσης δυνατή η αναστολή και η επαναφορά του sandbox χρησιμοποιώντας τις συναρτήσεις `sandbox_suspend` και `sandbox_unsuspend` από το `libsystem_sandbox.dylib`.

Σημειώστε ότι για την κλήση της συνάρτησης αναστολής ελέγχονται ορισμένα entitlements, ώστε να εξουσιοδοτηθεί ο caller να την καλέσει, όπως:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Αυτό το system call (#381) αναμένει ένα string ως πρώτο όρισμα, το οποίο υποδεικνύει το module που θα εκτελεστεί, και στη συνέχεια έναν κωδικό στο δεύτερο όρισμα, ο οποίος υποδεικνύει τη συνάρτηση που θα εκτελεστεί. Το τρίτο όρισμα εξαρτάται από τη συνάρτηση που εκτελείται.<sup>[[2]](#references)</sup>

Η συνάρτηση `___sandbox_ms` είναι wrapper του `mac_syscall`, υποδεικνύοντας στο πρώτο όρισμα το `"Sandbox"`, όπως ακριβώς η `___sandbox_msp` είναι wrapper του `mac_set_proc` (#387). Στη συνέχεια, ορισμένοι από τους υποστηριζόμενους κωδικούς από την `___sandbox_ms` εμφανίζονται στον παρακάτω πίνακα:

- **set_profile (#0)**: Εφαρμογή ενός compiled ή named profile σε ένα process.
- **platform_policy (#1)**: Επιβολή platform-specific ελέγχων policy (διαφέρει μεταξύ macOS και iOS).
- **check_sandbox (#2)**: Εκτέλεση manual ελέγχου μιας συγκεκριμένης λειτουργίας του sandbox.
- **note (#3)**: Προσθήκη annotation σε ένα Sandbox.
- **container (#4)**: Επισύναψη annotation σε ένα sandbox, συνήθως για debugging ή identification.
- **extension_issue (#5)**: Δημιουργία νέου extension για ένα process.
- **extension_consume (#6)**: Κατανάλωση ενός δεδομένου extension.
- **extension_release (#7)**: Αποδέσμευση της μνήμης που συνδέεται με ένα consumed extension.
- **extension_update_file (#8)**: Τροποποίηση των παραμέτρων ενός υπάρχοντος file extension μέσα στο sandbox.
- **extension_twiddle (#9)**: Προσαρμογή ή τροποποίηση ενός υπάρχοντος file extension (π.χ. TextEdit, rtf, rtfd).
- **suspend (#10)**: Προσωρινή αναστολή όλων των sandbox checks (απαιτούνται τα κατάλληλα entitlements).
- **unsuspend (#11)**: Επαναφορά όλων των sandbox checks που είχαν προηγουμένως ανασταλεί.
- **passthrough_access (#12)**: Επιτρέπει άμεση passthrough πρόσβαση σε έναν resource, παρακάμπτοντας τα sandbox checks.
- **set_container_path (#13)**: (μόνο iOS) Ορισμός container path για ένα app group ή signing ID.
- **container_map (#14)**: (μόνο iOS) Ανάκτηση ενός container path από το `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Ορισμός metadata user mode στο sandbox.
- **inspect (#16)**: Παροχή debug πληροφοριών σχετικά με ένα sandboxed process.
- **dump (#18)**: (macOS 11) Απόρριψη του τρέχοντος profile ενός sandbox για analysis.
- **vtrace (#19)**: Trace των sandbox operations για monitoring ή debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Απενεργοποίηση named profiles (π.χ. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Εκτέλεση πολλαπλών `sandbox_check` operations σε μία μόνο κλήση.
- **reference_retain_by_audit_token (#28)**: Δημιουργία reference για ένα audit token, ώστε να χρησιμοποιηθεί σε sandbox checks.
- **reference_release (#29)**: Αποδέσμευση ενός audit token reference που είχε προηγουμένως διατηρηθεί.
- **rootless_allows_task_for_pid (#30)**: Επαλήθευση του αν επιτρέπεται το `task_for_pid` (παρόμοια με τους ελέγχους `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Εφαρμογή ενός System Integrity Protection (SIP) manifest file.
- **rootless_whitelist_check (preflight) (#32)**: Έλεγχος του SIP manifest file πριν από την εκτέλεση.
- **rootless_protected_volume (#33)**: (macOS) Εφαρμογή SIP protections σε έναν δίσκο ή partition.
- **rootless_mkdir_protected (#34)**: Εφαρμογή SIP/DataVault protection σε μια διαδικασία δημιουργίας directory.

## Sandbox.kext

Σημειώστε ότι στο iOS το kernel extension περιέχει **hardcoded όλα τα profiles** μέσα στο segment `__TEXT.__const`, ώστε να αποτρέπεται η τροποποίησή τους. Ακολουθούν ορισμένες ενδιαφέρουσες συναρτήσεις από το kernel extension:

- **`hook_policy_init`**: Κάνει hook το `mpo_policy_init` και καλείται μετά το `mac_policy_register`. Εκτελεί τις περισσότερες αρχικοποιήσεις του Sandbox. Αρχικοποιεί επίσης το SIP.
- **`hook_policy_initbsd`**: Ρυθμίζει το sysctl interface, κάνοντας register τα `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` και `security.mac.sandbox.debug_mode` (αν έχει γίνει boot με `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Καλείται από το `mac_syscall` με `"Sandbox"` ως πρώτο όρισμα και έναν κωδικό που υποδεικνύει τη λειτουργία ως δεύτερο. Χρησιμοποιείται ένα switch για την εύρεση του κώδικα που θα εκτελεστεί, σύμφωνα με τον ζητούμενο κωδικό.

### MACF Hooks

Το **`Sandbox.kext`** χρησιμοποιεί περισσότερα από εκατό hooks μέσω MACF. Τα περισσότερα hooks απλώς ελέγχουν ορισμένες trivial περιπτώσεις που επιτρέπουν την εκτέλεση της ενέργειας· αν δεν ισχύει αυτό, καλούν το **`cred_sb_evalutate`** με τα **credentials** από το MACF, έναν αριθμό που αντιστοιχεί στην **operation** που θα εκτελεστεί και ένα **buffer** για το output.<sup>[[1]](#references)</sup>

Ένα καλό παράδειγμα είναι η συνάρτηση **`_mpo_file_check_mmap`**, η οποία κάνει hook το `mmap` και αρχίζει να ελέγχει αν η νέα μνήμη πρόκειται να είναι writable (και, αν δεν είναι, επιτρέπει την εκτέλεση). Στη συνέχεια ελέγχει αν χρησιμοποιείται για το dyld shared cache και, αν ισχύει αυτό, επιτρέπει την εκτέλεση. Τέλος, καλεί το **`sb_evaluate_internal`** (ή ένα από τα wrappers του) για να εκτελέσει περαιτέρω checks αδειοδότησης.

Επιπλέον, από τα εκατοντάδες hooks που χρησιμοποιεί το Sandbox, υπάρχουν 3 ιδιαίτερα ενδιαφέροντα:

- `mpo_proc_check_for`: Εφαρμόζει το profile αν χρειάζεται και αν δεν είχε εφαρμοστεί προηγουμένως.
- `mpo_vnode_check_exec`: Καλείται όταν ένα process φορτώνει το σχετικό binary. Στη συνέχεια εκτελείται profile check, καθώς και έλεγχος που απαγορεύει SUID/SGID executions.
- `mpo_cred_label_update_execve`: Καλείται όταν γίνεται assign το label. Είναι η μεγαλύτερη συνάρτηση, καθώς καλείται όταν το binary έχει φορτωθεί πλήρως αλλά δεν έχει εκτελεστεί ακόμη. Εκτελεί ενέργειες όπως η δημιουργία του sandbox object, η επισύναψη του sandbox struct στα kauth credentials και η αφαίρεση της πρόσβασης σε mach ports...

Σημειώστε ότι το **`_cred_sb_evalutate`** είναι wrapper πάνω από το **`sb_evaluate_internal`** και ότι αυτή η συνάρτηση λαμβάνει τα credentials και στη συνέχεια εκτελεί την evaluation χρησιμοποιώντας τη συνάρτηση **`eval`**, η οποία συνήθως αξιολογεί το **platform profile**, που εφαρμόζεται από προεπιλογή σε όλα τα processes, και στη συνέχεια το **specific process profile**. Σημειώστε ότι το platform profile είναι ένα από τα κύρια components του **SIP** στο macOS.

## Sandboxd

Το Sandbox διαθέτει επίσης ένα user daemon που εκτελείται και εκθέτει το XPC Mach service `com.apple.sandboxd`, δεσμεύοντας την special port 14 (`HOST_SEATBELT_PORT`), την οποία χρησιμοποιεί το kernel extension για να επικοινωνεί μαζί του. Εκθέτει ορισμένες συναρτήσεις χρησιμοποιώντας MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks που κάνει register το Sandbox kext)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, το entry point πίσω από το `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [man page `sandbox_init(3)`](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
