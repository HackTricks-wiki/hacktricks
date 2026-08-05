# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το macOS Sandbox (αρχικά ονομαζόταν Seatbelt) **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο Sandbox profile** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο στους αναμενόμενους πόρους**.

Κάθε εφαρμογή με το **entitlement** **`com.apple.security.app-sandbox`** θα εκτελείται μέσα στο sandbox. Τα **Apple binaries** συνήθως εκτελούνται μέσα σε Sandbox και όλες οι εφαρμογές από το **App Store έχουν αυτό το entitlement**. Επομένως, αρκετές εφαρμογές θα εκτελούνται μέσα στο sandbox.<sup>[[4]](#references)</sup>

Για να ελέγχει τι μπορεί ή δεν μπορεί να κάνει μια διεργασία, το **Sandbox διαθέτει hooks** σχεδόν σε κάθε λειτουργία που μπορεί να επιχειρήσει μια διεργασία (συμπεριλαμβανομένων των περισσότερων syscalls), χρησιμοποιώντας **MACF**. Ωστόσο, **ανάλογα** με τα **entitlements** της εφαρμογής, το Sandbox μπορεί να είναι πιο permissive με τη διεργασία.

Μερικά σημαντικά components του Sandbox είναι:

- Το **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- Το **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Ένας **daemon** που εκτελείται σε userland `/usr/libexec/sandboxd`
- Τα **containers** `~/Library/Containers`

### Containers

Κάθε sandboxed εφαρμογή θα έχει το δικό της container στο `~/Library/Containers/{CFBundleIdentifier}` :
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
Μέσα σε κάθε φάκελο bundle id μπορείτε να βρείτε το **plist** και το **Data directory** της εφαρμογής, με μια δομή που μιμείται τον φάκελο Home:
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
> Σημειώστε ότι ακόμη κι αν υπάρχουν symlinks για να «διαφύγετε» από το Sandbox και να αποκτήσετε πρόσβαση σε άλλους φακέλους, το App εξακολουθεί να χρειάζεται **permissions** για να αποκτήσει πρόσβαση σε αυτούς. Αυτά τα permissions βρίσκονται μέσα στο **`.plist`** στο `RedirectablePaths`.

Το **`SandboxProfileData`** είναι το compiled sandbox profile CFData encoded σε B64.
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
> Όλα όσα δημιουργούνται/τροποποιούνται από μια εφαρμογή σε Sandbox θα αποκτήσουν το **quarantine attribut**e. Αυτό θα εμποδίσει έναν χώρο sandbox ενεργοποιώντας το Gatekeeper, αν η εφαρμογή sandbox προσπαθήσει να εκτελέσει κάτι με το **`open`**.

## Sandbox Profiles

Τα Sandbox profiles είναι αρχεία διαμόρφωσης που υποδεικνύουν τι θα **επιτρέπεται/απαγορεύεται** σε αυτό το **Sandbox**. Χρησιμοποιούν τη **Sandbox Profile Language (SBPL)**, η οποία χρησιμοποιεί τη γλώσσα προγραμματισμού [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

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
> Δείτε αυτή την [**έρευνα**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **για να ελέγξετε περισσότερες ενέργειες που θα μπορούσαν να επιτρέπονται ή να απορρίπτονται.**<sup>[[5]](#references)</sup>
>
> Σημειώστε ότι στη compiled έκδοση ενός profile, τα ονόματα των operations αντικαθίστανται από τις καταχωρίσεις τους σε έναν array που είναι γνωστός στο dylib και στο kext, κάνοντας τη compiled έκδοση μικρότερη και δυσκολότερη στην ανάγνωση.

Σημαντικά **system services** εκτελούνται επίσης μέσα στο δικό τους custom **sandbox**, όπως το service `mdnsresponder`. Μπορείτε να δείτε αυτά τα custom **sandbox profiles** μέσα στα:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Άλλα sandbox profiles μπορούν να ελεγχθούν στο [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- Στο iOS, το platform profile βρίσκεται μέσα στο sandbox `.kext`, στο `_platform_profile_data` μέσα στο binary.

Οι εφαρμογές του **App Store** χρησιμοποιούν το **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Σε αυτό το profile μπορείτε να δείτε πώς entitlements όπως το **`com.apple.security.network.server`** επιτρέπουν σε μια process να χρησιμοποιεί το network.

Στη συνέχεια, ορισμένα **Apple daemon services** χρησιμοποιούν διαφορετικά profiles, τα οποία βρίσκονται στα `/System/Library/Sandbox/Profiles/*.sb` ή `/usr/share/sandbox/*.sb`. Αυτά τα sandboxes εφαρμόζονται στην κύρια function που καλεί το API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

Το **SIP** είναι ένα Sandbox profile που ονομάζεται platform_profile στο `/System/Library/Sandbox/rootless.conf`.

### Παραδείγματα Sandbox Profile

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
> Σημειώστε ότι το **λογισμικό** που έχει δημιουργηθεί από την **Apple** και εκτελείται σε **Windows** **δεν διαθέτει πρόσθετες προφυλάξεις ασφαλείας**, όπως το application sandboxing.

Παραδείγματα Bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (έχουν τη δυνατότητα να γράφουν αρχεία εκτός του sandbox, των οποίων το όνομα ξεκινά με `~$`).<sup>[[7]](#references)</sup>

### Tracing του Sandbox

#### Μέσω profile

Είναι δυνατή η καταγραφή όλων των ελέγχων που εκτελεί το sandbox κάθε φορά που ελέγχεται μια ενέργεια. Για αυτό, δημιουργήστε το ακόλουθο profile:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Και μετά απλώς εκτέλεσε κάτι χρησιμοποιώντας αυτό το profile:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Στο `/tmp/trace.out` θα μπορείτε να δείτε κάθε sandbox check που εκτελείται κάθε φορά που καλείται (συνεπώς, πολλές διπλότυπες εγγραφές).

Είναι επίσης δυνατή η ανίχνευση του sandbox με την παράμετρο **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Μέσω API

Η συνάρτηση `sandbox_set_trace_path`, που εξάγεται από το `libsystem_sandbox.dylib`, επιτρέπει τον καθορισμό ενός ονόματος αρχείου trace, όπου θα εγγράφονται τα sandbox checks.\
Είναι επίσης δυνατό να γίνει κάτι παρόμοιο καλώντας τις `sandbox_vtrace_enable()` και στη συνέχεια λαμβάνοντας τα error logs από το buffer μέσω της `sandbox_vtrace_report()`.

### Επιθεώρηση Sandbox

Το `libsandbox.dylib` εξάγει μια συνάρτηση που ονομάζεται sandbox_inspect_pid, η οποία παρέχει μια λίστα με την κατάσταση sandbox μιας διεργασίας (συμπεριλαμβανομένων των extensions). Ωστόσο, μόνο platform binaries μπορούν να χρησιμοποιήσουν αυτήν τη συνάρτηση.

### Προφίλ Sandbox σε MacOS & iOS

Το MacOS αποθηκεύει τα system sandbox profiles σε δύο τοποθεσίες: **/usr/share/sandbox/** και **/System/Library/Sandbox/Profiles**.

Και αν μια εφαρμογή τρίτου μέρους διαθέτει το entitlement _**com.apple.security.app-sandbox**_, το σύστημα εφαρμόζει το προφίλ **/System/Library/Sandbox/Profiles/application.sb** σε αυτήν τη διεργασία.

Στο iOS, το default profile ονομάζεται **container** και δεν διαθέτουμε την αναπαράσταση κειμένου SBPL. Στη μνήμη, αυτό το sandbox αναπαρίσταται ως δυαδικό δέντρο Allow/Deny για κάθε permission του sandbox.

### Προσαρμοσμένο SBPL σε εφαρμογές του App Store

Θα μπορούσε να είναι δυνατή η δημιουργία εφαρμογών από εταιρείες, οι οποίες θα εκτελούνται **με custom Sandbox profiles** (αντί για το default profile). Χρειάζεται να χρησιμοποιήσουν το entitlement **`com.apple.security.temporary-exception.sbpl`**, το οποίο πρέπει να εγκριθεί από την Apple.

Είναι δυνατό να ελεγχθεί ο ορισμός αυτού του entitlement στο **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Αυτό θα κάνει **eval το string μετά από αυτό το entitlement** ως Sandbox profile.

### Μεταγλώττιση και απομεταγλώττιση ενός Sandbox Profile

Το εργαλείο **`sandbox-exec`** χρησιμοποιεί τις συναρτήσεις `sandbox_compile_*` από το `libsandbox.dylib`. Οι κύριες exported συναρτήσεις είναι: `sandbox_compile_file` (αναμένει file path, παράμετρος `-f`), `sandbox_compile_string` (αναμένει string, παράμετρος `-p`), `sandbox_compile_name` (αναμένει όνομα ενός container, παράμετρος `-n`), `sandbox_compile_entitlements` (αναμένει entitlements plist).

Αυτή η αντίστροφα αναλυμένη και [**open sourced έκδοση του εργαλείου sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) επιτρέπει στο **`sandbox-exec`** να γράψει σε ένα file το compiled sandbox profile.

Επιπλέον, για να περιορίσει μια process μέσα σε ένα container, μπορεί να καλέσει το `sandbox_spawnattrs_set[container/profilename]` και να περάσει ένα container ή ένα pre-existing profile.

## Debug και Bypass του Sandbox

Στο macOS, σε αντίθεση με το iOS όπου οι processes γίνονται sandboxed από την αρχή από τον kernel, οι **processes πρέπει να κάνουν opt-in στο sandbox από μόνες τους**. Αυτό σημαίνει ότι στο macOS μια process δεν περιορίζεται από το sandbox μέχρι να αποφασίσει ενεργά να εισέλθει σε αυτό, αν και οι εφαρμογές του App Store είναι πάντα sandboxed.

Οι processes γίνονται αυτόματα Sandboxed από το userland κατά την εκκίνησή τους, αν έχουν το entitlement: `com.apple.security.app-sandbox`. Για λεπτομερή εξήγηση αυτής της διαδικασίας, έλεγξε:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Οι extensions επιτρέπουν την παροχή επιπλέον privileges σε ένα object και παρέχονται με την κλήση μίας από τις συναρτήσεις:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Οι extensions αποθηκεύονται στο δεύτερο MACF label slot, προσβάσιμο από τα process credentials. Το παρακάτω **`sbtool`** μπορεί να έχει πρόσβαση σε αυτές τις πληροφορίες.

Σημείωσε ότι οι extensions συνήθως παρέχονται από allowed processes. Για παράδειγμα, το `tccd` θα παρέχει το extension token του `com.apple.tcc.kTCCServicePhotos` όταν μια process προσπαθήσει να αποκτήσει πρόσβαση στις photos και επιτραπεί σε ένα XPC message. Στη συνέχεια, η process θα πρέπει να καταναλώσει το extension token ώστε να προστεθεί σε αυτήν.\
Σημείωσε ότι τα extension tokens είναι μεγάλα hexadecimals που κωδικοποιούν τα granted permissions. Ωστόσο, δεν έχουν το allowed PID hardcoded, πράγμα που σημαίνει ότι οποιαδήποτε process με πρόσβαση στο token μπορεί να το **καταναλώσει από multiple processes**.

Σημείωσε επίσης ότι οι extensions σχετίζονται στενά και με τα entitlements, επομένως η κατοχή συγκεκριμένων entitlements μπορεί να παρέχει αυτόματα συγκεκριμένες extensions.

### **Έλεγχος των PID Privileges**

[**Σύμφωνα με αυτό**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), οι συναρτήσεις **`sandbox_check`** (είναι ένα `__mac_syscall`) μπορούν να ελέγξουν **αν μια operation επιτρέπεται ή όχι** από το sandbox σε ένα συγκεκριμένο PID, audit token ή unique ID.<sup>[[8]](#references)</sup>

Το [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (βρες το [compiled εδώ](https://newosxbook.com/articles/hitsb.html)) μπορεί να ελέγξει αν ένα PID μπορεί να εκτελέσει συγκεκριμένες actions:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Είναι επίσης δυνατό να γίνει suspend και unsuspend του sandbox χρησιμοποιώντας τις συναρτήσεις `sandbox_suspend` και `sandbox_unsuspend` από το `libsystem_sandbox.dylib`.

Σημειώστε ότι για την κλήση της συνάρτησης suspend ελέγχονται ορισμένα entitlements, ώστε να εξουσιοδοτηθεί ο caller να την καλέσει, όπως:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Αυτό το system call (#381) αναμένει ένα string ως πρώτο όρισμα, το οποίο υποδεικνύει το module που θα εκτελεστεί, και στη συνέχεια έναν κωδικό στο δεύτερο όρισμα, ο οποίος υποδεικνύει τη συνάρτηση που θα εκτελεστεί. Το τρίτο όρισμα εξαρτάται από τη συνάρτηση που εκτελείται.<sup>[[2]](#references)</sup>

Η συνάρτηση `___sandbox_ms` είναι wrapper για την κλήση του `mac_syscall`, υποδεικνύοντας ως πρώτο όρισμα το `"Sandbox"`, όπως ακριβώς η `___sandbox_msp` είναι wrapper για το `mac_set_proc` (#387). Στη συνέχεια, ορισμένοι από τους υποστηριζόμενους κωδικούς της `___sandbox_ms` παρατίθενται στον ακόλουθο πίνακα:

- **set_profile (#0)**: Εφαρμογή ενός compiled ή named profile σε μια διεργασία.
- **platform_policy (#1)**: Επιβολή platform-specific policy checks (διαφέρει μεταξύ macOS και iOS).
- **check_sandbox (#2)**: Εκτέλεση manual check για μια συγκεκριμένη sandbox operation.
- **note (#3)**: Προσθήκη annotation σε ένα Sandbox.
- **container (#4)**: Επισύναψη annotation σε ένα sandbox, συνήθως για debugging ή identification.
- **extension_issue (#5)**: Δημιουργία νέου extension για μια διεργασία.
- **extension_consume (#6)**: Κατανάλωση ενός δεδομένου extension.
- **extension_release (#7)**: Αποδέσμευση της μνήμης που συνδέεται με ένα consumed extension.
- **extension_update_file (#8)**: Τροποποίηση των παραμέτρων ενός υπάρχοντος file extension μέσα στο sandbox.
- **extension_twiddle (#9)**: Προσαρμογή ή τροποποίηση ενός υπάρχοντος file extension (π.χ. TextEdit, rtf, rtfd).
- **suspend (#10)**: Προσωρινή αναστολή όλων των sandbox checks (απαιτούνται τα κατάλληλα entitlements).
- **unsuspend (#11)**: Επαναφορά όλων των sandbox checks που είχαν προηγουμένως ανασταλεί.
- **passthrough_access (#12)**: Allow direct passthrough access σε έναν resource, παρακάμπτοντας τα sandbox checks.
- **set_container_path (#13)**: (iOS only) Ορισμός container path για ένα app group ή signing ID.
- **container_map (#14)**: (iOS only) Ανάκτηση ενός container path από το `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Ορισμός user mode metadata στο sandbox.
- **inspect (#16)**: Παροχή debug information σχετικά με μια sandboxed διεργασία.
- **dump (#18)**: (macOS 11) Απόρριψη του τρέχοντος profile ενός sandbox για analysis.
- **vtrace (#19)**: Καταγραφή sandbox operations για monitoring ή debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Απενεργοποίηση named profiles (π.χ. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Εκτέλεση πολλαπλών `sandbox_check` operations σε μία κλήση.
- **reference_retain_by_audit_token (#28)**: Δημιουργία reference για ένα audit token, ώστε να χρησιμοποιηθεί σε sandbox checks.
- **reference_release (#29)**: Αποδέσμευση ενός audit token reference που είχε προηγουμένως διατηρηθεί.
- **rootless_allows_task_for_pid (#30)**: Επαλήθευση του αν επιτρέπεται το `task_for_pid` (παρόμοια με τα `csr` checks).
- **rootless_whitelist_push (#31)**: (macOS) Εφαρμογή ενός System Integrity Protection (SIP) manifest file.
- **rootless_whitelist_check (preflight) (#32)**: Έλεγχος του SIP manifest file πριν από την εκτέλεση.
- **rootless_protected_volume (#33)**: (macOS) Εφαρμογή SIP protections σε έναν δίσκο ή partition.
- **rootless_mkdir_protected (#34)**: Εφαρμογή SIP/DataVault protection σε μια διαδικασία δημιουργίας directory.

## Sandbox.kext

Σημειώστε ότι στο iOS το kernel extension περιέχει **hardcoded όλα τα profiles** μέσα στο segment `__TEXT.__const`, ώστε να αποτρέπεται η τροποποίησή τους. Ακολουθούν ορισμένες ενδιαφέρουσες συναρτήσεις του kernel extension:

- **`hook_policy_init`**: Κάνει hook το `mpo_policy_init` και καλείται μετά το `mac_policy_register`. Εκτελεί τις περισσότερες αρχικοποιήσεις του Sandbox. Αρχικοποιεί επίσης το SIP.
- **`hook_policy_initbsd`**: Ρυθμίζει το sysctl interface, κάνοντας register τα `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` και `security.mac.sandbox.debug_mode` (αν το σύστημα έχει γίνει boot με `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Καλείται από το `mac_syscall` με `"Sandbox"` ως πρώτο όρισμα και έναν κωδικό που υποδεικνύει την operation ως δεύτερο. Χρησιμοποιείται ένα switch για την εύρεση του κωδικού που θα εκτελεστεί σύμφωνα με τον ζητούμενο κωδικό.

### MACF Hooks

Το **`Sandbox.kext`** χρησιμοποιεί περισσότερα από εκατό hooks μέσω MACF. Τα περισσότερα hooks απλώς ελέγχουν ορισμένες trivial περιπτώσεις που επιτρέπουν την εκτέλεση της action· αν όχι, καλούν το **`cred_sb_evalutate`** με τα **credentials** από το MACF, έναν αριθμό που αντιστοιχεί στην **operation** που θα εκτελεστεί και ένα **buffer** για το output.<sup>[[1]](#references)</sup>

Ένα καλό παράδειγμα είναι η συνάρτηση **`_mpo_file_check_mmap`**, η οποία κάνει hook το **`mmap`** και αρχίζει ελέγχοντας αν η νέα memory πρόκειται να είναι writable (και, αν όχι, επιτρέπει την execution). Στη συνέχεια ελέγχει αν χρησιμοποιείται για το dyld shared cache και, αν ισχύει αυτό, επιτρέπει την execution. Τέλος, καλεί το **`sb_evaluate_internal`** (ή ένα από τα wrappers του) για να εκτελέσει περαιτέρω allowance checks.

Επιπλέον, από τα εκατοντάδες hooks που χρησιμοποιεί το Sandbox, υπάρχουν 3 που είναι ιδιαίτερα ενδιαφέροντα:

- `mpo_proc_check_for`: Εφαρμόζει το profile αν απαιτείται και αν δεν έχει εφαρμοστεί προηγουμένως.
- `mpo_vnode_check_exec`: Καλείται όταν μια διεργασία φορτώνει το αντίστοιχο binary. Στη συνέχεια εκτελείται profile check, καθώς και check που απαγορεύει SUID/SGID executions.
- `mpo_cred_label_update_execve`: Καλείται όταν γίνεται assign το label. Είναι το μεγαλύτερο, καθώς καλείται όταν το binary έχει φορτωθεί πλήρως, αλλά δεν έχει εκτελεστεί ακόμη. Εκτελεί actions όπως η δημιουργία του sandbox object, η επισύναψη του sandbox struct στα kauth credentials, η αφαίρεση access σε mach ports...

Σημειώστε ότι το **`_cred_sb_evalutate`** είναι wrapper πάνω από το **`sb_evaluate_internal`** και ότι αυτή η συνάρτηση λαμβάνει τα credentials ως όρισμα και στη συνέχεια εκτελεί την evaluation χρησιμοποιώντας τη συνάρτηση **`eval`**, η οποία συνήθως αξιολογεί το **platform profile**, που εφαρμόζεται από default σε όλες τις διεργασίες, και στη συνέχεια το **specific process profile**. Σημειώστε ότι το platform profile είναι ένα από τα βασικά components του **SIP** στο macOS.

## Sandboxd

Το Sandbox διαθέτει επίσης ένα user daemon που εκτελείται και εκθέτει το XPC Mach service `com.apple.sandboxd`, δεσμεύοντας το special port 14 (`HOST_SEATBELT_PORT`), το οποίο χρησιμοποιεί το kernel extension για να επικοινωνεί μαζί του. Εκθέτει ορισμένες συναρτήσεις χρησιμοποιώντας MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
