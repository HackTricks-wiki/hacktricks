# Κόλπα FS του macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Συνδυασμοί δικαιωμάτων POSIX

Για έναν **κατάλογο**, τα τρία bit δικαιωμάτων έχουν διαφορετική σημασία από ό,τι σε ένα κανονικό αρχείο. Το `chmod(1)` αποκαλεί το bit εκτέλεσης "**αναζήτηση**" όταν εφαρμόζεται σε κατάλογο:<sup>[[2]](#references)</sup>

> `0100` Για αρχεία, επιτρέπει την εκτέλεση από τον ιδιοκτήτη. Για καταλόγους, επιτρέπει στον ιδιοκτήτη να κάνει **αναζήτηση** στον κατάλογο.

- **ανάγνωση** - μπορείτε να **απαριθμήσετε** τις εγγραφές του καταλόγου (να δείτε τα ονόματα).
- **εγγραφή** - μπορείτε να **δημιουργήσετε, μετονομάσετε και διαγράψετε εγγραφές** στον κατάλογο. Σημειώστε ότι αυτό είναι ιδιότητα του *γονικού* καταλόγου, όχι του αρχείου: μπορείτε να διαγράψετε ένα αρχείο που δεν μπορείτε να διαβάσετε ή να τροποποιήσετε, εφόσον μπορείτε να γράψετε στον γονικό του κατάλογο.
  - Για να διαγράψετε έναν **υποκατάλογο**, πρέπει να είναι κενός, κάτι που με τη σειρά του απαιτεί επαρκή δικαιώματα για να αφαιρεθούν όλα τα περιεχόμενά του.
  - Αν ο κατάλογος έχει το **sticky bit** (`S_ISVTX`, όπως το `/tmp`), αυτό περιορίζεται — το POSIX ορίζει ότι μια διεργασία μπορεί τότε να διαγράψει ή να μετονομάσει αρχεία σε αυτόν μόνο αν είναι ιδιοκτήτρια του αρχείου ή του καταλόγου, ή έχει τα κατάλληλα προνόμια.<sup>[[1]](#references)</sup>
- **εκτέλεση / αναζήτηση** - σας **επιτρέπεται να διασχίσετε** τον κατάλογο. Η επίλυση ονομάτων διαδρομής εντοπίζει κάθε στοιχείο «στον κατάλογο που καθορίζεται από το προηγούμενο στοιχείο», επομένως **η απώλεια δικαιωμάτων αναζήτησης σε οποιοδήποτε στοιχείο του προθέματος της διαδρομής καθιστά μη προσβάσιμα μέσω διαδρομής όλα τα στοιχεία κάτω από αυτό**, ακόμα κι αν το ίδιο το τελικό αρχείο είναι αναγνώσιμο από όλους.<sup>[[1]](#references)</sup>

### Επικίνδυνοι συνδυασμοί

**Πώς να αντικαταστήσετε ένα αρχείο/φάκελο που ανήκει στον root**, όταν:

- Ένας γονικός **κατάλογος** στη διαδρομή ανήκει στον χρήστη
- Ένας γονικός **κατάλογος** στη διαδρομή ανήκει σε μια **ομάδα χρηστών** με **δικαίωμα εγγραφής**
- Μια **ομάδα** χρηστών έχει **δικαίωμα εγγραφής** στο **αρχείο**

Με οποιονδήποτε από τους προηγούμενους συνδυασμούς, ένας attacker θα μπορούσε να **εισαγάγει** έναν **συμβολικό/σκληρό σύνδεσμο** στην αναμενόμενη διαδρομή, ώστε να επιτύχει προνομιούχα αυθαίρετη εγγραφή.

### Ειδική περίπτωση καταλόγου root με R+X

Αυτό προκύπτει άμεσα από τον παραπάνω κανόνα επίλυσης διαδρομών. Αν ένας **κατάλογος παρέχει μόνο R+X στον root**, τα αρχεία μέσα σε αυτόν είναι απρόσιτα *μέσω διαδρομής* σε όλους τους υπόλοιπους — αλλά τα **δικά τους bit δικαιωμάτων μπορεί να εξακολουθούν να επιτρέπουν την πρόσβαση**. Το μόνο εμπόδιο είναι ο κατάλογος.

Έτσι, κάθε primitive που σας επιτρέπει να βγάλετε το αρχείο **έξω από αυτόν τον κατάλογο** — μια προνομιούχα διεργασία που **μετακινεί/μετονομάζει/αντιγράφει** μια διαδρομή που επιλέγει ο attacker σε μια τοποθεσία την οποία *μπορείτε* να διασχίσετε — μετατρέπεται σε αυθαίρετη ανάγνωση, χωρίς να χρειάζεται ποτέ να παρακάμψετε τα ίδια τα δικαιώματα του αρχείου:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Αναζητήστε προνομιούχες διεργασίες μετακίνησης αρχείων (installers, log rotators, crash/diagnostic collectors, λειτουργίες backup και "export") που δέχονται ως πηγή μια διαδρομή που ορίζει χρήστης με χαμηλότερα προνόμια.

## Symbolic Link / Hard Link

### Αρχείο/φάκελος με permissive δικαιώματα

Αν μια προνομιούχα διεργασία γράφει δεδομένα σε **αρχείο** που μπορεί να **ελέγχεται** από χρήστη με **χαμηλότερα προνόμια** ή που μπορεί να **έχει δημιουργηθεί προηγουμένως** από χρήστη με χαμηλότερα προνόμια, ο χρήστης μπορεί απλώς να το **κατευθύνει σε άλλο αρχείο** μέσω ενός Symbolic ή Hard link και η προνομιούχα διεργασία θα γράψει σε εκείνο το αρχείο.

Ελέγξτε τις άλλες ενότητες για περιπτώσεις όπου ένας attacker θα μπορούσε να **καταχραστεί ένα arbitrary write για να κλιμακώσει προνόμια**.

### Άνοιγμα με `O_NOFOLLOW`

Σύμφωνα με το [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Αν χρησιμοποιείται το `O_NOFOLLOW` στη μάσκα και το αρχείο-στόχος που περνά στο `open()` είναι symbolic link, τότε το `open()` θα αποτύχει."* Ελέγχεται μόνο το **τελικό** στοιχείο — κάθε **ενδιάμεσο** στοιχείο εξακολουθεί να επιλύεται και να ακολουθείται. Έτσι, ένας developer που «προστάτευσε» μια εγγραφή με `O_NOFOLLOW` μπορεί και πάλι να δεχτεί επίθεση μέσω ενός symlink σε οποιονδήποτε **γονικό κατάλογο** της διαδρομής-στόχου.<sup>[[3]](#references)</sup>

Η ίδια man page τεκμηριώνει τις σημαίες που κλείνουν ουσιαστικά αυτό το κενό:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"αν ... οποιοδήποτε στοιχείο της διαδρομής που περνά στο `open()` είναι symbolic link, τότε το `open()` θα αποτύχει."*
- **`O_RESOLVE_BENEATH`** — *"αν ... η επίλυση της καθορισμένης διαδρομής διαφύγει από τον κατάλογο που σχετίζεται με το fd, τότε το `openat()` θα αποτύχει."*

Διαφορετικά, οι υπόλοιποι τρόποι για να αποτρέψετε την αντικατάσταση symlink στη μέση της διαδρομής είναι να χρησιμοποιήσετε `openat()` σχετικό με ένα directory FD που έχετε ήδη επικυρώσει ή να χρησιμοποιήσετε `realpath()` και έπειτα να επαναλάβετε την επικύρωση.

## .fileloc

Αρχεία με επέκταση **`.fileloc`** μπορούν να δείχνουν σε άλλες εφαρμογές ή binaries, ώστε όταν ανοιχτούν, να εκτελεστεί η εφαρμογή ή το binary που υποδεικνύουν.\
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

Αν μια κλήση στο `open` δεν έχει τη σημαία `O_CLOEXEC`, το file descriptor θα κληρονομηθεί από τη child process. Επομένως, αν μια προνομιούχα διεργασία ανοίξει ένα προνομιούχο αρχείο και εκτελέσει μια διεργασία που ελέγχεται από τον attacker, ο attacker θα **κληρονομήσει το FD για το προνομιούχο αρχείο**.

Το χαρακτηριστικό παράδειγμα είναι το **`DYLD_PRINT_TO_FILE` LPE στο OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- Το `dyld` λάμβανε υπόψη το `DYLD_PRINT_TO_FILE=/path` ακόμη και σε **περιορισμένα (suid root) binaries**, επειδή η συγκεκριμένη μεταβλητή γινόταν parse εκτός του `processDyldEnvironmentVariable()`.
- Εκτελούσε `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, οπότε **δημιουργούσε ένα αρχείο με ιδιοκτήτη root σε αυθαίρετη διαδρομή**.
- Το FD **δεν έκλεινε ποτέ και δεν είχε σημαία close-on-exec**, επομένως κάθε child του suid binary κληρονομούσε ένα **εγγράψιμο FD για αρχείο με ιδιοκτήτη root**.
- Η εκτέλεση, για παράδειγμα, του `DYLD_PRINT_TO_FILE=/etc/target suid_binary` και στη συνέχεια η ανάγνωση του αριθμού του κληρονομημένου FD στη child διεργασία επέτρεπε αυθαίρετες εγγραφές σε αρχεία με ιδιοκτήτη root· το `fcntl(fd, F_SETFL, 0)` αφαιρούσε ακόμη και το `O_APPEND`, επιτρέποντας την αντικατάσταση του περιεχομένου αντί για προσθήκη.

Το ίδιο μοτίβο εμφανίζεται κάθε φορά που μια προνομιούχα διεργασία ανοίγει ένα αρχείο **πριν** εκτελέσει με `exec` κάτι που ελέγχετε (εργαλεία-βοηθούς, editors τύπου `crontab` που καλούνται μέσω του `$EDITOR`, αρχεία καταγραφής/debug που ανοίγονται από διαδρομή σε env var...). Καταγράψτε τα FD που κληρονομήσατε με:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Οτιδήποτε μεγαλύτερο από `2` που δείχνει σε αρχείο το οποίο δεν μπορείτε να ανοίξετε μόνοι σας αποτελεί primitive arbitrary-write (ή arbitrary-read).

## Αποφύγετε τα tricks με quarantine xattrs

### Αφαιρέστε το

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

Αν ένα αρχείο/φάκελος έχει αυτό το αμετάβλητο χαρακτηριστικό, δεν θα είναι δυνατό να του προστεθεί ένα xattr

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Συστήματα αρχείων χωρίς υποστήριξη xattr

Δεν αποθηκεύουν εγγενώς όλα τα συστήματα αρχείων που μπορεί να προσαρτήσει το macOS **extended attributes**. Τα HFS+ και APFS τα υποστηρίζουν· τα **FAT32, exFAT και (τα περισσότερα) NFS mounts δεν τα υποστηρίζουν** — το macOS τα προσομοιώνει γράφοντας ένα συνοδευτικό αρχείο **AppleDouble** με όνομα `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Αυτό έχει σημασία για το quarantine, επειδή το xattr διατηρείται μόνο αν μπορεί πράγματι να γραφτεί **και να διαβαστεί ξανά** από τον ίδιο τόμο:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Αν ο τόμος διαβαστεί αργότερα από ένα path που αγνοεί το συνοδευτικό `._` (ή αν το συνοδευτικό αρχείο αφαιρεθεί/διαγραφεί), το αρχείο φτάνει **χωρίς quarantine flag** — και ένα `.app` χωρίς quarantine αρκεί για να διαφύγει από το App Sandbox, όπως περιγράφεται στο [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL και συμπεριφορά quarantine του AppleDouble

Για το παράδειγμα ACL `writeextattr`, τον μηχανισμό AppleDouble `com.apple.acl.text` και τα βήματα δημιουργίας και επικύρωσης του sidecar, δείτε το [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Bypass ελέγχων υπογραφής

### Bypass ελέγχων platform binaries

Ορισμένοι έλεγχοι ασφαλείας εξετάζουν αν το binary είναι **platform binary**, για παράδειγμα, ώστε να επιτρέψουν τη σύνδεση με μια υπηρεσία XPC. Ωστόσο, όπως παρουσιάζεται σε ένα bypass στο https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, είναι δυνατό να παρακαμφθεί αυτός ο έλεγχος με τη λήψη ενός platform binary (όπως το /bin/ls) και την εισαγωγή του exploit μέσω dyld, χρησιμοποιώντας τη μεταβλητή περιβάλλοντος `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass των flags `CS_REQUIRE_LV` και `CS_FORCED_LV`

Ένα binary που εκτελείται μπορεί να τροποποιήσει τα δικά του flags για να παρακάμψει τους ελέγχους, με κώδικα όπως ο εξής:<sup>[[7]](#references)</sup>

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



## Παράκαμψη Code Signatures

Τα bundles περιέχουν το αρχείο **`_CodeSignature/CodeResources`**, το οποίο περιέχει το **hash** κάθε **file** του **bundle**. Σημειώστε ότι το hash του CodeResources είναι επίσης **ενσωματωμένο στο executable**, οπότε δεν μπορούμε να το πειράξουμε ούτε αυτό.

Ωστόσο, υπάρχουν ορισμένα αρχεία των οποίων η signature δεν θα ελεγχθεί. Αυτά έχουν το key `omit` στο plist, όπως:

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

Είναι δυνατό να υπολογιστεί η υπογραφή ενός πόρου από το CLI με:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Προσάρτηση dmgs

Ένας χρήστης μπορεί να προσαρτήσει ένα προσαρμοσμένο dmg, το οποίο έχει δημιουργηθεί ακόμη και πάνω σε ορισμένους υπάρχοντες φακέλους. Έτσι μπορείτε να δημιουργήσετε ένα προσαρμοσμένο πακέτο dmg με προσαρμοσμένο περιεχόμενο:

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

Συνήθως, το macOS προσαρτά δίσκους επικοινωνώντας με την υπηρεσία Mach `com.apple.DiskArbitrarion.diskarbitrariond` (που παρέχεται από το `/usr/libexec/diskarbitrationd`). Αν προσθέσετε την παράμετρο `-d` στο αρχείο plist του LaunchDaemons και κάνετε επανεκκίνηση, θα αποθηκεύει αρχεία καταγραφής στο `/var/log/diskarbitrationd.log`.\
Ωστόσο, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα `hdik` και `hdiutil` για απευθείας επικοινωνία με το kext `com.apple.driver.DiskImages`.

## Αυθαίρετες εγγραφές

### Περιοδικά sh scripts

Αν το script σας μπορεί να ερμηνευτεί ως **shell script**, θα μπορούσατε να αντικαταστήσετε το **`/etc/periodic/daily/999.local`** shell script, το οποίο ενεργοποιείται καθημερινά.

Μπορείτε να **προσποιηθείτε** την εκτέλεση αυτού του script με: **`sudo periodic daily`**

### Daemons

Γράψτε ένα αυθαίρετο **LaunchDaemon**, όπως το **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, με ένα plist που εκτελεί ένα αυθαίρετο script, για παράδειγμα:

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

Απλώς δημιουργήστε το script `/Applications/Scripts/privesc.sh` με τις **εντολές** που θέλετε να εκτελεστούν ως root.

### Αρχείο Sudoers

Αν έχετε **arbitrary write**, μπορείτε να δημιουργήσετε ένα αρχείο μέσα στον φάκελο **`/etc/sudoers.d/`** που θα σας παραχωρεί δικαιώματα **sudo**.

### Αρχεία PATH

Το αρχείο **`/etc/paths`** είναι ένα από τα κύρια σημεία που συμπληρώνουν τη μεταβλητή περιβάλλοντος PATH. Πρέπει να είστε root για να το αντικαταστήσετε, αλλά αν ένα script από **privileged process** εκτελεί κάποια **εντολή χωρίς το πλήρες path**, ίσως μπορέσετε να την κάνετε **hijack** τροποποιώντας αυτό το αρχείο.

Μπορείτε επίσης να γράψετε αρχεία στο **`/etc/paths.d`** για να φορτώσετε νέους φακέλους στη μεταβλητή περιβάλλοντος `PATH`.

### cups-files.conf

Αυτή η τεχνική χρησιμοποιήθηκε σε [αυτό το writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Δημιουργήστε το αρχείο `/etc/cups/cups-files.conf` με το ακόλουθο περιεχόμενο:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

This θα δημιουργήσει το αρχείο `/etc/sudoers.d/lpe` με δικαιώματα 777. Τα επιπλέον άχρηστα δεδομένα στο τέλος χρησιμεύουν για να ενεργοποιήσουν τη δημιουργία του error log.

Στη συνέχεια, γράψτε στο `/etc/sudoers.d/lpe` την απαραίτητη ρύθμιση για privilege escalation, όπως `%staff ALL=(ALL) NOPASSWD:ALL`.

Έπειτα, τροποποιήστε ξανά το αρχείο `/etc/cups/cups-files.conf`, ορίζοντας `LogFilePerm 700`, ώστε το νέο αρχείο sudoers να γίνει έγκυρο μέσω της κλήσης του `cupsctl`.

### Sandbox Escape

Είναι δυνατό να γίνει escape από το macOS sandbox με FS arbitrary write. Για μερικά παραδείγματα, ανατρέξτε στη σελίδα [macOS Auto Start](../../../../macos-auto-start-locations.md), αλλά μια συνηθισμένη μέθοδος είναι η εγγραφή ενός αρχείου προτιμήσεων του Terminal στο `~/Library/Preferences/com.apple.Terminal.plist`, το οποίο εκτελεί μια εντολή κατά την εκκίνηση, και η κλήση του με `open`.

## Δημιουργία εγγράψιμων αρχείων ως άλλοι χρήστες

Ένα πολύ συνηθισμένο privesc primitive είναι να κάνετε μια **privileged process να δημιουργήσει ένα αρχείο για εσάς** σε έναν κατάλογο που ελέγχετε και, στη συνέχεια, να διατηρήσετε **write access** σε αυτό το αρχείο. Χρειάζονται δύο στοιχεία:

1. Ένας κατάλογος που σας ανήκει (ή στον οποίο μπορείτε να ορίσετε ένα **inheritable ACL**), ώστε οτιδήποτε δημιουργείται μέσα του να κληρονομεί τα δικαιώματά σας.
2. Μια privileged/`suid` process στην οποία μπορείτε να υποδείξετε **πού** να δημιουργήσει ένα αρχείο — συνήθως μέσω μιας debug/logging environment variable, ενός config file ή του XPC API ενός helper.

Το μέρος με το **inheritable ACL** είναι αυτό που καθιστά το αρχείο εγγράψιμο από εσάς, παρόλο που ανήκει σε άλλον χρήστη. Οι σημαίες κληρονομικότητας `file_inherit` / `directory_inherit` τεκμηριώνονται στο [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Τώρα οποιοδήποτε αρχείο δημιουργεί μια προνομιούχα διεργασία μέσα στο `$DIRNAME` είναι **εγγράψιμο από εσένα**. Αν αυτός ο κατάλογος είναι επίσης μια τοποθεσία από την οποία εκτελείται αργότερα κάτι **ως root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ένας κατάλογος LaunchDaemon...), αυτό οδηγεί απευθείας σε κλιμάκωση προνομίων σε root. Δες τις ενότητες [Sudoers File](#sudoers-file) και [cups-files.conf](#cups-filesconf) παραπάνω για το τι να γράψεις μόλις αποκτήσεις το αρχείο.

Για ένα πλήρες παράδειγμα της αλυσίδας «μια μεταβλητή περιβάλλοντος κάνει μια διεργασία root να δημιουργήσει ένα αρχείο και το FD διαρρέει σε εσένα», δες παραπάνω το [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Κοινόχρηστη μνήμη POSIX

Η **κοινόχρηστη μνήμη POSIX** επιτρέπει σε διεργασίες λειτουργικών συστημάτων συμβατών με POSIX να έχουν πρόσβαση σε μια κοινή περιοχή μνήμης, διευκολύνοντας την ταχύτερη επικοινωνία σε σύγκριση με άλλες μεθόδους επικοινωνίας μεταξύ διεργασιών. Περιλαμβάνει τη δημιουργία ή το άνοιγμα ενός αντικειμένου κοινόχρηστης μνήμης με τη `shm_open()`, τον ορισμό του μεγέθους του με τη `ftruncate()` και τη χαρτογράφησή του στον χώρο διευθύνσεων της διεργασίας με τη χρήση της `mmap()`. Οι διεργασίες μπορούν έπειτα να διαβάζουν και να γράφουν απευθείας σε αυτήν την περιοχή μνήμης. Για τη διαχείριση της ταυτόχρονης πρόσβασης και την αποτροπή αλλοίωσης δεδομένων, χρησιμοποιούνται συχνά μηχανισμοί συγχρονισμού, όπως mutexes ή semaphores. Τέλος, οι διεργασίες αποχαρτογραφούν και κλείνουν την κοινόχρηστη μνήμη με τις `munmap()` και `close()` και, προαιρετικά, αφαιρούν το αντικείμενο μνήμης με τη `shm_unlink()`. Αυτό το σύστημα είναι ιδιαίτερα αποτελεσματικό για αποδοτικό και γρήγορο IPC σε περιβάλλοντα όπου πολλές διεργασίες χρειάζεται να έχουν γρήγορη πρόσβαση σε κοινόχρηστα δεδομένα.

<details>

<summary>Παράδειγμα κώδικα παραγωγού</summary>

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

Τα **macOSCguarded descriptors** είναι μια λειτουργία ασφαλείας που εισήχθη στο macOS για να ενισχύσει την ασφάλεια και την αξιοπιστία των **file descriptor operations** σε εφαρμογές χρηστών. Αυτά τα guarded descriptors επιτρέπουν τη συσχέτιση συγκεκριμένων περιορισμών ή «guards» με file descriptors, οι οποίοι επιβάλλονται από τον kernel.

Αυτή η λειτουργία είναι ιδιαίτερα χρήσιμη για την αποτροπή ορισμένων κατηγοριών ευπαθειών ασφαλείας, όπως η **μη εξουσιοδοτημένη πρόσβαση σε αρχεία** ή οι **συνθήκες ανταγωνισμού**. Αυτές οι ευπάθειες εμφανίζονται, για παράδειγμα, όταν ένα thread αποκτά πρόσβαση σε ένα file description, παρέχοντας **σε άλλο ευάλωτο thread πρόσβαση σε αυτό**, ή όταν ένα file descriptor **κληρονομείται** από μια ευάλωτη child process. Ορισμένες συναρτήσεις που σχετίζονται με αυτήν τη λειτουργία είναι:

- `guarded_open_np`: Ανοίγει ένα file descriptor με guard
- `guarded_close_np`: Κλείνει το
- `change_fdguard_np`: Αλλάζει τα guard flags ενός descriptor (ακόμη και αφαιρώντας την προστασία του guard)

## References

- [1] [POSIX.1-2024 — Βασικοί ορισμοί, Κεφ. 4 (Δικαιώματα πρόσβασης αρχείων, προστασία καταλόγων, επίλυση ονομάτων διαδρομών)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Τοπική κλιμάκωση προνομίων μέσω DYLD_PRINT_TO_FILE στο OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Ποια συστήματα αρχείων και cloud services διατηρούν extended attributes;](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Μια νέα εποχή για τα macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Αποκαλύπτοντας ευπάθειες της Apple: Η ιστορία ελέγχου των diskarbitrationd και storagekitd, Μέρος 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
