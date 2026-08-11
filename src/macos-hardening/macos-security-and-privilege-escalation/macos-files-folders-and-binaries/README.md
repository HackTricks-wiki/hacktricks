# Αρχεία, φάκελοι, binaries και μνήμη του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Διάταξη ιεραρχίας αρχείων

Η Apple τεκμηριώνει το filesystem του macOS ως μια ιεραρχία από system, local, network και user domains. Τα ακριβή περιεχόμενα διαφέρουν ανάλογα με την έκδοση του OS, ενώ οι τοποθεσίες του συστήματος προστατεύονται ή συντίθενται όλο και περισσότερο. <sup>[[1]](#references)</sup>

- **/Applications**: Οι εγκατεστημένες εφαρμογές πρέπει να βρίσκονται εδώ. Όλοι οι χρήστες θα μπορούν να έχουν πρόσβαση σε αυτές.
- **/bin**: Binaries γραμμής εντολών
- **/cores**: Αν υπάρχει, χρησιμοποιείται για την αποθήκευση core dumps
- **/dev**: Όλα αντιμετωπίζονται ως αρχείο, επομένως εδώ μπορεί να δείτε αποθηκευμένες hardware devices.
- **/etc**: Αρχεία configuration
- **/Library**: Εδώ μπορεί να βρεθεί μεγάλος αριθμός υποκαταλόγων και αρχείων που σχετίζονται με preferences, caches και logs. Ένας φάκελος Library υπάρχει στο root και στον κατάλογο κάθε χρήστη.
- **/private**: Δεν τεκμηριώνεται, αλλά πολλοί από τους προαναφερθέντες φακέλους είναι symbolic links προς τον private directory.
- **/sbin**: Essential system binaries (σχετικά με τη διαχείριση)
- **/System**: Αρχεία που απαιτούνται από το macOS· αυτό το tree περιέχει κυρίως components που παρέχονται από την Apple.
- **/tmp**: Προσωρινά αρχεία (symbolic link προς το `/private/tmp`). Σε παλαιότερες εγκαταστάσεις καθαρίζονταν συνήθως τα παλιά προσωρινά αρχεία με περιοδικό προγραμματισμό, ο οποίος μερικές φορές περιγραφόταν ως τρεις ημέρες, όμως ο τρέχων χρόνος καθαρισμού εξαρτάται από το σύστημα και την policy· μην βασίζεστε στο ότι τα δεδομένα θα παραμείνουν εκεί.
- **/Users**: Home directory των χρηστών.
- **/usr**: Config και system binaries
- **/var**: Log files
- **/Volumes**: Τα mounted volumes εμφανίζονται εδώ.
- **/.vol**: Εκτελώντας `stat a.txt` λαμβάνετε κάτι όπως `16777223 7545753 -rw-r--r-- 1 username wheel ...`, όπου ο πρώτος αριθμός είναι το id number του volume όπου υπάρχει το αρχείο και ο δεύτερος είναι ο inode number. Μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο αυτού του αρχείου μέσω του /.vol/ με αυτές τις πληροφορίες, εκτελώντας `cat /.vol/16777223/7545753`

### Φάκελοι εφαρμογών

- Οι **system applications** βρίσκονται στο `/System/Applications`
- Οι **installed** εφαρμογές συνήθως εγκαθίστανται στο `/Applications` ή στο `~/Applications`
- Τα application data μπορούν να βρεθούν στο `/Library/Application Support` για εφαρμογές που εκτελούνται ως root και στο `~/Library/Application Support` για εφαρμογές που εκτελούνται ως ο χρήστης.
- Τα **daemons** εφαρμογών τρίτων που **χρειάζεται να εκτελούνται ως root** συνήθως βρίσκονται στο `/Library/PrivilegedHelperTools/`.
- Οι **sandboxed** εφαρμογές αντιστοιχίζονται στον φάκελο `~/Library/Containers`. Κάθε εφαρμογή έχει έναν φάκελο που ονομάζεται σύμφωνα με το bundle ID της εφαρμογής (`com.apple.Safari`).
- Ο **kernel** βρίσκεται στο `/System/Library/Kernels/kernel`
- Τα **kernel extensions της Apple** βρίσκονται στο `/System/Library/Extensions`
- Τα **kernel extensions τρίτων** αποθηκεύονται στο `/Library/Extensions`

### Αρχεία με ευαίσθητες πληροφορίες

Το macOS αποθηκεύει ευαίσθητες πληροφορίες, συμπεριλαμβανομένων credentials, σε διάφορες τοποθεσίες:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Ευάλωτοι pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Ειδικά extensions του OS X

- **`.dmg`**: Τα Apple Disk Image files χρησιμοποιούνται πολύ συχνά για installers.
- **`.kext`**: Πρέπει να ακολουθεί συγκεκριμένη structure και αποτελεί την έκδοση driver του OS X. (είναι bundle)
- **`.plist`**: Ένα property list αποθηκεύει structured information σε XML ή binary format.
- Μπορεί να είναι XML ή binary. Τα binary μπορούν να διαβαστούν με:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Ένα application bundle που ακολουθεί την standard directory structure του macOS.
- **`.dylib`**: Dynamic libraries (όπως τα Windows DLL files)
- **`.pkg`**: Είναι ίδια με τα xar (eXtensible Archive format). Η installer command μπορεί να χρησιμοποιηθεί για την εγκατάσταση των περιεχομένων αυτών των αρχείων.
- **`.DS_Store`**: Αυτό το αρχείο υπάρχει σε κάθε directory και αποθηκεύει τα attributes και τις customisations του directory.
- **`.Spotlight-V100`**: Αυτός ο φάκελος εμφανίζεται στο root directory κάθε volume του συστήματος.
- **`.metadata_never_index`**: Αν αυτό το αρχείο βρίσκεται στο root ενός volume, το Spotlight δεν θα κάνει index σε αυτό το volume.
- **`.noindex`**: Αρχεία και φάκελοι με αυτό το extension δεν θα γίνονται index από το Spotlight.
- **`.sdef`**: Ένα scripting definition file που περιγράφει πώς το AppleScript μπορεί να αλληλεπιδράσει με μια εφαρμογή.

### macOS Bundles

Ένα bundle είναι ένας directory με standardized hierarchy που το Finder μπορεί να παρουσιάζει ως ένα ενιαίο object· τα application bundles χρησιμοποιούν το extension `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Στα macOS και iOS, οι system libraries και frameworks που χρησιμοποιούνται συχνά είναι prelinked στο **dyld shared cache**, γεγονός που βελτιώνει την απόδοση κατά την εκκίνηση των εφαρμογών. Παρότι αντιμετωπίζεται ως μία logical cache, οι τρέχουσες εκδόσεις μπορεί να την αποθηκεύουν ως main cache μαζί με πολλαπλά subcache files αντί για κυριολεκτικά ένα αρχείο. Το format και η τοποθεσία της είναι implementation details που αλλάζουν ανάλογα με τις εκδόσεις του OS. <sup>[[3]](#references)</sup>

Στο macOS βρίσκεται στο `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` και σε παλαιότερες εκδόσεις μπορεί να μπορείτε να βρείτε το **shared cache** στο **`/System/Library/dyld/`**.\
Στο iOS μπορείτε να τα βρείτε στο **`/System/Library/Caches/com.apple.dyld/`**.

Παρόμοια με το dyld shared cache, ο kernel και τα kernel extensions μεταγλωττίζονται επίσης σε kernel cache, η οποία φορτώνεται κατά το boot.

Παλαιότερες εκδόσεις μπορούσαν να εξαχθούν με το [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Αυτό το build μπορεί να μην υποστηρίζει τα τρέχοντα cache formats· το [**dyldextractor**](https://github.com/arandomdev/dyldextractor) είναι μια ακόμη επιλογή:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Σημειώστε ότι ακόμη κι αν το εργαλείο `dyld_shared_cache_util` δεν λειτουργεί, μπορείτε να περάσετε το **shared dyld binary στο Hopper** και το Hopper θα μπορεί να αναγνωρίσει όλες τις βιβλιοθήκες και να σας επιτρέψει να **επιλέξετε ποια** θέλετε να διερευνήσετε:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Ορισμένοι extractors δεν θα λειτουργήσουν, καθώς τα dylibs είναι prelinked με hard coded διευθύνσεις και επομένως μπορεί να κάνουν άλμα σε άγνωστες διευθύνσεις

> [!TIP]
> Είναι επίσης δυνατή η λήψη του Shared Library Cache άλλων \*OS συσκευών στο macos με τη χρήση emulator στο Xcode. Θα ληφθούν μέσα στο: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, όπως:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

Το **`dyld`** χρησιμοποιεί το syscall **`shared_region_check_np`** για να γνωρίζει αν το SLC έχει γίνει mapped (το οποίο επιστρέφει τη διεύθυνση) και το **`shared_region_map_and_slide_np`** για να κάνει map το SLC.

Σημειώστε ότι ακόμη κι αν το SLC έχει γίνει slid κατά την πρώτη χρήση, όλες οι **διεργασίες** χρησιμοποιούν το **ίδιο αντίγραφο**, γεγονός που **εξάλειψε το ASLR** protection εάν ο attacker μπορούσε να εκτελεί processes στο σύστημα. Αυτό έγινε πράγματι exploit στο παρελθόν και διορθώθηκε με τον shared region pager.

Τα branch pools είναι μικρά Mach-O dylibs που δημιουργούν μικρούς χώρους μεταξύ των image mappings, καθιστώντας αδύνατο το interpose των functions.

### Override SLCs

Με τη χρήση των μεταβλητών περιβάλλοντος:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Αυτό θα επιτρέψει τη φόρτωση ενός νέου shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** και χειροκίνητη αντικατάσταση των libraries με symlinks προς το shared cache με τα πραγματικά libraries (θα χρειαστεί να τα κάνετε extract)

## Special File Permissions

### Folder permissions

Για έναν directory, το **read** επιτρέπει την εμφάνιση των entries, το **write** επιτρέπει τη δημιουργία ή αφαίρεση entries και το **execute** επιτρέπει το traversal. Κατά συνέπεια, ένας χρήστης που μπορεί να διαβάσει ένα file αλλά δεν μπορεί να κάνει traverse έναν parent directory δεν μπορεί να αποκτήσει πρόσβαση σε αυτό το file μέσω path. <sup>[[4]](#references)</sup>

### Flag modifiers

Τα files μπορούν να έχουν flags που αλλάζουν τη συμπεριφορά τους. Επιθεωρήστε τα flags σε έναν directory με `ls -lO /path/directory`.

- **`uchg`**: Γνωστό ως flag **uchange**, θα **εμποδίσει οποιαδήποτε ενέργεια** που αλλάζει ή διαγράφει το **file**. Για να το ορίσετε, εκτελέστε: `chflags uchg file.txt`
- Ο root user θα μπορούσε να **αφαιρέσει το flag** και να τροποποιήσει το file
- **`restricted`**: Αυτό το flag κάνει το file να είναι **protected by SIP** (δεν μπορείτε να προσθέσετε αυτό το flag σε ένα file).
- **`Sticky bit`**: Σε έναν directory όπου έχει οριστεί το sticky bit, μόνο ο owner του file, ο owner του directory ή ο root μπορεί να μετονομάσει ή να διαγράψει ένα entry. Αυτό ενεργοποιείται συνήθως στο `/tmp` για να εμποδίζει τους χρήστες να διαγράφουν ή να μετακινούν files άλλων χρηστών.

Όλα τα flags μπορούν να βρεθούν στο file `sys/stat.h` (εντοπίστε το χρησιμοποιώντας `mdfind stat.h | grep stat.h`) και είναι:

- `UF_SETTABLE` 0x0000ffff: Mask των flags που μπορούν να αλλάξουν οι owners.
- `UF_NODUMP` 0x00000001: Να μην γίνεται dump του file.
- `UF_IMMUTABLE` 0x00000002: Το file δεν μπορεί να αλλάξει.
- `UF_APPEND` 0x00000004: Οι εγγραφές στο file μπορούν να γίνονται μόνο με append.
- `UF_OPAQUE` 0x00000008: Ο directory είναι opaque σε σχέση με το union.
- `UF_COMPRESSED` 0x00000020: Το file είναι compressed (σε ορισμένα file-systems).
- `UF_TRACKED` 0x00000040: Δεν υπάρχουν notifications για deletes/renames σε files με αυτό το flag.
- `UF_DATAVAULT` 0x00000080: Απαιτείται entitlement για reading και writing.
- `UF_HIDDEN` 0x00008000: Υπόδειξη ότι αυτό το item δεν πρέπει να εμφανίζεται σε GUI.
- `SF_SUPPORTED` 0x009f0000: Mask των flags που υποστηρίζονται από τον superuser.
- `SF_SETTABLE` 0x3fff0000: Mask των flags που μπορούν να αλλάξουν από τον superuser.
- `SF_SYNTHETIC` 0xc0000000: Mask των synthetic flags που είναι read-only από το system.
- `SF_ARCHIVED` 0x00010000: Το file είναι archived.
- `SF_IMMUTABLE` 0x00020000: Το file δεν μπορεί να αλλάξει.
- `SF_APPEND` 0x00040000: Οι εγγραφές στο file μπορούν να γίνονται μόνο με append.
- `SF_RESTRICTED` 0x00080000: Απαιτείται entitlement για writing.
- `SF_NOUNLINK` 0x00100000: Το item δεν μπορεί να αφαιρεθεί, να μετονομαστεί ή να γίνει mount.
- `SF_FIRMLINK` 0x00800000: Το file είναι firmlink.
- `SF_DATALESS` 0x40000000: Το file είναι dataless object.

### **File ACLs**

Τα **ACLs** των files περιέχουν **ACEs** (Access Control Entries), όπου μπορούν να εκχωρηθούν **πιο λεπτομερή permissions** σε διαφορετικούς users.

Είναι δυνατό να εκχωρηθούν σε έναν **directory** τα εξής permissions: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Για ένα **file**: `read`, `write`, `append` και `execute`.

Όταν το file περιέχει ACLs, θα **βρείτε ένα "+" κατά την εμφάνιση των permissions, όπως στο**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Μπορείτε να **διαβάσετε τα ACLs** του αρχείου με:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Μπορείτε να βρείτε **όλα τα αρχεία με ACLs** με την ακόλουθη εντολή (είναι πολύ αργή):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Τα extended attributes είναι named metadata values που αποθηκεύονται ξεχωριστά από τα συνηθισμένα attributes ενός αρχείου. Παραθέστε τα με `ls -l@` και ελέγξτε ή τροποποιήστε τα με `xattr`. <sup>[[5]](#references)</sup> Μερικά συνηθισμένα extended attributes είναι:

- `com.apple.resourceFork`: Συμβατότητα με resource fork. Εμφανίζεται επίσης ως `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadata καραντίνας του macOS Gatekeeper
- `metadata:*`: Metadata του macOS, όπως `_backup_excludeItem` ή `kMD*`
- `com.apple.lastuseddate` (#PS): Ημερομηνία τελευταίας χρήσης του αρχείου
- `com.apple.FinderInfo`: Πληροφορίες του macOS Finder, όπως color tags
- `com.apple.TextEncoding`: Καθορίζει το text encoding αρχείων ASCII
- `com.apple.logd.metadata`: Χρησιμοποιείται από το logd σε αρχεία στο `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` στη ρίζα του filesystem)
- `com.apple.rootless`: Metadata του macOS που σχετίζονται με το System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Επισημάνσεις του logd για boot epochs με μοναδικό UUID
- `com.apple.decmpfs`: Metadata διαφανούς συμπίεσης αρχείων του macOS
- `com.apple.cprotect`: \*OS: Δεδομένα encryption ανά αρχείο (III/11)
- `com.apple.installd.*`: \*OS: Metadata που χρησιμοποιούνται από το installd, π.χ. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Τα resource forks παρέχουν ένα alternate data stream στο macOS. Το περιεχόμενο μπορεί να αποθηκευτεί στο extended attribute `com.apple.ResourceFork` και να προσπελαστεί μέσω του `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Μπορείτε να **εντοπίσετε όλα τα αρχεία που περιέχουν αυτό το extended attribute** με:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Το extended attribute `com.apple.decmpfs` αποθηκεύει metadata για διαφανή συμπίεση· δεν υποδεικνύει κρυπτογράφηση. Ανάλογα με τη μορφή συμπίεσης, τα συμπιεσμένα δεδομένα μπορεί να αποθηκεύονται στο attribute ή σε resource fork και αποσυμπιέζονται διαφανώς κατά την ανάγνωσή τους.

Το flag `UF_COMPRESSED` εμφανίζεται ως `compressed` στην `ls -lO`. Μην το διαγράφετε χειροκίνητα: κάτι τέτοιο μπορεί να κάνει το σύστημα να ερμηνεύσει λανθασμένα τη συμπιεσμένη αναπαράσταση.

Η εντολή που διαγράφει το flag εμφανίζεται εδώ επειδή είναι χρήσιμη κατά τη διάρκεια forensic review, όμως η εκτέλεσή της σε ένα συμπιεσμένο αρχείο μπορεί να κάνει το αρχείο να φαίνεται κενό ή μη προσβάσιμο μέχρι να επιδιορθωθούν τα metadata:
```bash
chflags nocompressed /path/to/file
```
Το ενσωματωμένο utility `/usr/bin/afscexpand` μπορεί να επιβάλει την αποσυμπίεση transparently compressed αρχείων. Το ξεχωριστό third-party utility `afsctool` μπορεί επίσης να επιθεωρήσει ή να αποσυμπιέσει συμπίεση Apple filesystem, αλλά δεν θα πρέπει να συγχέεται με την ενσωματωμένη εντολή. <sup>[[8]](#references)</sup>


### Ενδιαφέρουσες τοποθεσίες διαμόρφωσης (macOS)

| Διαδρομή / Τοποθεσία | Σκοπός / Τι διαμορφώνει | Ασφάλεια / Δυνατότητα επίθεσης |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Αποθηκεύει τα plist αρχεία feature-flag της Apple, τα οποία ελέγχουν προαιρετικές ή πειραματικές συμπεριφορές σε system daemons / frameworks | Αν ένας attacker μπορεί να παρακάμψει το SIP ή να αποκτήσει privilege, η παραποίηση αυτών μπορεί να ενεργοποιήσει κρυφές code paths ή να απενεργοποιήσει safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Περιέχει metadata έκδοσης του macOS (ProductVersion, BuildVersion), τα οποία χρησιμοποιούνται από apps / installers για τον έλεγχο συμπεριφοράς | Η τροποποίηση μπορεί να παραπλανήσει apps ή installers ώστε να αποδεχτούν μη υποστηριζόμενες εκδόσεις του OS ή να ξεκλειδώσουν features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Προτιμήσεις εφαρμογών / system-wide | Αν είναι writable, οι attackers μπορούν να εισαγάγουν settings για να κατευθύνουν τη συμπεριφορά apps, να απενεργοποιήσουν protections ή να προκαλέσουν misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Ορισμοί plist για background daemons και agents | Η εισαγωγή ή τροποποίηση κακόβουλων plist (αν το επιτρέπουν τα permissions) επιτρέπει persistence ή privilege escalations |
| `/etc/hosts` | Αντιστοιχίσεις hostname ↔ IP που χρησιμοποιούνται από τον system DNS resolver | Ανακατεύθυνση domain names, interception traffic, spoofing services υπό local control |
| `/etc/sudoers` | Ορίζει ποιοι μπορούν να εκτελούν commands με `sudo` και υπό ποιες συνθήκες | Ένα κατεστραμμένο αρχείο sudoers μπορεί να εκχωρήσει root ή ακατάλληλα privileges σε attacker accounts |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist ορισμού local user accounts | Η παραποίηση επιτρέπει τη δημιουργία ή τροποποίηση user accounts, password hashes ή user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Η εγκατάσταση ή τροποποίηση kexts μπορεί να οδηγήσει σε kernel-level control· προστατεύεται σε μεγάλο βαθμό από SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Αποθηκεύει configuration για την επιβολή system policies (π.χ. Gatekeeper, notarization) | Η παραποίηση μπορεί να επιτρέψει την παράκαμψη policy checks ή trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries και config files | Το misconfiguration οδηγεί σε αδύναμη SSH security, unauthorized access ή insecure algorithms |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) που χρησιμοποιούνται για τον περιορισμό ενεργειών processes | Η αντικατάσταση ή τροποποίηση των profiles μπορεί να ανοίξει sandbox escape vectors ή να αποδυναμώσει το containment |

> **Σημείωση**: Πολλές από αυτές τις διαδρομές βρίσκονται σε SIP-protected directories (π.χ. `/System`) και προστατεύονται από writes, εκτός αν το SIP έχει απενεργοποιηθεί ή παρακαμφθεί.


## Universal Binaries And Mach-O Format

Το Mach-O είναι το native executable format στο macOS. Ένα universal ή fat binary περιέχει πολλαπλά architecture-specific Mach-O slices σε ένα αρχείο· η ειδική σελίδα εξηγεί και τα δύο formats:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

Τα LaunchServices, file quarantine και Gatekeeper επηρεάζουν συλλογικά τον τρόπο με τον οποίο το macOS χειρίζεται downloaded files και επιλέγει applications για extensions και URL schemes. Οι βάσεις δεδομένων τους και τα internal resource files αλλάζουν μεταξύ releases· χρησιμοποιήστε τις ειδικές σελίδες αντί να αντιμετωπίζετε ένα private CoreTypes path ως σταθερό policy interface:

Σε releases που εκθέτουν τα legacy CoreTypes risk metadata κάτω από `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, οι κατηγορίες που συναντώνται συνήθως είναι:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: περιεχόμενο που θεωρείται αρκετά ασφαλές για automatic opening σύμφωνα με την ισχύουσα application policy.
- **`LSRiskCategoryNeutral`**: περιεχόμενο που κανονικά δεν ενεργοποιεί warning και δεν ανοίγει automatically.
- **`LSRiskCategoryUnsafeExecutable`**: executable content για το οποίο ο χρήστης θα πρέπει να λάβει application warning.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: containers, όπως archives, που μπορεί να περιέχουν executable content και απαιτούν περαιτέρω inspection.

Αυτά είναι implementation details και όχι stable public policy API· επιβεβαιώστε τα πραγματικά metadata και τη συμπεριφορά Safari/Gatekeeper στην έκδοση macOS που ελέγχεται.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Περιέχει πληροφορίες για downloaded files, όπως το URL από το οποίο κατέβηκαν.
- **Unified log**: Σε τρέχουσες εκδόσεις macOS, χρησιμοποιήστε τα `log show` και `log stream` για την αναζήτηση system και application events. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** και **`/private/var/log/asl/*.asl`**: Legacy logging artifacts που μπορεί να παραμένουν σχετικά σε παλαιότερα systems. Σε αυτά τα releases, το `/System/Library/LaunchDaemons/com.apple.syslogd.plist` διαμορφώνει το `syslogd`· το `launchctl list | grep com.apple.syslogd` μπορεί να βοηθήσει στον προσδιορισμό του αν το service είναι loaded.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Αποθηκεύει files και applications στα οποία έγινε πρόσφατη πρόσβαση μέσω του "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy preference path που σχετίζεται με login items· οι σύγχρονες εκδόσεις macOS χρησιμοποιούν επιπλέον mechanisms.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log που μπορεί να περιέχει πληροφορίες για drives, συμπεριλαμβανομένων USB devices.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Δεδομένα για wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data.

## References

- [1] [Apple - Οδηγός Προγραμματισμού File System](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Οδηγός Προγραμματισμού Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - επισκόπηση dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Οδηγός Προγραμματισμού File System: Ασφάλεια File System στο macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - σελίδα manual του macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - σελίδα manual του macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - σελίδα manual του macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
