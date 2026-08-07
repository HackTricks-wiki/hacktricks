# Αρχεία, φάκελοι, binaries και μνήμη του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Διάταξη ιεραρχίας αρχείων

- **/Applications**: Οι εγκατεστημένες εφαρμογές θα πρέπει να βρίσκονται εδώ. Όλοι οι χρήστες θα μπορούν να έχουν πρόσβαση σε αυτές.
- **/bin**: Binaries γραμμής εντολών
- **/cores**: Αν υπάρχει, χρησιμοποιείται για την αποθήκευση core dumps
- **/dev**: Τα πάντα αντιμετωπίζονται ως αρχείο, επομένως μπορεί να δείτε συσκευές hardware αποθηκευμένες εδώ.
- **/etc**: Αρχεία ρυθμίσεων
- **/Library**: Εδώ μπορούν να βρεθούν πολλοί υποκατάλογοι και αρχεία σχετικά με προτιμήσεις, caches και logs. Ένας φάκελος Library υπάρχει στο root και στον κατάλογο κάθε χρήστη.
- **/private**: Δεν τεκμηριώνεται, αλλά πολλοί από τους προαναφερθέντες φακέλους είναι symbolic links προς τον κατάλογο private.
- **/sbin**: Βασικά system binaries (σχετικά με τη διαχείριση)
- **/System**: Αρχεία που απαιτούνται για τη λειτουργία του OS X. Εδώ θα πρέπει να βρίσκονται κυρίως αρχεία ειδικά για την Apple (όχι τρίτων κατασκευαστών).
- **/tmp**: Τα αρχεία διαγράφονται μετά από 3 ημέρες (είναι soft link προς το /private/tmp)
- **/Users**: Home directory των χρηστών.
- **/usr**: Ρυθμίσεις και system binaries
- **/var**: Αρχεία log
- **/Volumes**: Οι προσαρτημένοι δίσκοι θα εμφανίζονται εδώ.
- **/.vol**: Εκτελώντας `stat a.txt` λαμβάνετε κάτι όπως `16777223 7545753 -rw-r--r-- 1 username wheel ...`, όπου ο πρώτος αριθμός είναι το id του volume όπου υπάρχει το αρχείο και ο δεύτερος είναι ο αριθμός inode. Μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο αυτού του αρχείου μέσω του /.vol/ με αυτές τις πληροφορίες, εκτελώντας `cat /.vol/16777223/7545753`

### Φάκελοι εφαρμογών

- Οι **system applications** βρίσκονται στο `/System/Applications`
- Οι **εγκατεστημένες** εφαρμογές συνήθως εγκαθίστανται στο `/Applications` ή στο `~/Applications`
- Τα **application data** μπορούν να βρεθούν στο `/Library/Application Support` για εφαρμογές που εκτελούνται ως root και στο `~/Library/Application Support` για εφαρμογές που εκτελούνται ως ο χρήστης.
- Τα **daemons** εφαρμογών τρίτων κατασκευαστών που **χρειάζεται να εκτελούνται ως root** συνήθως βρίσκονται στο `/Library/PrivilegedHelperTools/`
- Οι **sandboxed** εφαρμογές αντιστοιχίζονται στον φάκελο `~/Library/Containers`. Κάθε εφαρμογή έχει έναν φάκελο που ονομάζεται σύμφωνα με το bundle ID της εφαρμογής (`com.apple.Safari`).
- Ο **kernel** βρίσκεται στο `/System/Library/Kernels/kernel`
- Τα **kernel extensions** της **Apple** βρίσκονται στο `/System/Library/Extensions`
- Τα **kernel extensions** τρίτων κατασκευαστών αποθηκεύονται στο `/Library/Extensions`

### Αρχεία με ευαίσθητες πληροφορίες

Το MacOS αποθηκεύει πληροφορίες όπως passwords σε διάφορες τοποθεσίες:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Ευάλωτοι pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Ειδικά extensions του OS X

- **`.dmg`**: Τα Apple Disk Image files είναι πολύ συνηθισμένα για installers.
- **`.kext`**: Πρέπει να ακολουθεί συγκεκριμένη δομή και αποτελεί την έκδοση driver του OS X. (είναι bundle)
- **`.plist`**: Γνωστό και ως property list, αποθηκεύει πληροφορίες σε XML ή binary format.
- Μπορεί να είναι XML ή binary. Τα binary μπορούν να διαβαστούν με:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple applications που ακολουθούν directory structure (είναι bundle).
- **`.dylib`**: Dynamic libraries (όπως τα Windows DLL files)
- **`.pkg`**: Είναι ίδια με τα xar (eXtensible Archive format). Η installer command μπορεί να χρησιμοποιηθεί για την εγκατάσταση του περιεχομένου αυτών των αρχείων.
- **`.DS_Store`**: Αυτό το αρχείο υπάρχει σε κάθε directory και αποθηκεύει τα attributes και τις customisations του directory.
- **`.Spotlight-V100`**: Αυτός ο φάκελος εμφανίζεται στο root directory κάθε volume του συστήματος.
- **`.metadata_never_index`**: Αν αυτό το αρχείο βρίσκεται στο root ενός volume, το Spotlight δεν θα κάνει index σε αυτό το volume.
- **`.noindex`**: Αρχεία και φάκελοι με αυτό το extension δεν θα γίνονται index από το Spotlight.
- **`.sdef`**: Αρχεία μέσα σε bundles που καθορίζουν τον τρόπο αλληλεπίδρασης με την εφαρμογή από ένα AppleScript.

### macOS Bundles

Ένα bundle είναι ένα **directory** που **μοιάζει με αντικείμενο στο Finder** (Παράδειγμα Bundle είναι τα αρχεία `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Στο macOS (και το iOS), όλες οι system shared libraries, όπως frameworks και dylibs, **συνδυάζονται σε ένα single file**, το οποίο ονομάζεται **dyld shared cache**. Αυτό βελτίωσε την απόδοση, καθώς ο κώδικας μπορεί να φορτώνεται ταχύτερα.

Στο macOS βρίσκεται στο `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` και σε παλαιότερες εκδόσεις μπορεί να βρείτε το **shared cache** στο **`/System/Library/dyld/`**.\
Στο iOS μπορείτε να τα βρείτε στο **`/System/Library/Caches/com.apple.dyld/`**.

Παρόμοια με το dyld shared cache, ο kernel και τα kernel extensions μεταγλωττίζονται επίσης σε ένα kernel cache, το οποίο φορτώνεται κατά την εκκίνηση.

Για την εξαγωγή των libraries από το single file dylib shared cache ήταν δυνατή η χρήση του binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), το οποίο μπορεί να μην λειτουργεί πλέον, αλλά μπορείτε επίσης να χρησιμοποιήσετε το [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Σημειώστε ότι ακόμη και αν το εργαλείο `dyld_shared_cache_util` δεν λειτουργεί, μπορείτε να περάσετε το **shared dyld binary στο Hopper** και το Hopper θα μπορεί να αναγνωρίσει όλες τις βιβλιοθήκες και να σας επιτρέψει να **επιλέξετε ποια** θέλετε να διερευνήσετε:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Ορισμένοι extractors δεν θα λειτουργήσουν, καθώς τα dylibs είναι prelinked με hard coded διευθύνσεις και επομένως ενδέχεται να κάνουν jump σε άγνωστες διευθύνσεις

> [!TIP]
> Είναι επίσης δυνατό να κατεβάσετε το Shared Library Cache άλλων \*OS συσκευών στο macOS χρησιμοποιώντας έναν emulator στο Xcode. Θα κατέβουν μέσα στο: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, όπως:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

Το **`dyld`** χρησιμοποιεί το syscall **`shared_region_check_np`** για να γνωρίζει αν το SLC έχει γίνει mapped (το οποίο επιστρέφει τη διεύθυνση) και το **`shared_region_map_and_slide_np`** για να κάνει map το SLC.

Σημειώστε ότι ακόμη και αν το SLC γίνει slid κατά την πρώτη χρήση, όλες οι **διεργασίες** χρησιμοποιούν το **ίδιο αντίγραφο**, γεγονός που **εξαλείφει το ASLR** protection αν ο attacker μπορούσε να εκτελέσει διεργασίες στο σύστημα. Αυτό έγινε πράγματι exploited στο παρελθόν και διορθώθηκε με τον shared region pager.

Τα Branch pools είναι μικρά Mach-O dylibs που δημιουργούν μικρούς χώρους μεταξύ των image mappings, καθιστώντας αδύνατο το interpose των functions.

### Override SLCs

Χρησιμοποιώντας τις μεταβλητές περιβάλλοντος:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Αυτό θα επιτρέψει τη φόρτωση ενός νέου shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** και χειροκίνητη αντικατάσταση των βιβλιοθηκών με symlinks προς το shared cache και τις πραγματικές βιβλιοθήκες (θα χρειαστεί να τις κάνετε extract)

## Ειδικά File Permissions

### Folder permissions

Σε έναν **φάκελο**, το **read** επιτρέπει την **καταχώρισή** του, το **write** επιτρέπει τη **διαγραφή** και την εγγραφή αρχείων σε αυτόν, ενώ το **execute** επιτρέπει τη **διάσχιση** του directory. Έτσι, για παράδειγμα, ένας user με **read permission σε ένα file** μέσα σε έναν κατάλογο όπου **δεν έχει execute** permission **δεν θα μπορεί να διαβάσει** το file.

### Flag modifiers

Υπάρχουν ορισμένα flags που μπορούν να οριστούν στα files και θα κάνουν το file να συμπεριφέρεται διαφορετικά. Μπορείτε να **ελέγξετε τα flags** των files μέσα σε ένα directory με `ls -lO /path/directory`

- **`uchg`**: Γνωστό ως flag **uchange**, θα **εμποδίσει οποιαδήποτε ενέργεια** που αλλάζει ή διαγράφει το **file**. Για να το ορίσετε, εκτελέστε: `chflags uchg file.txt`
- Ο root user μπορεί να **αφαιρέσει το flag** και να τροποποιήσει το file
- **`restricted`**: Αυτό το flag κάνει το file να είναι **protected by SIP** (δεν μπορείτε να προσθέσετε αυτό το flag σε ένα file).
- **`Sticky bit`**: Αν ένας κατάλογος έχει sticky bit, **μόνο ο owner του directory ή ο root μπορούν να μετονομάσουν ή να διαγράψουν** files. Συνήθως ορίζεται στο directory /tmp για να εμποδίζει τους ordinary users να διαγράφουν ή να μετακινούν files άλλων χρηστών.

Όλα τα flags μπορούν να βρεθούν στο file `sys/stat.h` (βρείτε το χρησιμοποιώντας `mdfind stat.h | grep stat.h`) και είναι:

- `UF_SETTABLE` 0x0000ffff: Mask των flags που μπορούν να αλλάξουν οι owners.
- `UF_NODUMP` 0x00000001: Να μη γίνει dump του file.
- `UF_IMMUTABLE` 0x00000002: Το file δεν μπορεί να αλλάξει.
- `UF_APPEND` 0x00000004: Οι εγγραφές στο file μπορούν μόνο να γίνονται στο τέλος.
- `UF_OPAQUE` 0x00000008: Το directory είναι opaque σε σχέση με το union.
- `UF_COMPRESSED` 0x00000020: Το file είναι compressed (σε ορισμένα file-systems).
- `UF_TRACKED` 0x00000040: Δεν αποστέλλονται notifications για deletes/renames σε files με αυτό το flag.
- `UF_DATAVAULT` 0x00000080: Απαιτείται entitlement για read και write.
- `UF_HIDDEN` 0x00008000: Υπόδειξη ότι αυτό το item δεν πρέπει να εμφανίζεται σε GUI.
- `SF_SUPPORTED` 0x009f0000: Mask των flags που υποστηρίζονται από τον superuser.
- `SF_SETTABLE` 0x3fff0000: Mask των flags που μπορούν να αλλάξουν οι superusers.
- `SF_SYNTHETIC` 0xc0000000: Mask των system read-only synthetic flags.
- `SF_ARCHIVED` 0x00010000: Το file είναι archived.
- `SF_IMMUTABLE` 0x00020000: Το file δεν μπορεί να αλλάξει.
- `SF_APPEND` 0x00040000: Οι εγγραφές στο file μπορούν μόνο να γίνονται στο τέλος.
- `SF_RESTRICTED` 0x00080000: Απαιτείται entitlement για writing.
- `SF_NOUNLINK` 0x00100000: Το item δεν μπορεί να αφαιρεθεί, να μετονομαστεί ή να γίνει mount.
- `SF_FIRMLINK` 0x00800000: Το file είναι firmlink.
- `SF_DATALESS` 0x40000000: Το file είναι dataless object.

### **File ACLs**

Τα **ACLs** των files περιέχουν **ACE** (Access Control Entries), όπου μπορούν να εκχωρηθούν **πιο granular permissions** σε διαφορετικούς users.

Είναι δυνατό να δοθούν σε ένα **directory** τα εξής permissions: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Και σε ένα **file**: `read`, `write`, `append`, `execute`.

Όταν το file περιέχει ACLs, θα **βρείτε ένα "+" κατά την καταχώριση των permissions, όπως στο**:
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
Μπορείτε να βρείτε **όλα τα αρχεία με ACLs** με (αυτό είναι πάρα πολύ αργό):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Τα extended attributes έχουν ένα όνομα και οποιαδήποτε επιθυμητή τιμή και μπορούν να προβληθούν με τη χρήση του `ls -@` και να υποβληθούν σε χειρισμό με την εντολή `xattr`. Μερικά συνηθισμένα extended attributes είναι:

- `com.apple.resourceFork`: Συμβατότητα με resource fork. Εμφανίζεται επίσης ως `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: μηχανισμός καραντίνας του Gatekeeper (III/6)
- `metadata:*`: MacOS: διάφορα metadata, όπως `_backup_excludeItem` ή `kMD*`
- `com.apple.lastuseddate` (#PS): Ημερομηνία τελευταίας χρήσης του αρχείου
- `com.apple.FinderInfo`: MacOS: πληροφορίες του Finder (π.χ. χρωματιστά Tags)
- `com.apple.TextEncoding`: Καθορίζει την κωδικοποίηση κειμένου των αρχείων κειμένου ASCII
- `com.apple.logd.metadata`: Χρησιμοποιείται από το logd σε αρχεία στο `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` στη ρίζα του filesystem)
- `com.apple.rootless`: MacOS: Χρησιμοποιείται από το System Integrity Protection για την επισήμανση αρχείων (III/10)
- `com.apple.uuidb.boot-uuid`: Επισημάνσεις του logd για epochs εκκίνησης με μοναδικό UUID
- `com.apple.decmpfs`: MacOS: Διαφανής συμπίεση αρχείων (II/7)
- `com.apple.cprotect`: \*OS: Δεδομένα κρυπτογράφησης ανά αρχείο (III/11)
- `com.apple.installd.*`: \*OS: Metadata που χρησιμοποιούνται από το installd, π.χ. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Αυτός είναι ένας τρόπος απόκτησης **Alternate Data Streams σε MacOS** machines. Μπορείτε να αποθηκεύσετε περιεχόμενο μέσα σε ένα extended attribute που ονομάζεται **com.apple.ResourceFork** μέσα σε ένα αρχείο, αποθηκεύοντάς το στο **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Μπορείτε να **βρείτε όλα τα αρχεία που περιέχουν αυτό το extended attribute** με:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Το extended attribute `com.apple.decmpfs` υποδεικνύει ότι το αρχείο είναι αποθηκευμένο κρυπτογραφημένο, το `ls -l` θα αναφέρει **μέγεθος 0** και τα compressed δεδομένα βρίσκονται μέσα σε αυτό το attribute. Κάθε φορά που γίνεται πρόσβαση στο αρχείο, αυτό αποκρυπτογραφείται στη μνήμη.

Αυτό το attr μπορεί να εμφανιστεί με το `ls -lO`, όπου υποδεικνύεται ως compressed, επειδή τα compressed αρχεία φέρουν επίσης το flag `UF_COMPRESSED`. Αν από ένα compressed αρχείο αφαιρεθεί αυτό το flag με `chflags nocompressed </path/to/file>`, το σύστημα δεν θα γνωρίζει ότι το αρχείο ήταν compressed και, επομένως, δεν θα μπορεί να αποσυμπιέσει και να αποκτήσει πρόσβαση στα δεδομένα (θα θεωρεί ότι είναι πραγματικά κενό).

Το tool afscexpand μπορεί να χρησιμοποιηθεί για force decompress ενός αρχείου.


### Ενδιαφέρουσες τοποθεσίες configuration (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Αποθηκεύει τα plist αρχεία των feature flags της Apple, τα οποία ελέγχουν προαιρετικές ή experimental συμπεριφορές σε system daemons / frameworks | Αν ένας attacker μπορεί να παρακάμψει το SIP ή να αποκτήσει privilege, η τροποποίησή τους μπορεί να ενεργοποιήσει κρυφές code paths ή να απενεργοποιήσει safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Περιέχει metadata για την έκδοση του macOS (ProductVersion, BuildVersion), τα οποία χρησιμοποιούνται από apps / installers για τον έλεγχο συμπεριφοράς | Η τροποποίηση μπορεί να παραπλανήσει apps ή installers ώστε να αποδεχτούν μη υποστηριζόμενες εκδόσεις OS ή να ξεκλειδώσουν features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferences εφαρμογών / σε επίπεδο ολόκληρου του συστήματος | Αν είναι writable, οι attackers μπορούν να εισάγουν settings για να κατευθύνουν τη συμπεριφορά apps, να απενεργοποιήσουν protections ή να προκαλέσουν misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Ορισμοί plist για background daemons και agents | Η εισαγωγή ή τροποποίηση malicious plist (αν το επιτρέπουν τα permissions) επιτρέπει persistence ή privilege escalations |
| `/etc/hosts` | Αντιστοιχίσεις hostname ↔ IP που χρησιμοποιούνται από τον system DNS resolver | Redirecting domain names, interception traffic, spoofing services υπό local control |
| `/etc/sudoers` | Καθορίζει ποιοι μπορούν να εκτελούν commands με `sudo` και υπό ποιες συνθήκες | Ένα corrupted sudoers file μπορεί να παραχωρήσει root ή ακατάλληλα privileges σε attacker accounts |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist ορισμοί local user accounts | Η τροποποίηση επιτρέπει τη δημιουργία ή αλλαγή user accounts, password hashes ή user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Η εγκατάσταση ή τροποποίηση kexts μπορεί να οδηγήσει σε kernel-level control· προστατεύεται αυστηρά από SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Αποθηκεύει configuration για την επιβολή system policies (π.χ. Gatekeeper, notarization) | Η τροποποίησή τους μπορεί να επιτρέψει την παράκαμψη policy checks ή trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries και config files | Το misconfiguration οδηγεί σε αδύναμη SSH security, unauthorized access ή insecure algorithms |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) που χρησιμοποιούνται για τον περιορισμό ενεργειών των processes | Η αντικατάσταση ή τροποποίηση των profiles μπορεί να δημιουργήσει sandbox escape vectors ή να αποδυναμώσει το containment |

> **Σημείωση**: Πολλά από αυτά τα paths βρίσκονται σε directories που προστατεύονται από το SIP (π.χ. `/System`) και προστατεύονται από writes, εκτός αν το SIP είναι disabled ή bypassed.


## **Universal binaries &** Mach-o Format

Τα binaries του Mac OS συνήθως compiled ως **universal binaries**. Ένα **universal binary** μπορεί να **υποστηρίζει πολλαπλές architectures μέσα στο ίδιο file**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Το directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` είναι το σημείο όπου αποθηκεύονται πληροφορίες σχετικά με το **ρίσκο που συνδέεται με διαφορετικά file extensions**. Αυτό το directory κατηγοριοποιεί τα αρχεία σε διάφορα επίπεδα ρίσκου, επηρεάζοντας τον τρόπο με τον οποίο το Safari χειρίζεται αυτά τα αρχεία μετά το download. Οι κατηγορίες είναι οι εξής:

- **LSRiskCategorySafe**: Τα αρχεία αυτής της κατηγορίας θεωρούνται **εντελώς ασφαλή**. Το Safari θα ανοίξει αυτόματα αυτά τα αρχεία μετά το download.
- **LSRiskCategoryNeutral**: Αυτά τα αρχεία δεν εμφανίζουν warnings και **δεν ανοίγουν αυτόματα** από το Safari.
- **LSRiskCategoryUnsafeExecutable**: Τα αρχεία αυτής της κατηγορίας **ενεργοποιούν warning** που υποδεικνύει ότι το αρχείο είναι application. Αυτό λειτουργεί ως security measure για την ενημέρωση του χρήστη.
- **LSRiskCategoryMayContainUnsafeExecutable**: Αυτή η κατηγορία αφορά αρχεία, όπως archives, τα οποία μπορεί να περιέχουν executable. Το Safari θα **ενεργοποιήσει warning**, εκτός αν μπορεί να επαληθεύσει ότι όλα τα περιεχόμενα είναι safe ή neutral.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Περιέχει πληροφορίες για downloaded files, όπως το URL από το οποίο έγινε το download.
- **`/var/log/system.log`**: Κύριο log των OSX systems. Το com.apple.syslogd.plist είναι υπεύθυνο για την εκτέλεση του syslogging (μπορείτε να ελέγξετε αν είναι disabled αναζητώντας το "com.apple.syslogd" στο `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Αυτά είναι τα Apple System Logs, τα οποία μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Αποθηκεύει αρχεία και applications στα οποία έγινε πρόσφατη πρόσβαση μέσω του "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Αποθηκεύει items που θα γίνουν launch κατά την εκκίνηση του system
- **`$HOME/Library/Logs/DiskUtility.log`**: Log file για το DiskUtility App (πληροφορίες σχετικά με drives, συμπεριλαμβανομένων των USBs)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Δεδομένα σχετικά με wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Λίστα με deactivated daemons.

{{#include ../../../banners/hacktricks-training.md}}
