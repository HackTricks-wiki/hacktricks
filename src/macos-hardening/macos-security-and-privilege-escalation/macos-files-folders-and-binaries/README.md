# Αρχεία, φάκελοι, binaries και μνήμη στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## Ιεραρχία συστήματος αρχείων

Η Apple περιγράφει το σύστημα αρχείων του macOS ως ιεραρχία τομέων συστήματος, τοπικών, δικτυακών και χρηστών. Το ακριβές περιεχόμενο διαφέρει ανά έκδοση του λειτουργικού συστήματος, ενώ όλο και περισσότερες τοποθεσίες συστήματος προστατεύονται ή δημιουργούνται συνθετικά. <sup>[[1]](#references)</sup>

- **/Applications**: Εδώ βρίσκονται οι εγκατεστημένες εφαρμογές. Όλοι οι χρήστες έχουν πρόσβαση σε αυτές.
- **/bin**: Binaries γραμμής εντολών
- **/cores**: Αν υπάρχει, χρησιμοποιείται για την αποθήκευση core dumps
- **/dev**: Τα πάντα αντιμετωπίζονται ως αρχεία, επομένως εδώ μπορεί να δείτε αποθηκευμένες συσκευές υλικού.
- **/etc**: Αρχεία ρυθμίσεων
- **/Library**: Εδώ βρίσκονται πολλοί υποκατάλογοι και αρχεία σχετικά με προτιμήσεις, caches και logs. Υπάρχει φάκελος Library στη ρίζα και στον κατάλογο κάθε χρήστη.
- **/private**: Δεν είναι τεκμηριωμένο, αλλά πολλοί από τους φακέλους που αναφέρθηκαν είναι συμβολικοί σύνδεσμοι προς τον κατάλογο private.
- **/sbin**: Απαραίτητα binaries συστήματος (σχετικά με τη διαχείριση)
- **/System**: Αρχεία που απαιτούνται από το macOS· αυτό το δέντρο περιέχει κυρίως στοιχεία που παρέχονται από την Apple.
- **/tmp**: Προσωρινά αρχεία (συμβολικός σύνδεσμος προς το `/private/tmp`). Σε παλαιότερες εγκαταστάσεις, τα παλιά προσωρινά αρχεία συνήθως διαγράφονταν περιοδικά, μερικές φορές ανά τρεις ημέρες· σήμερα, ο χρόνος εκκαθάρισης εξαρτάται από το σύστημα και την πολιτική του. Μην βασίζεστε στο ότι τα δεδομένα θα παραμείνουν εκεί.
- **/Users**: Αρχικός κατάλογος χρηστών.
- **/usr**: Ρυθμίσεις και binaries συστήματος
- **/var**: Αρχεία καταγραφής
- **/Volumes**: Εδώ εμφανίζονται οι προσαρτημένοι τόμοι.
- **/.vol**: Εκτελώντας `stat a.txt`, λαμβάνετε κάτι σαν `16777223 7545753 -rw-r--r-- 1 username wheel ...`, όπου ο πρώτος αριθμός είναι το αναγνωριστικό του τόμου στον οποίο βρίσκεται το αρχείο και ο δεύτερος ο αριθμός inode. Μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο αυτού του αρχείου μέσω του /.vol/ χρησιμοποιώντας αυτά τα στοιχεία και εκτελώντας `cat /.vol/16777223/7545753`

### Φάκελοι εφαρμογών

- Οι **εφαρμογές συστήματος** βρίσκονται στο `/System/Applications`
- Οι **εγκατεστημένες** εφαρμογές βρίσκονται συνήθως στα `/Applications` ή `~/Applications`
- Τα **δεδομένα εφαρμογών** βρίσκονται στο `/Library/Application Support` για εφαρμογές που εκτελούνται ως root και στο `~/Library/Application Support` για εφαρμογές που εκτελούνται ως χρήστης.
- Οι **daemons** τρίτων εφαρμογών που **πρέπει να εκτελούνται ως root** βρίσκονται συνήθως στο `/Library/PrivilegedHelperTools/`.
- Οι **sandboxed** εφαρμογές αντιστοιχίζονται στον φάκελο `~/Library/Containers`. Κάθε εφαρμογή έχει έναν φάκελο με όνομα που αντιστοιχεί στο bundle ID της εφαρμογής (`com.apple.Safari`).
- Ο **kernel** βρίσκεται στο `/System/Library/Kernels/kernel`
- Τα **kernel extensions της Apple** βρίσκονται στο `/System/Library/Extensions`
- Τα **kernel extensions τρίτων** αποθηκεύονται στο `/Library/Extensions`

### Αρχεία με ευαίσθητες πληροφορίες

Το macOS αποθηκεύει ευαίσθητες πληροφορίες, συμπεριλαμβανομένων διαπιστευτηρίων, σε διάφορες τοποθεσίες:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Ευάλωτοι εγκαταστάτες pkg


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Για τη διάκριση μεταξύ του εγγράψιμου τόμου Data και του σφραγισμένου τόμου System που εμφανίζονται σε αυτή την ιεραρχία, δείτε το [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Επεκτάσεις ειδικές για το OS X

- **`.dmg`**: Τα αρχεία Apple Disk Image χρησιμοποιούνται πολύ συχνά για εγκαταστάτες.
- **`.kext`**: Πρέπει να ακολουθεί συγκεκριμένη δομή και είναι η έκδοση του OS X για ένα driver. (είναι bundle)
- **`.plist`**: Μια property list αποθηκεύει δομημένες πληροφορίες σε μορφή XML ή binary.
  - Μπορεί να είναι XML ή binary. Τα binary αρχεία μπορούν να διαβαστούν με:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Ένα application bundle που ακολουθεί την τυπική δομή καταλόγων του macOS.
- **`.dylib`**: Dynamic libraries (όπως τα αρχεία DLL των Windows)
- **`.pkg`**: Τα σύγχρονα flat installer packages είναι αρχεία XAR, αλλά το `.pkg` είναι μορφή εγκαταστάτη και όχι συνώνυμο του XAR. Τα παλαιότερα installer packages τύπου bundle είναι κατάλογοι. Δείτε το [macOS installers](macos-installers-abuse.md) για τη δομή και την επιθεώρηση των packages. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Αυτό το αρχείο υπάρχει σε κάθε κατάλογο και αποθηκεύει τα χαρακτηριστικά και τις προσαρμογές του καταλόγου.
- **`.Spotlight-V100`**: Αυτός ο φάκελος εμφανίζεται στον ριζικό κατάλογο κάθε τόμου του συστήματος.
- **`.metadata_never_index`**: Αν αυτό το αρχείο βρίσκεται στη ρίζα ενός τόμου, το Spotlight δεν θα ευρετηριάσει αυτόν τον τόμο.
- **`.noindex`**: Τα αρχεία και οι φάκελοι με αυτή την επέκταση δεν θα ευρετηριαστούν από το Spotlight.
- **`.sdef`**: Ένα αρχείο ορισμού scripting που περιγράφει πώς μπορεί το AppleScript να αλληλεπιδρά με μια εφαρμογή.

### macOS Bundles

Ένα bundle είναι ένας κατάλογος με τυποποιημένη ιεραρχία, τον οποίο το Finder μπορεί να εμφανίσει ως ένα ενιαίο αντικείμενο· τα application bundles χρησιμοποιούν την επέκταση `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Στα macOS και iOS, οι βιβλιοθήκες συστήματος και τα frameworks που χρησιμοποιούνται συχνά προ-συνδέονται στο **dyld shared cache**, βελτιώνοντας την απόδοση εκκίνησης των εφαρμογών. Παρότι αντιμετωπίζεται ως μία λογική cache, οι τρέχουσες εκδόσεις ενδέχεται να την αποθηκεύουν ως κύρια cache μαζί με πολλαπλά αρχεία subcache, αντί κυριολεκτικά ως ένα αρχείο. Η μορφή και η τοποθεσία της είναι λεπτομέρειες υλοποίησης που αλλάζουν ανά έκδοση λειτουργικού συστήματος. <sup>[[3]](#references)</sup>

Στο macOS βρίσκεται στο `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, ενώ σε παλαιότερες εκδόσεις μπορεί να βρείτε την **shared cache** στο **`/System/Library/dyld/`**.\
Στο iOS μπορείτε να τη βρείτε στο **`/System/Library/Caches/com.apple.dyld/`**.

Όπως και το dyld shared cache, ο kernel και τα kernel extensions μεταγλωττίζονται επίσης σε kernel cache, η οποία φορτώνεται κατά την εκκίνηση.

Σε παλαιότερες εκδόσεις, η εξαγωγή μπορούσε να γίνει με το [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Αυτό το build ενδέχεται να μην υποστηρίζει τις τρέχουσες μορφές cache· μια άλλη επιλογή είναι το [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Σημειώστε ότι ακόμα κι αν το εργαλείο `dyld_shared_cache_util` δεν λειτουργεί, μπορείτε να περάσετε το **shared dyld binary στο Hopper** και το Hopper θα μπορεί να αναγνωρίσει όλες τις βιβλιοθήκες και να σας αφήσει να **επιλέξετε ποια** θέλετε να εξετάσετε:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Ορισμένα extractors δεν λειτουργούν, καθώς οι dylibs είναι prelinked με hard coded διευθύνσεις και, επομένως, ενδέχεται να κάνουν jump σε άγνωστες διευθύνσεις.

> [!TIP]
> Είναι επίσης δυνατό να κατεβάσετε το Shared Library Cache άλλων συσκευών \*OS στο macOS χρησιμοποιώντας έναν emulator στο Xcode. Θα κατέβουν μέσα στο: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, όπως:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Αντιστοίχιση SLC

Το **`dyld`** χρησιμοποιεί το syscall **`shared_region_check_np`** για να διαπιστώσει αν έχει γίνει mapping του SLC (το οποίο επιστρέφει τη διεύθυνση) και το **`shared_region_map_and_slide_np`** για να κάνει mapping του SLC.

Σημειώστε ότι, ακόμα κι αν γίνεται slide στο SLC κατά την πρώτη χρήση, όλες οι **διεργασίες** χρησιμοποιούν το **ίδιο αντίγραφο**, γεγονός που **εξουδετέρωνε την προστασία ASLR** αν ο επιτιθέμενος μπορούσε να εκτελέσει διεργασίες στο σύστημα. Αυτό έγινε πράγματι αντικείμενο εκμετάλλευσης στο παρελθόν και διορθώθηκε με τον shared region pager.

Τα Branch pools είναι μικρά Mach-O dylibs που δημιουργούν μικρά κενά μεταξύ των image mappings, καθιστώντας αδύνατο το interpose των συναρτήσεων.

### Περιορισμοί περιβάλλοντος του shared cache

Το `DYLD_SHARED_CACHE_DIR` ορίζει έναν κατάλογο cache, ενώ το `DYLD_SHARED_REGION` επιλέγει έναν τρόπο λειτουργίας shared-region. Η προηγούμενη γραφή `DYLD_DHARED_REGION` ήταν άκυρη και το `avoid` δεν είναι τιμή για το `DYLD_SHARED_CACHE_DIR`. Η τρέχουσα έκδοση του dyld επιτρέπει τη λειτουργία `private` μόνο όταν υπάρχει άδεια AMFI για χρήση προσαρμοσμένων shared caches, επομένως η ρύθμιση μόνο μεταβλητών περιβάλλοντος δεν αποδεικνύει ότι μια διεργασία μπορεί να φορτώσει μια αντικαταστατική cache. <sup>[[10]](#references)</sup>

## Ειδικά δικαιώματα αρχείων

### Δικαιώματα φακέλων

Για έναν κατάλογο, το **read** επιτρέπει την εμφάνιση των εγγραφών, το **write** επιτρέπει τη δημιουργία ή την αφαίρεσή τους και το **execute** επιτρέπει την περιήγηση στον κατάλογο. Συνεπώς, ένας χρήστης που μπορεί να διαβάσει ένα αρχείο αλλά δεν μπορεί να περιηγηθεί σε έναν γονικό κατάλογο δεν μπορεί να αποκτήσει πρόσβαση στο αρχείο μέσω της διαδρομής του. <sup>[[4]](#references)</sup>

### Τροποποιητές flags

Τα αρχεία μπορούν να έχουν flags που τροποποιούν τη συμπεριφορά τους. Ελέγξτε τα flags ενός καταλόγου με `ls -lO /path/directory`.

- **`uchg`**: Γνωστό ως flag **uchange**, **αποτρέπει οποιαδήποτε ενέργεια** που αλλάζει ή διαγράφει το **αρχείο**. Για να το ορίσετε, εκτελέστε: `chflags uchg file.txt`
  - Ο κάτοχος του αρχείου ή ο root μπορεί να αφαιρέσει αυτό το **user** flag με `chflags nouchg file.txt`· δεν αποτελεί προστασία έναντι κανενός από τους δύο. Το ξεχωριστό immutable flag **system** (`schg`) περιορίζεται στον root. <sup>[[11]](#references)</sup>
- **`restricted`**: Αυτό το flag προστατεύει το αρχείο μέσω του **SIP** (δεν μπορείτε να προσθέσετε αυτό το flag σε ένα αρχείο).
- **`Sticky bit`**: Σε έναν κατάλογο με ενεργοποιημένο sticky bit, μόνο ο κάτοχος του αρχείου, ο κάτοχος του καταλόγου ή ο root μπορούν να μετονομάσουν ή να διαγράψουν μια εγγραφή. Συνήθως είναι ενεργοποιημένο στο `/tmp` για να αποτρέπει τους χρήστες από το να διαγράφουν ή να μετακινούν αρχεία άλλων χρηστών.

Όλα τα flags βρίσκονται στο αρχείο `sys/stat.h` (εντοπίστε το με `mdfind stat.h | grep stat.h`) και είναι τα εξής:

- `UF_SETTABLE` 0x0000ffff: Μάσκα flags που μπορούν να αλλάξουν οι κάτοχοι.
- `UF_NODUMP` 0x00000001: Να μη γίνει dump του αρχείου.
- `UF_IMMUTABLE` 0x00000002: Το αρχείο δεν μπορεί να τροποποιηθεί.
- `UF_APPEND` 0x00000004: Οι εγγραφές στο αρχείο μπορούν μόνο να προσαρτώνται.
- `UF_OPAQUE` 0x00000008: Ο κατάλογος είναι opaque ως προς το union.
- `UF_COMPRESSED` 0x00000020: Το αρχείο είναι συμπιεσμένο (σε ορισμένα file systems).
- `UF_TRACKED` 0x00000040: Δεν αποστέλλονται ειδοποιήσεις για διαγραφές/μετονομασίες αρχείων με αυτό το flag.
- `UF_DATAVAULT` 0x00000080: Απαιτείται entitlement για ανάγνωση και εγγραφή.
- `UF_HIDDEN` 0x00008000: Ένδειξη ότι αυτό το στοιχείο δεν πρέπει να εμφανίζεται σε GUI.
- `SF_SUPPORTED` 0x009f0000: Μάσκα flags που υποστηρίζονται από τον superuser.
- `SF_SETTABLE` 0x3fff0000: Μάσκα flags που μπορούν να αλλάξουν από τον superuser.
- `SF_SYNTHETIC` 0xc0000000: Μάσκα system read-only synthetic flags.
- `SF_ARCHIVED` 0x00010000: Το αρχείο είναι αρχειοθετημένο.
- `SF_IMMUTABLE` 0x00020000: Το αρχείο δεν μπορεί να τροποποιηθεί.
- `SF_APPEND` 0x00040000: Οι εγγραφές στο αρχείο μπορούν μόνο να προσαρτώνται.
- `SF_RESTRICTED` 0x00080000: Απαιτείται entitlement για εγγραφή.
- `SF_NOUNLINK` 0x00100000: Το στοιχείο δεν μπορεί να αφαιρεθεί, να μετονομαστεί ή να γίνει mount σε αυτό.
- `SF_FIRMLINK` 0x00800000: Το αρχείο είναι firmlink.
- `SF_DATALESS` 0x40000000: Το αρχείο είναι dataless object.

### **ACL αρχείων**

Τα **ACL** αρχείων περιέχουν **ACE** (Access Control Entries), όπου μπορούν να οριστούν πιο **λεπτομερή δικαιώματα** για διαφορετικούς χρήστες.

Είναι δυνατό να εκχωρηθούν σε έναν **κατάλογο** τα εξής δικαιώματα: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Για ένα **αρχείο**: `read`, `write`, `append` και `execute`.

Όταν το αρχείο περιέχει ACL, θα **βρείτε ένα "+" κατά την εμφάνιση των δικαιωμάτων, όπως εδώ**:

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

Μπορείτε να βρείτε **όλα τα αρχεία με ACLs** με την ακόλουθη εντολή (αυτό είναι πολύ αργό):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Εκτεταμένα χαρακτηριστικά

Τα εκτεταμένα χαρακτηριστικά είναι επώνυμες τιμές μεταδεδομένων που αποθηκεύονται ξεχωριστά από τα συνηθισμένα χαρακτηριστικά ενός αρχείου. Μπορείτε να τα εμφανίσετε με `ls -l@` και να τα επιθεωρήσετε ή να τα τροποποιήσετε με `xattr`. <sup>[[5]](#references)</sup> Μερικά κοινά εκτεταμένα χαρακτηριστικά είναι:

- `com.apple.resourceFork`: Συμβατότητα με resource fork. Εμφανίζεται επίσης ως `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Μεταδεδομένα καραντίνας του macOS Gatekeeper
- `metadata:*`: Μεταδεδομένα macOS, όπως `_backup_excludeItem` ή `kMD*`
- `com.apple.lastuseddate` (#PS): Ημερομηνία τελευταίας χρήσης του αρχείου
- `com.apple.FinderInfo`: Πληροφορίες macOS Finder, όπως ετικέτες χρωμάτων
- `com.apple.TextEncoding`: Καθορίζει την κωδικοποίηση κειμένου των αρχείων κειμένου ASCII
- `com.apple.logd.metadata`: Χρησιμοποιείται από το logd σε αρχεία στο `/var/db/diagnostics`
- `com.apple.genstore.*`: Γενεαλογικός χώρος αποθήκευσης (`/.DocumentRevisions-V100` στη ρίζα του συστήματος αρχείων)
- `com.apple.rootless`: Μεταδεδομένα macOS που σχετίζονται με το System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Σημάνσεις του logd για εποχές εκκίνησης με μοναδικό UUID
- `com.apple.decmpfs`: Μεταδεδομένα διαφανούς συμπίεσης αρχείων macOS
- `com.apple.cprotect`: \*OS: Δεδομένα κρυπτογράφησης ανά αρχείο (III/11)
- `com.apple.installd.*`: \*OS: Μεταδεδομένα που χρησιμοποιούνται από το installd, π.χ. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Τα resource forks παρέχουν μια εναλλακτική ροή δεδομένων στο macOS. Το περιεχόμενο μπορεί να αποθηκευτεί στο εκτεταμένο χαρακτηριστικό `com.apple.ResourceFork` και να προσπελαστεί μέσω του `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Μπορείτε να **βρείτε όλα τα αρχεία που περιέχουν αυτό το εκτεταμένο γνώρισμα** με:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

Το extended attribute `com.apple.decmpfs` αποθηκεύει metadata για διαφανή συμπίεση· δεν υποδηλώνει κρυπτογράφηση. Ανάλογα με τη μορφή συμπίεσης, τα συμπιεσμένα δεδομένα μπορεί να αποθηκεύονται στο attribute ή σε resource fork και αποσυμπιέζονται αυτόματα κατά την ανάγνωση.

Το flag `UF_COMPRESSED` εμφανίζεται ως `compressed` στην έξοδο της `ls -lO`. Μην το εκκαθαρίζετε χειροκίνητα: αυτό μπορεί να κάνει το σύστημα να ερμηνεύσει εσφαλμένα τη συμπιεσμένη αναπαράσταση.

Η εντολή που εκκαθαρίζει το flag εμφανίζεται εδώ επειδή είναι χρήσιμη κατά τη forensic εξέταση, αλλά η εκτέλεσή της σε συμπιεσμένο αρχείο μπορεί να κάνει το αρχείο να εμφανίζεται κενό ή μη προσβάσιμο μέχρι να επιδιορθωθούν τα metadata:

```bash
chflags nocompressed /path/to/file
```

Το ενσωματωμένο βοηθητικό πρόγραμμα `/usr/bin/afscexpand` μπορεί να επιβάλει την αποσυμπίεση αρχείων που έχουν συμπιεστεί διαφανώς. Το ξεχωριστό βοηθητικό πρόγραμμα τρίτου κατασκευαστή `afsctool` μπορεί επίσης να επιθεωρεί ή να αποσυμπιέζει συμπίεση του Apple filesystem, αλλά δεν πρέπει να συγχέεται με την ενσωματωμένη εντολή. <sup>[[8]](#references)</sup>


### Ενδιαφέρουσες τοποθεσίες διαμόρφωσης (macOS)

| Διαδρομή / Τοποθεσία | Σκοπός / Τι διαμορφώνει | Ασφάλεια / Δυνατότητες επίθεσης |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Αποθηκεύει τα plist αρχεία feature-flag της Apple, τα οποία ελέγχουν προαιρετικές ή πειραματικές συμπεριφορές σε system daemons / frameworks | Αν ένας επιτιθέμενος μπορεί να παρακάμψει το SIP ή να αποκτήσει προνόμια, η αλλοίωσή τους θα μπορούσε να ενεργοποιήσει κρυφές διαδρομές κώδικα ή να απενεργοποιήσει δικλίδες ασφαλείας |
| `/System/Library/CoreServices/systemVersion.plist` | Περιέχει μεταδεδομένα έκδοσης macOS (ProductVersion, BuildVersion) που χρησιμοποιούνται από εφαρμογές / installers για τον έλεγχο συμπεριφοράς | Η τροποποίησή του μπορεί να ξεγελάσει εφαρμογές ή installers ώστε να αποδεχτούν μη υποστηριζόμενες εκδόσεις λειτουργικού συστήματος ή να ξεκλειδώσουν λειτουργίες |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Προτιμήσεις εφαρμογών / συστήματος | Αν είναι εγγράψιμα, οι επιτιθέμενοι μπορούν να εισαγάγουν ρυθμίσεις που επηρεάζουν τη συμπεριφορά εφαρμογών, απενεργοποιούν προστασίες ή προκαλούν εσφαλμένη διαμόρφωση |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Ορισμοί plist για background daemons και agents | Η εισαγωγή ή τροποποίηση κακόβουλων plist (αν το επιτρέπουν τα δικαιώματα) παρέχει δυνατότητα persistence ή κλιμάκωσης προνομίων |
| `/etc/hosts` | Αντιστοιχίσεις ονομάτων υπολογιστών ↔ IP που χρησιμοποιούνται από τον system DNS resolver | Ανακατεύθυνση domain names, υποκλοπή κίνησης, πλαστογράφηση υπηρεσιών υπό τοπικό έλεγχο |
| `/etc/sudoers` | Ορίζει ποιοι μπορούν να εκτελούν εντολές με `sudo` και υπό ποιες συνθήκες | Ένα αλλοιωμένο αρχείο sudoers μπορεί να εκχωρήσει root ή ακατάλληλα προνόμια σε λογαριασμούς επιτιθέμενων |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist ορισμοί τοπικών λογαριασμών χρηστών | Η αλλοίωση επιτρέπει τη δημιουργία ή τροποποίηση λογαριασμών χρηστών, password hashes ή μεταδεδομένων χρηστών |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Η εγκατάσταση ή τροποποίηση kexts μπορεί να οδηγήσει σε έλεγχο σε επίπεδο kernel· προστατεύονται αυστηρά από SIP / πολιτικές υπογραφής |
| `/private/var/db/SystemPolicyConfiguration/` | Αποθηκεύει διαμόρφωση για την επιβολή πολιτικών συστήματος (π.χ. Gatekeeper, notarization) | Η αλλοίωσή τους μπορεί να επιτρέψει την παράκαμψη ελέγχων πολιτικής ή κανόνων εμπιστοσύνης |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Βοηθητικά binaries και αρχεία διαμόρφωσης SSH | Η εσφαλμένη διαμόρφωση οδηγεί σε αδύναμη ασφάλεια SSH, μη εξουσιοδοτημένη πρόσβαση ή μη ασφαλείς αλγορίθμους |
| `/System/Library/Sandbox/Profiles` | Προφίλ system sandbox (SBPL) που χρησιμοποιούνται για τον περιορισμό ενεργειών διεργασιών | Η αντικατάσταση ή τροποποίηση προφίλ μπορεί να δημιουργήσει διαδρομές διαφυγής από το sandbox ή να αποδυναμώσει τον περιορισμό |

> **Σημείωση**: Πολλές από αυτές τις διαδρομές βρίσκονται σε καταλόγους που προστατεύονται από το SIP (π.χ. `/System`) και δεν επιτρέπεται η εγγραφή σε αυτές, εκτός αν το SIP απενεργοποιηθεί ή παρακαμφθεί.  


## Universal Binaries και μορφή Mach-O

Το Mach-O είναι η εγγενής μορφή εκτελέσιμων αρχείων στο macOS. Ένα universal ή fat binary περιέχει πολλαπλά Mach-O slices, ειδικά για διαφορετικές αρχιτεκτονικές, σε ένα αρχείο· η ειδική σελίδα εξηγεί και τις δύο μορφές:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Απόρριψη μνήμης macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Κίνδυνοι αρχείων και μεταδεδομένα χειριστών

Τα LaunchServices, το file quarantine και το Gatekeeper επηρεάζουν από κοινού τον τρόπο με τον οποίο το macOS χειρίζεται αρχεία που έχουν ληφθεί και επιλέγει εφαρμογές για extensions και URL schemes. Οι βάσεις δεδομένων τους και τα εσωτερικά αρχεία πόρων αλλάζουν ανά έκδοση· χρησιμοποιήστε τις ειδικές σελίδες αντί να θεωρείτε μια ιδιωτική διαδρομή CoreTypes ως σταθερό interface πολιτικής:

Σε εκδόσεις που εκθέτουν τα παλαιού τύπου μεταδεδομένα κινδύνου CoreTypes στη διαδρομή `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, οι κατηγορίες που συναντώνται συνήθως είναι οι εξής:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Περιεχόμενο που θεωρείται αρκετά ασφαλές για αυτόματο άνοιγμα, σύμφωνα με την ισχύουσα πολιτική της εφαρμογής.
- **`LSRiskCategoryNeutral`**: Περιεχόμενο που συνήθως δεν ενεργοποιεί προειδοποίηση και δεν ανοίγει αυτόματα.
- **`LSRiskCategoryUnsafeExecutable`**: Εκτελέσιμο περιεχόμενο για το οποίο ο χρήστης θα πρέπει να λάβει προειδοποίηση εφαρμογής.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Περιέκτες, όπως αρχεία αρχειοθέτησης, που ενδέχεται να περιέχουν εκτελέσιμο περιεχόμενο και απαιτούν περαιτέρω έλεγχο.

Πρόκειται για λεπτομέρειες υλοποίησης, όχι για σταθερό δημόσιο API πολιτικής· επιβεβαιώστε τα πραγματικά μεταδεδομένα και τη συμπεριφορά του Safari/Gatekeeper στην έκδοση macOS που εξετάζετε.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Αρχεία καταγραφής

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Περιέχει πληροφορίες για αρχεία που έχουν ληφθεί, όπως το URL από το οποίο λήφθηκαν.
- **Unified log**: Στις τρέχουσες εκδόσεις macOS, αναζητήστε συμβάντα συστήματος και εφαρμογών με τις εντολές `log show` και `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** και **`/private/var/log/asl/*.asl`**: Παλαιού τύπου στοιχεία καταγραφής που ενδέχεται να εξακολουθούν να είναι σχετικά σε παλαιότερα συστήματα. Σε αυτές τις εκδόσεις, το `/System/Library/LaunchDaemons/com.apple.syslogd.plist` διαμορφώνει το `syslogd`· η εντολή `launchctl list | grep com.apple.syslogd` μπορεί να βοηθήσει να διαπιστωθεί αν η υπηρεσία έχει φορτωθεί.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Αποθηκεύει αρχεία και εφαρμογές στα οποία έγινε πρόσφατη πρόσβαση μέσω του "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Παλαιού τύπου διαδρομή προτιμήσεων που σχετίζεται με τα login items· οι σύγχρονες εκδόσεις macOS χρησιμοποιούν επιπλέον μηχανισμούς.
- **`$HOME/Library/Logs/DiskUtility.log`**: Παλαιό αρχείο καταγραφής του Disk Utility που ενδέχεται να περιέχει πληροφορίες για μονάδες δίσκου, συμπεριλαμβανομένων συσκευών USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Δεδομένα σχετικά με ασύρματα access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Παλαιού τύπου δεδομένα παράκαμψης του launchd.



## References

- [1] [Apple - Οδηγός προγραμματισμού συστημάτων αρχείων](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Οδηγός προγραμματισμού bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Επισκόπηση dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Οδηγός προγραμματισμού συστημάτων αρχείων: Ασφάλεια συστήματος αρχείων macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Σελίδα εγχειριδίου macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Σελίδα εγχειριδίου macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Σελίδα εγχειριδίου macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Αποσυσκευασία Apple Archives](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Ασφάλεια Shell Script: ειδικές σημαίες δικαιωμάτων αρχείων](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Εργασίες υπογραφής κώδικα: πακέτα installer](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
