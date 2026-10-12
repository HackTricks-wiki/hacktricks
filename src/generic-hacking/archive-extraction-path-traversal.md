# Διαδρομή διέλευσης κατά την εξαγωγή αρχείων archive ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές μορφές archive (ZIP, RAR, TAR, 7-ZIP κ.λπ.) επιτρέπουν σε κάθε καταχώριση να έχει τη δική της **εσωτερική διαδρομή**. Όταν ένα εργαλείο εξαγωγής ακολουθεί τυφλά αυτήν τη διαδρομή, ένα ειδικά διαμορφωμένο όνομα αρχείου που περιέχει `..` ή μια **απόλυτη διαδρομή** (π.χ. `C:\Windows\System32\`) θα γραφτεί έξω από τον κατάλογο που επέλεξε ο χρήστης.  
Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **path traversal κατά την εξαγωγή archive**.<sup>[[6]](#references)</sup>

Οι συνέπειες κυμαίνονται από την αντικατάσταση αυθαίρετων αρχείων έως την άμεση επίτευξη **remote code execution (RCE)**, με την τοποθέτηση ενός payload σε μια θέση **αυτόματης εκτέλεσης**, όπως ο φάκελος *Startup* των Windows.

## Βασική αιτία

1. Ο επιτιθέμενος δημιουργεί ένα archive του οποίου μία ή περισσότερες κεφαλίδες αρχείων περιέχουν:
   * Σχετικές ακολουθίες traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Απόλυτες διαδρομές (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Ή ειδικά διαμορφωμένα **symlinks** που οδηγούν έξω από τον κατάλογο προορισμού (συνηθισμένο σε ZIP/TAR σε *nix*). 
2. Το θύμα εξάγει το archive χρησιμοποιώντας ένα ευάλωτο εργαλείο που εμπιστεύεται την ενσωματωμένη διαδρομή (ή ακολουθεί τα symlinks), αντί να την εξυγιαίνει ή να επιβάλλει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο γράφεται σε θέση που ελέγχει ο επιτιθέμενος και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιήσει αυτήν τη διαδρομή.

### Traversal με `.NET` `Path.Combine` + `ZipArchive`

Ένα συνηθισμένο anti-pattern στο .NET είναι ο συνδυασμός του επιδιωκόμενου προορισμού με το **ελεγχόμενο από τον χρήστη** `ZipArchiveEntry.FullName` και η εξαγωγή χωρίς κανονικοποίηση διαδρομής:<sup>[[4]](#references)[[8]](#references)</sup>

```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
    foreach (var entry in zip.Entries)
    {
        var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
        entry.ExtractToFile(dest);
    }
}
```

- Αν το `entry.FullName` ξεκινά με `..\\`, γίνεται path traversal· αν είναι **absolute path**, το αριστερό τμήμα απορρίπτεται εντελώς, με αποτέλεσμα η ταυτότητα της εξαγωγής να επιτρέπει **arbitrary file write**.
- Αρχείο proof-of-concept για εγγραφή σε έναν αδελφό κατάλογο `app` που παρακολουθείται από προγραμματισμένο scanner:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Η απόθεση αυτού του ZIP στα επιτηρούμενα εισερχόμενα έχει ως αποτέλεσμα τη δημιουργία του `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal έξω από το `C:\samples\queue\` και επιτρέποντας επόμενα primitives (π.χ. DLL hijacks).

### Ρίζα εξαγωγής υπό τον έλεγχο του χρήστη

Ελέγξτε επίσης **τον κατάλογο που περνά στον extractor**, όχι μόνο τα ονόματα των μελών του archive. Μια εφαρμογή μπορεί να παράγει αυτόν τον κατάλογο από έναν τίτλο, ένα όνομα έργου ή κάποιο άλλο πεδίο του αιτήματος. Μια τιμή όπως `../../../../app/module` μπορεί να μετακινήσει τη ρίζα εξαγωγής έξω από την περιοχή μεταφόρτωσης πριν ο extractor επεξεργαστεί οποιοδήποτε μέλος. Σε αυτή την περίπτωση, ακόμη και ένα archive που περιέχει μόνο το ασφαλές basename `api.py` μπορεί να αντικαταστήσει κώδικα της εφαρμογής.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Αυτό αποτελεί ξεχωριστό όριο περιορισμού από το κλασικό Zip-Slip. Επικυρώστε τόσο τη ρίζα εξαγωγής μετά την επίλυση όσο και τη διαδρομή κάθε μέλους μετά την επίλυση. Ο έλεγχος της ρίζας μπορεί να βασίζεται στα στοιχεία της διαδρομής αντί σε ένα πρόθεμα συμβολοσειράς:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Για μια ασφαλή δοκιμή, ανεβάστε ένα έγκυρο archive που περιέχει ένα canary file και τοποθετήστε ακολουθίες path traversal σε κάθε πεδίο που μπορεί να επιλέγει τον κατάλογο εξαγωγής. Παρακολουθήστε τόσο τον προβλεπόμενο κατάλογο όσο και μια προσωρινή εξωτερική διαδρομή. Αν ο προορισμός μπορεί να προσπελάσει ένα imported module, η αντικατάστασή του μπορεί να οδηγήσει σε εκτέλεση κώδικα κατά την επαναφόρτωση των workers· ένα HTTP 500 ή μια επαναφορά σύνδεσης κατά την επαναφόρτωση δεν αποδεικνύει ότι η εγγραφή απέτυχε.<sup>[[14]](#references)[[15]](#references)</sup> Δείτε επίσης την ευρύτερη [μεθοδολογία file upload](../pentesting-web/file-upload/).

## Προηγμένα primitives παράκαμψης ορίων archive

Αντιμετωπίστε την εξαγωγή ως ακολουθία μεταβολών του filesystem και όχι ως ανεξάρτητους ελέγχους ονομάτων αρχείων. Μια εγγραφή που είναι ασφαλής κατά την ανάλυση μπορεί να γίνει επικίνδυνη αφού ένα προηγούμενο μέλος δημιουργήσει ή αντικαταστήσει έναν σύνδεσμο· το ίδιο πρόβλημα εμφανίζεται όταν ένας extractor αποθηκεύει στην cache έναν κατάλογο ως ασφαλή και αργότερα αλλάζει τον τύπο του.<sup>[[11]](#references)</sup>

### Μετατοπίσεις μέσω link και συγκρούσεις εγγραφών

* **Εγγραφή μέσω symlink**: δημιουργήστε `pivot -> /tmp` και έπειτα εξαγάγετε ένα κανονικό μέλος ως `pivot/PWNED.txt`. Αν ο extractor ακολουθήσει το πρώτο μέλος κατά τη δημιουργία του δεύτερου, η εγγραφή διαφεύγει χωρίς `..` στο όνομα του δεύτερου.
* **Σύγκρουση directory-cache/TOCTOU**: δημιουργήστε τον κατάλογο `d/sub/`, αντικαταστήστε το `d/sub` με ένα symlink προς το `/tmp` και έπειτα δημιουργήστε το `d/sub/PWNED.txt`. Αυτό στοχεύει extractors που επικυρώνουν ή αποθηκεύουν στην cache τον κατάλογο μία φορά και δεν τον ελέγχουν ξανά πριν από την τελική εγγραφή.
* **Ανάγνωση/αντικατάσταση μέσω hardlink**: τα TAR και RAR μπορούν να αναπαριστούν hardlinks. Ένα hardlink προς ένα υπάρχον αρχείο του host μπορεί να αποκαλύψει το περιεχόμενό του, αν κάποιο μεταγενέστερο στοιχείο εξυπηρετήσει το εξαγμένο όνομα· μια συγκρουόμενη κανονική εγγραφή μπορεί αντί γι’ αυτό να αντικαταστήσει το συνδεδεμένο inode. Αυτό περιορίζεται από τους κανόνες του ίδιου filesystem και τα δικαιώματα hardlink του OS.
* **Υπάρχον ή δια-archive pivot**: επαναλάβετε με μη κενό προορισμό. Ένα archive μπορεί να τοποθετήσει έναν σύνδεσμο και μια μεταγενέστερη εξαγωγή να κάνει εγγραφή μέσω αυτού, ακόμη κι αν κάθε archive περνά έναν stateless έλεγχο ονόματος κεφαλίδας.<sup>[[11]](#references)</sup>

### Συγκρούσεις ισοδυναμίας filesystem

Συγκρίνετε τα ονόματα με βάση τη συμπεριφορά του filesystem που θα τα δεχτεί. Χρήσιμες περιπτώσεις διαφοροποίησης περιλαμβάνουν τα `LINK` και `link` σε filesystem χωρίς διάκριση πεζών-κεφαλαίων, γραφές Unicode NFC και NFD, ονόματα ισοδύναμα βάσει συμβατότητας όπως `ﬁle` και `file`, διπλά μέλη που αλλάζουν μια διαδρομή από κατάλογο σε symlink και ανάστροφες κάθετες που ερμηνεύονται ως διαχωριστικά μόνο στα Windows. Δοκιμάστε επίσης ονόματα που περιέχουν ADS στο NTFS. Αυτές οι περιπτώσεις μπορούν να κάνουν τον validator να βλέπει δύο διαδρομές ενώ το filesystem επιλύει μία.<sup>[[5]](#references)[[11]](#references)</sup>

Επομένως, ένα συμπαγές corpus θα πρέπει να ελέγχει συνδυασμούς με συγκεκριμένη σειρά, όπως **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, μικτές `/` και `\`, απόλυτα/rooted ονόματα και συμπιεσμένα wrappers όπως `.tar.gz`. Εκτελέστε τις δοκιμές μόνο σε προσωρινό VM/container και παρακολουθήστε τόσο τον προορισμό όσο και την προβλεπόμενη εξωτερική διαδρομή canary.<sup>[[11]](#references)</sup>

Η δομική ασάφεια ειδικά στα ZIP μπορεί να έχει ως αποτέλεσμα το pre-scan και ο πραγματικός extractor να βλέπουν διαφορετικά ονόματα εγγραφών ή διαφορετικά δέντρα. Δείτε την ενότητα [Σύγχυση parser μεταξύ local header και central directory](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), αντί να εμπιστεύεστε την έξοδο μίας μόνο βιβλιοθήκης ZIP.

## Παράδειγμα από τον πραγματικό κόσμο – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows και τα Windows components RAR/UnRAR δεν επικύρωναν τα ονόματα αρχείων κατά την εξαγωγή. Το ελάττωμα αξιοποιούσε NTFS alternate data streams (ADS) για να παρακάμψει την επιλεγμένη διαδρομή εξαγωγής και να γράψει αρχεία σε μη προβλεπόμενες τοποθεσίες.<sup>[[5]](#references)</sup>
Ένα κακόβουλο RAR archive που περιέχει μια εγγραφή όπως η εξής:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

θα κατέληγε **έξω** από τον επιλεγμένο κατάλογο εξόδου και μέσα στον φάκελο *Startup* του χρήστη. Η ESET παρατήρησε κακόβουλα αρχεία LNK να αποσυμπιέζονται εκεί και να εκτελούνται κατά τη σύνδεση του χρήστη, παρέχοντας persistence και δυνατότητα για RCE.<sup>[[5]](#references)</sup>

### Δημιουργία αρχείου PoC (Linux/Mac)

Επειδή το CVE-2025-8088 χρησιμοποιεί διαδρομή traversal σε όνομα ADS, χρησιμοποιήστε ένα ειδικά σχεδιασμένο generator για να δημιουργήσετε το RAR και δοκιμάστε την αποσυμπίεση μόνο σε απομονωμένο lab με ευάλωτη έκδοση του WinRAR.<sup>[[5]](#references)</sup>

### Παρατηρημένη εκμετάλλευση στην πράξη

Η ESET ανέφερε εκστρατείες spear-phishing της RomCom (Storm-0978/UNC2596), οι οποίες περιλάμβαναν συνημμένα αρχεία RAR που εκμεταλλεύονταν το CVE-2025-8088 για την εγκατάσταση προσαρμοσμένων backdoors και τη διευκόλυνση επιχειρήσεων ransomware.<sup>[[5]](#references)</sup>

## Νεότερες περιπτώσεις (2024–2026)

### 7-Zip: traversal μέσω συμβολικού συνδέσμου ZIP → RCE (CVE-2025-11001 / ZDI-25-949)
* **Σφάλμα**: Οι καταχωρίσεις ZIP που ήταν **συμβολικοί σύνδεσμοι** ακολουθούνταν κατά την αποσυμπίεση, επιτρέποντας στους επιτιθέμενους να ξεφύγουν από τον κατάλογο προορισμού και να αντικαταστήσουν αυθαίρετες διαδρομές. Η μόνη ενέργεια που απαιτείται από τον χρήστη είναι να *ανοίξει/αποσυμπιέσει* το αρχείο.<sup>[[1]](#references)</sup>
* **Επηρεαζόμενες εκδόσεις**: Εκδόσεις του 7-Zip πριν από την **25.00**. Το σφάλμα στην επεξεργασία συμβολικών συνδέσμων διορθώθηκε στην **25.00** (Ιούλιος 2025) και σε νεότερες εκδόσεις.<sup>[[1]](#references)[[10]](#references)</sup>
* **Διαδρομή επίπτωσης**: Αντικατάσταση του `Start Menu/Programs/Startup` ή τοποθεσιών εκτέλεσης υπηρεσιών → ο κώδικας εκτελείται στην επόμενη σύνδεση ή επανεκκίνηση της υπηρεσίας.
* **Γρήγορο fixture χειρισμού συμβολικών συνδέσμων (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Αυτό το archive περιέχει μια καταχώριση symlink που δείχνει έξω από τον κατάλογο εξαγωγής· χρησιμοποιήστε έναν αναλώσιμο προορισμό και επαληθεύστε ότι ο extractor δεν τον ακολουθεί. Μια δοκιμή write-through χρειάζεται επίσης μια καταχώριση κανονικού αρχείου κάτω από το symlink.

### Go mholt/archiver σύγκρουση symlink στο `Unarchive()` (CVE-2025-3445)
* **Σφάλμα**: Η `archiver.Unarchive()` μπορεί να εξαγάγει ένα ZIP symlink και στη συνέχεια να το αποαναφέρει όταν ένα μεταγενέστερο κανονικό μέλος έχει το ίδιο όνομα, μετατρέποντας μια φαινομενικά εντός του καταλόγου εγγραφή σε εγγραφή εκτός αυτού.<sup>[[2]](#references)</sup>
* **Επηρεάζεται**: `github.com/mholt/archiver` ≤ 3.5.1 (το project είναι πλέον deprecated).<sup>[[2]](#references)</sup>
* **Διόρθωση**: Μεταβείτε στο `mholt/archives` ≥ 0.1.0 ή απορρίψτε τους συνδέσμους και επιλύστε ξανά κάθε προορισμό αμέσως πριν τον ανοίξετε.<sup>[[2]](#references)</sup>
* **Ελάχιστη γεννήτρια σύγκρουσης** (έπειτα καλέστε `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Παράκαμψη φιλτραρισμένης εξαγωγής TAR στο CPython (CVE-2026-11940)

Ακόμη και τα `tarfile.extractall(filter="data")` και `filter="tar"` είχαν παρακάμψεις λόγω της σειράς των συνδέσμων. Σε αυτή την περίπτωση, ένα hardlink αναφερόταν σε ένα symlink που είχε αρχειοθετηθεί σε βαθύτερη διαδρομή· η εφεδρική εξαγωγή επικύρωνε το σχετικό symlink σε εκείνη τη βαθιά θέση, αλλά το αναδημιουργούσε στην πιο ρηχή θέση του hardlink, όπου ο ίδιος σχετικός στόχος διέφευγε. Αυτό αποτελεί χρήσιμο γενικό έλεγχο: φροντίστε η επικύρωση και η υλοποίηση να διαφωνούν ως προς τον βασικό κατάλογο ή τον τελικό τύπο του μέλους.<sup>[[12]](#references)</sup>

### Διαφυγή στόχου hardlink στο Node `tar` μέσω αλυσίδας symlink (GHSA-83g3-92jg-28cx)

Το πακέτο `tar` του Node.js δεχόταν από το `tar.extract()` ένα hardlink του οποίου ο στόχος φαινόταν λεξικά να βρίσκεται εντός των ορίων, αλλά επιλυόταν εκτός του ριζικού καταλόγου εξαγωγής μέσω δύο προηγούμενων symlink. Η επίθεση λειτουργεί με τις προεπιλεγμένες επιλογές εξαγωγής: οι έλεγχοι του γονικού καταλόγου προορισμού κάλυπταν το όνομα του hardlink εντός της ρίζας, ενώ ο στόχος του hardlink περνούσε στο σύστημα αρχείων χωρίς να επιλυθεί ολόκληρη η αλυσίδα για να ελεγχθεί ότι βρίσκεται εντός των ορίων. Επηρεάζονται οι εκδόσεις `tar` ≤ 7.5.7· η έκδοση 7.5.8 διορθώνει το ζήτημα.<sup>[[13]](#references)</sup>

Το σημαντικό στοιχείο της δοκιμαστικής περίπτωσης είναι η **διατεταγμένη σχέση** μεταξύ των μελών, όχι αυτά τα κυριολεκτικά ονόματα:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Αν η εξαγωγή πετύχει, το `exfil` παραμένει ορατό μέσα στο δέντρο εξόδου, αλλά μοιράζεται ένα inode με το επιλεγμένο εξωτερικό αρχείο· η ανάγνωσή του διαρρέει το περιεχόμενο αυτού του αρχείου, ενώ η εγγραφή σε αυτό τροποποιεί το αρχικό. Αυτό το bypass δείχνει γιατί δεν αρκεί να ελέγχετε μόνο την τελική διαδρομή, να αφαιρείτε τα απόλυτα προθέματα ή να αποκλείετε το `..` στην κεφαλίδα του hardlink: επικυρώστε τους στόχους των συνδέσμων αφού εφαρμόσετε όλη την κατάσταση του συστήματος αρχείων που έχει δημιουργηθεί από προηγούμενες εγγραφές.<sup>[[13]](#references)</sup>

## Συμβουλές εντοπισμού

* **Στατική επιθεώρηση** – Καταγράψτε τόσο τα ονόματα των μελών όσο και τους στόχους των συνδέσμων. Επισημάνετε τα `../`, `..\\`, τις απόλυτες/rooted διαδρομές, τα symlinks, τα hardlinks, τα ειδικά αρχεία, τα διπλότυπα ονόματα, τις αλλαγές τύπου και τις συγκρούσεις μεταξύ ισοδύναμων ονομάτων ως προς τα πεζά/κεφαλαία ή το Unicode. Διατηρήστε τη σειρά των εγγραφών κατά την ανασκόπηση, καθώς το exploit μπορεί να εξαρτάται από προηγούμενα μέλη.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Κανονικοποίηση** – Βεβαιωθείτε ότι ο επιλυμένος γονικός κατάλογος μαζί με το τελικό basename παραμένει κάτω από τον επιλυμένο προορισμό (συγκρίνετε τα στοιχεία της διαδρομής, όχι ένα ακατέργαστο πρόθεμα συμβολοσειράς). Επαναλάβετε τον έλεγχο μετά από κάθε προηγούμενο μέλος· ένας εφάπαξ έλεγχος `realpath(join(dest, name))` είναι ευάλωτος σε αντικατάσταση link και μπορεί να αποτύχει για ένα φύλλο που δεν έχει δημιουργηθεί ακόμη.<sup>[[3]](#references)[[11]](#references)</sup>
* **Εξαγωγή σε sandbox** – Αποσυμπιέστε σε έναν νέο, προσωρινό κατάλογο χρησιμοποιώντας extractor με ελέγχους διαδρομών/symlink (για παράδειγμα, τους προεπιλεγμένους ασφαλείς ελέγχους του bsdtar ή το 7-Zip ≥ 25.00) και, στη συνέχεια, επαληθεύστε ότι το δέντρο που προέκυψε δεν περιέχει links που οδηγούν προς τα έξω. Η απομόνωση πρέπει να εμποδίζει μια διαφυγή που έχει ήδη ενεργοποιηθεί να φτάσει σε διαδρομές του host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Σημασία έχουν και οι μεταγενέστερες αναγνώσεις** – Ένα symlink ή hardlink που παραμένει μπορεί να γίνει primitive ανάγνωσης αυθαίρετων αρχείων, όταν ένα εργαλείο προεπισκόπησης, CDN, file browser ή pipeline πακέτων ανοίξει ή σερβίρει αργότερα το εξαγμένο όνομα, ακόμη κι αν η ίδια η εξαγωγή δεν δημιούργησε κανένα αρχείο εκτός του προορισμού.<sup>[[11]](#references)</sup>
* **Παρακολούθηση endpoint** – Δημιουργήστε ειδοποίηση για νέα εκτελέσιμα αρχεία που γράφονται σε θέσεις `Startup`/`Run`/`cron` λίγο μετά το άνοιγμα ενός archive από WinRAR/7-Zip/etc.

## Μετριασμός & Ενίσχυση Ασφάλειας

1. **Ενημερώστε τον extractor** – Τα WinRAR 7.13+, 7-Zip 25.00+ και Node `tar` 7.5.8+ περιλαμβάνουν διορθώσεις για τα ζητήματα διαδρομών/symlink/στόχων link που αναφέρονται.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Εξάγετε archives με τις επιλογές “**Do not extract paths**” / “**Ignore paths**”, όπου είναι δυνατό. Για μη έμπιστες εισόδους, απορρίψτε symbolic links, hardlinks, devices και FIFOs, εκτός αν τα χρειάζεται ρητά η εφαρμογή.<sup>[[9]](#references)[[11]](#references)</sup>
3. Εξάγετε σε **νέο, κενό κατάλογο**. Μη συγχωνεύετε μη έμπιστα μέλη σε δέντρο που περιέχει διαδρομές τις οποίες μπορεί να αντικαταστήσει ο attacker και μη χρησιμοποιείτε ξανά κατάλογο που δημιουργήθηκε από προηγούμενο archive.<sup>[[11]](#references)</sup>
4. Σε Unix, αφαιρέστε προνόμια και απομονώστε τον προορισμό σε **chroot/mount namespace**· στα Windows, χρησιμοποιήστε **AppContainer** ή sandbox. Ένας έλεγχος μετά την εξαγωγή δεν αρκεί, επειδή μια εγγραφή εκτός ορίων συμβαίνει πριν από τον έλεγχο.<sup>[[11]](#references)</sup>
5. Σε προσαρμοσμένο κώδικα, εφαρμόστε τους κανόνες του target OS για διαχωριστικά, πεζά/κεφαλαία και Unicode και επικυρώστε τόσο το μέλος όσο και τον στόχο του link. Επιλύστε και ανοίξτε τον προορισμό χωρίς να ακολουθείτε links· μην διαχωρίζετε τον έλεγχο περιορισμού διαδρομής από μια μεταγενέστερη λειτουργία δημιουργίας/αντικατάστασης. Ο validator πρέπει να χρησιμοποιεί ακριβώς την ίδια βάση και σημασιολογία εξομοίωσης link με τη διαδρομή εγγραφής.<sup>[[11]](#references)[[12]](#references)</sup>

## Επιπλέον Επηρεαζόμενες / Ιστορικές Περιπτώσεις

* 2018 – Μαζική προειδοποίηση *Zip-Slip* από τη Snyk, που επηρέασε πολλές βιβλιοθήκες Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal κατά την εξαγωγή TAR σε slugs (διορθώθηκε στην έκδοση v0.16.3).<sup>[[7]](#references)</sup>
* Κάθε προσαρμοσμένη λογική εξαγωγής που επικυρώνει τις συμβολοσειρές των headers, αλλά όχι τους στόχους των links και την τελική διαδρομή του filesystem που χρησιμοποιείται για κάθε εγγραφή.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – Διαδρομή ZIP μέσω symlink στο 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Έρευνα της JFrog – Zip-Slip στο mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Αποτροπή του Zip Slip στο .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Αλυσίδα HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Έρευνα της ESET – Ενημερώστε τώρα τα εργαλεία WinRAR: οι RomCom και άλλοι εκμεταλλεύονται ευπάθεια zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Δημόσια γνωστοποίηση κρίσιμης ευπάθειας αυθαίρετης αντικατάστασης αρχείων: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: Το go-slug είναι ευάλωτο σε επίθεση Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Μέθοδος Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Σημαίες ασφαλούς εξαγωγής του bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Αναφέρθηκε Proof-of-Concept exploit για το CVE-2025-11001 στο 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Διασκεδάζοντας με zip-slips, tar-slips, symlinks, hardlinks, collisions και άλλα](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Παράκαμψη του φίλτρου εξαγωγής tarfile στο CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – Διαφυγή στόχου hardlink του node-tar μέσω αλυσίδας symlink](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – Ρίζα εξαγωγής SCORM ελεγχόμενη από τον χρήστη](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Πολλαπλές ευπάθειες στο Frappe LMS που οδηγούν σε απομακρυσμένη εκτέλεση κώδικα](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
