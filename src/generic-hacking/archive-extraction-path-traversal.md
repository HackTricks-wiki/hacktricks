# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλά archive formats (ZIP, RAR, TAR, 7-ZIP κ.λπ.) επιτρέπουν σε κάθε entry να περιέχει το δικό του **internal path**. Όταν ένα extraction utility ακολουθεί τυφλά αυτό το path, ένα crafted filename που περιέχει `..` ή ένα **absolute path** (π.χ. `C:\Windows\System32\`) θα εγγραφεί εκτός του directory που επέλεξε ο user.
Αυτή η κατηγορία vulnerability είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Οι συνέπειες κυμαίνονται από την overwrite arbitrary files έως την άμεση επίτευξη **remote code execution (RCE)** με την τοποθέτηση ενός payload σε μια θέση **auto-run**, όπως το Windows *Startup* folder.

## Αιτία

1. Ο attacker δημιουργεί ένα archive όπου ένα ή περισσότερα file headers περιέχουν:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ή crafted **symlinks** που επιλύονται εκτός του target dir (συνηθισμένο σε ZIP/TAR σε *nix).
2. Το victim κάνει extract το archive με ένα vulnerable tool που εμπιστεύεται το embedded path (ή ακολουθεί symlinks), αντί να το sanitise ή να επιβάλλει την extraction κάτω από το directory που επιλέχθηκε.
3. Το file εγγράφεται στη location που ελέγχει ο attacker και εκτελείται/φορτώνεται την επόμενη φορά που το system ή ο user ενεργοποιεί αυτό το path.

### .NET `Path.Combine` + `ZipArchive` traversal

Ένα συνηθισμένο .NET anti-pattern είναι ο συνδυασμός του intended destination με το **user-controlled** `ZipArchiveEntry.FullName` και η εκτέλεση extraction χωρίς path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Αν το `entry.FullName` ξεκινά με `..\\`, πραγματοποιεί traversal· αν είναι **absolute path**, το αριστερό τμήμα απορρίπτεται εξ ολοκλήρου, με αποτέλεσμα **arbitrary file write** ως identity του extraction.
- Archive proof-of-concept για εγγραφή σε έναν sibling κατάλογο `app` που παρακολουθείται από έναν scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Η απόθεση αυτού του ZIP στο monitored inbox έχει ως αποτέλεσμα τη δημιουργία του `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal εκτός του `C:\samples\queue\` και επιτρέποντας follow-on primitives (π.χ. DLL hijacks).

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows και τα Windows RAR/UnRAR components απέτυχαν να επικυρώσουν τα filenames κατά την extraction. Το flaw χρησιμοποιούσε NTFS alternate data streams (ADS) για να παρακάμψει το επιλεγμένο extraction path και να γράψει αρχεία σε unintended locations.<sup>[[5]](#references)</sup>
Ένα malicious RAR archive που περιείχε ένα entry όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
θα κατέληγε **εκτός** του επιλεγμένου καταλόγου εξόδου και μέσα στον φάκελο *Startup* του χρήστη. Η ESET παρατήρησε κακόβουλα αρχεία LNK να αποσυμπιέζονται εκεί και να εκτελούνται κατά το logon του χρήστη, παρέχοντας persistence και διαδρομή προς RCE.<sup>[[5]](#references)</sup>

### Δημιουργία PoC Archive (Linux/Mac)

Επειδή το CVE-2025-8088 χρησιμοποιεί traversal path σε όνομα ADS, χρησιμοποιήστε έναν ειδικά σχεδιασμένο generator για να δημιουργήσετε το RAR και, στη συνέχεια, δοκιμάστε την extraction μόνο σε απομονωμένο lab με vulnerable WinRAR build.<sup>[[5]](#references)</sup>

### Παρατηρημένη Exploitation in the Wild

Η ESET ανέφερε spear-phishing campaigns της RomCom (Storm-0978/UNC2596), οι οποίες επισύναπταν RAR archives που εκμεταλλεύονταν το CVE-2025-8088 για την ανάπτυξη customised backdoors και τη διευκόλυνση ransomware operations.<sup>[[5]](#references)</sup>

## Νεότερες περιπτώσεις (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Οι ZIP entries που ήταν **symbolic links** γίνονταν dereference κατά την extraction, επιτρέποντας στους attackers να διαφύγουν από τον destination directory και να κάνουν overwrite αυθαίρετων paths. Η αλληλεπίδραση του χρήστη περιορίζεται στο *άνοιγμα/extracting* του archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds πριν από το **25.00**. Το flaw στην επεξεργασία των symbolic links διορθώθηκε στην **25.00** (Ιούλιος 2025) και στις νεότερες εκδόσεις.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Overwrite του `Start Menu/Programs/Startup` ή locations όπου εκτελούνται services → ο κώδικας εκτελείται στο επόμενο logon ή service restart.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Αυτό το archive περιέχει symlink entry που δείχνει έξω από τον extraction directory. Χρησιμοποιήστε disposable target και επαληθεύστε ότι ο extractor δεν το ακολουθεί. Ένα write-through test χρειάζεται επίσης μια regular-file entry κάτω από το symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: Το `archiver.Unarchive()` ακολουθεί `../` και symlinked ZIP entries, γράφοντας έξω από το `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (το project είναι πλέον deprecated).
* **Fix**: Μεταβείτε στο `mholt/archives` ≥ 0.1.0 ή υλοποιήστε canonical-path checks πριν από το write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Συμβουλές Detection

* **Static inspection** – Καταγράψτε τα archive entries και επισημάνετε οποιοδήποτε name περιέχει `../`, `..\\`, *absolute paths* (`/`, `C:`) ή entries τύπου *symlink*, των οποίων το target βρίσκεται έξω από το extraction dir.
* **Canonicalisation** – Βεβαιωθείτε ότι το `realpath(join(dest, name))` παραμένει μέσα στο `realpath(dest)` (συγκρίνετε path components και όχι μόνο ένα raw string prefix). Απορρίψτε το διαφορετικά.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Κάντε decompress σε disposable directory, χρησιμοποιώντας extractor με path/symlink checks (για παράδειγμα τα default secure checks του bsdtar ή το 7-Zip ≥ 25.00), και στη συνέχεια επαληθεύστε ότι τα resulting paths παραμένουν μέσα στον directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Δημιουργήστε alert για νέα executables που γράφονται σε locations `Startup`/`Run`/`cron` λίγο μετά το άνοιγμα ενός archive από WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Ενημερώστε τον extractor** – Τα WinRAR 7.13+ και 7-Zip 25.00+ περιέχουν fixes για τα path/symlink issues που αναφέρονται.<sup>[[1]](#references)[[5]](#references)</sup>
2. Κάντε extract τα archives με “**Do not extract paths**” / “**Ignore paths**” όπου είναι δυνατό.
3. Σε Unix, κάντε drop privileges και κάντε mount ένα **chroot/namespace** πριν από την extraction· στα Windows, χρησιμοποιήστε **AppContainer** ή sandbox.
4. Αν γράφετε custom code, κάντε normalise με `realpath()`/`PathCanonicalize()` **πριν** από το create/write και απορρίψτε οποιοδήποτε entry διαφεύγει από το destination.

## Επιπλέον Affected / Ιστορικές περιπτώσεις

* 2018 – Massive *Zip-Slip* advisory από τη Snyk που επηρέασε πολλές Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR extraction traversal σε slugs (διορθώθηκε στο v0.16.3).<sup>[[7]](#references)</sup>
* Οποιαδήποτε custom extraction logic που δεν καλεί `PathCanonicalize` / `realpath` πριν από το write.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Αποτροπή του Zip Slip σε .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ενημερώστε τώρα τα WinRAR tools: RomCom και άλλοι εκμεταλλεύονται zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Δημόσια αποκάλυψη Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: Το go-slug είναι vulnerable σε Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Μέθοδος Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Secure extraction flags του bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Αναφέρθηκε Proof-of-Concept Exploit για το CVE-2025-11001 στο 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
