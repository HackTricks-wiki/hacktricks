# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Επισκόπηση

Πολλές μορφές archive (ZIP, RAR, TAR, 7-ZIP κ.λπ.) επιτρέπουν σε κάθε entry να περιέχει το δικό του **internal path**. Όταν ένα extraction utility ακολουθεί τυφλά αυτό το path, ένα crafted filename που περιέχει `..` ή ένα **absolute path** (π.χ. `C:\Windows\System32\`) θα εγγραφεί έξω από τον κατάλογο που επέλεξε ο χρήστης.
Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Οι συνέπειες κυμαίνονται από την αντικατάσταση αυθαίρετων αρχείων έως την άμεση επίτευξη **remote code execution (RCE)** μέσω απόθεσης ενός payload σε μια θέση **auto-run**, όπως ο φάκελος *Startup* των Windows.

## Root Cause

1. Ο attacker δημιουργεί ένα archive όπου ένα ή περισσότερα file headers περιέχουν:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ή crafted **symlinks** που επιλύονται έξω από το target dir (συνηθισμένο σε ZIP/TAR σε *nix*).
2. Το victim κάνει extract το archive με ένα vulnerable tool που εμπιστεύεται το embedded path (ή ακολουθεί symlinks) αντί να το κάνει sanitise ή να επιβάλλει extraction κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο εγγράφεται στη location που ελέγχει ο attacker και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιήσει αυτό το path.

### .NET `Path.Combine` + `ZipArchive` traversal

Ένα συνηθισμένο .NET anti-pattern είναι ο συνδυασμός του intended destination με το **user-controlled** `ZipArchiveEntry.FullName` και η εξαγωγή χωρίς path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Αν το `entry.FullName` ξεκινά με `..\\`, κάνει traversal· αν είναι **absolute path**, το αριστερό τμήμα απορρίπτεται εξ ολοκλήρου, με αποτέλεσμα ένα **arbitrary file write** ως ταυτότητα εξαγωγής.
- Proof-of-concept archive για εγγραφή σε έναν sibling κατάλογο `app`, τον οποίο παρακολουθεί ένας scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Η απόθεση αυτού του ZIP στον monitored inbox έχει ως αποτέλεσμα τη δημιουργία του `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal εκτός του `C:\samples\queue\` και επιτρέποντας follow-on primitives (π.χ. DLL hijacks).

## Πραγματικό Παράδειγμα – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows και τα Windows RAR/UnRAR components του απέτυχαν να επικυρώσουν τα filenames κατά την extraction. Το flaw χρησιμοποίησε NTFS alternate data streams (ADS) για να παρακάμψει το επιλεγμένο extraction path και να γράψει αρχεία σε μη προβλεπόμενες τοποθεσίες.<sup>[[5]](#references)</sup>
Ένα κακόβουλο RAR archive που περιείχε ένα entry όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
θα κατέληγε **εκτός** του επιλεγμένου output directory και μέσα στον φάκελο *Startup* του χρήστη. Η ESET παρατήρησε κακόβουλα αρχεία LNK να αποσυμπιέζονται εκεί και να εκτελούνται κατά το logon του χρήστη, παρέχοντας persistence και μια διαδρομή προς RCE.<sup>[[5]](#references)</sup>

### Δημιουργία ενός PoC Archive (Linux/Mac)

Επειδή το CVE-2025-8088 χρησιμοποιεί traversal path σε όνομα ADS, χρησιμοποιήστε έναν ειδικά σχεδιασμένο generator για να δημιουργήσετε το RAR και, στη συνέχεια, δοκιμάστε την εξαγωγή μόνο σε isolated lab με vulnerable WinRAR build.<sup>[[5]](#references)</sup>

### Παρατηρηθείσα Exploitation in the Wild

Η ESET ανέφερε spear-phishing campaigns της RomCom (Storm-0978/UNC2596), οι οποίες επισύναπταν RAR archives που εκμεταλλεύονταν το CVE-2025-8088 για την ανάπτυξη customised backdoors και τη διευκόλυνση ransomware operations.<sup>[[5]](#references)</sup>

## Νεότερες περιπτώσεις (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Οι ZIP entries που ήταν **symbolic links** γίνονταν dereference κατά την extraction, επιτρέποντας στους attackers να εξέλθουν από το destination directory και να κάνουν overwrite αυθαίρετων paths. Η αλληλεπίδραση του χρήστη περιορίζεται στο *άνοιγμα/εξαγωγή* του archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds πριν από το **25.00**. Το flaw στην επεξεργασία symbolic links διορθώθηκε στην έκδοση **25.00** (Ιούλιος 2025) και στις μεταγενέστερες εκδόσεις.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Overwrite του `Start Menu/Programs/Startup` ή locations εκτέλεσης services → ο κώδικας εκτελείται στο επόμενο logon ή service restart.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Αυτό το archive περιέχει ένα symlink entry που δείχνει εκτός του extraction directory· χρησιμοποιήστε disposable target και επαληθεύστε ότι ο extractor δεν το ακολουθεί. Ένα write-through test χρειάζεται επίσης ένα regular-file entry κάτω από το symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: Η `archiver.Unarchive()` ακολουθεί `../` και symlinked ZIP entries, γράφοντας εκτός του `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (το project είναι πλέον deprecated).
* **Fix**: Μεταβείτε στο `mholt/archives` ≥ 0.1.0 ή υλοποιήστε canonical-path checks πριν από την εγγραφή.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Συμβουλές Detection

* **Static inspection** – Παραθέστε τα archive entries και επισημάνετε οποιοδήποτε name περιέχει `../`, `..\\`, *absolute paths* (`/`, `C:`) ή entries τύπου *symlink* των οποίων το target βρίσκεται εκτός του extraction dir.
* **Canonicalisation** – Βεβαιωθείτε ότι το `realpath(join(dest, name))` παραμένει μέσα στο `realpath(dest)` (συγκρίνετε path components και όχι μόνο ένα raw string prefix). Απορρίψτε το διαφορετικά.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Κάντε decompress σε disposable directory χρησιμοποιώντας extractor με path/symlink checks (για παράδειγμα, τα προεπιλεγμένα secure checks του bsdtar ή 7-Zip ≥ 25.00) και, στη συνέχεια, επαληθεύστε ότι τα resulting paths παραμένουν μέσα στο directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Δημιουργήστε alert για νέα executables που γράφονται σε locations `Startup`/`Run`/`cron` λίγο μετά το άνοιγμα ενός archive από WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update του extractor** – Τα WinRAR 7.13+ και 7-Zip 25.00+ περιλαμβάνουν fixes για τα path/symlink issues που αναφέρονται.<sup>[[1]](#references)[[5]](#references)</sup>
2. Κάντε extract τα archives με “**Do not extract paths**” / “**Ignore paths**” όπου είναι δυνατό.
3. Σε Unix, κάντε drop privileges και κάντε mount ενός **chroot/namespace** πριν από την extraction· σε Windows, χρησιμοποιήστε **AppContainer** ή sandbox.
4. Αν γράφετε custom code, κάντε normalise με `realpath()`/`PathCanonicalize()` **πριν** από create/write και απορρίψτε οποιοδήποτε entry διαφεύγει από το destination.

## Πρόσθετες / Ιστορικές επηρεαζόμενες περιπτώσεις

* 2018 – Massive advisory για *Zip-Slip* από τη Snyk, που επηρέαζε πολλές Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – Το HashiCorp `go-slug` (CVE-2025-0377) ήταν ευάλωτο σε TAR extraction traversal σε slugs (διορθώθηκε στην έκδοση v0.16.3).<sup>[[7]](#references)</sup>
* Οποιαδήποτε custom extraction logic που δεν καλεί `PathCanonicalize` / `realpath` πριν από την εγγραφή.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Έρευνα της JFrog – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Αποτροπή του Zip Slip σε .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Έρευνα της ESET – Ενημερώστε τώρα τα WinRAR tools: Η RomCom και άλλοι εκμεταλλεύονται zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: Το go-slug είναι ευάλωτο σε Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Μέθοδος Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Αναφέρθηκε Proof-of-Concept Exploit για το CVE-2025-11001 στο 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
