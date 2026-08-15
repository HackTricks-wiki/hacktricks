# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές μορφές archive (ZIP, RAR, TAR, 7-ZIP κ.λπ.) επιτρέπουν σε κάθε entry να περιέχει το δικό του **internal path**. Όταν ένα extraction utility ακολουθεί τυφλά αυτό το path, ένα crafted filename που περιέχει `..` ή ένα **absolute path** (π.χ. `C:\Windows\System32\`) θα γραφτεί έξω από τον κατάλογο που επέλεξε ο χρήστης.
Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Οι συνέπειες κυμαίνονται από την αντικατάσταση αυθαίρετων αρχείων έως την άμεση επίτευξη **remote code execution (RCE)** μέσω τοποθέτησης ενός payload σε μια θέση **auto-run**, όπως ο φάκελος *Startup* των Windows.

## Βασική αιτία

1. Ο attacker δημιουργεί ένα archive όπου ένα ή περισσότερα file headers περιέχουν:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ή crafted **symlinks** που επιλύονται εκτός του target dir (συνηθισμένο σε ZIP/TAR σε *nix).
2. Το victim κάνει extract το archive με ένα vulnerable tool που εμπιστεύεται το embedded path (ή ακολουθεί symlinks), αντί να το sanitise ή να επιβάλλει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο γράφεται στη location που ελέγχει ο attacker και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιεί αυτό το path.

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
- Αν το `entry.FullName` ξεκινά με `..\\`, πραγματοποιεί traversal· αν είναι **absolute path**, το αριστερό τμήμα απορρίπτεται πλήρως, με αποτέλεσμα ένα **arbitrary file write** ως ταυτότητα εξαγωγής.
- Proof-of-concept archive για εγγραφή σε έναν αδελφό κατάλογο `app` που παρακολουθείται από έναν προγραμματισμένο scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Η απόθεση αυτού του ZIP στο monitored inbox έχει ως αποτέλεσμα τη δημιουργία του `C:\samples\app\0xdf.txt`, αποδεικνύοντας traversal εκτός του `C:\samples\queue\` και επιτρέποντας follow-on primitives (π.χ. DLL hijacks).

## Advanced Archive-Breakout Primitives

Αντιμετωπίστε το extraction ως ακολουθία filesystem mutations και όχι ως ανεξάρτητους ελέγχους filenames. Ένα entry που είναι ασφαλές κατά το parsing μπορεί να γίνει unsafe αφού ένα προηγούμενο member δημιουργήσει ή αντικαταστήσει ένα link· το ίδιο ζήτημα εμφανίζεται όταν ένας extractor αποθηκεύει έναν directory ως ασφαλή και αργότερα αλλάζει τον τύπο του.<sup>[[11]](#references)</sup>

### Link pivots και collisions μεταξύ entries

* **Symlink write-through**: δημιουργήστε `pivot -> /tmp` και στη συνέχεια κάντε extract ένα regular member ως `pivot/PWNED.txt`. Αν ο extractor ακολουθήσει το πρώτο member κατά το materialising του δεύτερου, το write διαφεύγει χωρίς `..` στο δεύτερο name.
* **Directory-cache/TOCTOU collision**: δημιουργήστε το directory `d/sub/`, αντικαταστήστε το `d/sub` με symlink προς `/tmp` και στη συνέχεια δημιουργήστε το `d/sub/PWNED.txt`. Αυτό στοχεύει extractors που επικυρώνουν ή κάνουν cache το directory μία φορά και δεν το ελέγχουν ξανά πριν από το τελικό write.
* **Hardlink read/overwrite**: τα TAR και RAR μπορούν να αναπαραστήσουν hardlinks. Ένα hardlink προς υπάρχον host file μπορεί να αποκαλύψει τα περιεχόμενά του αν ένα μεταγενέστερο component χρησιμοποιεί το extracted name· ένα colliding regular entry μπορεί, αντίθετα, να κάνει overwrite το linked inode. Αυτό περιορίζεται από τους κανόνες same-filesystem και OS hardlink-permission.
* **Pre-existing ή cross-archive pivot**: επαναλάβετε τη δοκιμή με non-empty destination. Ένα archive μπορεί να εγκαταστήσει ένα link και ένα μεταγενέστερο extraction να γράψει μέσω αυτού, ακόμη και αν κάθε archive περνά έναν stateless header-name check.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Συγκρίνετε τα names χρησιμοποιώντας τα semantics του filesystem που θα τα παραλάβει. Χρήσιμες differential cases περιλαμβάνουν `LINK` έναντι `link` σε case-insensitive filesystems, NFC έναντι NFD Unicode spellings, compatibility-equivalent names όπως `ﬁle` έναντι `file`, duplicate members που αλλάζουν ένα path από directory σε symlink και backslashes που ερμηνεύονται ως separators μόνο στα Windows. Ελέγξτε επίσης names που περιέχουν ADS στο NTFS. Αυτές οι περιπτώσεις μπορεί να κάνουν τον validator να βλέπει δύο paths ενώ το filesystem επιλύει ένα.<sup>[[5]](#references)[[11]](#references)</sup>

Επομένως, ένα compact corpus θα πρέπει να ελέγχει ordered combinations των **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mixed `/` και `\`, absolute/rooted names και compressed wrappers όπως `.tar.gz`. Εκτελέστε το μόνο σε disposable VM/container και παρακολουθήστε τόσο το destination όσο και το intended outside canary path.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Το WinRAR για Windows και τα Windows RAR/UnRAR components του απέτυχαν να επικυρώσουν τα filenames κατά το extraction. Το flaw χρησιμοποίησε NTFS alternate data streams (ADS) για να παρακάμψει το selected extraction path και να γράψει files σε unintended locations.<sup>[[5]](#references)</sup>
Ένα malicious RAR archive που περιέχει ένα entry όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
θα κατέληγε **εκτός** του επιλεγμένου καταλόγου εξόδου και μέσα στον φάκελο *Startup* του χρήστη. Η ESET παρατήρησε κακόβουλα αρχεία LNK να αποσυμπιέζονται εκεί και να εκτελούνται κατά τη σύνδεση του χρήστη, παρέχοντας persistence και μια διαδρομή προς RCE.<sup>[[5]](#references)</sup>

### Δημιουργία PoC Archive (Linux/Mac)

Επειδή το CVE-2025-8088 χρησιμοποιεί traversal path σε όνομα ADS, χρησιμοποιήστε έναν generator ειδικά σχεδιασμένο για τη δημιουργία του RAR και, στη συνέχεια, δοκιμάστε την εξαγωγή μόνο σε απομονωμένο lab με ευάλωτη έκδοση του WinRAR.<sup>[[5]](#references)</sup>

### Παρατηρημένη Εκμετάλλευση στο Wild

Η ESET ανέφερε spear-phishing campaigns της RomCom (Storm-0978/UNC2596), οι οποίες επισύναπταν RAR archives που εκμεταλλεύονταν το CVE-2025-8088 για την ανάπτυξη customised backdoors και τη διευκόλυνση ransomware operations.<sup>[[5]](#references)</sup>

## Νεότερες Περιπτώσεις (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Οι ZIP entries που ήταν **symbolic links** γίνονταν dereference κατά την εξαγωγή, επιτρέποντας στους attackers να διαφύγουν από τον κατάλογο προορισμού και να κάνουν overwrite αυθαίρετων paths. Η αλληλεπίδραση του χρήστη περιορίζεται στο *άνοιγμα/εξαγωγή* του archive.<sup>[[1]](#references)</sup>
* **Affected**: Εκδόσεις 7-Zip πριν από την **25.00**. Το flaw στην επεξεργασία των symbolic links διορθώθηκε στην **25.00** (Ιούλιος 2025) και στις μεταγενέστερες εκδόσεις.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Overwrite του `Start Menu/Programs/Startup` ή τοποθεσιών service-run → ο κώδικας εκτελείται στην επόμενη σύνδεση ή επανεκκίνηση της υπηρεσίας.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Αυτό το archive περιέχει ένα symlink entry που δείχνει εκτός του καταλόγου εξαγωγής· χρησιμοποιήστε disposable target και επαληθεύστε ότι ο extractor δεν το ακολουθεί. Ένα write-through test χρειάζεται επίσης ένα regular-file entry κάτω από το symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: Το `archiver.Unarchive()` μπορεί να εξαγάγει ένα ZIP symlink και στη συνέχεια να κάνει dereference όταν ένα μεταγενέστερο regular member έχει το ίδιο όνομα, μετατρέποντας ένα φαινομενικά in-root write σε out-of-root write.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (το project είναι πλέον deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Μεταβείτε στο `mholt/archives` ≥ 0.1.0 ή απορρίψτε τα links και κάντε re-resolve κάθε destination αμέσως πριν το άνοιγμά του.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (και, στη συνέχεια, καλέστε `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

Ακόμη και τα `tarfile.extractall(filter="data")` και `filter="tar"` έχουν παρουσιάσει bypasses που βασίζονται στη σειρά των links. Σε αυτή την περίπτωση, ένα hardlink αναφερόταν σε ένα symlink που είχε αρχειοθετηθεί σε βαθύτερο path· η fallback extraction επικύρωνε το relative symlink σε εκείνη τη βαθιά τοποθεσία, αλλά το αναδημιουργούσε στη ρηχότερη τοποθεσία του hardlink, όπου ο ίδιος relative target διέφευγε. Αυτό αποτελεί χρήσιμο γενικό test: κάντε τη validation και τη materialisation να διαφωνούν σχετικά με τον base directory ή τον τελικό τύπο του member.<sup>[[12]](#references)</sup>

## Συμβουλές Detection

* **Static inspection** – Καταγράψτε τόσο τα member names όσο και τα link targets. Εντοπίστε `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes και collisions ισοδύναμων περιπτώσεων ως προς το case/Unicode. Διατηρήστε τη σειρά των entries κατά την ανασκόπηση, επειδή το exploit μπορεί να εξαρτάται από προηγούμενα members.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Βεβαιωθείτε ότι ο resolved parent μαζί με το final basename παραμένει κάτω από το resolved destination (συγκρίνετε path components, όχι ένα raw string prefix). Κάντε re-check μετά από κάθε προηγούμενο member· ένα one-time `realpath(join(dest, name))` test είναι ευάλωτο σε αντικατάσταση link και μπορεί να αποτύχει για ένα leaf που δεν έχει ακόμη δημιουργηθεί.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Κάντε decompress σε έναν νέο, disposable κατάλογο χρησιμοποιώντας extractor με path/symlink checks (για παράδειγμα, τα default secure checks του bsdtar ή 7-Zip ≥ 25.00) και, στη συνέχεια, επαληθεύστε ότι το resulting tree δεν περιέχει outward links. Η isolation πρέπει να εμποδίζει ένα escape που έχει ήδη ενεργοποιηθεί από το να φτάσει σε host paths.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Ένα symlink ή hardlink που έχει παραμείνει μπορεί να γίνει primitive για arbitrary-file-read όταν ένα previewer, CDN, file browser ή package pipeline ανοίξει ή σερβίρει αργότερα το extracted name, ακόμη και αν η extraction δεν δημιούργησε κανένα outside file.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Δημιουργήστε alert για νέα executables που γράφονται σε τοποθεσίες `Startup`/`Run`/`cron` λίγο μετά το άνοιγμα ενός archive από WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – Τα WinRAR 7.13+ και 7-Zip 25.00+ περιέχουν fixes για τα path/symlink issues που αναφέρονται.<sup>[[1]](#references)[[5]](#references)</sup>
2. Κάντε extract τα archives με “**Do not extract paths**” / “**Ignore paths**” όταν είναι δυνατό. Για untrusted input, απορρίψτε symbolic links, hardlinks, devices και FIFOs, εκτός αν η εφαρμογή τα χρειάζεται ρητά.<sup>[[9]](#references)[[11]](#references)</sup>
3. Κάντε extract σε έναν **νέο κενό κατάλογο**. Μην κάνετε merge untrusted members σε tree που περιέχει paths τα οποία μπορούν να αντικατασταθούν από attacker και μην επαναχρησιμοποιείτε κατάλογο που έχει δημιουργηθεί από προηγούμενο archive.<sup>[[11]](#references)</sup>
4. Σε Unix, αφαιρέστε privileges και απομονώστε το destination σε **chroot/mount namespace**· στα Windows, χρησιμοποιήστε **AppContainer** ή sandbox. Ένα post-extraction scan από μόνο του δεν επαρκεί, επειδή ένα escaped write πραγματοποιείται πριν από το scan.<sup>[[11]](#references)</sup>
5. Σε custom code, εφαρμόστε τους separator/case/Unicode rules του target OS και επικυρώστε τόσο το member όσο και το link target. Κάντε resolve και open το destination χωρίς να ακολουθείτε links· μην διαχωρίζετε ένα containment check από μια μεταγενέστερη create/replace operation. Ο validator πρέπει να χρησιμοποιεί ακριβώς το ίδιο base και τα ίδια link-emulation semantics με το write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Massive advisory για *Zip-Slip* από τη Snyk, που επηρέαζε πολλές Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – Το `go-slug` της HashiCorp (CVE-2025-0377), TAR extraction traversal σε slugs (διορθώθηκε στην v0.16.3).<sup>[[7]](#references)</sup>
* Οποιαδήποτε custom extraction logic που επικυρώνει header strings αλλά όχι τα link targets και το final filesystem path που χρησιμοποιείται για κάθε write.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Αποτροπή του Zip Slip σε .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Αλυσίδα HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ενημερώστε τώρα τα WinRAR tools: η RomCom και άλλοι εκμεταλλεύονται zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: Το go-slug της HashiCorp είναι ευάλωτο σε Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Μέθοδος Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Secure extraction flags του bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Αναφέρθηκε Proof-of-Concept Exploit για το CVE-2025-11001 στο 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Hacking fun με zip-slips, tar-slips, symlinks, hardlinks, collisions και άλλα](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Bypass του tarfile extraction filter για το CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
