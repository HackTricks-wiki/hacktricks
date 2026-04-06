# ZIPs κόλπα

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** για τη διαχείριση των **zip files** είναι απαραίτητα για τη διάγνωση, επιδιόρθωση και cracking αρχείων zip. Εδώ είναι μερικά βασικά εργαλεία:

- **`unzip`**: Αποκαλύπτει γιατί ένα αρχείο zip ενδέχεται να μην αποσυμπιεστεί.
- **`zipdetails -v`**: Προσφέρει λεπτομερή ανάλυση των πεδίων του format αρχείου zip.
- **`zipinfo`**: Καταγράφει τα περιεχόμενα ενός αρχείου zip χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν κατεστραμμένα αρχεία zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Εργαλείο για brute-force cracking κωδικών zip, αποτελεσματικό για κωδικούς μέχρι περίπου 7 χαρακτήρες.

Η [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει πλήρεις λεπτομέρειες για τη δομή και τα πρότυπα των αρχείων zip.

Είναι κρίσιμο να σημειωθεί ότι τα password-protected αρχεία zip **δεν κρυπτογραφούν τα ονόματα αρχείων ή τα μεγέθη αρχείων** στο εσωτερικό τους, μια ευπάθεια που δεν ισχύει για RAR ή 7z αρχεία που κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, αρχεία zip κρυπτογραφημένα με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε μια **plaintext attack** εάν υπάρχει μη κρυπτογραφημένο αντίγραφο ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να σπάσει τον κωδικό του zip — μια ευπάθεια που περιγράφεται στο άρθρο του HackThis και εξηγείται περαιτέρω σε αυτή την ακαδημαϊκή εργασία. Ωστόσο, αρχεία zip που προστατεύονται με **AES-256** είναι ανθεκτικά σε αυτή την plaintext attack, κάτι που δείχνει τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Οι σύγχρονοι Android malware droppers χρησιμοποιούν κακοσχηματισμένα metadata ZIP για να σπάσουν static εργαλεία (jadx/apktool/unzip) ενώ αφήνουν το APK εγκαταστάσιμο στη συσκευή. Τα πιο συνηθισμένα κόλπα είναι:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Συμπτώματα:
- `jadx-gui` fails with errors like:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- Το `unzip` ζητάει κωδικό για βασικά αρχεία APK παρόλο που ένα έγκυρο APK δεν μπορεί να έχει κρυπτογραφημένα τα `classes*.dex`, `resources.arsc`, ή `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Ανίχνευση με zipdetails:
```bash
zipdetails -v sample.apk | less
```
Κοιτάξτε το General Purpose Bit Flag για local και central headers. Μια ενδεικτική τιμή είναι το bit 0 ενεργοποιημένο (Encryption) ακόμα και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετική: Αν ένα APK εγκαθίσταται και τρέχει στη συσκευή αλλά βασικές εγγραφές φαίνονται "κρυπτογραφημένες" στα εργαλεία, το GPBF έχει τροποποιηθεί.

Επιδιόρθωση: Καθαρίστε το bit 0 του GPBF τόσο στις εγγραφές Local File Headers (LFH) όσο και στο Central Directory (CD). Ελάχιστος byte-patcher:

<details>
<summary>Ελάχιστος patcher εκκαθάρισης bit GPBF</summary>
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
</details>

Χρήση:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Τώρα θα πρέπει να δείτε `General Purpose Flag  0000` στις βασικές καταχωρήσεις και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Μεγάλα/προσαρμοσμένα Extra πεδία για να σπάσουν τους αναλυτές

Οι επιτιθέμενοι γεμίζουν υπερβολικά μεγάλα Extra πεδία και ασυνήθιστα IDs στις κεφαλίδες για να προκαλέσουν σφάλματα στους decompilers. Στην πράξη μπορεί να δείτε προσαρμοσμένους δείκτες (π.χ., συμβολοσειρές όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παραδείγματα που παρατηρήθηκαν: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που φέρουν μεγάλα payloads.

Ευριστικές DFIR:
- Ειδοποίηση όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε βασικές εγγραφές (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεώρηση άγνωστων Extra IDs σε αυτές τις εγγραφές ως ύποπτη.

Πρακτική αντιμετώπιση: η αναδόμηση του αρχείου (π.χ. re-zipping των εξαχθέντων αρχείων) αφαιρεί τα κακόβουλα Extra fields. Εάν εργαλεία αρνούνται να εξάγουν λόγω ψεύτικης κρυπτογράφησης, πρώτα καθαρίστε το `GPBF bit 0` όπως παραπάνω, και μετά επαναπακετάρετε:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Συγκρούσεις ονομάτων αρχείων/καταλόγων (απόκρυψη πραγματικών στοιχείων)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Κάποιοι extractors και decompilers μπερδεύονται και ενδέχεται να επικαλύψουν ή να κρύψουν το πραγματικό αρχείο με μια καταχώρηση καταλόγου. Αυτό έχει παρατηρηθεί με καταχωρήσεις που συγκρούονται με βασικά ονόματα APK όπως το `classes.dex`.

Triage and safe extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Επίθημα για προγραμματικό εντοπισμό:
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Blue-team detection ideas:
- Σημάνετε APKs των οποίων τα local headers δηλώνουν κρυπτογράφηση (GPBF bit 0 = 1) αλλά παρόλα αυτά εγκαθίστανται/τρέχουν.
- Σημάνετε μεγάλα/άγνωστα Extra fields σε core entries (αναζητήστε markers όπως `JADXBLOCK`).
- Σημάνετε path-collisions (`X` and `X/`) ειδικά για `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Other malicious ZIP tricks (2024–2026)

### Συγκολλημένα central directories (παραπλάνηση multi-EOCD)

Πρόσφατες phishing εκστρατείες διανέμουν ένα μόνο blob που στην πραγματικότητα είναι **δύο ZIP αρχεία συγκολλημένα**. Το κάθε ένα έχει το δικό του End of Central Directory (EOCD) + central directory. Διάφοροι extractors αναλύουν διαφορετικούς καταλόγους (7zip διαβάζει τον πρώτο, WinRAR τον τελευταίο), επιτρέποντας στους επιτιθέμενους να κρύβουν payloads που μόνο ορισμένα εργαλεία εμφανίζουν. Αυτό επίσης παρακάμπτει τα βασικά mail gateway AV που επιθεωρούν μόνο τον πρώτο κατάλογο.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Αν εμφανιστούν περισσότερα από ένα EOCD ή υπάρχουν προειδοποιήσεις "data after payload", διαχωρίστε το blob και ελέγξτε κάθε τμήμα:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Στη σύγχρονη "better zip bomb" κατασκευή δημιουργείται ένας μικρός **kernel** (highly compressed DEFLATE block) και επαναχρησιμοποιείται μέσω overlapping local headers. Κάθε central directory entry δείχνει στα ίδια συμπιεσμένα δεδομένα, επιτυγχάνοντας >28M:1 ratios χωρίς nesting archives. Βιβλιοθήκες που εμπιστεύονται τα μεγέθη του central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) μπορούν να αναγκαστούν να δεσμεύσουν petabytes.

**Γρήγορος εντοπισμός (duplicate LFH offsets)**
```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**Διαχείριση**
- Εκτελέστε ένα dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` και βεβαιωθείτε ότι οι offsets είναι αυστηρά αύξουσες και μοναδικές.
- Περιορίστε το αποδεκτό συνολικό μη-συμπιεσμένο μέγεθος και τον αριθμό εγγραφών πριν την εξαγωγή (`zipdetails -t` ή custom parser).
- Όταν πρέπει να εξαγάγετε, κάντε το μέσα σε cgroup/VM με όρια CPU+δίσκου (αποφύγετε ανεξέλεγκτες καταρρεύσεις από unbounded inflation).

---

### Σύγχυση parser: local-header vs central-directory

Πρόσφατη έρευνα σε differential-parser έδειξε ότι η ασάφεια των ZIP εξακολουθεί να είναι εκμεταλλεύσιμη σε σύγχρονες toolchains. Η βασική ιδέα είναι απλή: κάποιο software εμπιστεύεται το **Local File Header (LFH)** ενώ άλλο εμπιστεύεται το **Central Directory (CD)**, οπότε ένα archive μπορεί να παρουσιάσει διαφορετικά filenames, paths, comments, offsets ή σύνολα εγγραφών σε διαφορετικά εργαλεία.

Πρακτικές επιθετικές χρήσεις:
- Κάντε ένα upload filter, AV pre-scan, ή package validator να βλέπει ένα benign file στο CD ενώ ο extractor τιμά ένα διαφορετικό LFH name/path.
- Κακοποιήστε duplicate names, εγγραφές που υπάρχουν μόνο σε μία δομή, ή αμφίσημα Unicode path metadata (π.χ. Info-ZIP Unicode Path Extra Field `0x7075`) ώστε διαφορετικοί parsers να ανακατασκευάζουν διαφορετικά δέντρα.
- Συνδυάστε αυτό με path traversal για να μετατρέψετε μια "harmless" archive όψη σε write-primitive κατά την εξαγωγή. Για την πλευρά της εξαγωγής, δείτε [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR triage:
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
Δεν έχω το περιεχόμενο του αρχείου src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md. Παρακαλώ επικολλήστε εδώ το τμήμα που θέλετε να μεταφράσω ΚΑΙ το κείμενο με το οποίο θέλετε να το «συμπληρώσω». Θα επιστρέψω το συνδυασμένο markdown με το σχετικό αγγλικό κείμενο μεταφρασμένο στα Ελληνικά, διατηρώντας ανέπαφα tags, paths, links και κώδικα.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Ευρετικές οδηγίες:
- Απόρριψε ή απομόνωσε αρχεία με ασυμφωνία στα ονόματα LFH/CD, διπλότυπα ονόματα αρχείων, πολλαπλές εγγραφές EOCD ή επιπλέον bytes μετά το τελικό EOCD.
- Θεώρησε τα ZIP που χρησιμοποιούν ασυνήθιστα Unicode-path extra fields ή ασυνεπείς σχόλια ως ύποπτα αν διαφορετικά εργαλεία διαφωνούν στο δέντρο εξαγωγής.
- Αν η ανάλυση έχει μεγαλύτερη σημασία από τη διατήρηση των αρχικών bytes, επανασυσκεύασε το αρχείο με έναν αυστηρό parser μετά την εξαγωγή σε sandbox και σύγκρινε τη λίστα αρχείων που προκύπτει με τα αρχικά metadata.

Αυτό έχει σημασία πέρα από τα οικοσυστήματα πακέτων: η ίδια κλάση ασάφειας μπορεί να κρύψει payloads από mail gateways, static scanners και custom ingestion pipelines που "peek" στα περιεχόμενα ZIP πριν κάποιος άλλος extractor επεξεργαστεί το αρχείο.

---



## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
