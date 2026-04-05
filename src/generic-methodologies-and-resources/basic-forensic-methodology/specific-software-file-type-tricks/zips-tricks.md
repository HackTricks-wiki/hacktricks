# Κόλπα με ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Εργαλεία γραμμής εντολών** για τη διαχείριση **zip files** είναι απαραίτητα για τη διάγνωση, την επισκευή, και το cracking zip αρχείων. Εδώ μερικά βασικά βοηθητικά προγράμματα:

- **`unzip`**: Αποκαλύπτει γιατί ένα zip αρχείο μπορεί να μην αποσυμπιεστεί.
- **`zipdetails -v`**: Προσφέρει λεπτομερή ανάλυση των πεδίων της μορφής αρχείου zip.
- **`zipinfo`**: Απαριθμεί τα περιεχόμενα ενός zip αρχείου χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επισκευάσουν κατεστραμένα zip αρχεία.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ένα εργαλείο για brute-force cracking των zip passwords, αποτελεσματικό για κωδικούς έως περίπου 7 χαρακτήρες.

Το [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει αναλυτικές λεπτομέρειες για τη δομή και τα πρότυπα των zip αρχείων.

Είναι σημαντικό να σημειωθεί ότι τα password-protected zip αρχεία **δεν κρυπτογραφούν τα ονόματα αρχείων ή τα μεγέθη αρχείων** στο εσωτερικό τους, ένα πρόβλημα ασφάλειας που δεν υπάρχει σε RAR ή 7z αρχεία τα οποία κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, zip αρχεία κρυπτογραφημένα με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε ένα plaintext attack αν υπάρχει διαθέσιμη μια μη κρυπτογραφημένη αντιγραφή ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να σπάσει το password του zip, μια ευπάθεια που περιγράφεται στο [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και επεξηγείται περαιτέρω σε [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Ωστόσο, zip αρχεία προστατευμένα με **AES-256** encryption είναι ανθεκτικά σε αυτό το plaintext attack, δείχνοντας τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Οι σύγχρονοι Android malware droppers χρησιμοποιούν malformed ZIP metadata για να σπάσουν static tools (jadx/apktool/unzip) ενώ κρατούν το APK installable στη συσκευή. Τα πιο κοινά κόλπα είναι:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Συμπτώματα:
- `jadx-gui` αποτυγχάνει με σφάλματα όπως:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` ζητάει password για βασικά αρχεία APK παρόλο που ένα έγκυρο APK δεν μπορεί να έχει κρυπτογραφημένα `classes*.dex`, `resources.arsc`, ή `AndroidManifest.xml`:

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
Κοίταξε το General Purpose Bit Flag για local και central headers. Μια ενδεικτική τιμή είναι το bit 0 ενεργοποιημένο (Encryption) ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετική: Αν ένα APK εγκαθίσταται και τρέχει στη συσκευή αλλά οι βασικές εγγραφές εμφανίζονται "encrypted" σε tools, ο GPBF έχει παραποιηθεί.

Διόρθωση: Καθαρίστε το bit 0 του GPBF τόσο στις Local File Headers (LFH) όσο και στις Central Directory (CD) εγγραφές. Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
Τώρα θα πρέπει να βλέπετε `General Purpose Flag  0000` στις βασικές εγγραφές και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Large/custom Extra fields to break parsers

Οι επιτιθέμενοι τοποθετούν υπερμεγέθη Extra πεδία και περίεργα IDs στις κεφαλίδες για να προκαλέσουν σφάλματα στους decompilers. Στην πράξη μπορεί να δείτε προσαρμοσμένους δείκτες (π.χ., συμβολοσειρές όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παρατηρούμενα παραδείγματα: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που μεταφέρουν μεγάλα payloads.

DFIR ευριστικές:
- Ειδοποιήστε όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε βασικά entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεωρήστε άγνωστα Extra IDs σε αυτές τις εγγραφές ύποπτα.

Πρακτική αντιμετώπιση: η αναδημιουργία του archive (π.χ., re-zipping των εξαγόμενων αρχείων) αφαιρεί τα malicious Extra fields. Αν τα εργαλεία αρνούνται να εξάγουν λόγω ψευδούς κρυπτογράφησης, πρώτα καθαρίστε το GPBF bit 0 όπως παραπάνω, και μετά επαναπακετάρετε:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Σύγκρουση ονομάτων αρχείου/φακέλου (απόκρυψη πραγματικών αρχείων)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν φάκελο `X/`. Ορισμένοι extractors και decompilers μπερδεύονται και ενδέχεται να επικαλύψουν ή να κρύψουν το πραγματικό αρχείο με μια καταχώριση φακέλου. Αυτό έχει παρατηρηθεί σε καταχωρίσεις που συγκρούονται με βασικά ονόματα APK όπως `classes.dex`.

Triage και ασφαλής εξαγωγή:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Επίθημα για προγραμματική ανίχνευση:
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
- Σημάνετε APKs των οποίων οι local headers υποδεικνύουν κρυπτογράφηση (GPBF bit 0 = 1), αλλά εγκαθίστανται/εκτελούνται.
- Σημάνετε μεγάλα/άγνωστα Extra fields σε βασικές εγγραφές (αναζητήστε δείκτες όπως `JADXBLOCK`).
- Σημάνετε συγκρούσεις διαδρομών (`X` και `X/`) ειδικά για `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Άλλα κακόβουλα ZIP tricks (2024–2026)

### Συγκολλημένοι κεντρικοί κατάλογοι (multi-EOCD evasion)

Πρόσφατες phishing καμπάνιες διανέμουν ένα ενιαίο blob που στην πραγματικότητα είναι **two ZIP files concatenated**. Το κάθε ένα έχει το δικό του End of Central Directory (EOCD) + central directory. Διάφοροι extractors αναλύουν διαφορετικούς καταλόγους (7zip διαβάζει τον πρώτο, WinRAR τον τελευταίο), επιτρέποντας σε επιτιθέμενους να κρύψουν payloads που εμφανίζονται μόνο από κάποια εργαλεία. Αυτό επίσης παρακάμπτει τα βασικά mail gateway AV που επιθεωρούν μόνο τον πρώτο κατάλογο.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Αν εμφανιστούν περισσότερα από ένα EOCD ή υπάρχουν προειδοποιήσεις "data after payload", χωρίστε το blob και εξετάστε κάθε μέρος:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Η σύγχρονη "better zip bomb" κατασκευάζει έναν μικρό **kernel** (ιδιαίτερα συμπιεσμένο DEFLATE block) και τον επαναχρησιμοποιεί μέσω overlapping local headers. Κάθε central directory entry παραπέμπει στα ίδια συμπιεσμένα δεδομένα, επιτυγχάνοντας αναλογίες >28M:1 χωρίς nested archives. Βιβλιοθήκες που εμπιστεύονται τα central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP πριν από hardened builds) μπορούν να εξαναγκαστούν να δεσμεύσουν petabytes.

**Γρήγορη ανίχνευση (duplicate LFH offsets)**
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
- Εκτελέστε μια προσομοιωμένη εκτέλεση (dry-run): `zipdetails -v file.zip | grep -n "Rel Off"` και βεβαιωθείτε ότι τα offsets είναι αυστηρά αυξανόμενα και μοναδικά.
- Περιορίστε το αποδεκτό συνολικό μη συμπιεσμένο μέγεθος και τον αριθμό των εγγραφών πριν την εξαγωγή (`zipdetails -t` ή custom parser).
- Όταν πρέπει να εξάγετε, κάντε το μέσα σε cgroup/VM με όρια CPU+δίσκου (αποφύγετε καταρρεύσεις από μη ελεγχόμενη διόγκωση πόρων).

---

### Σύγχυση parser: Local-header vs central-directory

Πρόσφατη έρευνα σε differential-parser έδειξε ότι η ασάφεια στα ZIP εξακολουθεί να είναι εκμεταλλεύσιμη σε σύγχρονες toolchains. Η βασική ιδέα είναι απλή: κάποιο λογισμικό εμπιστεύεται το **Local File Header (LFH)** ενώ άλλο εμπιστεύεται το **Central Directory (CD)**, οπότε ένα αρχείο μπορεί να παρουσιάζει διαφορετικά filenames, paths, comments, offsets ή σύνολα εγγραφών σε διαφορετικά εργαλεία.

Πρακτικές επιθετικές χρήσεις:
- Κάντε ένα upload filter, AV pre-scan ή package validator να βλέπει ένα αβλαβές αρχείο στο CD ενώ ο extractor σέβεται διαφορετικό όνομα/μονοπάτι στο LFH.
- Εκμεταλλευτείτε διπλά ονόματα, εγγραφές που υπάρχουν μόνο σε μία δομή, ή ασαφές Unicode path metadata (για παράδειγμα, Info-ZIP Unicode Path Extra Field `0x7075`) ώστε διαφορετικοί parsers να ανακατασκευάζουν διαφορετικά δέντρα.
- Συνδυάστε αυτό με path traversal για να μετατρέψετε μια «αβλαβή» προβολή του αρχείου σε write-primitive κατά την εξαγωγή. Για την πλευρά της εξαγωγής, δείτε [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Διαλογή DFIR:
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
I don't have the content of src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md. Please paste the markdown you want translated (or specify the exact text to "complement it with") and I will translate it to Greek following the rules.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Απορρίψτε ή απομονώστε αρχεία με μη ταιριαστά ονόματα LFH/CD, διπλά ονόματα αρχείων, πολλαπλές εγγραφές EOCD, ή επιπλέον bytes μετά το τελικό EOCD.
- Θεωρήστε ύποπτα τα ZIP που χρησιμοποιούν ασυνήθιστα Unicode-path extra fields ή ασυνεπή comments εάν διαφορετικά εργαλεία διαφωνούν σχετικά με το extracted tree.
- Αν η ανάλυση έχει μεγαλύτερη σημασία από τη διατήρηση των αρχικών bytes, επανασυσκευάστε το αρχείο με έναν strict parser μετά την εξαγωγή σε sandbox και συγκρίνετε τη λίστα αρχείων που προκύπτει με τα αρχικά metadata.

Αυτό έχει σημασία πέρα από τα package ecosystems: η ίδια κλάση ασάφειας μπορεί να κρύψει payloads από mail gateways, static scanners, και custom ingestion pipelines που "peek" στα περιεχόμενα ZIP πριν κάποιος άλλος extractor χειριστεί το αρχείο.

---



## Αναφορές

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
