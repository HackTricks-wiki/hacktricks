# Κόλπα για ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Εργαλεία γραμμής εντολών** για τη διαχείριση zip αρχείων είναι απαραίτητα για τη διάγνωση, την επιδιόρθωση και το cracking zip αρχείων. Εδώ είναι μερικά βασικά βοηθητικά προγράμματα:

- **`unzip`**: Αποκαλύπτει γιατί ένα zip αρχείο μπορεί να μην αποσυμπιεστεί.
- **`zipdetails -v`**: Παρέχει λεπτομερή ανάλυση των πεδίων του format των zip αρχείων.
- **`zipinfo`**: Λίστα με τα περιεχόμενα ενός zip αρχείου χωρίς να τα εξαγάγετε.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν κατεστραμμένα zip αρχεία.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Εργαλείο για brute-force cracking των κωδικών zip, αποτελεσματικό για κωδικούς μέχρι περίπου 7 χαρακτήρες.

Η [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει αναλυτικές λεπτομέρειες για τη δομή και τα πρότυπα των zip αρχείων.

Είναι κρίσιμο να σημειωθεί ότι τα password-protected zip αρχεία **δεν κρυπτογραφούν τα ονόματα αρχείων ή τα μεγέθη αρχείων** στο εσωτερικό τους, ένα πρόβλημα ασφάλειας που δεν υπάρχει σε RAR ή 7z αρχεία τα οποία κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, τα zip αρχεία κρυπτογραφημένα με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε μια **plaintext attack** αν υπάρχει διαθέσιμη μη κρυπτογραφημένη αντίγραφο ενός συμπιεσμένου αρχείου. Αυτή η επίθεση αξιοποιεί το γνωστό περιεχόμενο για να σπάσει τον κωδικό του zip, μια ευπάθεια που αναλύεται στο [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται περαιτέρω σε [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Ωστόσο, τα zip αρχεία προστατευμένα με **AES-256** κρυπτογράφηση είναι ανθεκτικά στην plaintext attack, υπογραμμίζοντας τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Οι σύγχρονοι Android malware droppers χρησιμοποιούν κακοσχηματισμένα ZIP metadata για να χαλάσουν στατικά εργαλεία (jadx/apktool/unzip) ενώ το APK παραμένει εγκαταστάσιμο στη συσκευή. Τα πιο κοινά κόλπα είναι:

- Fake encryption ρυθμίζοντας το ZIP General Purpose Bit Flag (GPBF) bit 0
- Κατάχρηση μεγάλων/προσαρμοσμένων Extra fields για σύγχυση των parser
- Συγκρούσεις ονομάτων αρχείων/φακέλων για να κρύψουν πραγματικά artifacts (π.χ., ένας φάκελος με όνομα `classes.dex/` δίπλα στο πραγματικό `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) χωρίς πραγματική κρυπτογράφηση

Συμπτώματα:
- `jadx-gui` αποτυγχάνει με σφάλματα όπως:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` ζητάει κωδικό για βασικά αρχεία του APK παρόλο που ένα έγκυρο APK δεν μπορεί να έχει κρυπτογραφημένα `classes*.dex`, `resources.arsc`, ή `AndroidManifest.xml`:

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
Κοιτάξτε το General Purpose Bit Flag για τα local and central headers. Μια ενδεικτική τιμή είναι το bit 0 set (Encryption) ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετική: Αν ένα APK εγκαθίσταται και τρέχει στη συσκευή αλλά οι βασικές εγγραφές εμφανίζονται ως "encrypted" στα εργαλεία, η GPBF έχει παραποιηθεί.

Διόρθωση: καθαρίστε το bit 0 της GPBF τόσο στις Local File Headers (LFH) όσο και στις εγγραφές του Central Directory (CD). Ελάχιστος byte-patcher:
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
Χρήση:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Τώρα θα πρέπει να δείτε `General Purpose Flag  0000` στις βασικές εγγραφές και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Μεγάλα/προσαρμοσμένα Extra fields για να σπάσουν parsers

Οι επιτιθέμενοι γεμίζουν υπερμεγέθη Extra fields και ασυνήθιστα IDs στις κεφαλίδες για να προκαλέσουν σφάλματα στους decompilers. Στο φυσικό περιβάλλον μπορεί να δείτε προσαρμοσμένους δείκτες (π.χ., συμβολοσειρές όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Examples observed: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR heuristics:
- Ειδοποίηση όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεωρήστε άγνωστα Extra IDs σε αυτές τις εγγραφές ως ύποπτα.

Practical mitigation: rebuilding the archive (e.g., re-zipping extracted files) strips malicious Extra fields. If tools refuse to extract due to fake encryption, first clear GPBF bit 0 as above, then repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Σύγκρουση ονομάτων αρχείου/καταλόγου (απόκρυψη πραγματικών στοιχείων)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Ορισμένοι extractors και decompilers μπερδεύονται και μπορεί να επικάλυψουν ή να αποκρύψουν το πραγματικό αρχείο με μια καταχώρηση καταλόγου. Αυτό έχει παρατηρηθεί με καταχωρήσεις που συγκρούονται με βασικά ονόματα APK όπως `classes.dex`.

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
Προγραμματική ανίχνευση post-fix:
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
Ιδέες ανίχνευσης για Blue-team:
- Επισημάνετε APKs των οποίων οι τοπικές κεφαλίδες δηλώνουν κρυπτογράφηση (GPBF bit 0 = 1) αλλά εγκαθίστανται/εκτελούνται.
- Επισημάνετε μεγάλα/άγνωστα Extra fields σε core entries (αναζητήστε markers όπως `JADXBLOCK`).
- Επισημάνετε path-collisions (`X` και `X/`) ειδικά για `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Αναφορές

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
