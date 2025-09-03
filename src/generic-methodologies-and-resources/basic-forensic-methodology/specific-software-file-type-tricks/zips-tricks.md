# Τρικ για ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Εργαλεία γραμμής εντολών** για τη διαχείριση αρχείων zip είναι απαραίτητα για τη διάγνωση, επιδιόρθωση και cracking αρχείων zip. Ακολουθούν μερικά βασικά utilities:

- **`unzip`**: Αποκαλύπτει γιατί ένα αρχείο zip μπορεί να μην αποσυμπιεστεί.
- **`zipdetails -v`**: Παρέχει λεπτομερή ανάλυση των πεδίων του format zip.
- **`zipinfo`**: Καταγράφει τα περιεχόμενα ενός αρχείου zip χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν corrupted αρχεία zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ένα εργαλείο για brute-force cracking κωδικών zip, αποτελεσματικό για κωδικούς περίπου έως 7 χαρακτήρες.

Η [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει πλήρεις λεπτομέρειες για τη δομή και τα standards των αρχείων zip.

Είναι κρίσιμο να σημειωθεί ότι τα password-protected αρχεία zip **δεν κρυπτογραφούν τα ονόματα αρχείων ή τα μεγέθη αρχείων** στο εσωτερικό, ένα πρόβλημα ασφάλειας που δεν ισχύει για RAR ή 7z που κρυπτογραφούν αυτή την πληροφορία. Επιπλέον, αρχεία zip κρυπτογραφημένα με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε μια plaintext attack εάν υπάρχει διαθέσιμη μια μη κρυπτογραφημένη αντίγραφα ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να σπάσει τον κωδικό του zip, μια ευπάθεια που αναλύεται στο [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται αναλυτικότερα σε [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Ωστόσο, αρχεία zip που προστατεύονται με AES-256 είναι ανθεκτικά σε αυτή την plaintext attack, υπογραμμίζοντας τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

---

## Τεχνικές αντι-ανάλυσης σε APKs χρησιμοποιώντας παραποιημένα headers ZIP

Σύγχρονοι Android malware droppers χρησιμοποιούν κακοσχηματισμένα metadata ZIP για να σπάσουν statικά εργαλεία (jadx/apktool/unzip) ενώ διατηρούν το APK εγκαταστάσιμο στη συσκευή. Τα πιο συνηθισμένα τρικ είναι:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) χωρίς πραγματικό crypto

Συμπτώματα:
- `jadx-gui` αποτυγχάνει με σφάλματα όπως:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` ζητάει κωδικό για βασικά αρχεία APK παρόλο που ένα έγκυρο APK δεν μπορεί να έχει encrypted `classes*.dex`, `resources.arsc`, ή `AndroidManifest.xml`:

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
Δες το General Purpose Bit Flag για τα local και central headers. Μια χαρακτηριστική τιμή είναι το bit 0 set (Encryption) ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετικό: Αν ένα APK εγκαθίσταται και τρέχει στη συσκευή αλλά βασικές εγγραφές εμφανίζονται "encrypted" στα εργαλεία, το GPBF έχει παραποιηθεί.

Διόρθωση: Καθαρίστε το GPBF bit 0 τόσο στις Local File Headers (LFH) όσο και στις Central Directory (CD) εγγραφές. Minimal byte-patcher:
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
Τώρα θα πρέπει να βλέπετε `General Purpose Flag  0000` στις βασικές εγγραφές και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Μεγάλα/προσαρμοσμένα Extra fields για να προκαλέσουν σφάλματα στους parsers

Οι επιτιθέμενοι γεμίζουν υπερμεγέθη Extra fields και ασυνήθιστα IDs στις κεφαλίδες για να μπερδέψουν τους decompilers. Στην πράξη μπορεί να δείτε προσαρμοσμένους δείκτες (π.χ., strings like `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παραδείγματα που παρατηρήθηκαν: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που μεταφέρουν μεγάλα payloads.

DFIR ευριστικές:
- Ειδοποίηση όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε βασικές καταχωρίσεις (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεώρησε τα άγνωστα Extra IDs σε αυτές τις καταχωρίσεις ως ύποπτα.

Πρακτική αντιμετώπιση: η επαν-δημιουργία του αρχείου (π.χ., επανασυμπίεση των εξαγόμενων αρχείων) αφαιρεί κακόβουλα Extra fields. Αν εργαλεία αρνηθούν να εξαγάγουν λόγω ψεύτικης κρυπτογράφησης, πρώτα καθάριστε το GPBF bit 0 όπως παραπάνω, και μετά επανασυσκευάστε:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Συγκρούσεις ονομάτων αρχείων/καταλόγων (απόκρυψη πραγματικών τεκμηρίων)

A ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Ορισμένα extractors και decompilers μπερδεύονται και μπορεί να επικαλύψουν ή να κρύψουν το πραγματικό αρχείο με μια καταχώρηση καταλόγου. Αυτό έχει παρατηρηθεί με καταχωρήσεις που συγκρούονται με βασικά ονόματα APK όπως `classes.dex`.

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
Προγραμματικός εντοπισμός post-fix:
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
- Επισήμανση των APKs των οποίων οι τοπικές κεφαλίδες δηλώνουν κρυπτογράφηση (GPBF bit 0 = 1) αλλά παρόλα αυτά εγκαθίστανται/εκτελούνται.
- Επισήμανση μεγάλων/άγνωστων Extra fields σε core entries (ψάξτε για δείκτες όπως `JADXBLOCK`).
- Επισήμανση συγκρούσεων διαδρομών (`X` and `X/`) ειδικά για `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Αναφορές

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
