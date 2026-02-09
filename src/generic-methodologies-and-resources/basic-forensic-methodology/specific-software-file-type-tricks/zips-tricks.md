# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** για τη διαχείριση **zip files** είναι απαραίτητα για τη διάγνωση, την επισκευή και το cracking των zip αρχείων. Ακολουθούν μερικά βασικά εργαλεία:

- **`unzip`**: Δείχνει γιατί ένα zip αρχείο μπορεί να μην αποσυμπιεστεί.
- **`zipdetails -v`**: Προσφέρει λεπτομερή ανάλυση των πεδίων της μορφής αρχείου zip.
- **`zipinfo`**: Εμφανίζει τα περιεχόμενα ενός zip αρχείου χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν κατεστραμμένα zip αρχεία.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ένα εργαλείο για brute-force cracking κωδικών zip, αποτελεσματικό για κωδικούς μέχρι περίπου 7 χαρακτήρες.

Το [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει πλήρεις λεπτομέρειες για τη δομή και τα πρότυπα των zip αρχείων.

Είναι σημαντικό να σημειωθεί ότι τα password-protected zip files **do not encrypt filenames or file sizes** εσωτερικά, μια ευπάθεια που δεν υπάρχει σε RAR ή 7z αρχεία τα οποία κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, τα zip αρχεία κρυπτογραφημένα με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε ένα **plaintext attack** εάν υπάρχει αμη κρυπτογραφημένο αντίγραφο ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να σπάσει τον κωδικό του zip, μια ευπάθεια που περιγράφεται στο [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται περαιτέρω σε [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Ωστόσο, τα zip αρχεία προστατευμένα με **AES-256** κρυπτογράφηση είναι ανθεκτικά σε αυτή την plaintext attack, επισημαίνοντας τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Σύγχρονοι Android malware droppers χρησιμοποιούν malformed ZIP metadata για να “σπάσουν” static tools (jadx/apktool/unzip) ενώ το APK παραμένει εγκαταστάσιμο στη συσκευή. Τα πιο κοινά tricks είναι:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Συμπτώματα:
- `jadx-gui` αποτυγχάνει με σφάλματα όπως:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` ζητάει password για βασικά APK αρχεία παρόλο που ένα έγκυρο APK δεν μπορεί να έχει κρυπτογραφημένα `classes*.dex`, `resources.arsc`, ή `AndroidManifest.xml`:

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
Κοιτάξτε το General Purpose Bit Flag για τα local και central headers. Μια χαρακτηριστική τιμή είναι το bit 0 ενεργοποιημένο (Encryption) ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετική: Αν ένα APK εγκαθίσταται και τρέχει στη συσκευή αλλά οι βασικές εγγραφές εμφανίζονται "encrypted" στα tools, ο GPBF έχει παραποιηθεί.

Διορθώστε το εκκαθαρίζοντας το bit 0 του GPBF τόσο στις Local File Headers (LFH) όσο και στις εγγραφές του Central Directory (CD). Ελάχιστος byte-patcher:

<details>
<summary>Ελάχιστος GPBF bit-clear patcher</summary>
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
Πρέπει τώρα να δείτε `General Purpose Flag  0000` στις core εγγραφές και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Μεγάλα/εξατομικευμένα Extra fields που σπάνε τους parsers

Επιτιθέμενοι γεμίζουν υπερμεγέθη Extra fields και περίεργα IDs στα headers για να προκαλέσουν σφάλματα στους decompilers. Σε πραγματικά περιστατικά μπορεί να δείτε προσαρμοσμένους δείκτες (π.χ., strings όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παραδείγματα που παρατηρήθηκαν: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που φέρουν μεγάλα payloads.

DFIR heuristics:
- Ειδοποίηση όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεωρείτε τα άγνωστα Extra IDs σε αυτές τις εγγραφές ως ύποπτα.

Πρακτική αντιμετώπιση: η αναδημιουργία του αρχείου (π.χ. επανασυμπίεση των εξαγόμενων αρχείων) αφαιρεί τα κακόβουλα Extra fields. Εάν τα εργαλεία αρνούνται να εξάγουν λόγω ψεύτικης κρυπτογράφησης, πρώτα καθαρίστε το GPBF bit 0 όπως παραπάνω, και στη συνέχεια επανασυσκευάστε:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Συγκρούσεις ονομάτων αρχείων/καταλόγων (απόκρυψη πραγματικών αντικειμένων)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Ορισμένα extractors και decompilers μπερδεύονται και μπορεί να επικαλύψουν ή να κρύψουν το πραγματικό αρχείο με μια καταχώρηση καταλόγου. Αυτό έχει παρατηρηθεί με καταχωρήσεις που συγκρούονται με βασικά ονόματα APK όπως `classes.dex`.

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
Ιδέες ανίχνευσης για Blue-team:
- Επισημάνετε APKs των οποίων τα local headers δηλώνουν κρυπτογράφηση (GPBF bit 0 = 1) αλλά εγκαθίστανται/τρέχουν.
- Επισημάνετε μεγάλα/άγνωστα Extra fields σε core entries (ψάξτε για δείκτες όπως `JADXBLOCK`).
- Επισημάνετε path-collisions (`X` και `X/`) ειδικά για `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Άλλες κακόβουλες τεχνικές ZIP (2024–2025)

### Συνενωμένοι κεντρικοί κατάλογοι (multi-EOCD evasion)

Πρόσφατες phishing εκστρατείες διανέμουν ένα μόνο blob που στην πραγματικότητα είναι **δύο ZIP αρχεία συνενωμένα**. Το καθένα έχει το δικό του End of Central Directory (EOCD) + κεντρικό κατάλογο. Διάφοροι extractors αναλύουν διαφορετικούς καταλόγους (7zip διαβάζει τον πρώτο, WinRAR τον τελευταίο), επιτρέποντας στους επιτιθέμενους να κρύβουν payloads που εμφανίζονται μόνο από ορισμένα εργαλεία. Αυτό επίσης παρακάμπτει βασικά mail gateway AV που επιθεωρούν μόνο τον πρώτο κατάλογο.

**Εντολές Triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Εάν εμφανίζονται περισσότερα από ένα EOCD ή υπάρχουν προειδοποιήσεις "data after payload", διαχωρίστε το blob και ελέγξτε κάθε μέρος:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Οι σύγχρονες "better zip bomb" δημιουργούν ένα μικροσκοπικό **kernel** (ιδιαίτερα συμπιεσμένο DEFLATE block) και το επαναχρησιμοποιούν μέσω overlapping local headers. Κάθε central directory entry δείχνει στα ίδια compressed data, επιτυγχάνοντας αναλογίες >28M:1 χωρίς nesting archives. Βιβλιοθήκες που εμπιστεύονται τα central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) μπορούν να αναγκαστούν να δεσμεύσουν petabytes.

**Γρήγορος εντοπισμός (διπλά LFH offsets)**
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
- Πραγματοποιήστε μια δοκιμαστική διέλευση: `zipdetails -v file.zip | grep -n "Rel Off"` και βεβαιωθείτε ότι τα offsets αυξάνονται αυστηρά και είναι μοναδικά.
- Περιορίστε το αποδεκτό συνολικό μέγεθος χωρίς συμπίεση και τον αριθμό εγγραφών πριν την αποσυμπίεση (`zipdetails -t` or custom parser).
- Όταν πρέπει να αποσυμπιέσετε, κάντε το μέσα σε cgroup/VM με όρια CPU+disk (αποφύγετε καταρρεύσεις από ανεξέλεγκτη αύξηση πόρων).

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
