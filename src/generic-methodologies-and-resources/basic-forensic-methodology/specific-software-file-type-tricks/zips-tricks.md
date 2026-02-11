# Κόλπα για ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Εργαλεία γραμμής εντολών** για τη διαχείριση των **zip files** είναι απαραίτητα για τη διάγνωση, την επισκευή και το cracking zip αρχείων. Ακολουθούν κάποια βασικά εργαλεία:

- **`unzip`**: Αποκαλύπτει γιατί ένα zip αρχείο ενδέχεται να μην αποσυμπιεστεί.
- **`zipdetails -v`**: Προσφέρει λεπτομερή ανάλυση των πεδίων του μορφότυπου zip.
- **`zipinfo`**: Λίστα με τα περιεχόμενα ενός zip αρχείου χωρίς εξαγωγή.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επισκευάσουν κατεστραμμένα zip αρχεία.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Εργαλείο για brute-force cracking κωδικών zip, αποτελεσματικό για κωδικούς έως περίπου 7 χαρακτήρων.

Το [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει αναλυτικές πληροφορίες για τη δομή και τα πρότυπα των zip αρχείων.

Είναι σημαντικό να σημειωθεί ότι τα password-protected zip αρχεία **δεν κρυπτογραφούν τα ονόματα αρχείων ή τα μεγέθη αρχείων** στο εσωτερικό τους, μια ευπάθεια που δεν μοιράζονται τα RAR ή 7z αρχεία τα οποία κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, αρχεία zip κρυπτογραφημένα με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε επίθεση **known-plaintext** εάν υπάρχει μη κρυπτογραφημένο αντίγραφο ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να σπάσει τον κωδικό του zip, μια ευπάθεια που περιγράφεται στο [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται περαιτέρω σε [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Ωστόσο, αρχεία zip που προστατεύονται με **AES-256** είναι άνοσα σε αυτή την plaintext επίθεση, υπογραμμίζοντας τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

---

## Αντι-ανάλυσης κόλπα σε APKs που χρησιμοποιούν παραποιημένα ZIP headers

Τα σύγχρονα Android malware droppers χρησιμοποιούν κακοσχηματισμένα ZIP metadata για να σπάσουν static εργαλεία (jadx/apktool/unzip) ενώ διατηρούν το APK εγκαταστάσιμο στη συσκευή. Τα πιο συνηθισμένα κόλπα είναι:

- Ψεύτικη κρυπτογράφηση με το να τίθεται το ZIP General Purpose Bit Flag (GPBF) bit 0
- Κατάχρηση μεγάλων/προσαρμοσμένων Extra fields για να μπερδεύουν parsers
- Συγκρούσεις ονομάτων αρχείων/καταλόγων για να κρύβουν πραγματικά artifacts (π.χ., ένας κατάλογος με όνομα `classes.dex/` δίπλα στο πραγματικό `classes.dex`)

### 1) Ψευδής κρυπτογράφηση (GPBF bit 0 ενεργοποιημένο) χωρίς πραγματική κρυπτογραφία

Συμπτώματα:
- `jadx-gui` αποτυγχάνει με σφάλματα όπως:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` ζητάει κωδικό για βασικά αρχεία APK παρόλο που ένα έγκυρο APK δεν μπορεί να έχει κρυπτογραφημένα `classes*.dex`, `resources.arsc`, ή `AndroidManifest.xml`:

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
Δείτε το General Purpose Bit Flag για τους local και central headers. Μια χαρακτηριστική τιμή είναι το bit 0 ενεργοποιημένο (Encryption) ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετικό: Εάν ένα APK εγκαθίσταται και τρέχει στη συσκευή αλλά οι βασικές εγγραφές εμφανίζονται "κρυπτογραφημένες" στα εργαλεία, το GPBF έχει παραποιηθεί.

Διόρθωση: Καθαρίστε το bit 0 του GPBF τόσο στις Local File Headers (LFH) όσο και στις Central Directory (CD) εγγραφές. Ελάχιστος byte-patcher:

<details>
<summary>Ελάχιστο patcher εκκαθάρισης bit GPBF</summary>
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
Τώρα θα πρέπει να δείτε `General Purpose Flag  0000` στις βασικές εγγραφές και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Μεγάλα/προσαρμοσμένα Extra fields για να σπάνε parsers

Οι επιτιθέμενοι γεμίζουν υπερμεγέθη Extra fields και περίεργα IDs μέσα στα headers για να προκαλέσουν προβλήματα στους decompilers. Στη φύση μπορεί να δείτε προσαρμοσμένους markers (π.χ., συμβολοσειρές όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παραδείγματα που παρατηρήθηκαν: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που μεταφέρουν μεγάλα payloads.

DFIR ευρετικές:
- Ειδοποίηση όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε βασικές εγγραφές (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεώρησε τα άγνωστα Extra IDs σε αυτές τις εγγραφές ως ύποπτα.

Πρακτική αντιμετώπιση: η επαναδημιουργία του αρχείου (π.χ. επανασυμπίεση των εξαγόμενων αρχείων) αφαιρεί κακόβουλα Extra fields. Αν τα εργαλεία αρνούνται να εξαγάγουν λόγω ψευδοκρυπτογράφησης, πρώτα καθάρισε το GPBF bit 0 όπως παραπάνω, και μετά επανασυσκέυασε:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Σύγκρουση ονομάτων αρχείων/καταλόγων (απόκρυψη πραγματικών αντικειμένων)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Ορισμένα extractors και decompilers μπερδεύονται και μπορεί να επικαλύψουν ή να αποκρύψουν το πραγματικό αρχείο με μια εγγραφή καταλόγου. Αυτό έχει παρατηρηθεί με εγγραφές που συγκρούονται με βασικά ονόματα APK όπως `classes.dex`.

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
Προγραμματικός εντοπισμός (επίθημα):
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
- Σημάνετε APKs των οποίων οι τοπικές κεφαλίδες σημειώνουν κρυπτογράφηση (GPBF bit 0 = 1) αλλά εγκαθίστανται/εκτελούνται.
- Σημάνετε μεγάλα/άγνωστα Extra fields στις κύριες εγγραφές (αναζητήστε δείκτες όπως `JADXBLOCK`).
- Σημάνετε συγκρούσεις διαδρομών (`X` και `X/`) ειδικά για `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Other malicious ZIP tricks (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

Πρόσφατες εκστρατείες phishing στέλνουν ένα ενιαίο blob που στην πραγματικότητα είναι **δύο αρχεία ZIP συγκολλημένα**. Το καθένα έχει το δικό του End of Central Directory (EOCD) + central directory. Διάφοροι extractors αναλύουν διαφορετικούς καταλόγους (7zip διαβάζει τον πρώτο, WinRAR τον τελευταίο), επιτρέποντας σε επιτιθέμενους να κρύβουν payloads που εμφανίζονται μόνο από μερικά εργαλεία. Αυτό επίσης παρακάμπτει τα βασικά mail gateway AV που ελέγχουν μόνο τον πρώτο κατάλογο.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Εάν εμφανιστούν περισσότερα από ένα EOCD ή υπάρχουν προειδοποιήσεις "data after payload", διαχωρίστε το blob και εξετάστε κάθε μέρος:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Σύγχρονη "better zip bomb" κατασκευάζει έναν μικροσκοπικό **kernel** (υπερ-συμπιεσμένο DEFLATE block) και τον επαναχρησιμοποιεί μέσω overlapping local headers. Κάθε central directory entry δείχνει στα ίδια compressed data, επιτυγχάνοντας αναλογίες >28M:1 χωρίς nesting archives. Βιβλιοθήκες που εμπιστεύονται τα central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) μπορούν να αναγκαστούν να δεσμεύσουν petabytes.

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
**Χειρισμός**
- Εκτελέστε έναν dry-run έλεγχο: `zipdetails -v file.zip | grep -n "Rel Off"` και βεβαιωθείτε ότι οι offsets είναι αυστηρά αύξουσες και μοναδικές.
- Περιορίστε το αποδεκτό συνολικό μη συμπιεσμένο μέγεθος και τον αριθμό εγγραφών πριν από την εξαγωγή (`zipdetails -t` or custom parser).
- Όταν πρέπει να εξαγάγετε, κάντε το μέσα σε cgroup/VM με όρια CPU+δίσκου (αποφύγετε ανεξέλεγκτες καταρρεύσεις λόγω διόγκωσης).

---

## Αναφορές

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
