# Κόλπα ZIPs

{{#include ../../../banners/hacktricks-training.md}}

Τα **Command-line tools** για τη διαχείριση **zip files** είναι απαραίτητα για τη διάγνωση, την επιδιόρθωση και το cracking zip files. Ακολουθούν ορισμένα βασικά utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Αποκαλύπτει γιατί ένα zip file ενδέχεται να μην αποσυμπιέζεται.
- **`zipdetails -v`**: Προσφέρει λεπτομερή ανάλυση των πεδίων του zip file format.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Εμφανίζει τα περιεχόμενα ενός zip file χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν κατεστραμμένα zip files.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Tool για brute-force cracking zip passwords, αποτελεσματικό για passwords έως περίπου 7 χαρακτήρες.

Η [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει ολοκληρωμένες λεπτομέρειες σχετικά με τη δομή και τα standards των zip files.<sup>[[4]](#references)</sup>

Είναι σημαντικό να σημειωθεί ότι τα password-protected zip files **δεν κρυπτογραφούν τα filenames ή τα file sizes** που περιέχουν, ένα security flaw που δεν υπάρχει στα RAR ή 7z files, τα οποία κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, τα zip files που είναι encrypted με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε **plaintext attack** εάν υπάρχει διαθέσιμο ένα unencrypted αντίγραφο ενός compressed file.<sup>[[1]](#references)</sup> Αυτό το attack αξιοποιεί το γνωστό περιεχόμενο για να κάνει crack το password του zip, μια ευπάθεια που περιγράφεται λεπτομερώς στο [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται περαιτέρω σε [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Ωστόσο, τα zip files που προστατεύονται με **AES-256** encryption είναι immune σε αυτό το plaintext attack, αναδεικνύοντας τη σημασία της επιλογής secure encryption methods για sensitive data.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks σε APKs με χρήση manipulated ZIP headers

Τα σύγχρονα Android malware droppers χρησιμοποιούν malformed ZIP metadata για να προκαλούν προβλήματα σε static tools (jadx/apktool/unzip), διατηρώντας παράλληλα το APK installable στη συσκευή. Τα πιο συνηθισμένα tricks είναι τα εξής:<sup>[[2]](#references)</sup>

- Fake encryption με ενεργοποίηση του bit 0 του ZIP General Purpose Bit Flag (GPBF)
- Abusing μεγάλων/custom Extra fields για τη σύγχυση των parsers
- File/directory name collisions για την απόκρυψη πραγματικών artifacts (π.χ. ένα directory με όνομα `classes.dex/` δίπλα στο πραγματικό `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) χωρίς πραγματικό crypto

Συμπτώματα:
- Το `jadx-gui` αποτυγχάνει με errors όπως:

``` 
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- Το `unzip` ζητά password για core APK files, παρότι ένα valid APK δεν μπορεί να έχει encrypted `classes*.dex`, `resources.arsc` ή `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection με zipdetails:
```bash
zipdetails -v sample.apk | less
```
Ελέγξτε το General Purpose Bit Flag για τις local και central headers. Ενδεικτική τιμή είναι το bit 0 ενεργοποιημένο (Encryption), ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετική: Αν ένα APK εγκαθίσταται και εκτελείται στη συσκευή, αλλά οι βασικές καταχωρίσεις εμφανίζονται ως "encrypted" στα εργαλεία, έχει παραποιηθεί το GPBF.

Διόρθωση με εκκαθάριση του bit 0 του GPBF τόσο στις Local File Headers (LFH) όσο και στις καταχωρίσεις του Central Directory (CD). Ελάχιστο byte-patcher:

<details>
<summary>Ελάχιστο GPBF bit-clear patcher</summary>
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
Θα πρέπει τώρα να βλέπετε `General Purpose Flag  0000` στις βασικές εγγραφές και τα εργαλεία θα αναλύσουν ξανά το APK.

### 2) Μεγάλα/προσαρμοσμένα πεδία Extra για την αποτυχία των parsers

Οι επιτιθέμενοι τοποθετούν υπερμεγέθη πεδία Extra και ασυνήθιστα IDs στις επικεφαλίδες, ώστε να προκαλέσουν προβλήματα στους decompilers. Στην πράξη, μπορεί να δείτε προσαρμοσμένους markers (π.χ. strings όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παρατηρημένα παραδείγματα: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που μεταφέρουν μεγάλα payloads.

DFIR heuristics:
- Δημιουργήστε alert όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Αντιμετωπίστε τα άγνωστα Extra IDs σε αυτά τα entries ως ύποπτα.

Πρακτικό mitigation: η ανακατασκευή του archive (π.χ. re-zipping των extracted files) αφαιρεί τα malicious Extra fields. Αν τα tools αρνούνται να κάνουν extract λόγω fake encryption, πρώτα καθαρίστε το GPBF bit 0 όπως παραπάνω και, στη συνέχεια, κάντε repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Συγκρούσεις ονομάτων αρχείων/καταλόγων (απόκρυψη πραγματικών artifacts)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Ορισμένοι extractors και decompilers μπερδεύονται και ενδέχεται να επικαλύψουν ή να αποκρύψουν το πραγματικό αρχείο με μια καταχώριση καταλόγου. Αυτό έχει παρατηρηθεί σε καταχωρίσεις που συγκρούονται με βασικά ονόματα APK, όπως το `classes.dex`.

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
Προγραμματικός εντοπισμός μετά τη διόρθωση:
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
Ιδέες ανίχνευσης από Blue-team:
- Εντοπίστε APKs των οποίων τα local headers δηλώνουν encryption (GPBF bit 0 = 1), αλλά τα APKs εγκαθίστανται/εκτελούνται.
- Εντοπίστε μεγάλα/άγνωστα Extra fields σε core entries (αναζητήστε markers όπως `JADXBLOCK`).
- Εντοπίστε path-collisions (`X` και `X/`) ειδικά για τα `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Άλλα malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Πρόσφατες phishing campaigns αποστέλλουν ένα ενιαίο blob που στην πραγματικότητα είναι **δύο ZIP files ενωμένα**. Κάθε αρχείο έχει το δικό του End of Central Directory (EOCD) και central directory. Διαφορετικοί extractors κάνουν parse διαφορετικά directories (το 7zip διαβάζει το πρώτο, το WinRAR το τελευταίο), επιτρέποντας στους attackers να κρύβουν payloads που εμφανίζονται μόνο σε ορισμένα tools. Αυτό παρακάμπτει επίσης το basic mail gateway AV που επιθεωρεί μόνο το πρώτο directory.<sup>[[5]](#references)[[6]](#references)</sup>

**Εντολές triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Αν εμφανίζονται περισσότερα από ένα EOCD ή υπάρχουν προειδοποιήσεις "data after payload", διαχωρίστε το blob και εξετάστε κάθε τμήμα:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (μη αναδρομικές)

Οι σύγχρονες κατασκευές "better zip bomb" δημιουργούν έναν μικροσκοπικό **kernel** (μπλοκ DEFLATE με υψηλή συμπίεση) και τον επαναχρησιμοποιούν μέσω επικαλυπτόμενων local headers. Κάθε καταχώριση του central directory δείχνει στα ίδια συμπιεσμένα δεδομένα, επιτυγχάνοντας αναλογίες >28M:1 χωρίς ένθεση archives. Βιβλιοθήκες που εμπιστεύονται τα μεγέθη του central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP πριν από τα hardened builds) μπορούν να εξαναγκαστούν να δεσμεύσουν petabytes.<sup>[[7]](#references)[[8]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
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
- Εκτέλεσε μια dry-run περιήγηση: `zipdetails -v file.zip | grep -n "Rel Off"` και βεβαιώσου ότι τα offsets αυξάνονται αυστηρά και είναι μοναδικά.
- Θέσε ανώτατο όριο στο συνολικό αποσυμπιεσμένο μέγεθος και στον αριθμό των entries πριν από την extraction (`zipdetails -t` ή custom parser).
- Όταν πρέπει να κάνεις extraction, εκτέλεσέ το μέσα σε cgroup/VM με όρια CPU και disk (για αποφυγή crashes από ανεξέλεγκτο inflation).

---

### Σύγχυση parser μεταξύ local header και central directory

Πρόσφατη έρευνα σε differential-parser έδειξε ότι η ασάφεια στα ZIP εξακολουθεί να είναι exploitable σε σύγχρονα toolchains. Η βασική ιδέα είναι απλή: κάποιο software εμπιστεύεται το **Local File Header (LFH)**, ενώ άλλο το **Central Directory (CD)**, οπότε ένα archive μπορεί να παρουσιάζει διαφορετικά filenames, paths, comments, offsets ή entry sets σε διαφορετικά tools.<sup>[[9]](#references)</sup>

Πρακτικές offensive χρήσεις:
- Κάνε ένα upload filter, AV pre-scan ή package validator να δει ένα benign file στο CD, ενώ ο extractor χρησιμοποιεί διαφορετικό LFH name/path.
- Εκμεταλλεύσου duplicate names, entries που υπάρχουν μόνο στη μία δομή ή ambiguous Unicode path metadata (για παράδειγμα, το Info-ZIP Unicode Path Extra Field `0x7075`), ώστε διαφορετικοί parsers να ανακατασκευάζουν διαφορετικά trees.
- Συνδύασέ το με path traversal, ώστε μια "harmless" archive view να μετατραπεί σε write-primitive κατά την extraction. Για την πλευρά της extraction, δες το [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Συμπλήρωσέ το με:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Ευρετικές:
- Απορρίψτε ή απομονώστε αρχεία που περιέχουν ασυμφωνίες μεταξύ των ονομάτων LFH/CD, διπλότυπα filenames, πολλαπλές εγγραφές EOCD ή bytes μετά το τελικό EOCD.<sup>[[10]](#references)</sup>
- Αντιμετωπίστε τα ZIPs που χρησιμοποιούν ασυνήθιστα Unicode-path extra fields ή ασυνεπή comments ως ύποπτα, εάν διαφορετικά εργαλεία διαφωνούν σχετικά με το extracted tree.<sup>[[9]](#references)</sup>
- Εάν η ανάλυση είναι σημαντικότερη από τη διατήρηση των αρχικών bytes, δημιουργήστε ξανά το archive με strict parser μετά την extraction σε sandbox και συγκρίνετε την resulting file list με τα αρχικά metadata.

Αυτό έχει σημασία πέρα από τα package ecosystems: η ίδια ambiguity class μπορεί να κρύψει payloads από mail gateways, static scanners και custom ingestion pipelines που κάνουν "peek" στα περιεχόμενα ZIP πριν ένας διαφορετικός extractor χειριστεί το archive.

---



## Αναφορές

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
