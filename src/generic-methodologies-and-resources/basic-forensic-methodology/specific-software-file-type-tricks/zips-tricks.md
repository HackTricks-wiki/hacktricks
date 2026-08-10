# Κόλπα ZIP

Τα **Command-line tools** για τη διαχείριση **zip files** είναι απαραίτητα για τη διάγνωση, την επιδιόρθωση και το cracking zip files. Ακολουθούν ορισμένα βασικά utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Αποκαλύπτει γιατί ένα zip file ενδέχεται να μην αποσυμπιέζεται.
- **`zipdetails -v`**: Παρέχει λεπτομερή ανάλυση των πεδίων της μορφής zip file.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Εμφανίζει τα περιεχόμενα ενός zip file χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν κατεστραμμένα zip files.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ένα tool για brute-force cracking κωδικών ZIP, αποτελεσματικό για κωδικούς έως περίπου 7 χαρακτήρες.

Η [προδιαγραφή της μορφής Zip file](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει ολοκληρωμένες λεπτομέρειες σχετικά με τη δομή και τα πρότυπα των zip files.<sup>[[4]](#references)</sup>

Είναι σημαντικό να σημειωθεί ότι τα παραδοσιακά password-protected ZIP files γενικά αφήνουν ορατά τα filenames και τα file sizes, σε αντίθεση με τα header-encryption modes που υποστηρίζονται από τα RAR και 7z. Επιπλέον, τα ZIP files που είναι encrypted με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε **plaintext attack** όταν υπάρχει διαθέσιμο ένα unencrypted αντίγραφο ενός compressed file.<sup>[[1]](#references)</sup> Αυτή η επίθεση αξιοποιεί το γνωστό περιεχόμενο για να κάνει crack το password του ZIP, όπως εξηγείται σε [αυτή την ακαδημαϊκή εργασία](https://math.ucr.edu/~mike/zipattacks.pdf) και παρουσιάζεται σε αυτό το [Hack This Site walk-through](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Ωστόσο, το ZipCrypto known-plaintext attack δεν εφαρμόζεται σε entries που προστατεύονται με **AES-256** encryption.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks σε APKs με χρήση manipulated ZIP headers

Τα σύγχρονα Android malware droppers χρησιμοποιούν malformed ZIP metadata για να προκαλούν δυσλειτουργίες σε static tools (jadx/apktool/unzip), διατηρώντας παράλληλα το APK εγκαταστάσιμο στη συσκευή. Τα πιο συνηθισμένα tricks είναι:<sup>[[2]](#references)</sup>

- Fake encryption με ορισμό του bit 0 του ZIP General Purpose Bit Flag (GPBF)
- Κατάχρηση μεγάλων/custom Extra fields για σύγχυση των parsers
- Συγκρούσεις μεταξύ ονομάτων file/directory για την απόκρυψη πραγματικών artifacts (π.χ. ένα directory με όνομα `classes.dex/` δίπλα στο πραγματικό `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) χωρίς πραγματικό crypto

Συμπτώματα:
- Το `jadx-gui` αποτυγχάνει με errors όπως:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- Το `unzip` ζητά password για βασικά APK files, παρόλο που ένα έγκυρο APK δεν μπορεί να έχει encrypted `classes*.dex`, `resources.arsc` ή `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Εντοπισμός με το zipdetails:
```bash
zipdetails -v sample.apk | less
```
Ελέγξτε το General Purpose Bit Flag στις local και central headers. Μια ενδεικτική τιμή είναι το bit 0 set (Encryption), ακόμη και για core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Ευρετική: Αν ένα APK εγκαθίσταται και εκτελείται στη συσκευή, αλλά οι βασικές καταχωρίσεις εμφανίζονται ως «κρυπτογραφημένες» στα εργαλεία, το GPBF έχει παραποιηθεί.

Διορθώστε το καθαρίζοντας το bit 0 του GPBF τόσο στις Local File Headers (LFH) όσο και στις καταχωρίσεις του Central Directory (CD). Ελάχιστο byte-patcher:

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
Θα πρέπει τώρα να βλέπετε `General Purpose Flag  0000` στις βασικές καταχωρίσεις και τα εργαλεία θα αναλύουν ξανά το APK.

### 2) Μεγάλα/προσαρμοσμένα Extra fields για την αποδιοργάνωση parsers

Οι attackers τοποθετούν υπερμεγέθη Extra fields και ασυνήθιστα IDs στις κεφαλίδες, ώστε να προκαλέσουν προβλήματα στους decompilers. Στο wild μπορεί να δείτε προσαρμοσμένους markers (π.χ. strings όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Έλεγχος:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Παραδείγματα που παρατηρήθηκαν: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που μεταφέρουν μεγάλα payloads.<sup>[[2]](#references)</sup>

Ευρετικές μέθοδοι DFIR:
- Δημιουργήστε alert όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε βασικές εγγραφές (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Θεωρήστε ύποπτα τα άγνωστα Extra IDs σε αυτές τις εγγραφές.

Πρακτικός μετριασμός: η ανακατασκευή του archive (π.χ. με re-zipping των extracted files) αφαιρεί τα κακόβουλα Extra fields. Αν τα εργαλεία αρνούνται να κάνουν extract λόγω fake encryption, πρώτα καθαρίστε το GPBF bit 0 όπως παραπάνω και, στη συνέχεια, κάντε repackage:
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
Προγραμματικός εντοπισμός μετά την επιδιόρθωση:
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
- Επισήμανση APKs των οποίων τα local headers δηλώνουν encryption (GPBF bit 0 = 1), αλλά εγκαθίστανται/εκτελούνται.
- Επισήμανση μεγάλων/άγνωστων Extra fields σε core entries (αναζητήστε markers όπως `JADXBLOCK`).
- Επισήμανση path-collisions (`X` και `X/`) ειδικά για τα `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Άλλα κακόβουλα ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Σε μια phishing campaign του 2024, οι attackers διένειμαν ένα ενιαίο blob που στην πραγματικότητα ήταν **δύο ZIP files concatenated**. Καθένα είχε το δικό του End of Central Directory (EOCD) record και central directory. Διαφορετικοί extractors έκαναν parse διαφορετικά directories (το 7-Zip διάβαζε το πρώτο, ενώ το WinRAR το τελευταίο), επιτρέποντας στους attackers να κρύβουν payloads που εμφανίζονταν μόνο σε ορισμένα tools· scanners που επιθεωρούν μόνο ένα directory μπορεί να παραλείψουν το άλλο archive.<sup>[[5]](#references)[[6]](#references)</sup>

**Εντολές triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Αν εμφανίζονται περισσότερα από ένα EOCD ή υπάρχουν προειδοποιήσεις "data after payload", διαχωρίστε το blob και εξετάστε κάθε τμήμα:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Τα Quoted-overlap ZIP bombs δημιουργούν έναν μικροσκοπικό **kernel** (ένα μπλοκ DEFLATE με υψηλή συμπίεση) και τον επαναχρησιμοποιούν σε overlapping entries. Οι παραλλαγές full-overlap δείχνουν πολλές central-directory entries σε ένα local header, ενώ οι παραλλαγές quoted-overlap ενσωματώνουν local headers μέσα σε DEFLATE streams· η δημοσιευμένη κατασκευή επιτυγχάνει αναλογία μεγαλύτερη από 28M:1 χωρίς nested archives.<sup>[[7]](#references)</sup>

**Γρήγορη ανίχνευση (διπλότυπα LFH offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
**Handling**
- Εκτέλεσε έναν dry-run έλεγχο: `zipdetails -v file.zip | grep -n "Local Header Offset"` και σύγκρινε τα αναφερόμενα offsets των local headers και τα ranges των compressed δεδομένων· τα διπλότυπα offsets υποδεικνύουν variants με πλήρη επικάλυψη.<sup>[[7]](#references)[[8]](#references)</sup>
- Θέσε ανώτατο όριο στο συνολικό uncompressed μέγεθος και στον αριθμό των entries πριν από την extraction, χρησιμοποιώντας parser· το `zipinfo -t file.zip` αναφέρει τα totals, αλλά δεν επιβάλλει όριο ασφαλείας.<sup>[[8]](#references)</sup>
- Όταν πρέπει να κάνεις extraction, εκτέλεσέ το μέσα σε cgroup/VM με όρια CPU και disk, ώστε να αποφύγεις crashes από uncontrolled inflation.<sup>[[8]](#references)</sup>

---

### Σύγχυση μεταξύ local-header και central-directory parser

Πρόσφατη έρευνα differential-parser έδειξε ότι η ασάφεια του ZIP εξακολουθεί να είναι exploitable σε σύγχρονα toolchains. Η βασική ιδέα είναι απλή: κάποιο software εμπιστεύεται το **Local File Header (LFH)**, ενώ άλλο εμπιστεύεται το **Central Directory (CD)**, επομένως ένα archive μπορεί να εμφανίζει διαφορετικά filenames, paths, comments, offsets ή entry sets σε διαφορετικά tools.<sup>[[9]](#references)</sup>

Πρακτικές offensive χρήσεις:
- Κάνε ένα upload filter, AV pre-scan ή package validator να δει ένα benign file στο CD, ενώ ο extractor να ακολουθήσει διαφορετικό LFH name/path.
- Εκμεταλλεύσου duplicate names, entries που υπάρχουν μόνο σε μία structure ή ambiguous Unicode path metadata (για παράδειγμα, το Info-ZIP Unicode Path Extra Field `0x7075`), ώστε διαφορετικοί parsers να ανακατασκευάσουν διαφορετικά trees.
- Συνδύασέ το με path traversal για να μετατρέψεις μια "harmless" archive view σε write-primitive κατά την extraction. Για την πλευρά της extraction, δες το [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
- Για ingestion ευαίσθητο σε θέματα ασφάλειας, απορρίπτετε ή απομονώνετε αρχεία με ασυμφωνίες στα ονόματα LFH/CD, διπλότυπα filenames, πολλαπλές εγγραφές EOCD ή bytes μετά το τελικό EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Αντιμετωπίζετε ως ύποπτα τα ZIP που χρησιμοποιούν ασυνήθιστα Unicode-path extra fields ή ασυνεπή comments, εάν διαφορετικά εργαλεία διαφωνούν ως προς το extracted tree.<sup>[[4]](#references)[[9]](#references)</sup>
- Εάν η ανάλυση είναι σημαντικότερη από τη διατήρηση των αρχικών bytes, δημιουργήστε ξανά το archive με strict parser μετά την extraction σε sandbox και συγκρίνετε τη resulting file list με τα αρχικά metadata.

Αυτό έχει σημασία πέρα από τα package ecosystems: η ίδια κατηγορία ασάφειας μπορεί να αποκρύψει payloads από mail gateways, static scanners και custom ingestion pipelines που κάνουν "peek" στα περιεχόμενα ZIP πριν ένας διαφορετικός extractor διαχειριστεί το archive.<sup>[[9]](#references)</sup>

---



## References

- [1] [Οδηγός Πεδίου CTF Forensics (Mike's Blog, κατηγορία CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Μέρος 1 – Ένα multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Προδιαγραφή Μορφής Αρχείων ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Ευέλικτη Δομή των Zip Archives που Αξιοποιείται για την Απόκρυψη Malware χωρίς Εντοπισμό (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers θάβουν malware σε νέα επίθεση με ZIP files — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Ένα καλύτερο zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Κατανόηση των Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Το ZIP μου δεν είναι το δικό σου ZIP: Εντοπισμός και Exploiting Semantic Gaps μεταξύ ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Πρόληψη ZIP parser confusion attacks σε Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks με Μειωμένο Γνωστό Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Ρεαλιστική Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
