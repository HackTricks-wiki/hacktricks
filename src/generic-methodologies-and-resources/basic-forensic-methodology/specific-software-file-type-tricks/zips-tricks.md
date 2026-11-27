# Κόλπα με ZIP

{{#include ../../../banners/hacktricks-training.md}}

Τα **εργαλεία γραμμής εντολών** για τη διαχείριση **αρχείων zip** είναι απαραίτητα για τη διάγνωση, την επιδιόρθωση και το cracking αρχείων zip. Ακολουθούν μερικά βασικά εργαλεία:<sup>[[1]](#references)</sup>

- **`unzip`**: Αποκαλύπτει γιατί ένα αρχείο zip μπορεί να μην αποσυμπιέζεται.
- **`zipdetails -v`**: Παρέχει λεπτομερή ανάλυση των πεδίων της μορφής αρχείων zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Εμφανίζει τα περιεχόμενα ενός αρχείου zip χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Επιχειρούν να επιδιορθώσουν κατεστραμμένα αρχεία zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Εργαλείο για επιθέσεις λεξικού και brute-force σε κωδικούς ZIP· η εφικτότητα εξαρτάται από τον χώρο αναζήτησης κωδικών.<sup>[[15]](#references)</sup>

Η [προδιαγραφή μορφής αρχείων Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει ολοκληρωμένες πληροφορίες για τη δομή και τα πρότυπα των αρχείων zip.<sup>[[4]](#references)</sup>

Τα παραδοσιακά αρχεία ZIP που προστατεύονται με κωδικό αφήνουν γενικά ορατά τα ονόματα αρχείων και τα μεγέθη τους, σε αντίθεση με τις λειτουργίες κρυπτογράφησης κεφαλίδων που υποστηρίζουν τα RAR και 7z. Μια επίθεση known-plaintext στο ZipCrypto ανακτά **εσωτερικά κλειδιά κρυπτογράφησης**, όχι απαραίτητα τον αρχικό κωδικό· τα κλειδιά αρκούν για την αποκρυπτογράφηση εγγραφών που έχουν κρυπτογραφηθεί με τον ίδιο κωδικό.<sup>[[13]](#references)</sup> Η επίθεση απαιτεί γνωστά byte της ροής **πριν από την κρυπτογράφηση**: για ένα αποθηκευμένο μέλος, αυτά είναι τα αρχικά byte του αρχείου, ενώ για ένα μέλος DEFLATE είναι τα συμπιεσμένα byte, κάτι που μπορεί να απαιτεί την αναδημιουργία της ακριβούς εξόδου συμπίεσης.<sup>[[13]](#references)[[14]](#references)</sup> Δείτε το [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) για μια πρακτική διαδικασία. Για το υπόβαθρο της κρυπτανάλυσης, δείτε [την εργασία](https://math.ucr.edu/~mike/zipattacks.pdf) και [τον οδηγό βήμα προς βήμα](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Αυτή η επίθεση ZipCrypto δεν εφαρμόζεται σε εγγραφές ZIP που έχουν κρυπτογραφηθεί με AES.<sup>[[13]](#references)</sup>

---

## Τεχνικές anti-reversing σε APK με αλλοιωμένες κεφαλίδες ZIP

Τα σύγχρονα malware droppers Android χρησιμοποιούν κακοσχηματισμένα μεταδεδομένα ZIP για να εμποδίσουν τα στατικά εργαλεία (jadx/apktool/unzip), διατηρώντας παράλληλα τη δυνατότητα εγκατάστασης του APK στη συσκευή. Οι πιο συνηθισμένες τεχνικές είναι οι εξής:<sup>[[2]](#references)</sup>

- Εικονική κρυπτογράφηση με ενεργοποίηση του bit 0 της σημαίας γενικής χρήσης ZIP (GPBF)
- Κατάχρηση μεγάλων ή προσαρμοσμένων πεδίων Extra για να μπερδέψουν τους parsers
- Συγκρούσεις ονομάτων αρχείων/καταλόγων για την απόκρυψη πραγματικών artefacts (π.χ. ένας κατάλογος με όνομα `classes.dex/` δίπλα στο πραγματικό `classes.dex`)

### 1) Εικονική κρυπτογράφηση (ενεργοποιημένο το bit 0 του GPBF) χωρίς πραγματική κρυπτογράφηση

Συμπτώματα:
- Το `jadx-gui` αποτυγχάνει με σφάλματα όπως τα εξής:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- Το `unzip` ζητά κωδικό πρόσβασης για βασικά αρχεία APK, παρόλο που ένα έγκυρο APK δεν μπορεί να έχει κρυπτογραφημένα τα `classes*.dex`, `resources.arsc` ή `AndroidManifest.xml`:
  
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

Εξετάστε τη σημαία bit γενικού σκοπού (General Purpose Bit Flag) στις τοπικές και κεντρικές κεφαλίδες. Ενδεικτική τιμή είναι το bit 0 ενεργοποιημένο (κρυπτογράφηση), ακόμη και για βασικές εγγραφές:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Ευρετικός κανόνας: Αν ένα APK εγκαθίσταται και εκτελείται στη συσκευή, αλλά τα βασικά entries εμφανίζονται ως «κρυπτογραφημένα» στα εργαλεία, έχει παραποιηθεί το GPBF.

Για να το διορθώσετε, καθαρίστε το bit 0 του GPBF τόσο στις Τοπικές Κεφαλίδες Αρχείων (LFH) όσο και στις εγγραφές του Κεντρικού Καταλόγου (CD). Ελάχιστο εργαλείο τροποποίησης bytes:

<details>
<summary>Ελάχιστο εργαλείο εκκαθάρισης bit GPBF</summary>

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

Μόνο το bit 0 πρέπει να αλλάξει: για παράδειγμα, το `0A09` γίνεται `0A08`, όχι `0000`. Αυτός ο minimal patcher σαρώνει ακατέργαστα bytes για signatures κεφαλίδων, επομένως bytes μέσα στα δεδομένα αρχείου που μοιάζουν με signatures μπορεί να προκαλέσουν false matches· δουλέψτε σε αντίγραφο και επιβεβαιώστε τη λίστα εγγραφών και τις κεφαλίδες που προκύπτουν πριν χρησιμοποιήσετε το αποτέλεσμα.<sup>[[4]](#references)</sup>

### 2) Μεγάλα/προσαρμοσμένα πεδία Extra για να μπερδέψετε parsers

Οι επιτιθέμενοι γεμίζουν τις κεφαλίδες με υπερμεγέθη πεδία Extra και ασυνήθιστα IDs για να προκαλέσουν προβλήματα στους decompilers. Στην πράξη, μπορεί να συναντήσετε προσαρμοσμένους δείκτες (π.χ. συμβολοσειρές όπως `JADXBLOCK`) ενσωματωμένους εκεί.

Επιθεώρηση:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Παραδείγματα που έχουν παρατηρηθεί: άγνωστα IDs όπως `0xCAFE` ("Java Executable") ή `0x414A` ("JA:") που περιέχουν μεγάλα payloads.<sup>[[2]](#references)</sup>

Ευρετικές DFIR:
- Ειδοποίηση όταν τα Extra fields είναι ασυνήθιστα μεγάλα σε βασικές εγγραφές (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Αντιμετώπιση άγνωστων Extra IDs σε αυτές τις εγγραφές ως ύποπτων.

Πρακτικό μέτρο μετριασμού: η ανακατασκευή του archive (π.χ. επανασυμπίεση των εξαγόμενων αρχείων) αφαιρεί τα κακόβουλα Extra fields. Αν τα εργαλεία αρνούνται να κάνουν εξαγωγή λόγω πλαστής κρυπτογράφησης, πρώτα μηδενίστε το GPBF bit 0 όπως παραπάνω και έπειτα δημιουργήστε ξανά το archive:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Συγκρούσεις ονομάτων αρχείων/καταλόγων (απόκρυψη πραγματικών artifacts)

Ένα ZIP μπορεί να περιέχει τόσο ένα αρχείο `X` όσο και έναν κατάλογο `X/`. Ορισμένα εργαλεία εξαγωγής και decompiler μπερδεύονται και ενδέχεται να επικαλύψουν ή να αποκρύψουν το πραγματικό αρχείο με μια εγγραφή καταλόγου. Αυτό έχει παρατηρηθεί σε εγγραφές που συγκρούονται με βασικά ονόματα APK, όπως το `classes.dex`.

Διαλογή και ασφαλής εξαγωγή:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Προγραμματική ανίχνευση μετά τη διόρθωση:

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

Ιδέες εντοπισμού για blue team:
- Εντοπίστε APK των οποίων οι local headers δηλώνουν κρυπτογράφηση (GPBF bit 0 = 1), αλλά τα οποία εγκαθίστανται/εκτελούνται.
- Εντοπίστε μεγάλα/άγνωστα Extra fields σε βασικές εγγραφές (αναζητήστε markers όπως `JADXBLOCK`).
- Εντοπίστε συγκρούσεις διαδρομών (`X` και `X/`) ειδικά για τα `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Άλλα κακόβουλα κόλπα ZIP (2024–2026)

### Συνενωμένοι central directories (παράκαμψη πολλαπλών EOCD)

Σε μια phishing καμπάνια του 2024, οι attackers διένειμαν ένα ενιαίο blob που στην πραγματικότητα αποτελούνταν από **δύο συνενωμένα αρχεία ZIP**. Καθένα είχε τη δική του εγγραφή End of Central Directory (EOCD) και το δικό του central directory. Διαφορετικά προγράμματα αποσυμπίεσης διάβαζαν διαφορετικούς καταλόγους (το 7-Zip διάβαζε τον πρώτο, ενώ το WinRAR διάβαζε τον τελευταίο), επιτρέποντας στους attackers να κρύβουν payloads που εμφάνιζαν μόνο ορισμένα εργαλεία· οι scanners που ελέγχουν μόνο έναν κατάλογο μπορεί να μην εντοπίσουν το άλλο archive.<sup>[[5]](#references)[[6]](#references)</sup>

**Εντολές αρχικής διαλογής**

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

### Quoted-overlap / overlapping-entry bombs (μη αναδρομικές)

Τα Quoted-overlap ZIP bombs δημιουργούν έναν μικροσκοπικό **kernel** (ένα εξαιρετικά συμπιεσμένο μπλοκ DEFLATE) και τον επαναχρησιμοποιούν σε επικαλυπτόμενες εγγραφές. Οι παραλλαγές Full-overlap δείχνουν πολλές εγγραφές του κεντρικού καταλόγου σε μία κεφαλίδα τοπικού αρχείου, ενώ οι παραλλαγές quoted-overlap περικλείουν κεφαλίδες τοπικών αρχείων μέσα σε ροές DEFLATE· η δημοσιευμένη κατασκευή επιτυγχάνει λόγο συμπίεσης πάνω από 28M:1 χωρίς ένθετα αρχεία.<sup>[[7]](#references)</sup>

**Γρήγορος εντοπισμός (διπλότυπα LFH offsets)**

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

**Χειρισμός**
- Εκτελέστε μια δοκιμαστική αναλυτική περιήγηση: `zipdetails -v file.zip | grep -n "Local Header Offset"` και συγκρίνετε τις αναφερόμενες μετατοπίσεις local-header και τα εύρη συμπιεσμένων δεδομένων· οι διπλότυπες μετατοπίσεις υποδεικνύουν παραλλαγές πλήρους επικάλυψης.<sup>[[7]](#references)[[8]](#references)</sup>
- Ορίστε, μέσω parser, ανώτατα όρια στο συνολικό αποσυμπιεσμένο μέγεθος και στον αριθμό καταχωρίσεων πριν από την εξαγωγή· το `zipinfo -t file.zip` αναφέρει τα σύνολα, αλλά δεν επιβάλλει όριο ασφαλείας.<sup>[[8]](#references)</sup>
- Όταν πρέπει να γίνει εξαγωγή, εκτελέστε την μέσα σε cgroup/VM με όρια CPU και δίσκου (αποφύγετε ανεξέλεγκτα crashes κατά την αποσυμπίεση).<sup>[[8]](#references)</sup>

---

### Σύγχυση parser μεταξύ local-header και central-directory

Πρόσφατη έρευνα σε differential-parser έδειξε ότι η ασάφεια των ZIP εξακολουθεί να είναι εκμεταλλεύσιμη στις σύγχρονες toolchains. Η βασική ιδέα είναι απλή: κάποιο λογισμικό εμπιστεύεται το **Local File Header (LFH)**, ενώ άλλο το **Central Directory (CD)**, επομένως ένα αρχείο μπορεί να εμφανίζει διαφορετικά ονόματα αρχείων, διαδρομές, σχόλια, μετατοπίσεις ή σύνολα καταχωρίσεων σε διαφορετικά εργαλεία.<sup>[[9]](#references)</sup>

Πρακτικές επιθετικές χρήσεις:
- Κάντε ένα φίλτρο μεταφορτώσεων, έναν προέλεγχο AV ή έναν validator πακέτων να βλέπει ένα αβλαβές αρχείο στο CD, ενώ ο extractor χρησιμοποιεί διαφορετικό όνομα/διαδρομή LFH.
- Εκμεταλλευτείτε διπλότυπα ονόματα, καταχωρίσεις που υπάρχουν μόνο σε μία δομή ή αμφίσημα μεταδεδομένα διαδρομής Unicode (για παράδειγμα, το Info-ZIP Unicode Path Extra Field `0x7075`), ώστε διαφορετικοί parser να ανασυνθέτουν διαφορετικά δέντρα.
- Συνδυάστε το με path traversal, ώστε μια «αβλαβής» προβολή του αρχείου να μετατραπεί σε primitive εγγραφής κατά την εξαγωγή. Για την πλευρά της εξαγωγής, δείτε το [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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

Συμπληρώστε το με:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Ευρετικές:
- Για εισαγωγή ευαίσθητη ως προς την ασφάλεια, απορρίψτε ή απομονώστε αρχεία με ασυμφωνίες στα ονόματα LFH/CD, διπλότυπα ονόματα αρχείων, πολλαπλές εγγραφές EOCD ή bytes που ακολουθούν την τελική εγγραφή EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Αντιμετωπίστε ως ύποπτα τα ZIP που χρησιμοποιούν ασυνήθιστα extra fields για διαδρομές Unicode ή ασυνεπή σχόλια, αν διαφορετικά εργαλεία διαφωνούν ως προς το δέντρο αρχείων που εξάγεται.<sup>[[4]](#references)[[9]](#references)</sup>
- Αν η ανάλυση έχει μεγαλύτερη σημασία από τη διατήρηση των αρχικών bytes, δημιουργήστε ξανά το αρχείο με strict parser αφού το εξαγάγετε σε sandbox και συγκρίνετε τη λίστα αρχείων που προκύπτει με τα αρχικά μεταδεδομένα.

Αυτό έχει σημασία και πέρα από τα οικοσυστήματα πακέτων: η ίδια κατηγορία ασάφειας μπορεί να αποκρύψει payloads από mail gateways, static scanners και προσαρμοσμένες ροές εισαγωγής που «ρίχνουν μια ματιά» στα περιεχόμενα ενός ZIP πριν το αρχείο υποβληθεί σε επεξεργασία από διαφορετικό extractor.<sup>[[9]](#references)</sup>

---





## References

- [1] [Οδηγός πεδίου για CTF Forensics (Ιστολόγιο του Mike, κατηγορία CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Μέρος 1 – Ένα multistage dropper (αντι-αντίστροφη μηχανική APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Προδιαγραφή μορφής αρχείων ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Η ευέλικτη δομή των αρχείων ZIP αξιοποιείται για την απόκρυψη malware χωρίς εντοπισμό (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Οι hackers κρύβουν malware σε νέα επίθεση με αρχεία ZIP — συνένωση κεντρικών καταλόγων ZIP](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Μια καλύτερη zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Κατανόηση των Zip Bombs: κατασκευή πυρήνα με επικαλύψεις/παρατιθέμενες επικαλύψεις](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Το ZIP μου δεν είναι το δικό σου ZIP: εντοπισμός και εκμετάλλευση σημασιολογικών κενών μεταξύ ZIP parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Αποτροπή επιθέσεων σύγχυσης ZIP parser σε προγράμματα εγκατάστασης πακέτων Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Επιθέσεις ZIP με μειωμένο γνωστό απλό κείμενο (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Ρεαλιστική αποστολή στον ιστό, επίπεδο 15 (επίθεση ZIP με γνωστό απλό κείμενο)](https://www.hackthissite.org/articles/read/793)
- [13] [Χρήση του bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Εκμάθηση επίθεσης bkcrack με γνωστό απλό κείμενο](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Αποθετήριο fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
