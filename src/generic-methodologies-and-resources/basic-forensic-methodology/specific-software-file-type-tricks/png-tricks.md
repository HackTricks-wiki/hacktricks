# Κόλπα PNG

{{#include ../../../banners/hacktricks-training.md}}

Τα **αρχεία PNG** είναι πολύ συνηθισμένα σε **CTF**, στην **αντιμετώπιση περιστατικών** και στο **malware staging**, επειδή είναι **χωρίς απώλειες**, βασίζονται σε **chunks** και πολλά εργαλεία τα αποδίδουν κανονικά, ακόμη κι όταν περιέχουν **επιπλέον metadata**, **προσαρτημένα payloads** ή **μερικώς κατεστραμμένα chunks**.

Αντιμετωπίστε ένα PNG ως **container**, όχι απλώς ως εικόνα.

## Γρήγορη διαλογή

Ξεκινήστε με ελέγχους σε επίπεδο container προτού στραφείτε στο LSB stego. Για τη ροή εργασίας bit-plane/LSB, δείτε [την ειδική σελίδα για το image stego](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Χρήσιμα πράγματα που πρέπει να αναζητήσετε:

- **Μη αναμενόμενα ancillary chunks**, όπως `tEXt`, `zTXt`, `iTXt`, `eXIf` ή `iCCP`
- **Σφάλματα CRC** ή κακοσχηματισμένα μήκη chunk
- **Πρόσθετα δεδομένα μετά το `IEND`**
- **Πολλαπλά markers `IEND`** ή ανακτήσιμα τμήματα `IDAT` μετά το επίσημο τέλος του αρχείου
- Ένα αρχείο που είναι έγκυρο PNG **και** μοιάζει επίσης με ZIP/PDF/script κατά την εξαγωγή δεδομένων

Θυμηθείτε ότι η ελάχιστη έγκυρη δομή είναι συνήθως:

- `IHDR` (πρέπει να είναι πρώτο)
- `IDAT` (ένα ή περισσότερα διαδοχικά chunks)
- `IEND` (πρέπει να είναι τελευταίο)

## Δεδομένα που ακολουθούν το `IEND`

Ένα από τα πιο ισχυρά ενδεικτικά ευρήματα σε ένα PNG είναι **δεδομένα που έχουν προστεθεί μετά το τελικό chunk `IEND`**. Πολλοί decoders τα αγνοούν, κάτι που τα καθιστά χρήσιμα για:

- **Απλό stego / κρυφά payloads**
- **PNG polyglots**
- **Προετοιμασία malware**
- **Ανάκτηση παλαιότερων δεδομένων εικόνας** από προβληματικούς editors

Γρήγορος εντοπισμός:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Η αναζήτηση για τα bytes `IEND` είναι μόνο μια ένδειξη: τα ίδια bytes μπορεί να εμφανίζονται σε δεδομένα chunk ή σε πλαστό trailer. Για αξιόπιστο carving, ακολούθησε τα chunks με πρόθεμα μήκους από την υπογραφή PNG και σταμάτησε στο πρώτο δομικό `IEND`· ο [chunk walker παρακάτω](#extract-ancillary-chunk-payloads) αποθηκεύει επίσης το trailer.<sup>[[6]](#references)</sup>

Δοκίμασε επίσης γενικούς parsers αρχείων αρχειοθέτησης απευθείας στο PNG ή στο carved trailer:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Ανάκτηση περικομμένων/αποκρυμμένων screenshots τύπου Acropalypse

Ένα πολύ πρακτικό πρόσφατο τέχνασμα ψηφιακής εγκληματολογίας PNG είναι να ελέγξετε αν ένας επεξεργαστής screenshot **έγραψε πάνω** σε ένα PNG χωρίς πρώτα να **περικόψει** το παλιό αρχείο. Σε αυτές τις περιπτώσεις, bytes από την **προηγούμενη εικόνα** μπορεί να παραμείνουν μετά το `IEND`, ενώ μερικές φορές είναι δυνατό να ανακατασκευαστούν εν μέρει επιπλέον δεδομένα `IDAT`.

Αυτό έγινε ευρέως γνωστό με το **aCropalypse** (Google Pixel Markup) και το σχετικό πρόβλημα του **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Στην πράξη, αν ένα «περικομμένο» ή «αποκρυμμένο» PNG εξακολουθεί να περιέχει παλιά δεδομένα στο τέλος, ίσως μπορέσετε να ανακτήσετε μέρος του αρχικού screenshot.<sup>[[1]](#references)</sup>

Πρακτική ροή εργασίας:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Ενδείξεις που δικαιολογούν έντονα περαιτέρω ανάλυση:

- Το `pngcheck` αναφέρει **πρόσθετα δεδομένα μετά το `IEND`**
- Βρίσκετε **περισσότερα από ένα `IEND`**
- Βρίσκετε **επιπλέον chunks `IDAT`** μετά το φαινομενικό τέλος της εικόνας
- Το screenshot προήλθε από συσκευή/editor που είναι γνωστό ότι έχει επηρεαστεί

Αν συμβεί αυτό, περάστε το αρχείο από ένα **εργαλείο ανάκτησης aCropalypse** πριν θεωρήσετε αξιόπιστη τη λογοκρισία.

## Κατάχρηση chunks που έχει πρακτική σημασία

Τα πιο ενδιαφέροντα chunks PNG για έρευνες δεν είναι συνήθως τα προφανή chunks εικόνας, αλλά εκείνα που μπορούν να μεταφέρουν **κείμενο**, **metadata** ή **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata κειμένου και συμπιεσμένο κείμενο
- `eXIf` – δεδομένα EXIF μέσα σε PNG
- `iCCP` – ενσωματωμένο προφίλ ICC
- `PLTE` – δεδομένα παλέτας σε εικόνες με ευρετήριο, αλλά και χρήσιμα σε σενάρια απόκρυψης payload.<sup>[[2]](#references)</sup>

Εξαγάγετέ τα με:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Για persistence offensive payload μέσα σε PNG chunks (για παράδειγμα, τεχνικές με **PLTE**, **IDAT** ή **tEXt** που επιβιώνουν από ορισμένους μετασχηματισμούς εικόνων PHP), δείτε τις πιο αναλυτικές σημειώσεις για uploads εδώ:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Εξαγωγή payloads από ancillary chunks

Ένας attacker μπορεί να τοποθετήσει αυθαίρετα bytes σε ένα **unknown ancillary chunk πριν από το `IEND`**. Οι συνηθισμένοι PNG decoders μπορούν να αγνοήσουν ένα unknown ancillary chunk, ενώ ένα script που ανακτά την εικόνα ως bytes μπορεί να διαβάσει και να χρησιμοποιήσει το payload· το άνοιγμα του PNG από μόνο του δεν το εκτελεί.<sup>[[4]](#references)[[6]](#references)</sup> Η αρχική έρευνα παρουσίασε ένα compressed και encrypted custom chunk.<sup>[[4]](#references)</sup> Ένα μεταγενέστερο παράδειγμα σε browser χρησιμοποίησε τα bytes που εξήχθησαν για να παρέχει HTML ή ένα download.<sup>[[5]](#references)</sup>

Ένα πεζό πρώτο γράμμα στον τύπο chunk σημαίνει *ancillary*· ένα πεζό δεύτερο γράμμα σημαίνει *private*. Για παράδειγμα, το `paMP` είναι private, ενώ το `pAMP` χρησιμοποιεί το public namespace, παρόλο που το τελευταίο επινοήθηκε για την επίδειξη.<sup>[[4]](#references)[[6]](#references)</sup> Ένα chunk έχει τη μορφή `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`· το CRC καλύπτει τα type και data. Κάντε parse αυτή τη δομή αντί να αναζητάτε ένα όνομα type μέσα σε compressed δεδομένα `IDAT`. Ο παρακάτω walker επικυρώνει τα όρια και τα CRC, εξάγει τα ancillary payloads ως raw bytes και γράφει τυχόν bytes μετά το δομικό `IEND` στο `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Εξαγωγή ancillary chunks και του PNG trailer</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Εξετάστε τα carved bytes με τα `file`, `strings` ή `binwalk`· αποσυμπιέστε τα μόνο αν το carrier είναι πράγματι συμπιεσμένο.<sup>[[4]](#references)</sup> Η επανακωδικοποίηση μπορεί να αφαιρέσει το carrier, επομένως συγκρίνετε τα bytes που ανέβηκαν και ανακτήθηκαν πριν βασιστείτε σε αυτό.<sup>[[2]](#references)[[6]](#references)</sup>

## Επιδιόρθωση κατεστραμμένων PNG

Για τον έλεγχο της ακεραιότητας και τον εντοπισμό της ακριβούς κατεστραμμένης περιοχής, το **pngcheck** παραμένει ένα από τα καλύτερα εργαλεία για αρχή:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Αν το αρχείο έχει υποστεί ζημιά και δεν είναι σκόπιμα κακόβουλο, το **PCRT** μπορεί να φανεί χρήσιμο σε CTF και εργαστηριακές ασκήσεις για τη διόρθωση συνηθισμένων προβλημάτων, όπως εσφαλμένες κεφαλίδες, λανθασμένες τιμές IHDR, προβλήματα CRC ή κακοσχηματισμένες διατάξεις chunks.

Αν ο στόχος σας είναι να **απολυμάνετε** ένα PNG που περιέχει ύποπτα δεδομένα trailer, διατηρώντας την ορατή εικόνα, το ExifTool μπορεί να αφαιρέσει ρητά το trailer:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Για ευαίσθητα αποδεικτικά στοιχεία, να εργάζεστε πάντα σε ένα **αντίγραφο** και να διατηρείτε τα hash του πρωτοτύπου πριν επιχειρήσετε επισκευές.



## References

- [1] [Εκμετάλλευση του aCropalypse: Ανάκτηση περικομμένων PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Μόνιμα PHP payloads σε PNG: Πώς να εισαγάγετε κώδικα PHP σε μια εικόνα — και να παραμείνει εκεί](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Τα ancillary chunks είναι ιδανικό μέρος για την αποθήκευση ευαίσθητων πληροφοριών](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Χρήση έγκυρων ancillary chunks για τη λαθραία μεταφορά δεδομένων σε ένα endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Προδιαγραφή Portable Network Graphics (PNG) (Τρίτη έκδοση)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
