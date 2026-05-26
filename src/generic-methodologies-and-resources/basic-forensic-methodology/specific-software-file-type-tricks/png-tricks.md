# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

Τα **αρχεία PNG** είναι πολύ συνηθισμένα σε **CTFs**, **incident response**, και **malware staging** επειδή είναι **lossless**, **chunk-based**, και πολλά εργαλεία θα τα αποδώσουν χωρίς πρόβλημα ακόμα κι όταν περιέχουν **extra metadata**, **appended payloads**, ή **partially corrupted chunks**.

Να αντιμετωπίζεις ένα PNG ως **container**, όχι απλώς ως εικόνα.

## Quick triage

Ξεκίνα με ελέγχους σε επίπεδο container πριν περάσεις σε LSB stego. Για το bit-plane/LSB workflow, δες [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Χρήσιμα πράγματα να αναζητήσετε:

- **Απροσδόκητα ancillary chunks** όπως `tEXt`, `zTXt`, `iTXt`, `eXIf`, ή `iCCP`
- **CRC errors** ή malformed chunk lengths
- **Πρόσθετα δεδομένα μετά το `IEND`**
- **Πολλαπλά `IEND` markers** ή recoverable `IDAT` fragments μετά το τυπικό τέλος του αρχείου
- Ένα αρχείο που είναι έγκυρο PNG **και** επίσης μοιάζει με ZIP/PDF/script όταν carved

Θυμηθείτε ότι η ελάχιστη έγκυρη δομή είναι συνήθως:

- `IHDR` (πρέπει να είναι πρώτο)
- `IDAT` (ένα ή περισσότερα consecutive chunks)
- `IEND` (πρέπει να είναι τελευταίο)

## Trailing data after `IEND`

Ένα από τα πιο high-signal PNG artefacts είναι τα **δεδομένα που προσαρτώνται μετά το τελικό `IEND` chunk**. Πολλά decoders το αγνοούν, κάτι που το καθιστά χρήσιμο για:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** από buggy editors

Γρήγορος έλεγχος:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Αν θέλετε να απομονώσετε όλα όσα βρίσκονται μετά το τελικό `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Δοκιμάστε επίσης γενικούς archive parsers απευθείας πάνω στο PNG ή στο carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Ανάκτηση τύπου Acropalypse από cropped/redacted screenshots

Ένα πολύ πρακτικό πρόσφατο PNG forensic trick είναι να ελέγχεις αν ένας screenshot editor **αντικατέστησε** ένα PNG χωρίς να **truncating** πρώτα το παλιό αρχείο. Σε τέτοιες περιπτώσεις, bytes από την **previous image** μπορούν να παραμείνουν μετά το `IEND`, και μερικές φορές extra `IDAT` data μπορεί να ανακατασκευαστεί μερικώς.

Αυτό έγινε γνωστό με το **aCropalypse** (Google Pixel Markup) και το σχετικό issue του **Windows Snipping Tool**. Στην πράξη, αν ένα "cropped" ή "redacted" PNG εξακολουθεί να περιέχει παλιά trailing data, μπορεί να μπορέσεις να recover μέρος του original screenshot.

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Σημάδια που δικαιολογούν έντονα βαθύτερη ανάλυση:

- Το `pngcheck` αναφέρει **additional data after `IEND`**
- Βρίσκεις **περισσότερο από ένα `IEND`**
- Βρίσκεις **extra `IDAT` chunks** μετά το φαινομενικό τέλος της εικόνας
- Το screenshot προήλθε από συσκευή/editor γνωστό ότι έχει επηρεαστεί

Αν συμβεί αυτό, πέρασε το αρχείο σε ένα **aCropalypse recovery tool** πριν θεωρήσεις ότι το redaction είναι αξιόπιστο.

## Chunk abuse που μετράει στην πράξη

Τα πιο ενδιαφέροντα PNG chunks για investigations συνήθως δεν είναι τα προφανή image ones, αλλά τα chunks που μπορούν να μεταφέρουν **text**, **metadata**, ή **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata και compressed text
- `eXIf` – EXIF data μέσα σε PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data σε indexed images, αλλά επίσης χρήσιμο σε payload-smuggling scenarios

Dump them with:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Για offensive payload persistence μέσα σε PNG chunks (για παράδειγμα **PLTE**, **IDAT**, ή **tEXt** tricks που επιβιώνουν από ορισμένα PHP image transformations), δες τις πιο αναλυτικές σημειώσεις με έμφαση στο upload εδώ:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{endref}}

## Corrupted PNG repair

Για έλεγχο ακεραιότητας και εντοπισμό της ακριβούς χαλασμένης περιοχής, το **pngcheck** παραμένει ένα από τα καλύτερα πρώτα tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Αν το αρχείο είναι damaged αντί για intentionally malicious, το **PCRT** μπορεί να είναι χρήσιμο σε CTFs και lab work για τη διόρθωση κοινών issues όπως bad headers, wrong IHDR values, CRC problems, ή malformed chunk layouts.

Αν ο στόχος σου είναι να **sanitize** ένα PNG που περιέχει suspicious trailer data ενώ διατηρείς το visible image, το ExifTool μπορεί να αφαιρέσει explicitly το trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Για ευαίσθητα αποδεικτικά στοιχεία, εργάζεστε πάντα σε ένα **αντίγραφο** και κρατήστε hashes του πρωτοτύπου πριν επιχειρήσετε επιδιορθώσεις.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
