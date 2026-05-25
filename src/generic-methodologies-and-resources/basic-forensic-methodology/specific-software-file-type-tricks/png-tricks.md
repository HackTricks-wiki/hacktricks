# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

Τα **αρχεία PNG** είναι πολύ συνηθισμένα σε **CTFs**, **incident response** και **malware staging** επειδή είναι **lossless**, **chunk-based**, και πολλά εργαλεία θα τα αποδώσουν ευχαρίστως ακόμη κι όταν περιέχουν **extra metadata**, **appended payloads** ή **partially corrupted chunks**.

Δείτε ένα PNG ως **container**, όχι απλώς ως εικόνα.

## Γρήγορο triage

Ξεκινήστε με ελέγχους σε επίπεδο container πριν περάσετε σε LSB stego. Για το bit-plane/LSB workflow, δείτε [τη dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Χρήσιμα πράγματα για να ψάξετε:

- **Unexpected ancillary chunks** όπως `tEXt`, `zTXt`, `iTXt`, `eXIf`, ή `iCCP`
- **CRC errors** ή malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** ή recoverable `IDAT` fragments μετά το formal end of the file
- Ένα αρχείο που είναι valid PNG **και** επίσης μοιάζει με ZIP/PDF/script όταν carved

Να θυμάστε ότι η ελάχιστη valid δομή είναι συνήθως:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## Trailing data after `IEND`

Ένα από τα πιο υψηλού σήματος PNG artefacts είναι **data appended after the final `IEND` chunk**. Πολλοί decoders το αγνοούν, κάτι που το κάνει χρήσιμο για:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** από buggy editors

Quick detection:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Αν θέλεις να αποκόψεις όλα όσα βρίσκονται μετά το τελικό `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Δοκίμασε επίσης γενικούς archive parsers απευθείας στο PNG ή στο carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Ανάκτηση τύπου Acropalypse από cropped/redacted screenshots

Ένα πολύ πρακτικό πρόσφατο PNG forensic trick είναι να ελέγξεις αν ένα screenshot editor **αντικατέστησε** ένα PNG χωρίς πρώτα να **truncating** το παλιό αρχείο. Σε αυτές τις περιπτώσεις, bytes από την **previous image** μπορούν να παραμείνουν μετά το `IEND`, και μερικές φορές extra `IDAT` data μπορούν να ανακατασκευαστούν μερικώς.

Αυτό έγινε ευρέως γνωστό με το **aCropalypse** (Google Pixel Markup) και το σχετικό ζήτημα του **Windows Snipping Tool**. Στην πράξη, αν ένα "cropped" ή "redacted" PNG εξακολουθεί να περιέχει παλιά trailing data, μπορεί να μπορέσεις να ανακτήσεις μέρος του αρχικού screenshot.

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
- Το screenshot προήλθε από συσκευή/editor που είναι γνωστό ότι έχει επηρεαστεί

Αν συμβεί αυτό, πέρασε το αρχείο σε ένα **aCropalypse recovery tool** πριν θεωρήσεις ότι το redaction είναι αξιόπιστο.

## Chunk abuse που έχει σημασία στην πράξη

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
Για επίμονη αποθήκευση offensive payload μέσα σε PNG chunks (για παράδειγμα **PLTE**, **IDAT**, ή **tEXt** tricks που επιβιώνουν από ορισμένα PHP image transformations), δες τις πιο αναλυτικές σημειώσεις με έμφαση στο upload εδώ:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Επιδιόρθωση κατεστραμμένου PNG

Για έλεγχο ακεραιότητας και εντοπισμό της ακριβούς κατεστραμμένης περιοχής, το **pngcheck** παραμένει ένα από τα καλύτερα πρώτα tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Αν το αρχείο είναι κατεστραμμένο και όχι σκόπιμα malicious, το **PCRT** μπορεί να είναι χρήσιμο σε CTFs και lab work για τη διόρθωση συνηθισμένων issues όπως κακά headers, λάθος τιμές IHDR, CRC προβλήματα ή malformed chunk layouts.

Αν ο στόχος σου είναι να **sanitize** ένα PNG που περιέχει ύποπτα trailer data, διατηρώντας το ορατό image, το ExifTool μπορεί να αφαιρέσει ρητά το trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Για ευαίσθητα αποδεικτικά στοιχεία, πάντα να δουλεύεις σε ένα **αντίγραφο** και να κρατάς hashes του πρωτότυπου πριν επιχειρήσεις επισκευές.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
