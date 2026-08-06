# Κόλπα PNG

{{#include ../../../banners/hacktricks-training.md}}

**Τα αρχεία PNG** είναι πολύ συνηθισμένα σε **CTFs**, στην **απόκριση σε περιστατικά** και στο **malware staging**, επειδή είναι **χωρίς απώλειες**, βασίζονται σε **chunks** και πολλά εργαλεία θα τα αποδώσουν κανονικά ακόμη και όταν περιέχουν **επιπλέον metadata**, **επισυναπτόμενα payloads** ή **μερικώς κατεστραμμένα chunks**.

Αντιμετωπίστε ένα PNG ως **container**, όχι απλώς ως εικόνα.

## Γρήγορο triage

Ξεκινήστε με ελέγχους σε επίπεδο container πριν προχωρήσετε σε LSB stego. Για τη ροή εργασίας bit-plane/LSB, ελέγξτε τη [dedicated image stego σελίδα](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Χρήσιμα πράγματα που πρέπει να αναζητήσετε:

- **Μη αναμενόμενα ancillary chunks**, όπως `tEXt`, `zTXt`, `iTXt`, `eXIf` ή `iCCP`
- **Σφάλματα CRC** ή malformed chunk lengths
- **Επιπλέον δεδομένα μετά το `IEND`**
- **Πολλαπλοί markers `IEND`** ή recoverable `IDAT` fragments μετά το επίσημο τέλος του αρχείου
- Ένα αρχείο που είναι έγκυρο PNG **και** ταυτόχρονα μοιάζει με ZIP/PDF/script όταν γίνεται carving

Να θυμάστε ότι η ελάχιστη έγκυρη δομή συνήθως είναι:

- `IHDR` (πρέπει να είναι πρώτο)
- `IDAT` (ένα ή περισσότερα consecutive chunks)
- `IEND` (πρέπει να είναι τελευταίο)

## Trailing data after `IEND`

Ένα από τα artefacts PNG με το υψηλότερο signal είναι τα **δεδομένα που προστίθενται μετά το τελικό `IEND` chunk**. Πολλοί decoders τα αγνοούν, γεγονός που τα καθιστά χρήσιμα για:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Ανάκτηση παλαιότερων image data** από προβληματικούς editors

Γρήγορος εντοπισμός:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Εάν θέλετε να εξαγάγετε όλα όσα ακολουθούν το τελικό `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Επίσης, δοκιμάστε generic archive parsers απευθείας στο PNG ή στο carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recovery τύπου Acropalypse από cropped/redacted screenshots

Ένα πολύ πρακτικό πρόσφατο PNG forensic trick είναι να ελέγξετε αν ένας screenshot editor έκανε **overwrite** σε ένα PNG χωρίς να κάνει πρώτα **truncate** στο παλιό αρχείο. Σε αυτές τις περιπτώσεις, bytes από την **προηγούμενη εικόνα** μπορεί να παραμείνουν μετά το `IEND`, και μερικές φορές επιπλέον δεδομένα `IDAT` μπορούν να ανακατασκευαστούν εν μέρει.

Αυτό έγινε ευρέως γνωστό με το **aCropalypse** (Google Pixel Markup) και το σχετικό ζήτημα του **Windows Snipping Tool**. Στην πράξη, αν ένα "cropped" ή "redacted" PNG εξακολουθεί να περιέχει παλιά trailing data, ίσως μπορέσετε να ανακτήσετε μέρος του αρχικού screenshot.<sup>[[1]](#references)</sup>

Πρακτικό workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ενδείξεις που δικαιολογούν έντονα βαθύτερη ανάλυση:

- Το `pngcheck` αναφέρει **additional data after `IEND`**
- Εντοπίζετε **περισσότερα από ένα `IEND`**
- Εντοπίζετε **επιπλέον `IDAT` chunks** μετά το φαινομενικό τέλος της εικόνας
- Το screenshot προήλθε από συσκευή/editor που είναι γνωστό ότι έχει επηρεαστεί

Αν συμβαίνει αυτό, περάστε το αρχείο από ένα **aCropalypse recovery tool** πριν θεωρήσετε αξιόπιστη τη redaction.

## Κατάχρηση chunks που έχει πρακτική σημασία

Τα πιο ενδιαφέροντα PNG chunks για investigations συνήθως δεν είναι τα προφανή chunks εικόνας, αλλά εκείνα που μπορούν να μεταφέρουν **κείμενο**, **metadata** ή **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata και συμπιεσμένο κείμενο
- `eXIf` – EXIF data μέσα σε PNG
- `iCCP` – embedded ICC profile
- `PLTE` – δεδομένα παλέτας σε indexed images, αλλά και χρήσιμα σε σενάρια payload-smuggling<sup>[[2]](#references)</sup>

Κάντε dump με:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Για persistence offensive payload μέσα σε PNG chunks (για παράδειγμα tricks με **PLTE**, **IDAT** ή **tEXt** που επιβιώνουν από ορισμένους PHP image transformations), δείτε τις πιο λεπτομερείς upload-focused σημειώσεις εδώ<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Επιδιόρθωση corrupted PNG

Για τον έλεγχο της ακεραιότητας και τον ακριβή εντοπισμό της κατεστραμμένης περιοχής, το **pngcheck** παραμένει ένα από τα καλύτερα εργαλεία πρώτου ελέγχου:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Αν το αρχείο έχει υποστεί damage και δεν είναι σκόπιμα malicious, το **PCRT** μπορεί να είναι χρήσιμο σε CTFs και σε εργαστηριακή εργασία για τη διόρθωση συνηθισμένων προβλημάτων, όπως bad headers, λανθασμένες τιμές IHDR, προβλήματα CRC ή malformed chunk layouts.

Αν ο στόχος σας είναι να κάνετε **sanitize** ένα PNG που περιέχει ύποπτα trailer data, διατηρώντας παράλληλα την ορατή εικόνα, το ExifTool μπορεί να αφαιρέσει explicit το trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Για ευαίσθητα στοιχεία, να εργάζεστε πάντα σε ένα **αντίγραφο** και να διατηρείτε τα hashes του αρχικού αρχείου πριν επιχειρήσετε επιδιορθώσεις.

## Αναφορές

- [1] [Exploiting aCropalypse: Ανάκτηση περικομμένων PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: Πώς να εισαγάγετε κώδικα PHP σε μια εικόνα — και να τον διατηρήσετε εκεί](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
