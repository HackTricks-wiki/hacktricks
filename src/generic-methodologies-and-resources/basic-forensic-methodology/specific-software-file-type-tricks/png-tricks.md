# Κόλπα PNG

Τα **αρχεία PNG** είναι πολύ συνηθισμένα σε **CTFs**, στο **incident response** και στο **malware staging**, επειδή είναι **lossless**, βασίζονται σε **chunks** και πολλά εργαλεία τα αποδίδουν κανονικά, ακόμη και όταν περιέχουν **επιπλέον metadata**, **appended payloads** ή **μερικώς κατεστραμμένα chunks**.

Αντιμετωπίστε ένα PNG ως **container**, όχι απλώς ως εικόνα.

## Γρήγορος αρχικός έλεγχος

Ξεκινήστε με ελέγχους σε επίπεδο container πριν προχωρήσετε σε LSB stego. Για τη ροή εργασίας bit-plane/LSB, δείτε [την ειδική σελίδα για image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Χρήσιμα πράγματα που πρέπει να αναζητήσετε:

- **Μη αναμενόμενα ancillary chunks**, όπως `tEXt`, `zTXt`, `iTXt`, `eXIf` ή `iCCP`
- **Σφάλματα CRC** ή κακοσχηματισμένα μήκη chunks
- **Πρόσθετα δεδομένα μετά το `IEND`**
- **Πολλαπλοί markers `IEND`** ή ανακτήσιμα fragments `IDAT` μετά το επίσημο τέλος του αρχείου
- Ένα αρχείο που είναι έγκυρο PNG **και** μοιάζει επίσης με ZIP/PDF/script όταν γίνεται carving

Να θυμάστε ότι η ελάχιστη έγκυρη δομή είναι συνήθως:

- `IHDR` (πρέπει να είναι πρώτο)
- `IDAT` (ένα ή περισσότερα διαδοχικά chunks)
- `IEND` (πρέπει να είναι τελευταίο)

## Δεδομένα μετά το `IEND`

Ένα από τα artefacts PNG με το υψηλότερο signal είναι τα **δεδομένα που επισυνάπτονται μετά το τελικό chunk `IEND`**. Πολλοί decoders τα αγνοούν, γεγονός που τα καθιστά χρήσιμα για:

- **Απλό stego / κρυφά payloads**
- **PNG polyglots**
- **Malware staging**
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
Αν θέλετε να κάνετε carving όλων όσων βρίσκονται μετά το τελικό `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Δοκιμάστε επίσης generic archive parsers απευθείας πάνω στο PNG ή στο carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Ανάκτηση τύπου Acropalypse από περικομμένα/λογοκριμένα screenshots

Ένα πολύ πρακτικό πρόσφατο PNG forensic trick είναι να ελέγξετε αν ένας screenshot editor **έγραψε πάνω** σε ένα PNG χωρίς να **περικόψει** πρώτα το παλιό αρχείο. Σε αυτές τις περιπτώσεις, bytes από την **προηγούμενη εικόνα** μπορεί να παραμείνουν μετά το `IEND`, ενώ μερικές φορές μπορούν να ανακατασκευαστούν εν μέρει επιπλέον δεδομένα `IDAT`.

Αυτό έγινε ευρέως γνωστό με το **aCropalypse** (Google Pixel Markup) και το σχετικό ζήτημα του **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Στην πράξη, αν ένα "περικομμένο" ή "λογοκριμένο" PNG εξακολουθεί να περιέχει παλιά δεδομένα στο τέλος του, ενδέχεται να μπορείτε να ανακτήσετε μέρος του αρχικού screenshot.<sup>[[1]](#references)</sup>

Πρακτική διαδικασία:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ενδείξεις που δικαιολογούν έντονα βαθύτερη ανάλυση:

- Το `pngcheck` αναφέρει **additional data after `IEND`**
- Εντοπίζετε **περισσότερα από ένα `IEND`**
- Εντοπίζετε **επιπλέον chunks `IDAT`** μετά το φαινομενικό τέλος της εικόνας
- Το screenshot προήλθε από συσκευή/editor που είναι γνωστό ότι έχει επηρεαστεί

Αν συμβαίνει αυτό, δώστε το αρχείο σε ένα **aCropalypse recovery tool** πριν θεωρήσετε αξιόπιστη τη redaction.

## Κατάχρηση chunks που έχει πρακτική σημασία

Τα πιο ενδιαφέροντα PNG chunks για investigations συνήθως δεν είναι τα προφανή chunks εικόνας, αλλά εκείνα που μπορούν να μεταφέρουν **κείμενο**, **metadata** ή **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata κειμένου και συμπιεσμένο κείμενο
- `eXIf` – δεδομένα EXIF μέσα σε PNG
- `iCCP` – ενσωματωμένο ICC profile
- `PLTE` – δεδομένα παλέτας σε indexed images, αλλά επίσης χρήσιμα σε σενάρια payload-smuggling.<sup>[[2]](#references)</sup>

Εξαγάγετέ τα με:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Για offensive payload persistence μέσα σε PNG chunks (για παράδειγμα tricks με **PLTE**, **IDAT** ή **tEXt** που επιβιώνουν από ορισμένους PHP image transformations), δείτε τις πιο λεπτομερείς upload-focused σημειώσεις εδώ:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Για τον έλεγχο της ακεραιότητας και τον εντοπισμό της ακριβούς κατεστραμμένης περιοχής, το **pngcheck** παραμένει ένα από τα καλύτερα αρχικά tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Αν το αρχείο έχει υποστεί ζημιά και δεν είναι σκόπιμα κακόβουλο, το **PCRT** μπορεί να φανεί χρήσιμο σε CTFs και εργαστηριακή εργασία για τη διόρθωση συνηθισμένων προβλημάτων, όπως κατεστραμμένα headers, εσφαλμένες τιμές IHDR, προβλήματα CRC ή malformed chunk layouts.

Αν ο στόχος σας είναι να **sanitize** ένα PNG που περιέχει ύποπτα trailer data, διατηρώντας παράλληλα την ορατή εικόνα, το ExifTool μπορεί να αφαιρέσει ρητά το trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Για ευαίσθητα στοιχεία, εργάζεστε πάντα σε ένα **αντίγραφο** και διατηρείτε τα hashes του πρωτοτύπου πριν επιχειρήσετε επιδιορθώσεις.

## References

- [1] [Εκμετάλλευση του aCropalypse: Ανάκτηση περικομμένων PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads σε PNGs: Πώς να εισαγάγετε PHP code σε μια εικόνα – και να το διατηρήσετε εκεί](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
