# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα CTF image stego περιορίζονται σε μία από τις εξής κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Γρήγορη αξιολόγηση

Δώστε προτεραιότητα σε στοιχεία σε επίπεδο container πριν από βαθιά ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και ελέγξτε τη δομή: `file`, `magick identify -verbose`, εργαλεία επικύρωσης μορφής (π.χ., `pngcheck`).
- Εξάγετε metadata και ορατές συμβολοσειρές: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για ενσωματωμένο/προσαρτημένο περιεχόμενο: `binwalk` και έλεγχος τέλους αρχείου (`tail | xxd`).
- Διακλαδιστείτε ανά container:
  - PNG/BMP: bit-planes/LSB και ανωμαλίες σε επίπεδο chunk.
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG: εξαγωγή καρέ, διαφορά καρέ, τεχνάσματα παλέτας.

## Bit-planes / LSB

### Τεχνική

Τα PNG/BMP είναι δημοφιλή στα CTF γιατί αποθηκεύουν pixels με τρόπο που καθιστά εύκολη την **χειραγώγηση σε επίπεδο bit**. Ο κλασικός μηχανισμός απόκρυψης/εξαγωγής είναι:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλά bits.
- Το **λιγότερο σημαντικό bit** (LSB) κάθε καναλιού αλλάζει ελάχιστα την εικόνα.
- Οι επιτιθέμενοι κρύβουν δεδομένα σε αυτά τα χαμηλής τάξης bits, μερικές φορές με stride, permutation, ή επιλογή ανά κανάλι.

Τι να περιμένετε στις προκλήσεις:

- Το payload βρίσκεται μόνο σε ένα κανάλι (π.χ., `R` LSB).
- Το payload βρίσκεται στο alpha κανάλι.
- Το payload είναι συμπιεσμένο/κωδικοποιημένο μετά την εξαγωγή.
- Το μήνυμα είναι διασκορπισμένο ανά planes ή κρυμμένο μέσω XOR μεταξύ planes.

Επιπλέον οικογένειες που μπορεί να συναντήσετε (εξαρτώμενες από την υλοποίηση):

- **LSB matching** (όχι μόνο αναστροφή του bit, αλλά προσαρμογές +/-1 για να ταιριάξει το στοχευμένο bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload σε δείκτες χρώματος αντί για raw RGB)
- **Alpha-only payloads** (εντελώς αόρατο στην RGB προβολή)

### Εργαλεία

#### zsteg

`zsteg` απαριθμεί πολλά LSB/bit-plane σχήματα εξαγωγής για PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: εκτελεί μια σειρά μετασχηματισμών (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: χειροκίνητα οπτικά φίλτρα (απομόνωση καναλιών, επιθεώρηση επιπέδων, XOR, κ.λπ).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

Η FFT δεν είναι LSB extraction; χρησιμοποιείται σε περιπτώσεις όπου το περιεχόμενο κρύβεται σκόπιμα στον χώρο συχνοτήτων ή σε λεπτά μοτίβα.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage που χρησιμοποιείται συχνά σε CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Εσωτερικά PNG: chunks, διαφθορά και κρυμμένα δεδομένα

### Τεχνική

Το PNG είναι μια μορφή που χρησιμοποιεί chunks. Σε πολλές προκλήσεις το payload αποθηκεύεται στο επίπεδο container/chunk αντί σε τιμές pixels:

- `tEXt` / `iTXt` / `zTXt` (metadata κειμένου, μερικές φορές συμπιεσμένα)
- `iCCP` (ICC profile) και άλλα ancillary chunks που χρησιμοποιούνται ως φορέας
- `eXIf` (EXIF data σε PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Τι να προσέξετε:

- Παράξενοι συνδυασμοί width/height/bit-depth/colour-type
- CRC/chunk σφάλματα (το pngcheck συνήθως δείχνει την ακριβή θέση)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε πιο λεπτομερή προβολή των chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Χρήσιμες αναφορές:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: μεταδεδομένα, DCT-domain tools, and ELA limitations

### Τεχνική

Το JPEG δεν αποθηκεύεται ως raw pixels· συμπιέζεται στο DCT domain. Γι' αυτό τα JPEG stego tools διαφέρουν από τα PNG LSB tools:

- Τα μεταδεδομένα/σχόλια ως payloads είναι σε επίπεδο αρχείου (υψηλό σήμα και γρήγορη επιθεώρηση)
- Τα DCT-domain stego tools ενσωματώνουν bits σε συντελεστές συχνότητας

Λειτουργικά, αντιμετωπίστε το JPEG ως:

- Ένα δοχείο για τμήματα μεταδεδομένων (υψηλό σήμα, γρήγορη επιθεώρηση)
- Έναν συμπιεσμένο χώρο σήματος (DCT coefficients) όπου λειτουργούν εξειδικευμένα stego tools

### Γρήγοροι έλεγχοι
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Τοποθεσίες υψηλού σήματος:

- EXIF/XMP/IPTC μεταδεδομένα
- Τμήμα σχολίου JPEG (`COM`)
- Τμήματα εφαρμογής (`APP1` for EXIF, `APPn` for vendor data)

### Κοινά εργαλεία

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Εάν αντιμετωπίζετε συγκεκριμένα payloads steghide σε JPEGs, σκεφτείτε να χρησιμοποιήσετε το `stegseek` (πιο γρήγορο bruteforce από παλαιότερα scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

Η ELA αναδεικνύει διάφορα artifacts επανασυμπίεσης· μπορεί να υποδείξει περιοχές που επεξεργάστηκαν, αλλά δεν αποτελεί stego detector από μόνη της:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Κινούμενες εικόνες

### Τεχνική

Για κινούμενες εικόνες, υποθέστε ότι το μήνυμα βρίσκεται:

- Σε ένα μόνο καρέ (εύκολο), ή
- Διασκορπισμένο σε πολλά καρέ (η σειρά έχει σημασία), ή
- Ορατό μόνο όταν κάνετε diff σε διαδοχικά καρέ

### Εξαγωγή καρέ
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Κατόπιν αντιμετωπίστε τα καρέ σαν κανονικά PNG: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή καρέ)
- `imagemagick`/`magick` για μετασχηματισμούς ανά καρέ

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Ενσωμάτωση προστατευμένη με φράση πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται με φράση πρόσβασης αντί για χειραγώγηση σε επίπεδο pixel, αυτή είναι συνήθως η ταχύτερη οδός.

### steghide

Υποστηρίζει `JPEG, BMP, WAV, AU` και μπορεί να ενσωματώσει/εξαγάγει κρυπτογραφημένα payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have the README.md contents — please paste the exact text from src/stego/images/README.md here and I'll translate it to Greek following your rules.
```bash
stegcracker file.jpg wordlist.txt
```
Αποθετήριο: https://github.com/Paradoxis/StegCracker

### stegpy

Υποστηρίζει PNG/BMP/GIF/WebP/WAV.

Αποθετήριο: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
