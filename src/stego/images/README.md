# Steganography Εικόνων

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα CTF image stego περιορίζονται σε μία από τις εξής κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Payloads σε metadata/comments
- Παράξενα PNG chunks / επιδιόρθωση corruption
- Εργαλεία στο JPEG DCT-domain (OutGuess κ.λπ.)
- Βασισμένα σε frames (GIF/APNG)

## Γρήγορη αρχική αξιολόγηση

Δώστε προτεραιότητα στα στοιχεία σε επίπεδο container πριν από τη βαθιά ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και επιθεωρήστε τη δομή: `file`, `magick identify -verbose`, format validators (π.χ. `pngcheck`).
- Εξαγάγετε metadata και ορατά strings: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για embedded/appended content: `binwalk` και επιθεώρηση του τέλους του αρχείου (`tail | xxd`).
- Επιλέξτε ανάλογα με το container:
- PNG/BMP: bit-planes/LSB και anomalies σε επίπεδο chunk.
- JPEG: metadata + εργαλεία DCT-domain (οικογένειες τύπου OutGuess/F5).
- GIF/APNG: εξαγωγή frames, frame differencing, τεχνικές με palettes.

## Bit-planes / LSB

### Technique

Τα PNG/BMP είναι δημοφιλή στα CTFs επειδή αποθηκεύουν τα pixels με τρόπο που διευκολύνει το **bit-level manipulation**. Ο κλασικός μηχανισμός hide/extract είναι:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλά bits.
- Το **least significant bit** (LSB) κάθε καναλιού αλλάζει ελάχιστα την εικόνα.
- Οι attackers κρύβουν δεδομένα σε αυτά τα low-order bits, μερικές φορές χρησιμοποιώντας stride, permutation ή επιλογή ανά channel.

Τι να περιμένετε στα challenges:

- Το payload βρίσκεται σε ένα μόνο channel (π.χ. `R` LSB).
- Το payload βρίσκεται στο alpha channel.
- Το payload είναι compressed/encoded μετά το extraction.
- Το message είναι διαμοιρασμένο σε planes ή κρυμμένο μέσω XOR μεταξύ planes.

Πρόσθετες οικογένειες που μπορεί να συναντήσετε (ανάλογα με την υλοποίηση):

- **LSB matching** (όχι απλώς αλλαγή του bit, αλλά προσαρμογές +/-1 ώστε να ταιριάζει το target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: το payload βρίσκεται στα color indices αντί για τα raw RGB)
- **Alpha-only payloads** (εντελώς αόρατα σε RGB view)

### Tooling

#### zsteg

Το `zsteg` enumerates πολλά LSB/bit-plane extraction patterns για PNG/BMP:
```bash
zsteg -a file.png
```
Αποθετήριο: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: εκτελεί μια σειρά από transforms (metadata, image transforms, brute forcing παραλλαγών LSB).
- `stegsolve`: χειροκίνητα visual filters (απομόνωση channel, επιθεώρηση plane, XOR κ.λπ.).

Λήψη του Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Κόλπα ορατότητας βασισμένα σε FFT

Το FFT δεν είναι εξαγωγή LSB· χρησιμοποιείται σε περιπτώσεις όπου το περιεχόμενο είναι σκόπιμα κρυμμένο στον χώρο συχνοτήτων ή σε διακριτικά μοτίβα.

- Demo του EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Η web-based αρχική ανάλυση χρησιμοποιείται συχνά σε CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Εσωτερικά του PNG: chunks, καταστροφή και κρυφά δεδομένα

### Τεχνική

Το PNG είναι format βασισμένο σε chunks. Σε πολλές προκλήσεις το payload αποθηκεύεται σε επίπεδο container/chunk και όχι στις τιμές των pixels:

- **Επιπλέον bytes μετά το `IEND`** (πολλοί viewers αγνοούν τα trailing bytes)
- **Μη τυπικά ancillary chunks** που περιέχουν payloads
- **Κατεστραμμένες headers** που αποκρύπτουν τις διαστάσεις ή προκαλούν αποτυχία στους parsers μέχρι να διορθωθούν

Σημεία των chunks υψηλής αξίας που πρέπει να ελεγχθούν:

- `tEXt` / `iTXt` / `zTXt` (metadata κειμένου, μερικές φορές συμπιεσμένα)
- `iCCP` (ICC profile) και άλλα ancillary chunks που χρησιμοποιούνται ως φορείς
- `eXIf` (δεδομένα EXIF σε PNG)

### Εντολές αρχικής ανάλυσης
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Τι να αναζητήσετε:

- Παράξενοι συνδυασμοί width/height/bit-depth/colour-type
- Σφάλματα CRC/chunk (το pngcheck συνήθως υποδεικνύει το ακριβές offset)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε πιο λεπτομερή προβολή των chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Χρήσιμες αναφορές:

- Προδιαγραφή PNG (δομή, chunks): https://www.w3.org/TR/PNG/
- Τεχνάσματα μορφής αρχείων (ιδιαίτερες περιπτώσεις PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: μεταδεδομένα, εργαλεία στο DCT domain και περιορισμοί του ELA

### Technique

Το JPEG δεν αποθηκεύεται ως raw pixels· συμπιέζεται στο DCT domain. Γι' αυτό τα εργαλεία stego για JPEG διαφέρουν από τα εργαλεία PNG LSB:

- Τα payloads μεταδεδομένων/σχολίων βρίσκονται σε επίπεδο αρχείου (υψηλό σήμα και γρήγορος έλεγχος)
- Τα εργαλεία stego στο DCT domain ενσωματώνουν bits σε frequency coefficients

Σε επιχειρησιακό επίπεδο, αντιμετωπίστε το JPEG ως:

- Container για segments μεταδεδομένων (υψηλό σήμα, γρήγορος έλεγχος)
- Compressed signal domain (DCT coefficients), όπου λειτουργούν εξειδικευμένα εργαλεία stego

### Γρήγοροι έλεγχοι
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Τοποθεσίες με υψηλή ένδειξη:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` για EXIF, `APPn` για vendor data)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Αν αντιμετωπίζετε συγκεκριμένα steghide payloads σε JPEG, εξετάστε το ενδεχόμενο χρήσης του `stegseek` (ταχύτερο bruteforce από παλαιότερα scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

Το ELA επισημαίνει διαφορετικά artifacts από recompression· μπορεί να σας κατευθύνει σε περιοχές που έχουν υποστεί επεξεργασία, αλλά δεν αποτελεί από μόνο του stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Για animated images, θεωρήστε ότι το μήνυμα:

- Βρίσκεται σε ένα μόνο frame (εύκολο), ή
- Είναι κατανεμημένο σε πολλά frames (η σειρά έχει σημασία), ή
- Είναι ορατό μόνο όταν κάνετε diff μεταξύ διαδοχικών frames

### Extract frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Στη συνέχεια, χειρίσου τα frames όπως τα κανονικά PNG: `zsteg`, `pngcheck`, απομόνωση καναλιών.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή frames)
- `imagemagick`/`magick` για μετασχηματισμούς ανά frame

Η διαφοροποίηση μεταξύ frames είναι συχνά καθοριστική:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Κωδικοποίηση pixel count σε APNG

- Εντοπίστε containers APNG: `exiftool -a -G1 file.png | grep -i animation` ή `file`.
- Εξαγάγετε frames χωρίς αλλαγή χρονισμού: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Ανακτήστε payloads που έχουν κωδικοποιηθεί ως pixel counts ανά frame:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Τα challenges με animation μπορεί να κωδικοποιούν κάθε byte ως το πλήθος ενός συγκεκριμένου χρώματος σε κάθε frame· η συνένωση των μετρήσεων ανακατασκευάζει το μήνυμα.<sup>[[1]](#references)</sup>

## Ενσωμάτωση με προστασία κωδικού πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται από passphrase αντί για χειρισμό σε επίπεδο pixel, αυτή είναι συνήθως η ταχύτερη διαδρομή.

### steghide

Υποστηρίζει `JPEG, BMP, WAV, AU` και μπορεί να ενσωματώνει/εξάγει κρυπτογραφημένα payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Αποθετήριο: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Υποστηρίζει PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Παραπομπές

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
