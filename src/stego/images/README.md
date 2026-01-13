# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα CTF image stego καταλήγουν σε μία από τις παρακάτω κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Γρήγορη αξιολόγηση

Δώστε προτεραιότητα σε στοιχεία επιπέδου container πριν από βαθιά ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και ελέγξτε τη δομή: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Εξαγάγετε metadata και ορατά strings: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για embedded/appended περιεχόμενο: `binwalk` και έλεγχος τέλους αρχείου (`tail | xxd`).
- Διαχωρίστε ανά container:
- PNG/BMP: bit-planes/LSB και ανωμαλίες σε επίπεδο chunk.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: εξαγωγή frames, frame differencing, κόλπα με palette.

## Bit-planes / LSB

### Τεχνική

Τα PNG/BMP είναι δημοφιλή σε CTFs επειδή αποθηκεύουν pixels με τρόπο που κάνει εύκολη την **bit-level manipulation**. Ο κλασικός μηχανισμός απόκρυψης/εξαγωγής είναι:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλαπλά bits.
- Το **least significant bit** (LSB) κάθε καναλιού αλλάζει την εικόνα πολύ λίγο.
- Οι επιτιθέμενοι κρύβουν δεδομένα σε αυτά τα low-order bits, μερικές φορές με stride, permutation, ή επιλογή ανά κανάλι.

Τι να περιμένετε σε προκλήσεις:

- Το payload βρίσκεται σε ένα κανάλι μόνο (π.χ., `R` LSB).
- Το payload βρίσκεται στο alpha channel.
- Το payload είναι συμπιεσμένο/κωδικοποιημένο μετά την εξαγωγή.
- Το μήνυμα είναι διασκορπισμένο σε planes ή κρυμμένο μέσω XOR ανάμεσα σε planes.

Επιπλέον οικογένειες που μπορεί να συναντήσετε (εξαρτάται από την υλοποίηση):

- **LSB matching** (όχι απλώς αναστροφή του bit, αλλά προσαρμογές +/-1 για να ταιριάξει το target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload σε color indices αντί για raw RGB)
- **Alpha-only payloads** (εντελώς αόρατο στην RGB προβολή)

### Εργαλεία

#### zsteg

`zsteg` απαριθμεί πολλά μοτίβα εξαγωγής LSB/bit-plane για PNG/BMP:
```bash
zsteg -a file.png
```
Αποθετήριο: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: τρέχει μια σειρά μετασχηματισμών (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: χειροκίνητα οπτικά φίλτρα (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

Το FFT δεν είναι LSB extraction· χρησιμοποιείται σε περιπτώσεις όπου το περιεχόμενο κρύβεται σκόπιμα στον συχνοτικό χώρο ή σε λεπτά μοτίβα.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage που χρησιμοποιείται συχνά σε CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

Το PNG είναι μια μορφή που βασίζεται σε chunks. Σε πολλές προκλήσεις το payload αποθηκεύεται σε επίπεδο container/chunk αντί για τις τιμές των pixels:

- **Επιπλέον bytes μετά το `IEND`** (πολλοί viewers αγνοούν τα trailing bytes)
- **Non-standard ancillary chunks** που φέρουν payloads
- **Κατεστραμμένοι headers** που κρύβουν διαστάσεις ή σπάνε parsers μέχρι να διορθωθούν

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (μεταδεδομένα κειμένου, μερικές φορές συμπιεσμένα)
- `iCCP` (ICC profile) και άλλα ancillary chunks που χρησιμοποιούνται ως φορέας
- `eXIf` (EXIF δεδομένα σε PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Τι να προσέξετε:

- Ασυνήθιστοι συνδυασμοί πλάτους/ύψους/βάθους bit/τύπου χρώματος
- Σφάλματα CRC ή chunk (pngcheck συνήθως δείχνει την ακριβή μετατόπιση)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε πιο λεπτομερή προβολή των chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Χρήσιμες αναφορές:

- PNG προδιαγραφή (structure, chunks): https://www.w3.org/TR/PNG/
- Κόλπα μορφής αρχείου (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Τεχνική

Το JPEG δεν αποθηκεύεται ως raw pixels· συμπιέζεται στο DCT domain. Γι' αυτό τα JPEG stego εργαλεία διαφέρουν από τα PNG LSB εργαλεία:

- Metadata/comment payloads είναι σε επίπεδο αρχείου (υψηλό σήμα και γρήγορος στον έλεγχο)
- DCT-domain stego εργαλεία ενσωματώνουν bits σε συντελεστές συχνότητας

Σε λειτουργικό επίπεδο, θεωρήστε το JPEG ως:

- Ένα δοχείο για metadata segments (υψηλό σήμα, γρήγορος έλεγχος)
- Ένας συμπιεσμένος τομέας σήματος (DCT coefficients) όπου λειτουργούν εξειδικευμένα stego εργαλεία

### Γρήγοροι έλεγχοι
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC metadata
- τμήμα σχολίου JPEG (`COM`)
- Τμήματα εφαρμογής (`APP1` για EXIF, `APPn` για δεδομένα προμηθευτή)

### Συνήθη εργαλεία

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA επισημαίνει διάφορα ίχνη επανασυμπίεσης· μπορεί να υποδείξει περιοχές που έχουν επεξεργαστεί, αλλά δεν είναι από μόνη της ένας stego detector:

## Κινούμενες εικόνες

### Τεχνική

Για κινούμενες εικόνες, υποθέστε ότι το μήνυμα είναι:

- Σε ένα καρέ (εύκολο), ή
- Διασπαρμένο σε καρέ (η σειρά έχει σημασία), ή
- Ορατό μόνο όταν κάνετε diff σε διαδοχικά καρέ

### Εξαγωγή καρέ
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Στη συνέχεια χειριστείτε τα frames όπως κανονικά PNGs: `zsteg`, `pngcheck`, channel isolation.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή frames)
- `imagemagick`/`magick` για μετασχηματισμούς ανά frame

Το Frame differencing είναι συχνά καθοριστικό:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Εντοπίστε κοντέινερ APNG: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Εξάγετε καρέ χωρίς επαναχρονισμό: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Ανακτήστε τα payloads που κωδικοποιήθηκαν ως αριθμοί pixel ανά καρέ:
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
Οι κινούμενες προκλήσεις μπορεί να κωδικοποιούν κάθε byte ως τον αριθμό ενός συγκεκριμένου χρώματος σε κάθε καρέ· η συνένωση των μετρήσεων ανασυνθέτει το μήνυμα.

## Ενσωμάτωση προστατευμένη με κωδικό

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται με passphrase αντί για χειραγώγηση σε επίπεδο pixel, αυτός είναι συνήθως ο ταχύτερος τρόπος.

### steghide

Υποστηρίζει `JPEG, BMP, WAV, AU` και μπορεί να embed/extract κρυπτογραφημένα payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Δεν βλέπω το περιεχόμενο του αρχείου src/stego/images/README.md. Μπορείς να επικολλήσεις εδώ το κείμενο που θέλεις να μεταφράσω (ή να υποδείξεις ακριβώς ποιο τμήμα); Θα το μεταφράσω στα Ελληνικά διατηρώντας απείραχτα tags, links και paths.
```bash
stegcracker file.jpg wordlist.txt
```
Αποθετήριο: https://github.com/Paradoxis/StegCracker

### stegpy

Υποστηρίζει PNG/BMP/GIF/WebP/WAV.

Αποθετήριο: https://github.com/dhsdshdhk/stegpy

## Αναφορές

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
