# Steganography Εικόνων

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα image stego σε CTF περιορίζονται σε μία από τις παρακάτω κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Payloads σε metadata/comments
- Παράξενα PNG chunks / επιδιόρθωση corruption
- Εργαλεία στο JPEG DCT-domain (OutGuess κ.λπ.)
- Βασισμένα σε frames (GIF/APNG)

## Γρήγορο triage

Δώστε προτεραιότητα σε evidence σε επίπεδο container πριν από τη βαθιά ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και εξετάστε τη δομή: `file`, `magick identify -verbose`, format validators (π.χ. `pngcheck`).
- Εξαγάγετε metadata και ορατά strings: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για embedded/appended content: `binwalk` και επιθεώρηση του τέλους του αρχείου (`tail | xxd`).
- Επιλέξτε ανάλογα με το container:
- PNG/BMP: bit-planes/LSB και anomalies σε επίπεδο chunk.
- JPEG: metadata + tooling στο DCT-domain (οικογένειες τύπου OutGuess/F5).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

Τα PNG/BMP είναι δημοφιλή σε CTF επειδή αποθηκεύουν τα pixels με τρόπο που κάνει τον **χειρισμό σε επίπεδο bit** εύκολο. Ο κλασικός μηχανισμός hide/extract είναι:

- Κάθε channel pixel (R/G/B/A) έχει πολλά bits.
- Το **least significant bit** (LSB) κάθε channel αλλάζει ελάχιστα την εικόνα.
- Οι attackers κρύβουν data σε αυτά τα low-order bits, μερικές φορές χρησιμοποιώντας stride, permutation ή επιλογή ανά channel.

Τι να περιμένετε στα challenges:

- Το payload βρίσκεται σε ένα μόνο channel (π.χ. `R` LSB).
- Το payload βρίσκεται στο alpha channel.
- Το payload είναι compressed/encoded μετά το extraction.
- Το μήνυμα είναι κατανεμημένο σε planes ή κρυμμένο μέσω XOR μεταξύ planes.

Πρόσθετες οικογένειες που μπορεί να συναντήσετε (ανάλογα με την implementation):

- **LSB matching** (όχι απλώς αλλαγή του bit, αλλά προσαρμογές +/-1 ώστε να ταιριάζει το target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: το payload βρίσκεται στα color indices αντί για raw RGB)
- **Alpha-only payloads** (εντελώς αόρατα σε RGB view)

### Tooling

#### zsteg

Το `zsteg` απαριθμεί πολλά patterns extraction για LSB/bit-plane σε PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: εκτελεί μια σειρά από transforms (metadata, image transforms, brute forcing παραλλαγών LSB).
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR κ.λπ.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Κόλπα ορατότητας βασισμένα σε FFT

Το FFT δεν είναι LSB extraction· χρησιμοποιείται σε περιπτώσεις όπου το content είναι σκόπιμα κρυμμένο στο frequency space ή σε subtle patterns.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage χρησιμοποιείται συχνά σε CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, και hidden data

### Technique

Το PNG είναι chunked format. Σε πολλά challenges το payload αποθηκεύεται στο επίπεδο του container/chunk και όχι στις pixel values:

- **Extra bytes μετά το `IEND`** (πολλά viewers αγνοούν τα trailing bytes)
- **Non-standard ancillary chunks** που μεταφέρουν payloads
- **Corrupted headers** που κρύβουν τις διαστάσεις ή προκαλούν failure στους parsers μέχρι να διορθωθούν

High-signal chunk locations προς έλεγχο:

- `tEXt` / `iTXt` / `zTXt` (text metadata, μερικές φορές compressed)
- `iCCP` (ICC profile) και άλλα ancillary chunks που χρησιμοποιούνται ως carrier
- `eXIf` (EXIF data σε PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Τι να αναζητήσετε:

- Παράξενοι συνδυασμοί width/height/bit-depth/colour-type
- Σφάλματα CRC/chunk (το pngcheck συνήθως υποδεικνύει το ακριβές offset)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε μια πιο λεπτομερή προβολή των chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Χρήσιμες αναφορές:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, και περιορισμοί του ELA

### Technique

Το JPEG δεν αποθηκεύεται ως raw pixels· συμπιέζεται στο DCT domain. Γι’ αυτό τα JPEG stego tools διαφέρουν από τα PNG LSB tools:

- Τα metadata/comment payloads βρίσκονται σε επίπεδο αρχείου (high-signal και γρήγορα στην επιθεώρηση)
- Τα DCT-domain stego tools ενσωματώνουν bits σε frequency coefficients

Σε operational επίπεδο, αντιμετωπίστε το JPEG ως:

- Container για metadata segments (high-signal, γρήγορα στην επιθεώρηση)
- Compressed signal domain (DCT coefficients), όπου λειτουργούν εξειδικευμένα stego tools

### Γρήγοροι έλεγχοι
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Τοποθεσίες υψηλού σήματος:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` για EXIF, `APPn` για vendor data)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Αν αντιμετωπίζετε συγκεκριμένα steghide payloads σε JPEGs, εξετάστε τη χρήση του `stegseek` (faster bruteforce από παλαιότερα scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

Το ELA επισημαίνει διαφορετικά recompression artifacts· μπορεί να σας υποδείξει περιοχές που έχουν υποστεί επεξεργασία, αλλά δεν είναι από μόνο του stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Κινούμενες εικόνες

### Technique

Για κινούμενες εικόνες, θεωρήστε ότι το μήνυμα:

- Βρίσκεται σε ένα μόνο frame (εύκολο), ή
- Είναι κατανεμημένο σε πολλά frames (η σειρά έχει σημασία), ή
- Είναι ορατό μόνο όταν κάνετε diff σε διαδοχικά frames

### Εξαγωγή frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Στη συνέχεια χειρίσου τα καρέ όπως τα κανονικά PNG: `zsteg`, `pngcheck`, απομόνωση καναλιών.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή καρέ)
- `imagemagick`/`magick` για μετασχηματισμούς ανά καρέ

Η αφαίρεση διαφορών μεταξύ καρέ είναι συχνά καθοριστική:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Κωδικοποίηση APNG με καταμέτρηση pixel

- Εντοπισμός containers APNG: `exiftool -a -G1 file.png | grep -i animation` ή `file`.
- Εξαγωγή frames χωρίς re-timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Ανάκτηση payloads κωδικοποιημένων ως μετρήσεις pixel ανά frame:
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
Τα Animated challenges μπορεί να κωδικοποιούν κάθε byte ως το πλήθος ενός συγκεκριμένου χρώματος σε κάθε frame· η συνένωση των μετρήσεων ανακατασκευάζει το μήνυμα.<sup>[[1]](#references)</sup>

## Ενσωμάτωση με προστασία κωδικού πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται με passphrase αντί για χειρισμό σε επίπεδο pixel, αυτή είναι συνήθως η ταχύτερη λύση.

### steghide

Υποστηρίζει `JPEG, BMP, WAV, AU` και μπορεί να ενσωματώνει/εξάγει κρυπτογραφημένα payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Υποστηρίζει PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Αναφορές

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
