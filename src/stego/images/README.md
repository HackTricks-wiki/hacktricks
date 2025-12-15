# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα CTF image stego μειώνονται σε ένα από αυτά τα παρακάτω:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Δώστε προτεραιότητα σε αποδείξεις σε επίπεδο container πριν από βαθύτερη ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και επιθεωρήστε τη δομή: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Εξαγάγετε metadata και ορατές συμβολοσειρές: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για embedded/appended περιεχόμενο: `binwalk` και έλεγχος τέλους αρχείου (`tail | xxd`).
- Branch by container:
- PNG/BMP: bit-planes/LSB και ανωμαλίες σε επίπεδο chunks.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP είναι δημοφιλή σε CTFs επειδή αποθηκεύουν pixels με τρόπο που κάνει τον **bit-level manipulation** εύκολο. Ο κλασσικός μηχανισμός απόκρυψης/εξαγωγής είναι:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλαπλά bits.
- Το **least significant bit** (LSB) κάθε καναλιού αλλάζει την εικόνα πολύ λίγο.
- Οι επιτιθέμενοι κρύβουν δεδομένα σε αυτά τα low-order bits, μερικές φορές με stride, permutation, ή per-channel επιλογή.

Τι να περιμένετε στις προκλήσεις:

- Το payload βρίσκεται μόνο σε ένα κανάλι (π.χ., `R` LSB).
- Το payload βρίσκεται στο alpha κανάλι.
- Το payload είναι συμπιεσμένο/κωδικοποιημένο μετά την εξαγωγή.
- Το μήνυμα διασκορπίζεται across planes ή κρύβεται μέσω XOR μεταξύ planes.

Επιπλέον οικογένειες που μπορεί να συναντήσετε (implementation-dependent):

- **LSB matching** (όχι απλά flipping του bit, αλλά προσαρμογές +/-1 για να ταιριάξει το target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (εντελώς αόρατα στην εμφάνιση RGB)

### Tooling

#### zsteg

`zsteg` απαριθμεί πολλά πρότυπα εξαγωγής LSB/bit-plane για PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: τρέχει ένα σετ μετασχηματισμών (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: χειροκίνητα οπτικά φίλτρα (channel isolation, plane inspection, XOR, etc).

Λήψη Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

Το FFT δεν είναι LSB extraction· προορίζεται για περιπτώσεις όπου το περιεχόμενο κρύβεται σκόπιμα στον χώρο συχνοτήτων ή σε λεπτά μοτίβα.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage που συχνά χρησιμοποιείται σε CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

Το PNG είναι μια μορφή με chunks. Σε πολλές προκλήσεις το payload αποθηκεύεται σε επίπεδο container/chunk αντί για τις τιμές των pixels:

- **Extra bytes after `IEND`** (πολλά προγράμματα προβολής αγνοούν τα bytes που ακολουθούν)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** που κρύβουν διαστάσεις ή σπάνε τους parsers μέχρι να διορθωθούν

Τοποθεσίες chunks υψηλού ενδιαφέροντος για έλεγχο:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Τι να προσέξετε:

- Περίεργοι συνδυασμοί width/height/bit-depth/colour-type
- Σφάλματα CRC/chunk (pngcheck συνήθως δείχνει το ακριβές offset)
- Προειδοποιήσεις για επιπλέον δεδομένα μετά το `IEND`

Αν χρειάζεστε πιο λεπτομερή προβολή των chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Χρήσιμες αναφορές:

- PNG specification (δομή, chunks): https://www.w3.org/TR/PNG/
- Τεχνικές μορφής αρχείου (PNG/JPEG/GIF ακραίες περιπτώσεις): https://github.com/corkami/docs

## JPEG: μεταδεδομένα, DCT-domain tools, και περιορισμοί ELA

### Τεχνική

Τα JPEG δεν αποθηκεύονται ως raw pixels· συμπιέζονται στο DCT domain. Γι' αυτό τα JPEG stego tools διαφέρουν από τα PNG LSB tools:

- Metadata/comment payloads βρίσκονται σε επίπεδο αρχείου (υψηλό σήμα και γρήγορος έλεγχος)
- DCT-domain stego tools ενσωματώνουν bits σε συντελεστές συχνότητας

Σε λειτουργικό επίπεδο, αντιμετωπίζουμε το JPEG ως:

- Ένα δοχείο για metadata segments (υψηλό σήμα, γρήγορος έλεγχος)
- Μια συμπιεσμένη περιοχή σήματος (DCT coefficients) όπου λειτουργούν εξειδικευμένα stego tools

### Γρήγοροι έλεγχοι
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC μεταδεδομένα
- τμήμα σχολίων JPEG (`COM`)
- Τμήματα εφαρμογής (`APP1` για EXIF, `APPn` για δεδομένα προμηθευτή)

### Κοινά εργαλεία

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA highlights different recompression artifacts; it can point you to regions that were edited, but it’s not a stego detector by itself:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Κινούμενες εικόνες

### Τεχνική

Για κινούμενες εικόνες, υποθέστε ότι το μήνυμα είναι:

- Σε ένα μόνο καρέ (εύκολο), ή
- Διασκορπισμένο σε καρέ (η σειρά έχει σημασία), ή
- Ορατό μόνο όταν κάνετε diff στα διαδοχικά καρέ

### Εξαγωγή καρέ
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Στη συνέχεια αντιμετωπίστε τα frames όπως τα κανονικά PNG: `zsteg`, `pngcheck`, channel isolation.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή καρέ)
- `imagemagick`/`magick` για μετασχηματισμούς ανά καρέ

Frame differencing είναι συχνά καθοριστικό:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Ενσωμάτωση προστατευμένη με κωδικό πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται από φράση πρόσβασης αντί για χειρισμό σε επίπεδο pixel, αυτός είναι συνήθως ο ταχύτερος δρόμος.

### steghide

Υποστηρίζει `JPEG, BMP, WAV, AU` και μπορεί να ενσωματώσει/εξάγει κρυπτογραφημένα payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Υποστηρίζει PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
