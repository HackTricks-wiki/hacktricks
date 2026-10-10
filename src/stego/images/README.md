# Steganography εικόνας

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα CTF image stego περιορίζονται σε μία από τις εξής κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Payloads σε metadata/comments
- Παράξενη συμπεριφορά PNG chunks / επιδιόρθωση αλλοιώσεων
- Εργαλεία για το πεδίο DCT JPEG (OutGuess κ.λπ.)
- Βασισμένα σε frames (GIF/APNG)

## Γρήγορη διαλογή

Δώστε προτεραιότητα στα στοιχεία επιπέδου container πριν από τη βαθιά ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και εξετάστε τη δομή: `file`, `magick identify -verbose`, validators μορφής (π.χ. `pngcheck`).
- Εξαγάγετε metadata και ορατές συμβολοσειρές: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για ενσωματωμένο/προσαρτημένο περιεχόμενο: `binwalk` και επιθεώρηση του τέλους του αρχείου (`tail | xxd`).
- Επιλέξτε κατεύθυνση ανάλογα με το container:
  - PNG/BMP: bit-planes/LSB και ανωμαλίες σε επίπεδο chunk.
  - JPEG: metadata και εργαλεία για το πεδίο DCT (οικογένειες τύπου OutGuess/F5).
  - GIF/APNG: εξαγωγή frames, διαφορές μεταξύ frames, τεχνικές με παλέτες.

## Bit-planes / LSB

### Τεχνική

Τα PNG/BMP είναι δημοφιλή στα CTF επειδή αποθηκεύουν τα pixels με τρόπο που διευκολύνει τον **χειρισμό σε επίπεδο bit**. Ο κλασικός μηχανισμός απόκρυψης/εξαγωγής είναι ο εξής:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλά bits.
- Το **λιγότερο σημαντικό bit** (LSB) κάθε καναλιού αλλάζει ελάχιστα την εικόνα.
- Οι επιτιθέμενοι κρύβουν δεδομένα σε αυτά τα bits χαμηλής τάξης, μερικές φορές χρησιμοποιώντας βήμα, μετάθεση ή επιλογή ανά κανάλι.

Τι να περιμένετε στις προκλήσεις:

- Το payload βρίσκεται μόνο σε ένα κανάλι (π.χ. LSB του `R`).
- Το payload βρίσκεται στο κανάλι alpha.
- Το payload συμπιέζεται/κωδικοποιείται μετά την εξαγωγή.
- Το μήνυμα κατανέμεται σε planes ή κρύβεται μέσω XOR μεταξύ planes.

Πρόσθετες κατηγορίες που μπορεί να συναντήσετε (ανάλογα με την υλοποίηση):

- **LSB matching** (όχι απλώς αντιστροφή του bit, αλλά προσαρμογές +/-1 ώστε να ταιριάζει το bit-στόχος)
- **Απόκρυψη βάσει παλέτας/δεικτών** (indexed PNG/GIF: το payload βρίσκεται στους δείκτες χρωμάτων και όχι στις ακατέργαστες τιμές RGB)
- **Payloads μόνο στο alpha** (εντελώς αόρατα σε προβολή RGB)

### Εργαλεία

#### zsteg

Το `zsteg` εξετάζει πολλά μοτίβα εξαγωγής LSB/bit-plane για PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: εκτελεί μια σειρά από μετασχηματισμούς (metadata, μετασχηματισμούς εικόνας, brute forcing παραλλαγών LSB).
- `stegsolve`: χειροκίνητα οπτικά φίλτρα (απομόνωση καναλιών, επιθεώρηση επιπέδων, XOR κ.λπ.).

Λήψη του Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Τεχνικές ανάδειξης με βάση το FFT

Το FFT δεν είναι εξαγωγή LSB· χρησιμοποιείται όταν το περιεχόμενο είναι σκόπιμα κρυμμένο στον χώρο συχνοτήτων ή σε διακριτικά μοτίβα.

- Demo του EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Η διαδικτυακή αρχική διαλογή χρησιμοποιείται συχνά σε CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Εσωτερικά του PNG: chunks, αλλοίωση και κρυφά δεδομένα

### Τεχνική

Το PNG είναι μορφότυπος που αποτελείται από chunks. Σε πολλές προκλήσεις, το payload αποθηκεύεται σε επίπεδο container/chunk και όχι στις τιμές των pixel:

- **Επιπλέον bytes μετά το `IEND`** (πολλά προγράμματα προβολής αγνοούν τα bytes που ακολουθούν)
- **Μη τυπικά ancillary chunks** που μεταφέρουν payloads
- **Αλλοιωμένες κεφαλίδες** που κρύβουν τις διαστάσεις ή κάνουν τους parsers να αποτυγχάνουν μέχρι να διορθωθούν

Σημεία των chunks με υψηλή πιθανότητα να περιέχουν δεδομένα, τα οποία αξίζει να ελεγχθούν:

- `tEXt` / `iTXt` / `zTXt` (metadata κειμένου, μερικές φορές συμπιεσμένα)
- `iCCP` (προφίλ ICC) και άλλα ancillary chunks που χρησιμοποιούνται ως φορείς
- `eXIf` (δεδομένα EXIF σε PNG)

### Εντολές αρχικής διαλογής

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Τι να αναζητήσετε:

- Παράξενοι συνδυασμοί πλάτους/ύψους/βάθους bit/τύπου χρώματος
- Σφάλματα CRC/chunk (το pngcheck συνήθως υποδεικνύει την ακριβή μετατόπιση)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε μια πιο λεπτομερή προβολή των chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Χρήσιμες αναφορές:

- Προδιαγραφή PNG (δομή, chunks): https://www.w3.org/TR/PNG/
- Κόλπα με τις μορφές αρχείων (ειδικές περιπτώσεις PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, εργαλεία στο πεδίο DCT και περιορισμοί του ELA

### Τεχνική

Το JPEG δεν αποθηκεύεται ως ακατέργαστα pixels· συμπιέζεται στο πεδίο DCT. Γι’ αυτό τα εργαλεία stego για JPEG διαφέρουν από τα εργαλεία LSB για PNG:

- Τα payloads metadata/comment βρίσκονται σε επίπεδο αρχείου (υψηλής ένδειξης και γρήγορα στον έλεγχο)
- Τα εργαλεία stego στο πεδίο DCT ενσωματώνουν bits σε συντελεστές συχνότητας

Στην πράξη, αντιμετωπίστε το JPEG ως:

- Ένα container για τμήματα metadata (υψηλής ένδειξης, γρήγορα στον έλεγχο)
- Ένα συμπιεσμένο πεδίο σήματος (συντελεστές DCT), στο οποίο λειτουργούν εξειδικευμένα εργαλεία stego

### Γρήγοροι έλεγχοι

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Τοποθεσίες με υψηλή πιθανότητα:

- Μεταδεδομένα EXIF/XMP/IPTC
- Τμήμα σχολίων JPEG (`COM`)
- Τμήματα εφαρμογών (`APP1` για EXIF, `APPn` για δεδομένα προμηθευτή)

### Συνήθη εργαλεία

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Αν αντιμετωπίζετε συγκεκριμένα payloads steghide σε JPEG, εξετάστε το ενδεχόμενο χρήσης του `stegseek` (ταχύτερο bruteforce από παλαιότερα scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Ανάλυση επιπέδων σφάλματος

Η ELA αναδεικνύει διαφορετικά artifacts επανασυμπίεσης· μπορεί να σας κατευθύνει σε περιοχές που έχουν υποστεί επεξεργασία, αλλά δεν είναι από μόνη της ανιχνευτής stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Κινούμενες εικόνες

### Τεχνική

Για κινούμενες εικόνες, θεωρήστε ότι το μήνυμα:

- Βρίσκεται σε ένα μόνο καρέ (εύκολο), ή
- Είναι κατανεμημένο σε πολλά καρέ (η σειρά έχει σημασία), ή
- Είναι ορατό μόνο όταν συγκρίνετε διαδοχικά καρέ

### Εξαγωγή καρέ

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Στη συνέχεια, χειριστείτε τα καρέ όπως τα κανονικά PNG: `zsteg`, `pngcheck`, απομόνωση καναλιών.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή καρέ)
- `imagemagick`/`magick` για μετασχηματισμούς ανά καρέ

Η σύγκριση διαφορών μεταξύ καρέ είναι συχνά καθοριστική:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Κωδικοποίηση μετρήσεων pixel σε APNG

- Εντοπίστε containers APNG: `exiftool -a -G1 file.png | grep -i animation` ή `file`.
- Εξαγάγετε τα frames χωρίς αλλαγή χρονισμού: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Ανακτήστε τα payloads που έχουν κωδικοποιηθεί ως μετρήσεις pixel ανά frame:

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

Τα animated challenges μπορεί να κωδικοποιούν κάθε byte ως το πλήθος ενός συγκεκριμένου χρώματος σε κάθε frame· η συνένωση των πληθών ανασυνθέτει το μήνυμα.<sup>[[1]](#references)</sup>

## Ενσωμάτωση με προστασία κωδικού πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται με passphrase αντί για χειρισμό σε επίπεδο pixel, αυτή είναι συνήθως η ταχύτερη μέθοδος.

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

Αποθετήριο: https://github.com/Paradoxis/StegCracker

### stegpy

Υποστηρίζει PNG/BMP/GIF/WebP/WAV.

Αποθετήριο: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pink, Η λίστα επιθυμιών του Santa, Χριστουγεννιάτικα μεταδεδομένα, Καταγεγραμμένος θόρυβος](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
