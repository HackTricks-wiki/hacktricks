# Steganography εικόνας

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα CTF με stego εικόνων εμπίπτουν σε μία από τις εξής κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Payloads σε metadata/comments
- Παράξενη συμπεριφορά PNG chunks / επιδιόρθωση αλλοιώσεων
- Εργαλεία πεδίου DCT JPEG (OutGuess κ.λπ.)
- Βασισμένα σε frames (GIF/APNG)

## Γρήγορη διαλογή

Δώστε προτεραιότητα στα στοιχεία σε επίπεδο container πριν από τη λεπτομερή ανάλυση περιεχομένου:

- Επικυρώστε το αρχείο και επιθεωρήστε τη δομή: `file`, `magick identify -verbose`, validators μορφής (π.χ. `pngcheck`).
- Εξαγάγετε metadata και ορατές συμβολοσειρές: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για ενσωματωμένο/προσαρτημένο περιεχόμενο: `binwalk` και επιθεώρηση του τέλους του αρχείου (`tail | xxd`).
- Επιλέξτε κατεύθυνση ανάλογα με το container:
  - PNG/BMP: bit-planes/LSB και ανωμαλίες σε επίπεδο chunk.
  - JPEG: metadata + εργαλεία πεδίου DCT (οικογένειες τύπου OutGuess/F5).
  - GIF/APNG: εξαγωγή frames, σύγκριση διαφορών μεταξύ frames, τεχνικές με παλέτες.

## Bit-planes / LSB

### Τεχνική

Τα PNG/BMP είναι δημοφιλή στα CTF επειδή αποθηκεύουν τα pixels με τρόπο που διευκολύνει τον **χειρισμό σε επίπεδο bit**. Ο κλασικός μηχανισμός απόκρυψης/εξαγωγής είναι ο εξής:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλαπλά bits.
- Το **λιγότερο σημαντικό bit** (LSB) κάθε καναλιού αλλάζει ελάχιστα την εικόνα.
- Οι επιτιθέμενοι κρύβουν δεδομένα σε αυτά τα bit χαμηλής τάξης, μερικές φορές χρησιμοποιώντας stride, permutation ή επιλογή ανά κανάλι.

Τι να περιμένετε στα challenges:

- Το payload βρίσκεται σε ένα μόνο κανάλι (π.χ. στο LSB του `R`).
- Το payload βρίσκεται στο κανάλι alpha.
- Το payload είναι συμπιεσμένο/κωδικοποιημένο μετά την εξαγωγή.
- Το μήνυμα είναι κατανεμημένο σε planes ή κρυμμένο μέσω XOR μεταξύ planes.

Πρόσθετες οικογένειες που μπορεί να συναντήσετε (ανάλογα με την υλοποίηση):

- **LSB matching** (όχι απλώς αντιστροφή του bit, αλλά προσαρμογές +/-1 ώστε να ταιριάζει με το επιθυμητό bit)
- **Απόκρυψη βάσει παλέτας/δεικτών** (indexed PNG/GIF: payload στους δείκτες χρωμάτων αντί για raw RGB)
- **Payload μόνο στο alpha** (εντελώς αόρατο σε προβολή RGB)

### Εργαλεία

#### zsteg

Το `zsteg` εντοπίζει και εξάγει δεδομένα με πολλά μοτίβα LSB/bit-plane για PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: εκτελεί μια σειρά μετασχηματισμών (metadata, μετασχηματισμούς εικόνας, brute forcing παραλλαγών LSB).
- `stegsolve`: χειροκίνητα οπτικά φίλτρα (απομόνωση καναλιών, επιθεώρηση επιπέδων, XOR κ.λπ.).

Λήψη του Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Τεχνικές ορατότητας με βάση το FFT

Το FFT δεν είναι εξαγωγή LSB· χρησιμοποιείται όταν το περιεχόμενο είναι σκόπιμα κρυμμένο στον χώρο συχνοτήτων ή σε ανεπαίσθητα μοτίβα.

- Επίδειξη EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Τα εργαλεία διαλογής μέσω ιστού χρησιμοποιούνται συχνά σε CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Εσωτερική δομή PNG: chunks, αλλοίωση και κρυφά δεδομένα

### Τεχνική

Το PNG είναι μορφότυπο που αποτελείται από chunks. Σε πολλές προκλήσεις, το payload αποθηκεύεται στο επίπεδο του container/chunk και όχι στις τιμές των pixel:

- **Επιπλέον bytes μετά το `IEND`** (πολλά προγράμματα προβολής αγνοούν τα bytes που ακολουθούν)
- **Μη τυπικά ancillary chunks** που περιέχουν payload· δείτε τη [ροή εργασιών για περιήγηση στα PNG chunks και carving](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Αλλοιωμένες κεφαλίδες** που αποκρύπτουν διαστάσεις ή προκαλούν αστοχία στους parsers μέχρι να διορθωθούν

Σημαντικές θέσεις chunks προς έλεγχο:

- `tEXt` / `iTXt` / `zTXt` (metadata κειμένου, μερικές φορές συμπιεσμένα)
- `iCCP` (ICC profile) και άλλα ancillary chunks που χρησιμοποιούνται ως φορείς
- `eXIf` (δεδομένα EXIF σε PNG)

### Εντολές διαλογής

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Τι να αναζητήσετε:

- Παράξενοι συνδυασμοί πλάτους/ύψους/βάθους bit/τύπου χρώματος
- Σφάλματα CRC/chunk (το pngcheck συνήθως υποδεικνύει την ακριβή θέση)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε λεπτομερέστερη προβολή των chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Χρήσιμες αναφορές:

- Προδιαγραφή PNG (δομή, chunks): https://www.w3.org/TR/PNG/
- Κόλπα σε μορφές αρχείων (ειδικές περιπτώσεις PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: μεταδεδομένα, εργαλεία στο πεδίο DCT και περιορισμοί του ELA

### Τεχνική

Το JPEG δεν αποθηκεύεται ως ακατέργαστα pixel· συμπιέζεται στο πεδίο DCT. Γι’ αυτό τα εργαλεία stego για JPEG διαφέρουν από τα εργαλεία LSB για PNG:

- Τα payload μεταδεδομένων/σχολίων βρίσκονται σε επίπεδο αρχείου (εύκολα εντοπίσιμα και γρήγορα στην επιθεώρηση)
- Τα εργαλεία stego στο πεδίο DCT ενσωματώνουν bit στους συντελεστές συχνότητας

Σε επιχειρησιακό επίπεδο, αντιμετωπίστε το JPEG ως:

- Ένα container για τμήματα μεταδεδομένων (εύκολα εντοπίσιμα και γρήγορα στην επιθεώρηση)
- Ένα συμπιεσμένο πεδίο σήματος (συντελεστές DCT), όπου λειτουργούν εξειδικευμένα εργαλεία stego

### Γρήγοροι έλεγχοι

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Σημεία με ισχυρές ενδείξεις:

- Μεταδεδομένα EXIF/XMP/IPTC
- Τμήμα σχολίου JPEG (`COM`)
- Τμήματα εφαρμογής (`APP1` για EXIF, `APPn` για δεδομένα προμηθευτή)

### Συνήθη εργαλεία

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Αν αντιμετωπίζετε συγκεκριμένα payloads steghide σε JPEG, εξετάστε το ενδεχόμενο να χρησιμοποιήσετε το `stegseek` (ταχύτερο bruteforce από παλαιότερα scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

Το ELA αναδεικνύει διαφορετικά τεχνουργήματα επανασυμπίεσης· μπορεί να σας υποδείξει περιοχές που έχουν τροποποιηθεί, αλλά από μόνο του δεν αποτελεί ανιχνευτή stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Κινούμενες εικόνες

### Τεχνική

Για κινούμενες εικόνες, υποθέστε ότι το μήνυμα είναι:

- Σε ένα μόνο καρέ (εύκολο), ή
- Κατανεμημένο σε πολλά καρέ (η σειρά έχει σημασία), ή
- Ορατό μόνο όταν συγκρίνετε διαδοχικά καρέ

### Εξαγωγή καρέ

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Στη συνέχεια, χειρίσου τα καρέ όπως τα κανονικά PNG: `zsteg`, `pngcheck`, απομόνωση καναλιών.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή καρέ)
- `imagemagick`/`magick` για μετασχηματισμούς ανά καρέ

Η σύγκριση διαφορών μεταξύ καρέ είναι συχνά καθοριστική:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Κωδικοποίηση μετρήσεων pixel σε APNG

- Εντοπίστε τα containers APNG: `exiftool -a -G1 file.png | grep -i animation` ή `file`.
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

Οι animated challenges μπορεί να κωδικοποιούν κάθε byte ως το πλήθος ενός συγκεκριμένου χρώματος σε κάθε frame· η συνένωση των πληθών ανασυνθέτει το μήνυμα.<sup>[[1]](#references)</sup>

## Ενσωμάτωση με προστασία κωδικού πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται με passphrase και όχι με χειρισμό σε επίπεδο pixel, αυτή είναι συνήθως η ταχύτερη προσέγγιση.

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



## References

- [1] [Flagvent 2025 (Μεσαίο) — ροζ, Λίστα επιθυμιών του Santa, Χριστουγεννιάτικα μεταδεδομένα, Καταγεγραμμένος θόρυβος](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
