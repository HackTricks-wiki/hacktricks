# Στεγανογραφία εικόνας

{{#include ../../banners/hacktricks-training.md}}

Το image stego σε CTF συνήθως εμπίπτει σε μία από τις εξής κατηγορίες:

- LSB/bit-planes (PNG/BMP)
- Payloads σε metadata/comments
- Παράξενη συμπεριφορά ή επιδιόρθωση κατεστραμμένων PNG chunks
- Εργαλεία JPEG στο πεδίο DCT (OutGuess κ.λπ.)
- Βασισμένα σε frames (GIF/APNG)

## Γρήγορος αρχικός έλεγχος

Δώστε προτεραιότητα στα στοιχεία σε επίπεδο container πριν από την εις βάθος ανάλυση περιεχομένου. Δείτε τη [γενική ροή εργασίας stego](../workflow/) για αναγνώριση αρχείων και carving πριν από ελέγχους ειδικά για εικόνες.

- Επικυρώστε το αρχείο και ελέγξτε τη δομή: `file`, `magick identify -verbose`, validators μορφής (π.χ. `pngcheck`).
- Εξαγάγετε metadata και ορατά strings: `exiftool -a -u -g1`, `strings`.
- Ελέγξτε για ενσωματωμένο ή προσαρτημένο περιεχόμενο: `binwalk` και επιθεώρηση του τέλους του αρχείου (`tail | xxd`).
- Επιλέξτε προσέγγιση ανάλογα με το container:
  - PNG/BMP: bit-planes/LSB και ανωμαλίες σε επίπεδο chunk.
  - JPEG: metadata + εργαλεία στο πεδίο DCT (οικογένειες τύπου OutGuess/F5).
  - GIF/APNG: εξαγωγή frames, σύγκριση διαφορών μεταξύ frames, τεχνικές με palette.

## Bit-planes / LSB

### Τεχνική

Τα PNG/BMP είναι δημοφιλή στα CTF επειδή αποθηκεύουν τα pixels με τρόπο που διευκολύνει τον **χειρισμό σε επίπεδο bit**. Ο κλασικός μηχανισμός απόκρυψης/εξαγωγής είναι ο εξής:

- Κάθε κανάλι pixel (R/G/B/A) έχει πολλαπλά bits.
- Το **λιγότερο σημαντικό bit** (LSB) κάθε καναλιού αλλάζει ελάχιστα την εικόνα.
- Οι επιτιθέμενοι κρύβουν δεδομένα σε αυτά τα bits χαμηλής τάξης, μερικές φορές χρησιμοποιώντας stride, permutation ή επιλογή ανά κανάλι.

Τι να περιμένετε στις προκλήσεις:

- Το payload βρίσκεται μόνο σε ένα κανάλι (π.χ. στο LSB του `R`).
- Το payload βρίσκεται στο κανάλι alpha.
- Το payload συμπιέζεται/κωδικοποιείται μετά την εξαγωγή.
- Το μήνυμα κατανέμεται σε planes ή κρύβεται μέσω XOR μεταξύ planes.

Επιπλέον οικογένειες που μπορεί να συναντήσετε (ανάλογα με την υλοποίηση):

- **LSB matching** (όχι απλώς αντιστροφή του bit, αλλά προσαρμογές +/-1 ώστε να αντιστοιχεί στο bit-στόχο)
- **Απόκρυψη βάσει palette/index** (indexed PNG/GIF: payload στους δείκτες χρωμάτων αντί για ακατέργαστες τιμές RGB)
- **Payloads μόνο στο alpha** (εντελώς αόρατα στην προβολή RGB)

### Δείκτες palette σε indexed-color εικόνες

Ένα indexed PNG ή GIF αποθηκεύει έναν **δείκτη** palette ανά pixel, όχι ένα RGB triplet. Δύο δείκτες μπορούν να αντιστοιχούν στο ίδιο ορατό χρώμα, οπότε η μετατροπή σε RGB πριν από την ανάλυση μπορεί να σβήσει την κρυφή διάκριση. Εξετάστε τις διπλότυπες ή σχεδόν διπλότυπες εγγραφές palette και, στη συνέχεια, αποδώστε μια δυαδική μάσκα για τα pixels που χρησιμοποιούν κάθε ύποπτο δείκτη. Αυτή η μέθοδος έχει αποκαλύψει κρυφό κείμενο και αλλαγές σε QR code σε πρόσφατες προκλήσεις GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Για ένα indexed PNG με ένα frame (ή το **πρώτο frame** ενός GIF), διατηρήστε τη λειτουργία `P` του Pillow και αλλάξτε το `target` σε έναν ενδιαφέροντα δείκτη που αναφέρει το script. Ελέγξτε τη διαφάνεια (`tRNS` ή δείκτη διαφάνειας GIF) καθώς και το RGB όταν επιλέγετε δείκτες.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Για animated GIF, εξετάστε τα καρέ ξεχωριστά. Το Pillow συνήθως μετατρέπει τα επόμενα καρέ σε RGB/RGBA κατά τη σύνθεση· το `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` διατηρεί τη λειτουργία `P` μόνο όσο η παλέτα δεν αλλάζει. Αν ένα καρέ έχει τοπική παλέτα ή έχει ήδη συντεθεί, εξετάστε τα αρχικά δεδομένα καρέ με δείκτες αντί να θεωρείτε ότι τα pixel που μετατράπηκαν σε RGB είναι δείκτες.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Εργαλεία

#### zsteg

Το `zsteg` απαριθμεί πολλά μοτίβα εξαγωγής LSB/bit-plane για PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: εκτελεί μια σειρά μετασχηματισμών (μεταδεδομένα, μετασχηματισμούς εικόνας, brute forcing παραλλαγών LSB).
- `stegsolve`: χειροκίνητα οπτικά φίλτρα (απομόνωση καναλιών, επιθεώρηση επιπέδων, XOR κ.λπ.).

Λήψη του Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Τεχνικές ορατότητας με βάση το FFT

Το FFT δεν είναι εξαγωγή LSB· χρησιμοποιείται σε περιπτώσεις όπου το περιεχόμενο είναι σκόπιμα κρυμμένο στον χώρο συχνοτήτων ή σε διακριτικά μοτίβα.

- Επίδειξη EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Συχνά χρησιμοποιούνται εργαλεία διαλογής μέσω web σε CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Εσωτερικά στοιχεία PNG: chunks, αλλοίωση και κρυφά δεδομένα

### Τεχνική

Το PNG είναι μορφή που αποτελείται από chunks. Σε πολλές προκλήσεις, το payload αποθηκεύεται στο επίπεδο του container/chunk και όχι στις τιμές των pixel:

- **Επιπλέον bytes μετά το `IEND`** (πολλά προγράμματα προβολής αγνοούν τα bytes που ακολουθούν)
- **Μη τυπικά ancillary chunks** που μεταφέρουν payload· δείτε τη [ροή εργασίας για την περιήγηση στα chunks PNG και το carving](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Αλλοιωμένες κεφαλίδες** που αποκρύπτουν τις διαστάσεις ή προκαλούν σφάλματα στους parsers μέχρι να διορθωθούν

Σημεία των chunks με υψηλή πιθανότητα να περιέχουν χρήσιμα δεδομένα:

- `tEXt` / `iTXt` / `zTXt` (μεταδεδομένα κειμένου, μερικές φορές συμπιεσμένα)
- `iCCP` (προφίλ ICC) και άλλα ancillary chunks που χρησιμοποιούνται ως φορείς
- `eXIf` (δεδομένα EXIF σε PNG)

### Bytes φίλτρου scanline PNG ως φορέας

Το PNG αποθηκεύει ένα byte τύπου φίλτρου (0–4) πριν από κάθε scanline στη μη συμπιεσμένη ροή `IDAT`. Αυτά τα bytes δεν είναι τιμές pixel· τα αποκωδικοποιημένα RGB pixels δεν διατηρούν τις αρχικές επιλογές φίλτρου, ενώ η επανακωδικοποίηση μπορεί να τις αλλάξει. Ένας encoder μπορεί νόμιμα να χρησιμοποιεί διαφορετικά φίλτρα, αλλά σκόπιμα μοτίβα μπορούν να κωδικοποιήσουν ένα σύντομο μήνυμα· σε πρόσφατη πρόκληση, οι τιμές φίλτρου 1–4 χρησιμοποιήθηκαν ως σύμβολα δύο bit. Εξετάστε το **αρχικό αρχείο** και συνενώστε όλα τα δεδομένα `IDAT` πριν από την αποσυμπίεση. Για την ακόλουθη περίπτωση μη διεμπλεκόμενων εικόνων RGB/RGBA 8-bit, το stride ισούται με το πλάτος επί τον αριθμό καναλιών· οι εικόνες Adam7 απαιτούν πλάτη scanline ειδικά για κάθε πέρασμα.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Λίστα των bytes φίλτρου scanline PNG χωρίς επανακωδικοποίηση</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Εκτελέστε το ως `python3 filters.py suspect.png`. Ελέγξτε αν η ακολουθία των φίλτρων, αντί για τα αποκωδικοποιημένα pixel, ακολουθεί μια εύλογη αντιστοίχιση συμβόλων. Η αντιστοίχιση εξαρτάται από την πρόκληση· η απλή ποικιλία δεν αποδεικνύει την ύπαρξη steganography.<sup>[[3]](#references)[[7]](#references)</sup>

### Εντολές αρχικής διαλογής

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Τι να αναζητήσετε:

- Ασυνήθιστους συνδυασμούς πλάτους/ύψους/βάθους bit/τύπου χρώματος
- Σφάλματα CRC/chunk (το pngcheck συνήθως υποδεικνύει την ακριβή μετατόπιση)
- Προειδοποιήσεις για πρόσθετα δεδομένα μετά το `IEND`

Αν χρειάζεστε λεπτομερέστερη προβολή των chunks:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Χρήσιμες αναφορές:

- Προδιαγραφή PNG (δομή, chunks): https://www.w3.org/TR/PNG/
- Τεχνάσματα μορφών αρχείων (ειδικές περιπτώσεις PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, εργαλεία στο πεδίο DCT και περιορισμοί του ELA

### Τεχνική

Το JPEG δεν αποθηκεύεται ως ακατέργαστα pixel· συμπιέζεται στο πεδίο DCT. Γι’ αυτό τα εργαλεία stego για JPEG διαφέρουν από τα εργαλεία PNG LSB:

- Τα payload των metadata/σχολίων βρίσκονται σε επίπεδο αρχείου (έντονη ένδειξη και γρήγορος έλεγχος)
- Τα εργαλεία stego στο πεδίο DCT ενσωματώνουν bit στους συντελεστές συχνότητας

Πρακτικά, αντιμετωπίστε το JPEG ως:

- Ένα container για τμήματα metadata (έντονη ένδειξη, γρήγορος έλεγχος)
- Ένα συμπιεσμένο πεδίο σήματος (συντελεστές DCT), στο οποίο λειτουργούν εξειδικευμένα εργαλεία stego

### Γρήγοροι έλεγχοι

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Τοποθεσίες με ισχυρές ενδείξεις:

- Μεταδεδομένα EXIF/XMP/IPTC
- Τμήμα σχολίων JPEG (`COM`)
- Τμήματα εφαρμογών (`APP1` για EXIF, `APPn` για δεδομένα προμηθευτή)

### Συνήθη εργαλεία

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Αν αντιμετωπίζετε συγκεκριμένα payloads steghide σε JPEG, εξετάστε το ενδεχόμενο να χρησιμοποιήσετε το `stegseek` (ταχύτερο bruteforce από παλαιότερα scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Ανάλυση επιπέδου σφάλματος

Η ELA επισημαίνει διαφορετικά τεχνουργήματα επανασυμπίεσης· μπορεί να σας υποδείξει περιοχές που έχουν υποστεί επεξεργασία, αλλά δεν αποτελεί από μόνη της ανιχνευτή stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Κινούμενες εικόνες

### Τεχνική

Για κινούμενες εικόνες, υποθέστε ότι το μήνυμα βρίσκεται:

- Σε ένα μόνο καρέ (εύκολο), ή
- Κατανεμημένο σε πολλά καρέ (η σειρά έχει σημασία), ή
- Ορατό μόνο όταν κάνετε diff διαδοχικών καρέ

### Εξαγωγή καρέ

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Έπειτα, χειρίσου τα καρέ όπως τα κανονικά PNG: `zsteg`, `pngcheck`, απομόνωση καναλιών.

Εναλλακτικά εργαλεία:

- `gifsicle --explode anim.gif` (γρήγορη εξαγωγή καρέ)
- `imagemagick`/`magick` για μετασχηματισμούς ανά καρέ

Η σύγκριση διαφορών μεταξύ καρέ είναι συχνά καθοριστική:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Κωδικοποίηση με πλήθος pixel σε APNG

- Εντοπίστε containers APNG: `exiftool -a -G1 file.png | grep -i animation` ή `file`.
- Εξαγάγετε τα καρέ χωρίς αλλαγή χρονισμού: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Ανακτήστε τα payloads που είναι κωδικοποιημένα ως πλήθος pixel ανά καρέ:

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

Τα animated challenges μπορεί να κωδικοποιούν κάθε byte ως το πλήθος ενός συγκεκριμένου χρώματος σε κάθε frame· η συνένωση των μετρήσεων ανασυνθέτει το μήνυμα.<sup>[[1]](#references)</sup>

## Ενσωμάτωση με προστασία κωδικού πρόσβασης

Αν υποψιάζεστε ότι η ενσωμάτωση προστατεύεται με passphrase αντί να βασίζεται σε χειρισμό σε επίπεδο pixel, αυτή είναι συνήθως η ταχύτερη προσέγγιση.

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

- [1] [Flagvent 2025 (Medium) — ροζ, Η λίστα επιθυμιών του Santa, Χριστουγεννιάτικα μεταδεδομένα, Καταγεγραμμένος θόρυβος](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 write-up — Στριμμένα χρώματα](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Προδιαγραφή Portable Network Graphics (PNG), Τρίτη έκδοση](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Βαθιά κάτω υπάρχει κάτι στο νερό](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Μορφές αρχείων εικόνας του Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Προδιαγραφή GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF write-up](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
