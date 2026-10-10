# Stego Ροή εργασίας

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα προβλήματα stego λύνονται πιο γρήγορα με συστηματική αρχική αξιολόγηση παρά με τη δοκιμή τυχαίων εργαλείων.

## Βασική ροή

### Γρήγορη λίστα ελέγχου αρχικής αξιολόγησης

Στόχος είναι να απαντηθούν αποτελεσματικά δύο ερωτήματα:

1. Ποιος είναι ο πραγματικός container/format;
2. Βρίσκεται το payload στα metadata, σε bytes που έχουν προστεθεί, σε ενσωματωμένα αρχεία ή σε stego επιπέδου περιεχομένου;

#### 1) Αναγνώριση του container

```bash
file target
ls -lah target
```

Αν το `file` και η επέκταση διαφωνούν, εξετάστε την υπογραφή αντί να εμπιστευτείτε την κατάληξη. Το `file` βασίζεται επίσης σε ευρετικές μεθόδους και μπορεί να ξεγελαστεί από κακοσχηματισμένα ή πολυγλωσσικά δεδομένα εισόδου. Αντιμετωπίστε τις συνήθεις μορφές ως containers όταν χρειάζεται (για παράδειγμα, τα έγγραφα OOXML είναι πακέτα ZIP).<sup>[[2]](#references)</sup>

#### 2) Αναζητήστε μεταδεδομένα και εμφανείς συμβολοσειρές

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Δοκιμάστε πολλαπλές κωδικοποιήσεις:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Έλεγχος για προσαρτημένα δεδομένα / ενσωματωμένα αρχεία

```bash
binwalk target
binwalk -e target
```

Αν η εξαγωγή αποτύχει, αλλά αναφέρονται signatures, κάντε χειροκίνητα carve στα offsets με `dd` και εκτελέστε ξανά το `file` στην περιοχή που απομονώθηκε.

#### 4) Αν πρόκειται για εικόνα

- Ελέγξτε για ανωμαλίες: `magick identify -verbose file`
- Αν είναι PNG/BMP, εξετάστε τα bit-planes/LSB: `zsteg -a file.png`
- Επικυρώστε τη δομή PNG: `pngcheck -v file.png`
- Χρησιμοποιήστε οπτικά φίλτρα (Stegsolve / StegoVeritas) όταν το περιεχόμενο μπορεί να αποκαλυφθεί με μετασχηματισμούς καναλιών/plane

#### 5) Αν πρόκειται για ήχο

- Ξεκινήστε με spectrogram (Sonic Visualiser)
- Αποκωδικοποιήστε/επιθεωρήστε τα streams: `ffmpeg -v info -i file -f null -`
- Αν ο ήχος θυμίζει δομημένους τόνους, δοκιμάστε αποκωδικοποίηση DTMF

### Βασικά εργαλεία

Αυτά εντοπίζουν συχνές περιπτώσεις σε επίπεδο container: payloads στα metadata, bytes που έχουν προστεθεί στο τέλος και ενσωματωμένα αρχεία που κρύβονται με παραπλανητική επέκταση.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

Αποθετήριο: https://github.com/ReFirmLabs/binwalk

#### Foremost

```bash
foremost -i file
```

Αποθετήριο έργου: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Containers, appended data, and polyglot tricks

Πολλές προκλήσεις στεγανογραφίας περιλαμβάνουν επιπλέον bytes μετά από ένα έγκυρο αρχείο ή embedded archives που μεταμφιέζονται μέσω της επέκτασης αρχείου.

#### Appended payloads

Πολλές μορφές αρχείων αγνοούν τα bytes στο τέλος. Ένα ZIP/PDF/script μπορεί να προσαρτηθεί σε ένα image/audio container.

Γρήγοροι έλεγχοι:

```bash
binwalk file
tail -c 200 file | xxd
```

Αν γνωρίζετε ένα offset, κάντε carving με `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

Όταν το `file` μπερδεύεται, αναζήτησε magic bytes με το `xxd` και σύγκρινέ τα με γνωστές υπογραφές:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Δοκιμάστε 7z και unzip, ακόμα κι αν η επέκταση δεν λέει ότι είναι zip:

```bash
7z l file
unzip -l file
```

### Παράδοξα κοντά στο stego

Γρήγοροι σύνδεσμοι για μοτίβα που εμφανίζονται συχνά δίπλα στο stego (QR από δυαδικά δεδομένα, braille κ.λπ.).

#### QR codes από δυαδικά δεδομένα

Αν το μήκος ενός blob είναι τέλειο τετράγωνο, μπορεί να είναι ακατέργαστα pixels για εικόνα/QR.

```python
import math
math.isqrt(2500)  # 50
```

Βοηθητικό εργαλείο μετατροπής δυαδικών δεδομένων σε εικόνα:

- Βοηθητικό εργαλείο δυαδικής εικόνας του dCode.<sup>[[5]](#references)</sup>

#### Μπράιγ

- Μεταφραστής Μπράιγ της Branah.<sup>[[6]](#references)</sup>

Για ευρύτερες συλλογές εργαλείων στεγανογραφίας και πόρους για συγκεκριμένες τεχνικές, δείτε το ενσωματωμένο stego-toolkit και την επιμελημένη λίστα του 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Εικόνα Docker με τα δημοφιλέστερα εργαλεία στεγανογραφίας σε ένα πακέτο](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Συμβάσεις ανοιχτής συσκευασίας ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Δυαδική εικόνα](https://www.dcode.fr/binary-image)
- [6] [Branah — Μεταφραστής Μπράιγ](https://www.branah.com/braille-translator)
- [7] [0xRick - Πόροι στεγανογραφίας](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
