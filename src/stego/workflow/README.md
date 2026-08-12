# Ροή εργασίας Stego

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα προβλήματα Stego επιλύονται ταχύτερα με συστηματικό triage παρά με τη δοκιμή τυχαίων εργαλείων.

## Βασική ροή

### Λίστα ελέγχου γρήγορου triage

Ο στόχος είναι να απαντηθούν αποτελεσματικά δύο ερωτήσεις:

1. Ποιο είναι το πραγματικό container/format;
2. Βρίσκεται το payload σε metadata, σε appended bytes, σε embedded files ή σε content-level stego;

#### 1) Εντοπισμός του container
```bash
file target
ls -lah target
```
Αν το `file` και η επέκταση διαφωνούν, εξετάστε την υπογραφή αντί να εμπιστευτείτε την κατάληξη. Το `file` βασίζεται επίσης σε ευρετικές μεθόδους και μπορεί να παραπλανηθεί από κακοσχηματισμένη ή polyglot είσοδο. Αντιμετωπίστε τις συνηθισμένες μορφές ως containers όπου αρμόζει (για παράδειγμα, τα έγγραφα OOXML είναι πακέτα ZIP).<sup>[[2]](#references)</sup>

#### 2) Αναζητήστε μεταδεδομένα και προφανή strings
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
Αν η εξαγωγή αποτύχει αλλά αναφέρονται signatures, κάντε χειροκίνητα carve τα offsets με `dd` και εκτελέστε ξανά το `file` στην περιοχή που έγινε carve.

#### 4) Αν είναι εικόνα

- Ελέγξτε για anomalies: `magick identify -verbose file`
- Αν είναι PNG/BMP, απαριθμήστε bit-planes/LSB: `zsteg -a file.png`
- Επικυρώστε τη δομή PNG: `pngcheck -v file.png`
- Χρησιμοποιήστε visual filters (Stegsolve / StegoVeritas) όταν το περιεχόμενο μπορεί να αποκαλυφθεί μέσω μετασχηματισμών καναλιών/planes

#### 5) Αν είναι audio

- Πρώτα spectrogram (Sonic Visualiser)
- Αποκωδικοποιήστε/επιθεωρήστε streams: `ffmpeg -v info -i file -f null -`
- Αν το audio μοιάζει με structured tones, δοκιμάστε DTMF decoding

### Βασικά εργαλεία

Αυτά εντοπίζουν συχνές περιπτώσεις σε επίπεδο container: payloads σε metadata, appended bytes και embedded files που μεταμφιέζονται μέσω extension.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Αποθετήριο του project: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### αρχείο / συμβολοσειρές
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data και polyglot tricks

Πολλές προκλήσεις στεγανογραφίας περιλαμβάνουν extra bytes μετά από ένα έγκυρο αρχείο ή embedded archives που μεταμφιέζονται μέσω extension.

#### Appended payloads

Πολλά formats αγνοούν τα trailing bytes. Ένα ZIP/PDF/script μπορεί να προσαρτηθεί σε ένα image/audio container.

Γρήγοροι έλεγχοι:
```bash
binwalk file
tail -c 200 file | xxd
```
Αν γνωρίζετε ένα offset, κάντε carve με το `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Όταν το `file` μπερδεύεται, αναζητήστε magic bytes με το `xxd` και συγκρίνετέ τα με γνωστές υπογραφές:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Δοκιμάστε τα `7z` και `unzip`, ακόμη κι αν η επέκταση δεν υποδεικνύει ότι πρόκειται για zip:
```bash
7z l file
unzip -l file
```
### Παράξενες περιπτώσεις κοντά στο stego

Γρήγοροι σύνδεσμοι για μοτίβα που εμφανίζονται τακτικά δίπλα σε stego (QR-from-binary, braille κ.λπ.).

#### QR codes από binary

Αν το μήκος ενός blob είναι τέλειο τετράγωνο, μπορεί να αποτελεί ακατέργαστα pixels για μια εικόνα/QR.
```python
import math
math.isqrt(2500)  # 50
```
Βοηθητικό εργαλείο μετατροπής δυαδικού σε εικόνα:

- Βοηθητικό εργαλείο binary-image του dCode.<sup>[[5]](#references)</sup>

#### Braille

- Μεταφραστής Braille του Branah.<sup>[[6]](#references)</sup>

Για ευρύτερες συλλογές εργαλείων steganography και πόρων ειδικά για τεχνικές, δείτε το συνοδευτικό stego-toolkit και την επιμελημένη λίστα του 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker image με τα δημοφιλέστερα εργαλεία steganography σε ενιαίο πακέτο](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Συμβάσεις ECMA-376 Open Packaging](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Δυαδική εικόνα](https://www.dcode.fr/binary-image)
- [6] [Branah — Μεταφραστής Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Πόροι steganography](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
