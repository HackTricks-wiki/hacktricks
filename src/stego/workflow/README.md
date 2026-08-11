# Stego Ροή εργασίας

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα προβλήματα stego επιλύονται ταχύτερα με συστηματικό triage παρά με τη δοκιμή τυχαίων εργαλείων.

## Βασική ροή

### Γρήγορη λίστα ελέγχου triage

Ο στόχος είναι να απαντηθούν αποτελεσματικά δύο ερωτήσεις:

1. Ποιο είναι το πραγματικό container/format;
2. Βρίσκεται το payload στα metadata, σε προσαρτημένα bytes, σε embedded files ή σε content-level stego;

#### 1) Identify το container
```bash
file target
ls -lah target
```
Αν το `file` και η επέκταση διαφωνούν, διερευνήστε το signature αντί να εμπιστευτείτε το suffix. Το `file` είναι επίσης heuristic και μπορεί να μπερδευτεί από malformed ή polyglot input. Αντιμετωπίστε τα common formats ως containers όπου είναι κατάλληλο (για παράδειγμα, τα έγγραφα OOXML είναι ZIP packages).<sup>[[2]](#references)</sup>

#### 2) Αναζητήστε metadata και προφανή strings
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
Αν η εξαγωγή αποτύχει αλλά αναφερθούν signatures, κάντε χειροκίνητα carve στα offsets με `dd` και εκτελέστε ξανά το `file` στην περιοχή που έγινε carve.

#### 4) Αν είναι εικόνα

- Ελέγξτε για anomalies: `magick identify -verbose file`
- Αν είναι PNG/BMP, απαριθμήστε bit-planes/LSB: `zsteg -a file.png`
- Επικυρώστε τη δομή PNG: `pngcheck -v file.png`
- Χρησιμοποιήστε visual filters (Stegsolve / StegoVeritas) όταν το περιεχόμενο μπορεί να αποκαλυφθεί μέσω μετασχηματισμών καναλιών/planes

#### 5) Αν είναι audio

- Πρώτα spectrogram (Sonic Visualiser)
- Αποκωδικοποιήστε/επιθεωρήστε τα streams: `ffmpeg -v info -i file -f null -`
- Αν το audio μοιάζει με structured tones, δοκιμάστε DTMF decoding

### Βασικά και απαραίτητα εργαλεία

Αυτά εντοπίζουν συχνές περιπτώσεις σε επίπεδο container: payloads σε metadata, appended bytes και embedded files που μεταμφιέζονται μέσω extension.<sup>[[1]](#references)[[3]](#references)</sup>

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
#### αρχείο / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, and polyglot tricks

Πολλές προκλήσεις steganography περιλαμβάνουν επιπλέον bytes μετά από ένα έγκυρο αρχείο ή embedded archives που μεταμφιέζονται μέσω extension.

#### Appended payloads

Πολλά formats αγνοούν τα trailing bytes. Ένα ZIP/PDF/script μπορεί να προσαρτηθεί σε ένα image/audio container.

Γρήγοροι έλεγχοι:
```bash
binwalk file
tail -c 200 file | xxd
```
Αν γνωρίζεις ένα offset, κάνε carve με `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Όταν το `file` μπερδεύεται, αναζήτησε magic bytes με το `xxd` και σύγκρινέ τα με γνωστές signatures:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Δοκίμασε `7z` και `unzip` ακόμη κι αν η επέκταση δεν υποδεικνύει ότι είναι zip:
```bash
7z l file
unzip -l file
```
### Ιδιαιτερότητες κοντά στο stego

Γρήγοροι σύνδεσμοι για μοτίβα που εμφανίζονται τακτικά κοντά σε stego (QR-from-binary, braille κ.λπ.).

#### QR codes από δυαδικά δεδομένα

Αν το μήκος ενός blob είναι τέλειο τετράγωνο, ενδέχεται να αποτελεί ακατέργαστα pixel για μια εικόνα/QR.
```python
import math
math.isqrt(2500)  # 50
```
Βοηθητικό εργαλείο μετατροπής binary σε εικόνα:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker image με τα δημοφιλέστερα εργαλεία steganography σε ένα πακέτο](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Συμβάσεις ανοιχτής συσκευασίας ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Δυαδική εικόνα](https://www.dcode.fr/binary-image)
- [6] [Branah — Μεταφραστής Braille](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
