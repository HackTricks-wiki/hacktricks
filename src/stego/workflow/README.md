# Ροή εργασίας Stego

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα προβλήματα Stego επιλύονται ταχύτερα με συστηματικό triage παρά με τη δοκιμή τυχαίων εργαλείων.

## Βασική ροή

### Checklist γρήγορου triage

Ο στόχος είναι να απαντηθούν αποτελεσματικά δύο ερωτήσεις:

1. Ποιο είναι το πραγματικό container/format;
2. Βρίσκεται το payload στα metadata, σε appended bytes, σε embedded files ή σε content-level stego;

#### 1) Identify the container
```bash
file target
ls -lah target
```
Αν το `file` και η επέκταση διαφωνούν, εμπιστευτείτε το `file`. Αντιμετωπίστε τις συνηθισμένες μορφές ως containers όπου είναι κατάλληλο (π.χ. τα έγγραφα OOXML είναι αρχεία ZIP).

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
Αν η εξαγωγή αποτύχει αλλά αναφέρονται signatures, κάντε χειροκίνητο carve των offsets με `dd` και εκτελέστε ξανά το `file` στην περιοχή που απομονώθηκε.

#### 4) Αν πρόκειται για image

- Ελέγξτε για anomalies: `magick identify -verbose file`
- Αν είναι PNG/BMP, απαριθμήστε τα bit-planes/LSB: `zsteg -a file.png`
- Επικυρώστε τη δομή του PNG: `pngcheck -v file.png`
- Χρησιμοποιήστε visual filters (Stegsolve / StegoVeritas) όταν το περιεχόμενο μπορεί να αποκαλυφθεί μέσω μετασχηματισμών καναλιών/planes

#### 5) Αν πρόκειται για audio

- Ξεκινήστε με spectrogram (Sonic Visualiser)
- Κάντε decode/inspect τα streams: `ffmpeg -v info -i file -f null -`
- Αν το audio μοιάζει με structured tones, δοκιμάστε DTMF decoding

### Εργαλεία καθημερινής χρήσης

Αυτά εντοπίζουν τις συνηθέστερες περιπτώσεις σε επίπεδο container: payloads σε metadata, appended bytes και embedded files που μεταμφιέζονται μέσω extension.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

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
### Containers, appended data και polyglot tricks

Πολλές steganography challenges είναι extra bytes μετά από ένα έγκυρο file ή embedded archives που μεταμφιέζονται μέσω του extension.

#### Προσαρτημένα payloads

Πολλά formats αγνοούν τα trailing bytes. Ένα ZIP/PDF/script μπορεί να προσαρτηθεί σε ένα image/audio container.

Γρήγοροι έλεγχοι:
```bash
binwalk file
tail -c 200 file | xxd
```
Αν γνωρίζεις ένα offset, κάνε carve με το `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Όταν το `file` μπερδεύεται, αναζητήστε magic bytes με `xxd` και συγκρίνετέ τα με γνωστές signatures:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Δοκίμασε τα `7z` και `unzip`, ακόμη κι αν η επέκταση δεν υποδεικνύει ότι πρόκειται για zip:
```bash
7z l file
unzip -l file
```
### Παραξενιές κοντά στο stego

Γρήγοροι σύνδεσμοι για μοτίβα που εμφανίζονται τακτικά δίπλα σε stego (QR-from-binary, braille κ.λπ.).

#### QR codes from binary

Αν το μήκος ενός blob είναι τέλειο τετράγωνο, μπορεί να αποτελείται από raw pixels για μια εικόνα/QR.
```python
import math
math.isqrt(2500)  # 50
```
Βοηθητικό εργαλείο μετατροπής δυαδικού σε εικόνα:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Αναφορές

- [1] [DominicBreuker/stego-toolkit - Docker image με τα δημοφιλέστερα εργαλεία steganography συγκεντρωμένα](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
