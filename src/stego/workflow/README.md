# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα stego προβλήματα λύνονται πιο γρήγορα με συστηματική διαλογή παρά με τη δοκιμή τυχαίων εργαλείων.

## Βασική ροή

### Σύντομη λίστα ελέγχου διαλογής

Ο στόχος είναι να απαντηθούν δύο ερωτήματα αποτελεσματικά:

1. Ποιος είναι ο πραγματικός περιέκτης/μορφότυπος;
2. Βρίσκεται το payload στα metadata, σε appended bytes, σε embedded files, ή σε content-level stego;

#### 1) Αναγνώριση του περιέκτη/μορφότυπου
```bash
file target
ls -lah target
```
If `file` and the extension disagree, trust `file`. Treat common formats as containers when appropriate (π.χ., OOXML documents are ZIP files).

#### 2) Αναζητήστε metadata και προφανείς strings
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
If extraction fails but signatures are reported, manually carve offsets with `dd` and re-run `file` on the carved region.

#### 4) If image

- Ελέγξτε για ανωμαλίες: `magick identify -verbose file`
- Αν PNG/BMP, απαριθμήστε bit-planes/LSB: `zsteg -a file.png`
- Επαληθεύστε τη δομή PNG: `pngcheck -v file.png`
- Χρησιμοποιήστε οπτικά φίλτρα (Stegsolve / StegoVeritas) όταν το περιεχόμενο μπορεί να αποκαλυφθεί μέσω μετασχηματισμών καναλιού/επιπέδου

#### 5) If audio

- Πρώτα spectrogram (Sonic Visualiser)
- Αποκωδικοποιήστε/επιθεωρήστε streams: `ffmpeg -v info -i file -f null -`
- Αν ο ήχος μοιάζει με δομημένους τόνους, δοκιμάστε αποκωδικοποίηση DTMF

### Βασικά εργαλεία

Αυτά χειρίζονται τις συχνές περιπτώσεις σε επίπεδο container: metadata payloads, appended bytes και embedded files που κρύβονται πίσω από extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to the repository files directly. Please paste the contents of src/stego/workflow/README.md (or the specific section you want translated, e.g. the "Foremost" section) here, and I'll translate the English text to Greek while preserving all markdown/html/tags, links, paths and code as you requested.
```bash
foremost -i file
```
I don't have access to your repo contents. Please paste the contents of src/stego/workflow/README.md (or the specific sections you want translated). I'll translate the English text to Greek following your rules.
```bash
exiftool file
exiv2 file
```
I don't have the file contents. Please paste the contents of src/stego/workflow/README.md (or the specific strings you want translated) and I'll translate them to Greek, preserving all markdown/html/tags and non‑translatable items as requested.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, προστιθέμενα δεδομένα και polyglot tricks

Πολλές προκλήσεις steganography περιέχουν επιπλέον bytes μετά από ένα έγκυρο αρχείο, ή ενσωματωμένα archives μεταμφιεσμένα μέσω της κατάληξης.

#### Appended payloads

Πολλές μορφές αγνοούν τα trailing bytes. Ένα ZIP/PDF/script μπορεί να προσαρτηθεί σε ένα image/audio container.

Γρήγοροι έλεγχοι:
```bash
binwalk file
tail -c 200 file | xxd
```
Αν γνωρίζετε ένα offset, carve με `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Μαγικά bytes

Όταν το `file` μπερδεύεται, ψάξτε για μαγικά bytes με το `xxd` και συγκρίνετε με γνωστές υπογραφές:
```bash
xxd -g 1 -l 32 file
```
#### Zip-μεταμφιεσμένο

Δοκιμάστε `7z` και `unzip` ακόμα κι αν η επέκταση δεν λέει zip:
```bash
7z l file
unzip -l file
```
### Παράξενες εμφανίσεις κοντά σε stego

Γρήγοροι σύνδεσμοι για μοτίβα που εμφανίζονται τακτικά δίπλα σε stego (QR-from-binary, braille, κ.λπ).

#### Κωδικοί QR από binary

Αν το μήκος ενός blob είναι τέλειο τετράγωνο, μπορεί να είναι ακατέργαστα pixels για μια εικόνα/QR.
```python
import math
math.isqrt(2500)  # 50
```
Βοηθητικό Binary-to-image:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Μπράιγ

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Λίστες αναφοράς

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
