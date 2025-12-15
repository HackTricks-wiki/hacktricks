# Stego Ροή Εργασίας

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα προβλήματα stego λύνονται πιο γρήγορα με συστηματική διαλογή παρά με τη δοκιμή τυχαίων εργαλείων.

## Κύρια ροή

### Γρήγορη λίστα ελέγχου διαλογής

Ο στόχος είναι να απαντηθούν δύο ερωτήματα αποδοτικά:

1. Ποιος είναι ο πραγματικός container/format;
2. Το payload βρίσκεται στα metadata, σε appended bytes, σε embedded files, ή σε content-level stego;

#### 1) Αναγνώριση του container
```bash
file target
ls -lah target
```
Αν το `file` και η επέκταση διαφωνούν, εμπιστευτείτε το `file`. Θεωρείτε τα κοινά formats ως containers όταν είναι κατάλληλο (π.χ., OOXML έγγραφα είναι ZIP files).

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
Εάν η εξαγωγή αποτύχει αλλά αναφέρονται signatures, κόψτε χειροκίνητα τα offsets με `dd` και ξανατρέξτε `file` στην αποκομμένη περιοχή.

#### 4) Αν πρόκειται για εικόνα

- Επιθεωρήστε ανωμαλίες: `magick identify -verbose file`
- Αν PNG/BMP, απαριθμήστε επίπεδα bit/LSB: `zsteg -a file.png`
- Επαληθεύστε τη δομή PNG: `pngcheck -v file.png`
- Χρησιμοποιήστε οπτικά φίλτρα (Stegsolve / StegoVeritas) όταν το περιεχόμενο μπορεί να αποκαλυφθεί από μετασχηματισμούς καναλιού/επιπέδου

#### 5) Αν πρόκειται για ήχο

- Πρώτα spectrogram (Sonic Visualiser)
- Αποκωδικοποιήστε/επιθεωρήστε streams: `ffmpeg -v info -i file -f null -`
- Αν ο ήχος μοιάζει με δομημένους τόνους, δοκιμάστε αποκωδικοποίηση DTMF

### Βασικά εργαλεία

Αυτά εντοπίζουν τις συχνές περιπτώσεις σε επίπεδο container: φορτία μεταδεδομένων, προσκολλημένα bytes, και ενσωματωμένα αρχεία που κρύβονται πίσω από παραπλανητική κατάληξη.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to the repo files. Please paste the contents of src/stego/workflow/README.md (or the parts you want translated). I will translate the English text to Greek while preserving all code, tags, links, refs and markdown exactly as requested.
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
Δεν έχει παρασχεθεί κανένα περιεχόμενο προς μετάφραση. Παρακαλώ επικολλήστε το περιεχόμενο του αρχείου src/stego/workflow/README.md (ή τα strings) που θέλετε να μεταφραστούν.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, and polyglot tricks

Πολλές steganography προκλήσεις αποτελούνται από επιπλέον bytes μετά από ένα έγκυρο αρχείο ή από ενσωματωμένα archives που μεταμφιέζονται με αλλαγή της κατάληξης.

#### Appended payloads

Πολλές μορφές (formats) αγνοούν τα trailing bytes. Ένα ZIP/PDF/script μπορεί να προσαρτηθεί σε ένα image/audio container.

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
#### Zip μεταμφιεσμένο

Δοκιμάστε `7z` και `unzip` ακόμη κι αν η επέκταση δεν αναφέρει zip:
```bash
7z l file
unzip -l file
```
### Παραξενιές κοντά σε stego

Γρήγοροι σύνδεσμοι για μοτίβα που εμφανίζονται τακτικά δίπλα σε stego (QR-from-binary, braille, etc).

#### QR κωδικοί από binary

Αν το μήκος ενός blob είναι τέλειο τετράγωνο, μπορεί να είναι raw pixels για μια εικόνα/QR.
```python
import math
math.isqrt(2500)  # 50
```
Βοηθητικό εργαλείο binary-to-image:

- https://www.dcode.fr/binary-image

#### Μπράιγ

- https://www.branah.com/braille-translator

## Λίστες αναφοράς

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
