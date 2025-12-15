# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Συνήθη μοτίβα:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Γρήγορη αξιολόγηση

Πριν από χρήση εξειδικευμένων εργαλείων:

- Επιβεβαιώστε τις λεπτομέρειες codec/container και τυχόν ανωμαλίες:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Εάν το audio περιέχει περιεχόμενο που μοιάζει με θόρυβο ή τονική δομή, ελέγξτε νωρίς ένα spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Τεχνική

Spectrogram stego κρύβει δεδομένα διαμορφώνοντας την ενέργεια στο χρόνο/συχνότητα έτσι ώστε να γίνεται ορατό μόνο σε ένα διάγραμμα χρόνο-συχνότητας (συχνά μη ακουστό ή αντιλαμβανόμενο ως θόρυβος).

### Sonic Visualiser

Κύριο εργαλείο για την επιθεώρηση spectrogram:

- https://www.sonicvisualiser.org/

### Εναλλακτικές

- Audacity (προβολή spectrogram, φίλτρα): https://www.audacityteam.org/
- `sox` μπορεί να δημιουργήσει spectrograms από το CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Technique

Για μη συμπιεσμένο PCM (WAV), κάθε δείγμα είναι ένας ακέραιος. Η τροποποίηση των χαμηλών bits αλλάζει το ηχητικό κύμα πολύ ελάχιστα, επομένως οι επιτιθέμενοι μπορούν να κρύψουν:

- 1 bit ανά δείγμα (ή περισσότερο)
- Διαπλεγμένο μεταξύ καναλιών
- Με stride/permutation

Άλλες οικογένειες απόκρυψης ήχου που μπορεί να συναντήσετε:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / ήχοι κλήσης

### Τεχνική

Το DTMF κωδικοποιεί χαρακτήρες ως ζεύγη σταθερών συχνοτήτων (πληκτρολόγιο τηλεφώνου). Εάν ο ήχος μοιάζει με τόνους πληκτρολογίου ή με κανονικά διπλής συχνότητας μπιπ, ελέγξτε την αποκωδικοποίηση DTMF νωρίς.

Αποκωδικοποιητές στο διαδίκτυο:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
