# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Common patterns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Γρήγορος έλεγχος

Πριν από εξειδικευμένα εργαλεία:

- Επιβεβαιώστε λεπτομέρειες codec/container και ανωμαλίες:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Αν ο ήχος περιέχει περιεχόμενο που μοιάζει με θόρυβο ή τονική δομή, ελέγξτε ένα spectrogram νωρίς.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Τεχνική

Spectrogram stego κρύβει δεδομένα διαμορφώνοντας την ενέργεια σε χρόνο/συχνότητα έτσι ώστε να γίνεται ορατό μόνο σε ένα διάγραμμα χρόνο-συχνότητα (συχνά μη ακουστό ή αντιλαμβανόμενο ως θόρυβος).

### Sonic Visualiser

Κύριο εργαλείο για την ανάλυση spectrogram:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Εναλλακτικές

- Audacity (spectrogram προβολή, φίλτρα): https://www.audacityteam.org/
- `sox` μπορεί να δημιουργήσει spectrograms από το CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Τεχνική

Για μη συμπιεσμένο PCM (WAV), κάθε δείγμα είναι ακέραιος αριθμός. Η τροποποίηση των χαμηλών bit αλλάζει την κυματομορφή ελάχιστα, οπότε οι επιτιθέμενοι μπορούν να κρύψουν:

- 1 bit ανά δείγμα (ή περισσότερα)
- Διαπλεγμένα μεταξύ των καναλιών
- Με βήμα/αντιμετάθεση

Άλλες τεχνικές απόκρυψης ήχου που μπορεί να συναντήσετε:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (εξαρτώμενα από τη μορφή και το εργαλείο)

### WavSteg

Από: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / τόνοι κλήσης

### Τεχνική

DTMF κωδικοποιεί χαρακτήρες ως ζεύγη σταθερών συχνοτήτων (πληκτρολόγιο τηλεφώνου). Εάν ο ήχος μοιάζει με τόνους πληκτρολογίου ή τακτικά δίσυχνα μπιπ, δοκιμάστε πρώιμη αποκωδικοποίηση DTMF.

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
