# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Κοινά μοτίβα:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Γρήγορη αξιολόγηση

Πριν από εξειδικευμένα εργαλεία:

- Επιβεβαιώστε τις λεπτομέρειες codec/container και τυχόν ανωμαλίες:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Εάν το audio περιέχει περιεχόμενο που μοιάζει με θόρυβο ή τηνική δομή, ελέγξτε ένα spectrogram νωρίς.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Τεχνική

Spectrogram stego κρύβει δεδομένα διαμορφώνοντας την ενέργεια στο χρόνο/τη συχνότητα, ώστε να γίνεται ορατό μόνο σε ένα γράφημα χρόνου-συχνότητας (συχνά μη ακουστό ή αντιληπτό ως θόρυβος).

### Sonic Visualiser

Κύριο εργαλείο για την επιθεώρηση φασματογραφήματος:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Εναλλακτικές

- Audacity (προβολή φασματογραφήματος, φίλτρα): https://www.audacityteam.org/
- `sox` μπορεί να δημιουργήσει φασματογραφήματα από το CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem αποκωδικοποίηση

Ο Frequency-shift keyed ήχος συχνά μοιάζει με εναλλασσόμενους μεμονωμένους τόνους σε ένα φασματογράφημα. Μόλις έχετε μια κατά προσέγγιση εκτίμηση του center/shift και του baud, brute force με `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ρυθμίζει αυτόματα το gain και ανιχνεύει τους mark/space τόνους· ρυθμίστε `--rx-invert` ή `--samplerate` αν η έξοδος είναι αλλοιωμένη.

## WAV LSB

### Τεχνική

Για uncompressed PCM (WAV), κάθε δείγμα είναι ένας ακέραιος. Η τροποποίηση των χαμηλών bits αλλάζει ελάχιστα την κυματομορφή, οπότε οι επιτιθέμενοι μπορούν να κρύψουν:

- 1 bit ανά δείγμα (ή περισσότερα)
- Διαπλεγμένα μεταξύ καναλιών
- Με stride/permutation

Άλλες οικογένειες audio-hiding που μπορεί να συναντήσετε:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

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

Το DTMF κωδικοποιεί χαρακτήρες ως ζεύγη σταθερών συχνοτήτων (πληκτρολόγιο τηλεφώνου). Αν ο ήχος μοιάζει με τόνους πληκτρολογίου ή με κανονικά διπλής συχνότητας σήματα, δοκιμάστε νωρίς την αποκωδικοποίηση DTMF.

Αποκωδικοποιητές online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Αναφορές

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
