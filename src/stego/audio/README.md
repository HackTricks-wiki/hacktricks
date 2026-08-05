# Στεγανογραφία Ήχου

{{#include ../../banners/hacktricks-training.md}}

Συνηθισμένα μοτίβα:

- Μηνύματα σε Spectrogram
- WAV LSB embedding
- DTMF / κωδικοποίηση dial tones
- Metadata payloads

## Γρήγορη αρχική εξέταση

Πριν από τη χρήση specialized tooling:

- Επιβεβαιώστε τις λεπτομέρειες codec/container και τις ανωμαλίες:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Αν ο ήχος περιέχει περιεχόμενο που μοιάζει με θόρυβο ή tonal structure, εξετάστε έγκαιρα ένα spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Στεγανογραφία φασματογραφήματος

### Τεχνική

Το Spectrogram stego αποκρύπτει δεδομένα διαμορφώνοντας την ενέργεια στον χρόνο/τη συχνότητα, ώστε να γίνεται ορατή μόνο σε ένα time-frequency plot (συχνά μη ακουστή ή αντιληπτή ως θόρυβος).

### Sonic Visualiser

Κύριο εργαλείο για την επιθεώρηση φασματογραφημάτων:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Εναλλακτικές

- Audacity (προβολή φασματογραφήματος, φίλτρα): https://www.audacityteam.org/
- Το `sox` μπορεί να δημιουργεί φασματογραφήματα από το CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / αποκωδικοποίηση modem

Ο ήχος με Frequency-shift keying συχνά μοιάζει με εναλλασσόμενους μεμονωμένους τόνους σε ένα φασματογράφημα.<sup>[[1]](#references)</sup> Μόλις έχετε μια κατά προσέγγιση εκτίμηση της κεντρικής συχνότητας/μετατόπισης και του baud rate, κάντε brute force με το `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
Το `minimodem` ρυθμίζει αυτόματα την απολαβή και εντοπίζει αυτόματα τους τόνους mark/space· προσαρμόστε το `--rx-invert` ή το `--samplerate` αν η έξοδος είναι παραμορφωμένη.

## WAV LSB

### Technique

Για μη συμπιεσμένο PCM (WAV), κάθε δείγμα είναι ένας ακέραιος. Η τροποποίηση των χαμηλών bit αλλάζει την κυματομορφή ελάχιστα, επομένως οι attackers μπορούν να κρύψουν:

- 1 bit ανά δείγμα (ή περισσότερα)
- Interleaved μεταξύ καναλιών
- Με stride/permutation

Άλλες οικογένειες τεχνικών απόκρυψης ήχου που μπορεί να συναντήσετε:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (εξαρτάται από το format και το εργαλείο)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / τόνοι κλήσης

### Τεχνική

Το DTMF κωδικοποιεί χαρακτήρες ως ζεύγη σταθερών συχνοτήτων (πληκτρολόγιο τηλεφώνου). Αν ο ήχος μοιάζει με τόνους πληκτρολογίου ή κανονικά beeps διπλής συχνότητας, δοκιμάστε νωρίς την αποκωδικοποίηση DTMF.

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Αναφορές

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
