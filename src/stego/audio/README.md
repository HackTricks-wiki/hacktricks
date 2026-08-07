# Steganography ήχου

{{#include ../../banners/hacktricks-training.md}}

Συνηθισμένα μοτίβα:

- Μηνύματα σε Spectrogram
- Ενσωμάτωση WAV LSB
- Κωδικοποίηση DTMF / dial tones
- Payloads σε Metadata

## Γρήγορη αρχική διαλογή

Πριν από τη χρήση εξειδικευμένων εργαλείων:

- Επιβεβαιώστε τις λεπτομέρειες του codec/container και τυχόν ανωμαλίες:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Αν ο ήχος περιέχει περιεχόμενο που μοιάζει με θόρυβο ή tonal structure, εξετάστε νωρίς ένα Spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Στεγανογραφία με spectrogram

### Technique

Το Spectrogram stego αποκρύπτει δεδομένα διαμορφώνοντας την ενέργεια στον χρόνο/τη συχνότητα, ώστε να γίνονται ορατά μόνο σε ένα time-frequency plot (συχνά μη ακουστά ή αντιληπτά ως θόρυβος).

### Sonic Visualiser

Κύριο εργαλείο για την επιθεώρηση spectrogram:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (προβολή spectrogram, φίλτρα): https://www.audacityteam.org/
- Το `sox` μπορεί να δημιουργεί spectrograms από το CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem αποκωδικοποίηση

Ο ήχος με frequency-shift keying συχνά εμφανίζεται ως εναλλασσόμενοι μονοί τόνοι σε ένα spectrogram. Μόλις αποκτήσετε μια κατά προσέγγιση εκτίμηση της κεντρικής συχνότητας/μετατόπισης και του baud, κάντε brute force με το `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` πραγματοποιεί αυτόματο gain και αυτόματη ανίχνευση τόνων mark/space· προσαρμόστε τα `--rx-invert` ή `--samplerate` αν η έξοδος είναι αλλοιωμένη.

## WAV LSB

### Τεχνική

Για μη συμπιεσμένο PCM (WAV), κάθε sample είναι ένας ακέραιος. Η τροποποίηση των χαμηλών bits αλλάζει τη waveform ελάχιστα, επομένως οι επιτιθέμενοι μπορούν να αποκρύψουν:

- 1 bit ανά sample (ή περισσότερα)
- Interleaved μεταξύ καναλιών
- Με stride/permutation

Άλλες οικογένειες απόκρυψης σε audio που ενδέχεται να συναντήσετε:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (εξαρτώμενα από το format και το tool)

### WavSteg

Από: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / τόνοι κλήσης

### Τεχνική

Το DTMF κωδικοποιεί χαρακτήρες ως ζεύγη σταθερών συχνοτήτων (πληκτρολόγιο τηλεφώνου). Αν ο ήχος μοιάζει με τόνους πληκτρολογίου ή κανονικά ηχητικά σήματα διπλής συχνότητας, δοκιμάστε νωρίς την αποκωδικοποίηση DTMF.

Διαδικτυακοί αποκωδικοποιητές:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Αναφορές

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
