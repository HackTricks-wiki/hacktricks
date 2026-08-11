# Στεγανογραφία Ήχου

{{#include ../../banners/hacktricks-training.md}}

Συνηθισμένα μοτίβα:

- Μηνύματα σε φασματογράφημα
- Ενσωμάτωση WAV LSB
- Κωδικοποίηση DTMF / τόνων κλήσης
- Payloads σε metadata

## Γρήγορος αρχικός έλεγχος

Πριν από τη χρήση εξειδικευμένων εργαλείων:

- Επιβεβαιώστε τις λεπτομέρειες του codec/container και τυχόν ανωμαλίες:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Αν ο ήχος περιέχει περιεχόμενο που μοιάζει με θόρυβο ή τονική δομή, εξετάστε νωρίς ένα φασματογράφημα.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganography φασματογραφήματος

### Technique

Το Spectrogram stego κρύβει δεδομένα διαμορφώνοντας την ενέργεια στον χρόνο/τη συχνότητα, ώστε να γίνεται ορατή σε ένα γράφημα χρόνου-συχνότητας, ενώ ο ήχος μπορεί να ακούγεται σαν τόνοι ή θόρυβος.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Κύριο εργαλείο για επιθεώρηση φασματογραφήματος:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (προβολή φασματογραφήματος και φίλτρα).<sup>[[6]](#references)</sup>
- Το `sox` μπορεί να δημιουργεί φασματογραφήματα από το CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Αποκωδικοποίηση FSK / modem

Ο ήχος με frequency-shift keying συχνά μοιάζει με εναλλασσόμενους μεμονωμένους τόνους σε ένα spectrogram. Μόλις αποκτήσετε μια κατά προσέγγιση εκτίμηση της κεντρικής συχνότητας/μετατόπισης και του baud, χρησιμοποιήστε brute force με το `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
Το `minimodem` υποστηρίζει λειτουργίες Bell και άλλες λειτουργίες FSK, καθώς και προσαρμοσμένες συχνότητες mark/space· συμβουλευτείτε τις επιλογές του αντί να υποθέτετε ότι κάθε recording μπορεί να ανιχνευτεί αυτόματα. Δοκιμάστε `--rx-invert`, μια explicit baud mode ή `--samplerate <Hz>` όταν η έξοδος είναι αλλοιωμένη.<sup>[[4]](#references)</sup>

## WAV LSB

### Τεχνική

Για ασυμπίεστο PCM (WAV), κάθε sample είναι ένας ακέραιος αριθμός. Η τροποποίηση των low bits αλλάζει τη waveform ελάχιστα, επομένως οι attackers μπορούν να κρύψουν:

- 1 bit ανά sample (ή περισσότερα)
- Interleaved μεταξύ των channels
- Με stride/permutation

Άλλες οικογένειες audio-hiding που μπορεί να συναντήσετε:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (εξαρτώνται από το format και το tool)

### WavSteg

Οι παρακάτω εντολές χρησιμοποιούν το WavSteg από το toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Το επίσημο repository και οι releases του DeepSound.<sup>[[7]](#references)</sup>

## DTMF / ήχοι κλήσης

### Τεχνική

Το DTMF αναπαριστά κάθε σήμα του πληκτρολογίου χρησιμοποιώντας μία συχνότητα από μια ομάδα χαμηλών συχνοτήτων και μία από μια ομάδα υψηλών συχνοτήτων. Αν ο ήχος μοιάζει με τόνους πληκτρολογίου ή με τακτικά beeps διπλής συχνότητας, δοκιμάστε νωρίς την αποκωδικοποίηση DTMF.<sup>[[5]](#references)</sup>

Online decoders:

- Εργαλείο browser `dtmf-detect`.<sup>[[8]](#references)</sup>
- Το `ribt/dtmf-decoder`, ένας decoder αρχείων ήχου που λειτουργεί offline.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Wishlist του Santa, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — τεκμηρίωση](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [Σύσταση ITU-T Q.23 — τεχνικά χαρακτηριστικά τηλεφωνικών συσκευών με πλήκτρα](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — επίσημο repository και releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
