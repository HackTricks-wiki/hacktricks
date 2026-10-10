# Στεγανογραφία ήχου

{{#include ../../banners/hacktricks-training.md}}

Συνηθισμένα μοτίβα:

- Μηνύματα σε φασματογράφημα
- Ενσωμάτωση LSB σε WAV
- Κωδικοποίηση DTMF / τόνων κλήσης
- Payloads σε metadata

## Γρήγορη διαλογή

Πριν χρησιμοποιήσετε εξειδικευμένα εργαλεία:

- Επιβεβαιώστε τις λεπτομέρειες του codec/container και εντοπίστε ανωμαλίες:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Αν ο ήχος περιέχει περιεχόμενο που μοιάζει με θόρυβο ή τονική δομή, εξετάστε έγκαιρα ένα φασματογράφημα.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Στεγανογραφία σε φασματογράφημα

### Τεχνική

Η στεγανογραφία σε φασματογράφημα αποκρύπτει δεδομένα διαμορφώνοντας την ενέργεια στον χρόνο και τη συχνότητα, ώστε να γίνονται ορατά σε ένα διάγραμμα χρόνου-συχνότητας, ενώ ο ήχος μπορεί να ακούγεται σαν τόνοι ή θόρυβος.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Βασικό εργαλείο για την επιθεώρηση φασματογραμμάτων:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Εναλλακτικές

- Audacity (προβολή φασματογραφήματος και φίλτρα).<sup>[[6]](#references)</sup>
- Το `sox` μπορεί να δημιουργήσει φασματογράμματα από το CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / αποκωδικοποίηση modem

Ο ήχος με διαμόρφωση FSK συχνά εμφανίζεται ως εναλλασσόμενοι μονοί τόνοι σε ένα φασματογράφημα. Μόλις υπολογίσετε κατά προσέγγιση την κεντρική συχνότητα, τη μετατόπιση και τον ρυθμό baud, κάντε brute force με το `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` υποστηρίζει Bell και άλλες λειτουργίες FSK, καθώς και προσαρμοσμένες συχνότητες mark/space· συμβουλευτείτε τις επιλογές του αντί να υποθέτετε ότι κάθε ηχογράφηση μπορεί να ανιχνευτεί αυτόματα. Δοκιμάστε τα `--rx-invert`, μια ρητή λειτουργία baud ή το `--samplerate <Hz>` όταν το αποτέλεσμα είναι παραμορφωμένο.<sup>[[4]](#references)</sup>

## WAV LSB

### Τεχνική

Στο ασυμπίεστο PCM (WAV), κάθε δείγμα είναι ένας ακέραιος αριθμός. Η τροποποίηση των χαμηλών bit αλλάζει ελάχιστα την κυματομορφή, οπότε οι επιτιθέμενοι μπορούν να κρύψουν:

- 1 bit ανά δείγμα (ή περισσότερα)
- Εναλλάξ μεταξύ καναλιών
- Με βήμα ή μετάθεση

Άλλες τεχνικές απόκρυψης σε ήχο που μπορεί να συναντήσετε:

- Κωδικοποίηση φάσης
- Απόκρυψη μέσω ηχούς
- Ενσωμάτωση φάσματος εξάπλωσης
- Πλευρικά κανάλια codec (ανάλογα με τη μορφή και το εργαλείο)

### WavSteg

Οι παρακάτω εντολές χρησιμοποιούν το WavSteg από το toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Το επίσημο repository και οι εκδόσεις του DeepSound.<sup>[[7]](#references)</sup>

## DTMF / ήχοι κλήσης

### Τεχνική

Το DTMF αναπαριστά κάθε σήμα πλήκτρου χρησιμοποιώντας μία συχνότητα από μια χαμηλή ομάδα και μία από μια υψηλή ομάδα. Αν ο ήχος μοιάζει με τόνους πληκτρολογίου ή με κανονικά ηχητικά σήματα διπλής συχνότητας, δοκιμάστε νωρίς την αποκωδικοποίηση DTMF.<sup>[[5]](#references)</sup>

Online αποκωδικοποιητές:

- Εργαλείο browser `dtmf-detect`.<sup>[[8]](#references)</sup>
- Το `ribt/dtmf-decoder`, ένας αποκωδικοποιητής αρχείων ήχου που λειτουργεί offline.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — ροζ, η λίστα επιθυμιών του Santa, χριστουγεννιάτικα metadata, καταγεγραμμένος θόρυβος](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — τεκμηρίωση](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK γραμμής εντολών](https://github.com/kamalmostafa/minimodem)
- [5] [Σύσταση ITU-T Q.23 — τεχνικά χαρακτηριστικά των τηλεφωνικών συσκευών με πλήκτρα](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — επίσημο repository και εκδόσεις](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
