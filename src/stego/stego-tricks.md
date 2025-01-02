# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Εξαγωγή Δεδομένων από Αρχεία**

### **Binwalk**

Ένα εργαλείο για την αναζήτηση δυαδικών αρχείων για ενσωματωμένα κρυφά αρχεία και δεδομένα. Εγκαθίσταται μέσω του `apt` και η πηγή του είναι διαθέσιμη στο [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Ανακτά αρχεία με βάση τις κεφαλίδες και τις υποσέλιδές τους, χρήσιμο για εικόνες png. Εγκαθίσταται μέσω του `apt` με την πηγή του στο [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Βοηθά στην προβολή μεταδεδομένων αρχείων, διαθέσιμο [εδώ](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Παρόμοιο με το exiftool, για προβολή μεταδεδομένων. Εγκαθίσταται μέσω `apt`, πηγή στο [GitHub](https://github.com/Exiv2/exiv2), και έχει μια [επίσημη ιστοσελίδα](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Αρχείο**

Καθορίστε τον τύπο του αρχείου με το οποίο ασχολείστε.

### **Συμβολοσειρές**

Εξάγει αναγνώσιμες συμβολοσειρές από αρχεία, χρησιμοποιώντας διάφορες ρυθμίσεις κωδικοποίησης για να φιλτράρει την έξοδο.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Σύγκριση (cmp)**

Χρήσιμο για τη σύγκριση ενός τροποποιημένου αρχείου με την αρχική του έκδοση που βρέθηκε online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Εξαγωγή Κρυφών Δεδομένων σε Κείμενο**

### **Κρυφά Δεδομένα σε Κενά**

Αόρατοι χαρακτήρες σε φαινομενικά κενά σημεία μπορεί να κρύβουν πληροφορίες. Για να εξαγάγετε αυτά τα δεδομένα, επισκεφθείτε [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Εξαγωγή Δεδομένων από Εικόνες**

### **Αναγνώριση Λεπτομερειών Εικόνας με το GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) χρησιμοποιείται για να προσδιορίσει τους τύπους αρχείων εικόνας και να εντοπίσει πιθανή διαφθορά. Εκτελέστε την παρακάτω εντολή για να ελέγξετε μια εικόνα:
```bash
./magick identify -verbose stego.jpg
```
Για να προσπαθήσετε να επισκευάσετε μια κατεστραμμένη εικόνα, η προσθήκη ενός σχολίου μεταδεδομένων μπορεί να βοηθήσει:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide για Απόκρυψη Δεδομένων**

Το Steghide διευκολύνει την απόκρυψη δεδομένων μέσα σε `JPEG, BMP, WAV, και AU` αρχεία, ικανό να ενσωματώνει και να εξάγει κρυπτογραφημένα δεδομένα. Η εγκατάσταση είναι απλή χρησιμοποιώντας `apt`, και ο [κώδικας πηγής είναι διαθέσιμος στο GitHub](https://github.com/StefanoDeVuono/steghide).

**Εντολές:**

- `steghide info file` αποκαλύπτει αν ένα αρχείο περιέχει κρυμμένα δεδομένα.
- `steghide extract -sf file [--passphrase password]` εξάγει τα κρυμμένα δεδομένα, ο κωδικός πρόσβασης είναι προαιρετικός.

Για εξαγωγή μέσω διαδικτύου, επισκεφθείτε [αυτή την ιστοσελίδα](https://futureboy.us/stegano/decinput.html).

**Επίθεση Bruteforce με Stegcracker:**

- Για να προσπαθήσετε να σπάσετε τον κωδικό πρόσβασης στο Steghide, χρησιμοποιήστε [stegcracker](https://github.com/Paradoxis/StegCracker.git) ως εξής:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg για PNG και BMP Αρχεία**

zsteg ειδικεύεται στην αποκάλυψη κρυφών δεδομένων σε αρχεία PNG και BMP. Η εγκατάσταση γίνεται μέσω `gem install zsteg`, με την [πηγή του στο GitHub](https://github.com/zed-0xff/zsteg).

**Εντολές:**

- `zsteg -a file` εφαρμόζει όλες τις μεθόδους ανίχνευσης σε ένα αρχείο.
- `zsteg -E file` καθορίζει ένα payload για εξαγωγή δεδομένων.

### **StegoVeritas και Stegsolve**

**stegoVeritas** ελέγχει τα μεταδεδομένα, εκτελεί μετασχηματισμούς εικόνας και εφαρμόζει LSB brute forcing μεταξύ άλλων χαρακτηριστικών. Χρησιμοποιήστε `stegoveritas.py -h` για μια πλήρη λίστα επιλογών και `stegoveritas.py stego.jpg` για να εκτελέσετε όλους τους ελέγχους.

**Stegsolve** εφαρμόζει διάφορα φίλτρα χρώματος για να αποκαλύψει κρυφά κείμενα ή μηνύματα μέσα σε εικόνες. Είναι διαθέσιμο στο [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT για Ανίχνευση Κρυφού Περιεχομένου**

Οι τεχνικές Fast Fourier Transform (FFT) μπορούν να αποκαλύψουν κρυφό περιεχόμενο σε εικόνες. Χρήσιμοι πόροι περιλαμβάνουν:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic στο GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy για Αρχεία Ήχου και Εικόνας**

Stegpy επιτρέπει την ενσωμάτωση πληροφοριών σε αρχεία εικόνας και ήχου, υποστηρίζοντας μορφές όπως PNG, BMP, GIF, WebP και WAV. Είναι διαθέσιμο στο [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck για Ανάλυση Αρχείων PNG**

Για να αναλύσετε αρχεία PNG ή να επιβεβαιώσετε την αυθεντικότητά τους, χρησιμοποιήστε:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Επιπλέον Εργαλεία για Ανάλυση Εικόνας**

Για περαιτέρω εξερεύνηση, σκεφτείτε να επισκεφθείτε:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Εξαγωγή Δεδομένων από Ήχους**

**Audio steganography** προσφέρει μια μοναδική μέθοδο για την απόκρυψη πληροφοριών μέσα σε αρχεία ήχου. Διάφορα εργαλεία χρησιμοποιούνται για την ενσωμάτωση ή την ανάκτηση κρυφού περιεχομένου.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide είναι ένα ευέλικτο εργαλείο σχεδιασμένο για την απόκρυψη δεδομένων σε αρχεία JPEG, BMP, WAV και AU. Λεπτομερείς οδηγίες παρέχονται στην [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Αυτό το εργαλείο είναι συμβατό με μια ποικιλία μορφών, συμπεριλαμβανομένων των PNG, BMP, GIF, WebP και WAV. Για περισσότερες πληροφορίες, ανατρέξτε στην [ενότητα του Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg είναι κρίσιμο για την αξιολόγηση της ακεραιότητας των αρχείων ήχου, επισημαίνοντας λεπτομερείς πληροφορίες και εντοπίζοντας τυχόν ανωμαλίες.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

Το WavSteg διακρίνεται στην απόκρυψη και εξαγωγή δεδομένων μέσα σε αρχεία WAV χρησιμοποιώντας τη στρατηγική του λιγότερο σημαντικού bit. Είναι διαθέσιμο στο [GitHub](https://github.com/ragibson/Steganography#WavSteg). Οι εντολές περιλαμβάνουν:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Το Deepsound επιτρέπει την κρυπτογράφηση και ανίχνευση πληροφοριών μέσα σε αρχεία ήχου χρησιμοποιώντας AES-256. Μπορεί να κατέβει από [την επίσημη σελίδα](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Ένα ανεκτίμητο εργαλείο για οπτική και αναλυτική επιθεώρηση αρχείων ήχου, το Sonic Visualizer μπορεί να αποκαλύψει κρυμμένα στοιχεία που δεν ανιχνεύονται με άλλους τρόπους. Επισκεφθείτε την [επίσημη ιστοσελίδα](https://www.sonicvisualiser.org/) για περισσότερα.

### **DTMF Tones - Dial Tones**

Η ανίχνευση τόνων DTMF σε αρχεία ήχου μπορεί να επιτευχθεί μέσω διαδικτυακών εργαλείων όπως [αυτός ο ανιχνευτής DTMF](https://unframework.github.io/dtmf-detect/) και [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Δυαδικά δεδομένα που τετραγωνίζονται σε ακέραιο αριθμό μπορεί να αντιπροσωπεύουν έναν κωδικό QR. Χρησιμοποιήστε αυτό το απόσπασμα για να ελέγξετε:
```python
import math
math.sqrt(2500) #50
```
Για τη μετατροπή δυαδικών σε εικόνα, ελέγξτε το [dcode](https://www.dcode.fr/binary-image). Για να διαβάσετε QR codes, χρησιμοποιήστε [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Μετάφραση Μπράιγ**

Για τη μετάφραση Μπράιγ, ο [Branah Braille Translator](https://www.branah.com/braille-translator) είναι μια εξαιρετική πηγή.

## **Αναφορές**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
