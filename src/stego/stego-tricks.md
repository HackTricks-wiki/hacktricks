# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Kutoa Data kutoka kwa Faili**

### **Binwalk**

Chombo cha kutafuta faili za binary kwa ajili ya faili na data zilizofichwa. Inapatikana kupitia `apt` na chanzo chake kinapatikana kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Inarejesha faili kulingana na vichwa na miguu yao, muhimu kwa picha za png. Imewekwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Inasaidia kuona metadata ya faili, inapatikana [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Inafanana na exiftool, kwa ajili ya kuangalia metadata. Inaweza kusakinishwa kupitia `apt`, chanzo kiko kwenye [GitHub](https://github.com/Exiv2/exiv2), na ina [tovuti rasmi](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Tambua aina ya faili unayoshughulika nayo.

### **Strings**

Hutoa maandiko yanayosomika kutoka kwa faili, kwa kutumia mipangilio mbalimbali ya uandishi ili kuchuja matokeo.
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

Inatumika kwa kulinganisha faili iliyobadilishwa na toleo lake asilia lililopatikana mtandaoni.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Kutoa Takwimu Zilizofichwa Katika Maandishi**

### **Takwimu Zilizofichwa Katika Nafasi**

Makarakteri yasiyoonekana katika nafasi zinazonekana kuwa tupu yanaweza kuficha taarifa. Ili kutoa data hii, tembelea [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Kutoa Takwimu Kutoka kwa Picha**

### **Kutambua Maelezo ya Picha kwa kutumia GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) hutumika kubaini aina za faili za picha na kutambua uwezekano wa uharibifu. Tekeleza amri iliyo hapa chini ili kukagua picha:
```bash
./magick identify -verbose stego.jpg
```
Ili kujaribu kurekebisha picha iliyo haribika, kuongeza maoni ya metadata kunaweza kusaidia:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide kwa Kuficha Data**

Steghide inarahisisha kuficha data ndani ya `JPEG, BMP, WAV, na AU` faili, ina uwezo wa kuingiza na kutoa data iliyosimbwa. Usanidi ni rahisi kutumia `apt`, na [mchakato wa chanzo upo kwenye GitHub](https://github.com/StefanoDeVuono/steghide).

**Amri:**

- `steghide info file` inaonyesha kama faili ina data iliyofichwa.
- `steghide extract -sf file [--passphrase password]` inatoa data iliyofichwa, nenosiri ni hiari.

Kwa utoaji wa mtandaoni, tembelea [tovuti hii](https://futureboy.us/stegano/decinput.html).

**Shambulio la Bruteforce na Stegcracker:**

- Ili kujaribu kuvunja nenosiri kwenye Steghide, tumia [stegcracker](https://github.com/Paradoxis/StegCracker.git) kama ifuatavyo:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg kwa Faili za PNG na BMP**

zsteg inajikita katika kufichua data iliyofichwa katika faili za PNG na BMP. Usanidi unafanywa kupitia `gem install zsteg`, ikiwa na [chanzo kwenye GitHub](https://github.com/zed-0xff/zsteg).

**Amri:**

- `zsteg -a file` inatumia mbinu zote za kugundua kwenye faili.
- `zsteg -E file` inaelezea payload kwa ajili ya uchimbaji wa data.

### **StegoVeritas na Stegsolve**

**stegoVeritas** inakagua metadata, inafanya mabadiliko ya picha, na inatumia LSB brute forcing miongoni mwa vipengele vingine. Tumia `stegoveritas.py -h` kwa orodha kamili ya chaguzi na `stegoveritas.py stego.jpg` kutekeleza ukaguzi wote.

**Stegsolve** inatumia filters mbalimbali za rangi kufichua maandiko au ujumbe uliofichwa ndani ya picha. Inapatikana kwenye [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT kwa Ugunduzi wa Maudhui ya Kufichwa**

Fast Fourier Transform (FFT) mbinu zinaweza kufichua maudhui yaliyofichwa katika picha. Rasilimali muhimu ni pamoja na:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic kwenye GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy kwa Faili za Sauti na Picha**

Stegpy inaruhusu kuingiza taarifa katika faili za picha na sauti, ikisaidia fomati kama PNG, BMP, GIF, WebP, na WAV. Inapatikana kwenye [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck kwa Uchambuzi wa Faili za PNG**

Ili kuchambua faili za PNG au kuthibitisha uhalali wao, tumia:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zana Zingine za Uchambuzi wa Picha**

Kwa uchunguzi zaidi, fikiria kutembelea:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Kutoa Data kutoka kwa Sauti**

**Audio steganography** inatoa njia ya kipekee ya kuficha taarifa ndani ya faili za sauti. Zana tofauti hutumiwa kwa ajili ya kuingiza au kupata maudhui yaliyofichwa.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide ni zana yenye uwezo wa kuficha data katika faili za JPEG, BMP, WAV, na AU. Maelekezo ya kina yanapatikana katika [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Zana hii inafaa kwa aina mbalimbali za muundo ikiwa ni pamoja na PNG, BMP, GIF, WebP, na WAV. Kwa maelezo zaidi, rejelea [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg ni muhimu kwa kutathmini uaminifu wa faili za sauti, ikionyesha taarifa za kina na kubaini tofauti zozote.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg inajulikana kwa kuficha na kutoa data ndani ya faili za WAV kwa kutumia mkakati wa bit isiyo na umuhimu. Inapatikana kwenye [GitHub](https://github.com/ragibson/Steganography#WavSteg). Amri ni:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound inaruhusu usimbaji na kugundua habari ndani ya faili za sauti kwa kutumia AES-256. Inaweza kupakuliwa kutoka [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Chombo kisicho na thamani kwa ukaguzi wa kuona na wa uchambuzi wa faili za sauti, Sonic Visualizer inaweza kufichua vipengele vilivyojificha ambavyo haviwezi kugundulika kwa njia nyingine. Tembelea [official website](https://www.sonicvisualiser.org/) kwa maelezo zaidi.

### **DTMF Tones - Dial Tones**

Kugundua sauti za DTMF katika faili za sauti kunaweza kufanywa kupitia zana za mtandaoni kama [this DTMF detector](https://unframework.github.io/dtmf-detect/) na [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Data za binary ambazo zinaweza kuja na nambari kamili zinaweza kuwakilisha QR code. Tumia kipande hiki kuangalia:
```python
import math
math.sqrt(2500) #50
```
Kwa kubadilisha binary kuwa picha, angalia [dcode](https://www.dcode.fr/binary-image). Kusoma QR codes, tumia [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tafsiri ya Braille**

Kwa kutafsiri Braille, [Branah Braille Translator](https://www.branah.com/braille-translator) ni rasilimali bora.

## **Marejeo**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
