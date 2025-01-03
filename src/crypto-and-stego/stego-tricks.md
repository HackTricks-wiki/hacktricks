# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **फाइलों से डेटा निकालना**

### **Binwalk**

एक उपकरण जो बाइनरी फाइलों में छिपी हुई फाइलों और डेटा की खोज करता है। इसे `apt` के माध्यम से स्थापित किया जाता है और इसका स्रोत [GitHub](https://github.com/ReFirmLabs/binwalk) पर उपलब्ध है।
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

हेडर और फुटर के आधार पर फ़ाइलों को पुनर्प्राप्त करता है, png छवियों के लिए उपयोगी। `apt` के माध्यम से स्थापित किया गया है, इसका स्रोत [GitHub](https://github.com/korczis/foremost) पर है।
```bash
foremost -i file # Extracts data
```
### **Exiftool**

फाइल मेटाडेटा देखने में मदद करता है, उपलब्ध [यहाँ](https://www.sno.phy.queensu.ca/~phil/exiftool/)।
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Exiftool के समान, मेटाडेटा देखने के लिए। `apt` के माध्यम से स्थापित किया जा सकता है, स्रोत [GitHub](https://github.com/Exiv2/exiv2) पर है, और इसका [आधिकारिक वेबसाइट](http://www.exiv2.org/) है।
```bash
exiv2 file # Shows the metadata
```
### **फाइल**

आप जिस फाइल से निपट रहे हैं, उसकी पहचान करें।

### **स्ट्रिंग्स**

फाइलों से पठनीय स्ट्रिंग्स निकालता है, आउटपुट को फ़िल्टर करने के लिए विभिन्न एन्कोडिंग सेटिंग्स का उपयोग करता है।
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

ऑनलाइन पाए गए मूल संस्करण के साथ संशोधित फ़ाइल की तुलना करने के लिए उपयोगी।
```bash
cmp original.jpg stego.jpg -b -l
```
## **पाठ में छिपे डेटा को निकालना**

### **स्पेस में छिपा डेटा**

दृश्यमान रूप से खाली स्पेस में अदृश्य वर्ण जानकारी छिपा सकते हैं। इस डेटा को निकालने के लिए, [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) पर जाएं।

## **छवियों से डेटा निकालना**

### **GraphicMagick के साथ छवि विवरण की पहचान करना**

[GraphicMagick](https://imagemagick.org/script/download.php) छवि फ़ाइल प्रकारों को निर्धारित करने और संभावित भ्रष्टाचार की पहचान करने के लिए कार्य करता है। एक छवि का निरीक्षण करने के लिए नीचे दिए गए कमांड को निष्पादित करें:
```bash
./magick identify -verbose stego.jpg
```
एक क्षतिग्रस्त छवि की मरम्मत करने के लिए, एक मेटाडेटा टिप्पणी जोड़ना मदद कर सकता है:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide के लिए डेटा छिपाना**

Steghide `JPEG, BMP, WAV, और AU` फ़ाइलों के भीतर डेटा छिपाने की सुविधा प्रदान करता है, जो एन्क्रिप्टेड डेटा को एम्बेड और निकालने में सक्षम है। इंस्टॉलेशन `apt` का उपयोग करके सीधा है, और इसका [स्रोत कोड GitHub पर उपलब्ध है](https://github.com/StefanoDeVuono/steghide)।

**कमांड:**

- `steghide info file` यह प्रकट करता है कि क्या एक फ़ाइल में छिपा हुआ डेटा है।
- `steghide extract -sf file [--passphrase password]` छिपा हुआ डेटा निकालता है, पासवर्ड वैकल्पिक है।

वेब-आधारित निष्कर्षण के लिए, [इस वेबसाइट](https://futureboy.us/stegano/decinput.html) पर जाएं।

**Stegcracker के साथ ब्रूटफोर्स अटैक:**

- Steghide पर पासवर्ड क्रैक करने का प्रयास करने के लिए, [stegcracker](https://github.com/Paradoxis/StegCracker.git) का उपयोग करें:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg PNG और BMP फ़ाइलों में छिपे डेटा को उजागर करने में विशेषज्ञता रखता है। स्थापना `gem install zsteg` के माध्यम से की जाती है, इसके [source on GitHub](https://github.com/zed-0xff/zsteg) पर।

**Commands:**

- `zsteg -a file` एक फ़ाइल पर सभी पहचान विधियों को लागू करता है।
- `zsteg -E file` डेटा निष्कर्षण के लिए एक पेलोड निर्दिष्ट करता है।

### **StegoVeritas and Stegsolve**

**stegoVeritas** मेटाडेटा की जांच करता है, छवि रूपांतरण करता है, और अन्य सुविधाओं के बीच LSB ब्रूट फोर्सिंग लागू करता है। विकल्पों की पूरी सूची के लिए `stegoveritas.py -h` का उपयोग करें और सभी जांच करने के लिए `stegoveritas.py stego.jpg` चलाएँ।

**Stegsolve** छवियों के भीतर छिपे पाठ या संदेशों को प्रकट करने के लिए विभिन्न रंग फ़िल्टर लागू करता है। यह [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) पर उपलब्ध है।

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) तकनीकें छवियों में छिपे सामग्री को उजागर कर सकती हैं। उपयोगी संसाधनों में शामिल हैं:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy छवि और ऑडियो फ़ाइलों में जानकारी को एम्बेड करने की अनुमति देता है, जो PNG, BMP, GIF, WebP, और WAV जैसे प्रारूपों का समर्थन करता है। यह [GitHub](https://github.com/dhsdshdhk/stegpy) पर उपलब्ध है।

### **Pngcheck for PNG File Analysis**

PNG फ़ाइलों का विश्लेषण करने या उनकी प्रामाणिकता को मान्य करने के लिए, उपयोग करें:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **छवि विश्लेषण के लिए अतिरिक्त उपकरण**

अधिक अन्वेषण के लिए, विचार करें:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **ऑडियो से डेटा निकालना**

**ऑडियो स्टेगनोग्राफी** ध्वनि फ़ाइलों के भीतर जानकारी छिपाने के लिए एक अनूठा तरीका प्रदान करती है। छिपी हुई सामग्री को एम्बेड या पुनः प्राप्त करने के लिए विभिन्न उपकरणों का उपयोग किया जाता है।

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide एक बहुपरकारी उपकरण है जिसे JPEG, BMP, WAV, और AU फ़ाइलों में डेटा छिपाने के लिए डिज़ाइन किया गया है। विस्तृत निर्देश [stego tricks documentation](stego-tricks.md#steghide) में प्रदान किए गए हैं।

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

यह उपकरण PNG, BMP, GIF, WebP, और WAV सहित विभिन्न प्रारूपों के साथ संगत है। अधिक जानकारी के लिए, [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) देखें।

### **ffmpeg**

ffmpeg ऑडियो फ़ाइलों की अखंडता का आकलन करने के लिए महत्वपूर्ण है, विस्तृत जानकारी को उजागर करता है और किसी भी विसंगतियों को इंगित करता है।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg WAV फ़ाइलों के भीतर डेटा को छिपाने और निकालने में सबसे कम महत्वपूर्ण बिट रणनीति का उपयोग करके उत्कृष्ट है। यह [GitHub](https://github.com/ragibson/Steganography#WavSteg) पर उपलब्ध है। कमांड में शामिल हैं:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound ध्वनि फ़ाइलों के भीतर जानकारी के एन्क्रिप्शन और पहचान की अनुमति देता है, जिसका उपयोग AES-256 किया जाता है। इसे [the official page](http://jpinsoft.net/deepsound/download.aspx) से डाउनलोड किया जा सकता है।

### **Sonic Visualizer**

ऑडियो फ़ाइलों के दृश्य और विश्लेषणात्मक निरीक्षण के लिए एक अमूल्य उपकरण, Sonic Visualizer छिपे हुए तत्वों को उजागर कर सकता है जो अन्य तरीकों से पता नहीं चल सकते। अधिक जानकारी के लिए [official website](https://www.sonicvisualiser.org/) पर जाएं।

### **DTMF Tones - Dial Tones**

ऑडियो फ़ाइलों में DTMF टोन का पता लगाने के लिए ऑनलाइन उपकरणों का उपयोग किया जा सकता है जैसे कि [this DTMF detector](https://unframework.github.io/dtmf-detect/) और [DialABC](http://dialabc.com/sound/detect/index.html)।

## **Other Techniques**

### **Binary Length SQRT - QR Code**

बाइनरी डेटा जो एक पूर्ण संख्या के लिए वर्ग करता है, एक QR कोड का प्रतिनिधित्व कर सकता है। जांचने के लिए इस स्निपेट का उपयोग करें:
```python
import math
math.sqrt(2500) #50
```
बाइनरी से इमेज रूपांतरण के लिए, [dcode](https://www.dcode.fr/binary-image) की जांच करें। QR कोड पढ़ने के लिए, [इस ऑनलाइन बारकोड रीडर](https://online-barcode-reader.inliteresearch.com/) का उपयोग करें।

### **ब्रेल अनुवाद**

ब्रेल का अनुवाद करने के लिए, [Branah Braille Translator](https://www.branah.com/braille-translator) एक उत्कृष्ट संसाधन है।

## **संदर्भ**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
