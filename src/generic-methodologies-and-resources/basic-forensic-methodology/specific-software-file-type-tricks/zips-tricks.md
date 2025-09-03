# ZIPs ट्रिक्स

{{#include ../../../banners/hacktricks-training.md}}

**कमांड-लाइन टूल्स** zip फ़ाइलों को मैनेज करने के लिए जरूरी हैं — इन्हें zip फ़ाइलों का डायग्नोसिस, रिपेयर और क्रैक करने में इस्तेमाल किया जाता है। यहाँ कुछ महत्वपूर्ण यूटิลिटी हैं:

- **`unzip`**: बताता है कि कोई zip फ़ाइल क्यों decompress नहीं हो रही है।
- **`zipdetails -v`**: zip फ़ाइल फॉर्मेट फ़ील्ड्स का विस्तृत विश्लेषण प्रदान करता है।
- **`zipinfo`**: zip फ़ाइल की सामग्री को बिना निकालें (extract किए) सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: क्षतिग्रस्त (corrupted) zip फ़ाइलों की मरम्मत की कोशिश करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip पासवर्ड्स को ब्रूट-फोर्स से क्रैक करने के लिए एक टूल, लगभग 7 अक्षरों तक के पासवर्ड के लिए प्रभावी।

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip फ़ाइलों की संरचना और मानकों पर व्यापक विवरण प्रदान करता है।

यह जानना महत्वपूर्ण है कि पासवर्ड-प्रोटेक्टेड zip फ़ाइलें अंदर के फ़ाइल नामों या फ़ाइल साइज़ को **एनक्रिप्ट नहीं करतीं (do not encrypt filenames or file sizes)** — यह एक सुरक्षा कमजोरी है जो RAR या 7z फ़ाइलों के साथ साझा नहीं होती क्योंकि वे इस जानकारी को एनक्रिप्ट करते हैं। आगे, पुराने ZipCrypto तरीके से एनक्रिप्ट की गई zip फ़ाइलें तब एक **plaintext attack** के प्रति संवेदनशील होती हैं जब किसी compressed फ़ाइल की एक अनएन्क्रिप्टेड कॉपी उपलब्ध हो। यह हमला ज्ञात कॉन्टेन्ट का उपयोग कर zip के पासवर्ड को क्रैक कर देता है — इस कमजोरी का वर्णन [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) में है और इसे [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) में और विस्तार से समझाया गया है। हालांकि, **AES-256** एनक्रिप्शन वाले zip फ़ाइलें इस plaintext attack से सुरक्षित होती हैं, जो संवेदनशील डेटा के लिए सुरक्षित एनक्रिप्शन विधियाँ चुनने के महत्व को दर्शाता है।

---

## APKs में हेरफेर किए गए ZIP headers का उपयोग करके Anti-reversing ट्रिक्स

आधुनिक Android malware droppers खराब/malformed ZIP metadata का उपयोग स्टैटिक टूल्स (jadx/apktool/unzip) को तोड़ने के लिए करते हैं, जबकि APK को डिवाइस पर इंस्टॉल करने योग्य बनाए रखते हैं। सबसे सामान्य ट्रिक्स हैं:

- ZIP General Purpose Bit Flag (GPBF) का bit 0 सेट करके Fake encryption
- पार्सर्स को भ्रमित करने के लिए बड़े/कस्टम Extra fields का दुरुपयोग
- वास्तविक आर्टिफैक्ट्स छिपाने के लिए फ़ाइल/डायरेक्टरी नामों का टकराव (उदा., एक directory जिसका नाम `classes.dex/` है, जो वास्तविक `classes.dex` के बगल में मौजूद हो)

### 1) Fake encryption (GPBF bit 0 set) बिना असली क्रिप्टो के

लक्षण:
- `jadx-gui` निम्न त्रुटियों के साथ फेल हो सकता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` मुख्य APK फ़ाइलों के लिए पासवर्ड माँगता है, भले ही एक वैध APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails के साथ पता लगाना:
```bash
zipdetails -v sample.apk | less
```
local और central headers के लिए General Purpose Bit Flag को देखें। एक स्पष्ट संकेतक मान है bit 0 set (Encryption) यहां तक कि core entries के लिए भी:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ह्यूरिस्टिक: यदि एक APK डिवाइस पर इंस्टॉल होकर चलता है लेकिन core entries टूल्स को "encrypted" दिखती हैं, तो GPBF में छेड़छाड़ की गई है।

ठीक करने के लिए GPBF बिट 0 को Local File Headers (LFH) और Central Directory (CD) दोनों एंट्रीज़ में क्लियर करें। Minimal byte-patcher:
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
उपयोग:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
अब आपको मुख्य प्रविष्टियों पर `General Purpose Flag  0000` दिखाई देना चाहिए और टूल्स APK को फिर से पार्स करेंगे।

### 2) पार्सर्स को तोड़ने के लिए बड़े/कस्टम Extra फ़ील्ड

हमलावर हेडरों में अतिविशाल Extra फ़ील्ड और अजीब IDs डाल देते हैं ताकि डीकम्पाइलर्स फंस जाएँ। वास्तविक दुनिया में आप वहाँ एम्बेडेड कस्टम मार्कर्स देख सकते हैं (उदा., स्ट्रिंग्स जैसे `JADXBLOCK`)।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
देखे गए उदाहरण: `0xCAFE` ("Java Executable") या `0x414A` ("JA:") जैसे अज्ञात IDs जो बड़े payloads ले जा रहे थे।

DFIR ह्यूरिस्टिक्स:
- कोर एंट्रीज़ (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े हों तो अलर्ट करें।
- उन एंट्रीज़ पर अज्ञात Extra IDs को संदिग्ध मानें।

व्यावहारिक निवारण: archive को फिर से बनाने से (उदा., निकाले गए फाइलों को re-zipping) दुर्भावनापूर्ण Extra fields हट जाते हैं। यदि tools नकली एन्क्रिप्शन के कारण extract करने से इनकार करते हैं, तो पहले ऊपर जैसा GPBF bit 0 साफ़ करें, फिर पुनः पैकेज करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) फ़ाइल/डायरेक्टरी नाम टकराव (वास्तविक आर्टिफैक्ट छिपाना)

एक ZIP में एक ही समय में एक फ़ाइल `X` और एक डायरेक्टरी `X/` हो सकती है। कुछ extractors और decompilers भ्रमित हो जाते हैं और डायरेक्टरी एंट्री के साथ वास्तविक फ़ाइल को ओवरले या छिपा सकते हैं। यह core APK नामों जैसे `classes.dex` के साथ एंट्री के टकराने में देखा गया है।

Triage and safe extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
प्रोग्रामैटिक डिटेक्शन पोस्ट-फिक्स:
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Blue-team detection ideas:
- उन APKs को फ़्लैग करें जिनके local headers एन्क्रिप्शन को चिह्नित करते हैं (GPBF bit 0 = 1) फिर भी install/run होते हैं।
- core entries पर बड़े/अज्ञात Extra fields को फ़्लैग करें (markers जैसे `JADXBLOCK` देखें)।
- path-collisions को फ़्लैग करें (`X` और `X/`) विशेष रूप से `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए।

---

## संदर्भ

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
