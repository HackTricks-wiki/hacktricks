# ZIPs ट्रिक्स

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zip files को प्रबंधित करने के लिए, zip फ़ाइलों का निदान, मरम्मत और क्रैकिंग करने के लिए आवश्यक हैं। यहाँ कुछ प्रमुख उपयोगिताएँ हैं:

- **`unzip`**: बताता है कि zip फ़ाइल क्यों निकाली/decompress नहीं हो रही।
- **`zipdetails -v`**: zip फ़ाइल फॉर्मेट के फ़ील्ड्स का विस्तृत विश्लेषण देता है।
- **`zipinfo`**: बिना निकालने के zip फ़ाइल की सामग्री सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: टूटी हुई zip फ़ाइलों की मरम्मत का प्रयास करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip पासवर्ड्स को ब्रूट-फोर्स से क्रैक करने का टूल, लगभग 7 कैरेक्टर्स तक के पासवर्ड्स के लिए प्रभावी।

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip फ़ाइलों की संरचना और मानकों पर व्यापक विवरण प्रदान करता है।

यह जानना महत्वपूर्ण है कि पासवर्ड-प्रोटेक्टेड zip फ़ाइलें अंदर की फ़ाइलों के नाम या फ़ाइल साइज को **एन्क्रिप्ट नहीं करतीं**, यह एक सुरक्षा दोष है जो RAR या 7z जैसी फ़ाइलों में मौजूद एन्क्रिप्शन के साथ साझा नहीं होता (वे यह जानकारी एन्क्रिप्ट करते हैं)। इसके अलावा, ZipCrypto मेथड से एन्क्रिप्ट की गई zip फ़ाइलें असुरक्षित हैं और यदि संकुचित फ़ाइल की एक अनएन्क्रिप्टेड कॉपी उपलब्ध है तो वे एक **plaintext attack** के प्रति संवेदनशील होती हैं। यह हमला ज्ञात सामग्री का उपयोग करके zip का पासवर्ड क्रैक कर देता है — इस कमजोरि का विवरण [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) में और [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) में दिया गया है। हालांकि, **AES-256** एन्क्रिप्शन वाली zip फ़ाइलें इस plaintext attack से सुरक्षित हैं, जो संवेदनशील डेटा के लिए सुरक्षित एन्क्रिप्शन विधियों के चयन का महत्व दर्शाता है।

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

आधुनिक Android malware droppers malformed ZIP metadata का उपयोग करके static tools (jadx/apktool/unzip) को तोड़ते हैं, जबकि APK को डिवाइस पर installable बनाए रखते हैं। सबसे आम ट्रिक्स हैं:

- ZIP General Purpose Bit Flag (GPBF) के bit 0 को सेट करके Fake encryption
- पार्सर्स को भ्रमित करने के लिए बड़े/कस्टम Extra fields का दुरुपयोग
- वास्तविक आर्टिफैक्ट्स छिपाने के लिए फ़ाइल/डायरेक्टरी नामों का टकराव (जैसे, वास्तविक `classes.dex` के बगल में `classes.dex/` नाम का एक डायरेक्टरी)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

लक्षण:
- `jadx-gui` निम्न त्रुटियों के साथ फेल हो जाता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` कोर APK फ़ाइलों के लिए पासवर्ड पूछता है, हालांकि एक वैध APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection with zipdetails:
```bash
zipdetails -v sample.apk | less
```
स्थानीय और केंद्रीय हेडर के लिए General Purpose Bit Flag को देखें। एक संकेतक मान है कि bit 0 सेट (Encryption) है, यहाँ तक कि core entries के लिए भी:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ह्यूरिस्टिक: यदि एक APK डिवाइस पर इंस्टॉल होकर चलता है लेकिन core एंट्रीज़ टूल्स को "encrypted" दिखाई देती हैं, तो GPBF में छेड़छाड़ की गई है।

GPBF बिट 0 को दोनों Local File Headers (LFH) और Central Directory (CD) एंट्रीज़ में क्लियर करके ठीक करें। Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
</details>

उपयोग:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
अब आपको कोर एंट्रियों पर `General Purpose Flag  0000` दिखना चाहिए और टूल्स APK को फिर से पार्स कर लेंगे।

### 2) बड़े/कस्टम Extra फ़ील्ड जो पार्सर्स को तोड़ दें

हमलावर बहुत बड़े Extra फ़ील्ड और अजीब IDs को हैडर्स में भर देते हैं ताकि decompilers फंस जाएँ। वास्तविक दुनिया में आप कस्टम मार्कर्स (उदा., स्ट्रिंग्स जैसे `JADXBLOCK`) वहां एम्बेडेड देख सकते हैं।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
देखे गए उदाहरण: अज्ञात IDs जैसे `0xCAFE` ("Java Executable") या `0x414A` ("JA:") जिनमें बड़े payloads होते हैं।

DFIR heuristics:
- Alert जब core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े हों।
- उन एंट्रियों पर unknown Extra IDs को suspicious समझें।

Practical mitigation: archive को पुनः बनाना (उदा., re-zipping extracted files) malicious Extra fields को हटा देता है। यदि tools नकली encryption के कारण extract करने से इनकार करते हैं, तो पहले ऊपर बताए अनुसार GPBF bit 0 को clear करें, फिर repackage करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) फ़ाइल/डायरेक्टरी नाम टकराव (वास्तविक अवशेषों को छिपाना)

एक ZIP एक ही बार में फ़ाइल `X` और डायरेक्टरी `X/` दोनों रख सकता है। कुछ extractors और decompilers भ्रमित हो जाते हैं और डायरेक्टरी एंट्री के साथ असली फ़ाइल को ओवरले या छिपा सकते हैं। यह मुख्य APK नामों जैसे `classes.dex` के साथ टकराने वाली एंट्रीज़ के साथ देखा गया है।

प्राथमिक जाँच और सुरक्षित निष्कर्षण:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
प्रोग्रामेटिक डिटेक्शन पोस्ट-फिक्स:
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
ब्लू-टीम डिटेक्शन विचार:
- उन APKs को फ़्लैग करें जिनके लोकल हैडर encryption (GPBF bit 0 = 1) दिखाते हैं, फिर भी वे install/run होते हैं।
- कोर एंट्रीज़ पर बड़े/अज्ञात Extra fields को फ़्लैग करें (ऐसे मार्कर देखें जैसे `JADXBLOCK`)।
- पाथ-कॉलिज़न (`X` और `X/`) को फ़्लैग करें, विशेषकर `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए।

---

## अन्य दुर्भावनापूर्ण ZIP ट्रिक्स (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

हालिया phishing campaigns एक single blob भेजती हैं जो वास्तव में **two ZIP files concatenated** होती है। प्रत्येक में उसकी अपनी End of Central Directory (EOCD) + central directory होती है। अलग-अलग extractors अलग-अलग directories पार्स करते हैं (7zip पहला पढ़ता है, WinRAR आख़िरी), जिससे attackers उन payloads को छुपा सकते हैं जिन्हें केवल कुछ tools ही दिखाती हैं। यह उन basic mail gateway AVs को भी बायपास करता है जो केवल पहले directory का निरीक्षण करते हैं।

**ट्रायज कमांड्स**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
यदि एक से अधिक EOCD दिखाई देते हैं या "data after payload" चेतावनियाँ मिलती हैं, तो blob को विभाजित करें और प्रत्येक भाग की जाँच करें:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

आधुनिक "better zip bomb" एक छोटा सा **kernel** बनाता है (highly compressed DEFLATE block) और overlapping local headers के माध्यम से इसे पुन: उपयोग करता है। प्रत्येक central directory entry उसी compressed data की ओर इशारा करता है, जिससे बिना nesting archives के >28M:1 अनुपात हासिल किए जा सकते हैं। जो libraries central directory sizes पर भरोसा करती हैं (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) उन्हें petabytes तक allocate करने के लिए मजबूर किया जा सकता है।

**त्वरित पहचान (duplicate LFH offsets)**
```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**हैंडलिंग**
- dry-run जाँच करें: `zipdetails -v file.zip | grep -n "Rel Off"` और सुनिश्चित करें कि offsets सख्ती से बढ़ते और अद्वितीय हों।
- निकालने से पहले स्वीकार्य कुल अनकंप्रेस्ड साइज और एंट्री काउंट को सीमित करें (`zipdetails -t` या कस्टम पार्सर)।
- जब आपको निकालना आवश्यक हो, तो इसे cgroup/VM के अंदर CPU+disk सीमाओं के साथ करें (अनियंत्रित इनफ्लेशन-आधारित क्रैश से बचें)।

---

## संदर्भ

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
