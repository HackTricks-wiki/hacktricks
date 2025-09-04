# ZIPs ट्रिक्स

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zip फ़ाइलों का प्रबंधन करने के लिए आवश्यक हैं, जो zip फ़ाइलों का निदान, मरम्मत और क्रैक करने में मदद करते हैं। यहां कुछ प्रमुख यूटिलिटीज़ हैं:

- **`unzip`**: बताता है कि zip फ़ाइल क्यों डीकम्प्रेस नहीं हो रही।
- **`zipdetails -v`**: zip फ़ाइल फॉर्मैट फ़ील्ड्स का विस्तृत विश्लेषण देता है।
- **`zipinfo`**: बिना निकाले zip फ़ाइल की सामग्री सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: करप्टेड zip फ़ाइलों की मरम्मत करने की कोशिश करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ज़िप पासवर्ड्स के ब्रूट-फोर्स क्रैकिंग के लिए एक टूल, लगभग 7 कैरेक्टर्स तक के पासवर्ड्स के लिए प्रभावी।

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip फ़ाइलों की संरचना और मानकों पर व्यापक जानकारी प्रदान करता है।

यह ध्यान रखना महत्वपूर्ण है कि पासवर्ड-प्रोटेक्टेड zip फ़ाइलें अंदर के filenames या file sizes को एन्क्रिप्ट नहीं करतीं, यह एक सुरक्षा दोष है जो RAR या 7z फ़ाइलों में मौजूद नहीं है जो इस जानकारी को एन्क्रिप्ट करते हैं। इसके अलावा, ZipCrypto विधि से एन्क्रिप्ट की गई zip फ़ाइलें उस स्थिति में **plaintext attack** के प्रति संवेदनशील होती हैं अगर संकुचित फ़ाइल की एक अनएन्क्रिप्टेड कॉपी उपलब्ध हो। यह हमला ज्ञात सामग्री का उपयोग करके zip का पासवर्ड क्रैक करता है, इस भेद्यता का विवरण [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) में दिया गया है और इसे [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) में और विस्तार से समझाया गया है। हालाँकि, **AES-256** एन्क्रिप्शन से सुरक्षित की गई zip फ़ाइलें इस plaintext attack से प्रतिरक्षित हैं, जो संवेदनशील डेटा के लिए सुरक्षित एन्क्रिप्शन विधियों के चुनाव का महत्व दर्शाता है।

---

## APKs में संशोधित ZIP हेडर्स का उपयोग करके एंटी-रिवर्सिंग ट्रिक्स

आधुनिक Android malware droppers खराब रूप से बने ZIP metadata का उपयोग करते हैं ताकि वे static tools (jadx/apktool/unzip) को तोड़ दें, जबकि APK को डिवाइस पर इंस्टॉल करने योग्य बनाए रखें। सबसे आम ट्रिक्स हैं:

- ZIP General Purpose Bit Flag (GPBF) का bit 0 सेट करके fake encryption
- parsers को भ्रमित करने के लिए large/custom Extra fields का दुरुपयोग
- फ़ाइल/डायरेक्टरी नाम टकराव का उपयोग करके वास्तविक आर्टिफैक्ट्स छुपाना (उदा., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

लक्षण:
- `jadx-gui` निम्न त्रुटियों के साथ फेल हो जाता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` मुख्य APK फ़ाइलों के लिए पासवर्ड माँगता है, हालाँकि वैध APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

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
local और central headers के लिए General Purpose Bit Flag को देखें। एक संकेतक मान core entries के लिए भी bit 0 set (Encryption) होना है:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
अनुमान: यदि एक APK डिवाइस पर इंस्टॉल और रन होता है लेकिन core entries टूल्स के लिए "encrypted" दिखाई देते हैं, तो GPBF में छेड़छाड़ की गई थी।

समाधान: Local File Headers (LFH) और Central Directory (CD) दोनों एंट्रीज़ में GPBF बिट 0 को क्लियर करें। न्यूनतम byte-patcher:
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
अब आप मुख्य प्रविष्टियों पर `General Purpose Flag  0000` देखेंगे और उपकरण फिर से APK को पार्स करेंगे।

### 2) पार्सर्स तोड़ने के लिए बड़े/कस्टम Extra फ़ील्ड

हमलावर हेडर में अत्यधिक बड़े Extra फ़ील्ड और अजीब IDs भर देते हैं ताकि decompilers फंस जाएँ। असल में आप कस्टम मार्कर्स (उदा., `JADXBLOCK` जैसी strings) वहां embedded देख सकते हैं।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
देखे गए उदाहरण: `0xCAFE` ("Java Executable") या `0x414A` ("JA:") जैसे अनजान IDs बड़े payloads ले जा रहे हैं।

DFIR heuristics:
- जब core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े हों तो alert करें।
- उन entries पर अनजान Extra IDs को संदिग्ध मानें।

Practical mitigation: archive को पुनर्निर्मित करने (उदा., re-zipping extracted files) से malicious Extra fields हट जाते हैं। यदि tools नकली encryption के कारण extract करने से इनकार करें, तो पहले ऊपर बताए अनुसार GPBF bit 0 को clear करें, फिर repackage करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (hiding real artifacts)

एक ZIP में एक फ़ाइल `X` और एक डायरेक्टरी `X/` दोनों हो सकते हैं। कुछ extractors और decompilers भ्रमित हो जाते हैं और डायरेक्टरी एंट्री के साथ वास्तविक फ़ाइल को ओवरले या छुपा सकते हैं। यह core APK नामों जैसे `classes.dex` के साथ एंट्री टकराने के मामलों में देखा गया है।

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
Blue-team डिटेक्शन विचार:
- Flag ऐसे APKs जिनके local headers एन्क्रिप्शन दर्शाते हैं (GPBF bit 0 = 1) फिर भी install/run होते हैं।
- Flag core entries पर बड़े/unknown Extra fields (markers जैसे `JADXBLOCK` देखें)।
- Flag path-collisions (`X` और `X/`) विशेष रूप से `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए।

---

## संदर्भ

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
