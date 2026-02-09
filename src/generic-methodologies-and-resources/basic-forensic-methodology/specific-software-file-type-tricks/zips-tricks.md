# ZIPs ट्रिक्स

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** zip files को मैनेज करने, diagnosis, मरम्मत और cracking करने के लिए आवश्यक हैं। नीचे कुछ प्रमुख उपयोगिताएँ हैं:

- **`unzip`**: बताता है कि कोई zip फ़ाइल क्यों अनज़िप नहीं हो रही।
- **`zipdetails -v`**: zip file format के फील्ड्स का विस्तृत विश्लेषण प्रदान करता है।
- **`zipinfo`**: zip फ़ाइल की सामग्री को बिना extract किए सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: corrupted zip फ़ाइलों की मरम्मत करने का प्रयास करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip passwords के brute-force cracking के लिए एक टूल, लगभग 7 characters तक के पासवर्ड के लिए प्रभावी।

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip फ़ाइलों की संरचना और मानकों पर व्यापक विवरण प्रदान करती है।

यह ध्यान देना महत्वपूर्ण है कि password-protected zip files के भीतर **filenames या file sizes encrypt नहीं होते**, यह एक सुरक्षा दोष है जो RAR या 7z जैसी फ़ाइलों में मौजूद एन्क्रिप्शन के साथ साझा नहीं होता, जो इस जानकारी को encrypt करते हैं। इसके अलावा, पुराने ZipCrypto तरीके से encrypted zip फ़ाइलें तब vulnerable होती हैं जब किसी compressed फ़ाइल की एक unencrypted copy उपलब्ध हो — इस स्थिति में एक **plaintext attack** संभव है। यह हमला ज्ञात कंटेंट का उपयोग करके zip का password क्रैक करने के लिए किया जाता है; इस कमजोर पड़ाव का वर्णन [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) में है और इसे [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) में और विस्तार से समझाया गया है। हालांकि, **AES-256** एन्क्रिप्शन से सुरक्षित zip फ़ाइलें इस plaintext attack से सुरक्षित रहती हैं, जो संवेदनशील डेटा के लिए सुरक्षित एन्क्रिप्शन विधियों के चुनाव का महत्व दर्शाता है।

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

आधुनिक Android malware droppers malformed ZIP metadata का उपयोग करते हैं ताकि static tools (jadx/apktool/unzip) टूट जाएँ, जबकि APK को डिवाइस पर installable बनाए रखा जा सके। सबसे सामान्य ट्रिक्स हैं:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

लक्षण:
- `jadx-gui` इस तरह की errors के साथ fail करता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` core APK files के लिए password पूछता है, जबकि एक valid APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

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
local और central headers के लिए General Purpose Bit Flag देखें। एक सूचक मान bit 0 set (Encryption) है, यहाँ तक कि core entries के लिए भी:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ह्यूरिस्टिक: यदि कोई APK डिवाइस पर इंस्टॉल और चलती है लेकिन टूल्स के लिए मुख्य एंट्रीज़ "encrypted" दिखाई देती हैं, तो GPBF में छेड़छाड़ की गई थी।

GPBF बिट 0 को Local File Headers (LFH) और Central Directory (CD) दोनों एंट्रीज़ में क्लियर करके ठीक करें। Minimal byte-patcher:

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
अब आप कोर एंट्रीज़ पर `General Purpose Flag  0000` देखना चाहिए और टूल्स APK को फिर से पार्स कर पाएँगे।

### 2) बड़े/कस्टम Extra फ़ील्ड्स जो parsers को तोड़ दें

हमलावर हेडर्स में अत्यधिक बड़े Extra फ़ील्ड्स और अजीब IDs भर देते हैं ताकि decompilers फंस जाएँ। वास्तविक परिदृश्य में आप कस्टम मार्कर्स (उदा., स्ट्रिंग्स जैसे `JADXBLOCK`) वहां एम्बेडेड देख सकते हैं।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Examples observed: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR heuristics:
- सतर्क रहें जब core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े हों।
- उन entries पर अज्ञात Extra IDs को संदिग्ध मानें।

Practical mitigation: archive को फिर से बनाना (उदाहरण के लिए, निकाली गई फाइलों को re-zipping) malicious Extra fields को हटा देता है। यदि tools नकली encryption के कारण extract करने से इनकार करते हैं, तो पहले ऊपर बताये अनुसार GPBF bit 0 को clear करें, फिर repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) फ़ाइल/डायरेक्टरी नाम टकराव (वास्तविक आर्टिफैक्ट छिपाना)

एक ZIP में एक फ़ाइल `X` और एक डायरेक्टरी `X/` दोनों हो सकते हैं। कुछ extractors और decompilers भ्रमित हो जाते हैं और डायरेक्टरी एंट्री के साथ वास्तविक फ़ाइल को ओवरले या छिपा सकते हैं। यह देखा गया है कि एंट्रीज़ core APK नामों जैसे `classes.dex` से टकराती हैं।

प्राथमिक जाँच और सुरक्षित निकासी:
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
- चिन्हित करें उन APKs को जिनके स्थानीय हेडर encryption दर्शाते हैं (GPBF bit 0 = 1) फिर भी वे install/run होते हैं।
- चिन्हित करें मुख्य प्रविष्टियों पर बड़ी/अज्ञात Extra fields (ऐसे मार्कर्स देखें जैसे `JADXBLOCK`)।
- चिन्हित करें path-collisions (`X` and `X/`) विशेष रूप से `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए।

---

## अन्य हानिकारक ZIP ट्रिक्स (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

हाल की phishing campaigns एक single blob भेजती हैं जो वास्तव में **दो ZIP files जुड़े हुए** होते हैं। प्रत्येक की अपनी End of Central Directory (EOCD) + central directory होती है। अलग-अलग extractors अलग directories को parse करते हैं (7zip पहला पढ़ता है, WinRAR आखिरी), जिससे attackers ऐसे payloads छुपा सकते हैं जो केवल कुछ टूल्स दिखाते हैं। यह बेसिक mail gateway AV को भी बायपास कर देता है जो केवल पहले directory की जांच करता है।

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
यदि एक से अधिक EOCD दिखाई देते हैं या "data after payload" चेतावनियाँ हैं, तो blob को विभाजित करके प्रत्येक भाग का निरीक्षण करें:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" एक छोटा सा **kernel** (highly compressed DEFLATE block) बनाता है और इसे overlapping local headers के माध्यम से पुन: उपयोग करता है। हर central directory entry उसी compressed data की ओर इशारा करती है, जिससे बिना archives नेस्ट किए >28M:1 अनुपात हासिल किया जा सकता है। central directory sizes पर भरोसा करने वाली लाइब्रेरीज़ (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) को पेटाबाइट्स allocate करने के लिए मजबूर किया जा सकता है।

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
- एक ड्राय-रन वॉक करें: `zipdetails -v file.zip | grep -n "Rel Off"` और सुनिश्चित करें कि offsets सख्ती से बढ़ते हुए और यूनिक हों।
- निष्कर्षण से पहले स्वीकार्य कुल अनकंप्रेस्ड आकार और एंट्री काउंट की सीमा तय करें (`zipdetails -t` or custom parser)।
- जब आपको extract करना अनिवार्य हो, तो इसे cgroup/VM के अंदर CPU+disk सीमाओं के साथ करें (असीमित वृद्धि से होने वाले क्रैश से बचें)।

---

## संदर्भ

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
