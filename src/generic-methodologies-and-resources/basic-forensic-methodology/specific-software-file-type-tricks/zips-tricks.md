# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**zip files** को manage करने के लिए **Command-line tools** zip files की diagnosis, repair और cracking के लिए आवश्यक हैं। यहाँ कुछ प्रमुख utilities दी गई हैं:<sup>[[1]](#references)</sup>

- **`unzip`**: यह बताता है कि कोई zip file decompress क्यों नहीं हो सकती।
- **`zipdetails -v`**: zip file format fields का विस्तृत analysis प्रदान करता है।<sup>[[3]](#references)</sup>
- **`zipinfo`**: zip file की contents को extract किए बिना list करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: corrupted zip files को repair करने का प्रयास करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip passwords की brute-force cracking के लिए एक tool, जो लगभग 7 characters तक के passwords के लिए प्रभावी है।

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip files की structure और standards के बारे में व्यापक विवरण प्रदान करती है।<sup>[[4]](#references)</sup>

यह ध्यान रखना महत्वपूर्ण है कि traditional password-protected ZIP files आम तौर पर filenames और file sizes को visible छोड़ती हैं, जबकि RAR और 7z द्वारा supported header-encryption modes ऐसा नहीं करते। इसके अलावा, पुराने ZipCrypto method से encrypted ZIP files **plaintext attack** के प्रति vulnerable होती हैं, यदि किसी compressed file की unencrypted copy उपलब्ध हो।<sup>[[1]](#references)</sup> यह attack ज्ञात content का उपयोग करके ZIP के password को crack करता है, जैसा कि [इस academic paper](https://math.ucr.edu/~mike/zipattacks.pdf) में समझाया गया है और [इस Hack This Site walk-through](https://www.hackthissite.org/articles/read/793) में प्रदर्शित किया गया है।<sup>[[11]](#references)[[12]](#references)</sup> हालांकि, ZipCrypto known-plaintext attack **AES-256** encryption से secured entries पर लागू नहीं होता।<sup>[[1]](#references)</sup>

---

## APKs में manipulated ZIP headers के साथ Anti-reversing tricks

Modern Android malware droppers malformed ZIP metadata का उपयोग static tools (jadx/apktool/unzip) को तोड़ने के लिए करते हैं, जबकि APK को on-device installable बनाए रखते हैं। सबसे common tricks हैं:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) के bit 0 को set करके fake encryption
- Parsers को confuse करने के लिए बड़े/custom Extra fields का दुरुपयोग
- Real artifacts को छिपाने के लिए file/directory name collisions (जैसे, real `classes.dex` के पास `classes.dex/` नाम की directory)

### 1) बिना real crypto के Fake encryption (GPBF bit 0 set)

Symptoms:
- `jadx-gui` इस प्रकार की errors के साथ fail होता है:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` core APK files के लिए password prompt दिखाता है, जबकि valid APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails से Detection:
```bash
zipdetails -v sample.apk | less
```
local और central headers के लिए General Purpose Bit Flag देखें। core entries के लिए भी bit 0 का set होना (Encryption) एक स्पष्ट संकेत है:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
हीयूरिस्टिक: यदि कोई APK device पर install और run हो जाता है, लेकिन core entries tools में "encrypted" दिखाई देती हैं, तो GPBF के साथ छेड़छाड़ की गई है।

LFH और CD entries, दोनों में GPBF bit 0 को clear करके इसे ठीक करें। Minimal byte-patcher:

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
अब आपको core entries पर `General Purpose Flag  0000` दिखाई देना चाहिए और tools APK को फिर से parse कर पाएंगे।

### 2) Parsers को तोड़ने के लिए बड़े/custom Extra fields

Attackers decompilers को गड़बड़ाने के लिए headers में oversized Extra fields और असामान्य IDs भर देते हैं। वास्तविक मामलों में आपको वहां embedded custom markers (जैसे `JADXBLOCK` जैसे strings) दिखाई दे सकते हैं।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
देखे गए उदाहरण: बड़े payloads ले जाने वाले अज्ञात IDs जैसे `0xCAFE` ("Java Executable") या `0x414A` ("JA:")।<sup>[[2]](#references)</sup>

DFIR heuristics:
- Core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े होने पर alert करें।
- उन entries पर अज्ञात Extra IDs को suspicious मानें।

Practical mitigation: archive को फिर से बनाना (जैसे extracted files को re-zipping करना) malicious Extra fields को हटा देता है। यदि tools fake encryption के कारण extract करने से मना करें, तो पहले ऊपर बताए अनुसार GPBF bit 0 को clear करें, फिर repackage करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (वास्तविक artifacts को छिपाना)

एक ZIP में file `X` और directory `X/` दोनों हो सकते हैं। कुछ extractors और decompilers भ्रमित हो जाते हैं और directory entry के साथ वास्तविक file को overlay या hide कर सकते हैं। ऐसा `classes.dex` जैसे core APK names के साथ collide करने वाली entries में देखा गया है।

Triage और सुरक्षित extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Fix के बाद Programmatic detection:
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
- ऐसे APKs को flag करें जिनके local headers encryption दर्शाते हैं (GPBF bit 0 = 1), फिर भी वे install/run हो जाते हैं।
- core entries पर मौजूद बड़े/अज्ञात Extra fields को flag करें (`JADXBLOCK` जैसे markers देखें)।
- विशेष रूप से `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए path-collisions (`X` और `X/`) को flag करें।

---

## Other malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

2024 के एक phishing campaign में attackers ने एक single blob भेजा, जो वास्तव में **दो ZIP files concatenated** थीं। प्रत्येक के पास अपना End of Central Directory (EOCD) record और central directory था। अलग-अलग extractors ने अलग directories parse कीं (7-Zip ने पहली पढ़ी, जबकि WinRAR ने आखिरी), जिससे attackers ऐसे payloads छिपा सके जिन्हें केवल कुछ tools दिखाते थे; केवल एक directory inspect करने वाले scanners दूसरे archive को miss कर सकते हैं।<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
यदि एक से अधिक EOCD दिखाई दें या `"data after payload"` warnings हों, तो blob को split करें और प्रत्येक part का निरीक्षण करें:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs एक छोटे **kernel** (अत्यधिक compressed DEFLATE block) का निर्माण करते हैं और overlapping entries में उसका पुनः उपयोग करते हैं। Full-overlap variants कई central-directory entries को एक local header की ओर point करते हैं, जबकि quoted-overlap variants DEFLATE streams के अंदर local headers को quote करते हैं; प्रकाशित construction nested archives के बिना 28M:1 से अधिक अनुपात प्राप्त करता है।<sup>[[7]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
**Handling**
- एक dry-run walk करें: `zipdetails -v file.zip | grep -n "Local Header Offset"` और संदर्भित local-header offsets तथा compressed-data ranges की तुलना करें; duplicate offsets full-overlap variants का संकेत देते हैं।<sup>[[7]](#references)[[8]](#references)</sup>
- Extraction से पहले parser के माध्यम से स्वीकार की जाने वाली कुल uncompressed size और entry count की सीमा तय करें; `zipinfo -t file.zip` totals रिपोर्ट करता है, लेकिन safety limit लागू नहीं करता।<sup>[[8]](#references)</sup>
- जब extraction आवश्यक हो, तो इसे CPU और disk limits वाले cgroup/VM के अंदर करें (unbounded inflation crashes से बचें)।<sup>[[8]](#references)</sup>

---

### Local-header बनाम central-directory parser confusion

हालिया differential-parser research से पता चला है कि modern toolchains में ZIP ambiguity अभी भी exploitable है। मुख्य विचार सरल है: कुछ software **Local File Header (LFH)** पर भरोसा करते हैं, जबकि अन्य **Central Directory (CD)** पर; इसलिए एक archive अलग-अलग tools के सामने अलग filenames, paths, comments, offsets या entry sets प्रस्तुत कर सकता है।<sup>[[9]](#references)</sup>

Practical offensive uses:
- किसी upload filter, AV pre-scan या package validator को CD में एक benign file दिखाएँ, जबकि extractor किसी अलग LFH name/path को मान्य करे।
- duplicate names, केवल एक structure में मौजूद entries या ambiguous Unicode path metadata (उदाहरण के लिए, Info-ZIP Unicode Path Extra Field `0x7075`) का दुरुपयोग करें, ताकि अलग-अलग parsers अलग trees reconstruct करें।
- इसे path traversal के साथ combine करके extraction के दौरान एक "harmless" archive view को write-primitive में बदलें। Extraction side के लिए [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) देखें।

DFIR triage:
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
इसे निम्नलिखित से पूरक करें:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Security-sensitive ingestion के लिए, ऐसे archives को reject या isolate करें जिनमें असंगत LFH/CD names, duplicate filenames, multiple EOCD records, या अंतिम EOCD के बाद trailing bytes हों।<sup>[[9]](#references)[[10]](#references)</sup>
- असामान्य Unicode-path extra fields या असंगत comments वाले ZIPs को suspicious मानें, यदि अलग-अलग tools द्वारा extracted tree में अंतर हो।<sup>[[4]](#references)[[9]](#references)</sup>
- यदि original bytes को preserve करने से अधिक महत्वपूर्ण analysis है, तो archive को sandbox में extraction के बाद strict parser के साथ repack करें और परिणामी file list की original metadata से तुलना करें।

यह package ecosystems से आगे भी महत्वपूर्ण है: यही ambiguity class mail gateways, static scanners और custom ingestion pipelines से payloads को छिपा सकती है, जो ZIP contents को "peek" करते हैं और फिर किसी अलग extractor से archive को handle करवाते हैं।<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistic Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
