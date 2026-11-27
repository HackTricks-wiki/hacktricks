# ZIPs की tricks

{{#include ../../../banners/hacktricks-training.md}}

**कमांड-लाइन टूल** **zip files** को प्रबंधित करने के लिए आवश्यक हैं, ताकि उनकी समस्याओं का पता लगाया जा सके, उन्हें ठीक किया जा सके और उनके passwords crack किए जा सकें। यहाँ कुछ प्रमुख utilities दी गई हैं:<sup>[[1]](#references)</sup>

- **`unzip`**: यह पता लगाने में मदद करता है कि zip file decompress क्यों नहीं हो सकती।
- **`zipdetails -v`**: zip file format के fields का विस्तृत विश्लेषण देता है।<sup>[[3]](#references)</sup>
- **`zipinfo`**: zip file की contents को extract किए बिना सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: corrupted zip files को ठीक करने की कोशिश करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP passwords पर dictionary और brute-force attacks के लिए एक tool; इसकी व्यवहार्यता password search space पर निर्भर करती है।<sup>[[15]](#references)</sup>

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip files की संरचना और standards के बारे में व्यापक जानकारी देता है।<sup>[[4]](#references)</sup>

पारंपरिक password-protected ZIP files में आम तौर पर filenames और file sizes दिखाई देते हैं, जबकि RAR और 7z में header-encryption modes इन्हें छिपा सकते हैं। ZipCrypto known-plaintext attack से **internal encryption keys** recover होती हैं, ज़रूरी नहीं कि मूल password भी मिले; ये keys उसी password से encrypted entries को decrypt करने के लिए पर्याप्त हैं।<sup>[[13]](#references)</sup> इस attack के लिए stream के **encryption से पहले** के ज्ञात bytes चाहिए: stored member के लिए ये मूल file के bytes होते हैं, लेकिन DEFLATE member के लिए ये compressed bytes होते हैं, जिन्हें पाने के लिए compression का ठीक वही output फिर से बनाना पड़ सकता है।<sup>[[13]](#references)[[14]](#references)</sup> व्यावहारिक प्रक्रिया के लिए [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) देखें। Cryptanalysis की पृष्ठभूमि के लिए [लेख](https://math.ucr.edu/~mike/zipattacks.pdf) और [चरण-दर-चरण विवरण](https://www.hackthissite.org/articles/read/793) देखें।<sup>[[11]](#references)[[12]](#references)</sup> यह ZipCrypto attack AES-encrypted ZIP entries पर लागू नहीं होता।<sup>[[13]](#references)</sup>

---

## Manipulated ZIP headers का उपयोग करके APKs में Anti-reversing tricks

आधुनिक Android malware droppers malformed ZIP metadata का उपयोग करके static tools (jadx/apktool/unzip) को बाधित करते हैं, जबकि APK को डिवाइस पर installable बनाए रखते हैं। सबसे आम tricks हैं:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) का bit 0 सेट करके fake encryption दिखाना
- Parsers को भ्रमित करने के लिए बड़े/custom Extra fields का दुरुपयोग करना
- असली artifacts छिपाने के लिए file/directory के नामों में टकराव पैदा करना (उदाहरण के लिए, असली `classes.dex` के साथ `classes.dex/` नाम की directory रखना)

### 1) असली crypto के बिना fake encryption (GPBF bit 0 सेट)

लक्षण:
- `jadx-gui` इस तरह की errors के साथ fail होता है:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` मुख्य APK फ़ाइलों के लिए पासवर्ड मांगता है, जबकि किसी मान्य APK में `classes*.dex`, `resources.arsc` या `AndroidManifest.xml` एन्क्रिप्टेड नहीं हो सकते:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

zipdetails से पता लगाना:

```bash
zipdetails -v sample.apk | less
```

Local और central headers के लिए General Purpose Bit Flag देखें। एक स्पष्ट संकेत bit 0 का set होना (Encryption) है, यहाँ तक कि core entries के लिए भी:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristic: अगर कोई APK device पर install होकर चलता है, लेकिन tools में उसकी core entries "encrypted" दिखती हैं, तो GPBF के साथ छेड़छाड़ की गई है।

इसे ठीक करने के लिए, Local File Headers (LFH) और Central Directory (CD) entries—दोनों में GPBF bit 0 को clear करें। Minimal byte-patcher:

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

केवल bit 0 बदलना चाहिए: उदाहरण के लिए, `0A09` बदलकर `0A08` हो जाता है, `0000` नहीं। यह minimal patcher raw bytes में header signatures ढूँढ़ता है, इसलिए file data के भीतर signature जैसी bytes से false matches हो सकते हैं; output इस्तेमाल करने से पहले उसकी copy पर काम करें और resulting entry list तथा headers की पुष्टि करें।<sup>[[4]](#references)</sup>

### 2) Parsers को तोड़ने के लिए बड़े/custom Extra fields

Attackers, decompilers को गड़बड़ाने के लिए headers में oversized Extra fields और असामान्य IDs भर देते हैं। वास्तविक मामलों में आपको वहाँ embedded custom markers (जैसे, `JADXBLOCK` जैसी strings) दिख सकते हैं।

Inspection:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

देखे गए उदाहरण: अज्ञात IDs जैसे `0xCAFE` ("Java Executable") या `0x414A` ("JA:") में बड़े payloads मौजूद थे।<sup>[[2]](#references)</sup>

DFIR heuristics:
- Core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े होने पर alert करें।
- उन entries पर अज्ञात Extra IDs को suspicious मानें।

व्यावहारिक mitigation: archive को फिर से बनाना (जैसे, निकाली गई files को दोबारा zip करना) malicious Extra fields हटा देता है। यदि fake encryption के कारण tools extract करने से इनकार करें, तो पहले ऊपर बताए अनुसार GPBF bit 0 clear करें, फिर दोबारा package करें:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) File/Directory नामों का टकराव (असली artifacts को छिपाना)

एक ZIP में `X` नाम की फ़ाइल और `X/` नाम की डायरेक्टरी, दोनों हो सकते हैं। कुछ extractors और decompilers भ्रमित हो जाते हैं और डायरेक्टरी entry असली फ़ाइल पर आच्छादित हो सकती है या उसे छिपा सकती है। ऐसा `classes.dex` जैसे core APK नामों से टकराने वाली entries के साथ देखा गया है।

जांच और सुरक्षित extraction:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

फ़िक्स के बाद प्रोग्रामेटिक पहचान:

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
- ऐसे APKs को flag करें जिनके local headers encryption दर्शाते हैं (GPBF bit 0 = 1), फिर भी वे install/run होते हैं।
- Core entries पर बड़े/अज्ञात Extra fields को flag करें (`JADXBLOCK` जैसे markers खोजें)।
- खास तौर पर `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए path-collisions (`X` और `X/`) को flag करें।

---

## अन्य malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

2024 के एक phishing campaign में, attackers ने एक ऐसा blob भेजा जो वास्तव में **दो ZIP files को जोड़कर बनाया गया था**। हर file का अपना End of Central Directory (EOCD) record और central directory था। अलग-अलग extractors ने अलग-अलग directories को parse किया (7-Zip ने पहली, जबकि WinRAR ने आखिरी), जिससे attackers ऐसे payloads छिपा सके जिन्हें केवल कुछ tools दिखाते थे; केवल एक directory की जाँच करने वाले scanners दूसरे archive को miss कर सकते हैं।<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

यदि एक से अधिक EOCD दिखाई दें या "data after payload" चेतावनियाँ हों, तो blob को विभाजित करें और प्रत्येक भाग का निरीक्षण करें:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs एक छोटा **kernel** (अत्यधिक compressed DEFLATE block) बनाते हैं और उसे overlapping entries में reuse करते हैं। Full-overlap variants कई central-directory entries को एक local header पर point करते हैं, जबकि quoted-overlap variants DEFLATE streams के अंदर local headers को quote करते हैं; प्रकाशित construction nested archives के बिना 28M:1 से अधिक compression ratio हासिल करता है।<sup>[[7]](#references)</sup>

**त्वरित पहचान (duplicate LFH offsets)**

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

**हैंडलिंग**
- dry-run walk करें: `zipdetails -v file.zip | grep -n "Local Header Offset"` चलाएँ और संदर्भित local-header offsets तथा compressed-data ranges की तुलना करें; duplicate offsets full-overlap variants का संकेत हैं।<sup>[[7]](#references)[[8]](#references)</sup>
- Extraction से पहले parser की मदद से स्वीकार्य कुल uncompressed size और entry count की सीमा तय करें; `zipinfo -t file.zip` totals दिखाता है, लेकिन कोई safety limit लागू नहीं करता।<sup>[[8]](#references)</sup>
- Extraction ज़रूरी हो, तो इसे CPU और disk limits वाले cgroup/VM के अंदर करें (अनियंत्रित inflation crashes से बचने के लिए)।<sup>[[8]](#references)</sup>

---

### Local-header बनाम central-directory parser confusion

हालिया differential-parser research से पता चला है कि ZIP ambiguity अब भी modern toolchains में exploitable है। मूल विचार सरल है: कुछ software **Local File Header (LFH)** पर भरोसा करते हैं, जबकि अन्य **Central Directory (CD)** पर; इसलिए एक ही archive अलग-अलग tools को अलग filenames, paths, comments, offsets या entry sets दिखा सकता है।<sup>[[9]](#references)</sup>

व्यावहारिक offensive उपयोग:
- ऐसा upload filter, AV pre-scan या package validator बनाएँ जो CD में benign file देखे, जबकि extractor किसी अलग LFH name/path को मानकर चले।
- duplicate names, केवल एक structure में मौजूद entries, या ambiguous Unicode path metadata (उदाहरण के लिए, Info-ZIP Unicode Path Extra Field `0x7075`) का दुरुपयोग करें, ताकि अलग-अलग parsers अलग-अलग trees बनाएँ।
- इसे path traversal के साथ जोड़कर extraction के दौरान किसी “harmless” archive view को write-primitive में बदलें। Extraction वाले हिस्से के लिए, [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) देखें।

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

इसे इनके साथ पूरित करें:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

अनुमान-आधारित संकेत:
- Security-sensitive ingestion के लिए, LFH/CD नामों में mismatch, duplicate filenames, multiple EOCD records, या final EOCD के बाद trailing bytes वाले archives को reject या isolate करें।<sup>[[9]](#references)[[10]](#references)</sup>
- अगर अलग-अलग tools extracted tree पर असहमत हों, तो असामान्य Unicode-path extra fields या inconsistent comments वाले ZIPs को suspicious मानें।<sup>[[4]](#references)[[9]](#references)</sup>
- अगर original bytes को सुरक्षित रखने से ज़्यादा analysis महत्वपूर्ण है, तो sandbox में extraction के बाद strict parser से archive को repackage करें और resulting file list की तुलना original metadata से करें।

यह package ecosystems तक सीमित नहीं है: इसी तरह की ambiguity mail gateways, static scanners और उन custom ingestion pipelines से payloads को छिपा सकती है, जो archive को किसी दूसरे extractor द्वारा handle किए जाने से पहले ZIP contents को "peek" करते हैं।<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF श्रेणी)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – एक multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Undetected malware छिपाने के लिए ZIP archives के flexible structure का exploit (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers ने नए ZIP file attack में malware छिपाया — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [एक बेहतर zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zip Bombs को समझना: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [मेरा ZIP, आपका ZIP नहीं है: ZIP parsers के बीच semantic gaps की पहचान और exploitation (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Python package installers पर ZIP parser confusion attacks को रोकना](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [कम ज्ञात plaintext के साथ ZIP attacks (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: वास्तविक-जैसा Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack का उपयोग](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack known-plaintext tutorial](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip repository](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
