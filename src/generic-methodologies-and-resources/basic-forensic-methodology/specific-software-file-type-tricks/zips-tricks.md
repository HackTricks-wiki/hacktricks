# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za kusimamia **zip files** ni muhimu kwa kutambua matatizo, kurekebisha, na kuvunja zip files. Hapa kuna utilities muhimu:<sup>[[1]](#references)</sup>

- **`unzip`**: Hufichua sababu inayoweza kufanya zip file ishindwe ku-decompress.
- **`zipdetails -v`**: Hutoa uchanganuzi wa kina wa fields za zip file format.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Huorodhesha yaliyomo kwenye zip file bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Hujaribu kurekebisha zip files zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Tool ya brute-force cracking ya zip passwords, yenye ufanisi kwa passwords zenye hadi takriban herufi 7.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) hutoa maelezo ya kina kuhusu muundo na standards za zip files.<sup>[[4]](#references)</sup>

Ni muhimu kutambua kwamba zip files zenye password **hazisimbaji kwa encryption filenames au file sizes** zilizomo ndani yake, ambayo ni security flaw ambayo haipo kwenye RAR au 7z files zinazofanya encryption ya taarifa hizi. Zaidi ya hayo, zip files zilizofanyiwa encryption kwa kutumia method ya zamani ya ZipCrypto ziko hatarini kwa **plaintext attack** ikiwa nakala isiyofanyiwa encryption ya compressed file inapatikana.<sup>[[1]](#references)</sup> Attack hii hutumia content inayojulikana kuvunja password ya zip, vulnerability iliyoelezwa kwa kina katika [makala ya HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [academic paper hii](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Hata hivyo, zip files zilizolindwa kwa **AES-256** encryption haziathiriwi na plaintext attack hii, jambo linaloonyesha umuhimu wa kuchagua encryption methods salama kwa sensitive data.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks katika APKs kwa kutumia ZIP headers zilizobadilishwa

Modern Android malware droppers hutumia malformed ZIP metadata kuvuruga static tools (jadx/apktool/unzip) huku zikiifanya APK iweze kusakinishwa kwenye kifaa. Mbinu zinazotumika zaidi ni:<sup>[[2]](#references)</sup>

- Fake encryption kwa kuweka bit 0 ya ZIP General Purpose Bit Flag (GPBF)
- Kutumia vibaya Extra fields kubwa/custom ili kuchanganya parsers
- File/directory name collisions za kuficha artifacts halisi (kwa mfano, directory inayoitwa `classes.dex/` iliyo karibu na `classes.dex` halisi)

### 1) Fake encryption (GPBF bit 0 set) bila crypto halisi

Dalili:
- `jadx-gui` hushindwa na errors kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` huomba password kwa core APK files ingawa APK halali haiwezi kuwa na `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml` zilizofanyiwa encryption:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Utambuzi kwa kutumia zipdetails:
```bash
zipdetails -v sample.apk | less
```
Angalia General Purpose Bit Flag ya local na central headers. Thamani bainifu ni bit 0 kuwa set (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: Ikiwa APK inasakinika na kufanya kazi kwenye kifaa lakini entries za msingi zinaonekana kuwa "encrypted" kwa tools, GPBF imechezewa.

Rekebisha kwa kuondoa bit 0 ya GPBF katika Local File Headers (LFH) na entries za Central Directory (CD). Minimal byte-patcher:

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

Matumizi:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Unapaswa sasa kuona `General Purpose Flag  0000` kwenye core entries, na tools zitaweza kuichanganua APK tena.

### 2) Extra fields kubwa/custom za kuvuruga parsers

Attackers huweka Extra fields zenye ukubwa kupita kiasi na IDs zisizo za kawaida kwenye headers ili kuvuruga decompilers. Katika mazingira halisi unaweza kuona custom markers (kwa mfano, strings kama `JADXBLOCK`) zikiwa zimewekwa humo.

Ukaguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano iliyobainika: IDs zisizojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") zikiwa na payloads kubwa.

Mbinu za DFIR:
- Toa alert wakati Extra fields ni kubwa isivyo kawaida kwenye entries msingi (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kuwa za kutia shaka.

Mitigation ya kivitendo: kujenga upya archive (kwa mfano, kuunda upya zip ya files zilizotolewa) huondoa Extra fields hasidi. Ikiwa tools zinakataa kutoa files kwa sababu ya fake encryption, kwanza futa GPBF bit 0 kama ilivyo hapo juu, kisha pakia upya:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Migongano ya majina ya faili/saraka (kuficha artifacts halisi)

ZIP inaweza kuwa na faili `X` na saraka `X/` kwa wakati mmoja. Baadhi ya extractors na decompilers huchanganyikiwa na zinaweza kufunika au kuficha faili halisi kwa entry ya saraka. Hili limeonekana kwenye entries zinazogongana na majina msingi ya APK kama `classes.dex`.

Uchunguzi wa awali na extraction salama:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Ugunduzi wa kiprogramu baada ya marekebisho:
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
- Flag APKs ambazo local headers zake zinaonyesha encryption (GPBF bit 0 = 1) lakini zinaweza kusakinishwa/kuendeshwa.
- Flag Extra fields kubwa/isiyojulikana kwenye core entries (tafuta markers kama `JADXBLOCK`).
- Flag path-collisions (`X` na `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine za malicious ZIP (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Phishing campaigns za hivi karibuni husafirisha blob moja ambayo kwa kweli ni **ZIP files mbili zilizounganishwa**. Kila moja ina End of Central Directory (EOCD) + central directory yake. Extractors tofauti huchanganua directories tofauti (7zip husoma ya kwanza, WinRAR ya mwisho), hivyo kuwawezesha attackers kuficha payloads ambazo zinaonyeshwa na baadhi tu ya tools. Hii pia hupita basic mail gateway AV inayokagua directory ya kwanza pekee.<sup>[[5]](#references)[[6]](#references)</sup>

**Amri za Triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ikiwa zaidi ya EOCD moja itaonekana au kuna maonyo ya "data after payload", gawanya blob na kagua kila sehemu:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Miundo ya kisasa ya **better zip bomb** huunda **kernel** ndogo (DEFLATE block iliyobanwa sana) na kuitumia tena kupitia local headers zinazoingiliana. Kila central directory entry huelekeza kwenye data ileile iliyobanwa, hivyo kufikia uwiano wa >28M:1 bila kuweka archives ndani ya nyingine. Libraries zinazoamini ukubwa wa central directory (`zipfile` ya Python, `java.util.zip` ya Java, Info-ZIP kabla ya builds zilizoimarishwa) zinaweza kulazimishwa ku-allocate petabytes.<sup>[[7]](#references)[[8]](#references)</sup>

**Utambuzi wa haraka (duplicate LFH offsets)**
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
**Utunzaji**
- Fanya ukaguzi wa dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` na uhakikishe kuwa offsets zinaongezeka kwa mpangilio mkali na ni za kipekee.
- Weka kikomo cha jumla ya ukubwa usiobanwa na idadi ya entries zinazokubalika kabla ya extraction (`zipdetails -t` au custom parser).
- Unapolazimika kufanya extraction, ifanyie kazi ndani ya cgroup/VM yenye vikomo vya CPU+disk (epuka crashes zinazosababishwa na inflation isiyo na kikomo).

---

### Mkanganyiko wa parser kati ya Local-header na central-directory

Utafiti wa hivi karibuni wa differential-parser umeonyesha kuwa utata wa ZIP bado unaweza kutumiwa vibaya katika toolchains za kisasa. Wazo kuu ni rahisi: baadhi ya software huamini **Local File Header (LFH)**, huku nyingine zikiamini **Central Directory (CD)**, hivyo archive moja inaweza kuwasilisha filenames, paths, comments, offsets, au entry sets tofauti kwa tools tofauti.<sup>[[9]](#references)</sup>

Matumizi ya vitendo ya offensive:
- Fanya upload filter, AV pre-scan, au package validator ione file salama katika CD, huku extractor ikifuata jina/path tofauti ya LFH.
- Tumia vibaya duplicate names, entries zinazopatikana katika structure moja pekee, au metadata tata ya Unicode path (kwa mfano, Info-ZIP Unicode Path Extra Field `0x7075`) ili parsers tofauti zijenge trees tofauti.
- Changanya hili na path traversal ili kubadilisha mwonekano wa archive "isiyo na madhara" kuwa write-primitive wakati wa extraction. Kwa upande wa extraction, tazama [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage ya DFIR:
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
Ikamilishe kwa:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Kataa au tenga archives zenye majina ya LFH/CD yasiyolingana, filenames zinazorudiwa, records nyingi za EOCD, au bytes zinazofuata baada ya EOCD ya mwisho.<sup>[[10]](#references)</sup>
- Chukulia ZIP zinazotumia unusual Unicode-path extra fields au comments zisizolingana kuwa za kutiliwa shaka ikiwa tools tofauti hazikubaliani kuhusu extracted tree.<sup>[[9]](#references)</sup>
- Ikiwa analysis ni muhimu zaidi kuliko kuhifadhi bytes za awali, repackage archive kwa kutumia strict parser baada ya extraction kwenye sandbox, kisha linganisha file list inayotokana na metadata ya awali.

Hili ni muhimu zaidi ya package ecosystems: aina hii ya ambiguity inaweza kuficha payloads kutoka kwa mail gateways, static scanners, na custom ingestion pipelines zinazofanya "peek" kwenye ZIP contents kabla ya extractor tofauti kushughulikia archive.

---



## Marejeo

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
