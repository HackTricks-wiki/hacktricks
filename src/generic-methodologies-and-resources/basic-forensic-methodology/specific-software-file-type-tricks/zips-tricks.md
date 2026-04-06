# Mbinu za ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Zana za mstari wa amri** za kusimamia **faili za zip** ni muhimu kwa kutambua matatizo, kutengeneza, na kuvunja faili za zip. Hapa kuna zana muhimu:

- **`unzip`**: Inaonyesha kwa nini faili ya zip inaweza isifunguliwe.
- **`zipdetails -v`**: Hutoa uchambuzi wa kina wa nyanja za muundo wa faili za zip.
- **`zipinfo`**: Inataja yaliyomo ndani ya faili ya zip bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kutengeneza faili za zip zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya kuvunja nenosiri za zip kwa brute-force, inafaa kwa nenosiri hadi karibu herufi 7.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) inatoa maelezo kamili juu ya muundo na viwango vya faili za zip.

Ni muhimu kutambua kuwa faili za zip zilizolindwa kwa nenosiri **hazifuniki majina ya faili au ukubwa wa faili** ndani yao, kasoro ya usalama ambayo haiwakii RAR au 7z ambao huwafunika taarifa hizi. Zaidi ya hayo, faili za zip zilizofunikwa kwa njia ya zamani ZipCrypto zinaweza kushambuliwa kwa **plaintext attack** ikiwa nakala isiyo wazi ya faili iliyosindika ipo. Shambulio hili linatumia maudhui yatakayojulikana kuvunja nenosiri la zip, kasoro iliyofafanuliwa zaidi katika [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na ilielezwa zaidi katika [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Hata hivyo, faili za zip zilizolindwa kwa **AES-256** zina kinga dhidi ya plaintext attack, zikionyesha umuhimu wa kuchagua mbinu thabiti za usimbaji kwa data nyeti.

---

## Mbinu za anti-reversing katika APKs kwa kutumia vichwa vya ZIP vilivyodanganywa

Dropper za malware za kisasa za Android zinatumia metadata ya ZIP iliyokataliwa ili kuvunja zana za static (jadx/apktool/unzip) huku zikiweka APK iweze kusanidiwa kwenye kifaa. Mbinu zinazotumika mara kwa mara ni:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Dalili:
- `jadx-gui` inashindwa na makosa kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` inauliza nenosiri kwa faili za msingi za APK ingawa APK halali hawezi kuwa na encrypted `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Ugunduzi kwa kutumia zipdetails:
```bash
zipdetails -v sample.apk | less
```
Angalia General Purpose Bit Flag ya local na central headers. Thamani inayoonyesha ni bit 0 set (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiki: Ikiwa APK inasakinishwa na kuendeshwa kwenye kifaa lakini core entries zinaonekana "encrypted" kwa tools, GPBF iliharibiwa.

Rekebisha kwa kufuta biti 0 ya GPBF katika Local File Headers (LFH) na Central Directory (CD) entries. Minimal byte-patcher:

<details>
<summary>Patcher ndogo ya kufuta biti 0 ya GPBF</summary>
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
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye core entries na zana zitachakata APK tena.

### 2) Large/custom Extra fields za kuvunja parsers

Washambulizi huweka Extra fields kubwa mno na IDs zisizo za kawaida ndani ya headers ili kuwashusha decompilers. Katika mazingira ya kawaida unaweza kuona alama maalum (kwa mfano, strings kama `JADXBLOCK`) zilizoingizwa hapo.

Uchunguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano yaliyobainika: vitambulisho visivyojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") vinavyobeba payload kubwa.

Vigezo vya DFIR:
- Toa onyo wakati Extra fields zinapokuwa kubwa kupita kiasi kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kuwa za shaka.

Kupunguza madhara kwa vitendo: kujenga upya archive (kwa mfano, re-zipping extracted files) huondoa Extra fields zenye uovu. Ikiwa tools zikikataa ku-extract kutokana na fake encryption, kwanza clear GPBF bit 0 kama ilivyoelezwa hapo juu, kisha repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Migongano ya majina ya Faili/Katalogi (kuwaficha vielelezo halisi)

ZIP inaweza kuwa na faili `X` na pia katalogi `X/`. Wachimbaji wa faili na decompilers wengine wanaweza kuchanganyikiwa na kuweza kuweka juu au kuficha faili halisi na rekodi ya katalogi. Hii imeonekana wakati rekodi zinapogongana na majina ya msingi ya APK kama `classes.dex`.

Triage na uchimbaji salama:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Post-fix ya utambuzi wa programu:
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
Mapendekezo ya utambuzi kwa Blue-team:
- Alamisha APKs ambazo vichwa vyao vya ndani vinaonyesha encryption (GPBF bit 0 = 1) lakini zinaweza kusakinishwa/kukimbia.
- Alamisha uwanja mkubwa/usiojulikana wa Extra kwenye sehemu za msingi (angalia alama kama `JADXBLOCK`).
- Alamisha migongano ya njia (`X` na `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine za ZIP zenye madhara (2024–2026)

### Central directories zilizounganishwa (multi-EOCD evasion)

Kampeni za hivi karibuni za phishing hutuma blob moja ambayo kwa kweli ni **ZIP files mbili zilizounganishwa**. Kila moja ina End of Central Directory (EOCD) yake + central directory. Extractors tofauti hufasiri directories tofauti (7zip husoma ya kwanza, WinRAR ya mwisho), kuruhusu watapeli kuficha payload ambazo zana fulani tu zinaonyesha. Hii pia inaepuka AV ya mail gateway ya msingi inayochunguza tu directory ya kwanza.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ikiwa EOCD zaidi ya moja inaonekana au kuna onyo la "data after payload", gawanya blob na kagua kila sehemu:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Ya kisasa "better zip bomb" huunda **kernel** ndogo (DEFLATE block iliyoshinikizwa sana) na kuirudia kwa kutumia overlapping local headers. Kila central directory entry inaelekeza kwenye data iliyoshinikizwa ile ile, ikifikia uwiano wa >28M:1 bila nesting archives. Maktaba zinazomwamini ukubwa wa central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) zinaweza kulazimishwa kutenga petabytes.

**Ugunduzi wa haraka (duplicate LFH offsets)**
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
**Kushughulikia**
- Fanya dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` na hakikisha offsets zinaongezeka kwa utaratibu na ni za kipekee.
- Weka kikomo kwa jumla ya ukubwa usiokandamizwa na idadi ya entries kabla ya extraction (`zipdetails -t` or custom parser).
- Unapohitajika kufanya extraction, fanya ndani ya cgroup/VM yenye vikwazo vya CPU na disk (epuka crashes zinazotokana na kuongezeka bila kikomo).

---

### Mchanganyiko wa parser: Local-header vs Central-directory

Tafiti za hivi karibuni za differential-parser zilionyesha kwamba kutokuwa na uwazi kwa ZIP bado kunaweza kutumiwa katika toolchains za kisasa. Wazo kuu ni rahisi: baadhi ya software inaamini **Local File Header (LFH)** wakati nyingine zinaamini **Central Directory (CD)**, hivyo archive moja inaweza kuonyesha majina tofauti ya faili, paths, comments, offsets, au seti za entries kwa zana tofauti.

Matumizi ya vitendo ya mashambulizi:
- Fanya filter ya upload, AV pre-scan, au package validator ione faili isiyo-hatari katika CD ilhali extractor inathamini jina/ njia tofauti kutoka LFH.
- Nyanyasa majina dufu, entries zilizopo tu katika muundo mmoja, au metadata ya Unicode ya njia isiyo wazi (kwa mfano, Info-ZIP Unicode Path Extra Field `0x7075`) ili parser tofauti zijajengea miti tofauti.
- Changanya hili na path traversal ili kugeuza muonekano wa archive "harmless" kuwa write-primitive wakati wa extraction. Kwa upande wa extraction, ona [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
I don't have the file contents to complement or translate. Please either:

- Paste the markdown/html content from src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md that you want complemented and translated, or
- Describe exactly what text or sections you want me to add (and any examples/code to include).

I'll return the complemented content translated to Swahili, preserving all markdown/html tags, links, paths and code unchanged.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Kanuni za uchambuzi:
- Kata au pasha kando archives zenye majina ya LFH/CD yasiyolingana, majina ya faili yanayorudiwa, rekodi nyingi za EOCD, au bytes za ziada baada ya EOCD ya mwisho.
- Tibu ZIPs zinazotumia unusual Unicode-path extra fields au comments zisizo thabiti kama zenye shaka ikiwa tools tofauti hazikubaliani kuhusu mti uliotolewa.
- Ikiwa uchambuzi ni muhimu zaidi kuliko kuhifadhi bytes za awali, repack the archive kwa strict parser baada ya extraction katika sandbox na linganisha orodha ya faili iliyotokana na metadata ya awali.

Hii ni muhimu zaidi ya package ecosystems: darasa sawa la ambiguity linaweza kuficha payloads kutoka kwa mail gateways, static scanners, na custom ingestion pipelines ambazo "peek" at ZIP contents kabla extractor tofauti ashughulikie archive.

---

## Marejeo

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
