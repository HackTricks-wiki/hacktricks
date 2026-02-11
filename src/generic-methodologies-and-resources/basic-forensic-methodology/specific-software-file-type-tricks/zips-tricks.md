# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Zana za mstari wa amri** za kusimamia zip files ni muhimu kwa utambuzi, ukarabati, na cracking zip files. Hapa kuna zana muhimu:

- **`unzip`**: Inaonyesha kwanini zip file inaweza isiweze ku-extract.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa sehemu za muundo wa zip file.
- **`zipinfo`**: Inaorodhesha yaliyomo ndani ya zip file bila kuziextract.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kutengeneza zip files zilizo corrupted.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana kwa brute-force cracking ya zip passwords, yenye ufanisi kwa passwords za karibu hadi herufi 7.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) inatoa maelezo kamili juu ya muundo na vigezo vya zip files.

Ni muhimu kutambua kwamba password-protected zip files hazifanyi encryption ya majina ya faili au ukubwa wa faili ndani yake, kasoro ya usalama ambayo haipo kwenye RAR au 7z ambazo huficha taarifa hizi. Zaidi ya hayo, zip files zilizofungwa kwa njia ya zamani ZipCrypto zinakuwa nyumbani kwa plaintext attack ikiwa nakala isiyoencrypted ya faili iliyokompressi inapatikana. Shambulio hili linatumia yaliyomo yanayojulikana kuvunja password ya zip, udhaifu uliotajwa katika [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Hata hivyo, zip files zilizo salama kwa AES-256 encryption hazina hatari ya plaintext attack, ikionyesha umuhimu wa kuchagua njia salama za encryption kwa data nyeti.

---

## Mbinu za anti-reversing katika APKs kwa kutumia ZIP headers zilizodanganywa

Dropper za kisasa za Android hutumia metadata ya ZIP iliyotengenezwa vibaya kuvunja zana za static (jadx/apktool/unzip) huku zikiendelea kufanya APK iwe installable kwenye kifaa. Mbinu zinazotumika mara kwa mara ni:

- Fake encryption kwa kuweka ZIP General Purpose Bit Flag (GPBF) bit 0
- Kutumia vibaya Extra fields kubwa/binafsi ili kuchanganya parsers
- Mgongano wa majina ya faili/dir ili kuficha artifacts halisi (mfano, saraka iliyoitwa `classes.dex/` karibu na `classes.dex` halisi)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Dalili:
- `jadx-gui` inashindwa na makosa kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` inauliza password kwa core APK files hata ingawa APK halali haiwezi kuwa na encrypted `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Uchunguzi kwa zipdetails:
```bash
zipdetails -v sample.apk | less
```
Angalia General Purpose Bit Flag kwa local na central headers. Thamani inayoashiria ni bit 0 imewekwa (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiki: Ikiwa APK inasakinishwa na kuendeshwa kwenye kifaa lakini rekodi za msingi zinaonekana "encrypted" kwa zana, GPBF iliharibiwa.

Rekebisha kwa kuondoa biti 0 ya GPBF katika Local File Headers (LFH) na Central Directory (CD) entries zote. Byte-patcher ndogo:

<details>
<summary>Patcher ndogo ya kufuta biti ya GPBF</summary>
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
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye core entries na zana zitasoma APK tena.

### 2) Vifungu vikubwa/vya custom vya Extra ili kuvunja parsers

Wavamizi huingiza Extra fields zilizo kubwa mno na IDs zisizo za kawaida kwenye headers ili kuvuruga decompilers. Katika mazingira halisi unaweza kuona alama za custom (e.g., strings like `JADXBLOCK`) zimetumwa hapo.

Ukaguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano iliyoonekana: IDs zisizojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") zikibeba payloads kubwa.

Kanuni za DFIR:
- Toa onyo wakati Extra fields ni kubwa isiyo ya kawaida kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kuwa zenye shaka.

Urekebishaji wa vitendo: kujenga upya archive (mf., re-zipping extracted files) huondoa Extra fields zenye madhara. Iwapo zana zitakataa kutoa kutokana na fake encryption, kwanza futa GPBF bit 0 kama ilivyoelezwa hapo juu, kisha pakiwa tena:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Mgongano la majina ya faili/folda (kuficha artefakti halisi)

ZIP inaweza kuwa na faili `X` na pia folda `X/`. Baadhi ya extractors na decompilers zinaweza kuchanganyikiwa na zinaweza kuifunika au kuficha faili halisi kwa viingizo vya directory. Hii imeonekana wakati viingizo vinapogongana na majina ya msingi ya APK kama `classes.dex`.

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
Post-fix ya ugundaji wa kiotomatiki:
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
Mawazo ya utambuzi ya Blue-team:
- Weka alama APKs ambazo local headers zinaonyesha encryption (GPBF bit 0 = 1) lakini zinaintall/kukimbia.
- Weka alama Extra fields kubwa/hazijulikani kwenye ingizo kuu (tazama alama kama `JADXBLOCK`).
- Weka alama migongano ya njia (`X` and `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine za ZIP zenye madhara (2024–2025)

### Central directories zilizounganishwa (kuepuka multi-EOCD)

Kampeni za hivi karibuni za phishing hutuma blob moja ambayo kwa kweli ni **ZIP mbili zilizounganishwa**. Kila moja ina End of Central Directory (EOCD) yake + central directory. Extractors tofauti hupitia directories tofauti (7zip husoma ya kwanza, WinRAR ya mwisho), na kuruhusu washambuliaji kuficha payloads ambazo zionekane tu kwa baadhi ya zana. Hii pia inaepusha AV ya msingi ya mail gateway inayochunguza directory ya kwanza tu.

**Amri za triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ikiwa EOCD inatokea zaidi ya moja au kuna onyo za "data after payload", gawanya blob na chunguza kila sehemu:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Toleo la kisasa la "better zip bomb" linaunda **kernel** ndogo (DEFLATE block iliyoshinikizwa sana) na kulitumia tena kupitia overlapping local headers. Kila entry ya central directory inarejea kwa data ile ile iliyoshinikwa, ikifikia uwiano wa >28M:1 bila kuweka archives ndani ya nyingine. Maktaba zinazomwamini ukubwa wa central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP kabla ya hardened builds) zinaweza kulazimishwa kugawa petabytes.

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
**Namna ya kushughulikia**
- Fanya dry-run ya ukaguzi: `zipdetails -v file.zip | grep -n "Rel Off"` na hakikisha offsets zinaongezeka kwa mpangilio mkali na ni za kipekee.
- Weka kikomo kwa jumla ya ukubwa usiokompress na idadi ya entry zinazokubaliwa kabla ya extraction (`zipdetails -t` or custom parser).
- Wakati lazima u-extract, fanya ndani ya cgroup/VM yenye vizingiti vya CPU na disk (epuka crashes za inflation zisizo na mipaka).

---

## Marejeleo

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
