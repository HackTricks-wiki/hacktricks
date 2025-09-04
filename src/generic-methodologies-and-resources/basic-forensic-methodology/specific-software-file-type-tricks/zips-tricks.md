# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za kusimamia **zip files** ni muhimu kwa kutambua matatizo, kurekebisha, na kuvunja zip files. Hapa kuna zana kuu:

- **`unzip`**: Inaonyesha kwa nini zip file inaweza isiweze kutolewa.
- **`zipdetails -v`**: Inatoa uchanganuzi wa kina wa mashamba ya format ya zip file.
- **`zipinfo`**: Hutoa orodha ya yaliyomo kwenye zip file bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kutengeneza tena zip files zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya brute-force kuvirusha password za zip, inayofanya kazi vizuri kwa password za takriban herufi 7 au chini.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) inatoa maelezo ya kina juu ya muundo na viwango vya zip files.

Ni muhimu kutambua kwamba zip files zilizo na password zinalindwa kwa njia ya password **hazifichi majina ya faili au ukubwa wa faili** ndani yao, kasoro ya usalama ambayo haishirikiani na RAR au 7z ambazo huweka siri taarifa hizi. Zaidi ya hayo, zip files zilizoingia na njia ya zamani ya ZipCrypto zinaweza kushambuliwa kwa kutumia plaintext attack ikiwa kuna nakala isiyofichwa ya faili iliyoshinikwa. Shambulio hili linatumia yaliyomo yanayojulikana kuvunja password ya zip, udhaifu ulioelezewa kwenye [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Hata hivyo, zip files zilizolindwa kwa **AES-256** ni salama dhidi ya plaintext attack hii, ikionyesha umuhimu wa kuchagua mbinu salama za encryption kwa data nyeti.

---

## Mbinu za anti-reversing katika APKs kwa kutumia vichwa vya ZIP vilivyobadilishwa

Malware droppers ya kisasa ya Android hutumia metadata ya ZIP iliyofanywa vibaya kuvunja zana za static (jadx/apktool/unzip) huku wakiruhusu APK kusakinishwa kifaa. Mbinu zinazotumika mara kwa mara ni:

- Fake encryption kwa kuweka ZIP General Purpose Bit Flag (GPBF) bit 0
- Kutumia Extra fields kubwa/maalum kuchanganya parsers
- Mgongano wa majina ya faili/dirctory kuficha artifacts halisi (mfano, directory yenye jina `classes.dex/` kando ya `classes.dex` halisi)

### 1) Fake encryption (GPBF bit 0 set) bila kripto halisi

Dalili:
- `jadx-gui` inashindwa na makosa kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` inauliza password kwa faili kuu za APK ingawa APK halali haiwezi kuwa na `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml` zilizofichwa kwa siri:

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
Tazama General Purpose Bit Flag kwa local na central headers. Thamani inayoonyesha ni bit 0 imewekwa (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiki: Ikiwa APK inasakinishwa na inakimbia kwenye kifaa lakini ingizo za msingi zinaonekana "encrypted" kwa zana, GPBF iliharibishwa.

Tengeneza kwa kufuta bit 0 ya GPBF katika Local File Headers (LFH) na Central Directory (CD) entries. Minimal byte-patcher:
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
Matumizi:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye core entries na zana zitasoma APK tena.

### 2) Large/custom Extra fields za kuvunja parsers

Wavamizi huingiza Extra fields zilizo kubwa sana na IDs zisizo za kawaida kwenye headers ili kuwapotosha decompilers. Katika mazingira halisi unaweza kuona custom markers (kwa mfano, strings kama `JADXBLOCK`) zimeingizwa hapo.

Uchunguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano yaliyobainika: vitambulisho visivyojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") vinabeba payload kubwa.

Miongozo ya DFIR:
- Toa tahadhari wakati Extra fields zinapokuwa zisizo za kawaida kwa ukubwa kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kama zenye shaka.

Uzuiaji wa vitendo: kujenga upya archive (mfano, re-zipping extracted files) huondoa Extra fields zenye uovu. Ikiwa zana zinakataa kutoa kwa sababu ya fake encryption, kwanza futa GPBF bit 0 kama ilivyoelezwa hapo juu, kisha repack:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Mgongano ya majina ya faili/saraka (kuficha artifacts halisi)

ZIP inaweza kuwa na faili `X` na saraka `X/`. Baadhi ya extractors na decompilers huchanganyikiwa na zinaweza ku-overlay au kuficha faili halisi kwa kuingia kwa saraka. Hii imeonekana ikitokea kwa maingizo yanapogongana na majina ya msingi ya APK kama `classes.dex`.

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
Kiambishi cha baada (post-fix) cha utambuzi wa kimaprogramu:
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
Mapendekezo ya utambuzi kwa timu ya Blue:
- Alama APK ambazo vichwa vya ndani vinaonyesha encryption (GPBF bit 0 = 1) lakini zinasakinishwa/zinakimbia.
- Alama mawanja ya ziada makubwa/ yasiyojulikana kwenye ingizo za msingi (tazama alama kama `JADXBLOCK`).
- Alama mgongano wa njia (`X` na `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Marejeo

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
