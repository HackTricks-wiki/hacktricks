# ZIP-truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** vir die bestuur van **zip files** is noodsaaklik vir die diagnose, herstel en kraak van zip files. Hier is 'n paar sleutelhulpmiddels:

- **`unzip`**: Onthul waarom 'n zip file dalk nie kan dekomprimeer nie.
- **`zipdetails -v`**: Bied 'n gedetailleerde ontleding van zip file-formaatvelde.
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files te herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n hulpmiddel vir brute-force kraak van zip passwords, effektief vir passwords tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) verskaf omvattende besonderhede oor die struktuur en standaarde van zip files.

Dit is belangrik om te let dat password-protected zip files **nie filenamens of lêergroottes binne die argief enkripteer nie**, 'n sekuriteitsfout wat nie deur RAR of 7z lêers gedeel word nie, aangesien hulle hierdie inligting enkripteer. Verder is zip files wat met die ouer ZipCrypto-metode geënkripteer is kwesbaar vir 'n **plaintext attack** as 'n ongeënkripteerde kopie van 'n gecomprimeerde lêer beskikbaar is. Hierdie aanval gebruik die bekende inhoud om die zip se wagwoord te kraak, 'n kwesbaarheid wat in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) uiteengesit word en verder verduidelik word in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Zip files wat met **AES-256** enkripsie beveilig is egter immuun teen hierdie plaintext attack, wat die belangrikheid aandui om veilige enkripsiemetodes te kies vir sensitiewe data.

---

## Anti-reversing truuks in APKs deur gemanipuleerde ZIP-headers

Moderne Android malware droppers gebruik wanvormige ZIP-metadata om statiese gereedskap (jadx/apktool/unzip) te breek terwyl die APK steeds op die toestel installeerbaar bly. Die mees algemene truuks is:

- Fake encryption deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/aangepaste Extra fields om parsers te verwar
- Lêer/gids naambotsings om werklike artefakte te verberg (bv. 'n directory genaamd `classes.dex/` langs die werklike `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptome:
- `jadx-gui` misluk met foute soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern-APK-lêers selfs al kan 'n geldige APK nie geënkripteerde `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` hê nie:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Opsporing met zipdetails:
```bash
zipdetails -v sample.apk | less
```
Kyk na die General Purpose Bit Flag vir local en central headers. 'n Duidelike teken is dat bit 0 gestel is (Encryption) selfs vir core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As 'n APK op die toestel installeer en hardloop maar kerninskrywings vir gereedskap as "geënkripteer" verskyn, is die GPBF gemanipuleer.

Los dit op deur GPBF bit 0 in beide Local File Headers (LFH) en Central Directory (CD) inskrywings uit te skakel. Minimale byte-patcher:
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
Gebruik:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien en tools sal die APK weer parse.

### 2) Groot/aangepaste Extra-velde om parsers te breek

Aanvallers prop oorgrootte Extra-velde en vreemde IDs in headers om decompilers te laat struikel. In die veld mag jy aangepaste merkers (bv. strings soos `JADXBLOCK`) daar ingebed sien.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Waargenome voorbeelde: onbekende IDs soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads dra.

DFIR heuristieke:
- Waarsku wanneer Extra-velde ongewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Beskou onbekende Extra IDs op daardie inskrywings as verdag.

Praktiese mitigasie: die herbou van die argief (bv. deur die uitgepakte lêers weer te zip) verwyder kwaadwillige Extra-velde. As gereedskap weier om te onttrek weens valse enkripsie, maak eers GPBF bit 0 skoon soos hierbo, en herverpak dan:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer/Gids-naambotsings (verberg werklike artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige uittrekkers en dekompileerders raak verward en kan die werklike lêer met 'n gidsinskrywing oorlê of verberg. Dit is waargeneem by inskrywings wat bots met kern-APK-name soos `classes.dex`.

Triasie en veilige ekstraksie:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programmatiese opsporing post-fix:
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
Blue-team opsporingsidees:
- Merk APKs waarvan die plaaslike headers enkripsie aandui (GPBF bit 0 = 1) maar steeds installeer/uitvoer.
- Merk groot of onbekende Extra-velde op kerninskrywings (soek merkers soos `JADXBLOCK`).
- Merk padbotsings (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Verwysings

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
