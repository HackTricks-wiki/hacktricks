# ZIPs truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** vir die bestuur van **zip files** is noodsaaklik vir die diagnose, herstel, en cracking van zip files. Hier is 'n paar sleutelhulpmiddels:

- **`unzip`**: Toon waarom 'n zip file dalk nie gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied gedetailleerde ontleding van zip file-formaat velde.
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files te herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n hulpmiddel vir brute-force cracking van zip-wagwoorde, effektief vir wagwoorde tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bied omvattende besonderhede oor die struktuur en standaarde van zip files.

Dit is belangrik om daarop te let dat wagwoord-beskermde zip files **nie filenamen of lêergroottes binne-in enkodeer nie**, 'n sekuriteitsgebrek wat nie by RAR of 7z files voorkom nie, aangesien dié die inligting enkodeer. Verder is zip files wat met die ouer ZipCrypto-metode versleuteld is kwesbaar vir 'n **plaintext attack** as 'n onversleutelde kopie van 'n gecomprimeerde lêer beskikbaar is. Hierdie aanval benut die bekende inhoud om die zip se wagwoord te crack, 'n kwesbaarheid wat in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) uiteengesit word en verder verduidelik in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Zip files wat egter met **AES-256** beskerm word, is immuun teen hierdie plaintext attack, wat die belangrikheid van veilige enkripsiemetodes vir sensitiewe data aantoon.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Moderne Android malware droppers gebruik foutief gevormde ZIP-metadata om statiese gereedskap (jadx/apktool/unzip) te breek terwyl die APK steeds op die toestel geïnstalleer kan word. Die mees algemene truuks is:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptome:
- `jadx-gui` faal met foute soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern APK-lêers, alhoewel 'n geldige APK nie versleutelde `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` kan hê nie:

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
Kyk na die General Purpose Bit Flag vir plaaslike en sentrale headers. ’n kenmerkende waarde is dat bit 0 gestel is (Encryption) selfs vir kerninskrywings:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As 'n APK op die toestel installeer en loop, maar kerninskrywings vir tools as "geënkripteer" verskyn, is die GPBF gemanipuleer.

Los dit op deur GPBF bit 0 in beide Local File Headers (LFH) en Central Directory (CD) inskrywings op 0 te stel. Minimale byte-patcher:
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
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien en gereedskap sal die APK weer ontleed.

### 2) Groot/aangepaste Extra-velde om parsers te breek

Aanvallers prop oorgrootte Extra-velde en vreemde ID's in opskrifte om dekompilers te laat struikel. In die praktyk mag jy pasgemaakte merkers (bv. strings soos `JADXBLOCK`) daarin ingebed sien.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Waargenome voorbeelde: onbekende ID's soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads dra.

DFIR heuristics:
- Waarsku wanneer Extra fields ongewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Beskou onbekende Extra IDs op daardie inskrywings as verdag.

Praktiese mitigasie: die herrangskikking van die argief (bv. re-zipping van uitgepakte lêers) verwyder kwaadwillige Extra fields. As tools weier om te onttrek weens vals enkripsie, vee eers GPBF bit 0 uit soos hierbo, en herpak dan:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer/Map-naambotsings (versteek werklike artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige extractors en decompilers raak verward en kan die werklike lêer oorlê of verberg met 'n gidsinskrywing. Dit is waargeneem met inskrywings wat bots met kern-APK-name soos `classes.dex`.

Triage en veilige uitpak:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programmatiese opsporing agtervoegsel:
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
Blue-team deteksie-ideeë:
- Merk APKs waarvan die lokale headers enkripsie aandui (GPBF bit 0 = 1) maar steeds installeer/voer uit.
- Merk groot/onbekende Extra fields op core entries (kyk vir merkers soos `JADXBLOCK`).
- Merk padbotsings (`X` and `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Verwysings

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
