# Trikovi sa ZIP fajlovima

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za upravljanje **zip fajlovima** su neophodni za dijagnostikovanje, popravku i probijanje zip fajlova. Evo nekoliko ključnih alata:

- **`unzip`**: Otkriva zašto se zip fajl možda ne može dekompresovati.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata zip fajla.
- **`zipinfo`**: Prikazuje sadržaj zip fajla bez ekstrakcije.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene zip fajlove.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force probijanje lozinki zip fajlova, efikasan za lozinke dužine do otprilike 7 karaktera.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip fajlova.

Važno je napomenuti da zip fajlovi zaštićeni lozinkom **ne šifruju nazive fajlova ili veličine fajlova** unutar arhive, što je sigurnosna mana koju nemaju RAR ili 7z fajlovi koji šifruju te informacije. Pored toga, zip fajlovi šifrovani starijom metodom ZipCrypto su podložni **plaintext attack** ako postoji nekriptovana kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj da bi otkrio lozinku zip arhive, ranjivost opisana u [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalje objašnjena u [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Međutim, zip fajlovi zaštićeni sa **AES-256** enkripcijom su imuni na ovaj plaintext attack, što naglašava važnost izbora sigurnih metoda enkripcije za osetljive podatke.

---

## Trikovi za anti-reversing u APK-ovima korišćenjem manipulisanih ZIP zaglavlja

Moderni Android malware droperi koriste malformirane ZIP meta-podatke da bi slomili statičke alate (jadx/apktool/unzip) dok APK ostaje instalabilan na uređaju. Najčešći trikovi su:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Zloupotreba velikih/prilagođenih Extra polja da zbuni parsere
- Kolizije imena fajlova/direktorijuma za skrivanje pravih artefakata (npr. direktorijum nazvan `classes.dex/` pored pravog `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptomi:
- `jadx-gui` javlja greške kao:
```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` traži lozinku za osnovne APK fajlove iako validan APK ne može imati kriptovane `classes*.dex`, `resources.arsc`, ili `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detekcija pomoću zipdetails:
```bash
zipdetails -v sample.apk | less
```
Pogledajte General Purpose Bit Flag za lokalna i centralna zaglavlja. Upadljiva vrednost je postavljen bit 0 (Encryption) čak i za osnovne unose:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali core entries izgledaju "encrypted" alatima, GPBF je izmenjen.

Rešenje: Očistite bit 0 GPBF-a u oba Local File Headers (LFH) i Central Directory (CD) unosa. Minimal byte-patcher:
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
Upotreba:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sada biste trebali videti `General Purpose Flag  0000` na osnovnim unosima i alati će ponovo parsirati APK.

### 2) Velika/prilagođena Extra polja koja ruše parsere

Napadači ubacuju prevelika Extra polja i neobične ID-e u zaglavlja kako bi pokvarili dekompajlere. U stvarnom svetu možete videti prilagođene markere (npr. stringove poput `JADXBLOCK`) ubačene tamo.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primećeni primeri: nepoznati ID-ovi kao `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji nose velike payloads.

DFIR heuristike:
- Upozori kada su Extra fields neuobičajeno veliki na core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Smatraj nepoznate Extra ID-ove na tim entry-ima sumnjivim.

Praktična mitigacija: ponovna izgradnja arhive (npr. ponovnim zipovanjem izvađenih fajlova) uklanja maliciozne Extra fields. Ako alati odbijaju ekstrakciju zbog lažne enkripcije, prvo očisti GPBF bit 0 kao gore, zatim ponovo upakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Sukobi imena fajlova/direktorijuma (skrivanje pravih artefakata)

ZIP arhiva može da sadrži i fajl `X` i direktorijum `X/`. Neki ekstraktori i dekompajleri se zbune i mogu prekriti ili sakriti pravi fajl unosom direktorijuma. Ovo je primećeno kod unosa koji se sudaraju sa osnovnim APK imenima kao što je `classes.dex`.

Trijaža i bezbedna ekstrakcija:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programatska detekcija post-fix:
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
Blue-team ideje za detekciju:
- Označiti APK-ove čija lokalna zaglavlja označavaju enkripciju (GPBF bit 0 = 1) ali se ipak instaliraju/pokreću.
- Označiti velika/nepoznata Extra polja na core entries (tražiti markere poput `JADXBLOCK`).
- Označiti path-collisions (`X` i `X/`) posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
