# ZIPs trikovi

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za upravljanje **zip files** su neophodni za dijagnostikovanje, popravku i cracking zip files. Ovde su neki ključni alati:

- **`unzip`**: Otkriva zašto se zip file možda ne dekompresuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja zip file formata.
- **`zipinfo`**: Navodi sadržaj zip file bez njihovog izdvajanja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave korumpirane zip files.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force cracking zip passwords, efikasan za passwords do oko 7 karaktera.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip files.

Važno je napomenuti da zip files zaštićeni lozinkom **ne šifruju nazive fajlova niti njihove veličine**, bezbednosni propust koji nije prisutan kod RAR ili 7z fajlova koji šifruju te informacije. Dalje, zip files šifrovani starijom ZipCrypto metodom su podložni **plaintext attack** ako postoji nezaštićena kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj da bi slomio lozinku zip-a, ranjivost detaljno opisana u [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalje objašnjena u [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Međutim, zip files zaštićeni sa **AES-256** enkripcijom su imuni na ovaj plaintext attack, što pokazuje važnost izbora sigurnih metoda enkripcije za osetljive podatke.

---

## Anti-reversing trikovi u APK-ovima korišćenjem manipulisanih ZIP headera

Moderni Android malware droperi koriste malformirane ZIP metadata da bi onemogućili statičke alate (jadx/apktool/unzip) dok APK ostaje instalabilan na uređaju. Najčešći trikovi su:

- Lažno šifrovanje postavljanjem ZIP General Purpose Bit Flag (GPBF) bit 0
- Zloupotreba velikih/po meri napravljenih Extra polja da bi se zbunili parseri
- Kolizije imena fajlova/direktorijuma radi skrivanja pravih artefakata (npr. direktorijum imenovan `classes.dex/` pored pravog `classes.dex`)

### 1) Lažno šifrovanje (GPBF bit 0 postavljen) bez stvarne kriptografije

Simptomi:
- `jadx-gui` greši sa porukama poput:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` traži lozinku za ključne APK fajlove iako validan APK ne može imati šifrovane `classes*.dex`, `resources.arsc`, ili `AndroidManifest.xml`:

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
Pogledajte General Purpose Bit Flag u lokalnim i centralnim zaglavljima. Jasan pokazatelj je postavljen bit 0 (Encryption) čak i za osnovne unose:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali osnovni unosi alatima deluju „šifrovano“, GPBF je bio izmenjen.

Rešenje: očistite bit 0 GPBF-a u oba Local File Headers (LFH) i Central Directory (CD) unosa. Minimal byte-patcher:

<details>
<summary>Minimalni GPBF patcher za čišćenje bita</summary>
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

Upotreba:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sada biste trebali videti `General Purpose Flag  0000` na osnovnim unosima i alati će ponovo parsirati APK.

### 2) Velika/po meri Extra polja koja lome parsere

Napadači ubacuju prevelika Extra polja i neobične ID-e u zaglavlja kako bi zbunili dekompajlere. U stvarnim slučajevima možete videti prilagođene markere (npr., stringove poput `JADXBLOCK`) ugrađene tamo.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zapaženi primeri: nepoznati ID-ovi poput `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji nose velike payloads.

DFIR heuristics:
- Upozori kada su Extra fields neuobičajeno veliki na ključnim unosima (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Smatraj nepoznate Extra ID-ove na tim unosima sumnjivim.

Praktična mitigacija: ponovno kreiranje arhive (npr. re-zipping izdvojenih fajlova) uklanja zlonamerna Extra fields. Ako alati odbijaju da izvuku zbog lažne enkripcije, prvo očisti GPBF bit 0 kao gore, zatim ponovo zapakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Sudari imena fajlova/direktorijuma (sakrivanje stvarnih artefakata)

ZIP arhiva može sadržati i fajl `X` i direktorijum `X/`. Neki alati za ekstrakciju i dekompajleri se zbune i mogu prekriti ili sakriti pravi fajl pomoću direktorijumske stavke. Ovo je primećeno kod stavki koje se sudaraju sa osnovnim APK imenima kao što je `classes.dex`.

Triage i bezbedna ekstrakcija:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programatska detekcija postfiksa:
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
Ideje za detekciju (Blue-team):
- Obeležite APKs čiji lokalni headeri označavaju enkripciju (GPBF bit 0 = 1), a ipak se instaliraju/pokreću.
- Obeležite velike/nepoznate Extra fields na core entries (tražite markere kao `JADXBLOCK`).
- Obeležite path-collisions (`X` and `X/`) posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ostali zlonamerni ZIP trikovi (2024–2025)

### Konkatenirani centralni direktorijumi (multi-EOCD evasion)

Nedavne phishing kampanje isporučuju jedan blob koji je zapravo **dva ZIP fajla konkatenirana**. Svaki ima svoj End of Central Directory (EOCD) + central directory. Različiti extractori parsiraju različite direktorijume (7zip čita prvi, WinRAR poslednji), što omogućava napadačima da sakriju payload-e koje pokazuju samo neki alati. Ovo takođe zaobilazi osnovni mail gateway AV koji inspektuje samo prvi direktorijum.

**Komande za trijažu**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ako se pojavi više od jednog EOCD ili postoje upozorenja "data after payload", podelite blob i pregledajte svaki deo:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderna "better zip bomb" gradi mali **kernel** (jako komprimovani DEFLATE block) i ponovo ga koristi putem overlapping local headers. Svaki central directory entry pokazuje na iste kompresovane podatke, postižući >28M:1 odnos bez ugnježđivanja arhiva. Biblioteke koje veruju central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) mogu biti primorane da alociraju petabajte.

**Brza detekcija (duplicate LFH offsets)**
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
**Rukovanje**
- Izvršite dry-run proveru: `zipdetails -v file.zip | grep -n "Rel Off"` i uverite se da su offseti strogo rastući i jedinstveni.
- Ograničite ukupnu prihvatljivu dekompresovanu veličinu i broj unosa pre ekstrakcije (`zipdetails -t` ili prilagođeni parser).
- Kada morate da ekstraktujete, radite to unutar cgroup/VM sa ograničenjima CPU-a i diska (izbegavajte padove usled neograničenog rasta).

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
