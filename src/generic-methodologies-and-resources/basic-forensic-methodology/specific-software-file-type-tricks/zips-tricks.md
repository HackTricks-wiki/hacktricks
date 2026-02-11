# ZIP trikovi

{{#include ../../../banners/hacktricks-training.md}}

**Alati komandne linije** za upravljanje **ZIP fajlovima** su esencijalni za dijagnostikovanje, popravku i probijanje zip fajlova. Evo nekoliko ključnih utilitija:

- **`unzip`**: otkriva zašto ZIP fajl možda ne može da se dekompresuje.
- **`zipdetails -v`**: pruža detaljnu analizu polja formata ZIP fajla.
- **`zipinfo`**: nabraja sadržaj ZIP fajla bez ekstrakcije.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: pokušavaju da poprave korumpirane ZIP fajlove.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: alat za brute-force probijanje ZIP lozinki, efikasan za lozinke do otprilike 7 karaktera.

Specifikacija formata ZIP fajla: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

Važno je napomenuti da ZIP fajlovi zaštićeni lozinkom **ne šifruju imena fajlova niti njihove veličine**, bezbednosni propust koji nije prisutan kod RAR ili 7z fajlova koji šifruju te informacije. Pored toga, ZIP fajlovi šifrovani starijom ZipCrypto metodom su ranjivi na plaintext attack ako je dostupna nešifrovana kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj da probije lozinku ZIP fajla; ranjivost je opisana u [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i detaljnije objašnjena u [ovoj akademskoj publikaciji](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Međutim, ZIP fajlovi zaštićeni **AES-256** šifrovanjem su imuni na ovaj plaintext attack, što pokazuje važnost odabira sigurnih metoda šifrovanja za osetljive podatke.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Moderne Android malware droppere koriste neispravne ZIP metadata da bi slomile statičke alate (jadx/apktool/unzip), dok APK ostaje instalabilan na uređaju. Najčešći trikovi su:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptomi:
- `jadx-gui` fails with errors like:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prompts for a password for core APK files even though a valid APK cannot have encrypted `classes*.dex`, `resources.arsc`, or `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Otkrivanje pomoću zipdetails:
```bash
zipdetails -v sample.apk | less
```
Pogledajte General Purpose Bit Flag za lokalna i centralna zaglavlja. Karakteristična vrednost je postavljen bit 0 (šifrovanje) čak i za osnovne unose:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali ključni unosi alatima izgledaju "šifrovano", GPBF je bio izmenjen.

Ispravka: resetovanjem GPBF bita 0 u oba Local File Headers (LFH) i Central Directory (CD) unosa. Minimalni byte-patcher:

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

Upotreba:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sada bi trebalo da vidite `General Purpose Flag  0000` na glavnim unosima i alati će ponovo parsirati APK.

### 2) Velika/prilagođena Extra polja koja kvare parsere

Napadači ubacuju prevelika Extra polja i neobične ID-e u zaglavlja kako bi zbunili dekompajlere. U stvarnom svetu možete videti prilagođene markere (npr. stringove poput `JADXBLOCK`) ugrađene tamo.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primećeni primeri: nepoznati ID-ovi poput `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji sadrže velike payloads.

DFIR heuristike:
- Upozori kada su Extra polja neobično velika na ključnim stavkama (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Smatraj nepoznate Extra ID-ove na tim stavkama sumnjivim.

Praktična mitigacija: ponovno izgradnja arhive (npr. re-zipping izvučenih fajlova) uklanja zlonamerna Extra polja. Ako alati odbiju da izvuku zbog lažne enkripcije, prvo očisti GPBF bit 0 kao gore, zatim ponovo zapakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Sukobi imena datoteka/direktorijuma (skrivanje stvarnih artefakata)

ZIP može da sadrži i fajl `X` i direktorijum `X/`. Neki programi za raspakivanje i dekompajleri se mogu zbuniti i preklopiti ili sakriti pravi fajl zapisom direktorijuma. Ovo je primećeno kod zapisa koji se sudaraju sa ključnim imenima u APK, poput `classes.dex`.

Trijaža i bezbedno raspakivanje:
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
Blue-team — ideje za detekciju:
- Označiti APK-ove čiji lokalni headeri označavaju enkripciju (GPBF bit 0 = 1) ali se ipak instaliraju/pokreću.
- Označiti velika/nepoznata Extra polja na core unosima (traži markere poput `JADXBLOCK`).
- Označiti kolizije putanja (`X` i `X/`) posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ostali maliciozni ZIP trikovi (2024–2025)

### Konkatenirani centralni direktorijumi (multi-EOCD obilaženje)

Nedavne phishing kampanje distribuiraju jedinstveni blob koji je zapravo **dva konkatenirana ZIP fajla**. Svaki ima svoj End of Central Directory (EOCD) i central directory. Različiti extractors parsiraju različite direktorijume (7zip čita prvi, WinRAR poslednji), što napadačima omogućava da sakriju payloads koje pokažu samo neki alati. Ovo takođe zaobilazi osnovni mail gateway AV koji pregledava samo prvi direktorijum.

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

Moderni "better zip bomb" gradi mali **kernel** (jako kompresovan DEFLATE blok) i ponovo ga koristi pomoću preklapajućih lokalnih zaglavlja. Svaki unos centralnog direktorijuma pokazuje na iste kompresovane podatke, ostvarujući odnos veći od 28M:1 bez ugnježđivanja arhiva. Biblioteke koje veruju veličinama centralnog direktorijuma (Python `zipfile`, Java `java.util.zip`, Info-ZIP pre hardened builds) mogu biti primorane da alociraju petabajte.

**Brzo otkrivanje (duplicate LFH offsets)**
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
- Izvršite probni pregled: `zipdetails -v file.zip | grep -n "Rel Off"` i uverite se da su offseti strogo rastući i jedinstveni.
- Ograničite prihvaćenu ukupnu nekompresovanu veličinu i broj unosa pre izdvajanja (`zipdetails -t` ili prilagođeni parser).
- Kada morate izdvojiti, radite to unutar cgroup/VM sa CPU+disk limitima (izbegavajte padove usled neograničenog rasta resursa).

---

## Izvori

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
