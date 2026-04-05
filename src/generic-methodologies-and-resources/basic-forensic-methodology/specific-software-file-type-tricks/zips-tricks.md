# ZIPs trikovi

{{#include ../../../banners/hacktricks-training.md}}

**Alati komandne linije** za upravljanje **zip files** su ključni za dijagnostikovanje, popravku i razbijanje zip fajlova. Evo nekoliko važnih utiliteta:

- **`unzip`**: Otkriva zašto se zip fajl možda ne može dekompresovati.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata zip fajla.
- **`zipinfo`**: Prikazuje sadržaj zip fajla bez izvlačenja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave korumpirane zip fajlove.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force cracking zip lozinki, efikasan za lozinke do otprilike 7 karaktera.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip fajlova.

Važno je napomenuti da password-protected zip files **ne enkriptuju imena fajlova ili veličine fajlova** u sebi, bezbednosni propust koji nije prisutan kod RAR ili 7z fajlova koji enkriptuju ove informacije. Nadalje, zip fajlovi enkriptovani starijom ZipCrypto metodom su podložni **known-plaintext attack** ako postoji nešifrovana kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj da bi se razbio password zip fajla, ranjivost opisana u [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i detaljnije objašnjena u [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Međutim, zip fajlovi zaštićeni sa **AES-256** enkripcijom su imuni na ovaj plaintext napad, što ističe važnost izbora sigurnih metoda enkripcije za osetljive podatke.

---

## Anti-reversing trikovi u APK-ovima korišćenjem manipulisanih ZIP hedera

Moderni Android malware droppers koriste malformirane ZIP metadata da bi pokvarili statičke alate (jadx/apktool/unzip) dok pritom ostavljaju APK instalabilnim na uređaju. Najčešći trikovi su:

- Fake encryption postavljanjem ZIP General Purpose Bit Flag (GPBF) bit 0
- Zloupotreba velikih/posebnih Extra polja da se zbune parseri
- Kolizije imena fajlova/direktorijuma da se sakriju pravi artefakti (npr. direktorijum nazvan `classes.dex/` pored pravog `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) bez prave kriptografije

Simptomi:
- `jadx-gui` pada sa greškama poput:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` traži lozinku za ključne APK fajlove iako validan APK ne može imati enkriptovane `classes*.dex`, `resources.arsc`, ili `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detekcija sa zipdetails:
```bash
zipdetails -v sample.apk | less
```
Pogledajte General Purpose Bit Flag za local i central headers. Otkrivajuća vrednost je bit 0 set (Encryption) čak i za core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće on-device, ali core entries izgledaju "encrypted" alatima, GPBF je izmenjen.

Popravite tako što ćete očistiti GPBF bit 0 u oba Local File Headers (LFH) i Central Directory (CD) entries. Minimalni byte-patcher:

<details>
<summary>Minimalni GPBF patcher za brisanje bita</summary>
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

### 2) Velika/prilagođena Extra polja koja lome parsere

Napadači ubacuju prevelika Extra polja i neobične ID-ove u zaglavlja kako bi zbunili dekompajlere. U praksi možete videti prilagođene markere (npr. stringove kao `JADXBLOCK`) ugrađene tamo.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primećeni primeri: nepoznati ID-ovi kao `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji nose velike payload-e.

DFIR heuristics:
- Upozori kada su Extra polja neuobičajeno velika na ključnim stavkama (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Smatraj nepoznate Extra ID-ove na tim stavkama sumnjivim.

Praktično rešenje: ponovno pakovanje arhive (npr. re-zipping izvađenih fajlova) uklanja zlonamerna Extra polja. Ako alati odbijaju da izvuku zbog lažne enkripcije, prvo očisti GPBF bit 0 kao gore, zatim ponovo spakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizije imena datoteka/direktorijuma (skrivanje stvarnih artefakata)

ZIP arhiva može sadržati i datoteku `X` i direktorijum `X/`. Neki extractors i decompilers se zbune i mogu prekriti ili sakriti stvarnu datoteku unosom direktorijuma. Ovo je primećeno kod unosa koji kolidiraju sa osnovnim imenima APK-ova kao što su `classes.dex`.

Triage i sigurno izdvajanje:
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
- Obeleži APKs čiji lokalni header-i označavaju enkripciju (GPBF bit 0 = 1) ali se ipak instaliraju/izvršavaju.
- Obeleži velike/nepoznate Extra fields na core entries (potraži markere kao `JADXBLOCK`).
- Obeleži path-collisions (`X` and `X/`) posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ostali zlonamerni ZIP trikovi (2024–2026)

### Konkatenirani centralni direktorijumi (izbegavanje multi-EOCD)

Nedavne phishing kampanje distribuiraju jedan blob koji je zapravo **dve ZIP datoteke spojene**. Svaka ima svoj End of Central Directory (EOCD) + central directory. Različiti extractori parsiraju različite direktorijume (7zip čita prvi, WinRAR poslednji), što napadačima omogućava da sakriju payloads koje samo neki alati prikazuju. Ovo takođe zaobilazi osnovni mail gateway AV koji inspektuje samo prvi direktorijum.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ako se pojavi više od jednog EOCD ili postoji upozorenje "data after payload", podelite blob i ispitajte svaki deo:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderni "better zip bomb" pravi mali **kernel** (jako komprimovan DEFLATE blok) i ponovo ga koristi putem preklapajućih lokalnih zaglavlja. Svaki unos u central directory pokazuje na iste kompresovane podatke, postižući odnos >28M:1 bez ugnježđavanja arhiva. Biblioteke koje veruju veličinama iz central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP pre hardened builds) mogu biti primorane da alociraju petabajte.

**Brza detekcija (duplikatni LFH offseti)**
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
- Izvedite dry-run pregled: `zipdetails -v file.zip | grep -n "Rel Off"` i proverite da su offseti strogo rastući i jedinstveni.
- Ograničite prihvaćenu ukupnu nekompresovanu veličinu i broj unosa pre ekstrakcije (`zipdetails -t` ili custom parser).
- Kada morate da ekstraktujete, radite to unutar cgroup/VM sa ograničenjima CPU i diska (izbegavajte padove usled nenadziranog rasta resursa).

---

### Local-header vs central-directory parser confusion

Nedavna istraživanja differential-parsera su pokazala da ZIP ambiguitet i dalje može biti iskorišćen u modernim toolchain-ovima. Osnovna ideja je jednostavna: neki softver veruje **Local File Header (LFH)** dok drugi veruju **Central Directory (CD)**, pa jedan arhiv može različitim alatima prikazati različita imena fajlova, putanje, komentare, offsete ili skupove unosa.

Praktične ofanzivne upotrebe:
- Naterajte upload filter, AV pre-scan ili package validator da vidi benignu datoteku u CD dok extractor poštuje drugačiji LFH name/path.
- Iskoristite duplikat imena, unose koji postoje samo u jednoj strukturi, ili dvosmislenu Unicode path metadata (na primer, Info-ZIP Unicode Path Extra Field `0x7075`) tako da različiti parseri rekonstrušu različita stabla.
- Kombinujte ovo sa path traversal da biste "harmless" prikaz arhive pretvorili u write-primitive tokom ekstrakcije. Za stranu ekstrakcije, vidi [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Nisi priložio sadržaj koji treba da dopunim. Pošalji tačan tekst koji želiš da ubacim i gde da ga umetnem (npr. na kraj fajla ili ispod određene sekcije).
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristika:
- Odbaciti ili izolovati arhive sa neusklađenim LFH/CD imenima, dupliranim imenima fajlova, više EOCD zapisa, ili pratećim bajtovima posle poslednjeg EOCD.
- Smatrati ZIP-ove koji koriste neobična Unicode-path extra fields ili nedosledne komentare sumnjivim ako se različiti alati ne slažu oko strukture izvađenih fajlova.
- Ako je analiza važnija od očuvanja originalnih bajtova, repack-ujte arhivu pomoću strict parser-a nakon ekstrakcije u sandbox-u i uporedite dobijenu listu fajlova sa originalnim metapodacima.

Ovo važi i izvan package ekosistema: ista klasa dvosmislenosti može sakriti payloads od mail gateways, static scanners, i custom ingestion pipelines koji "peek" at ZIP contents pre nego što drugi extractor obradi arhivu.

---



## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
