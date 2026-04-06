# ZIPs trikovi

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za upravljanje **zip fajlovima** su ključne za dijagnostikovanje, popravku i razbijanje zip fajlova. Evo nekoliko bitnih utiliteta:

- **`unzip`**: Otkriva zašto zip fajl možda neće da se dekompresuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata zip fajla.
- **`zipinfo`**: Navodi sadržaj zip fajla bez ekstrakcije.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene zip fajlove.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force probijanje zip lozinki, efikasan za lozinke do otprilike 7 karaktera.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip fajlova.

Važno je napomenuti da zip fajlovi zaštićeni lozinkom ne šifruju imena fajlova niti njihove veličine, što je sigurnosni propust koji RAR ili 7z fajlovi ne dele — oni šifruju te informacije. Pored toga, zip fajlovi šifrovani starijom ZipCrypto metodom su podložni **plaintext attack** ako je dostupna nešifrovana kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj za probijanje lozinke zip fajla, ranjivost detaljno opisana u [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dodatno objašnjena u [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Međutim, zip fajlovi zaštićeni AES-256 enkripcijom su imuni na ovaj **plaintext attack**, što pokazuje značaj izbora sigurnih metoda enkripcije za osetljive podatke.

---

## Trikovi protiv reverziranja u APK-ovima korišćenjem manipulisanih ZIP headera

Moderni Android malware droperi koriste malformirane ZIP metapodatke da razbiju statičke alate (jadx/apktool/unzip) dok APK ostaje instalabilan na uređaju. Najčešći trikovi su:

- Lažna enkripcija postavljanjem ZIP General Purpose Bit Flag (GPBF) bit 0
- Zloraba velikih/prilagođenih Extra polja da zbuni parsere
- Sudar imena fajlova/direktorijuma za sakrivanje stvarnih artefakata (npr. direktorijum nazvan `classes.dex/` pored stvarnog `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptomi:
- `jadx-gui` ne radi i prikazuje greške poput:

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

Detekcija pomoću zipdetails:
```bash
zipdetails -v sample.apk | less
```
Pogledajte General Purpose Bit Flag za lokalna i centralna zaglavlja. Upadljiva vrednost je bit 0 — postavljen (Encryption) čak i za osnovne unose:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali core entries izgledaju "encrypted" za tools, GPBF je manipulisan.

Rešenje: Očistite GPBF bit 0 u oba Local File Headers (LFH) i Central Directory (CD) unosa. Minimalni byte-patcher:

<details>
<summary>Minimalni GPBF bit-clear patcher</summary>
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

Korišćenje:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sada bi trebalo da vidite `General Purpose Flag  0000` na ključnim unosima i alati će ponovo parsirati APK.

### 2) Velika/prilagođena Extra polja koja kvare parsere

Napadači ubacuju prevelika Extra polja i neobične ID-ove u zaglavlja kako bi zbunili dekompajlere. U prirodi možete videti prilagođene markere (npr. stringove poput `JADXBLOCK`) ugrađene tamo.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primećeni primeri: nepoznati ID-ovi kao `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji nose velike payloads.

DFIR heuristike:
- Upozori kada su Extra fields neobično velika na ključnim unosima (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Smatraj nepoznate Extra ID-ove na tim unosima sumnjivim.

Praktična mitigacija: ponovna izgradnja arhive (npr. ponovnim zipovanjem izvađenih fajlova) uklanja zlonamerna Extra polja. Ako alati odbijaju da izvuku zbog lažnog šifrovanja, prvo očisti GPBF bit 0 kao gore, zatim ponovo spakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Sudari imena fajlova/direktorijuma (skrivanje stvarnih artefakata)

ZIP može sadržati i fajl `X` i direktorijum `X/`. Neki extractors i decompilers se zbune i mogu prekriti ili sakriti stvarni fajl unosom direktorijuma. Ovo je primećeno kod unosa koji kolidiraju sa ključnim imenima u APK-u kao što je `classes.dex`.

Trijaža i bezbedno izdvajanje:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programatsko otkrivanje postfiksa:
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
- Obeleži APKs čiji lokalni headeri označavaju enkripciju (GPBF bit 0 = 1) ali se ipak instaliraju/pokreću.
- Obeleži velika/nepoznata Extra polja na ključnim unosima (traži markere kao `JADXBLOCK`).
- Obeleži kolizije putanja (`X` i `X/`) posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Drugi zlonamerni ZIP trikovi (2024–2026)

### Konkatentirani centralni direktorijumi (izbegavanje multi-EOCD)

Nedavne phishing kampanje šalju jedan blob koji je zapravo **dva ZIP fajla spojena**. Svaki ima svoj End of Central Directory (EOCD) i central directory. Različiti extractori parsiraju različite direktorijume (7zip čita prvi, WinRAR poslednji), što omogućava napadačima da sakriju payload-e koje prikazuju samo neki alati. Ovo takođe zaobilazi osnovni mail gateway AV koji pregledava samo prvi direktorijum.

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

Modern "better zip bomb" pravi malo **kernel** (jako kompresovani DEFLATE blok) i ponovo ga koristi putem preklapajućih lokalnih zaglavlja. Svaki unos u centralnom direktorijumu pokazuje na iste kompresovane podatke, ostvarujući odnos >28M:1 bez ugnježđavanja arhiva. Biblioteke koje veruju veličinama u centralnom direktorijumu (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) mogu biti prisiljene da alociraju petabajte.

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
- Izvedite dry-run pregled: `zipdetails -v file.zip | grep -n "Rel Off"` i osigurajte da su offseti strogo rastući i jedinstveni.
- Ograničite prihvaćenu ukupnu dekompresovanu veličinu i broj zapisa pre ekstrakcije (`zipdetails -t` ili prilagođeni parser).
- Kada morate da ekstraktujete, radite to unutar cgroup/VM sa ograničenjima za CPU i disk (izbegavajte padove usled neograničenog rasta korišćenja resursa).

---

### Zbunjenost parsera: Local-header vs central-directory

Nedavno istraživanje diferencijalnih parsera pokazalo je da je ZIP dvosmislenost i dalje iskoristiva u modernim toolchain-ovima. Glavna ideja je jednostavna: neki softver veruje **Local File Header (LFH)** dok drugi veruju **Central Directory (CD)**, pa ista arhiva može različitim alatima prikazivati različita imena fajlova, putanje, komentare, offset-e ili skupove zapisa.

Praktične ofanzivne upotrebe:
- Naterajte upload filter, AV pre-scan ili package validator da u CD vidi benigni fajl dok extractor poštuje drugo ime/putanju iz LFH.
- Iskoristite duplirana imena, zapise prisutne samo u jednoj strukturi, ili dvosmislene Unicode path metapodatke (na primer, Info-ZIP Unicode Path Extra Field `0x7075`) tako da različiti parseri rekonstruiraju različita stabla.
- Kombinujte ovo sa path traversal kako biste "harmless" prikaz arhive pretvorili u write-primitive tokom ekstrakcije. Za stranu ekstrakcije, vidi [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR trijaža:
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
Nedostaje sadržaj koji treba dopuniti/prevesti. Pošaljite tekst iz datoteke ili precizirajte šta tačno da dopunim, pa ću to prevesti na srpski zadržavajući originalnu Markdown/HTML sintaksu i neprevodeći kod, linkove, taga i putanje.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristike:
- Odbacite ili izolujte arhive sa neusaglašenim LFH/CD imenima, duplikatima imena fajlova, više EOCD zapisa, ili zaostalim bajtovima nakon poslednjeg EOCD.
- Smatrajte ZIPs koji koriste neobične Unicode-path extra fields ili nedosledne komentare sumnjivim ako se različiti alati ne slažu oko izvučenog stabla.
- Ako je analiza važnija od očuvanja originalnih bajtova, repakujte arhivu koristeći striktan parser nakon ekstrakcije u sandbox i uporedite dobijenu listu fajlova sa originalnim metapodacima.

Ovo je važno i izvan ekosistema paketa: ista klasa dvosmislenosti može sakriti payloads od mail gateways, static scanners i custom ingestion pipelines koji "peek" u ZIP contents pre nego što drugi extractor obradi arhivu.

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
