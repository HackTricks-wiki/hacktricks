# ZIP tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za upravljanje **zip files** ključni su za dijagnostikovanje, popravku i crackovanje zip files. Evo nekoliko važnih utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Otkriva zašto zip file možda ne može da se dekompresuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja zip file formata.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Prikazuje sadržaj zip file-a bez njegovog raspakivanja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene zip files.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force crackovanje zip passwords, efikasan za passwords dužine do približno 7 karaktera.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip files.<sup>[[4]](#references)</sup>

Važno je napomenuti da tradicionalni password-protected ZIP files uglavnom ostavljaju filenames i file sizes vidljivim, za razliku od header-encryption režima koje podržavaju RAR i 7z. Pored toga, ZIP files encrypted starijom metodom ZipCrypto ranjivi su na **plaintext attack** ako je dostupna nešifrovana kopija compressed file-a.<sup>[[1]](#references)</sup> Ovaj napad koristi poznati sadržaj za crackovanje ZIP password-a, kao što je objašnjeno u [ovom akademskom radu](https://math.ucr.edu/~mike/zipattacks.pdf) i prikazano u [ovom Hack This Site vodiču](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Međutim, ZipCrypto known-plaintext attack ne primenjuje se na entries zaštićene **AES-256** encryption-om.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks u APKs korišćenjem izmenjenih ZIP headers

Moderni Android malware droppers koriste neispravne ZIP metadata podatke da bi onesposobili static tools (jadx/apktool/unzip), dok APK ostaje instalabilan na uređaju. Najčešće tricks su:<sup>[[2]](#references)</sup>

- Lažna encryption postavljanjem bita 0 ZIP General Purpose Bit Flag (GPBF)
- Zloupotreba velikih/custom Extra fields radi zbunjivanja parsera
- Kolizije imena file/directory objekata radi skrivanja stvarnih artifacts (npr. directory nazvan `classes.dex/` pored stvarnog `classes.dex`)

### 1) Lažna encryption (postavljen GPBF bit 0) bez stvarne crypto

Simptomi:
- `jadx-gui` ne uspeva uz greške poput:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` traži password za core APK files iako validan APK ne može imati encrypted `classes*.dex`, `resources.arsc` ili `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detekcija pomoću zipdetails-a:
```bash
zipdetails -v sample.apk | less
```
Pogledajte General Purpose Bit Flag za lokalna i centralna zaglavlja. Karakteristična vrednost je postavljen bit 0 (Encryption), čak i za osnovne stavke:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali alati prikazuju osnovne unose kao „encrypted“, GPBF je izmenjen.

Popravite to brisanjem GPBF bita 0 u Local File Header (LFH) i Central Directory (CD) unosima. Minimalni patcher bajtova:

<details>
<summary>Minimalni patcher za brisanje GPBF bita</summary>
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
Sada bi trebalo da vidite `General Purpose Flag  0000` u osnovnim unosima, a alati će ponovo parsirati APK.

### 2) Velika/prilagođena Extra polja za ometanje parsera

Napadači ubacuju prevelika Extra polja i neobične ID-jeve u zaglavlja kako bi izazvali probleme u decompiler-ima. U praksi možete naići na prilagođene oznake (npr. stringove poput `JADXBLOCK`) ugrađene u njih.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primeri koji su uočeni: nepoznati ID-jevi poput `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji sadrže velike payload-e.<sup>[[2]](#references)</sup>

DFIR heuristike:
- Upozoriti kada su Extra polja neuobičajeno velika u ključnim unosima (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Nepoznate Extra ID-jeve u tim unosima tretirati kao sumnjive.

Praktična mitigacija: ponovna izgradnja arhive (npr. ponovno zipovanje ekstrahovanih fajlova) uklanja zlonamerna Extra polja. Ako alati odbijaju ekstrakciju zbog lažne enkripcije, prvo obrišite GPBF bit 0 kao što je gore navedeno, a zatim ponovo upakujte:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizije imena datoteka/direktorijuma (skrivanje stvarnih artefakata)

ZIP može da sadrži i datoteku `X` i direktorijum `X/`. Neki extractors i decompilers se zbune i mogu da prekriju ili sakriju stvarnu datoteku unosom direktorijuma. Ovo je primećeno kod unosa koji se sudaraju sa osnovnim APK imenima kao što je `classes.dex`.

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
Programsko otkrivanje nakon ispravke:
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
- Označiti APK-ove čija lokalna zaglavlja označavaju enkripciju (GPBF bit 0 = 1), a koji se ipak instaliraju/pokreću.
- Označiti velike/nepoznate Extra fields u ključnim unosima (tražiti markere poput `JADXBLOCK`).
- Označiti kolizije putanja (`X` i `X/`), posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ostale zlonamerne ZIP trikove (2024–2026)

### Konkatenirani centralni direktorijumi (multi-EOCD evasion)

U jednoj phishing kampanji iz 2024. godine, napadači su isporučili jedan blob koji su zapravo činila **dva konkatenirana ZIP fajla**. Svaki je imao sopstveni End of Central Directory (EOCD) zapis i centralni direktorijum. Različiti extractors su parsirali različite direktorijume (7-Zip je čitao prvi, dok je WinRAR čitao poslednji), što je napadačima omogućilo da sakriju payload-e koje su prikazivali samo neki alati; skeneri koji proveravaju samo jedan direktorijum mogu propustiti drugu arhivu.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage komande**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Ako se pojavi više od jednog EOCD zapisa ili postoje upozorenja „data after payload“, podelite blob i pregledajte svaki deo:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs konstruišu mali **kernel** (visoko kompresovani DEFLATE blok) i ponovo ga koriste kroz preklapajuće unose. Full-overlap varijante usmeravaju više unosa central-directory ka jednom local header-u, dok quoted-overlap varijante navode local header-e unutar DEFLATE stream-ova; objavljena konstrukcija postiže odnos veći od 28M:1 bez nested archives.<sup>[[7]](#references)</sup>

**Brza detekcija (duplikatni LFH offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
- Izvršite dry-run prolaz: `zipdetails -v file.zip | grep -n "Local Header Offset"` i uporedite navedene local-header offsete i opsege kompresovanih podataka; duplikatni offseti ukazuju na varijante sa potpunim preklapanjem.<sup>[[7]](#references)[[8]](#references)</sup>
- Ograničite prihvatljivu ukupnu nekompresovanu veličinu i broj entries pre ekstrakcije pomoću parsera; `zipinfo -t file.zip` prikazuje ukupne vrednosti, ali ne nameće bezbednosno ograničenje.<sup>[[8]](#references)</sup>
- Kada morate da izvršite ekstrakciju, uradite to unutar cgroup/VM okruženja sa ograničenjima CPU-a i diska (izbegavajte crash-eve usled neograničene dekompresije).<sup>[[8]](#references)</sup>

---

### Zabuna parsera između local-header-a i central-directory-ja

Nedavna istraživanja differential-parser tehnika pokazala su da je ZIP dvosmislenost i dalje iskoristiva u modernim toolchain-ovima. Osnovna ideja je jednostavna: neki software veruje **Local File Header-u (LFH)**, dok drugi veruje **Central Directory-ju (CD)**, pa jedna arhiva može različitim alatima prikazati različite filenames, paths, comments, offsets ili sets entries.<sup>[[9]](#references)</sup>

Praktične ofanzivne upotrebe:
- Učinite da upload filter, AV pre-scan ili package validator u CD-u vidi benign fajl, dok extractor poštuje drugačije LFH ime/path.
- Iskoristite duplicate names, entries koje postoje samo u jednoj strukturi ili dvosmislene Unicode path metadata podatke (na primer, Info-ZIP Unicode Path Extra Field `0x7075`), tako da različiti parseri rekonstruišu različita stabla.
- Kombinujte ovo sa path traversal tehnikom da bezopasan prikaz arhive pretvorite u write-primitive tokom ekstrakcije. Za stranu koja obavlja ekstrakciju pogledajte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Dopunite ga sledećim:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristike:
- Za ingestion osetljiv na bezbednost, odbijte ili izolujte arhive sa neusaglašenim LFH/CD imenima, dupliranim imenima fajlova, više EOCD zapisa ili bajtovima nakon poslednjeg EOCD-a.<sup>[[9]](#references)[[10]](#references)</sup>
- ZIP-ove koji koriste neuobičajena dodatna polja Unicode putanja ili neusaglašene komentare tretirajte kao sumnjive ako se različiti alati ne slažu oko extracted stabla.<sup>[[4]](#references)[[9]](#references)</sup>
- Ako je analiza važnija od očuvanja originalnih bajtova, ponovo zapakujte arhivu pomoću strogog parsera nakon extraction-a u sandbox-u i uporedite rezultujuću listu fajlova sa originalnim metapodacima.

Ovo je važno i izvan package ekosistema: ista klasa dvosmislenosti može sakriti payloads od mail gateway-a, static scanner-a i custom ingestion pipeline-ova koji „zavire“ u ZIP sadržaj pre nego što drugi extractor obradi arhivu.<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF vodič za forenziku (Mike's Blog, CTF kategorija)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Deo 1 – Višestepeni dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress skripta)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specifikacija ZIP formata fajla (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Fleksibilna struktura ZIP arhiva iskorišćena za neotkriveno skrivanje malware-a (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hakeri zakopavaju malware u novom ZIP napadu — ulančani ZIP centralni direktorijumi](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Bolja zip bomba (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Razumevanje Zip bombi: konstrukcija preklapajućeg/„quoted-overlap“ kernela](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Moj ZIP nije tvoj ZIP: Identifikovanje i iskorišćavanje semantičkih razlika između ZIP parsera (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Sprečavanje napada konfuzijom ZIP parsera na Python package installere](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP napadi sa smanjenim poznatim otvorenim tekstom (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistična web misija, nivo 15 (ZIP napad sa poznatim otvorenim tekstom)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
