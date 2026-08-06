# ZIP trikovi

{{#include ../../../banners/hacktricks-training.md}}

**Alati komandne linije** za upravljanje **zip datotekama** neophodni su za dijagnostikovanje, popravku i crackovanje zip datoteka. Evo nekih ključnih uslužnih programa:<sup>[[1]](#references)</sup>

- **`unzip`**: Otkriva zašto zip datoteka možda ne može da se raspakuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata zip datoteke.
- **`zipinfo`**: Prikazuje sadržaj zip datoteke bez raspakivanja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene zip datoteke.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force crackovanje zip lozinki, efikasan za lozinke dužine do približno 7 karaktera.

[Specifikacija formata Zip datoteka](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip datoteka.<sup>[[4]](#references)</sup>

Važno je napomenuti da zip datoteke zaštićene lozinkom **ne šifruju nazive datoteka ni veličine datoteka** koje sadrže, što je bezbednosni propust koji ne postoji kod RAR ili 7z datoteka, koje šifruju ove informacije. Pored toga, zip datoteke šifrovane starijim metodom ZipCrypto ranjive su na **plaintext attack** ako je dostupna nešifrovana kopija kompresovane datoteke.<sup>[[1]](#references)</sup> Ovaj napad koristi poznati sadržaj za crackovanje lozinke zip datoteke; ranjivost je detaljno opisana u [HackThis članku](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dodatno objašnjena u [ovom akademskom radu](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Međutim, zip datoteke zaštićene **AES-256** enkripcijom imune su na ovaj plaintext attack, što pokazuje važnost izbora bezbednih metoda enkripcije za osetljive podatke.<sup>[[1]](#references)</sup>

---

## Anti-reversing trikovi u APK datotekama pomoću izmenjenih ZIP zaglavlja

Moderni Android malware dropperi koriste neispravne ZIP metapodatke kako bi onemogućili statičke alate (jadx/apktool/unzip), dok APK i dalje može da se instalira na uređaj. Najčešći trikovi su:<sup>[[2]](#references)</sup>

- Lažna enkripcija postavljanjem bita 0 ZIP General Purpose Bit Flag-a (GPBF)
- Zloupotreba velikih/prilagođenih Extra polja radi zbunjivanja parsera
- Kolizije naziva datoteka/direktorijuma radi skrivanja stvarnih artefakata (npr. direktorijum nazvan `classes.dex/` pored stvarnog `classes.dex`)

### 1) Lažna enkripcija (postavljen GPBF bit 0) bez stvarne kriptografije

Simptomi:
- `jadx-gui` otkazuje rad sa greškama kao što je:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` zahteva lozinku za osnovne APK datoteke iako validan APK ne može imati šifrovane `classes*.dex`, `resources.arsc` ili `AndroidManifest.xml`:

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
Pogledajte General Purpose Bit Flag za lokalna i centralna zaglavlja. Indikativna vrednost je postavljen bit 0 (Encryption), čak i za osnovne stavke:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali alati prikazuju da su ključni unosi „šifrovani“, GPBF je izmenjen.

Popravite tako što ćete obrisati GPBF bit 0 u Local File Headers (LFH) i Central Directory (CD) unosima. Minimalni patcher za brisanje bita:

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
You should now see `General Purpose Flag  0000` on core entries and tools will parse the APK again.

### 2) Large/custom Extra fields to break parsers

Napadači ubacuju prevelika Extra polja i neobične ID-jeve u headere kako bi izazvali greške u decompilerima. U praksi možete naići na custom markere (npr. stringove poput `JADXBLOCK`) ugrađene u njih.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primeri koji su uočeni: nepoznati ID-jevi poput `0xCAFE` ("Java Executable") ili `0x414A` ("JA:") koji sadrže velike payload-e.

DFIR heuristike:
- Upozoriti kada su Extra fields neuobičajeno veliki u ključnim unosima (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Nepoznate Extra ID-jeve u tim unosima tretirati kao sumnjive.

Praktična mitigacija: rebuilding archive-a (npr. ponovno zip-ovanje ekstrahovanih fajlova) uklanja zlonamerna Extra fields. Ako alati odbijaju ekstrakciju zbog lažne enkripcije, prvo obrišite GPBF bit 0 kao što je prethodno navedeno, a zatim ponovo zapakujte:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizije imena datoteka/direktorijuma (skrivanje stvarnih artefakata)

ZIP može sadržati i datoteku `X` i direktorijum `X/`. Neki extractors i decompilers se zbune i mogu preklopiti ili sakriti stvarnu datoteku unosom direktorijuma. Ovo je uočeno kod unosa koji se sudaraju sa ključnim APK imenima kao što je `classes.dex`.

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
Programatska detekcija nakon ispravke:
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
Ideje za Blue-team detekciju:
- Obeležite APK-ove čija lokalna zaglavlja označavaju encryption (GPBF bit 0 = 1), a koji se ipak instaliraju/pokreću.
- Obeležite velika/nepoznata Extra polja u osnovnim entries (tražite markere poput `JADXBLOCK`).
- Obeležite path-collisions (`X` i `X/`) posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Drugi zlonamerni ZIP trikovi (2024–2026)

### Konkatenirani centralni direktorijumi (multi-EOCD evasion)

Nedavne phishing campaigns isporučuju jedan blob koji je zapravo **dva ZIP fajla spojena**. Svaki ima sopstveni End of Central Directory (EOCD) + central directory. Različiti extractors parsiraju različite direktorijume (7zip čita prvi, WinRAR poslednji), što napadačima omogućava da sakriju payloads koje prikazuju samo neki alati. Ovo takođe zaobilazi osnovni mail gateway AV koji proverava samo prvi direktorijum.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ako se pojavi više od jednog EOCD-a ili postoje upozorenja „data after payload“, podelite blob i pregledajte svaki deo:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (nerekurzivne)

Modern "better zip bomb" builds mali **kernel** (visoko kompresovani DEFLATE blok) i ponovo ga koristi preko preklapajućih lokalnih zaglavlja. Svaki unos centralnog direktorijuma pokazuje na iste kompresovane podatke, čime se postižu odnosi kompresije veći od 28M:1 bez ugnježđivanja arhiva. Biblioteke koje veruju veličinama u centralnom direktorijumu (`Python zipfile`, `Java java.util.zip`, Info-ZIP pre hardened build-ova) mogu biti primorane da alociraju petabajte.<sup>[[7]](#references)[[8]](#references)</sup>

**Brza detekcija (duplirani LFH offsets)**
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
**Postupanje**
- Izvršite dry-run obilazak: `zipdetails -v file.zip | grep -n "Rel Off"` i proverite da su offsets strogo rastući i jedinstveni.
- Ograničite prihvaćenu ukupnu uncompressed veličinu i broj entries pre ekstrakcije (`zipdetails -t` ili custom parser).
- Kada morate izvršiti ekstrakciju, uradite to unutar cgroup/VM okruženja sa ograničenjima za CPU+disk (izbegavajte crash-eve usled neograničene inflacije).

---

### Zabuna između local-header i central-directory parsera

Nedavno istraživanje differential-parsera pokazalo je da je ZIP dvosmislenost i dalje exploitable u modernim toolchain-ima. Osnovna ideja je jednostavna: neki software veruje **Local File Header (LFH)**, dok drugi veruje **Central Directory (CD)**, pa jedan archive može različitim alatima prikazati različite filenames, paths, comments, offsets ili skupove entries.<sup>[[9]](#references)</sup>

Praktične offensive upotrebe:
- Učinite da upload filter, AV pre-scan ili package validator u CD-u vidi benign file, dok extractor poštuje drugačije LFH ime/path.
- Iskoristite duplicate names, entries koji postoje samo u jednoj strukturi ili ambiguous Unicode path metadata (na primer, Info-ZIP Unicode Path Extra Field `0x7075`), kako bi različiti parseri rekonstruisali različita stabla.
- Kombinujte ovo sa path traversal tehnikom da biste bezopasan archive prikaz pretvorili u write-primitive tokom ekstrakcije. Za extraction stranu pogledajte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Pošaljite tekst koji treba dopuniti.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristike:
- Odbacite ili izolujte arhive sa neusaglašenim LFH/CD imenima, dupliranim nazivima datoteka, više EOCD zapisa ili bajtovima nakon poslednjeg EOCD zapisa.<sup>[[10]](#references)</sup>
- ZIP datoteke koje koriste neuobičajena dodatna polja za Unicode putanje ili neusaglašene komentare tretirajte kao sumnjive ako se različiti alati ne slažu oko izdvojenog stabla.<sup>[[9]](#references)</sup>
- Ako je analiza važnija od očuvanja originalnih bajtova, ponovo zapakujte arhivu pomoću strict parser-a nakon izdvajanja u sandbox-u i uporedite dobijenu listu datoteka sa originalnim metapodacima.

Ovo je važno i izvan package ecosystem-a: ista klasa dvosmislenosti može sakriti payload-e od mail gateway-a, static scanner-a i prilagođenih ingestion pipeline-a koji „zavire“ u sadržaj ZIP-a pre nego što drugi extractor obradi arhivu.

---



## Reference

- [1] [Vodič kroz CTF Forensics (Mike's Blog, CTF kategorija)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Deo 1 – Višestepeni dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip skripta)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Specifikacija ZIP formata datoteke (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Fleksibilna struktura ZIP arhiva iskorišćena za neotkriveno skrivanje malware-a (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hakeri skrivaju malware u novom ZIP napadu — konkatenirani ZIP centralni direktorijumi](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Bolji zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Razumevanje Zip Bomb napada: konstrukcija kernela sa preklapanjem/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifikovanje i iskorišćavanje semantičkih razlika između ZIP parser-a (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Sprečavanje ZIP parser confusion napada na Python package installer-e](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP napadi sa smanjenim poznatim plaintext-om (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Razbijanje ZIP datoteka](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
