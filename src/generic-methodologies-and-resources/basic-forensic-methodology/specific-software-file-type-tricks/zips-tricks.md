# Triki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **pliki zip** są niezbędne do diagnozowania, naprawy i łamania zipów. Oto kluczowe narzędzia:

- **`unzip`**: Pokazuje, dlaczego plik zip może się nie rozpakować.
- **`zipdetails -v`**: Daje szczegółową analizę pól formatu pliku zip.
- **`zipinfo`**: Wypisuje zawartość pliku zip bez wyodrębniania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force łamania haseł zip, skuteczne dla haseł do około 7 znaków.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Warto zauważyć, że pliki zip chronione hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz — jest to luka bezpieczeństwa, której nie mają RAR ani 7z (które szyfrują te informacje). Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na atak **known plaintext** jeśli dostępna jest niezaszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znaną zawartość do złamania hasła zip, opisany w [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i szerzej objaśniony w [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Jednak pliki zip zabezpieczone za pomocą **AES-256** są odporne na ten atak known plaintext, co podkreśla znaczenie wyboru bezpiecznych metod szyfrowania dla danych wrażliwych.

---

## Triki anty-rewersingowe w APK wykorzystujące zmanipulowane nagłówki ZIP

Nowoczesne droppery malware na Androida używają sfałszowanych metadanych ZIP, aby zepsuć narzędzia statyczne (jadx/apktool/unzip), jednocześnie pozostawiając APK zainstalowalnym na urządzeniu. Najczęstsze sztuczki to:

- Fałszywe szyfrowanie przez ustawienie bitu 0 w ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych/niestandardowych pól Extra, by zmylić parsery
- Kolizje nazw plików/katalogów, aby ukryć prawdziwe artefakty (np. katalog nazwany `classes.dex/` obok prawdziwego `classes.dex`)

### 1) Fałszywe szyfrowanie (ustawiony bit 0 GPBF) bez rzeczywistego szyfrowania

Objawy:
- `jadx-gui` kończy się błędami takimi jak:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` pyta o hasło dla kluczowych plików APK, mimo że prawidłowy APK nie może mieć zaszyfrowanych `classes*.dex`, `resources.arsc`, ani `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Wykrywanie za pomocą zipdetails:
```bash
zipdetails -v sample.apk | less
```
Spójrz na General Purpose Bit Flag dla lokalnych i centralnych nagłówków. Charakterystyczną wartością jest ustawiony bit 0 (Encryption) nawet dla core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: If an APK installs and runs on-device but core entries appear "encrypted" to tools, the GPBF was tampered with.

Fix by clearing GPBF bit 0 in both Local File Headers (LFH) and Central Directory (CD) entries. Minimal byte-patcher:

<details>
<summary>Minimalny patcher czyszczący bit 0 GPBF</summary>
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

Użycie:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Powinieneś teraz zobaczyć `General Purpose Flag  0000` przy podstawowych wpisach, a narzędzia ponownie sparsują APK.

### 2) Duże/niestandardowe pola Extra, które łamią parsery

Atakujący umieszczają nadmiernie duże pola Extra i nietypowe ID w nagłówkach, aby zmylić dekompilery. W praktyce możesz natrafić na niestandardowe znaczniki (np. ciągi takie jak `JADXBLOCK`) osadzone tam.

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane ID, takie jak `0xCAFE` ("Java Executable") lub `0x414A` ("JA:"), zawierające duże payloads.

DFIR heurystyki:
- Generuj alert, gdy pola Extra są niezwykle duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Uznawaj nieznane ID Extra w tych wpisach za podejrzane.

Praktyczne środki zaradcze: odbudowa archiwum (np. ponowne spakowanie wyodrębnionych plików) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają rozpakowania z powodu fałszywego szyfrowania, najpierw wyczyść bit 0 GPBF jak powyżej, a następnie ponownie spakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie prawdziwych artefaktów)

Plik ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre narzędzia do rozpakowywania i dekompilatory mogą się w tym pogubić i nadpisać lub ukryć prawdziwy plik wpisem katalogu. Zaobserwowano to przy wpisach kolidujących z podstawowymi nazwami APK, takimi jak `classes.dex`.

Ocena wstępna i bezpieczne wypakowywanie:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Sufiks do wykrywania programowego:
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
Pomysły detekcyjne dla blue-team:
- Oznacz APKs, których lokalne nagłówki wskazują szyfrowanie (GPBF bit 0 = 1), a mimo to instalują/uruchamiają się.
- Oznacz duże/nieznane Extra fields w podstawowych wpisach (szukaj markerów takich jak `JADXBLOCK`).
- Oznacz kolizje ścieżek (`X` i `X/`) szczególnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe sztuczki ZIP (2024–2025)

### Konkatenowane katalogi centralne (omijanie multi-EOCD)

Najnowsze kampanie phishingowe wysyłają pojedynczy blob, który w rzeczywistości to **dwa sklejone pliki ZIP**. Każdy ma własny End of Central Directory (EOCD) + central directory. Różne extractors parsują różne katalogi (7zip czyta pierwszy, WinRAR ostatni), co pozwala atakującym ukryć payloady widoczne tylko w niektórych narzędziach. To także omija podstawowe mail gateway AV, które inspekcjonują tylko pierwszy katalog.

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Jeśli pojawi się więcej niż jedno EOCD lub będą ostrzeżenia "data after payload", rozdziel blob i sprawdź każdą część:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Nowoczesna "better zip bomb" tworzy niewielkie **kernel** (mocno skompresowany blok DEFLATE) i ponownie je wykorzystuje poprzez nakładające się local headers. Każdy wpis w central directory wskazuje na te same skompresowane dane, osiągając współczynniki >28M:1 bez zagnieżdżania archiwów. Biblioteki, które ufają rozmiarom central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP przed hardened builds) mogą zostać zmuszone do alokacji petabajtów.

**Szybkie wykrywanie (duplicate LFH offsets)**
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
**Obsługa**
- Wykonaj testowy przebieg: `zipdetails -v file.zip | grep -n "Rel Off"` i upewnij się, że offsety są ściśle rosnące i unikalne.
- Ogranicz akceptowany łączny rozmiar po dekompresji oraz liczbę wpisów przed rozpakowaniem (`zipdetails -t` lub własny parser).
- Jeśli musisz rozpakowywać, rób to wewnątrz cgroup/VM z limitami CPU i dysku (unikaj nieograniczonego wzrostu zasobów prowadzącego do awarii).

---

## Źródła

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
