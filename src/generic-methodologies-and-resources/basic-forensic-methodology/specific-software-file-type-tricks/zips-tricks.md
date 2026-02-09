# Triki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania plików zip. Oto kilka kluczowych narzędzi:

- **`unzip`**: Pokazuje, dlaczego plik zip może się nie rozpakować.
- **`zipdetails -v`**: Daje szczegółową analizę pól formatu pliku zip.
- **`zipinfo`**: Wyświetla zawartość pliku zip bez rozpakowywania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do łamania haseł zip metodą brute-force, skuteczne dla haseł do około 7 znaków.

Specyfikacja formatu [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera szczegółowe informacje o strukturze i standardach plików zip.

Trzeba zauważyć, że pliki zip chronione hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz archiwum — wada bezpieczeństwa, której nie mają RAR ani 7z (one szyfrują te informacje). Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na **plaintext attack**, jeśli dostępna jest niezaszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znaną zawartość do złamania hasła zipa — podatność opisana w [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i szerzej wyjaśniona w [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Jednak pliki zip zabezpieczone **AES-256** są odporne na ten plaintext attack, co pokazuje znaczenie wyboru bezpiecznych metod szyfrowania dla danych wrażliwych.

---

## Triki anty-rewersji w APKach wykorzystujące zmanipulowane nagłówki ZIP

Nowoczesne droppersy malware na Androida używają niepoprawnych metadanych ZIP, aby zepsuć działanie narzędzi statycznych (jadx/apktool/unzip), jednocześnie pozostawiając APK instalowalnym na urządzeniu. Najczęstsze triki to:

- Fałszywe szyfrowanie przez ustawienie bitu 0 w ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych/własnych pól Extra, aby zmylić parsery
- Kolizje nazw plików/katalogów, by ukryć prawdziwe artefakty (np. katalog o nazwie `classes.dex/` obok prawdziwego `classes.dex`)

### 1) Fałszywe szyfrowanie (ustawiony bit 0 GPBF) bez rzeczywistego szyfrowania

Objawy:
- `jadx-gui` kończy się błędami takimi jak:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prosi o hasło dla kluczowych plików APK, mimo że prawidłowe APK nie może mieć zaszyfrowanych `classes*.dex`, `resources.arsc`, ani `AndroidManifest.xml`:

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
Sprawdź General Purpose Bit Flag w nagłówkach lokalnych i centralnych. Wartością-wskazówką jest ustawiony bit 0 (Encryption) nawet dla core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i działa na urządzeniu, ale kluczowe wpisy wydają się "zaszyfrowane" dla narzędzi, to GPBF został zmanipulowany.

Napraw, wyczyszczając bit 0 GPBF zarówno w wpisach Local File Headers (LFH), jak i Central Directory (CD). Minimalny byte-patcher:

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

Użycie:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Powinieneś teraz zobaczyć `General Purpose Flag  0000` na kluczowych wpisach, a narzędzia ponownie sparsują APK.

### 2) Duże/własne pola Extra, które łamią parsery

Atakujący wstawiają nadmiernie duże pola Extra i nietypowe ID do nagłówków, aby zmylić dekompilatory. W warunkach rzeczywistych możesz zobaczyć niestandardowe markery (np. ciągi znaków takie jak `JADXBLOCK`) osadzone tam.

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane ID takie jak `0xCAFE` ("Java Executable") lub `0x414A` ("JA:") zawierające duże payloady.

DFIR heurystyki:
- Wysyłaj alert, gdy pola Extra są wyjątkowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane ID Extra w tych wpisach jako podejrzane.

Praktyczne środki zaradcze: ponowne zbudowanie archiwum (np. ponowne zipowanie wyodrębnionych plików) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają rozpakowania z powodu fałszywego szyfrowania, najpierw wyczyść GPBF bit 0 jak wyżej, a następnie ponownie zapakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

Plik ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre extractors i decompilers mogą się zdezorientować i mogą nadpisać lub ukryć rzeczywisty plik wpisem katalogu. Zaobserwowano to w przypadku wpisów kolidujących z kluczowymi nazwami APK, takimi jak `classes.dex`.

Triage and safe extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programowe wykrywanie — post-fix:
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
Blue-team detection ideas:
- Oznacz APKs, których lokalne nagłówki wskazują szyfrowanie (GPBF bit 0 = 1), a mimo to instalują/uruchamiają się.
- Oznacz duże/nieznane Extra fields w kluczowych wpisach (szukaj znaczników takich jak `JADXBLOCK`).
- Oznacz kolizje ścieżek (`X` i `X/`) szczególnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe triki ZIP (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

Recent phishing campaigns dostarczają pojedynczy blob, który w rzeczywistości jest **dwoma plikami ZIP sklejonymi**. Każdy ma własny End of Central Directory (EOCD) + central directory. Różne extractors parsują różne katalogi (7zip czyta pierwszy, WinRAR ostatni), co pozwala atakującym ukryć payloady, które pokażą tylko niektóre narzędzia. To także omija podstawowe mail gateway AV, które sprawdzają jedynie pierwszy katalog.

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Jeśli pojawi się więcej niż jeden EOCD lub wystąpią ostrzeżenia "data after payload", podziel blob i przeanalizuj każdą część:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Nowoczesna "better zip bomb" buduje mały **kernel** (silnie skompresowany blok DEFLATE) i ponownie wykorzystuje go poprzez overlapping local headers. Każdy central directory entry wskazuje na te same skompresowane dane, osiągając stosunki >28M:1 bez zagnieżdżania archiwów. Biblioteki, które ufają central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP przed hardened builds) można zmusić do zaalokowania petabajtów.

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
- Wykonaj dry-run (próbne przejście): `zipdetails -v file.zip | grep -n "Rel Off"` i upewnij się, że offsety są ściśle rosnące i unikatowe.
- Ogranicz akceptowany całkowity rozmiar po dekompresji oraz liczbę wpisów przed rozpakowaniem (`zipdetails -t` lub własny parser).
- Jeśli musisz rozpakować, rób to wewnątrz cgroup/VM z limitami CPU i dysku (unikaj niekontrolowanego rozrostu prowadzącego do awarii).

---

## Źródła

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
