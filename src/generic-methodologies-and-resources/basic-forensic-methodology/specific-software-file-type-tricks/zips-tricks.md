# Sztuczki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do obsługi **plików zip** są niezbędne do diagnozy, naprawy i łamania haseł w zipach. Oto najważniejsze narzędzia:

- **`unzip`**: Ujawnia, dlaczego plik zip może się nie rozpakowywać.
- **`zipdetails -v`**: Daje szczegółową analizę pól formatu pliku zip.
- **`zipinfo`**: Wypisuje zawartość pliku zip bez ich rozpakowywania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone archiwa zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force łamania haseł plików zip, skuteczne dla haseł do około 7 znaków.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Ważne jest zauważyć, że pliki zip chronione hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz, co stanowi wadę bezpieczeństwa, której nie mają archiwa RAR ani 7z, które szyfrują te informacje. Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na plaintext attack, jeśli dostępna jest niezaszyfrowana kopia skompresowanego pliku. Atak ten wykorzystuje znaną zawartość do złamania hasła zip — podatność opisana w [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalej wyjaśniona w [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Jednak pliki zip zabezpieczone szyfrowaniem **AES-256** są odporne na tę plaintext attack, co pokazuje znaczenie wyboru bezpiecznych metod szyfrowania dla danych wrażliwych.

---

## Sztuczki anty-rewersji w APKach wykorzystujące zmanipulowane nagłówki ZIP

Nowoczesne droppery malware na Androida używają niepoprawnych metadanych ZIP, aby zepsuć narzędzia statyczne (jadx/apktool/unzip), jednocześnie pozwalając na instalację APK na urządzeniu. Najczęstsze sztuczki to:

- Fałszywe szyfrowanie przez ustawienie bitu 0 w ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych/własnych pól Extra, aby zmylić parsery
- Kolizje nazw plików/katalogów w celu ukrycia rzeczywistych artefaktów (np. katalog o nazwie `classes.dex/` obok prawdziwego `classes.dex`)

### 1) Fałszywe szyfrowanie (GPBF bit 0 ustawiony) bez rzeczywistego szyfrowania

Objawy:
- `jadx-gui` zgłasza błędy takie jak:

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
Spójrz na General Purpose Bit Flag dla local i central headers. Wskazującą wartością jest ustawiony bit 0 (Encryption) nawet dla core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i działa na urządzeniu, ale kluczowe wpisy wyglądają dla narzędzi na "encrypted", GPBF został zmieniony.

Naprawa: wyczyść bit 0 GPBF zarówno w Local File Headers (LFH), jak i we wpisach Central Directory (CD). Minimalny byte-patcher:
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
Użycie:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Powinieneś teraz zobaczyć `General Purpose Flag  0000` na głównych wpisach, a narzędzia ponownie sparsują APK.

### 2) Duże/niestandardowe Extra fields, które łamią parsery

Atakujący upychają przewymiarowane Extra fields i dziwne ID w nagłówkach, aby zmylić dekompilery. W praktyce możesz zobaczyć tam niestandardowe znaczniki (np. ciągi takie jak `JADXBLOCK`) osadzone w tych polach.

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane ID, takie jak `0xCAFE` ("Java Executable") lub `0x414A` ("JA:"), niosące duże payloady.

DFIR heuristics:
- Wygeneruj alert, gdy Extra fields są wyjątkowo duże w przypadku kluczowych wpisów (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane Extra IDs w tych wpisach jako podejrzane.

Praktyczne środki zaradcze: odbudowanie archiwum (np. ponowne spakowanie wyodrębnionych plików) usuwa złośliwe Extra fields. Jeśli narzędzia odmawiają rozpakowania z powodu fałszywego szyfrowania, najpierw wyczyść GPBF bit 0 jak powyżej, a następnie zapakuj ponownie:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Zderzenia nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

Archiwum ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre ekstraktory i dekompilery mogą się z tym pogubić i nadpisać lub ukryć rzeczywisty plik wpisem katalogu. Zaobserwowano to przy kolizjach wpisów z podstawowymi nazwami APK, takimi jak `classes.dex`.

Selekcja i bezpieczne wypakowywanie:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Przyrostek do wykrywania programowego:
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
Blue-team — pomysły wykrywania:
- Oznacz APKs, których lokalne nagłówki oznaczają szyfrowanie (GPBF bit 0 = 1), lecz instalują/uruchamiają się.
- Oznacz duże/nieznane pola Extra na podstawowych wpisach (szukaj znaczników takich jak `JADXBLOCK`).
- Oznacz kolizje ścieżek (`X` i `X/`) szczególnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Źródła

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
