# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia w wierszu poleceń** do zarządzania **zip files** są niezbędne do diagnozowania, naprawiania i łamania plików zip. Oto kilka kluczowych narzędzi:

- **`unzip`**: Pokazuje, dlaczego plik zip może się nie rozpakowywać.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu zip.
- **`zipinfo`**: Wyświetla zawartość pliku zip bez wyodrębniania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force łamania haseł zip, skuteczne dla haseł do około 7 znaków.

Specyfikacja formatu pliku [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera kompleksowe informacje o strukturze i standardach plików zip.

Warto zauważyć, że pliki zip zabezpieczone hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz archiwum — jest to luka bezpieczeństwa, której nie mają RAR ani 7z, które szyfrują te informacje. Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na **plaintext attack**, jeśli dostępna jest nieszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znaną zawartość do złamania hasła zip, co opisano w artykule [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) oraz w [tym artykule naukowym](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Pliki zip zabezpieczone **AES-256** są jednak odporne na ten plaintext attack, co pokazuje, jak ważne jest wybieranie bezpiecznych metod szyfrowania dla danych wrażliwych.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Nowoczesne droppery malware na Androida używają sfałszowanych metadanych ZIP, aby zepsuć narzędzia statyczne (jadx/apktool/unzip), jednocześnie zachowując możliwość instalacji APK na urządzeniu. Najczęstsze sztuczki to:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Objawy:
- `jadx-gui` zgłasza błędy takie jak:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prosi o hasło dla kluczowych plików APK, mimo że prawidłowy APK nie może mieć zaszyfrowanych `classes*.dex`, `resources.arsc`, ani `AndroidManifest.xml`:

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
Spójrz na General Purpose Bit Flag w nagłówkach lokalnych i centralnych. Charakterystyczną wartością jest ustawiony bit 0 (Encryption) nawet dla głównych wpisów:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i uruchamia na urządzeniu, ale core entries wyglądają na "encrypted" dla narzędzi, GPBF został zmanipulowany.

Napraw to przez wyczyszczenie bitu 0 GPBF w wpisach Local File Headers (LFH) oraz Central Directory (CD). Minimal byte-patcher:
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
Powinieneś teraz widzieć `General Purpose Flag  0000` przy głównych wpisach, a narzędzia ponownie sparsują APK.

### 2) Duże/niestandardowe pola Extra, które łamią parsery

Atakujący umieszczają przesadnie duże pola Extra i nietypowe ID w nagłówkach, żeby rozbić dekompilery. W praktyce możesz spotkać niestandardowe markery (np. ciągi takie jak `JADXBLOCK`) osadzone tam.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane ID takie jak `0xCAFE` ("Java Executable") lub `0x414A` ("JA:") zawierające duże payloads.

DFIR heurystyki:
- Wyzwalaj alert, gdy Extra fields są wyjątkowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane Extra IDs w tych wpisach jako podejrzane.

Praktyczne łagodzenie: odbudowa archiwum (np. ponowne zipowanie wyodrębnionych plików) usuwa złośliwe Extra fields. Jeśli narzędzia odmawiają rozpakowania z powodu fałszywego szyfrowania, najpierw wyczyść GPBF bit 0 jak powyżej, a następnie ponownie spakuj:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie prawdziwych artefaktów)

A ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre programy rozpakowujące i dekompilery mogą się w tym pogubić i przykryć lub ukryć prawdziwy plik wpisem katalogu. Zaobserwowano to przy wpisach kolidujących z podstawowymi nazwami w APK, takimi jak `classes.dex`.

Triage i bezpieczne rozpakowywanie:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Postfiks wykrywania programowego:
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
- Flag APKs, których lokalne nagłówki oznaczają szyfrowanie (GPBF bit 0 = 1), a mimo to instalują/uruchamiają się.
- Flag duże/nieznane Extra fields w core entries (szukaj znaczników takich jak `JADXBLOCK`).
- Flag kolizje ścieżek (`X` i `X/`) szczególnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Źródła

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
