# Triki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia w wierszu poleceń** do zarządzania **zip files** są niezbędne do diagnozowania, naprawiania i łamania plików zip. Oto kilka kluczowych narzędzi:

- **`unzip`**: Ujawnia, dlaczego plik zip może się nie rozpakować.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu zip.
- **`zipinfo`**: Wyświetla zawartość pliku zip bez jego rozpakowywania.
- **`zip -F input.zip --out output.zip`** oraz **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force łamania haseł zip, skuteczne dla haseł do około 7 znaków.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Ważne jest, aby pamiętać, że password-protected zip files **do not encrypt filenames or file sizes** wewnątrz — jest to luka w zabezpieczeniach, której nie mają RAR ani 7z, które szyfrują te informacje. Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na **plaintext attack**, jeśli dostępna jest nieszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znaną zawartość do złamania hasła zip, podatność opisana w [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalej wyjaśniona w [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Jednak pliki zip zabezpieczone za pomocą **AES-256** są odporne na ten plaintext attack, co pokazuje, jak ważne jest wybieranie bezpiecznych metod szyfrowania dla danych wrażliwych.

---

## Sztuczki Anti-reversing w APKs wykorzystujące zmanipulowane nagłówki ZIP

Nowoczesne droppery malware na Androida używają niepoprawnych metadanych ZIP, aby zepsuć narzędzia statyczne (jadx/apktool/unzip), jednocześnie pozostawiając APK możliwym do zainstalowania na urządzeniu. Najczęstsze sztuczki to:

- Fałszywe szyfrowanie poprzez ustawienie ZIP General Purpose Bit Flag (GPBF) bit 0
- Wykorzystywanie dużych/własnych Extra fields do zmylenia parserów
- Kolizje nazw plików/katalogów w celu ukrycia rzeczywistych artefaktów (np. katalog o nazwie `classes.dex/` obok prawdziwego `classes.dex`)

### 1) Fałszywe szyfrowanie (GPBF bit 0 ustawiony) bez prawdziwej kryptografii

Objawy:
- `jadx-gui` nie uruchamia się i zwraca błędy takie jak:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prosi o hasło dla kluczowych plików APK, mimo że ważny APK nie może mieć zaszyfrowanych `classes*.dex`, `resources.arsc`, or `AndroidManifest.xml`:

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
Spójrz na General Purpose Bit Flag dla nagłówków lokalnych i centralnych. Wskazującą wartością jest ustawiony bit 0 (Encryption) nawet dla core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i uruchamia na urządzeniu, ale podstawowe wpisy wyglądają na "zaszyfrowane" dla narzędzi, GPBF został zmodyfikowany.

Napraw to przez wyczyszczenie bitu 0 GPBF zarówno w Local File Headers (LFH), jak i we wpisach Central Directory (CD). Minimalny byte-patcher:

<details>
<summary>Minimalny patcher czyszczący bit GPBF</summary>
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
Powinieneś teraz widzieć `General Purpose Flag  0000` na kluczowych wpisach, a narzędzia ponownie sparsują APK.

### 2) Duże/własne Extra fields łamiące parsery

Atakujący wkładają przerośnięte Extra fields i nietypowe ID w nagłówki, aby zmylić dekompilery. W praktyce możesz zobaczyć niestandardowe markery (np. ciągi znaków takie jak `JADXBLOCK`) osadzone w nich.

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Przykłady zaobserwowane: nieznane ID takie jak `0xCAFE` ("Java Executable") lub `0x414A` ("JA:") z dużymi payloads.

DFIR heuristics:
- Generuj alert, gdy pola Extra są nietypowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Uznawaj nieznane ID pól Extra w tych wpisach za podejrzane.

Praktyczne środki zaradcze: przebudowanie archiwum (np. ponowne zipowanie wyodrębnionych plików) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają wypakowania z powodu fałszywego szyfrowania, najpierw wyczyść GPBF bit 0 jak powyżej, a następnie spakuj ponownie:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolidacje nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre narzędzia rozpakowujące i dekompilery mylą się i mogą nałożyć lub ukryć rzeczywisty plik wpisem katalogu. Zaobserwowano to przy kolizjach wpisów z podstawowymi nazwami w APK, takimi jak `classes.dex`.

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
Poprawka po wykryciu programowym:
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
- Zgłaszaj APKs, których lokalne nagłówki oznaczają szyfrowanie (GPBF bit 0 = 1), a mimo to instalują się/uruchamiają.
- Zgłaszaj duże/nieznane Extra fields na core entries (szukaj markerów takich jak `JADXBLOCK`).
- Zgłaszaj kolizje ścieżek (`X` i `X/`) szczególnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe sztuczki ZIP (2024–2026)

### Scalane central directories (multi-EOCD evasion)

Najnowsze kampanie phishingowe dostarczają pojedynczy blob, który w rzeczywistości jest **dwoma plikami ZIP połączonymi**. Każdy z nich ma własny End of Central Directory (EOCD) oraz central directory. Różne narzędzia rozpakowujące parsują różne katalogi (7zip czyta pierwszy, WinRAR ostatni), co pozwala atakującym ukryć payloady widoczne tylko w niektórych narzędziach. To także omija podstawowe mail gateway AV, które sprawdza tylko pierwszy katalog.

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Jeśli pojawi się więcej niż jeden EOCD lub pojawią się ostrzeżenia "data after payload", podziel blob i sprawdź każdą część:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Nowoczesna "better zip bomb" tworzy mały **kernel** (mocno skompresowany blok DEFLATE) i ponownie wykorzystuje go poprzez nakładające się local headers. Każdy wpis central directory wskazuje na te same skompresowane dane, osiągając współczynniki >28M:1 bez nesting archives. Biblioteki, które ufają rozmiarom central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) mogą zostać zmuszone do zaalokowania petabajtów.

**Szybkie wykrywanie (duplikaty offsetów LFH)**
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
- Wykonaj symulowany przebieg (dry-run): `zipdetails -v file.zip | grep -n "Rel Off"` i upewnij się, że offsety są ściśle rosnące i unikatowe.
- Ogranicz akceptowaną całkowitą niekompresowaną wielkość i liczbę wpisów przed rozpakowaniem (`zipdetails -t` lub własny parser).
- Jeśli musisz rozpakować, rób to wewnątrz cgroup/VM z limitami CPU i dysku (unikaj nieograniczonych rozrostów prowadzących do awarii).

---

### Konfuzja parserów Local-header vs central-directory

Niedawne badania differential-parser pokazały, że niejednoznaczność ZIP wciąż jest wykorzystywalna w nowoczesnych toolchainach. Główna idea jest prosta: niektóre programy ufają **Local File Header (LFH)**, podczas gdy inne ufają **Central Directory (CD)**, więc jedno archiwum może przedstawiać różne nazwy plików, ścieżki, komentarze, offsety lub zestawy wpisów różnym narzędziom.

Praktyczne zastosowania (ofensywne):
- Spraw, żeby filtr uploadu, pre-skan AV lub walidator pakietów widział w CD łagodny plik, podczas gdy extractor respektuje inną nazwę/ścieżkę z LFH.
- Wykorzystaj duplikujące się nazwy, wpisy obecne tylko w jednej strukturze lub niejednoznaczną metadanych ścieżek Unicode (na przykład Info-ZIP Unicode Path Extra Field `0x7075`), tak aby różne parsery odtwarzały różne drzewa.
- Połącz to z path traversal, by zamienić "harmless" widok archiwum w write-primitive podczas rozpakowywania. Po stronie rozpakowywania zobacz [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage dla DFIR:
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
Proszę wklej zawartość pliku src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md lub opisz dokładnie, co mam do niego dopisać/uzupełnić — wtedy przetłumaczę i uzupełnię zgodnie z instrukcjami.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurystyki:
- Odrzucaj lub izoluj archiwa z niespójnymi nazwami LFH/CD, zduplikowanymi nazwami plików, wieloma rekordami EOCD lub dodatkowymi bajtami po finalnym EOCD.
- Traktuj ZIPs używające nietypowych Unicode-path extra fields lub niespójnych komentarzy jako podejrzane, jeśli różne narzędzia różnie interpretują strukturę rozpakowanych plików.
- Jeśli analiza jest ważniejsza niż zachowanie oryginalnych bajtów, przepakuj archiwum przy użyciu ścisłego parsera po rozpakowaniu w sandbox i porównaj otrzymaną listę plików z oryginalnymi metadata.

To ma znaczenie wykraczające poza ekosystemy pakietów: ta sama klasa niejednoznaczności może ukrywać payloads przed mail gateways, static scanners i custom ingestion pipelines, które "peek" at ZIP contents przed tym, jak inny extractor obsłuży archiwum.

---



## Referencje

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
