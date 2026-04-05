# Triki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania zipów. Oto kilka kluczowych narzędzi:

- **`unzip`**: Wyjaśnia, dlaczego plik zip może się nie rozpakować.
- **`zipdetails -v`**: Daje szczegółową analizę pól formatu zip.
- **`zipinfo`**: Wypisuje zawartość pliku zip bez rozpakowywania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do łamania haseł zip metodą brute-force, skuteczne dla haseł do około 7 znaków.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Warto zauważyć, że pliki zip chronione hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz archiwum — wada bezpieczeństwa, której nie mają RAR ani 7z, które szyfrują te informacje. Dodatkowo pliki zip szyfrowane starszą metodą ZipCrypto są podatne na atak **known-plaintext** jeśli dostępna jest nieszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znaną zawartość do złamania hasła zipa — podatność opisana w [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dodatkowo wyjaśniona w [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Jednak pliki zip zabezpieczone **AES-256** są odporne na ten atak plaintext, co podkreśla znaczenie wyboru bezpiecznych metod szyfrowania dla danych wrażliwych.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Nowoczesne droppery malware na Androida używają sfałszowanych metadanych ZIP, by zepsuć narzędzia statyczne (jadx/apktool/unzip), jednocześnie pozostawiając APK instalowalnym na urządzeniu. Najczęstsze sztuczki to:

- Fałszywe szyfrowanie przez ustawienie bitu 0 w ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych/niestandardowych pól Extra, by zdezorientować parsery
- Kolizje nazw plików/katalogów, by ukryć prawdziwe artefakty (np. katalog nazwany `classes.dex/` obok prawdziwego `classes.dex`)

### 1) Fałszywe szyfrowanie (GPBF bit 0 ustawiony) bez prawdziwego szyfrowania

Objawy:
- `jadx-gui` kończy się błędami typu:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prosi o hasło dla kluczowych plików APK, mimo że prawidłowy APK nie może mieć zaszyfrowanych `classes*.dex`, `resources.arsc` ani `AndroidManifest.xml`:

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
Spójrz na flagę bitów ogólnego przeznaczenia dla nagłówków lokalnych i centralnych. Charakterystyczną wartością jest ustawiony bit 0 (szyfrowanie) nawet dla podstawowych wpisów:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i uruchamia na urządzeniu, ale kluczowe wpisy dla narzędzi wyglądają na "zaszyfrowane", GPBF został zmodyfikowany.

Rozwiązanie: wyczyść bit 0 GPBF zarówno w Local File Headers (LFH), jak i we wpisach Central Directory (CD). Minimalny patcher bajtowy:

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
Powinieneś teraz zobaczyć `General Purpose Flag  0000` na głównych wpisach, a narzędzia ponownie sparsują APK.

### 2) Duże/własne pola Extra łamiące parsery

Atakujący umieszczają przerośnięte pola Extra i nietypowe ID w nagłówkach, by zmylić dekompilery. W praktyce możesz zobaczyć tam niestandardowe znaczniki (np. ciągi takie jak `JADXBLOCK`) osadzone w tych polach.

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowano przykłady: nieznane ID, takie jak `0xCAFE` ("Java Executable") lub `0x414A` ("JA:"), zawierające duże payloads.

Heurystyki DFIR:
- Wygeneruj alert, gdy pola Extra są nietypowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane identyfikatory Extra w tych wpisach jako podejrzane.

Praktyczne złagodzenie: odbudowa archiwum (np. ponowne spakowanie wyodrębnionych plików) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają rozpakowania z powodu fałszywego szyfrowania, najpierw wyzeruj bit 0 w GPBF jak powyżej, a następnie zapakuj ponownie:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie prawdziwych artefaktów)

Plik ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre extractors i decompilers mogą się zdezorientować i nadpisać lub ukryć rzeczywisty plik wpisem katalogu. Zaobserwowano to przy kolizjach wpisów z podstawowymi nazwami w APK, takimi jak `classes.dex`.

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
Programatyczne wykrywanie post-fix:
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
- Oznacz APKs, których lokalne nagłówki wskazują szyfrowanie (GPBF bit 0 = 1), a mimo to instalują się/uruchamiają.
- Oznacz duże/nieznane pola Extra w podstawowych wpisach (szukaj markerów takich jak `JADXBLOCK`).
- Wykrywaj kolizje ścieżek (`X` i `X/`) szczególnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe triki ZIP (2024–2026)

### Złączone katalogi centralne (multi-EOCD evasion)

W ostatnich kampaniach phishingowych wysyłany jest pojedynczy blob, który w rzeczywistości to **dwa pliki ZIP połączone razem**. Każdy ma własny End of Central Directory (EOCD) + central directory. Różne extractory parsują różne katalogi (7zip czyta pierwszy, WinRAR ostatni), co pozwala atakującym ukryć payloady widoczne tylko w niektórych narzędziach. To również omija podstawowe mail gateway AV, które sprawdzają tylko pierwszy katalog.

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Jeśli pojawi się więcej niż jeden EOCD lub wystąpią ostrzeżenia "data after payload", podziel blob i sprawdź każdą część:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Nowoczesny "better zip bomb" tworzy mały **kernel** (wysoko skompresowany blok DEFLATE) i ponownie używa go poprzez nakładające się local headers. Każdy wpis w central directory wskazuje na te same skompresowane dane, osiągając stosunki >28M:1 bez zagnieżdżania archiwów. Biblioteki, które ufają rozmiarom central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP przed hardened builds) mogą zostać zmuszone do alokowania petabajtów.

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
- Wykonaj próbny przebieg: `zipdetails -v file.zip | grep -n "Rel Off"` i upewnij się, że offsety są ściśle rosnące i unikalne.
- Ogranicz akceptowany łączny rozmiar po dekompresji i liczbę wpisów przed rozpakowaniem (`zipdetails -t` lub własny parser).
- Jeśli musisz wypakować, rób to w cgroup/VM z ograniczeniami CPU i dysku (unikaj awarii spowodowanych niekontrolowanym wzrostem zużycia).

---

### Zamieszanie parserów Local-header vs central-directory

Niedawne badania differential-parser wykazały, że niejednoznaczność ZIP jest nadal wykorzystywalna w nowoczesnych toolchainach. Główna idea jest prosta: niektóre programy ufają **Local File Header (LFH)**, podczas gdy inne ufają **Central Directory (CD)**, więc jedno archiwum może prezentować różne nazwy plików, ścieżki, komentarze, offsety lub zestawy wpisów różnym narzędziom.

Praktyczne zastosowania w ofensywie:
- Spraw, aby filtr przesyłania, skaner AV lub walidator pakietów widział w CD plik nieszkodliwy, podczas gdy ekstraktor korzysta z innej nazwy/ścieżki z LFH.
- Wykorzystaj duplikaty nazw, wpisy obecne tylko w jednej strukturze lub niejednoznaczne metadane ścieżek Unicode (na przykład Info-ZIP Unicode Path Extra Field `0x7075`), tak aby różne parsery rekonstruowały różne drzewa.
- Połącz to z path traversal, aby zmienić „nieszkodliwy” widok archiwum w write-primitive podczas rozpakowywania. Dla strony ekstrakcji zobacz [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Potrzebuję treści, którą mam przetłumaczyć i uzupełnić. Proszę wklej zawartość pliku src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md albo podaj konkretnie, jakie elementy mam dodać (np. przykłady, narzędzia, scenariusze, polecenia).  

Dodatkowo potwierdź: czy chcemy tylko przetłumaczyć istniejący tekst na polski i dodać uzupełnienia, czy też napisać nowy rozdział w tym pliku?
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurystyki:
- Odrzuć lub odizoluj archiwa z niezgodnymi nazwami LFH/CD, zduplikowanymi nazwami plików, wieloma rekordami EOCD lub z bajtami następującymi po ostatnim EOCD.
- Traktuj ZIPs korzystające z nietypowych Unicode-path extra fields lub niespójnych komentarzy jako podejrzane, jeśli różne narzędzia nie zgadzają się co do drzewa plików po ekstrakcji.
- Jeśli analiza jest ważniejsza niż zachowanie oryginalnych bajtów, przepakuj archiwum za pomocą ścisłego parsera po ekstrakcji w sandboxie i porównaj powstałą listę plików z oryginalnymi metadanymi.

To ma znaczenie poza ekosystemami pakietów: ta sama klasa niejednoznaczności może ukrywać ładunki przed bramkami pocztowymi, skanerami statycznymi i niestandardowymi potokami przetwarzania, które "peek" at ZIP contents zanim inne narzędzie rozpakowujące zajmie się archiwum.

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
