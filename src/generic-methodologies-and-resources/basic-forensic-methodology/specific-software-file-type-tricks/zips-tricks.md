# Sztuczki z ZIP-ami

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania plików zip. Oto kilka kluczowych narzędzi:<sup>[[1]](#references)</sup>

- **`unzip`**: Ujawnia, dlaczego plik zip może się nie rozpakowywać.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu pliku zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Wyświetla zawartość pliku zip bez jej rozpakowywania.
- **`zip -F input.zip --out output.zip`** oraz **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force łamania haseł do plików zip, skuteczne w przypadku haseł o długości do około 7 znaków.

[Specyfikacja formatu plików Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera kompleksowe informacje na temat struktury i standardów plików zip.<sup>[[4]](#references)</sup>

Należy pamiętać, że tradycyjne pliki ZIP chronione hasłem zazwyczaj ujawniają nazwy plików i ich rozmiary, w przeciwieństwie do trybów szyfrowania nagłówków obsługiwanych przez RAR i 7z. Ponadto pliki ZIP zaszyfrowane starszą metodą ZipCrypto są podatne na **atak plaintext**, jeśli dostępna jest nieszyfrowana kopia skompresowanego pliku.<sup>[[1]](#references)</sup> Atak ten wykorzystuje znaną zawartość do złamania hasła ZIP, jak wyjaśniono w [tym artykule akademickim](https://math.ucr.edu/~mike/zipattacks.pdf) i przedstawiono w [tym poradniku Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Jednak atak known-plaintext ZipCrypto nie ma zastosowania do wpisów zabezpieczonych szyfrowaniem **AES-256**.<sup>[[1]](#references)</sup>

---

## Techniki anti-reversing w APK z użyciem zmanipulowanych nagłówków ZIP

Nowoczesne malware droppery dla Androida używają niepoprawnych metadanych ZIP, aby powodować błędy narzędzi statycznych (jadx/apktool/unzip), zachowując jednocześnie możliwość instalacji APK na urządzeniu. Najczęstsze techniki to:<sup>[[2]](#references)</sup>

- Fałszywe szyfrowanie przez ustawienie bitu 0 w ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych lub niestandardowych pól Extra w celu wprowadzania parserów w błąd
- Kolizje nazw plików i katalogów w celu ukrycia prawdziwych artefaktów (np. katalog o nazwie `classes.dex/` obok właściwego `classes.dex`)

### 1) Fałszywe szyfrowanie (ustawiony bit 0 GPBF) bez rzeczywistej kryptografii

Objawy:
- `jadx-gui` kończy działanie z błędami takimi jak:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prosi o hasło do podstawowych plików APK, mimo że poprawny APK nie może mieć zaszyfrowanych plików `classes*.dex`, `resources.arsc` ani `AndroidManifest.xml`:

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
Spójrz na flagę bitową ogólnego przeznaczenia dla nagłówków lokalnych i centralnych. Charakterystyczną wartością jest ustawiony bit 0 (Encryption), nawet dla podstawowych wpisów:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i działa na urządzeniu, ale główne wpisy wyglądają dla narzędzi na „zaszyfrowane”, oznacza to, że GPBF został zmodyfikowany.

Napraw to, czyszcząc bit 0 GPBF zarówno we wpisach Local File Headers (LFH), jak i Central Directory (CD). Minimalny byte-patcher:

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
Powinieneś teraz zobaczyć `General Purpose Flag  0000` przy głównych wpisach, a narzędzia ponownie przeanalizują APK.

### 2) Duże/niestandardowe pola Extra zakłócające działanie parserów

Atakujący umieszczają w nagłówkach nadmiernie duże pola Extra i nietypowe identyfikatory, aby wywołać problemy w decompilerach. W praktyce możesz zobaczyć osadzone tam niestandardowe znaczniki (np. ciągi takie jak `JADXBLOCK`).

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane ID, takie jak `0xCAFE` („Java Executable”) lub `0x414A` („JA:”), zawierające duże payloady.<sup>[[2]](#references)</sup>

Heurystyki DFIR:
- Generuj alert, gdy pola Extra są wyjątkowo duże w podstawowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane ID Extra w tych wpisach jako podejrzane.

Praktyczne ograniczenie ryzyka: odbudowanie archiwum (np. ponowne spakowanie wyodrębnionych plików) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają ekstrakcji z powodu fałszywego szyfrowania, najpierw wyczyść bit 0 GPBF, jak opisano powyżej, a następnie ponownie spakuj archiwum:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre extractors i decompilers ulegają dezorientacji i mogą nakładać katalog na rzeczywisty plik lub ukrywać go za wpisem katalogu. Zaobserwowano to w przypadku wpisów kolidujących z podstawowymi nazwami APK, takimi jak `classes.dex`.

Triage i bezpieczna ekstrakcja:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programistyczne wykrywanie po naprawie:
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
Pomysły na wykrywanie przez blue-team:
- Oznaczaj APK, których lokalne nagłówki wskazują na szyfrowanie (GPBF bit 0 = 1), a mimo to są instalowane/uruchamiane.
- Oznaczaj duże/nieznane pola Extra w kluczowych wpisach (szukaj markerów takich jak `JADXBLOCK`).
- Oznaczaj kolizje ścieżek (`X` i `X/`) dotyczące konkretnie `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe triki ZIP (2024–2026)

### Połączone central directories (unikanie wykrycia przez wiele EOCD)

W kampanii phishingowej z 2024 roku atakujący dostarczyli pojedynczy blob, który w rzeczywistości składał się z **dwóch połączonych plików ZIP**. Każdy z nich miał własny rekord End of Central Directory (EOCD) i central directory. Różne extractors parsowały różne directories (7-Zip odczytywał pierwszą, a WinRAR ostatnią), co pozwalało atakującym ukrywać payloads, które były widoczne tylko w niektórych narzędziach; scannery sprawdzające tylko jeden directory mogą przeoczyć drugie archiwum.<sup>[[5]](#references)[[6]](#references)</sup>

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Jeśli pojawia się więcej niż jeden EOCD lub występują ostrzeżenia „data after payload”, podziel blob i sprawdź każdą część:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs tworzą mały **kernel** (silnie skompresowany blok DEFLATE) i ponownie wykorzystują go w nakładających się na siebie entries. Warianty full-overlap wskazują wieloma entries w central directory na jeden local header, natomiast warianty quoted-overlap umieszczają local headers wewnątrz streams DEFLATE; opublikowana konstrukcja osiąga współczynnik większy niż 28M:1 bez zagnieżdżonych archiwów.<sup>[[7]](#references)</sup>

**Szybkie wykrywanie (zduplikowane offsets LFH)**
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
**Obsługa**
- Wykonaj przejście dry-run: `zipdetails -v file.zip | grep -n "Local Header Offset"` i porównaj wskazane offsety local-header oraz zakresy skompresowanych danych; zduplikowane offsety wskazują warianty z pełnym nakładaniem się.<sup>[[7]](#references)[[8]](#references)</sup>
- Przed ekstrakcją ogranicz akceptowany całkowity rozmiar nieskompresowanych danych i liczbę wpisów za pomocą parsera; `zipinfo -t file.zip` raportuje wartości sumaryczne, ale nie wymusza limitu bezpieczeństwa.<sup>[[8]](#references)</sup>
- Gdy ekstrakcja jest konieczna, wykonuj ją wewnątrz cgroup/VM z limitami CPU i miejsca na dysku (unikaj crashy spowodowanych nieograniczoną dekompresją).<sup>[[8]](#references)</sup>

---

### Pomylenie parsera local-header z parserem central-directory

Nowsze badania nad differential-parserami wykazały, że niejednoznaczność ZIP nadal może być wykorzystywana w nowoczesnych toolchainach. Główna idea jest prosta: niektóre programy ufają **Local File Header (LFH)**, podczas gdy inne ufają **Central Directory (CD)**, dlatego jedno archiwum może prezentować różne nazwy plików, ścieżki, komentarze, offsety lub zestawy wpisów różnym narzędziom.<sup>[[9]](#references)</sup>

Praktyczne zastosowania ofensywne:
- Spraw, aby upload filter, pre-scan AV lub package validator zobaczył benign file w CD, podczas gdy extractor zastosuje inną nazwę/ścieżkę LFH.
- Wykorzystaj zduplikowane nazwy, wpisy obecne tylko w jednej strukturze lub niejednoznaczne metadane ścieżek Unicode (na przykład Info-ZIP Unicode Path Extra Field `0x7075`), aby różne parsery odtworzyły różne drzewa.
- Połącz to z path traversal, aby zamienić „nieszkodliwy” widok archiwum w write-primitive podczas ekstrakcji. Po stronie ekstrakcji zobacz [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage DFIR:
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
Uzupełnij to o:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurystyka:
- W przypadku ingestion wrażliwego pod względem bezpieczeństwa odrzucaj lub izoluj archiwa z niezgodnymi nazwami LFH/CD, zduplikowanymi nazwami plików, wieloma rekordami EOCD lub bajtami znajdującymi się za końcowym EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Traktuj ZIP-y używające nietypowych pól extra dla ścieżek Unicode lub niespójnych komentarzy jako podejrzane, jeśli różne narzędzia nie zgadzają się co do wyodrębnionego drzewa.<sup>[[4]](#references)[[9]](#references)</sup>
- Jeśli analiza jest ważniejsza niż zachowanie oryginalnych bajtów, przepakuj archiwum za pomocą strict parser po ekstrakcji w sandboxie i porównaj wynikową listę plików z oryginalnymi metadanymi.

Ma to znaczenie nie tylko w przypadku package ecosystems: ta sama klasa niejednoznaczności może ukrywać payloady przed mail gateways, static scanners i custom ingestion pipelines, które „podejrzą” zawartość ZIP-a, zanim inny extractor obsłuży archiwum.<sup>[[9]](#references)</sup>

---



## References

- [1] [Przewodnik terenowy po CTF Forensics (blog Mike'a, kategoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – część 1 – wieloetapowy dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (skrypt IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specyfikacja formatu plików ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Elastyczna struktura archiwów Zip wykorzystana do niewykrytego ukrywania malware (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackerzy ukrywają malware w nowym ataku na pliki ZIP — połączone central directories ZIP-ów](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Lepsza bomba zip (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zrozumienie bomb Zip: konstrukcja jądra overlapping/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mój ZIP to nie twój ZIP: identyfikowanie i wykorzystywanie luk semantycznych między parserami ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Zapobieganie atakom confusion parserów ZIP na instalatory pakietów Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataki ZIP z ograniczonym znanym tekstem jawnym (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: realistyczna misja webowa, poziom 15 (atak ZIP z użyciem znanego tekstu jawnego)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
