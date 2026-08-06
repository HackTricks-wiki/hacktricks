# Triki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania zabezpieczeń plików zip. Oto kilka kluczowych narzędzi:<sup>[[1]](#references)</sup>

- **`unzip`**: Ujawnia, dlaczego plik zip może się nie rozpakowywać.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu plików zip.
- **`zipinfo`**: Wyświetla zawartość pliku zip bez jej rozpakowywania.
- **`zip -F input.zip --out output.zip`** oraz **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force cracking haseł zip, skuteczne w przypadku haseł o długości do około 7 znaków.

[Specyfikacja formatu plików Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera kompleksowe informacje na temat struktury i standardów plików zip.<sup>[[4]](#references)</sup>

Należy pamiętać, że pliki zip chronione hasłem **nie szyfrują nazw plików ani rozmiarów plików** znajdujących się w ich wnętrzu. Jest to luka w zabezpieczeniach, której nie mają pliki RAR ani 7z, szyfrujące te informacje. Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na **plaintext attack**, jeśli dostępna jest nieszyfrowana kopia skompresowanego pliku.<sup>[[1]](#references)</sup> Atak ten wykorzystuje znaną zawartość do złamania hasła zip. Luka ta została szczegółowo opisana w [artykule HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dodatkowo wyjaśniona w [tej pracy naukowej](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Pliki zip zabezpieczone szyfrowaniem **AES-256** są jednak odporne na ten plaintext attack, co pokazuje znaczenie wyboru bezpiecznych metod szyfrowania dla wrażliwych danych.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks w APK przy użyciu zmanipulowanych nagłówków ZIP

Współczesne Android malware droppers wykorzystują nieprawidłowe metadane ZIP, aby blokować działanie narzędzi do analizy statycznej (jadx/apktool/unzip), jednocześnie pozostawiając APK możliwy do zainstalowania na urządzeniu. Najczęstsze triki to:<sup>[[2]](#references)</sup>

- Fałszywe szyfrowanie przez ustawienie bitu 0 ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych/niestandardowych pól Extra w celu zdezorientowania parserów
- Kolizje nazw plików/katalogów w celu ukrycia prawdziwych artefaktów (np. katalog o nazwie `classes.dex/` obok właściwego pliku `classes.dex`)

### 1) Fałszywe szyfrowanie (ustawiony bit 0 GPBF) bez rzeczywistej kryptografii

Objawy:
- `jadx-gui` kończy działanie z błędami takimi jak:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prosi o hasło dla podstawowych plików APK, mimo że prawidłowy APK nie może zawierać zaszyfrowanych plików `classes*.dex`, `resources.arsc` ani `AndroidManifest.xml`:

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
Sprawdź **General Purpose Bit Flag** dla nagłówków lokalnych i centralnych. Charakterystyczną wartością jest ustawiony bit 0 (Encryption), nawet dla podstawowych wpisów:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i działa na urządzeniu, ale podstawowe wpisy wyglądają dla narzędzi na „zaszyfrowane”, oznacza to, że GPBF został zmodyfikowany.

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
Teraz w wpisach core powinno być widoczne `General Purpose Flag  0000`, a narzędzia ponownie przeanalizują APK.

### 2) Duże/niestandardowe pola Extra zakłócające działanie parserów

Atakujący umieszczają w nagłówkach nadmiarowo duże pola Extra i nietypowe identyfikatory, aby zakłócić działanie decompilerów. W praktyce możesz napotkać niestandardowe markery (np. ciągi takie jak `JADXBLOCK`) osadzone w tych polach.

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane IDs, takie jak `0xCAFE` („Java Executable”) lub `0x414A` („JA:”), zawierające duże payloads.

Heurystyki DFIR:
- Generuj alert, gdy pola Extra są wyjątkowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane IDs Extra w tych wpisach jako podejrzane.

Praktyczne ograniczenie ryzyka: przebudowanie archiwum (np. ponowne spakowanie wyodrębnionych plików do ZIP) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają ekstrakcji z powodu fałszywego szyfrowania, najpierw wyczyść bit 0 GPBF, jak wyżej, a następnie przepakuj archiwum:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre extractors i dekompilatory mogą się pogubić i nałożyć katalog na rzeczywisty plik lub ukryć go wpisem katalogu. Zaobserwowano to w przypadku kolizji z podstawowymi nazwami APK, takimi jak `classes.dex`.

Wstępna analiza i bezpieczne rozpakowywanie:
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
Pomysły na detekcję po stronie blue-team:
- Oznaczaj pliki APK, których lokalne nagłówki wskazują szyfrowanie (GPBF bit 0 = 1), a mimo to dają się zainstalować/uruchomić.
- Oznaczaj duże lub nieznane pola Extra w kluczowych entries (szukaj markerów takich jak `JADXBLOCK`).
- Oznaczaj kolizje ścieżek (`X` i `X/`) w szczególności dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe triki ZIP (2024–2026)

### Połączone central directories (multi-EOCD evasion)

Najnowsze kampanie phishingowe dostarczają pojedynczy blob, który w rzeczywistości jest **dwoma połączonymi plikami ZIP**. Każdy z nich ma własny End of Central Directory (EOCD) oraz central directory. Różne extractors parsują różne directories (7zip odczytuje pierwszą, WinRAR ostatnią), co pozwala atakującym ukrywać payloads widoczne tylko w niektórych tools. Omija to również podstawowy mail gateway AV, który sprawdza tylko pierwszy directory.<sup>[[5]](#references)[[6]](#references)</sup>

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Jeśli pojawia się więcej niż jeden EOCD lub występują ostrzeżenia „data after payload”, podziel blob i zbadaj każdą część:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Nowoczesne „better zip bomb” tworzą niewielki **kernel** (silnie skompresowany blok DEFLATE) i wykorzystują go ponownie za pomocą nakładających się nagłówków lokalnych. Każdy wpis centralnego katalogu wskazuje te same skompresowane dane, osiągając współczynniki >28M:1 bez zagnieżdżania archiwów. Biblioteki, które ufają rozmiarom z centralnego katalogu (`zipfile` w Pythonie, `java.util.zip` w Javie, Info-ZIP przed utwardzonymi wersjami), mogą zostać zmuszone do zaalokowania petabajtów.<sup>[[7]](#references)[[8]](#references)</sup>

**Szybkie wykrywanie (zduplikowane offsety LFH)**
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
- Wykonaj skanowanie w trybie dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` i upewnij się, że offsety są ściśle rosnące oraz unikalne.
- Ogranicz akceptowany całkowity rozmiar po rozpakowaniu i liczbę wpisów przed ekstrakcją (`zipdetails -t` lub własny parser).
- Gdy ekstrakcja jest konieczna, wykonaj ją wewnątrz cgroup/VM z limitami CPU i dysku (unikaj crashy spowodowanych nieograniczonym rozrostem danych).

---

### Pomylenie parsera local-header z parserem central-directory

Najnowsze badania nad differential-parserami wykazały, że niejednoznaczność ZIP nadal może być wykorzystywana we współczesnych toolchainach. Główna idea jest prosta: niektóre programy ufają **Local File Header (LFH)**, podczas gdy inne ufają **Central Directory (CD)**, więc jedno archiwum może prezentować różne nazwy plików, ścieżki, komentarze, offsety lub zestawy wpisów różnym narzędziom.<sup>[[9]](#references)</sup>

Praktyczne zastosowania ofensywne:
- Spraw, aby filtr uploadu, skanowanie AV przed przetwarzaniem lub validator pakietów zobaczył nieszkodliwy plik w CD, podczas gdy extractor zastosuje inną nazwę/ścieżkę z LFH.
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
Heurystyki:
- Odrzucaj lub izoluj archiwa z niezgodnymi nazwami LFH/CD, zduplikowanymi nazwami plików, wieloma rekordami EOCD lub bajtami występującymi po końcowym EOCD.<sup>[[10]](#references)</sup>
- Traktuj ZIP-y wykorzystujące nietypowe dodatkowe pola ścieżek Unicode lub niespójne komentarze jako podejrzane, jeśli różne narzędzia nie zgadzają się co do wyodrębnionego drzewa plików.<sup>[[9]](#references)</sup>
- Jeśli analiza jest ważniejsza niż zachowanie oryginalnych bajtów, przepakuj archiwum za pomocą restrykcyjnego parsera po wyodrębnieniu go w sandboxie i porównaj wynikową listę plików z oryginalnymi metadanymi.

Ma to znaczenie nie tylko w przypadku ekosystemów pakietów: ta sama klasa niejednoznaczności może ukrywać payloady przed bramami pocztowymi, skanerami statycznymi i niestandardowymi pipeline'ami ingestującymi, które „zaglądają” do zawartości ZIP-a, zanim archiwum zostanie obsłużone przez inny extractor.

---



## Referencje

- [1] [Przewodnik terenowy po CTF Forensics (blog Mike'a, kategoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – część 1 – wieloetapowy dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (skrypt Archive::Zip)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Specyfikacja formatu plików ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Elastyczna struktura archiwów Zip wykorzystana do niewykrywalnego ukrywania malware (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackerzy zakopują malware w nowym ataku na pliki ZIP — konkatenowane katalogi centralne ZIP](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Lepsza bomba zip (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Zrozumienie bomb Zip: konstrukcja kernela z nakładającym się/cytowanym nakładaniem](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mój ZIP to nie twój ZIP: identyfikowanie i wykorzystywanie luk semantycznych między parserami ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Zapobieganie atakom typu ZIP parser confusion na instalatory pakietów Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataki na ZIP ze zredukowanym znanym tekstem jawnym (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Atak ze znanym tekstem jawnym: łamanie plików ZIP](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
