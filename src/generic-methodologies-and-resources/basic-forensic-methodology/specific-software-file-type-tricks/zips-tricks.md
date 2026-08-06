# Triki ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania plików zip. Oto kilka kluczowych narzędzi:<sup>[[1]](#references)</sup>

- **`unzip`**: Ujawnia, dlaczego plik zip może się nie rozpakowywać.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu pliku zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Wyświetla zawartość pliku zip bez jej rozpakowywania.
- **`zip -F input.zip --out output.zip`** oraz **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brute-force'owego łamania haseł zip, skuteczne w przypadku haseł o długości do około 7 znaków.

[Specyfikacja formatu pliku Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera kompleksowe informacje na temat struktury i standardów plików zip.<sup>[[4]](#references)</sup>

Należy pamiętać, że chronione hasłem pliki zip **nie szyfrują nazw plików ani ich rozmiarów**, co stanowi lukę bezpieczeństwa nieobecną w plikach RAR ani 7z, które szyfrują te informacje. Ponadto pliki zip zaszyfrowane starszą metodą ZipCrypto są podatne na **plaintext attack**, jeśli dostępna jest niezaszyfrowana kopia skompresowanego pliku.<sup>[[1]](#references)</sup> Atak ten wykorzystuje znaną zawartość do złamania hasła pliku zip. Luka ta została szczegółowo opisana w [artykule HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dokładniej wyjaśniona w [tym artykule naukowym](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Jednak pliki zip zabezpieczone szyfrowaniem **AES-256** są odporne na ten plaintext attack, co pokazuje znaczenie wyboru bezpiecznych metod szyfrowania w przypadku poufnych danych.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks w APK z użyciem zmanipulowanych nagłówków ZIP

Współczesne malware droppers dla Androida używają nieprawidłowych metadanych ZIP, aby zakłócać działanie narzędzi do analizy statycznej (jadx/apktool/unzip), jednocześnie zachowując możliwość instalacji APK na urządzeniu. Najczęstsze triki to:<sup>[[2]](#references)</sup>

- Fałszywe szyfrowanie poprzez ustawienie bitu 0 ZIP General Purpose Bit Flag (GPBF)
- Nadużywanie dużych/niestandardowych pól Extra w celu wprowadzania parserów w błąd
- Kolizje nazw plików/katalogów w celu ukrycia rzeczywistych artefaktów (np. katalog o nazwie `classes.dex/` obok właściwego `classes.dex`)

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
Sprawdź flagę bitową ogólnego przeznaczenia dla nagłówków lokalnych i centralnych. Charakterystyczną wartością jest ustawiony bit 0 (Encryption), nawet dla podstawowych wpisów:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurystyka: Jeśli APK instaluje się i działa na urządzeniu, ale główne wpisy wyglądają dla narzędzi na „zaszyfrowane”, oznacza to, że GPBF został zmodyfikowany.

Naprawa polega na wyczyszczeniu bitu 0 GPBF zarówno w Local File Headers (LFH), jak i we wpisach Central Directory (CD). Minimalny patcher bajtów:

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
Powinieneś teraz widzieć `General Purpose Flag  0000` przy wpisach core, a narzędzia ponownie przeanalizują APK.

### 2) Duże/niestandardowe pola Extra do łamania parserów

Atakujący umieszczają w nagłówkach nadmiernie duże pola Extra oraz nietypowe identyfikatory, aby zakłócić działanie decompilerów. W praktyce możesz zobaczyć osadzone tam niestandardowe znaczniki (np. ciągi takie jak `JADXBLOCK`).

Inspekcja:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Zaobserwowane przykłady: nieznane ID, takie jak `0xCAFE` („Java Executable”) lub `0x414A` („JA:”), zawierające duże payloady.

Heurystyki DFIR:
- Generuj alert, gdy pola Extra są nietypowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane ID Extra w tych wpisach jako podejrzane.

Praktyczne ograniczenie ryzyka: przebudowanie archiwum (np. ponowne spakowanie wyodrębnionych plików do ZIP) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają ekstrakcji z powodu fałszywego szyfrowania, najpierw wyczyść bit 0 GPBF, jak opisano powyżej, a następnie ponownie spakuj archiwum:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizje nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

ZIP może zawierać zarówno plik `X`, jak i katalog `X/`. Niektóre extractors i decompilers mogą się pomylić i nałożyć katalog na rzeczywisty plik lub ukryć go za wpisem katalogu. Zaobserwowano to w przypadku wpisów kolidujących z podstawowymi nazwami APK, takimi jak `classes.dex`.

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
Programowe wykrywanie po naprawie:
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
Pomysły na detekcję dla Blue-team:
- Oznaczaj APK, których lokalne nagłówki wskazują szyfrowanie (GPBF bit 0 = 1), a mimo to aplikacje instalują się/uruchamiają.
- Oznaczaj duże/nieznane pola Extra w kluczowych wpisach (szukaj znaczników takich jak `JADXBLOCK`).
- Oznaczaj kolizje ścieżek (`X` i `X/`) konkretnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe techniki ZIP (2024–2026)

### Połączone central directories (unikanie detekcji przez multi-EOCD)

Najnowsze kampanie phishingowe dostarczają pojedynczy blob, który w rzeczywistości jest **dwoma połączonymi plikami ZIP**. Każdy z nich ma własny End of Central Directory (EOCD) oraz central directory. Różne extractory analizują różne directory (7zip odczytuje pierwszą, WinRAR ostatnią), co pozwala atakującym ukrywać payloads widoczne tylko w niektórych narzędziach. Omija to również podstawowy mail gateway AV, który analizuje tylko pierwszą directory.<sup>[[5]](#references)[[6]](#references)</sup>

**Polecenia triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Jeśli pojawia się więcej niż jeden EOCD lub występują ostrzeżenia „data after payload”, podziel blob i przeanalizuj każdą część:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (nierekurencyjne)

Nowoczesne konstrukcje „better zip bomb” tworzą niewielki **kernel** (silnie skompresowany blok DEFLATE) i używają go ponownie za pośrednictwem nakładających się nagłówków lokalnych. Każdy wpis centralnego katalogu wskazuje te same skompresowane dane, co pozwala osiągnąć współczynniki >28M:1 bez zagnieżdżania archiwów. Biblioteki, które ufają rozmiarom z centralnego katalogu (`zipfile` w Pythonie, `java.util.zip` w Javie, Info-ZIP przed wydaniami z poprawkami bezpieczeństwa), mogą zostać zmuszone do alokacji petabajtów.<sup>[[7]](#references)[[8]](#references)</sup>

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
- Wykonaj przejście w trybie dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` i upewnij się, że offsety są ściśle rosnące i unikalne.
- Ustal maksymalny akceptowany łączny rozmiar rozpakowanych danych oraz liczbę wpisów przed ekstrakcją (`zipdetails -t` lub własny parser).
- Gdy ekstrakcja jest konieczna, wykonaj ją wewnątrz cgroup/VM z limitami CPU i dysku (aby uniknąć awarii spowodowanych nieograniczonym rozrostem danych).

---

### Pomieszanie parserów local-header i central-directory

Najnowsze badania nad differential-parserami wykazały, że niejednoznaczność ZIP nadal jest możliwa do wykorzystania w nowoczesnych toolchainach. Główna idea jest prosta: niektóre programy ufają **Local File Header (LFH)**, podczas gdy inne ufają **Central Directory (CD)**, dlatego jedno archiwum może prezentować różne nazwy plików, ścieżki, komentarze, offsety lub zestawy wpisów w różnych narzędziach.<sup>[[9]](#references)</sup>

Praktyczne zastosowania ofensywne:
- Spraw, aby filtr uploadu, skanowanie wstępne AV lub walidator pakietu zobaczył benign file w CD, podczas gdy extractor zastosuje inną nazwę/ścieżkę LFH.
- Wykorzystaj zduplikowane nazwy, wpisy obecne tylko w jednej strukturze lub niejednoznaczne metadane ścieżek Unicode (na przykład Info-ZIP Unicode Path Extra Field `0x7075`), aby różne parsery odtworzyły różne drzewa.
- Połącz to z path traversal, aby zamienić „nieszkodliwy” widok archiwum w prymityw zapisu podczas ekstrakcji. Po stronie ekstrakcji zobacz [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Uzupełnij to o:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurystyki:
- Odrzucaj lub izoluj archiwa z niezgodnymi nazwami LFH/CD, zduplikowanymi nazwami plików, wieloma rekordami EOCD lub bajtami występującymi po końcowym EOCD.<sup>[[10]](#references)</sup>
- Traktuj pliki ZIP używające nietypowych dodatkowych pól Unicode-path lub niespójnych komentarzy jako podejrzane, jeśli różne narzędzia nie zgadzają się co do wyodrębnionego drzewa.<sup>[[9]](#references)</sup>
- Jeśli analiza jest ważniejsza niż zachowanie oryginalnych bajtów, przepakuj archiwum przy użyciu strict parser po wyodrębnieniu w sandboxie i porównaj wynikową listę plików z oryginalnymi metadanymi.

Ma to znaczenie wykraczające poza ekosystemy pakietów: ta sama klasa niejednoznaczności może ukrywać payloady przed mail gateways, static scanners i niestandardowymi ingestion pipelines, które „zaglądają” do zawartości ZIP, zanim inny extractor obsłuży archiwum.

---



## References

- [1] [Przewodnik terenowy po CTF Forensics (blog Mike'a, kategoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – część 1 – wieloetapowy dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (skrypt Archive::Zip)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Specyfikacja formatu plików ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Elastyczna struktura archiwów Zip wykorzystana do niewykrywalnego ukrywania malware (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackerzy ukrywają malware w nowym ataku na pliki ZIP — konkatenowane central directories ZIP](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Lepsza zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Zrozumienie Zip Bombs: konstrukcja overlapped/quoted-overlap kernel](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: identyfikowanie i wykorzystywanie semantic gaps między parserami ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Zapobieganie atakom parser confusion w instalatorach pakietów Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: łamanie plików ZIP](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
