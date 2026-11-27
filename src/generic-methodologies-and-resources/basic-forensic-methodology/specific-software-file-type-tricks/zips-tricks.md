# Sztuczki z ZIP-ami

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania zabezpieczeń plików zip. Oto kilka przydatnych narzędzi:<sup>[[1]](#references)</sup>

- **`unzip`**: Pokazuje, dlaczego plik zip może się nie rozpakowywać.
- **`zipdetails -v`**: Zapewnia szczegółową analizę pól formatu pliku zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Wyświetla zawartość pliku zip bez jej rozpakowywania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Podejmują próbę naprawy uszkodzonych plików zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do ataków słownikowych i brute-force na hasła ZIP; wykonalność zależy od przestrzeni wyszukiwania haseł.<sup>[[15]](#references)</sup>

[Specyfikacja formatu plików Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera wyczerpujące informacje o strukturze i standardach plików zip.<sup>[[4]](#references)</sup>

Tradycyjne pliki ZIP chronione hasłem zazwyczaj nie ukrywają nazw plików ani ich rozmiarów, w przeciwieństwie do trybów szyfrowania nagłówków obsługiwanych przez RAR i 7z. Atak known-plaintext na ZipCrypto odzyskuje **wewnętrzne klucze szyfrujące**, niekoniecznie oryginalne hasło; klucze te wystarczają do odszyfrowania wpisów zaszyfrowanych tym samym hasłem.<sup>[[13]](#references)</sup> Atak wymaga znajomości bajtów strumienia **sprzed szyfrowania**: w przypadku elementu przechowywanego bez kompresji są to oryginalne bajty pliku, ale w przypadku elementu DEFLATE są to bajty skompresowane, co może wymagać odtworzenia dokładnie takiego samego wyniku kompresji.<sup>[[13]](#references)[[14]](#references)</sup> Zobacz [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack), aby poznać praktyczny przebieg ataku. Informacje o podstawach kryptoanalizy znajdziesz w [artykule](https://math.ucr.edu/~mike/zipattacks.pdf) i [praktycznym przewodniku](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Ten atak na ZipCrypto nie działa na wpisy ZIP szyfrowane algorytmem AES.<sup>[[13]](#references)</sup>

---

## Sztuczki utrudniające inżynierię wsteczną w APK-ach z użyciem zmanipulowanych nagłówków ZIP

Współczesne droppery malware na Androida wykorzystują nieprawidłowe metadane ZIP, aby zakłócać działanie narzędzi do analizy statycznej (jadx/apktool/unzip), a jednocześnie zachować możliwość instalacji APK na urządzeniu. Najczęstsze sztuczki to:<sup>[[2]](#references)</sup>

- Pozorowanie szyfrowania przez ustawienie bitu 0 flagi GPBF (ZIP General Purpose Bit Flag)
- Nadużywanie dużych lub niestandardowych pól Extra w celu dezorientowania parserów
- Kolizje nazw plików i katalogów ukrywające prawdziwe artefakty (np. katalog o nazwie `classes.dex/` obok właściwego pliku `classes.dex`)

### 1) Pozorowanie szyfrowania (ustawiony bit 0 GPBF) bez rzeczywistego szyfrowania

Objawy:
- `jadx-gui` kończy działanie z błędami takimi jak:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` prosi o hasło do podstawowych plików APK, mimo że prawidłowy APK nie może zawierać zaszyfrowanych plików `classes*.dex`, `resources.arsc` ani `AndroidManifest.xml`:
  
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

Sprawdź flagę bitową ogólnego przeznaczenia w lokalnych i centralnych nagłówkach. Charakterystyczną wartością jest ustawiony bit 0 (szyfrowanie), nawet w przypadku podstawowych wpisów:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heurystyka: Jeśli APK instaluje się i działa na urządzeniu, ale narzędzia pokazują, że kluczowe wpisy są „zaszyfrowane”, oznacza to, że GPBF został zmodyfikowany.

Naprawa polega na wyczyszczeniu bitu 0 GPBF zarówno we wpisach Local File Headers (LFH), jak i Central Directory (CD). Minimalny patcher bajtów:

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

Zmienić powinien się tylko bit 0: na przykład `0A09` zmienia się w `0A08`, a nie `0000`. Ten minimalny patcher wyszukuje sygnatury nagłówków w surowych bajtach, więc bajty przypominające sygnatury wewnątrz danych pliku mogą powodować fałszywe dopasowania; pracuj na kopii i przed użyciem wyniku sprawdź listę wpisów oraz nagłówki.<sup>[[4]](#references)</sup>

### 2) Duże/niestandardowe pola Extra, które zakłócają działanie parserów

Atakujący umieszczają w nagłówkach nadmiernie duże pola Extra i nietypowe identyfikatory, aby wywołać błędy dekompilatorów. W praktyce można spotkać niestandardowe znaczniki (np. ciągi takie jak `JADXBLOCK`) osadzone w tych polach.

Inspekcja:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Zaobserwowane przykłady: nieznane identyfikatory, takie jak `0xCAFE` („Java Executable”) lub `0x414A` („JA:”), zawierające duże payloady.<sup>[[2]](#references)</sup>

Heurystyki DFIR:
- Generuj alert, gdy pola Extra są wyjątkowo duże w kluczowych wpisach (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Traktuj nieznane identyfikatory Extra w tych wpisach jako podejrzane.

Praktyczna metoda ograniczania ryzyka: przebudowanie archiwum (np. ponowne spakowanie wyodrębnionych plików) usuwa złośliwe pola Extra. Jeśli narzędzia odmawiają wyodrębnienia z powodu fałszywego szyfrowania, najpierw wyczyść bit 0 GPBF, jak opisano powyżej, a następnie przepakuj:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Kolizje nazw plików/katalogów (ukrywanie rzeczywistych artefaktów)

ZIP może zawierać jednocześnie plik `X` i katalog `X/`. Niektóre narzędzia do rozpakowywania i dekompilatory mogą się pogubić i nałożyć wpis katalogu na rzeczywisty plik lub go ukryć. Zaobserwowano to w przypadku kolizji z podstawowymi nazwami APK, takimi jak `classes.dex`.

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

Programowe wykrywanie po poprawce:

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

Pomysły na wykrywanie dla zespołów blue team:
- Wykrywaj APK, których lokalne nagłówki oznaczają szyfrowanie (GPBF bit 0 = 1), a mimo to dają się zainstalować/uruchomić.
- Wykrywaj duże lub nieznane pola Extra w kluczowych wpisach (szukaj znaczników takich jak `JADXBLOCK`).
- Wykrywaj kolizje ścieżek (`X` i `X/`) konkretnie dla `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Inne złośliwe sztuczki ZIP (2024–2026)

### Połączone katalogi centralne (obejście przez wiele EOCD)

W kampanii phishingowej z 2024 roku atakujący rozsyłali jeden plik, który w rzeczywistości składał się z **dwóch połączonych plików ZIP**. Każdy miał własny rekord End of Central Directory (EOCD) i katalog centralny. Różne programy do rozpakowywania analizowały różne katalogi (7-Zip odczytywał pierwszy, a WinRAR ostatni), co pozwalało atakującym ukrywać payloady widoczne tylko w niektórych narzędziach; skanery analizujące tylko jeden katalog mogą przeoczyć drugie archiwum.<sup>[[5]](#references)[[6]](#references)</sup>

**Polecenia do wstępnej analizy**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Jeśli pojawia się więcej niż jeden EOCD lub ostrzeżenia „data after payload”, podziel blob i sprawdź każdą część:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs build a tiny **kernel** (a highly compressed DEFLATE block) and reuse it across overlapping entries. Full-overlap variants point multiple central-directory entries at one local header, while quoted-overlap variants quote local headers inside DEFLATE streams; the published construction achieves more than 28M:1 without nested archives.<sup>[[7]](#references)</sup>

**Szybkie wykrywanie (zduplikowane offsety LFH)**

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
- Przeprowadź próbę bez wykonywania zmian: `zipdetails -v file.zip | grep -n "Local Header Offset"` i porównaj wskazane przesunięcia nagłówków lokalnych oraz zakresy skompresowanych danych; zduplikowane przesunięcia wskazują warianty z pełnym nakładaniem się danych.<sup>[[7]](#references)[[8]](#references)</sup>
- Przed rozpakowaniem ogranicz parserem łączny akceptowany rozmiar po dekompresji i liczbę wpisów; `zipinfo -t file.zip` podaje sumy, ale nie wymusza limitu bezpieczeństwa.<sup>[[8]](#references)</sup>
- Jeśli musisz rozpakować archiwum, zrób to w cgroup/VM z limitami CPU i miejsca na dysku (unikaj awarii spowodowanych nieograniczoną dekompresją).<sup>[[8]](#references)</sup>

---

### Niezgodność parserów nagłówka lokalnego i katalogu centralnego

Najnowsze badania nad różnicami między parserami pokazały, że niejednoznaczności w ZIP-ach nadal można wykorzystywać we współczesnych łańcuchach narzędzi. Główna idea jest prosta: niektóre programy ufają **Local File Header (LFH)**, a inne **Central Directory (CD)**, więc jedno archiwum może prezentować różne nazwy plików, ścieżki, komentarze, przesunięcia lub zestawy wpisów różnym narzędziom.<sup>[[9]](#references)</sup>

Praktyczne zastosowania ofensywne:
- Spraw, by filtr przesyłanych plików, skanowanie antywirusowe przed rozpakowaniem lub walidator pakietów widział w CD nieszkodliwy plik, podczas gdy narzędzie rozpakowujące uwzględnia inną nazwę/ścieżkę z LFH.
- Wykorzystaj zduplikowane nazwy, wpisy występujące tylko w jednej strukturze lub niejednoznaczne metadane ścieżek Unicode (na przykład Info-ZIP Unicode Path Extra Field `0x7075`), aby różne parsery odtworzyły różne drzewa plików.
- Połącz to z path traversal, aby zmienić „nieszkodliwy” widok archiwum w prymityw zapisu podczas rozpakowywania. Informacje o stronie rozpakowywania znajdziesz w [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Wstępna analiza DFIR:

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
- W przypadku przetwarzania danych wrażliwych pod względem bezpieczeństwa odrzucaj lub izoluj archiwa, w których nazwy LFH/CD są niezgodne, występują zduplikowane nazwy plików, wiele rekordów EOCD lub bajty po końcowym EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Traktuj ZIP-y używające nietypowych dodatkowych pól ścieżek Unicode lub niespójnych komentarzy jako podejrzane, jeśli różne narzędzia nie zgadzają się co do wyodrębnionej struktury plików.<sup>[[4]](#references)[[9]](#references)</sup>
- Jeśli analiza jest ważniejsza niż zachowanie oryginalnych bajtów, po wyodrębnieniu archiwum w sandboxie przepakuj je za pomocą parsera o ścisłych regułach i porównaj uzyskaną listę plików z oryginalnymi metadanymi.

Ma to znaczenie nie tylko w ekosystemach pakietów: ta sama klasa niejednoznaczności może ukrywać payloady przed bramkami pocztowymi, skanerami statycznymi i niestandardowymi pipeline'ami przetwarzania danych, które „podglądają” zawartość ZIP przed przekazaniem archiwum innemu ekstraktorowi.<sup>[[9]](#references)</sup>

---





## References

- [1] [Przewodnik terenowy po analizie kryminalistycznej CTF (blog Mike'a, kategoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – część 1 – wieloetapowy dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (skrypt IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specyfikacja formatu plików ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Elastyczna struktura archiwów ZIP wykorzystana do ukrycia malware bez wykrycia (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hakerzy ukrywają malware w nowym ataku z użyciem plików ZIP — skonkatenowane katalogi centralne ZIP](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Lepsza bomba ZIP (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zrozumieć bomby ZIP: konstrukcja jądra z nakładającymi się/cytowanymi nakładającymi się fragmentami](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mój ZIP to nie twój ZIP: identyfikowanie i wykorzystywanie różnic semantycznych między parserami ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Zapobieganie atakom wykorzystującym dezorientację parserów ZIP w instalatorach pakietów Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataki ZIP przy ograniczonej ilości znanego tekstu jawnego (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: realistyczna misja internetowa, poziom 15 (atak ZIP ze znanym tekstem jawnym)](https://www.hackthissite.org/articles/read/793)
- [13] [Użycie bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Samouczek bkcrack dotyczący znanego tekstu jawnego](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Repozytorium fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
