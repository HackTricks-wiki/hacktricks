# Path Traversal podczas ekstrakcji archiwum ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Omówienie

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala, aby każdy wpis zawierał własną **ścieżkę wewnętrzną**. Gdy narzędzie do ekstrakcji bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę absolutną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Konsekwencje obejmują zarówno nadpisywanie dowolnych plików, jak i bezpośrednie uzyskanie **remote code execution (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder *Startup* systemu Windows.

## Przyczyna

1. Atakujący tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinki**, które wskazują poza katalog docelowy (częste w ZIP/TAR na systemach *nix).
2. Ofiara wypakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinkami), zamiast ją sanityzować albo wymuszać ekstrakcję w obrębie wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez atakującego i wykonany/załadowany przy następnym uruchomieniu tej ścieżki przez system lub użytkownika.

### Traversal `.NET` `Path.Combine` + `ZipArchive`

Częstym antywzorcem w .NET jest połączenie zamierzonego miejsca docelowego z kontrolowanym przez użytkownika `ZipArchiveEntry.FullName` i przeprowadzenie ekstrakcji bez normalizacji ścieżki:<sup>[[4]](#references)[[8]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje traversal; jeśli jest **ścieżką absolutną**, lewy komponent jest całkowicie odrzucany, co skutkuje **arbitrary file write** jako tożsamością ekstrakcji.
- Archiwum proof-of-concept zapisujące dane w sąsiednim katalogu `app`, monitorowanym przez skaner uruchamiany zgodnie z harmonogramem:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP do monitorowanej skrzynki odbiorczej skutkuje utworzeniem pliku `C:\samples\app\0xdf.txt`, co dowodzi traversal poza `C:\samples\queue\` i umożliwia wykorzystanie kolejnych primitives (np. DLL hijacks).

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla Windows oraz jego komponenty Windows RAR/UnRAR nieprawidłowo weryfikowały nazwy plików podczas rozpakowywania. Luka wykorzystywała alternate data streams (ADS) systemu NTFS do ominięcia wybranej ścieżki rozpakowywania i zapisywania plików w niezamierzonych lokalizacjach.<sup>[[5]](#references)</sup>
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
trafiłby **poza** wybrany katalog wyjściowy i do folderu *Startup* użytkownika. ESET zaobserwował rozpakowywanie tam złośliwych plików LNK i ich uruchamianie przy logowaniu użytkownika, co zapewniało persistence oraz ścieżkę do RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)

Ponieważ CVE-2025-8088 wykorzystuje ścieżkę traversal w nazwie ADS, użyj generatora przeznaczonego do tego celu, aby utworzyć RAR, a następnie testuj rozpakowywanie wyłącznie w izolowanym laboratorium z podatną wersją WinRAR.<sup>[[5]](#references)</sup>

### Zaobserwowane wykorzystanie w środowisku

ESET poinformował o kampaniach spear-phishingowych grupy RomCom (Storm-0978/UNC2596), w których dołączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania niestandardowych backdoorów i ułatwiania operacji ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: Wpisy ZIP będące **symbolicznymi linkami** były dereferencjonowane podczas rozpakowywania, co pozwalało atakującym wyjść poza katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika ogranicza się do *otwarcia/rozpakowania* archiwum.<sup>[[1]](#references)</sup>
* **Dotyczy**: wersji 7-Zip wcześniejszych niż **25.00**. Błąd przetwarzania symbolic links został naprawiony w wersji **25.00** (lipiec 2025) oraz nowszych.<sup>[[1]](#references)[[10]](#references)</sup>
* **Ścieżka wpływu**: Nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługi → kod zostaje uruchomiony przy następnym logowaniu lub restarcie usługi.
* **Szybki fixture do obsługi symlinków (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
To archiwum zawiera wpis symlink wskazujący poza katalog rozpakowywania; użyj jednorazowego katalogu docelowego i sprawdź, czy extractor za nim nie podąża. Test zapisu przez symlink wymaga również wpisu zwykłego pliku znajdującego się za symlinkiem.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` podąża za `../` oraz symlinkowanymi wpisami ZIP, zapisując poza `outputDir`.<sup>[[2]](#references)</sup>
* **Dotyczy**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie deprecated).
* **Naprawa**: Przejdź na `mholt/archives` ≥ 0.1.0 albo zaimplementuj sprawdzanie canonical path przed zapisem.
* **Minimalna reprodukcja**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki dotyczące wykrywania

* **Inspekcja statyczna** – Wyświetl wpisy archiwum i oznacz każdą nazwę zawierającą `../`, `..\\`, *ścieżki absolutne* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem rozpakowywania.
* **Canonicalisation** – Upewnij się, że `realpath(join(dest, name))` pozostaje wewnątrz `realpath(dest)` (porównuj komponenty ścieżki, a nie tylko surowy prefix stringa). W przeciwnym razie odrzuć wpis.<sup>[[3]](#references)</sup>
* **Rozpakowywanie w sandboxie** – Rozpakuj do jednorazowego katalogu przy użyciu extractora ze sprawdzaniem ścieżek/symlinków (na przykład domyślnych bezpiecznych kontroli bsdtar lub 7-Zip ≥ 25.00), a następnie sprawdź, czy wynikowe ścieżki pozostają wewnątrz katalogu.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitorowanie endpointów** – Generuj alerty dotyczące nowych plików wykonywalnych zapisywanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum przez WinRAR/7-Zip itd.

## Ograniczanie ryzyka i hardening

1. **Zaktualizuj extractor** – WinRAR 7.13+ i 7-Zip 25.00+ zawierają poprawki dotyczące przywołanych problemów ze ścieżkami/symlinkami.<sup>[[1]](#references)[[5]](#references)</sup>
2. Jeśli to możliwe, rozpakowuj archiwa z opcją „**Do not extract paths**” / „**Ignore paths**”.
3. W systemach Unix obniż uprawnienia i zamontuj **chroot/namespace** przed rozpakowywaniem; w Windows użyj **AppContainer** lub sandboxa.
4. Jeśli tworzysz własny kod, wykonaj normalizację za pomocą `realpath()`/`PathCanonicalize()` **przed** utworzeniem/zapisem i odrzuć każdy wpis wychodzący poza katalog docelowy.

## Dodatkowe / historyczne przypadki

* 2018 – obszerne ostrzeżenie dotyczące *Zip-Slip* opublikowane przez Snyk, obejmujące wiele bibliotek Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal podczas rozpakowywania TAR w slugach (naprawione w v0.16.3).<sup>[[7]](#references)</sup>
* Dowolna niestandardowa logika rozpakowywania, która nie wywołuje `PathCanonicalize` / `realpath` przed zapisem.

## References

- [1] [Trend Micro ZDI-25-949 – traversal symlinków ZIP w 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip w mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zapobieganie Zip Slip w .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – łańcuch HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Zaktualizuj teraz narzędzia WinRAR: RomCom i inni wykorzystują podatność zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Publiczne ujawnienie krytycznej podatności umożliwiającej dowolne nadpisywanie plików: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug podatny na atak Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flagi bezpiecznego rozpakowywania bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Zgłoszono exploit Proof-of-Concept dla CVE-2025-11001 w 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
