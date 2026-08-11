# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala każdemu wpisowi zawierać własną **internal path**. Gdy narzędzie do ekstrakcji bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **absolute path** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Skutki obejmują nadpisywanie dowolnych plików oraz bezpośrednie uzyskanie **remote code execution (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder *Startup* systemu Windows.

## Root Cause

1. Attacker tworzy archiwum, w którym nagłówki jednego lub większej liczby plików zawierają:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinks**, które wskazują poza katalog docelowy (częste w ZIP/TAR na *nix*).
2. Victim rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinks), zamiast ją sanityzować albo wymuszać ekstrakcję w obrębie wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez attackera i wykonany/załadowany przy następnym uruchomieniu tej ścieżki przez system lub użytkownika.

### .NET `Path.Combine` + `ZipArchive` traversal

Częstym anti-patternem w .NET jest połączenie zamierzonego miejsca docelowego z kontrolowanym przez użytkownika `ZipArchiveEntry.FullName` i przeprowadzenie ekstrakcji bez normalizacji ścieżki:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje traversal; jeśli jest **ścieżką absolutną**, komponent po lewej stronie jest całkowicie odrzucany, co skutkuje **dowolnym zapisem pliku** jako identyfikatorem ekstrakcji.
- Archiwum proof-of-concept zapisujące dane do sąsiedniego katalogu `app`, monitorowanego przez skaner uruchamiany zgodnie z harmonogramem:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP do monitorowanej skrzynki odbiorczej skutkuje utworzeniem `C:\samples\app\0xdf.txt`, co dowodzi możliwości przejścia poza `C:\samples\queue\` i umożliwia wykorzystanie kolejnych prymitywów (np. DLL hijacks).

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows oraz jego komponenty Windows RAR/UnRAR nieprawidłowo sprawdzały nazwy plików podczas rozpakowywania. Luka wykorzystywała alternate data streams (ADS) systemu NTFS do ominięcia wybranej ścieżki rozpakowywania i zapisywania plików w niezamierzonych lokalizacjach.<sup>[[5]](#references)</sup>
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
trafiałyby **poza** wybranym katalogiem wyjściowym i do folderu *Startup* użytkownika. ESET zaobserwował rozpakowywanie tam złośliwych plików LNK i ich wykonywanie podczas logowania użytkownika, co zapewniało persistence oraz ścieżkę do RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)

Ponieważ CVE-2025-8088 używa ścieżki traversal w nazwie ADS, do utworzenia pliku RAR należy użyć generatora przeznaczonego do tego celu, a następnie testować ekstrakcję wyłącznie w odizolowanym laboratorium z podatną wersją WinRAR.<sup>[[5]](#references)</sup>

### Zaobserwowane wykorzystanie w środowisku

ESET poinformował o kampaniach spear-phishingowych grupy RomCom (Storm-0978/UNC2596), w których dołączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania niestandardowych backdoorów i ułatwiania operacji ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2025)

### Traversal symlinków ZIP w 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: Wpisy ZIP będące **symbolicznymi linkami** były rozwiązywane podczas ekstrakcji, co pozwalało atakującym opuścić katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika ogranicza się do *otwarcia/rozpakowania* archiwum.<sup>[[1]](#references)</sup>
* **Podatne wersje**: Kompilacje 7-Zip starsze niż **25.00**. Błąd przetwarzania symbolic-linków naprawiono w wersji **25.00** (lipiec 2025) i nowszych.<sup>[[1]](#references)[[10]](#references)</sup>
* **Ścieżka wpływu**: Nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługę → kod zostanie wykonany przy następnym logowaniu lub ponownym uruchomieniu usługi.
* **Szybki fixture do obsługi symlinków (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
To archiwum zawiera wpis symlinku wskazujący poza katalog ekstrakcji; użyj jednorazowego katalogu docelowego i sprawdź, czy extractor go nie śledzi. Test zapisu przez symlink wymaga również wpisu zwykłego pliku znajdującego się za symlinkiem.

### Zip-Slip w Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` podąża za `../` i wpisami ZIP będącymi symlinkami, zapisując dane poza `outputDir`.<sup>[[2]](#references)</sup>
* **Podatne wersje**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie deprecated).
* **Naprawa**: Przejdź na `mholt/archives` ≥ 0.1.0 albo zaimplementuj sprawdzanie ścieżki kanonicznej przed zapisem.
* **Minimalna reprodukcja**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki dotyczące detekcji

* **Inspekcja statyczna** – Wyświetl wpisy archiwum i oznacz każdą nazwę zawierającą `../`, `..\\`, *ścieżki absolutne* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem ekstrakcji.
* **Kanonikalizacja** – Upewnij się, że `realpath(join(dest, name))` pozostaje wewnątrz `realpath(dest)` (porównuj komponenty ścieżki, a nie tylko surowy prefix tekstowy). W przeciwnym razie odrzuć wpis.<sup>[[3]](#references)</sup>
* **Ekstrakcja w sandboxie** – Rozpakowuj do jednorazowego katalogu za pomocą extractora ze sprawdzaniem ścieżek/symlinków (na przykład domyślne bezpieczne kontrole bsdtar lub 7-Zip ≥ 25.00), a następnie sprawdź, czy wynikowe ścieżki pozostają wewnątrz katalogu.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitorowanie endpointów** – Generuj alerty dotyczące nowych plików wykonywalnych zapisywanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum przez WinRAR/7-Zip/etc.

## Mitygacja i hardening

1. **Zaktualizuj extractor** – WinRAR 7.13+ i 7-Zip 25.00+ zawierają poprawki problemów ze ścieżkami d/symlinkami.<sup>[[1]](#references)[[5]](#references)</sup>
2. Jeśli to możliwe, rozpakowuj archiwa z opcją „**Do not extract paths**” / „**Ignore paths**”.
3. W systemach Unix obniż uprawnienia i zamontuj **chroot/namespace** przed ekstrakcją; w Windows użyj **AppContainer** lub sandboxa.
4. Jeśli tworzysz własny kod, normalizuj ścieżkę za pomocą `realpath()`/`PathCanonicalize()` **przed** utworzeniem/zapisem i odrzucaj każdy wpis, który wychodzi poza katalog docelowy.

## Dodatkowe / historyczne przypadki

* 2018 – Obszerne advisory Snyk dotyczące *Zip-Slip*, obejmujące wiele bibliotek Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal podczas ekstrakcji TAR w slugach (naprawiono w v0.16.3).<sup>[[7]](#references)</sup>
* Każda własna logika ekstrakcji, która przed zapisem nie wywołuje `PathCanonicalize` / `realpath`.

## References

- [1] [Trend Micro ZDI-25-949 – traversal symlinków ZIP w 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Badania JFrog – Zip-Slip w mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – zapobieganie Zip Slip w .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – łańcuch HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Badania ESET – zaktualizuj narzędzia WinRAR już teraz: RomCom i inni wykorzystują podatność zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – publiczne ujawnienie krytycznej podatności umożliwiającej dowolne nadpisywanie plików: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug podatny na atak Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flagi bezpiecznej ekstrakcji bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – zgłoszono exploit Proof-of-Concept dla CVE-2025-11001 w 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
