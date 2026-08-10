# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Wprowadzenie

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala, aby każdy wpis zawierał własną **internal path**. Gdy narzędzie do ekstrakcji bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **absolute path** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Skutki obejmują nadpisywanie dowolnych plików, a nawet bezpośrednie osiągnięcie **remote code execution (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder *Startup* systemu Windows.

## Główna przyczyna

1. Attacker tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinks**, które wskazują poza katalog docelowy (częste w ZIP/TAR na *nix*).
2. Victim wypakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinks), zamiast ją sanityzować albo wymuszać ekstrakcję wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez attackera i wykonany/załadowany przy następnym uruchomieniu tej ścieżki przez system lub użytkownika.

### .NET `Path.Combine` + `ZipArchive` traversal

Częstym antywzorcem w .NET jest łączenie zamierzonego miejsca docelowego z kontrolowanym przez użytkownika `ZipArchiveEntry.FullName` i wypakowywanie bez normalizacji ścieżki:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje traversal; jeśli jest **absolute path**, komponent po lewej stronie zostaje całkowicie odrzucony, co skutkuje **arbitrary file write** jako tożsamością ekstrakcji.
- Archive proof-of-concept zapisujące dane do sąsiedniego katalogu `app`, monitorowanego przez zaplanowany skaner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP do monitorowanej skrzynki odbiorczej skutkuje utworzeniem pliku `C:\samples\app\0xdf.txt`, co dowodzi możliwości przejścia poza `C:\samples\queue\` i umożliwia wykorzystanie kolejnych prymitywów (np. DLL hijacks).

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows oraz jego komponenty Windows RAR/UnRAR nieprawidłowo sprawdzały nazwy plików podczas rozpakowywania. Luka wykorzystywała alternatywne strumienie danych NTFS (ADS) w celu obejścia wybranej ścieżki rozpakowywania i zapisywania plików w niezamierzonych lokalizacjach.<sup>[[5]](#references)</sup>
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET observed malicious LNK files being unpacked there and executed at user logon, providing persistence and a path to RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)

Because CVE-2025-8088 uses a traversal path in an ADS name, use a purpose-built generator to create the RAR, then test extraction only in an isolated lab with a vulnerable WinRAR build.<sup>[[5]](#references)</sup>

### Zaobserwowane wykorzystanie na wolności

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds before **25.00**. The symbolic-link processing flaw was fixed in **25.00** (July 2025) and later.<sup>[[1]](#references)[[10]](#references)</sup>
* **Ścieżka wpływu**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
This archive contains a symlink entry pointing outside the extraction directory; use a disposable target and verify that the extractor does not follow it. A write-through test also needs a regular-file entry beneath the symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki dotyczące wykrywania

* **Static inspection** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`/`, `C:`) or entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` stays inside `realpath(dest)` (compare path components, not only a raw string prefix). Reject otherwise.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decompress into a disposable directory using an extractor with path/symlink checks (for example, bsdtar's default secure checks or 7-Zip ≥ 25.00), then verify resulting paths stay inside the directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Ograniczanie ryzyka i hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ contain fixes for the cited path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Dodatkowe / historyczne przypadki

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (fixed in v0.16.3).<sup>[[7]](#references)</sup>
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zapobieganie Zip Slip w .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Zaktualizuj teraz narzędzia WinRAR: RomCom i inni wykorzystują lukę zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Publiczne ujawnienie krytycznej luki umożliwiającej dowolne nadpisywanie plików: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug podatny na atak Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Flagi bezpiecznej ekstrakcji bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Zgłoszono exploit Proof-of-Concept dla CVE-2025-11001 w 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
