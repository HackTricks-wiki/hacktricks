# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP, itd.) pozwala, by każdy wpis zawierał własną **internal path**. Gdy narzędzie do rozpakowywania bezrefleksyjnie honoruje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **absolute path** (np. `C:\Windows\System32\`) zostanie zapisana poza wybranym przez użytkownika katalogiem.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.

Konsekwencje obejmują nadpisanie dowolnych plików lub bezpośrednie uzyskanie **remote code execution (RCE)** poprzez upuszczenie ładunku w lokalizacji **auto-run**, takiej jak folder Windows *Startup*.

## Przyczyna

1. Atakujący tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Ofiara rozpakowuje archiwum przy użyciu podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za **symlinks**) zamiast jej weryfikować i wymusić rozpakowanie wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez atakującego i zostaje uruchomiony/załadowany przy następnym wywołaniu tej ścieżki przez system lub użytkownika.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) failed to validate filenames during extraction.
A malicious RAR archive containing an entry such as:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
zostałby **poza** wybranym katalogiem wyjściowym i wewnątrz folderu *Startup* użytkownika. Po zalogowaniu Windows automatycznie uruchamia wszystko, co się tam znajduje, zapewniając *persistent* RCE.

### Tworzenie archiwum PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opcje użyte:
* `-ep`  – przechowuj ścieżki plików dokładnie tak, jak podane (nie obcinaj wiodącego `./`).

Dostarcz `evil.rar` ofierze i poproś ją o rozpakowanie go za pomocą podatnej wersji WinRAR.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Wypisz wpisy archiwum i oznacz każde nazwy zawierające `../`, `..\\`, *ścieżki absolutne* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem rozpakowywania.
* **Canonicalisation** – Upewnij się, że `realpath(join(dest, name))` nadal zaczyna się od `dest`. W przeciwnym razie odrzuć.
* **Sandbox extraction** – Rozpakowuj do tymczasowego katalogu przy użyciu *bezpiecznego* extractora (np. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i zweryfikuj, że powstałe ścieżki pozostają wewnątrz katalogu.
* **Endpoint monitoring** – Generuj alerty dla nowych plików wykonywalnych zapisanych w lokalizacjach `Startup`/`Run`/`cron` wkrótce po otwarciu archiwum przez WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – Zaktualizuj program do rozpakowywania; WinRAR 7.13+ i 7-Zip 25.00+ wdrażają sanitizację ścieżek/dowiązań symbolicznych. Oba narzędzia nadal nie mają automatycznej aktualizacji.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
