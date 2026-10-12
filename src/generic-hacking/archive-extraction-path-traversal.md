# Przechodzenie przez ścieżki podczas rozpakowywania archiwów („Zip-Slip”)

{{#include ../banners/hacktricks-training.md}}

## Omówienie

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itp.) pozwala, aby każdy wpis zawierał własną **ścieżkę wewnętrzną**. Jeśli narzędzie do rozpakowywania bezrefleksyjnie uwzględnia tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę bezwzględną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.  
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **przechodzenie przez ścieżki podczas rozpakowywania archiwów**.<sup>[[6]](#references)</sup>

Skutki obejmują zarówno nadpisanie dowolnych plików, jak i bezpośrednie uzyskanie **zdalnego wykonania kodu (RCE)** przez umieszczenie payloadu w lokalizacji **uruchamianej automatycznie**, takiej jak folder *Startup* w systemie Windows.

## Przyczyna źródłowa

1. Atakujący tworzy archiwum, w którym nagłówki jednego lub większej liczby plików zawierają:
   * Względne sekwencje przechodzenia po ścieżce (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Ścieżki bezwzględne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Lub spreparowane **symlinki**, które wskazują poza katalog docelowy (częste w ZIP/TAR na *nix*). 
2. Ofiara rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinkami) zamiast ją oczyszczać albo wymuszać rozpakowanie wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez atakującego i wykonany/załadowany przy następnym uruchomieniu systemu lub użytkownika, które wyzwoli tę ścieżkę.

### Przechodzenie po ścieżce za pomocą `.NET` `Path.Combine` + `ZipArchive`

Częstym antywzorcem w .NET jest łączenie zamierzonego katalogu docelowego z kontrolowanym przez **użytkownika** `ZipArchiveEntry.FullName` i rozpakowywanie bez normalizacji ścieżki:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Jeśli `entry.FullName` zaczyna się od `..\\`, dochodzi do path traversal; jeśli jest **ścieżką bezwzględną**, lewy komponent jest całkowicie odrzucany, co umożliwia **zapis dowolnego pliku** jako ścieżki docelowej ekstrakcji.
- Archiwum proof-of-concept do zapisania w sąsiednim katalogu `app`, monitorowanym przez skaner uruchamiany zgodnie z harmonogramem:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Upuszczenie tego pliku ZIP w monitorowanej skrzynce powoduje utworzenie pliku `C:\samples\app\0xdf.txt`, co dowodzi przejścia poza `C:\samples\queue\` i umożliwia wykorzystanie kolejnych prymitywów (np. DLL hijacks).

### Kontrolowany przez użytkownika katalog docelowy ekstrakcji

Przetestuj również **katalog przekazywany do ekstraktora**, a nie tylko nazwy elementów archiwum. Aplikacja może wyznaczać ten katalog na podstawie tytułu, nazwy projektu lub innego pola żądania. Wartość taka jak `../../../../app/module` może przenieść katalog docelowy ekstrakcji poza obszar przesyłania plików, zanim ekstraktor przetworzy jakiekolwiek elementy. W takim przypadku nawet archiwum zawierające wyłącznie bezpieczną nazwę bazową `api.py` może nadpisać kod aplikacji.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

To osobna granica izolacji, inna niż w przypadku klasycznego Zip-Slip. Zweryfikuj zarówno rozwiązaną ścieżkę główną ekstrakcji, jak i ścieżkę każdego rozwiązanego elementu. Do sprawdzenia ścieżki głównej można użyć jej komponentów zamiast prefiksu tekstowego:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Dla bezpiecznego testu prześlij prawidłowe archiwum zawierające jeden plik canary i umieść sekwencje path traversal w każdym polu, które może wskazywać katalog rozpakowywania. Monitoruj zarówno zamierzony katalog, jak i przeznaczoną do testów ścieżkę poza nim. Jeśli katalog docelowy może zawierać importowany moduł, nadpisanie go może doprowadzić do wykonania kodu po ponownym załadowaniu modułów przez procesy robocze; błąd HTTP 500 lub zerwanie połączenia podczas tego ponownego ładowania nie dowodzą, że zapis się nie powiódł.<sup>[[14]](#references)[[15]](#references)</sup> Zobacz również szerszą metodologię [file upload methodology](../pentesting-web/file-upload/).

## Zaawansowane prymitywy przełamywania zabezpieczeń archiwów

Traktuj rozpakowywanie jako sekwencję modyfikacji systemu plików, a nie jako niezależne sprawdzanie nazw plików. Wpis bezpieczny na etapie analizy może stać się niebezpieczny, gdy wcześniejszy element utworzy lub podmieni link; podobny problem występuje, gdy program rozpakowujący buforuje katalog jako bezpieczny, a później zmienia jego typ.<sup>[[11]](#references)</sup>

### Przekierowania przez linki i kolizje wpisów

* **Symlink write-through**: utwórz `pivot -> /tmp`, a następnie rozpakuj zwykły element jako `pivot/PWNED.txt`. Jeśli program rozpakowujący podąży za pierwszym elementem podczas zapisywania drugiego, zapis wyjdzie poza katalog docelowy, mimo że druga nazwa nie zawiera `..`.
* **Kolizja cache katalogu/TOCTOU**: utwórz katalog `d/sub/`, zastąp `d/sub` symlinkiem do `/tmp`, a następnie dodaj `d/sub/PWNED.txt`. Atakuje to programy rozpakowujące, które sprawdzają lub buforują katalog tylko raz i nie weryfikują go ponownie przed końcowym zapisem.
* **Odczyt/nadpisanie przez hardlink**: TAR i RAR mogą zawierać hardlinki. Hardlink do istniejącego pliku na hoście może ujawnić jego zawartość, jeśli późniejszy komponent udostępnia rozpakowaną nazwę; kolidujący zwykły wpis może natomiast nadpisać powiązany inode. Ograniczają to reguły dotyczące tego samego systemu plików oraz uprawnień systemu operacyjnego do tworzenia hardlinków.
* **Istniejące wcześniej lub międzyarchiwalne przekierowanie**: ponów próbę z niepustym katalogiem docelowym. Jedno archiwum może utworzyć link, przez który późniejsze rozpakowywanie zapisze plik, nawet jeśli każde archiwum osobno przejdzie bezstanowe sprawdzanie nazw w nagłówkach.<sup>[[11]](#references)</sup>

### Kolizje wynikające z równoważności w systemie plików

Porównuj nazwy zgodnie z regułami systemu plików, w którym zostaną zapisane. Przydatne przypadki różnicowe obejmują `LINK` i `link` w systemach plików niewrażliwych na wielkość liter, zapisy Unicode w NFC i NFD, nazwy równoważne w ramach zgodności, takie jak `ﬁle` i `file`, duplikaty wpisów zmieniające ścieżkę z katalogu w symlink oraz ukośniki odwrotne interpretowane jako separatory wyłącznie w systemie Windows. Testuj również nazwy zawierające ADS w systemie NTFS. Takie przypadki mogą sprawić, że walidator zobaczy dwie ścieżki, podczas gdy system plików rozpozna jedną.<sup>[[5]](#references)[[11]](#references)</sup>

Zwięzły zestaw testowy powinien zatem sprawdzać uporządkowane kombinacje **katalog → symlink → element podrzędny**, **symlink → kolidujący zwykły plik**, **hardlink → kolidujący zwykły plik**, mieszane `/` i `\`, nazwy bezwzględne/zakorzenione oraz skompresowane opakowania, takie jak `.tar.gz`. Uruchamiaj go wyłącznie w przeznaczonej do testów maszynie wirtualnej lub kontenerze i monitoruj zarówno katalog docelowy, jak i zamierzoną zewnętrzną ścieżkę canary.<sup>[[11]](#references)</sup>

Niejednoznaczności strukturalne specyficzne dla ZIP mogą sprawić, że wstępne skanowanie i właściwy program rozpakowujący zobaczą różne nazwy wpisów lub drzewa. Zobacz [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), zamiast ufać wynikowi tylko jednej biblioteki ZIP.

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla Windows oraz jego komponenty Windows RAR/UnRAR nie weryfikowały nazw plików podczas rozpakowywania. Luka wykorzystywała alternatywne strumienie danych NTFS (ADS), aby ominąć wybraną ścieżkę rozpakowywania i zapisywać pliki w niezamierzonych lokalizacjach.<sup>[[5]](#references)</sup>
Złośliwe archiwum RAR zawierające wpis taki jak:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

trafiłby **poza** wybranym katalogiem wyjściowym, do folderu *Startup* użytkownika. ESET zaobserwował złośliwe pliki LNK rozpakowywane w tym miejscu i uruchamiane przy logowaniu użytkownika, co zapewniało persistence i umożliwiało RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)

Ponieważ CVE-2025-8088 wykorzystuje traversal path w nazwie ADS, użyj specjalnie przygotowanego generatora do utworzenia pliku RAR, a następnie testuj rozpakowywanie wyłącznie w odizolowanym środowisku laboratoryjnym z podatną wersją WinRAR.<sup>[[5]](#references)</sup>

### Zaobserwowane ataki w środowisku naturalnym

ESET zgłosił kampanie spear-phishingowe RomCom (Storm-0978/UNC2596), w których załączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania dostosowanych backdoorów i prowadzenia działań ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2026)

### 7-Zip: traversal przez dowiązanie symboliczne w ZIP → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: Wpisy ZIP będące **dowiązaniami symbolicznymi** były dereferencjonowane podczas rozpakowywania, co pozwalało atakującym wyjść poza katalog docelowy i nadpisywać dowolne ścieżki. Wymagana jest jedynie interakcja użytkownika polegająca na *otwarciu/rozpakowaniu* archiwum.<sup>[[1]](#references)</sup>
* **Podatne wersje**: Wersje 7-Zip starsze niż **25.00**. Błąd w obsłudze dowiązań symbolicznych został naprawiony w wersji **25.00** (lipiec 2025) i nowszych.<sup>[[1]](#references)[[10]](#references)</sup>
* **Ścieżka ataku**: Nadpisanie lokalizacji `Start Menu/Programs/Startup` lub uruchamianych przez usługę → kod uruchamia się przy następnym logowaniu lub restarcie usługi.
* **Szybki przykład obsługi dowiązań symbolicznych (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  To archiwum zawiera wpis symlinku wskazujący poza katalog ekstrakcji; użyj tymczasowego celu i sprawdź, czy ekstraktor za nim nie podąża. Test zapisu przez symlink wymaga również zwykłego wpisu pliku znajdującego się pod symlinkiem.

### Go mholt/archiver `Unarchive()` — kolizja symlinków (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` może rozpakować symlink z ZIP-a, a następnie podążyć za nim, gdy późniejszy zwykły element ma tę samą nazwę, zmieniając pozornie zapis wewnątrz katalogu w zapis poza nim.<sup>[[2]](#references)</sup>
* **Podatne wersje**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie przestarzały).<sup>[[2]](#references)</sup>
* **Naprawa**: Przejdź na `mholt/archives` ≥ 0.1.0 albo odrzucaj linki i ponownie rozwiązuj ścieżkę każdego celu bezpośrednio przed jego otwarciem.<sup>[[2]](#references)</sup>
* **Minimalny generator kolizji** (następnie wywołaj `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Bypass filtrowanego wypakowywania TAR w CPythonie (CVE-2026-11940)

Nawet `tarfile.extractall(filter="data")` i `filter="tar"` były podatne na bypasses związane z kolejnością linków. W tym przypadku hardlink wskazywał na symlink zarchiwizowany pod głębszą ścieżką; mechanizm awaryjnego wypakowywania sprawdzał względny symlink w tej głębszej lokalizacji, ale odtwarzał go w płytszej lokalizacji hardlinka, gdzie ten sam względny cel prowadził poza katalog. To przydatny ogólny test: sprawdź, czy walidacja i materializacja różnią się co do katalogu bazowego lub końcowego typu elementu.<sup>[[12]](#references)</sup>

### Ucieczka celu hardlinka w Node `tar` przez łańcuch symlinków (GHSA-83g3-92jg-28cx)

Pakiet Node.js `tar` w funkcji `tar.extract()` akceptował hardlink, którego cel wyglądał na zawarty w katalogu, ale przez dwa wcześniejsze symlinki wskazywał poza katalog wypakowywania. Atak działa przy domyślnych opcjach wypakowywania: sprawdzanie katalogu nadrzędnego celu obejmowało nazwę hardlinka znajdującą się wewnątrz katalogu, natomiast cel hardlinka był przekazywany do systemu plików bez rozstrzygnięcia całego łańcucha w celu sprawdzenia, czy pozostaje w katalogu. Problem dotyczy wersji `tar` ≤ 7.5.7; poprawkę wprowadzono w wersji 7.5.8.<sup>[[13]](#references)</sup>

Kluczowym elementem testu jest **uporządkowana relacja** między elementami, a nie ich dosłowne nazwy:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Jeśli ekstrakcja się powiedzie, `exfil` pozostanie widoczny w drzewie wynikowym, ale będzie współdzielić inode z wybranym plikiem poza nim; odczytanie go ujawni zawartość tego pliku, a zapisanie do niego zmodyfikuje oryginał. To obejście pokazuje, dlaczego samo sprawdzanie końcowej ścieżki, usuwanie prefiksów ścieżek bezwzględnych lub blokowanie `..` w nagłówku hardlinka nie wystarcza: sprawdzaj cele dowiązań po uwzględnieniu całego wcześniej wyodrębnionego stanu systemu plików.<sup>[[13]](#references)</sup>

## Wskazówki dotyczące wykrywania

* **Analiza statyczna** – Wypisz zarówno nazwy elementów, jak i cele dowiązań. Oznacz `../`, `..\\`, ścieżki bezwzględne/zakorzenione, dowiązania symboliczne, dowiązania twarde, pliki specjalne, zduplikowane nazwy, zmiany typów oraz kolizje nazw równoważnych pod względem wielkości liter lub Unicode. Podczas analizy zachowaj kolejność elementów, ponieważ exploit może zależeć od wcześniejszych elementów.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Kanonizacja** – Upewnij się, że rozstrzygnięty katalog nadrzędny wraz z końcową nazwą bazową pozostaje wewnątrz rozstrzygniętego katalogu docelowego (porównuj komponenty ścieżki, a nie surowy prefiks tekstowy). Sprawdzaj to ponownie po każdym poprzedzającym elemencie; jednorazowy test `realpath(join(dest, name))` jest podatny na podmianę linku i może zawieść, jeśli element końcowy jeszcze nie istnieje.<sup>[[3]](#references)[[11]](#references)</sup>
* **Ekstrakcja w sandboxie** – Rozpakowuj do nowego, tymczasowego katalogu za pomocą ekstraktora sprawdzającego ścieżki i symlinki (na przykład domyślne bezpieczne kontrole bsdtar lub 7-Zip ≥ 25.00), a następnie sprawdź, czy wynikowe drzewo nie zawiera linków prowadzących poza katalog. Izolacja musi uniemożliwić, by już uruchomiony atak przez ucieczkę dosięgnął ścieżek hosta.<sup>[[1]](#references)[[9]](#references)</sup>
* **Późniejsze odczyty też mają znaczenie** – Pozostały symlink lub hardlink może umożliwić odczyt dowolnego pliku, gdy podglądarka, CDN, przeglądarka plików lub pipeline pakietów później otworzy albo udostępni wyodrębnioną nazwę, nawet jeśli sama ekstrakcja nie utworzyła żadnego pliku poza katalogiem.<sup>[[11]](#references)</sup>
* **Monitorowanie endpointów** – Generuj alerty o nowych plikach wykonywalnych zapisanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum w WinRAR/7-Zip itp.

## Mitigacja i utwardzanie

1. **Zaktualizuj ekstraktor** – WinRAR 7.13+, 7-Zip 25.00+ i Node `tar` 7.5.8+ zawierają poprawki dotyczące wskazanych problemów ze ścieżkami, symlinkami i celami linków.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Jeśli to możliwe, rozpakowuj archiwa z opcją „**Do not extract paths**” / „**Ignore paths**”. W przypadku niezaufanych danych wejściowych odrzucaj symlinki, hardlinki, urządzenia i FIFO, chyba że aplikacja wyraźnie ich potrzebuje.<sup>[[9]](#references)[[11]](#references)</sup>
3. Rozpakowuj do **nowego, pustego katalogu**. Nie scalaj niezaufanych elementów z drzewem zawierającym ścieżki, które atakujący może podmienić, i nie używaj ponownie katalogu utworzonego przez wcześniejsze archiwum.<sup>[[11]](#references)</sup>
4. W systemach Unix obniż uprawnienia i odizoluj katalog docelowy w **chroot/przestrzeni nazw montowań**; w Windows użyj **AppContainer** lub sandboxa. Samo skanowanie po ekstrakcji nie wystarczy, ponieważ zapis poza katalogiem następuje przed skanowaniem.<sup>[[11]](#references)</sup>
5. W kodzie niestandardowym stosuj reguły separatorów, wielkości liter i Unicode właściwe dla docelowego systemu operacyjnego oraz waliduj zarówno element archiwum, jak i cel linku. Rozwiązuj ścieżkę i otwieraj katalog docelowy bez podążania za linkami; nie oddzielaj kontroli zawierania od późniejszej operacji tworzenia lub podmiany. Walidator musi używać dokładnie tej samej ścieżki bazowej i semantyki emulacji linków co ścieżka zapisu.<sup>[[11]](#references)[[12]](#references)</sup>

## Dodatkowe przypadki podatne / historyczne

* 2018 – Szeroko zakrojone ostrzeżenie Snyk dotyczące *Zip-Slip*, obejmujące wiele bibliotek Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal podczas ekstrakcji TAR w slugach (naprawiono w v0.16.3).<sup>[[7]](#references)</sup>
* Dowolna niestandardowa logika ekstrakcji, która waliduje ciągi nagłówków, ale nie cele linków ani końcową ścieżkę systemu plików używaną przy każdym zapisie.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal ZIP przez symlink w 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip w mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Jak zapobiegać Zip Slip w .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – łańcuch HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Zaktualizuj narzędzia WinRAR już teraz: RomCom i inni wykorzystują podatność zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Publiczne ujawnienie krytycznej podatności umożliwiającej nadpisanie dowolnego pliku: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug podatny na atak Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flagi bezpiecznej ekstrakcji bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Zgłoszono exploit typu proof-of-concept dla CVE-2025-11001 w 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zabawa z zip-slips, tar-slips, symlinkami, hardlinkami, kolizjami i nie tylko](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – obejście filtra ekstrakcji tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – ucieczka celu hardlinka node-tar przez łańcuch symlinków](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – kontrolowany przez użytkownika katalog główny ekstrakcji SCORM](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Wiele podatności we Frappe LMS prowadzących do zdalnego wykonania kodu](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
