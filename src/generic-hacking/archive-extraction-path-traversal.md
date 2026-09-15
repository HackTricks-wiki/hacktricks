# Path Traversal podczas rozpakowywania archiwów ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Omówienie

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala każdemu wpisowi zawierać własną **ścieżkę wewnętrzną**. Gdy narzędzie do rozpakowywania bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę absolutną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **path traversal podczas rozpakowywania archiwów**.<sup>[[6]](#references)</sup>

Skutki obejmują nadpisywanie dowolnych plików, a nawet bezpośrednie uzyskanie **zdalnego wykonania kodu (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder *Startup* w systemie Windows.

## Przyczyna

1. Attacker tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinks**, które wskazują poza katalog docelowy (częste w ZIP/TAR na systemach *nix).
2. Victim rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinks), zamiast ją sanityzować albo wymuszać rozpakowywanie w obrębie wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez attackera i wykonany/załadowany przy następnym wywołaniu tej ścieżki przez system lub użytkownika.

### Traversal z użyciem `.NET` `Path.Combine` + `ZipArchive`

Częstym anti-patternem w .NET jest łączenie docelowego miejsca z kontrolowaną przez użytkownika właściwością `ZipArchiveEntry.FullName` i rozpakowywanie bez normalizacji ścieżki:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, dochodzi do traversal; jeśli jest **ścieżką absolutną**, komponent po lewej stronie jest całkowicie odrzucany, co skutkuje **dowolnym zapisem pliku** jako tożsamością ekstrakcji.
- Archive proof-of-concept do zapisu w sąsiednim katalogu `app`, monitorowanym przez zaplanowany skaner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego pliku ZIP w monitorowanej skrzynce odbiorczej skutkuje utworzeniem `C:\samples\app\0xdf.txt`, co dowodzi traversal poza `C:\samples\queue\` i umożliwia kolejne primitive (np. DLL hijacks).

## Zaawansowane primitive wydostawania się z archiwum

Traktuj ekstrakcję jako sekwencję mutacji systemu plików, a nie jako niezależne sprawdzanie nazw plików. Wpis, który jest bezpieczny podczas parsowania, może stać się niebezpieczny po tym, jak wcześniejszy element utworzy lub zastąpi link; ten sam problem występuje, gdy extractor buforuje katalog jako bezpieczny, a następnie zmienia jego typ.<sup>[[11]](#references)</sup>

### Pivoty linków i kolizje wpisów

* **Symlink write-through**: utwórz `pivot -> /tmp`, a następnie wyodrębnij zwykły element jako `pivot/PWNED.txt`. Jeśli extractor podąży za pierwszym elementem podczas materializowania drugiego, zapis wydostanie się poza dozwolony katalog bez użycia `..` w drugiej nazwie.
* **Kolizja directory-cache/TOCTOU**: dodaj katalog `d/sub/`, zastąp `d/sub` symlinkiem do `/tmp`, a następnie dodaj `d/sub/PWNED.txt`. Celuje to w extractory, które walidują lub buforują katalog raz i nie sprawdzają go ponownie przed końcowym zapisem.
* **Hardlink read/overwrite**: TAR i RAR mogą reprezentować hardlinki. Hardlink do istniejącego pliku hosta może ujawnić jego zawartość, jeśli późniejszy komponent udostępni wyodrębnioną nazwę; kolidujący zwykły wpis może natomiast nadpisać powiązany inode. Jest to ograniczone przez zasady dotyczące tego samego systemu plików i uprawnień do hardlinków w systemie operacyjnym.
* **Pre-existing or cross-archive pivot**: ponów próbę z niepustym katalogiem docelowym. Jedno archiwum może umieścić link, a późniejsza ekstrakcja może zapisać za jego pośrednictwem, nawet jeśli każde archiwum przejdzie bezstanową kontrolę nazwy w nagłówku.<sup>[[11]](#references)</sup>

### Kolizje równoważności systemu plików

Porównuj nazwy zgodnie z semantyką systemu plików, który będzie je odbierał. Przydatne przypadki różnicowe obejmują `LINK` i `link` w systemach plików niewrażliwych na wielkość liter, zapisy Unicode NFC i NFD, nazwy równoważne pod względem zgodności, takie jak `ﬁle` i `file`, zduplikowane elementy zmieniające ścieżkę z katalogu w symlink oraz backslashe interpretowane jako separatory tylko w systemie Windows. Testuj także nazwy zawierające ADS w systemie plików NTFS. Przypadki te mogą sprawić, że validator zobaczy dwie ścieżki, podczas gdy system plików rozwiąże jedną.<sup>[[5]](#references)[[11]](#references)</sup>

Kompaktowy corpus powinien zatem testować uporządkowane kombinacje **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mieszane `/` i `\`, nazwy absolutne/rooted oraz skompresowane wrappery, takie jak `.tar.gz`. Uruchamiaj go wyłącznie na disposable VM/container i obserwuj zarówno katalog docelowy, jak i zamierzoną zewnętrzną ścieżkę canary.<sup>[[11]](#references)</sup>

Specyficzna dla ZIP strukturalna niejednoznaczność może sprawić, że pre-scan i właściwy extractor zobaczą różne nazwy wpisów lub drzewa. Zobacz [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), zamiast ufać wynikowi tylko jednej biblioteki ZIP.

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla systemu Windows oraz jego komponenty Windows RAR/UnRAR nieprawidłowo sprawdzały nazwy plików podczas ekstrakcji. Luka wykorzystywała alternate data streams (ADS) systemu NTFS do ominięcia wybranej ścieżki ekstrakcji i zapisywania plików w niezamierzonych lokalizacjach.<sup>[[5]](#references)</sup>
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
znalazłby się **poza** wybranym katalogiem wyjściowym i wewnątrz folderu *Startup* użytkownika. ESET zaobserwował rozpakowywanie tam złośliwych plików LNK i ich wykonywanie podczas logowania użytkownika, co zapewniało persistence oraz ścieżkę do RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)

Ponieważ CVE-2025-8088 używa ścieżki traversal w nazwie ADS, należy użyć generatora przeznaczonego do tego celu, aby utworzyć plik RAR, a następnie testować rozpakowywanie wyłącznie w izolowanym labie z podatną wersją WinRAR.<sup>[[5]](#references)</sup>

### Zaobserwowane wykorzystanie na wolności

ESET poinformował o kampaniach spear-phishingowych grupy RomCom (Storm-0978/UNC2596), w których dołączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania dostosowanych backdoorów i ułatwiania operacji ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2026)

### Traversal symlinków ZIP w 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Wpisy ZIP będące **symlinkami** były dereferencjonowane podczas rozpakowywania, co pozwalało atakującym wyjść poza katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika ograniczała się do *otwarcia/rozpakowania* archiwum.<sup>[[1]](#references)</sup>
* **Affected**: Wersje 7-Zip starsze niż **25.00**. Błąd przetwarzania symlinków naprawiono w wersji **25.00** (lipiec 2025) oraz późniejszych.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługę → kod zostanie wykonany przy następnym logowaniu lub restarcie usługi.
* **Szybki fixture do obsługi symlinków (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
To archiwum zawiera wpis symlinka wskazującego poza katalog rozpakowywania; należy użyć jednorazowego celu i sprawdzić, czy extractor go nie podąża. Test zapisu przez symlink wymaga również wpisu zwykłego pliku znajdującego się pod symlinkiem.

### Kolizja symlinków w `Unarchive()` biblioteki Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` może rozpakować symlink ZIP, a następnie dokonać jego dereferencji, gdy późniejszy zwykły element ma taką samą nazwę, zamieniając pozornie zapis wewnątrz katalogu głównego na zapis poza nim.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Przejdź na `mholt/archives` ≥ 0.1.0 albo odrzucaj linki i ponownie rozwiązuj każdą lokalizację docelową bezpośrednio przed jej otwarciem.<sup>[[2]](#references)</sup>
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

### Obejście filtrowanego rozpakowywania TAR w CPython (CVE-2026-11940)

Nawet `tarfile.extractall(filter="data")` i `filter="tar"` miały przypadki obejścia związane z kolejnością linków. W tym przypadku hardlink wskazywał symlink zarchiwizowany w głębiej położonej ścieżce; awaryjne rozpakowywanie zweryfikowało względny symlink w tej głębokiej lokalizacji, ale odtworzyło go w płytszej lokalizacji hardlinka, gdzie ten sam względny cel wydostał się poza katalog. Jest to przydatny ogólny test: należy doprowadzić do niezgodności między walidacją a materializacją w zakresie katalogu bazowego lub końcowego typu elementu.<sup>[[12]](#references)</sup>

### Ucieczka celu hardlinka w Node `tar` przez łańcuch symlinków (GHSA-83g3-92jg-28cx)

Pakiet Node.js `tar` akceptował hardlink, którego cel wyglądał leksykalnie na zawarty w katalogu, ale rozwiązywał się poza rootem rozpakowywania przez dwa wcześniejsze symlinki. Atak działa przy użyciu domyślnych opcji rozpakowywania: kontrole katalogu nadrzędnego celu obejmowały nazwę hardlinka znajdującą się wewnątrz roota, natomiast cel hardlinka był przekazywany do systemu plików bez rozwiązywania całego łańcucha w celu sprawdzenia zawierania. Podatne są wersje `tar` ≤ 7.5.7; wersja 7.5.8 naprawia ten problem.<sup>[[13]](#references)</sup>

Najważniejszym elementem fixture jest **uporządkowana relacja** między elementami, a nie te dosłowne nazwy:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Jeśli ekstrakcja powiedzie się, `exfil` pozostaje widoczny w drzewie wynikowym, ale współdzieli inode z wybranym plikiem znajdującym się poza nim; odczyt tego pliku powoduje leak jego zawartości, a zapis modyfikuje oryginał. Ten bypass pokazuje, dlaczego samo sprawdzanie końcowej ścieżki, usuwanie prefiksów absolutnych lub blokowanie `..` w nagłówku hardlinku jest niewystarczające: należy walidować cele linków po zastosowaniu całego wcześniej wyekstrahowanego stanu systemu plików.<sup>[[13]](#references)</sup>

## Wskazówki dotyczące wykrywania

* **Inspekcja statyczna** – Wyświetl zarówno nazwy elementów, jak i cele linków. Oznacz `../`, `..\\`, ścieżki absolutne/zrootowane, symlinki, hardlinki, pliki specjalne, zduplikowane nazwy, zmiany typów oraz kolizje nazw równoważnych pod względem wielkości liter/Unicode. Podczas przeglądu zachowaj kolejność elementów, ponieważ exploit może zależeć od wcześniejszych elementów.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # uporządkowane elementy TAR, typy i cele linków
7z l -slt suspect.7z          # metadane techniczne, jedno pole w wierszu
zipinfo -v suspect.zip        # metadane centralnego katalogu ZIP i offsety
```

* **Kanonikalizacja** – Upewnij się, że rozwiązany katalog nadrzędny wraz z końcową nazwą pozostaje pod rozwiązanym katalogiem docelowym (porównuj komponenty ścieżki, a nie surowy prefiks tekstowy). Sprawdzaj ponownie po każdym poprzednim elemencie; jednorazowy test `realpath(join(dest, name))` jest podatny na podmianę linku i może nie zadziałać dla jeszcze nieutworzonego elementu końcowego.<sup>[[3]](#references)[[11]](#references)</sup>
* **Ekstrakcja w sandboxie** – Rozpakowuj do świeżego, tymczasowego katalogu przy użyciu extractora z kontrolą ścieżek/symlinków (na przykład domyślne bezpieczne kontrole bsdtar lub 7-Zip ≥ 25.00), a następnie sprawdź, czy wynikowe drzewo nie zawiera linków wychodzących poza nie. Izolacja musi uniemożliwiać dotarcie już wywołanego escape do ścieżek hosta.<sup>[[1]](#references)[[9]](#references)</sup>
* **Odczyty downstream mają znaczenie** – Zachowany symlink lub hardlink może stać się prymitywem arbitrary-file-read, gdy previewer, CDN, przeglądarka plików lub pipeline pakietu później otworzy albo udostępni wyekstrahowaną nazwę, nawet jeśli sama ekstrakcja nie utworzyła żadnego pliku poza katalogiem docelowym.<sup>[[11]](#references)</sup>
* **Monitorowanie endpointów** – Generuj alerty dotyczące nowych plików wykonywalnych zapisywanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum przez WinRAR/7-Zip/etc.

## Łagodzenie skutków i hardening

1. **Zaktualizuj extractor** – WinRAR 7.13+, 7-Zip 25.00+ i Node `tar` 7.5.8+ zawierają poprawki dotyczące wskazanych problemów ze ścieżkami/symlinkami/celami linków.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Jeśli to możliwe, ekstraktuj archiwa z opcją “**Do not extract paths**” / “**Ignore paths**”. W przypadku niezaufanych danych odrzucaj symlinki, hardlinki, urządzenia i FIFO, chyba że aplikacja wyraźnie ich potrzebuje.<sup>[[9]](#references)[[11]](#references)</sup>
3. Ekstraktuj do **nowego, pustego katalogu**. Nie scalaj niezaufanych elementów z drzewem zawierającym ścieżki, które może podmienić attacker, i nie używaj ponownie katalogu utworzonego przez wcześniejsze archiwum.<sup>[[11]](#references)</sup>
4. W systemie Unix obniż uprawnienia i odizoluj katalog docelowy w **chroot/mount namespace**; w systemie Windows użyj **AppContainer** lub sandboxa. Sam skan po ekstrakcji jest niewystarczający, ponieważ zapis poza katalogiem docelowym następuje przed skanem.<sup>[[11]](#references)</sup>
5. W kodzie niestandardowym stosuj reguły separatorów, wielkości liter i Unicode właściwe dla docelowego systemu operacyjnego oraz waliduj zarówno element, jak i cel linku. Rozwiązuj i otwieraj katalog docelowy bez podążania za linkami; nie oddzielaj kontroli zawierania od późniejszej operacji tworzenia/podmiany. Validator musi używać dokładnie tej samej podstawy i semantyki emulacji linków co ścieżka zapisu.<sup>[[11]](#references)[[12]](#references)</sup>

## Dodatkowe / historyczne przypadki podatności

* 2018 – Obszerne advisory *Zip-Slip* firmy Snyk dotyczące wielu bibliotek Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal podczas ekstrakcji TAR w slugach (naprawione w v0.16.3).<sup>[[7]](#references)</sup>
* Każda niestandardowa logika ekstrakcji, która waliduje ciągi z nagłówków, ale nie cele linków i końcową ścieżkę systemu plików używaną dla każdego zapisu.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal symlinków ZIP w 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip w mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zapobieganie Zip Slip w .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → łańcuch DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Zaktualizuj narzędzia WinRAR już teraz: RomCom i inni wykorzystują podatność zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Publiczne ujawnienie krytycznej podatności umożliwiającej dowolne nadpisanie pliku: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug podatny na atak Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flagi bezpiecznej ekstrakcji bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Zgłoszony exploit Proof-of-Concept dla CVE-2025-11001 w 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zabawa z zip-slip, tar-slip, symlinkami, hardlinkami, kolizjami i nie tylko](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Obejście filtra ekstrakcji tarfile dla CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – ucieczka celu hardlinku node-tar przez łańcuch symlinków](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
