# Path Traversal podczas rozpakowywania archiwów ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itd.) pozwala, aby każdy wpis zawierał własną **ścieżkę wewnętrzną**. Gdy narzędzie do rozpakowywania bezkrytycznie respektuje tę ścieżkę, spreparowana nazwa pliku zawierająca `..` lub **ścieżkę absolutną** (np. `C:\Windows\System32\`) zostanie zapisana poza katalogiem wybranym przez użytkownika.
Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Skutki obejmują nadpisywanie dowolnych plików, a nawet bezpośrednie uzyskanie **remote code execution (RCE)** poprzez umieszczenie payloadu w lokalizacji **auto-run**, takiej jak folder *Startup* systemu Windows.

## Przyczyna źródłowa

1. Attacker tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Względne sekwencje traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Lub spreparowane **symlinks**, które wskazują poza katalog docelowy (częste w ZIP/TAR na systemach *nix).
2. Victim rozpakowuje archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce (lub podąża za symlinkami), zamiast ją sanityzować albo wymuszać rozpakowywanie wewnątrz wybranego katalogu.
3. Plik zostaje zapisany w lokalizacji kontrolowanej przez attackera, a następnie wykonany/załadowany przy kolejnym uruchomieniu tej ścieżki przez system lub użytkownika.

### .NET `Path.Combine` + `ZipArchive` traversal

Częstym antywzorcem w .NET jest łączenie zamierzonego katalogu docelowego z kontrolowanym przez użytkownika `ZipArchiveEntry.FullName` i rozpakowywanie bez normalizacji ścieżki:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Jeśli `entry.FullName` zaczyna się od `..\\`, następuje traversal; jeśli jest **absolute path**, komponent po lewej stronie zostaje całkowicie odrzucony, co prowadzi do **arbitrary file write** jako identyfikatora ekstrakcji.
- Archive proof-of-concept zapisujący dane do sąsiedniego katalogu `app`, monitorowanego przez skaner uruchamiany zgodnie z harmonogramem:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Upuszczenie tego ZIP-a do monitorowanej skrzynki wejściowej powoduje utworzenie `C:\samples\app\0xdf.txt`, co dowodzi traversal poza `C:\samples\queue\` i umożliwia kolejne prymitywy (np. DLL hijacks).

## Zaawansowane prymitywy wydostawania się z archiwum

Traktuj ekstrakcję jako sekwencję mutacji systemu plików, a nie jako niezależne sprawdzanie nazw plików. Wpis, który jest bezpieczny podczas parsowania, może stać się niebezpieczny po tym, jak wcześniejszy element utworzy lub zastąpi link; ten sam problem występuje, gdy extractor buforuje katalog jako bezpieczny, a następnie zmienia jego typ.<sup>[[11]](#references)</sup>

### Pivoty linków i kolizje wpisów

* **Symlink write-through**: utwórz `pivot -> /tmp`, a następnie wypakuj zwykły element jako `pivot/PWNED.txt`. Jeśli extractor podąży za pierwszym elementem podczas materializowania drugiego, zapis wydostanie się poza docelową ścieżkę bez użycia `..` w drugiej nazwie.
* **Directory-cache/TOCTOU collision**: wygeneruj katalog `d/sub/`, zastąp `d/sub` symlinkiem do `/tmp`, a następnie wygeneruj `d/sub/PWNED.txt`. Atakuje to extractory, które sprawdzają lub buforują katalog jednokrotnie i nie weryfikują go ponownie przed końcowym zapisem.
* **Hardlink read/overwrite**: TAR i RAR mogą reprezentować hardlinki. Hardlink do istniejącego pliku hosta może ujawnić jego zawartość, jeśli późniejszy komponent udostępni wypakowaną nazwę; kolidujący zwykły element może zamiast tego nadpisać powiązany inode. Jest to ograniczone przez reguły dotyczące tego samego systemu plików i uprawnień systemu operacyjnego do tworzenia hardlinków.
* **Pre-existing or cross-archive pivot**: ponów próbę z niepustym miejscem docelowym. Jedno archiwum może umieścić link, a późniejsza ekstrakcja może zapisać przez ten link, nawet jeśli każde archiwum przejdzie bezstanową kontrolę nazwy w nagłówku.<sup>[[11]](#references)</sup>

### Kolizje wynikające z równoważności systemu plików

Porównuj nazwy z użyciem semantyki systemu plików, który będzie miejscem docelowym. Przydatne przypadki różnicowe obejmują `LINK` i `link` w systemach plików niewrażliwych na wielkość liter, zapisy Unicode NFC i NFD, nazwy równoważne pod względem kompatybilności, takie jak `ﬁle` i `file`, duplikaty elementów zmieniające ścieżkę z katalogu na symlink oraz backslashe interpretowane jako separatory wyłącznie w Windows. Testuj również nazwy zawierające ADS w NTFS. Te przypadki mogą sprawić, że validator zobaczy dwie ścieżki, podczas gdy system plików rozwiąże jedną.<sup>[[5]](#references)[[11]](#references)</sup>

Zwięzły corpus powinien zatem testować uporządkowane kombinacje **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mieszane `/` i `\`, nazwy absolutne/zaczynające się od katalogu głównego oraz skompresowane wrappery, takie jak `.tar.gz`. Uruchamiaj go wyłącznie w jednorazowej VM/containerze i monitoruj zarówno miejsce docelowe, jak i zamierzoną zewnętrzną ścieżkę canary.<sup>[[11]](#references)</sup>

## Przykład z rzeczywistego świata – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla Windows oraz jego komponenty Windows RAR/UnRAR nieprawidłowo weryfikowały nazwy plików podczas ekstrakcji. Luka wykorzystywała alternate data streams (ADS) systemu NTFS do ominięcia wybranej ścieżki ekstrakcji i zapisu plików w niezamierzonych lokalizacjach.<sup>[[5]](#references)</sup>
Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
trafiłyby **poza** wybrany katalog wyjściowy i do folderu *Startup* użytkownika. ESET zaobserwował rozpakowywanie tam złośliwych plików LNK i ich wykonywanie podczas logowania użytkownika, co zapewniało persistence oraz ścieżkę do RCE.<sup>[[5]](#references)</sup>

### Tworzenie archiwum PoC (Linux/Mac)

Ponieważ CVE-2025-8088 wykorzystuje traversal path w nazwie ADS, użyj generatora przeznaczonego do tego celu, aby utworzyć RAR, a następnie testuj extraction wyłącznie w izolowanym labie z użyciem podatnej wersji WinRAR.<sup>[[5]](#references)</sup>

### Zaobserwowane wykorzystanie w praktyce

ESET poinformował o kampaniach spear-phishingowych grupy RomCom (Storm-0978/UNC2596), w których dołączano archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania niestandardowych backdoorów i ułatwiania operacji ransomware.<sup>[[5]](#references)</sup>

## Nowsze przypadki (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Błąd**: Wpisy ZIP będące **symbolic links** były dereferencjonowane podczas extraction, co pozwalało atakującym wyjść poza katalog docelowy i nadpisać dowolne ścieżki. Interakcja użytkownika ogranicza się do *otwarcia/rozpakowania* archiwum.<sup>[[1]](#references)</sup>
* **Podatne**: Kompilacje 7-Zip starsze niż **25.00**. Błąd przetwarzania symbolic links został naprawiony w wersji **25.00** (lipiec 2025) i nowszych.<sup>[[1]](#references)[[10]](#references)</sup>
* **Ścieżka wpływu**: Nadpisanie `Start Menu/Programs/Startup` lub lokalizacji uruchamianych przez usługi → code zostanie wykonany przy następnym logowaniu lub restarcie usługi.
* **Szybki fixture do obsługi symlinków (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Archiwum zawiera wpis symlink wskazujący poza katalog extraction; użyj jednorazowego katalogu docelowego i sprawdź, czy extractor za nim nie podąża. Test zapisu wymaga również wpisu zwykłego pliku znajdującego się poniżej symlinka.

### Kolizja symlinków w Go mholt/archiver `Unarchive()` (CVE-2025-3445)
* **Błąd**: `archiver.Unarchive()` może wyodrębnić symlink ZIP, a następnie dokonać jego dereferencji, gdy późniejszy zwykły element ma taką samą nazwę, zmieniając pozornie zapis w obrębie katalogu na zapis poza nim.<sup>[[2]](#references)</sup>
* **Podatne**: `github.com/mholt/archiver` ≤ 3.5.1 (projekt jest obecnie deprecated).<sup>[[2]](#references)</sup>
* **Naprawa**: Przejdź na `mholt/archives` ≥ 0.1.0 albo odrzucaj links i ponownie rozwiązuj każdą ścieżkę docelową bezpośrednio przed jej otwarciem.<sup>[[2]](#references)</sup>
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

### Obejście filtrowanego extraction TAR w CPython (CVE-2026-11940)

Nawet `tarfile.extractall(filter="data")` i `filter="tar"` miały bypasses zależne od kolejności linków. W tym przypadku hardlink wskazywał na symlink zarchiwizowany w głębiej położonej ścieżce; fallback extraction weryfikował względny symlink w tej głębokiej lokalizacji, ale odtwarzał go w płytszej lokalizacji hardlinka, gdzie ten sam względny target wydostawał się poza katalog. Jest to użyteczny test ogólny: doprowadź do niezgodności między katalogiem bazowym używanym podczas walidacji i materializacji albo między końcowym typem elementu.<sup>[[12]](#references)</sup>

## Wskazówki dotyczące wykrywania

* **Inspekcja statyczna** – Wyświetl zarówno nazwy elementów, jak i targety linków. Oznaczaj `../`, `..\\`, ścieżki absolutne/rooted, symlinki, hardlinki, pliki specjalne, zduplikowane nazwy, zmiany typów oraz kolizje równoważne pod względem wielkości liter/Unicode. Zachowaj kolejność elementów podczas przeglądu, ponieważ exploit może zależeć od wcześniejszych elementów.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Upewnij się, że rozwiązany katalog nadrzędny wraz z końcową nazwą pozostaje poniżej rozwiązanej lokalizacji docelowej (porównuj komponenty ścieżki, a nie surowy prefix tekstowy). Wykonuj ponowną kontrolę po każdym wcześniejszym elemencie; jednorazowy test `realpath(join(dest, name))` jest podatny na zastąpienie linku i może nie zadziałać dla jeszcze nieutworzonego elementu końcowego.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extraction w sandboxie** – Rozpakowuj do nowego, jednorazowego katalogu za pomocą extractora z kontrolą ścieżek/symlinków (na przykład domyślnych bezpiecznych kontroli bsdtar lub 7-Zip ≥ 25.00), a następnie sprawdź, czy wynikowe drzewo nie zawiera linków prowadzących na zewnątrz. Izolacja musi uniemożliwiać już uruchomionemu escape'owi dotarcie do ścieżek hosta.<sup>[[1]](#references)[[9]](#references)</sup>
* **Odczyty downstream mają znaczenie** – Zachowany symlink lub hardlink może stać się prymitywem arbitrary-file-read, gdy previewer, CDN, przeglądarka plików lub pipeline pakietu później otworzy albo udostępni rozpakowaną nazwę, nawet jeśli samo rozpakowanie nie utworzyło pliku poza katalogiem.<sup>[[11]](#references)</sup>
* **Monitorowanie endpointów** – Generuj alerty dotyczące nowych plików wykonywalnych zapisywanych w lokalizacjach `Startup`/`Run`/`cron` krótko po otwarciu archiwum przez WinRAR/7-Zip/itp.

## Ograniczanie ryzyka i hardening

1. **Zaktualizuj extractor** – WinRAR 7.13+ i 7-Zip 25.00+ zawierają poprawki dotyczące wymienionych problemów ze ścieżkami/symlinkami.<sup>[[1]](#references)[[5]](#references)</sup>
2. Jeśli to możliwe, rozpakowuj archiwa z opcją „**Do not extract paths**” / „**Ignore paths**”. W przypadku niezaufanych danych odrzucaj symbolic links, hardlinks, urządzenia i FIFO, chyba że aplikacja wyraźnie ich potrzebuje.<sup>[[9]](#references)[[11]](#references)</sup>
3. Rozpakowuj do **nowego, pustego katalogu**. Nie łącz niezaufanych elementów z drzewem zawierającym ścieżki, które atakujący może zastąpić, i nie używaj ponownie katalogu utworzonego przez wcześniejsze archiwum.<sup>[[11]](#references)</sup>
4. W systemach Unix obniż uprawnienia i odizoluj lokalizację docelową w **chroot/mount namespace**; w Windows użyj **AppContainer** lub sandboxa. Samo skanowanie po extraction jest niewystarczające, ponieważ zapis poza katalogiem następuje przed skanowaniem.<sup>[[11]](#references)</sup>
5. W custom code stosuj reguły separatorów, wielkości liter i Unicode właściwe dla docelowego systemu operacyjnego oraz weryfikuj zarówno element, jak i target linku. Rozwiązuj i otwieraj lokalizację docelową bez podążania za linkami; nie oddzielaj kontroli zawierania od późniejszej operacji create/replace. Validator musi używać dokładnie tej samej bazy i semantyki emulacji linków co ścieżka zapisu.<sup>[[11]](#references)[[12]](#references)</sup>

## Dodatkowe / historyczne przypadki

* 2018 – Obszerne advisory *Zip-Slip* firmy Snyk dotyczące wielu bibliotek Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal podczas extraction TAR w slugach (naprawione w v0.16.3).<sup>[[7]](#references)</sup>
* Każda własna logika extraction, która weryfikuje stringi nagłówków, ale nie targety linków i końcową ścieżkę systemu plików używaną dla każdego zapisu.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – traversal ZIP symlinków w 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip w mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zapobieganie Zip Slip w .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – łańcuch HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Zaktualizuj narzędzia WinRAR już teraz: RomCom i inne grupy wykorzystują podatność zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Publiczne ujawnienie krytycznej podatności umożliwiającej dowolne nadpisywanie plików: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug firmy HashiCorp podatny na atak Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bezpieczne flagi extraction bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – zgłoszony exploit Proof-of-Concept dla CVE-2025-11001 w 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zabawa z zip-slipami, tar-slipami, symlinkami, hardlinkami, kolizjami i nie tylko](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – obejście filtra extraction tarfile dla CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
