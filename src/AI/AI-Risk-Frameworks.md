# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp zidentyfikowało 10 najważniejszych podatności machine learning, które mogą wpływać na systemy AI. Podatności te mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Aby zapoznać się z aktualną i szczegółową listą 10 najważniejszych podatności machine learning, odwiedź projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Atakujący dodaje niewielkie, często niewidoczne zmiany do **danych wejściowych**, aby model podjął błędną decyzję.\
*Przykład*: Kilka plam farby na znaku stop sprawia, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony błędnymi próbkami, ucząc model szkodliwych reguł.\
*Przykład*: Pliki binarne malware zostają oznaczone jako „benign” w zbiorze treningowym programu antywirusowego, dzięki czemu podobne malware może później ominąć detekcję.

- **Model Inversion Attack**: Poprzez sondowanie wyników atakujący tworzy **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adversary sprawdza, czy **konkretny rekord** został użyty podczas treningu, obserwując różnice w poziomie pewności.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego fraud.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (oraz jego IP).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service w celu zbudowania niemal równoważnego modelu lokalnego.

- **AI Supply-Chain Attack**: Przejęcie dowolnego komponentu (danych, bibliotek, pre-trained weights, CI/CD) w **pipeline ML** w celu uszkodzenia modeli zależnych.\
*Przykład*: Zatruta zależność w model-hub instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje umieszczona w **pre-trained model** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Model vision backbone z ukrytym triggerem nadal zmienia etykiety po dostosowaniu do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu**, faworyzując cele atakującego.\
*Przykład*: Wstrzyknięcie „czystych” wiadomości spam oznaczonych jako ham, aby filtr antyspamowy przepuszczał podobne przyszłe wiadomości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas transmisji**, a nie sam model, wprowadzając systemy zależne w błąd.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „malicious” na „benign” przed etapem kwarantanny pliku.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany w **parametrach modelu**, często po uzyskaniu dostępu z prawem zapisu, w celu zmiany jego zachowania.\
*Przykład*: Modyfikacja wag produkcyjnego modelu wykrywającego fraud, aby transakcje z określonych kart były zawsze zatwierdzane.


## Google SAIF Risks

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google przedstawia różne ryzyka związane z systemami AI:

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe/tuningowe, aby obniżyć dokładność, wszczepić backdoory lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Wprowadzanie chronionych prawem autorskim, wrażliwych lub niezatwierdzonych zbiorów danych tworzy ryzyko prawne, etyczne i związane z wydajnością, ponieważ model uczy się na danych, których nigdy nie był uprawniony używać.

- **Model Source Tampering**: Manipulacja kodem modelu, zależnościami lub wagami przez osoby wewnątrz organizacji albo w ramach supply-chain, przed treningiem lub w jego trakcie, może wprowadzić ukrytą logikę, która przetrwa nawet ponowny trening.

- **Excessive Data Handling**: Słabe mechanizmy przechowywania danych i zarządzania nimi powodują, że systemy przechowują lub przetwarzają więcej danych osobowych, niż jest to konieczne, zwiększając ryzyko ujawnienia i naruszenia zgodności.

- **Model Exfiltration**: Atakujący kradną pliki/wagi modelu, powodując utratę własności intelektualnej i umożliwiając tworzenie usług naśladujących oryginał lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Adversaries modyfikują artefakty modelu lub infrastrukturę serving, przez co działający model różni się od zweryfikowanej wersji, potencjalnie zmieniając swoje zachowanie.

- **Denial of ML Service**: Zalewanie API lub wysyłanie wejść typu „sponge” może wyczerpać zasoby obliczeniowe/energię i wyłączyć model, naśladując klasyczne ataki DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par wejście-wyjście, atakujący mogą sklonować lub zdestylować model, napędzając produkty imitujące oryginał oraz dostosowane adversarial attacks.

- **Insecure Integrated Component**: Podatne pluginy, agenty lub usługi upstream umożliwiają atakującym wstrzyknięcie kodu lub eskalację uprawnień w pipeline AI.

- **Prompt Injection**: Konstruowanie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji, które nadpisują intencję systemu i zmuszają model do wykonywania niezamierzonych poleceń.

- **Model Evasion**: Starannie zaprojektowane dane wejściowe powodują, że model błędnie klasyfikuje, halucynuje lub generuje niedozwolone treści, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje ze swoich danych treningowych albo kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wywnioskuje dane osobowe, które nigdy nie zostały podane, tworząc nowe zagrożenia dla prywatności poprzez wnioskowanie.

- **Insecure Model Output**: Niesanityzowane odpowiedzi przekazują użytkownikom lub systemom zależnym szkodliwy kod, dezinformację lub nieodpowiednie treści.

- **Rogue Actions**: Agenty zintegrowane autonomicznie wykonują niezamierzone operacje w świecie rzeczywistym (zapisy plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do rozumienia i ograniczania ryzyk związanych z systemami AI. Kategoryzuje różne techniki i taktyki ataków, które adversaries mogą stosować przeciwko modelom AI, a także sposoby wykorzystywania systemów AI do przeprowadzania różnych ataków.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atakujący kradną aktywne tokeny sesji lub dane uwierzytelniające cloud API i bez autoryzacji wywołują płatne LLM hostowane w chmurze. Dostęp jest często odsprzedawany za pośrednictwem reverse proxy, które wystawia konto ofiary, np. wdrożenia „oai-reverse-proxy”. Konsekwencje obejmują straty finansowe, wykorzystanie modelu poza polityką oraz przypisanie działań do tenanta ofiary.

TTPs:
- Pozyskiwanie tokenów z zainfekowanych maszyn developerskich lub przeglądarek; kradzież sekretów CI/CD; kupowanie wyciekłych cookies.
- Uruchomienie reverse proxy przekazującego żądania do prawdziwego dostawcy, ukrywającego klucz upstream i obsługującego wielu klientów.
- Nadużywanie bezpośrednich endpointów base model w celu ominięcia enterprise guardrails i rate limits.

Mitigations:
- Powiązanie tokenów z fingerprintem urządzenia, zakresami adresów IP i client attestation; wymuszanie krótkiego czasu ważności oraz odświeżania z MFA.
- Ograniczenie kluczy do minimum (bez dostępu do narzędzi, tam gdzie to możliwe tylko do odczytu); rotacja po wykryciu anomalii.
- Przekierowanie całego ruchu po stronie serwera przez policy gateway wymuszający safety filters, limity per-route i izolację tenantów.
- Monitorowanie nietypowych wzorców użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) oraz automatyczne odbieranie podejrzanych sesji.
- Preferowanie mTLS lub podpisanych JWT wystawianych przez IdP zamiast długo ważnych statycznych kluczy API.

## Wzmacnianie bezpieczeństwa self-hosted LLM inference

Uruchomienie lokalnego serwera LLM dla poufnych danych tworzy inną powierzchnię ataku niż API hostowane w chmurze: endpointy inference/debug mogą ujawniać prompty, stack serving zwykle udostępnia reverse proxy, a device nodes GPU zapewniają dostęp do dużych powierzchni `ioctl()`. Jeśli oceniasz lub wdrażasz usługę inference on-prem, przeanalizuj co najmniej poniższe punkty.

### Wyciek promptów przez endpointy debug i monitoringu

Traktuj API inference jako **wrażliwą usługę dla wielu użytkowników**. Trasy debugowania lub monitoringu mogą ujawniać treść promptów, stan slotów, metadane modelu lub informacje o wewnętrznej kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i jest przeznaczony wyłącznie do inspekcji/zarządzania slotami.

- Umieść reverse proxy przed serwerem inference i **domyślnie odrzucaj ruch**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metody HTTP + ścieżki wymagane przez klienta/UI.
- W miarę możliwości wyłącz endpointy introspekcji w samym backendzie, na przykład `llama-server --no-slots`.
- Powiąż reverse proxy z `127.0.0.1` i udostępnij je przez uwierzytelniony transport, taki jak lokalne przekierowanie portu SSH, zamiast publikować je w sieci LAN.

Przykładowa allowlist z nginx:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Kontenery rootless bez sieci i z gniazdami UNIX

Jeśli daemon inferencyjny obsługuje nasłuchiwanie na gnieździe UNIX, preferuj je zamiast TCP i uruchom kontener z **brakiem stosu sieciowego**:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Korzyści:
- `--network none` usuwa ekspozycję TCP/IP przychodzącą/wychodzącą i eliminuje user-mode helpers, których w przeciwnym razie potrzebowałyby rootless containers.
- UNIX socket pozwala użyć uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` oraz rootless Podman ograniczają skutki container breakout, ponieważ root kontenera nie jest rootem hosta.
- Montowania modeli tylko do odczytu zmniejszają ryzyko manipulacji modelem z wnętrza kontenera.

### Minimalizacja węzłów urządzeń GPU

W przypadku inference z użyciem GPU pliki `/dev/nvidia*` są wartościowymi lokalnymi powierzchniami ataku, ponieważ udostępniają duże handlery sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.

- Nie pozostawiaj `/dev/nvidia*` z możliwością zapisu dla wszystkich.
- Ogranicz dostęp do `nvidia`, `nvidiactl` oraz `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko zmapowany UID kontenera mógł je otwierać.
- Zablokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` oraz `nvidia_peermem`, na hostach headless inference.
- Ładuj wstępnie tylko wymagane moduły podczas bootowania, zamiast pozwalać runtime'owi na oportunistyczne `modprobe` tych modułów podczas uruchamiania inference.

Przykład:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jednym z ważnych punktów przeglądu jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie używa jawnie `cudaMallocManaged()`, nowsze CUDA runtimes mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, należy traktować je jako powierzchnię potencjalnego wycieku danych między tenantami. Jeśli inference backend to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.

### Izolacja LSM dla inference workers

AppArmor/SELinux/seccomp powinny być używane jako defense in depth wokół procesu inference:

- Zezwalaj wyłącznie na wymagane shared libraries, ścieżki modeli, katalog socketów i węzły urządzeń GPU.
- Jawnie odmawiaj ryzykownych capabilities, takich jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Utrzymuj katalog modelu w trybie tylko do odczytu, a ścieżki zapisu ogranicz wyłącznie do katalogów socketów runtime/cache.
- Monitoruj logi odmów, ponieważ dostarczają przydatnej telemetrii detekcyjnej, gdy model server lub post-exploitation payload próbuje wyjść poza oczekiwane zachowanie.

Przykładowe reguły AppArmor dla workera korzystającego z GPU:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Phantom Squatting: domeny halucynowane przez LLM jako wektor ataku na łańcuch dostaw AI

Phantom squatting to **odpowiednik slopsquattingu na poziomie domen/URL**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną **domenę portalu, API, webhooka, płatności, SSO, pobierania lub wsparcia** dla istniejącej marki, a atakujący rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.

Ma to znaczenie, ponieważ w wielu workflow wspomaganych przez AI wynik modelu jest traktowany jako **zaufana zależność**:
- Developerzy wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenci AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub cele webhooków.
- Wygenerowane runbooki lub dokumentacja mogą zawierać fałszywy URL tak, jakby był autorytatywny.

### Workflow ofensywny

1. **Zbadaj powierzchnię halucynacji**: zadawaj pytania dotyczące konkretnej marki i realistycznych workflow, takich jak portale `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.
2. **Normalizuj kandydatów**: rozwiązuj wygenerowane URL, sprowadzaj odpowiedzi NXDOMAIN do nadrzędnej domeny możliwej do zarejestrowania i usuwaj duplikaty rodzin promptów. Korpusy promptów powinny pozostać zróżnicowane, na przykład przez usuwanie prawie identycznych promptów przy użyciu **podobieństwa Jaccarda**.
3. **Nadaj priorytet przewidywalnym halucynacjom**:
- **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych wartościach temperatury, w tym przy niskiej temperaturze, takiej jak `T=0.1`.
- **Konsensus między modelami**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Zarejestruj i uzbrój** domenę nadrzędną, a następnie hostuj phishing, fałszywe pliki APK/ZIP do pobrania, harvestery poświadczeń, złośliwe dokumenty lub endpointy API gromadzące sekrety/dane webhooków. **Halucynacje wyłącznie na poziomie domeny** są najłatwiejsze do monetyzacji, ponieważ atakujący kontroluje całą przestrzeń nazw; halucynacje subdomen/ścieżek również mogą zostać wykorzystane, gdy znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Wykorzystaj okno zerowej reputacji**: nowo zarejestrowane domeny często nie mają historii na blocklistach, reputacji URL ani dojrzałej telemetrii, więc mogą omijać mechanizmy kontroli do czasu, aż detekcje nadążą. Atakujący mogą wydłużyć to okno za pomocą odpowiedzi benign tylko dla crawlerów, cloakingu przekierowań, bramek CAPTCHA lub opóźnionego stagingu payloadu.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku ofiary będącej człowiekiem fałszywa domena zwykle nadal wymaga kliknięcia i wykonania kolejnej czynności. W przypadku **agentowego workflow** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje halucynowany URL, pobiera go, analizuje odpowiedź, a następnie może ujawnić tokeny, wykonać instrukcje, pobrać zależność lub przesłać zatrute dane do CI/CD bez jakiejkolwiek weryfikacji przez człowieka.

### Praktyczne prompty atakującego

Najbardziej skuteczne prompty zwykle przypominają normalne zadania enterprise, a nie jawne przynęty phishingowe:
- „Jaki jest URL środowiska payment sandbox dla integracji `<brand>`?”
- „Jakiego endpointu webhooka powinienem użyć do powiadomień o buildach `<brand>`?”
- „Gdzie znajduje się portal employee benefits / billing / SSO dla `<brand>`?”
- „Podaj bezpośredni download aplikacji Android APK lub klienta desktopowego dla `<brand>`.”

### Odwrócenie podejścia defensywnego

Traktuj to jako proaktywny problem monitorowania domen, a nie wyłącznie problem prompt injection:
- Zbuduj **korpus promptów dotyczących marek** i okresowo sonduj LLM, na których polegają Twoi użytkownicy/agenci.
- Zapisuj halucynowane URL i śledź, które z nich są stabilne przy różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją domeny przez atakującego. Dodatni AEW oznacza, że obrońcy mogą zarejestrować domenę, skierować ją do sinkhole lub zablokować przed uzbrojeniem.
- Monitoruj przejścia **NXDOMAIN → zarejestrowana** dla domen nadrzędnych.
- Po rejestracji analizuj rejestratora, datę utworzenia, nameservery, osłonę prywatności, zawartość strony, zrzuty ekranu, status strony parkingowej i podobieństwo zasobów marki.
- Dodaj bramki polityk, aby agenci/developerzy **nie ufali domyślnie domenom wygenerowanym przez LLM**: wymagaj allowlist, weryfikacji własności, kontroli CT/RDAP lub akceptacji człowieka przed pierwszym użyciem.

To zagadnienie pasuje jednocześnie do kilku kategorii ryzyka AI: **atak na łańcuch dostaw AI**, **niebezpieczne wyjście modelu** oraz **nieautoryzowane działania**, gdy agenci autonomicznie korzystają z halucynowanego URL.

## Referencje
- [Unit 42 – Ryzyko związane z LLM używanymi jako code assistant: szkodliwe treści, nadużycia i oszustwa](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Przegląd schematu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Szczegółowa analiza wdrożenia on-premise serwera LLM z ograniczonymi uprawnieniami](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: domeny halucynowane przez AI jako wektor ataku na łańcuch dostaw oprogramowania](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: jak halucynacje AI napędzają nową klasę ataków na łańcuch dostaw](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
