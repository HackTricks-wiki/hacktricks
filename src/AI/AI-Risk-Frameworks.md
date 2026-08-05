# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP zidentyfikował 10 najważniejszych podatności machine learning, które mogą wpływać na systemy AI. Podatności te mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Aktualną i szczegółową listę 10 najważniejszych podatności machine learning znajdziesz w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Atakujący dodaje niewielkie, często niewidoczne zmiany do **danych wejściowych**, aby model podjął błędną decyzję.\
*Przykład*: Kilka plam farby na znaku STOP oszukuje samochód autonomiczny, który „rozpoznaje” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony błędnymi próbkami, co uczy model szkodliwych reguł.\
*Przykład*: Pliki binarne malware są błędnie oznaczane jako „benign” w korpusie treningowym programu antywirusowego, dzięki czemu podobne malware może później prześlizgnąć się niezauważone.

- **Model Inversion Attack**: Badając dane wyjściowe, atakujący tworzy **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adversary sprawdza, czy **konkretny rekord** został użyty podczas treningu, obserwując różnice w poziomie pewności modelu.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego fraud.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (oraz jego IP).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service w celu zbudowania niemal równoważnego modelu lokalnego.

- **AI Supply-Chain Attack**: Przejęcie dowolnego komponentu (danych, bibliotek, pre-trained weights, CI/CD) w **pipeline ML** w celu skażenia modeli zależnych.\
*Przykład*: Zatruta dependency z model-hub instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje umieszczona w **pre-trained model** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Backbone systemu wizyjnego z ukrytym triggerem nadal zmienia etykiety po dostosowaniu go do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu**, faworyzując cel atakującego.\
*Przykład*: Wstrzyknięcie „czystych” wiadomości spam oznaczonych jako ham, aby filtr antyspamowy przepuszczał podobne wiadomości w przyszłości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas przesyłania**, a nie sam model, oszukując systemy zależne.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „malicious” na „benign” przed etapem kwarantanny pliku.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany w **parametrach modelu**, często po uzyskaniu dostępu z prawem zapisu, w celu zmiany jego zachowania.\
*Przykład*: Zmiana wag produkcyjnego modelu wykrywającego fraud, aby transakcje z określonych kart były zawsze zatwierdzane.


## Google SAIF Risks

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google przedstawia różne ryzyka związane z systemami AI:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe/tuningowe, aby obniżyć dokładność, osadzić backdoory lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Włączenie chronionych prawem autorskim, wrażliwych lub niezatwierdzonych zbiorów danych powoduje ryzyka prawne, etyczne i wydajnościowe, ponieważ model uczy się na danych, których nie wolno mu było użyć.

- **Model Source Tampering**: Manipulacja kodem modelu, dependencies lub wagami przed treningiem albo w jego trakcie, dokonana w ramach supply chain lub przez insidera, może osadzić ukrytą logikę, która przetrwa nawet retraining.

- **Excessive Data Handling**: Słabe mechanizmy retencji danych i zarządzania nimi prowadzą do przechowywania lub przetwarzania większej ilości danych osobowych, niż jest to konieczne, zwiększając ryzyko ujawnienia i naruszenia zgodności.

- **Model Exfiltration**: Atakujący kradną pliki/wagi modelu, powodując utratę własności intelektualnej i umożliwiając tworzenie usług kopiujących model lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Adversaries modyfikują artefakty modelu lub infrastrukturę serving, przez co uruchomiony model różni się od zatwierdzonej wersji, co może zmienić jego zachowanie.

- **Denial of ML Service**: Zalewanie API lub wysyłanie danych wejściowych typu „sponge” może wyczerpać zasoby obliczeniowe/energię i wyłączyć model, przypominając klasyczne ataki DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par danych wejściowych i wyjściowych, atakujący mogą sklonować lub zdestylować model, wspierając tworzenie produktów imitujących model i niestandardowych adversarial attacks.

- **Insecure Integrated Component**: Podatne pluginy, agenty lub usługi upstream umożliwiają atakującym wstrzyknięcie kodu lub eskalację uprawnień w pipeline AI.

- **Prompt Injection**: Tworzenie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji, które nadpisują intencję systemu i powodują wykonywanie przez model niezamierzonych poleceń.

- **Model Evasion**: Starannie zaprojektowane dane wejściowe powodują błędną klasyfikację, halucynacje lub generowanie niedozwolonych treści przez model, obniżając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje z danych treningowych albo kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wywnioskowuje cechy osobowe, które nigdy nie zostały podane, powodując nowe zagrożenia dla prywatności wynikające z inferencji.

- **Insecure Model Output**: Niesanitizowane odpowiedzi przekazują użytkownikom lub systemom zależnym szkodliwy kod, dezinformację albo nieodpowiednie treści.

- **Rogue Actions**: Autonomicznie zintegrowane agenty wykonują niezamierzone operacje w świecie rzeczywistym (zapisy plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do zrozumienia i ograniczania ryzyk związanych z systemami AI. Klasyfikuje różne techniki i taktyki ataków, które adversaries mogą stosować przeciwko modelom AI, a także sposoby wykorzystywania systemów AI do przeprowadzania różnych ataków.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atakujący kradną aktywne tokeny sesji lub cloud API credentials i bez autoryzacji wywołują płatne, cloud-hosted LLM. Dostęp jest często odsprzedawany za pośrednictwem reverse proxies, które działają w imieniu konta ofiary, np. wdrożeń „oai-reverse-proxy”. Skutki obejmują straty finansowe, wykorzystywanie modelu niezgodnie z zasadami oraz przypisanie działań do tenanta ofiary.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Pozyskiwanie tokenów z zainfekowanych komputerów developerskich lub przeglądarek; kradzież sekretów CI/CD; kupowanie wyciekłych cookies.
- Uruchomienie reverse proxy, które przekazuje żądania do prawdziwego providera, ukrywając klucz upstream i multipleksując wielu klientów.
- Nadużywanie bezpośrednich endpointów base-model w celu ominięcia enterprise guardrails i rate limits.

Mitigations:
- Powiązanie tokenów z fingerprintem urządzenia, zakresami IP i client attestation; wymuszanie krótkiego czasu wygaśnięcia oraz odświeżanie z użyciem MFA.
- Minimalne ograniczenie zakresu kluczy (bez dostępu do narzędzi, read-only tam, gdzie ma to zastosowanie); rotacja po wykryciu anomalii.
- Zakończenie całego ruchu po stronie serwera za policy gateway, który wymusza filtry bezpieczeństwa, limity per route i izolację tenantów.
- Monitorowanie nietypowych wzorców użycia (nagłe skoki wydatków, nietypowe regiony, UA strings) i automatyczne unieważnianie podejrzanych sesji.
- Preferowanie mTLS lub podpisanych JWT wydawanych przez IdP zamiast długo działających statycznych kluczy API.

## Hardening self-hosted LLM inference

Uruchomienie lokalnego serwera LLM dla poufnych danych tworzy inną powierzchnię ataku niż cloud-hosted APIs: endpointy inference/debug mogą powodować leak promptów, stos serving zwykle udostępnia reverse proxy, a węzły urządzeń GPU zapewniają dostęp do dużej powierzchni `ioctl()`. Podczas oceny lub wdrażania usługi inference on-prem przejrzyj co najmniej poniższe punkty.<sup>[[4]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Traktuj API inference jako **wrażliwą usługę multi-user**. Trasy debug lub monitoring mogą ujawniać treść promptów, stan slotów, metadane modelu lub informacje o wewnętrznej kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i służy wyłącznie do ich inspekcji/zarządzania.<sup>[[4]](#references)[[5]](#references)</sup>

- Umieść reverse proxy przed serwerem inference i **domyślnie odrzucaj żądania**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metod HTTP + ścieżek wymagane przez klienta/UI.
- W miarę możliwości wyłącz endpointy introspekcji w samym backendzie, np. `llama-server --no-slots`.
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je przez uwierzytelniony transport, taki jak SSH local port forwarding, zamiast publikować je w sieci LAN.

Przykładowa allowlist dla nginx:
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
### Kontenery rootless bez sieci i z UNIX sockets

Jeśli daemon inference obsługuje nasłuchiwanie na UNIX socket, preferuj to rozwiązanie zamiast TCP i uruchom kontener z **wyłączonym stosem sieciowym**:
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
- `--network none` usuwa ekspozycję TCP/IP przychodzącą/wychodzącą i pozwala uniknąć helperów w trybie użytkownika, których w przeciwnym razie potrzebowałyby kontenery rootless.
- UNIX socket pozwala używać uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman zmniejszają skutki container breakout, ponieważ root w kontenerze nie jest rootem hosta.
- Montowanie modeli w trybie tylko do odczytu zmniejsza ryzyko manipulacji modelem z wnętrza kontenera.

### Minimalizacja węzłów urządzeń GPU

W przypadku inference wykorzystującego GPU pliki `/dev/nvidia*` są lokalnymi powierzchniami ataku o wysokiej wartości, ponieważ udostępniają rozbudowane handlery sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.<sup>[[4]](#references)</sup>

- Nie pozostawiaj `/dev/nvidia*` z możliwością zapisu dla wszystkich.
- Ogranicz `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko zmapowany UID kontenera mógł je otwierać.
- Zablokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`, na hostach inference bez wyświetlacza.
- Załaduj wstępnie tylko wymagane moduły podczas uruchamiania systemu, zamiast pozwalać runtime'owi na oportunistyczne `modprobe` podczas uruchamiania inference.

Przykład:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jednym z ważnych punktów przeglądu jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie używa jawnie `cudaMallocManaged()`, nowsze środowiska uruchomieniowe CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, należy traktować je jako powierzchnię ekspozycji danych między tenantami. Jeśli inference backend to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.

### Ograniczanie inference workers za pomocą LSM

AppArmor/SELinux/seccomp powinny być używane jako defense in depth wokół procesu inference:<sup>[[4]](#references)</sup>

- Zezwalaj wyłącznie na współdzielone biblioteki, ścieżki modeli, katalog socketów i węzły urządzeń GPU, które są rzeczywiście wymagane.
- Jawnie odmawiaj niebezpiecznych capabilities, takich jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Utrzymuj katalog modelu w trybie tylko do odczytu, a zapisywalne ścieżki ogranicz wyłącznie do katalogów socketów runtime/cache.
- Monitoruj logi odmów, ponieważ dostarczają użytecznej telemetrii detekcyjnej, gdy model server lub payload po post-exploitation próbuje wydostać się poza oczekiwane zachowanie.

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
## Phantom Squatting: halucynowane przez LLM domeny jako wektor ataku na łańcuch dostaw AI

Phantom squatting to **odpowiednik slopsquattingu na poziomie domen/URL-i**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną domenę **portalu, API, webhooka, rozliczeń, SSO, pobierania lub wsparcia** dla rzeczywistej marki, a atakujący rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.<sup>[[8]](#references)[[9]](#references)</sup>

Ma to znaczenie, ponieważ w wielu workflow wspomaganych przez AI wynik modelu jest traktowany jako **zaufana zależność**:
- Developerzy wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenci AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub cele webhooków.
- Wygenerowane runbooki lub dokumentacja mogą zawierać fałszywy URL tak, jakby był autorytatywny.

### Offensive workflow

1. **Probe the hallucination surface**: zadawaj pytania dotyczące konkretnej marki i realistycznych workflow, takich jak portale `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.
2. **Normalize candidates**: rozwiązuj wygenerowane URL-e, sprowadzaj odpowiedzi NXDOMAIN do nadrzędnej domeny możliwej do zarejestrowania i usuwaj duplikaty rodzin promptów. Korpusy promptów powinny pozostać zróżnicowane, na przykład przez usuwanie niemal identycznych promptów z użyciem **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych temperaturach, w tym przy niskiej temperaturze, np. `T=0.1`.
- **Cross-model consensus**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Register and weaponize** nadrzędną domenę, a następnie hostuj phishing, fałszywe pliki APK/ZIP, harvestery poświadczeń, złośliwe dokumenty lub endpointy API gromadzące sekrety i payloady webhooków. **Pure domain-level hallucinations** są najłatwiejsze do monetyzacji, ponieważ atakujący kontroluje całą przestrzeń nazw; halucynacje subdomen/ścieżek również mogą zostać wykorzystane, gdy znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Exploit the zero-reputation window**: nowo zarejestrowane domeny często nie mają historii na blocklistach, reputacji URL ani dojrzałej telemetrii, więc mogą omijać mechanizmy kontroli do czasu aktualizacji detekcji. Atakujący mogą wydłużyć to okno za pomocą odpowiedzi benign kierowanych wyłącznie do crawlerów, redirect cloaking, bramek CAPTCHA lub opóźnionego stagingu payloadu.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku ofiary będącej człowiekiem fałszywa domena zwykle nadal wymaga kliknięcia i wykonania kolejnej czynności. W przypadku **agentic workflow** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje halucynowany URL, pobiera go, analizuje odpowiedź, a następnie może ujawnić tokeny, wykonać instrukcje, pobrać zależność lub wprowadzić zatrute dane do CI/CD bez jakiejkolwiek weryfikacji przez człowieka.<sup>[[8]](#references)</sup>

### Practical attacker prompts

Wysokowydajne prompty zwykle przypominają normalne zadania enterprise, a nie jawne przynęty phishingowe:
- „Jaki jest URL payment sandbox dla integracji `<brand>`?”
- „Jakiego endpointu webhooka powinienem użyć dla powiadomień o buildach `<brand>`?”
- „Gdzie znajduje się portal employee benefits / billing / SSO dla `<brand>`?”
- „Podaj bezpośredni download Android APK lub klienta desktopowego dla `<brand>`.”

### Defensive inversion

Traktuj to jako problem proaktywnego monitorowania domen, a nie wyłącznie jako problem prompt injection:
- Zbuduj **brand prompt corpus** i okresowo odpytuj LLM-y, na których polegają Twoi użytkownicy/agenci.
- Zapisuj halucynowane URL-e i śledź, które z nich pozostają stabilne w różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją przez atakującego. Dodatnie AEW oznacza, że obrońcy mogą dokonać prerejestracji, skierować domenę do sinkhole lub zablokować ją przed weaponization.
- Monitoruj przejścia **NXDOMAIN → registered** dla domen nadrzędnych.
- Po rejestracji analizuj registrar, datę utworzenia, nameservery, privacy shielding, zawartość strony, screenshoty, status parked page i podobieństwo assetów marki.
- Dodaj policy gates, aby agenci/developerzy **domyślnie nie ufali domenom wygenerowanym przez LLM**: wymagaj allowlist, walidacji własności, sprawdzeń CT/RDAP lub akceptacji człowieka przed pierwszym użyciem.

Zjawisko to pasuje jednocześnie do kilku kategorii ryzyka AI: **AI supply-chain attack**, **insecure model output** oraz **rogue actions**, gdy agenci autonomicznie wykorzystują halucynowany URL.

## References
- [1] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
