# Zagrożenia AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp zidentyfikował 10 najważniejszych podatności machine learning, które mogą wpływać na systemy AI. Podatności te mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Zaktualizowaną i szczegółową listę 10 najważniejszych podatności machine learning można znaleźć w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Atakujący dodaje niewielkie, często niewidoczne zmiany do **danych wejściowych**, przez co model podejmuje błędną decyzję.\
*Przykład*: Kilka plamek farby na znaku stop sprawia, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony błędnymi próbkami, ucząc model szkodliwych reguł.\
*Przykład*: Pliki binarne malware zostają oznaczone jako „benign” w korpusie treningowym programu antywirusowego, dzięki czemu podobne malware może później ominąć detekcję.

- **Model Inversion Attack**: Na podstawie analizy odpowiedzi atakujący tworzy **model odwrotny**, który rekonstruuje wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adwersarz sprawdza, czy **konkretny rekord** został użyty podczas treningu, obserwując różnice w poziomie pewności modelu.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (oraz jego IP).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service w celu zbudowania niemal równoważnego modelu lokalnego.

- **AI Supply-Chain Attack**: Naruszenie dowolnego komponentu (danych, bibliotek, pre-trained weights, CI/CD) w **pipeline ML** w celu skażenia modeli downstream.\
*Przykład*: Zatruta dependency w model-hub instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje umieszczona w **pre-trained model** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Model vision backbone z ukrytym triggerem nadal zmienia etykiety po dostosowaniu do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu** na korzyść celów atakującego.\
*Przykład*: Wstrzyknięcie „czystych” wiadomości spam oznaczonych jako ham, aby filtr spam przepuszczał podobne wiadomości w przyszłości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas transmisji**, a nie sam model, wprowadzając w błąd systemy downstream.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „malicious” na „benign”, zanim etap kwarantanny pliku go otrzyma.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany samych **parametrów modelu**, często po uzyskaniu dostępu z prawem zapisu, w celu zmiany jego zachowania.\
*Przykład*: Modyfikacja weights modelu wykrywającego oszustwa w środowisku produkcyjnym, aby transakcje z określonych kart były zawsze zatwierdzane.


## Zagrożenia Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google przedstawia różne zagrożenia związane z systemami AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe albo tuningowe, aby obniżyć dokładność, umieścić backdoory lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Włączanie do procesu objętych prawami autorskimi, wrażliwych lub niezatwierdzonych zbiorów danych tworzy ryzyko prawne, etyczne i związane z wydajnością, ponieważ model uczy się na danych, do których użycia nigdy nie był uprawniony.

- **Model Source Tampering**: Manipulacja kodem modelu, dependencies lub weights przed treningiem albo w jego trakcie, przeprowadzona w ramach supply-chain lub przez insidera, może osadzić ukrytą logikę, która przetrwa nawet retraining.

- **Excessive Data Handling**: Słabe mechanizmy retencji danych i governance powodują, że systemy przechowują lub przetwarzają więcej danych osobowych, niż jest to konieczne, zwiększając ryzyko ujawnienia i naruszenia zgodności.

- **Model Exfiltration**: Atakujący kradną pliki lub weights modelu, powodując utratę własności intelektualnej i umożliwiając tworzenie usług kopiujących oryginał lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Adwersarze modyfikują artefakty modelu lub infrastrukturę serving, przez co uruchomiony model różni się od zweryfikowanej wersji, potencjalnie zmieniając swoje zachowanie.

- **Denial of ML Service**: Zalewanie API lub wysyłanie danych wejściowych typu „sponge” może wyczerpać zasoby obliczeniowe i energię oraz wyłączyć model, przypominając klasyczne ataki DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par wejście-wyjście, atakujący mogą sklonować lub distil model, wspierając produkty imitujące oryginał oraz niestandardowe adversarial attacks.

- **Insecure Integrated Component**: Podatne pluginy, agenty lub usługi upstream pozwalają atakującym wstrzyknąć kod albo eskalować uprawnienia w pipeline AI.

- **Prompt Injection**: Tworzenie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji, które nadpisują intencję systemu, powodując wykonywanie przez model niezamierzonych poleceń.

- **Model Evasion**: Starannie przygotowane dane wejściowe powodują, że model błędnie klasyfikuje, halucynuje lub generuje niedozwolone treści, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje z danych treningowych albo kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wywnioskuje cechy osobowe, które nigdy nie zostały podane, tworząc nowe zagrożenia dla prywatności poprzez inference.

- **Insecure Model Output**: Niesanitizowane odpowiedzi przekazują użytkownikom lub systemom downstream szkodliwy kod, dezinformację albo nieodpowiednie treści.

- **Rogue Actions**: Agenty zintegrowane autonomicznie wykonują niezamierzone operacje w świecie rzeczywistym (zapisy plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Macierz Mitre AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do rozumienia i ograniczania zagrożeń związanych z systemami AI. Kategoryzuje różne techniki i taktyki ataków, których adwersarze mogą używać przeciwko modelom AI, a także sposoby wykorzystywania systemów AI do przeprowadzania różnych ataków.<sup>[[3]](#references)</sup>

## LLMJacking (Kradzież tokenów i odsprzedaż dostępu do hostowanych w chmurze LLM)

Atakujący kradną aktywne tokeny sesji lub cloud API credentials i bez autoryzacji wywołują płatne, hostowane w chmurze LLM. Dostęp jest często odsprzedawany za pośrednictwem reverse proxy, które korzystają z konta ofiary, np. wdrożeń „oai-reverse-proxy”. Skutki obejmują straty finansowe, wykorzystywanie modelu niezgodnie z zasadami oraz przypisanie działań do tenanta ofiary.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Pozyskiwanie tokenów z zainfekowanych maszyn developerskich lub przeglądarek; kradzież sekretów CI/CD; kupowanie leaked cookies.<sup>[[5]](#references)</sup>
- Uruchomienie reverse proxy, które przekazuje żądania do prawdziwego providera, ukrywając klucz upstream i multipleksując wielu klientów.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Nadużywanie bezpośrednich endpointów base model w celu ominięcia enterprise guardrails i rate limits.<sup>[[4]](#references)</sup>

Środki zaradcze:
- Powiązanie tokenów z fingerprintem urządzenia, zakresami IP i client attestation; wymuszanie krótkich czasów wygaśnięcia oraz odświeżanie za pomocą MFA.
- Ograniczenie kluczy do minimum (bez dostępu do tools, read-only tam, gdzie ma to zastosowanie); rotacja po wykryciu anomalii.
- Zakończenie całego ruchu po stronie serwera za policy gateway, który wymusza safety filters, quotas dla poszczególnych tras oraz izolację tenantów.
- Monitorowanie nietypowych wzorców użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) i automatyczne odwoływanie podejrzanych sesji.
- Preferowanie mTLS lub podpisanych JWT wystawianych przez IdP zamiast długo ważnych statycznych kluczy API.

## Hardening self-hosted LLM inference

Uruchamianie lokalnego serwera LLM dla poufnych danych tworzy inną powierzchnię ataku niż hostowane w chmurze API: endpointy inference/debug mogą powodować leak promptów, serving stack zwykle udostępnia reverse proxy, a device nodes GPU zapewniają dostęp do dużych powierzchni `ioctl()`. Jeśli oceniasz lub wdrażasz usługę inference on-prem, przejrzyj co najmniej poniższe punkty.<sup>[[8]](#references)</sup>

### Prompt leakage przez endpointy debug i monitoring

Traktuj inference API jako **wrażliwą usługę multi-user**. Trasy debug lub monitoring mogą ujawniać zawartość promptów, stan slotów, metadane modelu lub informacje o wewnętrznej kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i służy wyłącznie do ich inspekcji oraz zarządzania nimi.<sup>[[8]](#references)</sup>

- Umieść reverse proxy przed inference serverem i **domyślnie odmawiaj dostępu**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metody HTTP i ścieżki wymagane przez klienta/UI.
- W miarę możliwości wyłącz endpointy introspection w samym backendzie, na przykład `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je za pośrednictwem uwierzytelnionego transportu, takiego jak SSH local port forwarding, zamiast publikować je w LAN.

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

Jeśli inference daemon obsługuje nasłuchiwanie na gnieździe UNIX, preferuj to rozwiązanie zamiast TCP i uruchamiaj kontener z **brakiem stosu sieciowego**:<sup>[[8]](#references)</sup>
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
- `--network none` usuwa ekspozycję TCP/IP przychodzącą/wychodzącą i pozwala uniknąć helperów user-mode, których w przeciwnym razie potrzebowałyby kontenery rootless.
- UNIX socket pozwala użyć uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman ograniczają skutki container breakout, ponieważ root kontenera nie jest rootem hosta.
- Montowania modeli tylko do odczytu zmniejszają ryzyko modyfikacji modelu z wnętrza kontenera.

W przypadku wdrożeń persistent te same ograniczenia można wyrazić za pomocą jednostek Podman Quadlet. Jeśli dostęp GPU jest delegowany przez Container Device Interface, specyfikację urządzenia CDI należy zawęzić tak bardzo, jak to możliwe, zamiast udostępniać każdy węzeł akceleratora.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimalizacja węzłów urządzeń GPU

W przypadku inference wspieranego przez GPU pliki `/dev/nvidia*` są wartościowymi lokalnymi powierzchniami ataku, ponieważ udostępniają rozbudowane handlery sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.<sup>[[8]](#references)</sup>

- Nie pozostawiaj `/dev/nvidia*` z zapisem dla wszystkich użytkowników.
- Ogranicz `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko zmapowany UID kontenera mógł je otwierać.
- Zablokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`, na hostach inference bez interfejsu graficznego.
- Ładuj wstępnie tylko wymagane moduły podczas bootowania, zamiast pozwalać runtime'owi na wykonywanie `modprobe` w sposób oportunistyczny podczas uruchamiania inference.

Przykład:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jednym z ważnych punktów przeglądu jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie używa jawnie `cudaMallocManaged()`, nowsze środowiska uruchomieniowe CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, należy traktować je jako powierzchnię cross-tenant data exposure. Jeśli inference backend to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.<sup>[[8]](#references)</sup>

### Ograniczanie procesów inference za pomocą LSM

AppArmor/SELinux/seccomp powinny być używane jako defense in depth wokół procesu inference:<sup>[[8]](#references)</sup>

- Zezwalaj wyłącznie na współdzielone biblioteki, ścieżki modeli, katalog socketów oraz węzły urządzeń GPU, które są rzeczywiście wymagane.
- Jawnie odmawiaj wysokiego ryzyka capabilities, takich jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Utrzymuj katalog modelu w trybie tylko do odczytu, a zapisywalne ścieżki ogranicz wyłącznie do katalogów socketów/cache runtime.
- Monitoruj logi odmów, ponieważ dostarczają użytecznych danych telemetrycznych do detekcji, gdy model server lub payload post-exploitation próbuje wyjść poza oczekiwane behaviour.

Przykładowe reguły AppArmor dla worker'a korzystającego z GPU:
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
## Phantom Squatting: domeny wygenerowane przez halucynacje LLM jako wektor AI Supply-Chain

Phantom squatting jest **odpowiednikiem slopsquatting dla domen/URL**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną **domenę portalu, API, webhooka, billing, SSO, pobierania lub supportu** dla istniejącej marki, a attacker rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ma to znaczenie, ponieważ w wielu workflow wspomaganych przez AI output modelu jest traktowany jako **zaufana zależność**:
- Developerzy wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenty AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub cele webhooków.
- Wygenerowane runbooki lub dokumentacja mogą zawierać fałszywy URL, jak gdyby był autorytatywny.

### Workflow ofensywny

1. **Probe hallucination surface**: zadawaj pytania dotyczące konkretnej marki i realistycznych workflow, takich jak portale `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: rozwiązuj wygenerowane URL, zamieniaj odpowiedzi NXDOMAIN na nadrzędną domenę możliwą do rejestracji i usuwaj duplikaty rodzin promptów. Zbiory promptów powinny pozostać różnorodne, na przykład przez usuwanie niemal identycznych elementów za pomocą **Jaccard similarity**.
3. **Nadaj priorytet przewidywalnym halucynacjom**:
- **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych temperaturach, w tym przy niskiej temperaturze, takiej jak `T=0.1`.
- **Cross-model consensus**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Zarejestruj i uzbroj** nadrzędną domenę, a następnie hostuj phishing, fałszywe pliki APK/ZIP do pobrania, credential harvestery, złośliwe dokumenty lub endpointy API zbierające sekrety/payloady webhooków. **Pure domain-level hallucinations** są najłatwiejsze do monetyzacji, ponieważ attacker kontroluje całą przestrzeń nazw; halucynacje subdomen/ścieżek nadal mogą zostać wykorzystane, gdy znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Wykorzystaj zero-reputation window**: nowo zarejestrowane domeny często nie mają historii na blocklistach, reputacji URL ani dojrzałej telemetrii, więc mogą omijać mechanizmy kontroli, dopóki detekcje ich nie obejmą. Attackers mogą wydłużyć to okno za pomocą odpowiedzi benign dostępnych wyłącznie dla crawlerów, redirect cloaking, bramek CAPTCHA lub opóźnionego stagingu payloadu.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku ofiary będącej człowiekiem fałszywa domena zwykle nadal wymaga kliknięcia i wykonania kolejnej czynności. W przypadku **agentic workflow** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje halucynowany URL, pobiera go, analizuje odpowiedź, a następnie może doprowadzić do wycieku tokenów, wykonać instrukcje, pobrać zależność lub przesłać zatrute dane do CI/CD bez jakiegokolwiek przeglądu przez człowieka.<sup>[[12]](#references)</sup>

### Praktyczne prompty attackera

Wysokowydajne prompty zwykle przypominają normalne zadania enterprise, a nie jawne przynęty phishingowe:<sup>[[12]](#references)</sup>
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Odwrócenie perspektywy obronnej

Traktuj to jako problem proaktywnego monitorowania domen, a nie tylko problem prompt injection:<sup>[[12]](#references)</sup>
- Zbuduj **brand prompt corpus** i okresowo przeprowadzaj probe na LLM, od których zależą Twoi użytkownicy/agenty.
- Przechowuj halucynowane URL i śledź, które z nich są stabilne przy różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją przez attackera. Dodatni AEW oznacza, że defenders mogą dokonać prerejestracji, utworzyć sinkhole lub zablokować domenę przed weaponization.
- Monitoruj przejścia **NXDOMAIN → registered** dla domen nadrzędnych.
- Po rejestracji przeanalizuj registrar, datę utworzenia, nameservery, privacy shielding, zawartość strony, zrzuty ekranu, status parked page oraz podobieństwo assetów marki.
- Dodaj policy gates, aby agenty/developerzy **domyślnie nie ufali domenom wygenerowanym przez LLM**: wymagaj allowlist, weryfikacji własności, kontroli CT/RDAP lub akceptacji człowieka przed pierwszym użyciem.

Zjawisko to jednocześnie pasuje do kilku kategorii ryzyka AI: **AI supply-chain attack**, **insecure model output** oraz **rogue actions**, gdy agenty autonomicznie korzystają z halucynowanego URL.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Ryzyka](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Ryzyka LLM Code Assistant: szkodliwe treści, niewłaściwe użycie i oszustwa](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: skradzione Cloud Credentials wykorzystane w nowym ataku AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Przegląd schematu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Szczegółowa analiza wdrożenia on-premise serwera LLM z niskimi uprawnieniami](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeny wygenerowane przez halucynacje AI jako wektor Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: jak halucynacje AI napędzają nową klasę ataków na Supply Chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
