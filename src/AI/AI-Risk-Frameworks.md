# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP zidentyfikował 10 najważniejszych podatności machine learning, które mogą wpływać na systemy AI. Podatności te mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Aktualną i szczegółową listę 10 najważniejszych podatności machine learning znajdziesz w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Atakujący dodaje niewielkie, często niewidoczne zmiany do **danych wejściowych**, aby model podjął błędną decyzję.\
*Przykład*: Kilka kropek farby na znaku stopu sprawia, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony nieprawidłowymi próbkami, ucząc model szkodliwych reguł.\
*Przykład*: Pliki binarne malware zostają oznaczone jako „benign” w korpusie treningowym programu antywirusowego, dzięki czemu podobne malware może później ominąć zabezpieczenia.

- **Model Inversion Attack**: Badając wyniki, atakujący tworzy **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adwersarz sprawdza, czy **konkretny rekord** został użyty podczas treningu, obserwując różnice w poziomie pewności modelu.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (oraz jego IP).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service w celu zbudowania niemal równoważnego modelu lokalnego.

- **AI Supply-Chain Attack**: Przejęcie dowolnego komponentu (danych, bibliotek, pre-trained weights, CI/CD) w **ML pipeline** w celu zainfekowania modeli downstream.\
*Przykład*: Zatruta dependency z model-hub instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje umieszczona w **pre-trained model** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Vision backbone z ukrytym wyzwalaczem nadal zmienia etykiety po dostosowaniu do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu**, faworyzując cele atakującego.\
*Przykład*: Wstrzyknięcie „czystych” wiadomości spam oznaczonych jako ham, aby filtr antyspamowy przepuszczał podobne przyszłe wiadomości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas transmisji**, a nie sam model, oszukując systemy downstream.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „malicious” na „benign” przed jego dotarciem do etapu kwarantanny pliku.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany **parametrów modelu**, często po uzyskaniu dostępu z prawem zapisu, w celu zmodyfikowania jego działania.\
*Przykład*: Zmiana weights modelu wykrywającego oszustwa działającego na produkcji, aby transakcje z określonych kart były zawsze zatwierdzane.


## Ryzyka Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google przedstawia różne ryzyka związane z systemami AI:

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe albo tuningowe, aby obniżyć dokładność, umieścić backdoory lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Wprowadzanie chronionych prawem autorskim, wrażliwych lub nieautoryzowanych zbiorów danych tworzy ryzyko prawne, etyczne i związane z wydajnością, ponieważ model uczy się na danych, do których użycia nigdy nie był uprawniony.

- **Model Source Tampering**: Manipulowanie kodem modelu, dependencies lub weights przed treningiem albo w jego trakcie, przez osoby z łańcucha dostaw lub insiderów, może wprowadzić ukrytą logikę, która przetrwa nawet retraining.

- **Excessive Data Handling**: Słabe mechanizmy przechowywania danych i zarządzania nimi powodują, że systemy przechowują lub przetwarzają więcej danych osobowych, niż jest to konieczne, zwiększając ryzyko ujawnienia i naruszenia zgodności.

- **Model Exfiltration**: Atakujący kradną pliki/weights modeli, powodując utratę własności intelektualnej i umożliwiając tworzenie usług kopiujących oryginał lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Adwersarze modyfikują artefakty modelu lub infrastrukturę serving, przez co uruchomiony model różni się od zweryfikowanej wersji, potencjalnie zmieniając swoje działanie.

- **Denial of ML Service**: Zalewanie API lub wysyłanie danych wejściowych typu „sponge” może wyczerpać zasoby obliczeniowe/energię i wyłączyć model, przypominając klasyczne ataki DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par wejście-wyjście, atakujący mogą sklonować lub skompresować model, wspierając tworzenie imitujących produktów i niestandardowych adversarial attacks.

- **Insecure Integrated Component**: Podatne pluginy, agenci lub usługi upstream umożliwiają atakującym wstrzyknięcie kodu lub eskalację uprawnień w AI pipeline.

- **Prompt Injection**: Konstruowanie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji, które nadpisują intencje systemu i powodują wykonywanie przez model niezamierzonych poleceń.

- **Model Evasion**: Starannie przygotowane dane wejściowe powodują, że model błędnie klasyfikuje dane, generuje halucynacje lub zwraca niedozwolone treści, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje ze swoich danych treningowych albo kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wywnioskuje cechy osobowe, które nigdy nie zostały podane, tworząc nowe zagrożenia dla prywatności poprzez inference.

- **Insecure Model Output**: Nieoczyszczone odpowiedzi przekazują użytkownikom lub systemom downstream szkodliwy kod, dezinformację albo nieodpowiednie treści.

- **Rogue Actions**: Agenci zintegrowani autonomicznie wykonują niezamierzone operacje w świecie rzeczywistym (zapisy plików, wywołania API, zakupy itd.) bez odpowiedniego nadzoru użytkownika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do zrozumienia i ograniczania ryzyka związanego z systemami AI. Kategoryzuje różne techniki ataków i taktyki, które adwersarze mogą stosować przeciwko modelom AI, a także sposoby wykorzystywania systemów AI do przeprowadzania różnych ataków.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atakujący kradną aktywne tokeny sesji lub cloud API credentials i bez autoryzacji wywołują płatne, hostowane w chmurze LLM. Dostęp jest często odsprzedawany za pośrednictwem reverse proxies, które pośredniczą w dostępie do konta ofiary, np. wdrożeń „oai-reverse-proxy”. Konsekwencje obejmują straty finansowe, wykorzystanie modelu niezgodne z polityką oraz przypisanie działań do tenanta ofiary.

TTPs:
- Pozyskiwanie tokenów z zainfekowanych maszyn deweloperskich lub przeglądarek; kradzież sekretów CI/CD; kupowanie leaked cookies.
- Uruchomienie reverse proxy, które przekazuje żądania do prawdziwego providera, ukrywając upstream key i multipleksując wielu klientów.
- Nadużywanie bezpośrednich endpointów base-model w celu ominięcia enterprise guardrails i limitów rate.

Mitigations:
- Powiązanie tokenów z odciskiem urządzenia, zakresami IP i client attestation; wymuszanie krótkiego czasu wygaśnięcia oraz odświeżanie z MFA.
- Minimalne ograniczenie zakresu kluczy (bez dostępu do narzędzi, read-only, jeśli ma zastosowanie); rotacja po wykryciu anomalii.
- Zakończenie całego ruchu po stronie serwera za policy gateway, który wymusza safety filters, limity per-route i izolację tenantów.
- Monitorowanie nietypowych wzorców użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) oraz automatyczne odbieranie podejrzanych sesji.
- Preferowanie mTLS lub signed JWTs wydawanych przez IdP zamiast długo działających statycznych API keys.

## Wzmacnianie bezpieczeństwa self-hosted LLM inference

Uruchomienie lokalnego serwera LLM dla poufnych danych tworzy inną powierzchnię ataku niż API hostowane w chmurze: endpointy inference/debug mogą powodować leak promptów, stos serving zwykle udostępnia reverse proxy, a węzły urządzeń GPU zapewniają dostęp do dużych powierzchni `ioctl()`. Jeśli oceniasz lub wdrażasz usługę inference on-prem, przeanalizuj co najmniej poniższe punkty.

### Wyciek promptów przez endpointy debug i monitoringu

Traktuj API inference jako **wrażliwą usługę dla wielu użytkowników**. Trasy debug lub monitoringu mogą ujawniać treść promptów, stan slotów, metadane modelu lub informacje o wewnętrznej kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i jest przeznaczony wyłącznie do ich inspekcji/zarządzania.

- Umieść reverse proxy przed serwerem inference i **domyślnie odmawiaj dostępu**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metody HTTP + ścieżki wymagane przez klienta/UI.
- Wyłącz endpointy introspection w samym backendzie, jeśli jest to możliwe, na przykład `llama-server --no-slots`.
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je przez uwierzytelniony transport, taki jak SSH local port forwarding, zamiast publikować je w sieci LAN.

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
### Rootless containers bez sieci i z gniazdami UNIX

Jeśli inference daemon obsługuje nasłuchiwanie na gnieździe UNIX, preferuj je zamiast TCP i uruchamiaj kontener z **brakiem stosu sieciowego**:
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
- `--network none` usuwa ekspozycję TCP/IP przychodzącą/wychodzącą i eliminuje user-mode helpers, których w przeciwnym razie potrzebowałyby kontenery rootless.
- UNIX socket pozwala użyć uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman ograniczają skutki container breakout, ponieważ root kontenera nie jest rootem hosta.
- Montowania modeli tylko do odczytu zmniejszają ryzyko modyfikacji modelu z wnętrza kontenera.

### Minimalizacja węzłów urządzeń GPU

W przypadku inference z użyciem GPU pliki `/dev/nvidia*` są wartościowymi lokalnymi attack surfaces, ponieważ udostępniają rozbudowane handlery sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.

- Nie pozostawiaj `/dev/nvidia*` z prawem zapisu dla wszystkich.
- Ogranicz dostęp do `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko mapowany UID kontenera mógł je otwierać.
- Zablokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`, na hostach inference bez interfejsu graficznego.
- Ładuj wstępnie tylko wymagane moduły podczas bootowania, zamiast pozwalać runtime na oportunistyczne `modprobe` tych modułów przy uruchamianiu inference.

Przykład:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jednym z ważnych punktów przeglądu jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie korzysta bezpośrednio z `cudaMallocManaged()`, nowsze środowiska uruchomieniowe CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, należy traktować je jako powierzchnię cross-tenant data exposure. Jeśli inference backend to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.

### Ograniczanie inference workers za pomocą LSM

AppArmor/SELinux/seccomp powinny być używane jako defense in depth wokół procesu inference:

- Zezwalaj wyłącznie na współdzielone biblioteki, ścieżki modeli, katalog socketów oraz węzły urządzeń GPU, które są rzeczywiście wymagane.
- Jawnie odmawiaj wysokiego ryzyka capabilities, takich jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Utrzymuj katalog modelu w trybie tylko do odczytu, a zapisywalne ścieżki ogranicz wyłącznie do katalogów socketów i cache runtime.
- Monitoruj logi odmów, ponieważ dostarczają użytecznej telemetrii detekcyjnej, gdy model server lub payload post-exploitation próbuje opuścić swoje oczekiwane zachowanie.

Przykładowe reguły AppArmor dla workera obsługującego GPU:
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
## Phantom Squatting: domeny wygenerowane halucynacyjnie przez LLM jako wektor AI supply-chain

Phantom squatting to **odpowiednik slopsquatting dla domen/URL-i**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną **domenę portalu, API, webhooka, billing, SSO, download lub support** należącą do prawdziwej marki, a attacker rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.

Ma to znaczenie, ponieważ w wielu workflow wspomaganych przez AI wynik modelu jest traktowany jako **zaufana zależność**:
- Developerzy wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenty AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub cele webhooków.
- Wygenerowane runbooki lub dokumentacja mogą osadzać fałszywy URL tak, jakby był autorytatywny.

### Offensive workflow

1. **Probe the hallucination surface**: zadawaj pytania związane z konkretną marką, dotyczące realistycznych workflow, takich jak `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub portale `mobile app`.
2. **Normalize candidates**: rozwiązuj wygenerowane URL-e, sprowadzaj odpowiedzi NXDOMAIN do nadrzędnej domeny możliwej do zarejestrowania i usuwaj duplikaty rodzin promptów. Zbiory promptów powinny pozostać zróżnicowane, na przykład poprzez usuwanie prawie identycznych promptów z użyciem **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych temperaturach, w tym przy niskiej temperaturze, takiej jak `T=0.1`.
- **Cross-model consensus**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Register and weaponize** nadrzędną domenę, a następnie hostuj phishing, fałszywe pliki APK/ZIP do pobrania, credential harvestery, złośliwe dokumenty lub endpointy API zbierające sekrety i payloady webhooków. **Pure domain-level hallucinations** są najłatwiejsze do monetyzacji, ponieważ attacker kontroluje całą przestrzeń nazw; halucynacje subdomen/ścieżek również mogą zostać wykorzystane, gdy znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Exploit the zero-reputation window**: nowo zarejestrowane domeny często nie mają historii na blocklistach, reputacji URL ani dojrzałej telemetrii, dzięki czemu mogą omijać mechanizmy kontroli do czasu, aż detekcje nadążą. Attackers mogą wydłużyć to okno za pomocą nieszkodliwych odpowiedzi wysyłanych wyłącznie crawlerom, redirect cloaking, bramek CAPTCHA lub opóźnionego stagingu payloadu.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku ludzkiej ofiary fałszywa domena zwykle nadal wymaga kliknięcia i wykonania kolejnej czynności. W przypadku **agentic workflow** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje halucynacyjny URL, pobiera go, parsuje odpowiedź, a następnie może spowodować leak tokenów, wykonać instrukcje, pobrać zależność lub przesłać zatrute dane do CI/CD bez jakiejkolwiek weryfikacji człowieka.

### Practical attacker prompts

Wysokowydajne prompty zwykle wyglądają jak normalne zadania enterprise, a nie jawne przynęty phishingowe:
- „Jaki jest URL payment sandbox dla integracji `<brand>`?”
- „Jakiego endpointu webhooka powinienem użyć do powiadomień o buildach `<brand>`?”
- „Gdzie znajduje się portal employee benefits / billing / SSO dla `<brand>`?”
- „Podaj bezpośredni download Android APK lub klienta desktopowego dla `<brand>`.”

### Defensive inversion

Traktuj to jako proaktywny problem monitorowania domen, a nie wyłącznie problem prompt injection:
- Zbuduj **brand prompt corpus** i okresowo sonduj LLM-y, na których polegają Twoi użytkownicy/agenci.
- Zapisuj halucynacyjne URL-e i śledź, które z nich pozostają stabilne przy różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją przez attackera. Dodatni AEW oznacza, że defenders mogą zarejestrować domenę, skierować ją do sinkhole lub zablokować przed weaponization.
- Monitoruj przejścia **NXDOMAIN → registered** dla domen nadrzędnych.
- Po rejestracji analizuj registrar, datę utworzenia, nameservery, privacy shielding, zawartość strony, screenshots, status parked-page i podobieństwo assetów marki.
- Dodaj policy gates, aby agenty/developerzy **domyślnie nie ufali domenom wygenerowanym przez LLM**: wymagaj allowlist, walidacji własności, kontroli CT/RDAP lub akceptacji człowieka przed pierwszym użyciem.

Zjawisko to pasuje jednocześnie do kilku kategorii ryzyka AI: **AI supply-chain attack**, **insecure model output** oraz **rogue actions**, gdy agenty autonomicznie wykorzystują halucynacyjny URL.

## References
- [Unit 42 – Ryzyko związane z Code Assistant LLMs: szkodliwe treści, nadużycia i oszustwa](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Przegląd schematu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv – Szczegółowa analiza wdrożenia on-premise, nisko uprzywilejowanego serwera LLM](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: domeny halucynowane przez AI jako wektor software supply chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: jak halucynacje AI napędzają nową klasę supply-chain attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
