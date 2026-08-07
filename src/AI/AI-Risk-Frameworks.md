# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## 10 najważniejszych podatności Machine Learning według OWASP

Owasp zidentyfikowało 10 najważniejszych podatności Machine Learning, które mogą wpływać na systemy AI. Podatności te mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Zaktualizowaną i szczegółową listę 10 najważniejszych podatności Machine Learning można znaleźć w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Atakujący dodaje niewielkie, często niewidoczne zmiany do **danych wejściowych**, aby model podjął błędną decyzję.\
*Przykład*: Kilka plam farby na znaku stop sprawia, że autonomiczny samochód „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony błędnymi próbkami, ucząc model szkodliwych reguł.\
*Przykład*: Pliki binarne malware zostają oznaczone jako „benign” w korpusie treningowym programu antywirusowego, dzięki czemu podobne malware może później ominąć zabezpieczenia.

- **Model Inversion Attack**: Badając dane wyjściowe, atakujący tworzy **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adwersarz sprawdza, czy **konkretny rekord** został użyty podczas treningu, obserwując różnice w poziomie pewności.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (oraz jego IP).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service w celu zbudowania niemal równoważnego modelu lokalnego.

- **AI Supply-Chain Attack**: Przejęcie dowolnego komponentu (danych, bibliotek, pre-trained weights, CI/CD) w **pipeline ML** w celu uszkodzenia modeli zależnych.\
*Przykład*: Zatruta zależność z model-hub instaluje backdoored model analizy sentymentu w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje umieszczona w **pre-trained model** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Backbone systemu wizyjnego z ukrytym wyzwalaczem nadal odwraca etykiety po dostosowaniu go do obrazowania medycznego.

- **Model Skewing**: Subtelnie tendencyjne lub błędnie oznaczone dane **przesuwają wyniki modelu**, faworyzując cele atakującego.\
*Przykład*: Wstrzykiwanie „czystych” wiadomości spamowych oznaczonych jako ham, aby filtr antyspamowy przepuszczał podobne wiadomości w przyszłości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas transmisji**, nie zmieniając samego modelu, i oszukuje systemy zależne.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „malicious” na „benign”, zanim etap kwarantanny pliku go zobaczy.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany w **parametrach modelu**, często po uzyskaniu dostępu z prawem zapisu, w celu zmiany jego zachowania.\
*Przykład*: Modyfikacja wag modelu wykrywającego oszustwa w środowisku produkcyjnym, aby transakcje z określonych kart były zawsze zatwierdzane.


## Ryzyka Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/) firmy Google przedstawia różne ryzyka związane z systemami AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe albo tuningowe, aby obniżyć dokładność, umieścić backdoory lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Wczytywanie chronionych prawem autorskim, wrażliwych lub niezatwierdzonych zbiorów danych tworzy ryzyko prawne, etyczne i związane z wydajnością, ponieważ model uczy się na danych, których nigdy nie zezwolono mu używać.

- **Model Source Tampering**: Manipulacja kodem modelu, zależnościami lub wagami przez osoby z łańcucha dostaw albo pracowników, przed treningiem lub w jego trakcie, może umieścić ukrytą logikę, która przetrwa nawet retraining.

- **Excessive Data Handling**: Słabe mechanizmy przechowywania danych i zarządzania nimi powodują, że systemy przechowują lub przetwarzają więcej danych osobowych, niż jest to konieczne, zwiększając ryzyko ujawnienia i naruszenia zgodności.

- **Model Exfiltration**: Atakujący kradną pliki i wagi modelu, powodując utratę własności intelektualnej oraz umożliwiając tworzenie usług naśladujących lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Adwersarze modyfikują artefakty modelu lub infrastrukturę udostępniającą model, przez co uruchomiony model różni się od zweryfikowanej wersji, potencjalnie zmieniając swoje zachowanie.

- **Denial of ML Service**: Zalewanie API lub wysyłanie danych wejściowych typu „sponge” może wyczerpać zasoby obliczeniowe i energię oraz wyłączyć model, przypominając klasyczne ataki DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par danych wejściowych i wyjściowych, atakujący mogą sklonować lub poddać model distillation, wspierając tworzenie produktów naśladujących i niestandardowych adversarial attacks.

- **Insecure Integrated Component**: Podatne pluginy, agenty lub usługi upstream umożliwiają atakującym wstrzyknięcie kodu lub eskalację uprawnień w pipeline AI.

- **Prompt Injection**: Tworzenie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji nadpisujących intencję systemu i zmuszenia modelu do wykonywania niezamierzonych poleceń.

- **Model Evasion**: Starannie przygotowane dane wejściowe powodują błędną klasyfikację, halucynacje lub generowanie niedozwolonych treści przez model, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje z danych treningowych albo kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wywnioskowuje cechy osobowe, które nigdy nie zostały podane, powodując nowe zagrożenia dla prywatności wynikające z wnioskowania.

- **Insecure Model Output**: Nieoczyszczone odpowiedzi przekazują użytkownikom lub systemom zależnym szkodliwy kod, dezinformację albo nieodpowiednie treści.

- **Rogue Actions**: Agenty zintegrowane autonomicznie wykonują niezamierzone operacje w świecie rzeczywistym (zapisy plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Macierz Mitre AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do rozumienia i ograniczania ryzyk związanych z systemami AI. Kategoryzuje różne techniki i taktyki ataków, które adwersarze mogą stosować przeciwko modelom AI, a także sposoby wykorzystywania systemów AI do przeprowadzania różnych ataków.<sup>[[3]](#references)</sup>

## LLMJacking (kradzież tokenów i odsprzedaż dostępu do LLM hostowanych w chmurze)

Atakujący kradną aktywne tokeny sesji lub dane uwierzytelniające cloud API i bez autoryzacji wywołują płatne LLM hostowane w chmurze. Dostęp jest często odsprzedawany za pośrednictwem reverse proxies, które korzystają z konta ofiary, np. wdrożeń „oai-reverse-proxy”. Skutki obejmują straty finansowe, użycie modelu niezgodne z zasadami oraz przypisanie działań do tenanta ofiary.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Pozyskiwanie tokenów z zainfekowanych komputerów deweloperów lub przeglądarek; kradzież sekretów CI/CD; kupowanie leaked cookies.<sup>[[5]](#references)</sup>
- Uruchomienie reverse proxy przekazującego żądania do oryginalnego dostawcy, ukrywającego klucz upstream i obsługującego wielu klientów.<sup>[[5]](#references)[[7]](#references)</sup>
- Nadużywanie bezpośrednich endpointów base-model w celu ominięcia enterprise guardrails i limitów rate limit.<sup>[[4]](#references)</sup>

Łagodzenie ryzyka:
- Powiązanie tokenów z fingerprintem urządzenia, zakresami adresów IP i atestacją klienta; wymuszanie krótkiego czasu wygaśnięcia oraz odświeżanie z użyciem MFA.
- Ograniczenie zakresu kluczy do minimum (bez dostępu do narzędzi, w miarę możliwości tylko do odczytu); rotacja po wykryciu anomalii.
- Zakończenie całego ruchu po stronie serwera za policy gateway, który wymusza filtry bezpieczeństwa, limity dla poszczególnych tras i izolację tenantów.
- Monitorowanie nietypowych wzorców użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) i automatyczne unieważnianie podejrzanych sesji.
- Preferowanie mTLS lub podpisanych JWT wydawanych przez IdP zamiast długoterminowych statycznych kluczy API.

## Hardening self-hosted LLM inference

Uruchamianie lokalnego serwera LLM dla poufnych danych tworzy inną powierzchnię ataku niż API hostowane w chmurze: endpointy inference/debug mogą ujawniać prompty, stack udostępniający model zwykle wystawia reverse proxy, a węzły urządzeń GPU zapewniają dostęp do dużych powierzchni `ioctl()`. Jeśli oceniasz lub wdrażasz usługę inference on-prem, sprawdź co najmniej poniższe punkty.<sup>[[8]](#references)</sup>

### Wyciek promptów przez endpointy debugowania i monitorowania

Traktuj API inference jako **wrażliwą usługę multi-user**. Trasy debugowania lub monitorowania mogą ujawniać treść promptów, stan slotów, metadane modelu lub informacje o wewnętrznej kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i służy wyłącznie do ich inspekcji i zarządzania nimi.<sup>[[8]](#references)</sup>

- Umieść reverse proxy przed serwerem inference i **domyślnie odrzucaj żądania**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metody HTTP i ścieżki wymagane przez klienta/UI.
- W miarę możliwości wyłącz endpointy introspekcji w samym backendzie, np. `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je przez uwierzytelniony transport, taki jak lokalne przekierowanie portu SSH, zamiast publikować je w sieci LAN.

Przykładowa allowlista z nginx:
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

Jeśli inference daemon obsługuje nasłuchiwanie na gnieździe UNIX, wybierz tę opcję zamiast TCP i uruchom kontener **bez stosu sieciowego**:<sup>[[8]](#references)</sup>
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
- UNIX socket pozwala używać uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` oraz rootless Podman zmniejszają skutki container breakout, ponieważ root w kontenerze nie jest rootem hosta.
- Montowania modeli tylko do odczytu zmniejszają ryzyko modyfikacji modeli z wnętrza kontenera.

### Minimalizacja węzłów urządzeń GPU

W przypadku inference z użyciem GPU pliki `/dev/nvidia*` są wartościowymi lokalnymi powierzchniami ataku, ponieważ udostępniają duże handlery sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.<sup>[[8]](#references)</sup>

- Nie pozostawiaj `/dev/nvidia*` z uprawnieniami do zapisu dla wszystkich.
- Ogranicz `nvidia`, `nvidiactl` oraz `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko zmapowany UID kontenera mógł je otwierać.
- Zablokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` oraz `nvidia_peermem`, na hostach headless inference.
- Ładuj wstępnie tylko wymagane moduły podczas bootowania, zamiast pozwalać runtime'owi na oportunistyczne używanie `modprobe` podczas uruchamiania inference.

Przykład:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jednym z ważnych punktów przeglądu jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie używa jawnie `cudaMallocManaged()`, nowsze CUDA runtimes nadal mogą wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, należy traktować je jako powierzchnię ujawnienia danych między tenantami. Jeśli inference backend to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.<sup>[[8]](#references)</sup>

### Ograniczanie inference workers za pomocą LSM

AppArmor/SELinux/seccomp powinny być używane jako defense in depth wokół procesu inference:<sup>[[8]](#references)</sup>

- Zezwalaj wyłącznie na współdzielone biblioteki, ścieżki modeli, katalog socketów i węzły urządzeń GPU, które są rzeczywiście wymagane.
- Jawnie blokuj wysokiego ryzyka capabilities, takie jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Utrzymuj katalog modelu w trybie tylko do odczytu, a zapisywalne ścieżki ogranicz wyłącznie do katalogów socketów/cache runtime.
- Monitoruj logi odmów, ponieważ dostarczają użytecznej telemetrii detekcyjnej, gdy model server lub payload po post-exploitation próbuje wyjść poza oczekiwane zachowanie.

Przykładowe reguły AppArmor dla workera wykorzystującego GPU:
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
## Phantom Squatting: domeny wyhalucynowane przez LLM jako wektor ataku na łańcuch dostaw AI

Phantom squatting to **odpowiednik slopsquatting dla domen/URL-i**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną domenę **portalu, API, webhooka, płatności, SSO, pobierania lub wsparcia** dla prawdziwej marki, a attacker rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.<sup>[[12]](#references)[[13]](#references)</sup>

Ma to znaczenie, ponieważ w wielu workflow wspomaganych przez AI wynik modelu jest traktowany jako **zaufana zależność**:
- Developerzy wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenty AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub cele webhooków.
- Wygenerowane runbooki lub dokumentacja mogą zawierać fałszywy URL, jak gdyby był autorytatywny.

### Workflow ofensywny

1. **Zbadaj powierzchnię halucynacji**: zadawaj pytania dotyczące konkretnej marki i realistycznych workflow, takich jak portale `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizuj kandydatów**: rozwiązuj wygenerowane URL-e, sprowadzaj odpowiedzi NXDOMAIN do nadrzędnej domeny możliwej do zarejestrowania i usuwaj duplikaty rodzin promptów. Korpusy promptów powinny pozostać zróżnicowane, na przykład poprzez usuwanie niemal identycznych promptów z użyciem **podobieństwa Jaccarda**.
3. **Nadaj priorytet przewidywalnym halucynacjom**:
- **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych wartościach temperatury, w tym przy niskiej temperaturze, takiej jak `T=0.1`.
- **Konsensus między modelami**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Zarejestruj i uzbrój** domenę nadrzędną, a następnie hostuj phishing, fałszywe pliki APK/ZIP do pobrania, harvestery danych uwierzytelniających, złośliwe dokumenty lub endpointy API zbierające sekrety/payloady webhooków. **Halucynacje występujące wyłącznie na poziomie domeny** są najłatwiejsze do monetyzacji, ponieważ attacker kontroluje całą przestrzeń nazw; halucynacje subdomen/ścieżek nadal mogą zostać wykorzystane, gdy znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Wykorzystaj okno zerowej reputacji**: nowo zarejestrowane domeny często nie mają historii na blocklistach, reputacji URL ani dojrzałej telemetrii, więc mogą omijać mechanizmy kontroli do czasu nadrobienia zaległości przez detekcje. Attackers mogą wydłużyć to okno za pomocą benign responses wyłącznie dla crawlerów, redirect cloaking, bramek CAPTCHA lub opóźnionego stagingu payloadów.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku ofiary będącej człowiekiem fałszywa domena zwykle nadal wymaga kliknięcia i wykonania kolejnej czynności. W przypadku **agentic workflow** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje wyhalucynowany URL, pobiera go, parsuje odpowiedź, a następnie może wykonać leak tokenów, instrukcji, pobrać zależność lub przesłać zatrute dane do CI/CD bez jakiejkolwiek weryfikacji człowieka.<sup>[[12]](#references)</sup>

### Praktyczne prompty attackera

Prompty o wysokiej skuteczności zwykle wyglądają jak normalne zadania enterprise, a nie jawne przynęty phishingowe:<sup>[[12]](#references)</sup>
- „Jaki jest URL payment sandbox dla integracji `<brand>`?”
- „Jakiego endpointu webhooka powinienem użyć dla powiadomień o buildach `<brand>`?”
- „Gdzie znajduje się portal employee benefits / billing / SSO dla `<brand>`?”
- „Podaj bezpośredni download Android APK lub klienta desktopowego dla `<brand>`.”

### Odwrócenie perspektywy defensywnej

Traktuj to jako problem proaktywnego monitorowania domen, a nie wyłącznie jako problem prompt injection:<sup>[[12]](#references)</sup>
- Zbuduj **korpus promptów marek** i okresowo sonduj LLM-y, na których polegają Twoi użytkownicy/agenty.
- Przechowuj wyhalucynowane URL-e i śledź, które z nich pozostają stabilne przy różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas od pierwszej halucynacji do rejestracji przez attackera. Dodatnie AEW oznacza, że defenders mogą zarejestrować domenę z wyprzedzeniem, utworzyć sinkhole lub zablokować ją przed uzbrojeniem.
- Monitoruj przejścia **NXDOMAIN → registered** dla domen nadrzędnych.
- Po rejestracji przeanalizuj registrar, datę utworzenia, nameservers, privacy shielding, zawartość strony, zrzuty ekranu, status parked-page oraz podobieństwo assetów marki.
- Dodaj policy gates, aby agenty/developerzy **domyślnie nie ufali domenom wygenerowanym przez LLM**: wymagaj allowlist, weryfikacji własności, kontroli CT/RDAP lub akceptacji człowieka przed pierwszym użyciem.

Zjawisko to pasuje jednocześnie do kilku kategorii ryzyka AI: **AI supply-chain attack**, **insecure model output** oraz **rogue actions**, gdy agenty autonomicznie korzystają z wyhalucynowanego URL-a.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – Ryzyko związane z LLM-ami asystentów kodu: szkodliwe treści, niewłaściwe użycie i oszustwa](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: skradzione dane uwierzytelniające Cloud użyte w nowym ataku AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Przegląd schematu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Szczegółowa analiza wdrożenia uprzywilejowanego w ograniczonym zakresie, lokalnego serwera LLM](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeny wyhalucynowane przez AI jako wektor ataku na łańcuch dostaw oprogramowania](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: jak halucynacje AI napędzają nową klasę ataków na łańcuch dostaw](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
