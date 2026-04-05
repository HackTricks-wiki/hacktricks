# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP zidentyfikował top 10 podatności w uczeniu maszynowym, które mogą wpływać na systemy AI. Te podatności mogą prowadzić do różnych problemów bezpieczeństwa, w tym Data Poisoning, model inversion i ataków adversarial. Zrozumienie tych zagrożeń jest kluczowe dla budowania bezpiecznych systemów AI.

Dla zaktualizowanej i szczegółowej listy top 10 podatności w uczeniu maszynowym odsyłam do projektu [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Atakujący dodaje drobne, często niewidoczne zmiany do **incoming data**, aby model podjął błędną decyzję.\
*Przykład*: Kilka odrobinek farby na znaku stop powoduje, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: Zestaw treningowy jest celowo zanieczyszczony złymi próbkami, ucząc model szkodliwych reguł.\
*Przykład*: Binaria malware są oznaczone jako „benign” w korpusie treningowym antywirusa, pozwalając podobnemu malware później przechodzić niezauważonym.

- **Model Inversion Attack**: Poprzez sondowanie outputów, atakujący buduje **reverse model**, który rekonstruuje wrażliwe cechy oryginalnych wejść.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego nowotwór.

- **Membership Inference Attack**: Adwersarz sprawdza, czy **konkretny rekord** był użyty podczas treningu, wykrywając różnice w confidence.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Wielokrotne zapytania pozwalają atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (i IP).\
*Przykład*: Zebranie wystarczającej liczby par Q&A z API ML‑as‑a‑Service, by zbudować lokalny model niemal równoważny.

- **AI Supply‑Chain Attack**: Kompromitowanie dowolnego komponentu (dane, biblioteki, pre‑trained weights, CI/CD) w **ML pipeline** w celu skompromitowania modeli downstream.\
*Przykład*: Zainfekowana zależność na model‑hub instaluje backdoored model sentiment‑analysis w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika jest umieszczona w **pre‑trained model** i przetrwa fine‑tuning na zadaniu ofiary.\
*Przykład*: Vision backbone z ukrytym triggerem dalej zmienia etykiety po adaptacji do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają outputy modelu**, faworyzując agendę atakującego.\
*Przykład*: Wstrzyknięcie „czystych” spamów oznaczonych jako ham, aby filtr antyspamowy przepuszczał podobne przyszłe wiadomości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu w tranzycie**, nie model sam w sobie, oszukując systemy downstream.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „malicious” na „benign” zanim etap kwarantanny pliku go zobaczy.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany w **parametrach modelu** samych w sobie, często po uzyskaniu dostępu zapisu, aby zmienić zachowanie.\
*Przykład*: Dostosowanie wag modelu wykrywającego oszustwa w produkcji, tak by transakcje z pewnych kart były zawsze zatwierdzane.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) przedstawia różne ryzyka związane z systemami AI:

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe/tuningowe, aby pogorszyć dokładność, zainstalować backdoory lub zmanipulować wyniki, podważając integralność modelu w całym lifecycle danych.

- **Unauthorized Training Data**: Pobieranie danych objętych prawami autorskimi, wrażliwych lub niedozwolonych zbiorów stwarza zobowiązania prawne, etyczne i wydajnościowe, ponieważ model uczy się z danych, których nie powinien był używać.

- **Model Source Tampering**: Manipulacja łańcuchem dostaw lub insidera w kodzie modelu, zależnościach lub weights przed lub w trakcie treningu może osadzić ukrytą logikę, która przetrwa nawet retraining.

- **Excessive Data Handling**: Słabe kontrole retencji i governance danych powodują, że systemy przechowują lub przetwarzają więcej danych osobowych niż to konieczne, zwiększając ekspozycję i ryzyko zgodności.

- **Model Exfiltration**: Atakujący kradnie pliki/weights modelu, powodując utratę własności intelektualnej i umożliwiając powielenie usług lub kolejne ataki.

- **Model Deployment Tampering**: Adwersarze modyfikują artefakty modelu lub infrastrukturę servingową, tak że uruchomiony model różni się od wersji zweryfikowanej, potencjalnie zmieniając zachowanie.

- **Denial of ML Service**: Zatłoczenie API lub wysyłanie „sponge” inputs może wyczerpać compute/energię i wyłączyć model, podobnie jak klasyczne ataki DoS.

- **Model Reverse Engineering**: Poprzez zebranie dużej liczby par input‑output, atakujący mogą sklonować lub distilować model, napędzając produkty‑imitacje i spersonalizowane ataki adversarial.

- **Insecure Integrated Component**: Wrażliwe pluginy, agenci lub usługi upstream pozwalają atakującym wstrzyknąć kod lub eskalować uprawnienia w pipeline AI.

- **Prompt Injection**: Tworzenie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji, które nadpisują intencję systemu, zmuszając model do wykonywania niezamierzonych poleceń.

- **Model Evasion**: Starannie zaprojektowane wejścia powodują, że model błędnie klasyfikuje, halucynuje lub generuje zabronione treści, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje ze swoich danych treningowych lub kontekstu użytkownika, naruszając prywatność i regulacje.

- **Inferred Sensitive Data**: Model wnioskuje cechy osobiste, których nigdy nie podano, tworząc nowe szkody prywatności przez inference.

- **Insecure Model Output**: Niesanitizowane odpowiedzi przekazują szkodliwy kod, dezinformację lub nieodpowiednie treści użytkownikom lub systemom downstream.

- **Rogue Actions**: Autonomicznie zintegrowani agenci wykonują niezamierzone operacje w świecie rzeczywistym (zapis plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) dostarcza kompleksowego frameworku do rozumienia i łagodzenia ryzyk związanych z systemami AI. Kategoryzuje różne techniki ataku i taktyki, których adwersarze mogą użyć przeciwko modelom AI, a także jak używać systemów AI do przeprowadzania różnych ataków.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atakujący kradną aktywne session tokens lub cloud API credentials i wywołują płatne, cloud‑hosted LLM bez autoryzacji. Dostęp jest często odsprzedawany przez reverse proxies, które frontują konto ofiary, np. deploymenty "oai-reverse-proxy". Konsekwencje obejmują straty finansowe, nadużycie modelu poza polityką i przypisanie działań do ofiary‑tenant.

TTPs:
- Harvest tokens z zainfekowanych maszyn deweloperskich lub przeglądarek; kraść CI/CD secrets; kupować leaked cookies.
- Uruchomić reverse proxy, które przekazuje żądania do prawdziwego providera, ukrywając upstream key i multiplexując wielu klientów.
- Abuse direct base‑model endpoints, aby obejść enterprise guardrails i rate limits.

Mitigations:
- Powiązać tokens z device fingerprint, zakresami IP i client attestation; wymuszać krótkie wygaśnięcia i odświeżanie z MFA.
- Scope keys minimalnie (bez dostępu do narzędzi, read‑only tam gdzie to możliwe); rotować przy anomalii.
- Zamykać cały traffic server‑side za policy gateway, który egzekwuje filtry bezpieczeństwa, per‑route quotas i tenant isolation.
- Monitorować nietypowe wzorce użycia (skoki wydatków, nietypowe regiony, UA strings) i auto‑revoke podejrzane sesje.
- Preferować mTLS lub signed JWTs wydawane przez twój IdP zamiast długowiecznych statycznych API keys.

## Self-hosted LLM inference hardening

Uruchamianie lokalnego serwera LLM dla danych poufnych tworzy inny attack surface niż cloud‑hosted API: inference/debug endpoints mogą leakować prompty, stos serwujący zwykle wystawia reverse proxy, a GPU device nodes dają dostęp do rozległego surface’u ioctl(). Jeśli oceniasz lub wdrażasz on‑prem inference service, sprawdź przynajmniej następujące punkty.

### Prompt leakage via debug and monitoring endpoints

Traktuj inference API jako **multi‑user sensitive service**. Trasy debugowania lub monitoringowe mogą ujawniać zawartość promptów, stan slotów, metadata modelu lub wewnętrzne informacje o kolejkach. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan per‑slot i jest przeznaczony tylko do inspekcji/zarządzania slotami.

- Umieść reverse proxy przed inference serverem i **deny by default**.
- Allowlistuj tylko dokładne kombinacje HTTP method + path, które są potrzebne klientowi/UI.
- Wyłącz introspection endpoints w samym backendzie, kiedy tylko to możliwe, np. `llama-server --no-slots`.
- Zwiąż reverse proxy z `127.0.0.1` i eksponuj je przez uwierzytelniony transport taki jak SSH local port forwarding zamiast publikować je w LAN.

Example allowlist with nginx:
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
### Kontenery uruchamiane bez uprawnień root, bez sieci i z gniazdami UNIX

Jeśli demon inferencji obsługuje nasłuchiwanie na gnieździe UNIX, preferuj to zamiast TCP i uruchom kontener z **brakiem stosu sieciowego**:
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
Benefits:
- `--network none` usuwa ekspozycję TCP/IP przychodzącą/wychodzącą i unika user-mode helperów, których w przeciwnym razie potrzebowałyby rootless containers.
- UNIX socket pozwala użyć uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` oraz rootless Podman zmniejszają wpływ container breakout, ponieważ container root nie jest rootem hosta.
- Montowania modeli tylko do odczytu zmniejszają szansę na manipulację modelem z wnętrza containera.

### Minimalizacja device-node dla GPU

Dla inference wspieranego przez GPU, pliki `/dev/nvidia*` są wartościowymi lokalnymi powierzchniami ataku, ponieważ eksponują rozbudowane handlery `ioctl()` sterownika i potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.

- Nie zostawiaj `/dev/nvidia*` zapisywalnych przez wszystkich.
- Ogranicz `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko mapowany UID kontenera mógł je otwierać.
- Umieść na czarnej liście niepotrzebne moduły takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na hostach inference bez interfejsu graficznego.
- Preloaduj tylko wymagane moduły przy starcie systemu zamiast pozwalać runtime'owi na oportunistyczne `modprobe` ich podczas uruchamiania inference.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jednym z ważnych punktów do sprawdzenia jest **`/dev/nvidia-uvm`**. Nawet jeśli obciążenie nie używa wprost `cudaMallocManaged()`, nowsze runtimy CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, traktuj je jako powierzchnię narażenia danych między tenantami. Jeśli inference backend to wspiera, Vulkan backend może być ciekawym kompromisem, ponieważ może uniknąć eksponowania `nvidia-uvm` w kontenerze.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp powinny być stosowane jako wielowarstwowa obrona wokół procesu inference:

- Zezwalaj tylko na biblioteki współdzielone, ścieżki modeli, katalog socketów i węzły urządzeń GPU, które są faktycznie wymagane.
- Wyraźnie zabraniaj uprawnień (capabilities) wysokiego ryzyka, takich jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Trzymaj katalog modeli w trybie tylko do odczytu, a ścieżki zapisu ogranicz wyłącznie do katalogów runtime socket/cache.
- Monitoruj denial logs, ponieważ dostarczają cennej telemetrii detekcyjnej, gdy model server lub post-exploitation payload próbuje wyjść poza oczekiwane zachowanie.

Example AppArmor rules for a GPU-backed worker:
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
## Źródła
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
