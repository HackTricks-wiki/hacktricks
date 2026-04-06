# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp zidentyfikował top 10 podatności w machine learning, które mogą wpływać na systemy AI. Te podatności mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych słabości jest kluczowe przy budowaniu bezpiecznych systemów AI.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: An attacker adds tiny, often invisible changes to **incoming data** so the model makes the wrong decision.\
*Przykład*: Kilka kropek farby na znaku stop powoduje, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: The **training set** is deliberately polluted with bad samples, teaching the model harmful rules.\
*Przykład*: Binarne próbki malware są błędnie oznaczone jako „benign” w korpusie treningowym antywirusa, co pozwala podobnym malware omijać detekcję.

- **Model Inversion Attack**: By probing outputs, an attacker builds a **reverse model** that reconstructs sensitive features of the original inputs.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: The adversary tests whether a **specific record** was used during training by spotting confidence differences.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego fraud.

- **Model Theft**: Repeated querying lets an attacker learn decision boundaries and **clone the model's behavior** (and IP).\
*Przykład*: Zebranie wystarczającej liczby par pytanie‑odpowiedź z ML‑as‑a‑Service API, by zbudować lokalny model o podobnych właściwościach.

- **AI Supply‑Chain Attack**: Compromise any component (data, libraries, pre‑trained weights, CI/CD) in the **ML pipeline** to corrupt downstream models.\
*Przykład*: Zatruty dependency na model‑hub instaluje backdoored model do analizy sentymentu w wielu aplikacjach.

- **Transfer Learning Attack**: Malicious logic is planted in a **pre‑trained model** and survives fine‑tuning on the victim's task.\
*Przykład*: Vision backbone z ukrytym triggerem nadal zmienia etykiety po adaptacji do obrazowania medycznego.

- **Model Skewing**: Subtly biased or mislabeled data **shifts the model's outputs** to favor the attacker's agenda.\
*Przykład*: Wstrzyknięcie „czystych” spamowych e‑maili oznaczonych jako ham, tak że filtr spamowy przepuszcza podobne wiadomości w przyszłości.

- **Output Integrity Attack**: The attacker **alters model predictions in transit**, not the model itself, tricking downstream systems.\
*Przykład*: Zmiana verdictu klasyfikatora malware z „malicious” na „benign” w tranzycie, zanim etap kwarantanny pliku go zobaczy.

- **Model Poisoning** --- Direct, targeted changes to the **model parameters** themselves, often after gaining write access, to alter behavior.\
*Przykład*: Modyfikacja wag modelu wykrywającego fraud w produkcji, tak że transakcje z określonych kart są zawsze zatwierdzane.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) outlines various risks associated with AI systems:

- **Data Poisoning**: Malicious actors alter or inject training/tuning data to degrade accuracy, implant backdoors, or skew results, undermining model integrity across the entire data-lifecycle.

- **Unauthorized Training Data**: Ingesting copyrighted, sensitive, or unpermitted datasets creates legal, ethical, and performance liabilities because the model learns from data it was never allowed to use.

- **Model Source Tampering**: Supply-chain or insider manipulation of model code, dependencies, or weights before or during training can embed hidden logic that persists even after retraining.

- **Excessive Data Handling**: Weak data-retention and governance controls lead systems to store or process more personal data than necessary, heightening exposure and compliance risk.

- **Model Exfiltration**: Attackers steal model files/weights, causing loss of intellectual property and enabling copy-cat services or follow-on attacks.

- **Model Deployment Tampering**: Adversaries modify model artifacts or serving infrastructure so the running model differs from the vetted version, potentially changing behaviour.

- **Denial of ML Service**: Flooding APIs or sending “sponge” inputs can exhaust compute/energy and knock the model offline, mirroring classic DoS attacks.

- **Model Reverse Engineering**: By harvesting large numbers of input-output pairs, attackers can clone or distil the model, fueling imitation products and customized adversarial attacks.

- **Insecure Integrated Component**: Vulnerable plugins, agents, or upstream services let attackers inject code or escalate privileges within the AI pipeline.

- **Prompt Injection**: Crafting prompts (directly or indirectly) to smuggle instructions that override system intent, making the model perform unintended commands.

- **Model Evasion**: Carefully designed inputs trigger the model to mis-classify, hallucinate, or output disallowed content, eroding safety and trust.

- **Sensitive Data Disclosure**: The model reveals private or confidential information from its training data or user context, violating privacy and regulations.

- **Inferred Sensitive Data**: The model deduces personal attributes that were never provided, creating new privacy harms through inference.

- **Insecure Model Output**: Unsanitized responses pass harmful code, misinformation, or inappropriate content to users or downstream systems.

- **Rogue Actions**: Autonomously-integrated agents execute unintended real-world operations (file writes, API calls, purchases, etc.) without adequate user oversight.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) provides a comprehensive framework for understanding and mitigating risks associated with AI systems. It categorizes various attack techniques and tactics that adversaries may use against AI models and also how to use AI systems to perform different attacks.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers steal active session tokens or cloud API credentials and invoke paid, cloud-hosted LLMs without authorization. Access is often resold via reverse proxies that front the victim’s account, e.g. "oai-reverse-proxy" deployments. Consequences include financial loss, model misuse outside policy, and attribution to the victim tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## Self-hosted LLM inference hardening

Uruchamianie lokalnego serwera LLM dla poufnych danych tworzy inny surface ataku niż cloud‑hosted API: inference/debug endpoints mogą ujawniać prompty, stos serwujący zwykle eksponuje reverse proxy, a węzły urządzeń GPU dają dostęp do rozległych powierzchni ioctl(). Jeśli oceniasz lub wdrażasz on‑prem inference service, sprawdź przynajmniej poniższe punkty.

### Prompt leakage via debug and monitoring endpoints

Traktuj inference API jako multi-user sensitive service. Endpointy debug lub monitoring mogą ujawniać zawartość promptów, stan slotów, metadane modelu lub wewnętrzne informacje o kolejce. W przypadku `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan per-slot i jest przeznaczony wyłącznie do inspekcji/zarządzania slotami.

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

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
### Kontenery rootless bez sieci i UNIX sockets

Jeśli demon inferencji obsługuje nasłuchiwanie na UNIX socket, wybierz to zamiast TCP i uruchom kontener bez **stosu sieciowego**:
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
- `--network none` usuwa ekspozycję TCP/IP przychodzącą/wychodzącą i eliminuje pomocniki w trybie użytkownika, których w przeciwnym razie potrzebowałyby kontenery rootless.
- Gniazdo UNIX pozwala użyć uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman zmniejszają skutki wydostania się z kontenera, ponieważ root w kontenerze nie jest rootem hosta.
- Montowania modeli tylko do odczytu zmniejszają szansę na manipulację modelem z wnętrza kontenera.

### Minimalizacja device-node'ów GPU

Dla inference opartego na GPU pliki `/dev/nvidia*` są cennymi lokalnymi powierzchniami ataku, ponieważ ujawniają rozbudowane funkcje obsługi sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.

- Nie pozostawiaj `/dev/nvidia*` z uprawnieniami zapisu dla wszystkich użytkowników.
- Ogranicz dostęp do `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby tylko zmapowany UID kontenera mógł je otworzyć.
- Na headless inference hostach zablokuj (blacklist) niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`.
- Wstępnie załaduj tylko wymagane moduły podczas bootowania zamiast pozwalać runtime'owi na okazjonalne uruchamianie `modprobe` podczas startu inference.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Nawet jeśli obciążenie nie używa wprost `cudaMallocManaged()`, nowsze runtime'y CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, traktuj je jako powierzchnię narażoną na ujawnienie danych między tenantami. Jeśli backend inferencyjny to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie uniknąć eksponowania `nvidia-uvm` do kontenera.

### Ograniczenia LSM dla procesów inferencyjnych

AppArmor/SELinux/seccomp powinny być stosowane jako wielowarstwowa obrona wokół procesu inferencyjnego:

- Zezwalaj tylko na udostępnione biblioteki, ścieżki modeli, katalog socketów oraz węzły urządzeń GPU, które są faktycznie wymagane.
- Jawnie odmawiaj niebezpiecznych uprawnień takich jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Utrzymuj katalog modeli jako read-only i ogranicz ścieżki zapisu wyłącznie do katalogów socket/cache runtime.
- Monitoruj logi odmów, ponieważ dostarczają przydatnej telemetrii detekcyjnej, gdy model server lub post-exploitation payload próbują wymknąć się spod oczekiwanego zachowania.

Przykładowe reguły AppArmor dla procesu obsługującego GPU:
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
## Referencje
- [Unit 42 – Ryzyka Code Assistant LLMs: Szkodliwe treści, nadużycia i wprowadzanie w błąd](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Przegląd schematu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (odsprzedawanie skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv – Dogłębna analiza wdrożenia lokalnego serwera LLM o niskich uprawnieniach](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) — specyfikacja](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
