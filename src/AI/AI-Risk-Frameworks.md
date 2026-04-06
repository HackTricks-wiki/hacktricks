# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp визначив top 10 вразливостей машинного навчання, які можуть вплинути на AI‑системи. Ці вразливості можуть призводити до різних проблем безпеки, включно з отруєнням даних, інверсією моделі та adversarial‑атаками. Розуміння цих вразливостей критичне для побудови безпечних AI‑систем.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Зловмисник додає дуже малі, часто непомітні зміни до **вхідних даних**, щоб змусити модель прийняти неправильне рішення.\
*Example*: A few specks of paint on a stop‑sign fool a self‑driving car into "seeing" a speed‑limit sign.

- **Data Poisoning Attack**: **training set** навмисно забруднюється шкідливими зразками, навчаючи модель шкідливих правил.\
*Example*: Malware binaries are mislabeled as "benign" in an antivirus training corpus, letting similar malware slip past later.

- **Model Inversion Attack**: Шляхом запитів по виходах, атакуючий будує **reverse model**, який реконструює чутливі характеристики початкових входів.\
*Example*: Re‑creating a patient's MRI image from a cancer‑detection model's predictions.

- **Membership Inference Attack**: Адвесарі перевіряє, чи був **конкретний запис** використаний під час тренування, виявляючи відмінності в confidence.\
*Example*: Confirming that a person's bank transaction appears in a fraud‑detection model's training data.

- **Model Theft**: Повторні запити дозволяють атакуючому вивчити межі рішень і **клонувати поведінку моделі** (та інтелектуальну власність).\
*Example*: Harvesting enough Q&A pairs from an ML‑as‑a‑Service API to build a near‑equivalent local model.

- **AI Supply‑Chain Attack**: Компрометація будь‑якого компоненту (дані, бібліотеки, pre‑trained weights, CI/CD) в **ML pipeline** для псування моделей вниз за ланцюгом.\
*Example*: A poisoned dependency on a model‑hub installs a backdoored sentiment‑analysis model across many apps.

- **Transfer Learning Attack**: Зловмисна логіка вбудовується в **pre‑trained model** і виживає після fine‑tuning на задачі жертви.\
*Example*: A vision backbone with a hidden trigger still flips labels after being adapted for medical imaging.

- **Model Skewing**: Тонко упереджені або неправильно марковані дані **зміщують виходи моделі** на користь намірів атакуючого.\
*Example*: Injecting "clean" spam emails labeled as ham so a spam filter lets similar future emails through.

- **Output Integrity Attack**: Атакуючий **змінює передбачення моделі під час трансферу**, а не саму модель, вводячи в оману downstream системи.\
*Example*: Flipping a malware classifier's "malicious" verdict to "benign" before the file‑quarantine stage sees it.

- **Model Poisoning** --- Прямі, цілеспрямовані зміни до **параметрів моделі** самих по собі, часто після отримання запису на запис, щоб змінити поведінку.\
*Example*: Tweaking weights on a fraud‑detection model in production so transactions from certain cards are always approved.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) описує різні ризики, пов'язані з AI‑системами:

- **Data Poisoning**: Зловмисні актори змінюють або інжектять training/tuning дані, щоб погіршити точність, імплантувати backdoors або змістити результати, підриваючи цілісність моделі через весь життєвий цикл даних.

- **Unauthorized Training Data**: Поглинання copyrighted, чутливих або неприпустимих наборів даних створює юридичні, етичні та продуктивні ризики, оскільки модель навчається на даних, які їй не дозволили використовувати.

- **Model Source Tampering**: Маніпуляція ланцюгом постачання або insider‑атаки на код моделі, залежності чи ваги до або під час тренування можуть вбудувати приховану логіку, яка зберігається навіть після повторного тренування.

- **Excessive Data Handling**: Слабкі контролі збереження даних і управління призводять до того, що системи зберігають або обробляють більше персональних даних, ніж необхідно, підвищуючи експозицію та ризики відповідності.

- **Model Exfiltration**: Атакуючі крадуть model files/weights, що спричиняє втрату інтелектуальної власності та дозволяє копіювати сервіси або проводити подальші атаки.

- **Model Deployment Tampering**: Адвесарі модифікують модельні артефакти або інфраструктуру serving, тож працююча модель відрізняється від перевіреної версії і може змінювати поведінку.

- **Denial of ML Service**: Завантаження API або надсилання “sponge” input‑ів може виснажити обчислювальні ресурси/енергію й вивести модель з ладу, імітуючи класичні DoS‑атаки.

- **Model Reverse Engineering**: Збирання великої кількості пар input‑output дозволяє атакуючим клонувати або дистилювати модель, підживлюючи імітаційні продукти і кастомізовані adversarial‑атаки.

- **Insecure Integrated Component**: Вразливі плагіни, агенти або upstream сервіси дозволяють атакуючим інжектити код або ескалювати привілеї в AI‑pipeline.

- **Prompt Injection**: Складання prompt‑ів (безпосередньо або опосередковано) для контрабанди інструкцій, які перекривають системний intent, змушуючи модель виконувати небажані команди.

- **Model Evasion**: Ретельно спроектовані input‑и змушують модель неправильно класифікувати, вигадувати факти або видавати заборонений контент, підриваючи безпеку й довіру.

- **Sensitive Data Disclosure**: Модель розкриває приватну або конфіденційну інформацію з training data або контексту користувача, порушуючи приватність і регуляції.

- **Inferred Sensitive Data**: Модель виводить персональні атрибути, які ніколи не були надані, створюючи нові шкоди приватності через інференцію.

- **Insecure Model Output**: Несанітизовані відповіді передають шкідливий код, misinformation або неприйнятний контент користувачам чи downstream системам.

- **Rogue Actions**: Автономно інтегровані агенти виконують небажані реальні операції (записи файлів, API‑виклики, покупки тощо) без адекватного нагляду користувача.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає всеохопну структуру для розуміння та пом'якшення ризиків, пов'язаних з AI‑системами. Вона категоризує різні техніки атак і тактики, які адвесарі можуть використовувати проти AI‑моделей, а також те, як використовувати AI‑системи для виконання різних атак.

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

Запуск локального LLM‑сервера для конфіденційних даних створює іншу поверхню атаки порівняно з cloud‑hosted API: inference/debug endpoints можуть leak prompts, serving stack зазвичай експонує reverse proxy, а GPU device nodes дають доступ до великих `ioctl()` поверхонь. Якщо ви оцінюєте або розгортаєте on‑prem inference service, перегляньте принаймні наступні пункти.

### Prompt leakage via debug and monitoring endpoints

Розглядайте inference API як **multi‑user sensitive service**. Debug або monitoring маршрути можуть показувати вміст prompt‑ів, стан слотів, метадані моделі або внутрішню інформацію черги. В `llama.cpp`, endpoint `/slots` особливо чутливий, бо показує per‑slot state і призначений лише для інспекції/керування слотами.

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
### Rootless контейнери без мережі та UNIX socket

Якщо inference daemon підтримує прослуховування на UNIX socket, віддавайте перевагу цьому замість TCP і запускайте контейнер з **відсутнім мережевим стеком**:
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
Переваги:
- `--network none` усуває відкриття TCP/IP для вхідних/вихідних з'єднань і дозволяє уникнути user-mode helpers, які в іншому випадку потрібні rootless containers.
- UNIX socket дозволяє використовувати POSIX permissions/ACLs на шляху сокета як перший рівень контролю доступу.
- `--userns=keep-id` та rootless Podman зменшують наслідки container breakout, тому що container root не є host root.
- Read-only model mounts зменшують ймовірність змінення моделі зсередини контейнера.

### GPU device-node minimization

Для GPU-backed inference файли `/dev/nvidia*` є цінними локальними поверхнями атаки, оскільки вони відкривають великі драйверні `ioctl()` обробники та потенційно спільні шляхи управління пам'яттю GPU.

- Не залишайте `/dev/nvidia*` доступними для запису для всіх (world writable).
- Обмежте `nvidia`, `nvidiactl` та `nvidia-uvm` за допомогою `NVreg_DeviceFileUID/GID/Mode`, udev rules та ACLs так, щоб їх міг відкривати лише відображений container UID.
- Занесіть у чорний список непотрібні модулі, такі як `nvidia_drm`, `nvidia_modeset` та `nvidia_peermem`, на headless inference hosts.
- Попередньо завантажуйте лише необхідні модулі під час boot замість того, щоб дозволяти runtime opportunistically викликати `modprobe` під час старту inference.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Одне важливе місце для перевірки — **`/dev/nvidia-uvm`**. Навіть якщо робоче навантаження явно не використовує `cudaMallocManaged()`, сучасні CUDA runtimes можуть все одно вимагати `nvidia-uvm`. Оскільки цей пристрій є спільним і відповідає за керування віртуальною пам'яттю GPU, розглядайте його як поверхню потенційного розкриття даних між орендарями. Якщо бекенд для інференсу це підтримує, Vulkan-бекенд може бути цікавим компромісом, оскільки він може уникнути експонування `nvidia-uvm` у контейнері взагалі.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp слід використовувати як багаторівневий захист навколо процесу інференсу:

- Дозволяйте лише ті спільні бібліотеки, шляхи моделей, каталог сокетів та вузли пристроїв GPU, які дійсно потрібні.
- Явно забороняйте високоризикові capabilities, такі як `sys_admin`, `sys_module`, `sys_rawio` та `sys_ptrace`.
- Тримайте каталог моделей у режимі лише для читання та обмежуйте записувані шляхи лише до каталогів сокетів/кешу середовища виконання.
- Моніторте логи відмов, оскільки вони дають корисну телеметрію для виявлення, коли сервер моделі або post-exploitation payload намагаються вийти за межі очікуваної поведінки.

Приклад правил AppArmor для воркера з підтримкою GPU:
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
## Джерела
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
