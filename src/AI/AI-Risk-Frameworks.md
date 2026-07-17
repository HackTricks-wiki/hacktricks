# Ризики AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp визначила 10 основних вразливостей машинного навчання, які можуть впливати на AI-системи. Ці вразливості можуть призводити до різних проблем безпеки, зокрема отруєння даних, інверсії моделі та adversarial-атак. Розуміння цих вразливостей має вирішальне значення для створення захищених AI-систем.

Актуальний і детальний список 10 основних вразливостей машинного навчання наведено в проєкті [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Зловмисник додає крихітні, часто невидимі зміни до **вхідних даних**, через що модель ухвалює неправильне рішення.\
*Приклад*: Кілька плям фарби на знаку STOP змушують self-driving автомобіль "побачити" знак обмеження швидкості.

- **Data Poisoning Attack**: До **навчального набору** навмисно додають шкідливі зразки, навчаючи модель небезпечних правил.\
*Приклад*: Бінарні файли malware позначають як "benign" у навчальному корпусі антивіруса, через що подібне malware згодом проходить перевірку.

- **Model Inversion Attack**: Аналізуючи відповіді, зловмисник створює **зворотну модель**, яка відновлює чутливі ознаки початкових вхідних даних.\
*Приклад*: Відтворення MRI-зображення пацієнта на основі прогнозів моделі виявлення раку.

- **Membership Inference Attack**: Зловмисник перевіряє, чи використовувався **конкретний запис** під час навчання, виявляючи відмінності у рівні впевненості.\
*Приклад*: Підтвердження того, що банківська транзакція певної особи міститься в навчальних даних моделі виявлення шахрайства.

- **Model Theft**: Повторні запити дають зловмиснику змогу вивчити межі ухвалення рішень і **клонувати поведінку моделі** (та IP).\
*Приклад*: Збір достатньої кількості пар запитань і відповідей з API ML-as-a-Service для створення майже еквівалентної локальної моделі.

- **AI Supply-Chain Attack**: Компрометація будь-якого компонента (даних, бібліотек, pre-trained weights, CI/CD) у **ML pipeline** для пошкодження наступних моделей.\
*Приклад*: Отруєна dependency у model-hub встановлює backdoored модель аналізу тональності в багатьох застосунках.

- **Transfer Learning Attack**: Шкідливу логіку вбудовують у **pre-trained model**, і вона зберігається після fine-tuning під завдання жертви.\
*Приклад*: Vision backbone із прихованим trigger і надалі змінює мітки після адаптації для медичної візуалізації.

- **Model Skewing**: Непомітно упереджені або неправильно марковані дані **зміщують виходи моделі**, спрямовуючи їх на користь цілей зловмисника.\
*Приклад*: Додавання "чистих" spam-листів, позначених як ham, щоб spam-фільтр пропускав подібні майбутні листи.

- **Output Integrity Attack**: Зловмисник **змінює прогнози моделі під час передавання**, не змінюючи саму модель, і вводить в оману наступні системи.\
*Приклад*: Заміна вердикту malware-класифікатора "malicious" на "benign" до того, як його побачить етап ізоляції файлу.

- **Model Poisoning** --- Прямі цілеспрямовані зміни самих **параметрів моделі**, часто після отримання write-доступу, щоб змінити її поведінку.\
*Приклад*: Зміна weights моделі виявлення шахрайства у production, щоб транзакції з певних карток завжди схвалювалися.


## Google SAIF Risks

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) від Google описує різні ризики, пов'язані з AI-системами:

- **Data Poisoning**: Зловмисники змінюють або впроваджують навчальні дані чи дані для tuning, щоб погіршити точність, встановити backdoor або спотворити результати, підриваючи цілісність моделі протягом усього data-lifecycle.

- **Unauthorized Training Data**: Використання захищених авторським правом, чутливих або несанкціонованих наборів даних створює юридичні, етичні та пов'язані з продуктивністю ризики, оскільки модель навчається на даних, які їй ніколи не дозволяли використовувати.

- **Model Source Tampering**: Маніпуляції зловмисників або інсайдерів із кодом моделі, dependencies чи weights до або під час навчання можуть вбудувати приховану логіку, яка зберігається навіть після повторного навчання.

- **Excessive Data Handling**: Слабкі засоби контролю зберігання даних і governance змушують системи зберігати або обробляти більше персональних даних, ніж потрібно, підвищуючи ризики витоку та недотримання вимог.

- **Model Exfiltration**: Зловмисники викрадають файли моделі або weights, що призводить до втрати інтелектуальної власності та дає змогу створювати копіювальні сервіси або здійснювати подальші атаки.

- **Model Deployment Tampering**: Зловмисники змінюють артефакти моделі або serving-інфраструктуру, через що запущена модель відрізняється від перевіреної версії та потенційно має іншу поведінку.

- **Denial of ML Service**: Flooding API або надсилання “sponge” inputs може вичерпати обчислювальні ресурси чи енергію та вивести модель з ладу, подібно до класичних DoS-атак.

- **Model Reverse Engineering**: Збираючи велику кількість пар вхід-вихід, зловмисники можуть клонувати або distil модель, створюючи продукти-імітації та кастомізовані adversarial-атаки.

- **Insecure Integrated Component**: Вразливі plugins, agents або upstream-сервіси дають зловмисникам змогу впроваджувати код або підвищувати привілеї в AI pipeline.

- **Prompt Injection**: Формування prompts (безпосередньо або опосередковано) для прихованого передавання інструкцій, які перезаписують намір системи та змушують модель виконувати ненавмисні команди.

- **Model Evasion**: Ретельно сформовані вхідні дані змушують модель неправильно класифікувати, галюцинувати або виводити заборонений контент, підриваючи безпеку та довіру.

- **Sensitive Data Disclosure**: Модель розкриває приватну або конфіденційну інформацію зі своїх навчальних даних чи контексту користувача, порушуючи конфіденційність і нормативні вимоги.

- **Inferred Sensitive Data**: Модель виводить персональні атрибути, які ніколи не надавалися, створюючи нові загрози приватності через inference.

- **Insecure Model Output**: Несанітизовані відповіді передають користувачам або downstream-системам шкідливий код, дезінформацію чи неприйнятний контент.

- **Rogue Actions**: Autonomously-integrated agents виконують ненавмисні операції у фізичному світі (запис файлів, API-виклики, покупки тощо) без належного контролю користувача.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає комплексну framework для розуміння ризиків, пов'язаних із AI-системами, та протидії їм. Вона класифікує різні attack techniques і tactics, які adversaries можуть застосовувати проти AI-моделей, а також способи використання AI-систем для виконання різних атак.


## LLMJacking (Викрадення токенів і перепродаж доступу до Cloud-hosted LLM)

Зловмисники викрадають активні session tokens або cloud API credentials і без дозволу викликають платні Cloud-hosted LLM. Доступ часто перепродається через reverse proxies, які працюють від імені акаунта жертви, наприклад deployment "oai-reverse-proxy". Наслідки включають фінансові збитки, використання моделі всупереч політикам і приписування активності tenant жертви.

TTPs:
- Викрадати tokens із заражених машин розробників або browsers; красти secrets CI/CD; купувати leaked cookies.
- Розгортати reverse proxy, який пересилає запити справжньому провайдеру, приховує upstream key і мультиплексує багатьох клієнтів.
- Зловживати direct base-model endpoints для обходу enterprise guardrails і rate limits.

Mitigations:
- Прив'язувати tokens до device fingerprint, діапазонів IP і client attestation; встановлювати короткий термін дії та виконувати refresh із MFA.
- Мінімізувати scope keys (без доступу до tools, read-only за можливості); виконувати ротацію при аномаліях.
- Завершувати весь трафік на стороні сервера за policy gateway, який застосовує safety filters, quotas для кожного route і tenant isolation.
- Відстежувати незвичні patterns використання (раптові стрибки витрат, нетипові регіони, UA strings) і автоматично відкликати підозрілі sessions.
- Надавати перевагу mTLS або підписаним JWT, виданим вашим IdP, замість довготривалих статичних API keys.

## Посилення безпеки Self-hosted LLM inference

Запуск локального LLM-сервера для конфіденційних даних створює іншу attack surface, ніж Cloud-hosted API: inference/debug endpoints можуть спричинити leak prompts, serving stack зазвичай відкриває reverse proxy, а GPU device nodes надають доступ до великих `ioctl()` surfaces. Якщо ви оцінюєте або розгортаєте on-prem inference service, перевірте щонайменше наведені нижче аспекти.

### Витік prompts через debug і monitoring endpoints

Розглядайте inference API як **multi-user sensitive service**. Debug або monitoring routes можуть розкривати вміст prompts, стан слотів, metadata моделі або інформацію про внутрішню queue. У `llama.cpp` endpoint `/slots` є особливо чутливим, оскільки розкриває стан окремих слотів і призначений лише для перевірки або керування слотами.

- Розмістіть reverse proxy перед inference-сервером і застосуйте **deny by default**.
- Дозволяйте лише точні комбінації HTTP method + path, необхідні client/UI.
- За можливості вимикайте introspection endpoints безпосередньо в backend, наприклад `llama-server --no-slots`.
- Прив'яжіть reverse proxy до `127.0.0.1` і надавайте доступ через authenticated transport, наприклад SSH local port forwarding, замість публікації в LAN.

Приклад allowlist для nginx:
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
### Rootless-контейнери без мережі та UNIX-сокети

Якщо inference daemon підтримує прослуховування UNIX-сокета, надавайте перевагу цьому варіанту замість TCP і запускайте контейнер із **відсутнім мережевим стеком**:
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
- `--network none` усуває вхідну/вихідну експозицію TCP/IP і уникає user-mode helpers, які в іншому разі були б потрібні rootless containers.
- UNIX socket дає змогу використовувати POSIX permissions/ACLs для шляху до socket як перший рівень контролю доступу.
- `--userns=keep-id` і rootless Podman зменшують наслідки container breakout, оскільки root у контейнері не є root на host.
- Read-only model mounts зменшують імовірність tampering із моделлю зсередини контейнера.

### Мінімізація GPU device-node

Для inference із використанням GPU файли `/dev/nvidia*` є цінними локальними attack surfaces, оскільки вони відкривають великі обробники драйвера `ioctl()` і потенційно спільні шляхи керування пам’яттю GPU.

- Не залишайте `/dev/nvidia*` доступними для запису всім користувачам.
- Обмежте `nvidia`, `nvidiactl` і `nvidia-uvm` за допомогою `NVreg_DeviceFileUID/GID/Mode`, udev rules і ACLs, щоб лише зіставлений container UID міг відкривати їх.
- Вимкніть непотрібні модулі, такі як `nvidia_drm`, `nvidia_modeset` і `nvidia_peermem`, на headless inference hosts.
- Завантажуйте під час boot лише необхідні модулі замість того, щоб runtime безумовно виконував `modprobe` під час запуску inference.

Приклад:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Один важливий момент для перевірки — **`/dev/nvidia-uvm`**. Навіть якщо workload явно не використовує `cudaMallocManaged()`, останні версії CUDA runtimes все одно можуть вимагати `nvidia-uvm`. Оскільки цей пристрій є спільним і відповідає за керування віртуальною пам'яттю GPU, розглядайте його як поверхню міжорендного витоку даних. Якщо inference backend це підтримує, Vulkan backend може бути цікавим компромісом, оскільки він може взагалі не вимагати надання `nvidia-uvm` контейнеру.

### LSM confinement для inference workers

AppArmor/SELinux/seccomp слід використовувати як defense in depth навколо inference process:

- Дозволяйте лише спільні libraries, model paths, socket directory і GPU device nodes, які справді потрібні.
- Явно забороняйте високоризикові capabilities, такі як `sys_admin`, `sys_module`, `sys_rawio` і `sys_ptrace`.
- Залишайте model directory доступною лише для читання, а writable paths обмежте лише runtime socket/cache directories.
- Відстежуйте denial logs, оскільки вони надають корисну telemetry для виявлення, коли model server або post-exploitation payload намагається вийти за межі очікуваної поведінки.

Приклад правил AppArmor для GPU-backed worker:
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
## Phantom Squatting: домени, галюциновані LLM, як вектор AI supply-chain

Phantom squatting — це **еквівалент slopsquatting для доменів/URL**. Замість галюцинації неіснуючої назви пакета LLM галюцинує правдоподібний **портал, API, webhook, billing, SSO, download або support-домен** реального бренду, а attacker реєструє цей namespace до того, як його використає людина або agent.

Це важливо, оскільки в багатьох workflow з AI-вбудованими можливостями результат моделі сприймається як **довірена dependency**:
- Developers вставляють запропонований endpoint у code або CI/CD integrations.
- AI agents автоматично отримують documentation, schemas, APKs, ZIPs або webhook targets.
- Згенеровані runbooks або docs можуть містити fake URL так, ніби він є authoritative.

### Offensive workflow

1. **Probe the hallucination surface**: ставте запитання, специфічні для бренду, про реалістичні workflow, наприклад портали `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` або `mobile app`.
2. **Normalize candidates**: розв’язуйте згенеровані URLs, зводьте NXDOMAIN responses до parent registerable domain і дедуплікуйте prompt families. Prompt corpora мають залишатися різноманітними, наприклад шляхом видалення near-duplicates за **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: той самий fake domain з’являється за різних temperature, включно з низькою temperature, наприклад `T=0.1`.
- **Cross-model consensus**: кілька LLM families генерують той самий fake domain.
4. **Register and weaponize** parent domain, потім розміщуйте phishing, fake APK/ZIP downloads, credential harvesters, malicious docs або API endpoints, які збирають secrets/webhook payloads. **Pure domain-level hallucinations** найпростіше монетизувати, оскільки attacker контролює весь namespace; subdomain/path hallucinations також можна використати, якщо normalized parent не зареєстрований.
5. **Exploit the zero-reputation window**: щойно зареєстровані domains часто не мають blocklist history, URL reputation і зрілої telemetry, тому можуть обходити controls, доки detections не наздоженуть. Attackers можуть продовжити це вікно за допомогою benign responses лише для crawlers, redirect cloaking, CAPTCHA gates або відкладеного payload staging.

### Why it is dangerous for agents

Для human victim fake domain зазвичай все ще потребує click і додаткової дії. В **agentic workflow** LLM може одночасно бути **lure** і **executor**: agent отримує hallucinated URL, fetches його, parses response, а потім може leak tokens, execute instructions, download a dependency або push poisoned data у CI/CD без будь-якого human review.

### Practical attacker prompts

High-yield prompts зазвичай виглядають як звичайні enterprise tasks, а не як явні phishing lures:
- “Який payment sandbox URL для integrations `<brand>`?”
- “Який webhook endpoint слід використовувати для build notifications `<brand>`?”
- “Де розташований employee benefits / billing / SSO portal для `<brand>`?”
- “Надай пряме завантаження Android APK або desktop client для `<brand>`.”

### Defensive inversion

Розглядайте це як proactive domain-monitoring problem, а не лише як prompt-injection problem:
- Створіть **brand prompt corpus** і періодично probe-те LLMs, на які покладаються ваші users/agents.
- Зберігайте hallucinated URLs і відстежуйте, які з них стабільні за різних temperatures/models.
- Відстежуйте **Adversarial Exploitation Window (AEW)**: час між першою hallucination і attacker registration. Позитивний AEW означає, що defenders можуть pre-register, sinkhole або pre-block домени до weaponization.
- Відстежуйте переходи **NXDOMAIN → registered** для parent domains.
- Після registration перевіряйте registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status і схожість brand assets.
- Додайте policy gates, щоб agents/developers **не довіряли LLM-generated domains за замовчуванням**: вимагайте allowlists, ownership validation, CT/RDAP checks або human approval перед першим використанням.

Це одночасно належить до кількох AI risk buckets: **AI supply-chain attack**, **insecure model output** і **rogue actions**, коли agents автономно споживають hallucinated URL.

## References
- [Unit 42 – Ризики Code Assistant LLMs: шкідливий контент, зловживання та deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Огляд LLMJacking scheme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (перепродаж викраденого LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive у deployment on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: домени, галюциновані AI, як Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: як AI hallucinations спричиняють новий клас Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
