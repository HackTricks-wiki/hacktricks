# Ризики AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP визначила 10 головних вразливостей machine learning, які можуть впливати на AI-системи. Ці вразливості можуть призводити до різноманітних проблем безпеки, зокрема отруєння даних, інверсії моделі та adversarial attacks. Розуміння цих вразливостей має вирішальне значення для побудови безпечних AI-систем.

Оновлений і детальний перелік 10 головних вразливостей machine learning наведено в проєкті [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Зловмисник додає невеликі, часто невидимі зміни до **вхідних даних**, через що модель ухвалює неправильне рішення.\
*Приклад*: Кілька плям фарби на знаку STOP змушують автомобіль із self-driving системою "побачити" знак обмеження швидкості.

- **Data Poisoning Attack**: **Training set** навмисно забруднюється шкідливими зразками, навчаючи модель небезпечних правил.\
*Приклад*: Бінарні файли malware позначаються як "benign" у training corpus антивіруса, що дозволяє подібному malware обходити перевірку надалі.

- **Model Inversion Attack**: Аналізуючи outputs, зловмисник створює **reverse model**, яка відновлює чутливі характеристики оригінальних inputs.\
*Приклад*: Відтворення MRI-зображення пацієнта на основі прогнозів моделі виявлення раку.

- **Membership Inference Attack**: Adversary перевіряє, чи використовувався **конкретний запис** під час training, аналізуючи відмінності у рівнях впевненості.\
*Приклад*: Підтвердження того, що банківська транзакція певної особи міститься у training data моделі виявлення шахрайства.

- **Model Theft**: Повторні запити дозволяють зловмиснику вивчити decision boundaries і **клонувати поведінку моделі** (та IP).\
*Приклад*: Збір достатньої кількості пар Q&A з ML-as-a-Service API для створення майже еквівалентної локальної моделі.

- **AI Supply-Chain Attack**: Компрометація будь-якого компонента (даних, бібліотек, pre-trained weights, CI/CD) у **ML pipeline** для пошкодження downstream-моделей.\
*Приклад*: Отруєна dependency у model-hub встановлює backdoored модель аналізу настроїв у багатьох застосунках.

- **Transfer Learning Attack**: Шкідлива логіка вбудовується в **pre-trained model** і зберігається після fine-tuning під задачу жертви.\
*Приклад*: Vision backbone із прихованим trigger продовжує змінювати labels після адаптації для medical imaging.

- **Model Skewing**: Непомітно упереджені або неправильно позначені дані **зміщують outputs моделі**, спрямовуючи їх на користь цілей зловмисника.\
*Приклад*: Додавання "чистих" spam-листів, позначених як ham, щоб spam filter пропускав подібні майбутні листи.

- **Output Integrity Attack**: Зловмисник **змінює predictions моделі під час передавання**, не змінюючи саму модель, і вводить downstream-системи в оману.\
*Приклад*: Заміна verdict класифікатора malware з "malicious" на "benign" до того, як його побачить етап file-quarantine.

- **Model Poisoning** --- Прямі, цілеспрямовані зміни самих **параметрів моделі**, часто після отримання write access, для зміни її поведінки.\
*Приклад*: Зміна weights production-моделі виявлення шахрайства так, щоб транзакції з певних карток завжди схвалювалися.


## Ризики Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) від Google описує різні ризики, пов'язані з AI-системами:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Зловмисники змінюють або додають training/tuning data, щоб погіршити точність, вбудувати backdoors або змістити результати, підриваючи цілісність моделі протягом усього data-lifecycle.

- **Unauthorized Training Data**: Використання захищених авторським правом, чутливих або несанкціонованих datasets створює юридичні, етичні та пов'язані з продуктивністю ризики, оскільки модель навчається на даних, які їй ніколи не дозволяли використовувати.

- **Model Source Tampering**: Supply-chain або insider-маніпуляції з кодом моделі, dependencies чи weights до або під час training можуть вбудувати приховану логіку, яка зберігається навіть після retraining.

- **Excessive Data Handling**: Слабкі засоби контролю зберігання даних і governance змушують системи зберігати або обробляти більше персональних даних, ніж необхідно, підвищуючи ризики витоку та недотримання вимог.

- **Model Exfiltration**: Зловмисники викрадають файли/weights моделі, що призводить до втрати інтелектуальної власності та уможливлює створення копій сервісів або подальші attacks.

- **Model Deployment Tampering**: Adversaries змінюють model artifacts або serving infrastructure, через що запущена модель відрізняється від перевіреної версії, потенційно змінюючи її поведінку.

- **Denial of ML Service**: Flooding APIs або надсилання “sponge” inputs може вичерпати обчислювальні ресурси/енергію та вивести модель з ладу, наслідуючи класичні DoS attacks.

- **Model Reverse Engineering**: Збираючи велику кількість пар input-output, зловмисники можуть клонувати або distil модель, створюючи продукти-імітації та спеціалізовані adversarial attacks.

- **Insecure Integrated Component**: Вразливі plugins, agents або upstream-сервіси дозволяють зловмисникам впроваджувати code або підвищувати privileges у межах AI pipeline.

- **Prompt Injection**: Створення prompts (безпосередньо або опосередковано) для прихованого додавання інструкцій, які перевизначають призначення системи та змушують модель виконувати ненавмисні команди.

- **Model Evasion**: Ретельно розроблені inputs змушують модель неправильно класифікувати, вигадувати або виводити заборонений content, підриваючи безпеку та довіру.

- **Sensitive Data Disclosure**: Модель розкриває приватну або конфіденційну інформацію зі своїх training data чи user context, порушуючи privacy та regulatory requirements.

- **Inferred Sensitive Data**: Модель виводить персональні характеристики, які ніколи не надавалися, створюючи нову шкоду privacy через inference.

- **Insecure Model Output**: Несанітизовані responses передають користувачам або downstream-системам шкідливий code, misinformation чи inappropriate content.

- **Rogue Actions**: Autonomously-integrated agents виконують ненавмисні операції у реальному світі (запис файлів, API calls, покупки тощо) без належного user oversight.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає комплексну framework для розуміння та зменшення ризиків, пов'язаних з AI-системами. Вона категоризує різні attack techniques і tactics, які adversaries можуть застосовувати проти AI-моделей, а також способи використання AI-систем для виконання різних attacks.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Зловмисники викрадають активні session tokens або cloud API credentials і без дозволу викликають платні cloud-hosted LLMs. Доступ часто перепродається через reverse proxies, які використовують account жертви, наприклад deployments "oai-reverse-proxy". Наслідки включають фінансові втрати, використання моделі всупереч policy та attribution до tenant жертви.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Збирати tokens із заражених developer machines або browsers; викрадати CI/CD secrets; купувати leaked cookies.<sup>[[5]](#references)</sup>
- Розгорнути reverse proxy, який пересилає requests справжньому provider, приховуючи upstream key і multiplexing багатьох customers.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Зловживати direct base-model endpoints, щоб обходити enterprise guardrails і rate limits.<sup>[[4]](#references)</sup>

Mitigations:
- Прив'язувати tokens до device fingerprint, IP ranges і client attestation; встановлювати короткі терміни дії та виконувати refresh за допомогою MFA.
- Обмежувати keys до мінімально необхідних permissions (без tool access, read-only за потреби); виконувати rotation у разі anomaly.
- Завершувати весь traffic на server-side за policy gateway, який застосовує safety filters, per-route quotas та tenant isolation.
- Відстежувати незвичні patterns використання (раптові spikes витрат, нетипові regions, UA strings) і автоматично відкликати підозрілі sessions.
- Надавати перевагу mTLS або signed JWTs, виданим вашим IdP, замість довгоживучих static API keys.

## Посилення безпеки self-hosted LLM inference

Запуск локального LLM-сервера для конфіденційних даних створює іншу attack surface порівняно з cloud-hosted APIs: inference/debug endpoints можуть спричинити leak prompts, serving stack зазвичай відкриває reverse proxy, а GPU device nodes надають доступ до великих `ioctl()` surfaces. Якщо ви оцінюєте або розгортаєте on-prem inference service, перевірте щонайменше наведені нижче пункти.<sup>[[8]](#references)</sup>

### Витік prompts через debug і monitoring endpoints

Розглядайте inference API як **multi-user sensitive service**. Debug або monitoring routes можуть розкривати prompt contents, slot state, model metadata або internal queue information. У `llama.cpp` endpoint `/slots` є особливо чутливим, оскільки розкриває per-slot state і призначений лише для slot inspection/management.<sup>[[8]](#references)</sup>

- Розмістіть reverse proxy перед inference server і **забороняйте все за замовчуванням**.
- Дозволяйте в allowlist лише точні комбінації HTTP method + path, необхідні client/UI.
- За можливості вимикайте introspection endpoints безпосередньо в backend, наприклад `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Прив'яжіть reverse proxy до `127.0.0.1` і надавайте доступ через authenticated transport, наприклад SSH local port forwarding, замість публікації в LAN.

Приклад allowlist із nginx:
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

Якщо inference daemon підтримує прослуховування UNIX-сокета, надавайте перевагу йому перед TCP і запускайте контейнер із **відсутнім мережевим стеком**:<sup>[[8]](#references)</sup>
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
- `--network none` усуває вхідну/вихідну експозицію TCP/IP і не допускає використання user-mode helpers, які в іншому разі були б потрібні rootless containers.
- UNIX socket дає змогу використовувати POSIX permissions/ACLs для шляху до socket як перший рівень контролю доступу.
- `--userns=keep-id` і rootless Podman зменшують вплив container breakout, оскільки root у container не є root на host.
- Read-only model mounts зменшують імовірність tampering моделі зсередини container.

Для persistent deployments ті самі обмеження можна задати за допомогою Podman Quadlet units. Якщо GPU access делегується через Container Device Interface, специфікацію CDI device слід обмежити якомога сильніше, а не відкривати кожен accelerator node.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Мінімізація GPU device-node

Для GPU-backed inference файли `/dev/nvidia*` є цінними локальними attack surfaces, оскільки відкривають великі driver `ioctl()` handlers і потенційно спільні GPU memory-management paths.<sup>[[8]](#references)</sup>

- Не залишайте `/dev/nvidia*` доступними для запису всім користувачам.
- Обмежте `nvidia`, `nvidiactl` і `nvidia-uvm` за допомогою `NVreg_DeviceFileUID/GID/Mode`, udev rules і ACLs, щоб лише mapped container UID міг їх відкривати.
- Заблокуйте непотрібні modules, як-от `nvidia_drm`, `nvidia_modeset` і `nvidia_peermem`, на headless inference hosts.
- Попередньо завантажуйте лише потрібні modules під час boot замість того, щоб дозволяти runtime opportunistically виконувати `modprobe` під час запуску inference.

Приклад:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Одним із важливих пунктів перевірки є **`/dev/nvidia-uvm`**. Навіть якщо workload явно не використовує `cudaMallocManaged()`, нові версії CUDA runtimes все одно можуть потребувати `nvidia-uvm`. Оскільки цей пристрій є спільним і відповідає за керування віртуальною пам’яттю GPU, його слід розглядати як поверхню витоку даних між tenants. Якщо inference backend це підтримує, Vulkan backend може бути цікавим компромісом, оскільки він може взагалі не вимагати надання `nvidia-uvm` контейнеру.<sup>[[8]](#references)</sup>

### LSM-ізоляція для inference workers

AppArmor/SELinux/seccomp слід використовувати як додатковий рівень захисту для inference process:<sup>[[8]](#references)</sup>

- Дозволяйте лише ті shared libraries, model paths, socket directory та GPU device nodes, які фактично потрібні.
- Явно забороняйте high-risk capabilities, як-от `sys_admin`, `sys_module`, `sys_rawio` і `sys_ptrace`.
- Залишайте model directory доступною лише для читання, а writable paths обмежте лише runtime socket/cache directories.
- Відстежуйте denial logs, оскільки вони надають корисну telemetry для виявлення спроб model server або post-exploitation payload вийти за межі очікуваної поведінки.

Приклад правил AppArmor для worker із підтримкою GPU:
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
## Phantom Squatting: домени, галюциновані LLM, як вектор атаки на AI supply chain

Phantom squatting — це **еквівалент slopsquatting для доменів/URL**. Замість галюцинації неіснуючої назви пакета, LLM галюцинує правдоподібний **портал, API, webhook, billing-, SSO-, download- або support-домен** реального бренду, а зловмисник реєструє цей namespace до того, як його використає людина або агент.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Це важливо, оскільки в багатьох workflow з підтримкою AI результат моделі сприймається як **довірена залежність**:
- Розробники вставляють запропонований endpoint у код або інтеграції CI/CD.
- AI-агенти автоматично отримують документацію, схеми, APK, ZIP або цілі webhook.
- Згенеровані runbook або документація можуть містити фальшивий URL так, ніби він є авторитетним.

### Offensive workflow

1. **Probe the hallucination surface**: ставте специфічні для бренду запитання про реалістичні workflow, наприклад портали `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` або `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: обробляйте згенеровані URL, зводьте відповіді NXDOMAIN до батьківського домену, доступного для реєстрації, і видаляйте дублікати між сімействами prompt. Prompt corpora мають залишатися різноманітними, наприклад шляхом видалення майже дублікатів із використанням **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: той самий фальшивий домен з’являється за різних temperature, зокрема за низької temperature, як `T=0.1`.
- **Cross-model consensus**: кілька сімейств LLM генерують той самий фальшивий домен.
4. **Register and weaponize** батьківський домен, а потім розмістіть phishing, фальшиві APK/ZIP-завантаження, credential harvesters, шкідливі документи або API endpoints, що збирають secrets/webhook payloads. **Pure domain-level hallucinations** найпростіше монетизувати, оскільки зловмисник контролює весь namespace; hallucinations субдоменів/шляхів також можна використовувати, якщо нормалізований батьківський домен не зареєстрований.
5. **Exploit the zero-reputation window**: нещодавно зареєстровані домени часто не мають історії у blocklist, URL reputation і зрілої telemetry, тому можуть обходити засоби контролю, доки detections не наздоженуть їх. Зловмисники можуть продовжити це вікно за допомогою benign-відповідей лише для crawler, redirect cloaking, CAPTCHA gates або відкладеного розгортання payload.

### Why it is dangerous for agents

Для людини-жертви фальшивий домен зазвичай все ще потребує кліку та додаткової дії. В **agentic workflow** LLM може бути одночасно **lure** і **executor**: агент отримує hallucinated URL, завантажує його, аналізує відповідь, а потім може leak tokens, виконати інструкції, завантажити dependency або передати poisoned data у CI/CD без перевірки людиною.<sup>[[12]](#references)</sup>

### Practical attacker prompts

Високоефективні prompts зазвичай виглядають як звичайні enterprise-завдання, а не як явні phishing lures:<sup>[[12]](#references)</sup>
- “Який URL payment sandbox для інтеграцій `<brand>`?”
- “Який webhook endpoint слід використовувати для build notifications `<brand>`?”
- “Де розташований employee benefits / billing / SSO portal для `<brand>`?”
- “Надай пряме завантаження Android APK або desktop client для `<brand>`.”

### Defensive inversion

Розглядайте це як проактивну проблему domain monitoring, а не лише як проблему prompt injection:<sup>[[12]](#references)</sup>
- Створіть **brand prompt corpus** і періодично перевіряйте LLM, на які покладаються ваші користувачі/агенти.
- Зберігайте hallucinated URLs і відстежуйте, які з них стабільні за різних temperatures/models.
- Відстежуйте **Adversarial Exploitation Window (AEW)**: час між першою hallucination і реєстрацією зловмисником. Позитивний AEW означає, що defenders можуть зареєструвати домен наперед, спрямувати його в sinkhole або додати до pre-block до weaponization.
- Відстежуйте переходи **NXDOMAIN → registered** для батьківських доменів.
- Після реєстрації перевіряйте registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status і схожість brand assets.
- Додайте policy gates, щоб агенти/розробники **не довіряли LLM-generated domains за замовчуванням**: вимагайте allowlists, перевірку ownership, CT/RDAP checks або human approval перед першим використанням.

Це одночасно відповідає кільком категоріям AI-ризиків: **AI supply-chain attack**, **insecure model output** і **rogue actions**, коли агенти автономно використовують hallucinated URL.

## References

- [1] [OWASP Top 10 вразливостей Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Ризики](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Ризики LLM Code Assistant: шкідливий контент, зловживання та обман](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: викрадені Cloud Credentials використані в новій AI-атаці](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Огляд схеми LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (перепродаж викраденого доступу до LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – детальний аналіз розгортання on-premise LLM server з низькими привілеями](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README сервера llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Специфікація CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: домени, галюциновані AI, як вектор атаки на Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: як AI-галюцинації спричиняють новий клас атак на Supply Chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
