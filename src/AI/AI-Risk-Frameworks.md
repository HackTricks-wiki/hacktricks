# Ризики AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 вразливостей Machine Learning

Owasp визначила 10 основних вразливостей Machine Learning, які можуть впливати на AI-системи. Ці вразливості можуть призводити до різних проблем безпеки, зокрема отруєння даних, інверсії моделі та adversarial attacks. Розуміння цих вразливостей має вирішальне значення для створення безпечних AI-систем.

Оновлений і детальний список 10 основних вразливостей Machine Learning дивіться у проєкті [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Зловмисник додає крихітні, часто невидимі зміни до **вхідних даних**, через що модель ухвалює неправильне рішення.\
*Приклад*: Кілька плям фарби на знаку STOP змушують безпілотний автомобіль "побачити" знак обмеження швидкості.

- **Data Poisoning Attack**: **Навчальний набір** навмисно забруднюється шкідливими зразками, навчаючи модель небезпечних правил.\
*Приклад*: Бінарні файли malware позначаються як "benign" у навчальному корпусі антивіруса, завдяки чому схоже malware згодом обходить виявлення.

- **Model Inversion Attack**: Аналізуючи відповіді, зловмисник створює **зворотну модель**, яка реконструює чутливі ознаки початкових вхідних даних.\
*Приклад*: Відтворення MRI-зображення пацієнта на основі прогнозів моделі виявлення раку.

- **Membership Inference Attack**: Зловмисник перевіряє, чи використовувався **конкретний запис** під час навчання, виявляючи відмінності у рівнях впевненості.\
*Приклад*: Підтвердження того, що банківська транзакція певної особи міститься в навчальних даних моделі виявлення шахрайства.

- **Model Theft**: Повторні запити дають змогу зловмиснику вивчити межі прийняття рішень і **клонувати поведінку моделі** (та IP).\
*Приклад*: Збір достатньої кількості пар запитання-відповідь з API ML-as-a-Service для створення майже еквівалентної локальної моделі.

- **AI Supply-Chain Attack**: Компрометація будь-якого компонента (даних, бібліотек, pre-trained weights, CI/CD) у **ML pipeline** для пошкодження подальших моделей.\
*Приклад*: Отруєна dependency з model-hub встановлює модель аналізу настроїв із backdoor у багатьох застосунках.

- **Transfer Learning Attack**: Шкідлива логіка вбудовується в **pre-trained model** і зберігається після fine-tuning під завдання жертви.\
*Приклад*: Vision backbone із прихованим тригером продовжує змінювати мітки після адаптації для medical imaging.

- **Model Skewing**: Непомітно упереджені або неправильно марковані дані **зміщують виходи моделі**, спрямовуючи їх на користь цілей зловмисника.\
*Приклад*: Додавання "чистих" spam-листів із міткою ham, щоб spam-фільтр пропускав схожі майбутні листи.

- **Output Integrity Attack**: Зловмисник **змінює прогнози моделі під час передавання**, не змінюючи саму модель, і вводить в оману downstream-системи.\
*Приклад*: Заміна вердикту malware-класифікатора з "malicious" на "benign" до того, як його побачить етап ізоляції файлу.

- **Model Poisoning** --- Прямі, цілеспрямовані зміни самих **параметрів моделі**, часто після отримання доступу на запис, для зміни її поведінки.\
*Приклад*: Зміна weights у production-моделі виявлення шахрайства, щоб транзакції з певних карток завжди схвалювалися.


## Ризики Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) від Google описує різні ризики, пов'язані з AI-системами:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Зловмисники змінюють або додають training/tuning data, щоб погіршити точність, вбудувати backdoor або спотворити результати, підриваючи цілісність моделі протягом усього data-lifecycle.

- **Unauthorized Training Data**: Використання захищених авторським правом, чутливих або несанкціонованих datasets створює юридичні, етичні та експлуатаційні ризики, оскільки модель навчається на даних, які їй ніколи не дозволяли використовувати.

- **Model Source Tampering**: Маніпуляції з code, dependencies або weights моделі з боку supply-chain чи інсайдера до або під час навчання можуть вбудувати приховану логіку, яка зберігається навіть після повторного навчання.

- **Excessive Data Handling**: Слабкі засоби зберігання даних і governance змушують системи зберігати або обробляти більше персональних даних, ніж необхідно, підвищуючи ризики витоку та недотримання вимог.

- **Model Exfiltration**: Зловмисники викрадають файли/weights моделі, що спричиняє втрату інтелектуальної власності та дає змогу створювати копіювальні сервіси або здійснювати подальші атаки.

- **Model Deployment Tampering**: Зловмисники змінюють артефакти моделі або serving infrastructure, через що запущена модель відрізняється від перевіреної версії та потенційно змінює поведінку.

- **Denial of ML Service**: Переповнення API або надсилання “sponge” inputs може виснажити обчислювальні ресурси/енергію та вивести модель з ладу, що нагадує класичні DoS-атаки.

- **Model Reverse Engineering**: Збираючи велику кількість пар input-output, зловмисники можуть клонувати або дистилювати модель, створюючи продукти-імітації та спеціалізовані adversarial attacks.

- **Insecure Integrated Component**: Вразливі plugins, agents або upstream-сервіси дають зловмисникам змогу впроваджувати code або підвищувати привілеї в AI pipeline.

- **Prompt Injection**: Створення prompts (безпосередньо або опосередковано) для прихованого передавання інструкцій, які перевизначають системний намір і змушують модель виконувати ненавмисні команди.

- **Model Evasion**: Ретельно створені inputs змушують модель неправильно класифікувати, галюцинувати або виводити заборонений контент, підриваючи безпеку та довіру.

- **Sensitive Data Disclosure**: Модель розкриває приватну або конфіденційну інформацію зі своїх training data чи user context, порушуючи privacy та нормативні вимоги.

- **Inferred Sensitive Data**: Модель виводить персональні атрибути, які ніколи не надавалися, створюючи нові ризики для privacy через inference.

- **Insecure Model Output**: Неочищені відповіді передають користувачам або downstream-системам шкідливий code, дезінформацію чи неприйнятний контент.

- **Rogue Actions**: Автономно інтегровані agents виконують ненавмисні операції у реальному світі (запис файлів, API-виклики, покупки тощо) без належного контролю користувача.

## Матриця Mitre AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає комплексну framework для розуміння ризиків, пов'язаних з AI-системами, та протидії їм. Вона класифікує різні attack techniques і tactics, які зловмисники можуть застосовувати проти AI-моделей, а також способи використання AI-систем для виконання різних атак.<sup>[[12]](#references)</sup>

## LLMJacking (викрадення токенів і перепродаж доступу до LLM, розміщених у cloud)

Зловмисники викрадають активні session tokens або cloud API credentials і без дозволу викликають платні LLM, розміщені у cloud. Доступ часто перепродається через reverse proxies, які працюють через обліковий запис жертви, наприклад deployments "oai-reverse-proxy". Наслідки включають фінансові збитки, використання моделі всупереч policy та прив'язку активності до tenant жертви.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Збирати tokens із заражених developer machines або browsers; викрадати CI/CD secrets; купувати leaked cookies.
- Розгорнути reverse proxy, який пересилає requests справжньому провайдеру, приховуючи upstream key і мультиплексуючи багатьох клієнтів.
- Зловживати direct base-model endpoints для обходу enterprise guardrails і rate limits.

Mitigations:
- Прив'язувати tokens до device fingerprint, діапазонів IP та client attestation; встановлювати короткі терміни дії та виконувати refresh із MFA.
- Мінімально обмежувати keys (без tool access, read-only де можливо); виконувати ротацію у разі аномалій.
- Завершувати весь traffic на стороні сервера за policy gateway, який застосовує safety filters, per-route quotas і tenant isolation.
- Відстежувати незвичні patterns використання (раптові стрибки витрат, нетипові регіони, UA strings) і автоматично відкликати підозрілі sessions.
- Віддавати перевагу mTLS або signed JWTs, виданим вашим IdP, замість static API keys із тривалим терміном дії.

## Посилення безпеки self-hosted LLM inference

Запуск локального LLM server для конфіденційних даних створює іншу attack surface порівняно з cloud-hosted APIs: inference/debug endpoints можуть спричинити leak prompts, serving stack зазвичай відкриває reverse proxy, а GPU device nodes надають доступ до великих поверхонь `ioctl()`. Якщо ви оцінюєте або розгортаєте on-prem inference service, перевірте принаймні наведені нижче аспекти.<sup>[[4]](#references)</sup>

### Витік prompts через debug і monitoring endpoints

Розглядайте inference API як **чутливий multi-user service**. Debug або monitoring routes можуть розкривати вміст prompts, стан слотів, metadata моделі або внутрішню інформацію про queue. У `llama.cpp` endpoint `/slots` є особливо чутливим, оскільки розкриває стан окремих слотів і призначений лише для їх перевірки/керування.<sup>[[4]](#references)[[5]](#references)</sup>

- Розмістіть reverse proxy перед inference server і **забороняйте все за замовчуванням**.
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
- `--network none` усуває вхідну/вихідну експозицію TCP/IP і не використовує user-mode helpers, які інакше були б потрібні rootless containers.
- UNIX socket дає змогу використовувати POSIX permissions/ACLs для шляху до socket як перший рівень контролю доступу.
- `--userns=keep-id` і rootless Podman зменшують вплив container breakout, оскільки root у container не є root на host.
- Read-only model mounts зменшують ймовірність tampering із моделлю зсередини container.

### Мінімізація GPU device-node

Для inference із використанням GPU файли `/dev/nvidia*` є цінними локальними attack surfaces, оскільки вони відкривають великі обробники драйвера `ioctl()` і потенційно спільні шляхи керування пам’яттю GPU.<sup>[[4]](#references)</sup>

- Не залишайте `/dev/nvidia*` доступними для запису всім.
- Обмежте `nvidia`, `nvidiactl` і `nvidia-uvm` за допомогою `NVreg_DeviceFileUID/GID/Mode`, udev rules і ACLs, щоб лише відповідний container UID міг їх відкривати.
- Заблокуйте непотрібні modules, такі як `nvidia_drm`, `nvidia_modeset` і `nvidia_peermem`, на headless inference hosts.
- Завантажуйте лише необхідні modules під час boot замість того, щоб runtime ситуативно виконував `modprobe` під час запуску inference.

Приклад:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Одним із важливих пунктів перевірки є **`/dev/nvidia-uvm`**. Навіть якщо workload явно не використовує `cudaMallocManaged()`, нові версії CUDA runtime все одно можуть вимагати `nvidia-uvm`. Оскільки цей пристрій є спільним і відповідає за керування віртуальною пам’яттю GPU, розглядайте його як поверхню витоку даних між tenant'ами. Якщо inference backend це підтримує, Vulkan backend може бути цікавим компромісом, оскільки він може взагалі не вимагати надання `nvidia-uvm` контейнеру.

### LSM-ізоляція inference workers

AppArmor/SELinux/seccomp слід використовувати як додатковий рівень захисту навколо inference-процесу:<sup>[[4]](#references)</sup>

- Дозволяйте лише спільні бібліотеки, шляхи до моделей, каталог сокетів і вузли пристроїв GPU, які справді необхідні.
- Явно забороняйте високоризикові capabilities, такі як `sys_admin`, `sys_module`, `sys_rawio` і `sys_ptrace`.
- Залишайте каталог моделей доступним лише для читання, а writable paths обмежте лише каталогами runtime socket/cache.
- Відстежуйте denial logs, оскільки вони надають корисну telemetry для виявлення спроб model server або post-exploitation payload вийти за межі очікуваної поведінки.

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

Phantom squatting є **еквівалентом slopsquatting для доменів/URL**. Замість галюцинації назви неіснуючого пакета LLM галюцинує правдоподібний **портал, API, webhook, billing, SSO, download або support-домен** реального бренду, а атакер реєструє цей namespace до того, як його використає людина або агент.<sup>[[8]](#references)[[9]](#references)</sup>

Це важливо, оскільки в багатьох AI-assisted workflow результат моделі сприймається як **довірена залежність**:
- Розробники вставляють запропонований endpoint у код або інтеграції CI/CD.
- AI-агенти автоматично отримують документацію, схеми, APK, ZIP або цілі webhook.
- Згенеровані runbook або документація можуть містити фальшивий URL так, ніби він є офіційним.

### Offensive workflow

1. **Probe the hallucination surface**: ставте запитання, специфічні для бренду, про реалістичні workflow, наприклад портали `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` або `mobile app`.
2. **Normalize candidates**: розв'язуйте згенеровані URL, зводьте відповіді NXDOMAIN до батьківського домену, який можна зареєструвати, і дедуплікуйте сімейства prompt. Prompt corpus має залишатися різноманітним, наприклад шляхом видалення майже дублікатів із використанням **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: той самий фальшивий домен з'являється за різних temperature, включно з низькою temperature, як-от `T=0.1`.
- **Cross-model consensus**: кілька сімейств LLM генерують той самий фальшивий домен.
4. **Register and weaponize** батьківський домен, а потім розмістіть phishing, фальшиві APK/ZIP downloads, credential harvesters, шкідливі документи або API endpoints, що збирають secrets/webhook payloads. **Pure domain-level hallucinations** найпростіше монетизувати, оскільки атакер контролює весь namespace; hallucinations піддоменів/шляхів також можна використати, якщо нормалізований батьківський домен не зареєстрований.
5. **Exploit the zero-reputation window**: щойно зареєстровані домени часто не мають історії у blocklist, URL reputation і зрілої telemetry, тому можуть обходити засоби контролю, доки detections не наздоженуть їх. Атакери можуть продовжити це вікно за допомогою benign-відповідей лише для crawler, redirect cloaking, CAPTCHA gates або відкладеного payload staging.

### Чому це небезпечно для агентів

Для людини-жертви фальшивий домен зазвичай усе ще потребує кліку та додаткової дії. В **agentic workflow** LLM може бути одночасно **lure** і **executor**: агент отримує галюцинований URL, відкриває його, аналізує відповідь, а потім може leak tokens, виконати інструкції, завантажити dependency або передати poisoned data у CI/CD без будь-якої перевірки людиною.<sup>[[8]](#references)</sup>

### Practical attacker prompts

High-yield prompts зазвичай виглядають як звичайні enterprise tasks, а не як явні phishing lures:
- “Який URL payment sandbox для інтеграцій `<brand>`?”
- “Який webhook endpoint слід використовувати для build notifications `<brand>`?”
- “Де розташований employee benefits / billing / SSO portal для `<brand>`?”
- “Надай пряме завантаження Android APK або desktop client для `<brand>`.”

### Defensive inversion

Розглядайте це як proactive domain-monitoring problem, а не лише як prompt-injection problem:
- Створіть **brand prompt corpus** і періодично перевіряйте LLM, на які покладаються ваші користувачі/агенти.
- Зберігайте hallucinated URLs і відстежуйте, які з них стабільні за різних temperatures/models.
- Відстежуйте **Adversarial Exploitation Window (AEW)**: час між першою галюцинацією та реєстрацією атакером. Позитивний AEW означає, що defenders можуть попередньо зареєструвати, sinkhole або pre-block домен до weaponization.
- Відстежуйте переходи **NXDOMAIN → registered** для батьківських доменів.
- Після реєстрації перевіряйте registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status і схожість brand assets.
- Додайте policy gates, щоб агенти/розробники **не довіряли LLM-generated domains за замовчуванням**: вимагайте allowlists, ownership validation, CT/RDAP checks або human approval перед першим використанням.

Це одночасно відповідає кільком AI risk buckets: **AI supply-chain attack**, **insecure model output** і **rogue actions**, коли агенти автономно споживають hallucinated URL.

## References
- [1] [Unit 42 – Ризики Code Assistant LLM: шкідливий контент, зловживання та обман](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [Огляд схеми LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (перепродаж викраденого доступу до LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Детальний аналіз розгортання on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [README сервера llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [Специфікація CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: домени, галюциновані AI, як вектор Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: як AI hallucinations спричиняють новий клас Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
