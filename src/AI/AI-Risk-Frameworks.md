# Ризики AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp визначила 10 основних вразливостей machine learning, які можуть впливати на AI-системи. Ці вразливості можуть призводити до різних проблем безпеки, зокрема data poisoning, model inversion та adversarial attacks. Розуміння цих вразливостей має вирішальне значення для створення безпечних AI-систем.

Оновлений і детальний список 10 основних вразливостей machine learning дивіться у проєкті [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Зловмисник додає крихітні, часто невидимі зміни до **вхідних даних**, щоб модель ухвалила неправильне рішення.\
*Приклад*: Кілька крапок фарби на знаку STOP змушують безпілотний автомобіль "побачити" знак обмеження швидкості.

- **Data Poisoning Attack**: **Навчальний набір** навмисно забруднюється шкідливими зразками, навчаючи модель небезпечних правил.\
*Приклад*: Бінарні файли malware позначаються як "benign" у навчальному корпусі антивіруса, завдяки чому подібне malware згодом проходить повз захист.

- **Model Inversion Attack**: Аналізуючи відповіді, зловмисник створює **зворотну модель**, яка відновлює чутливі ознаки початкових вхідних даних.\
*Приклад*: Відновлення MRI-зображення пацієнта за прогнозами моделі виявлення раку.

- **Membership Inference Attack**: Зловмисник перевіряє, чи використовувався **конкретний запис** під час навчання, виявляючи відмінності у рівнях упевненості.\
*Приклад*: Підтвердження того, що банківська транзакція певної особи міститься в навчальних даних моделі виявлення шахрайства.

- **Model Theft**: Повторне надсилання запитів дає змогу зловмиснику вивчити межі ухвалення рішень і **клонувати поведінку моделі** (та її IP).\
*Приклад*: Збір достатньої кількості пар запитання-відповідь з API ML-as-a-Service для створення майже еквівалентної локальної моделі.

- **AI Supply-Chain Attack**: Компрометація будь-якого компонента (даних, бібліотек, pre-trained weights, CI/CD) у **ML pipeline** для пошкодження моделей нижчого рівня.\
*Приклад*: Отруєна dependency у model-hub встановлює backdoored модель аналізу тональності в багатьох застосунках.

- **Transfer Learning Attack**: Шкідлива логіка вбудовується в **pre-trained model** і зберігається після fine-tuning під завдання жертви.\
*Приклад*: Vision backbone із прихованим тригером і надалі змінює мітки після адаптації для медичної візуалізації.

- **Model Skewing**: Непомітно упереджені або неправильно позначені дані **зміщують результати моделі** на користь цілей зловмисника.\
*Приклад*: Додавання "чистих" spam-листів із міткою ham, щоб spam-фільтр пропускав подібні майбутні листи.

- **Output Integrity Attack**: Зловмисник **змінює прогнози моделі під час передавання**, а не саму модель, вводячи в оману downstream-системи.\
*Приклад*: Заміна висновку класифікатора malware із "malicious" на "benign" до того, як його побачить етап карантину файлу.

- **Model Poisoning** --- Прямі, цілеспрямовані зміни самих **параметрів моделі**, часто після отримання доступу на запис, для зміни її поведінки.\
*Приклад*: Зміна ваг моделі виявлення шахрайства у production, щоб транзакції з певних карток завжди схвалювалися.


## Ризики Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) від Google описує різні ризики, пов’язані з AI-системами:

- **Отруєння даних**: Зловмисники змінюють або додають навчальні дані чи дані для tuning, щоб знизити точність, вбудувати backdoors або спотворити результати, підриваючи цілісність моделі протягом усього життєвого циклу даних.

- **Несанкціоновані навчальні дані**: Використання захищених авторським правом, чутливих або не дозволених наборів даних створює юридичні, етичні та пов’язані з продуктивністю ризики, оскільки модель навчається на даних, які їй ніколи не дозволяли використовувати.

- **Підміна джерела моделі**: Маніпуляції з code, dependencies або weights моделі з боку supply chain чи інсайдера до або під час навчання можуть вбудувати приховану логіку, яка зберігається навіть після повторного навчання.

- **Надмірна обробка даних**: Слабкі засоби зберігання даних і governance призводять до того, що системи зберігають або обробляють більше персональних даних, ніж потрібно, підвищуючи ризики витоку та недотримання вимог.

- **Викрадення моделі**: Зловмисники крадуть файли або weights моделі, що призводить до втрати інтелектуальної власності та дає змогу створювати копіювальні сервіси або здійснювати подальші атаки.

- **Підміна розгортання моделі**: Зловмисники змінюють артефакти моделі або serving infrastructure, через що запущена модель відрізняється від перевіреної версії та потенційно має іншу поведінку.

- **Відмова в обслуговуванні ML**: Flooding API або надсилання “sponge” inputs може вичерпати обчислювальні ресурси чи енергію та вивести модель з ладу, подібно до класичних DoS-атак.

- **Reverse Engineering моделі**: Збираючи велику кількість пар input-output, зловмисники можуть клонувати або distil модель, сприяючи створенню імітаційних продуктів і спеціалізованих adversarial attacks.

- **Незахищений інтегрований компонент**: Вразливі plugins, agents або upstream-сервіси дають зловмисникам змогу впроваджувати code або підвищувати привілеї в AI pipeline.

- **Prompt Injection**: Створення prompts (безпосередньо або опосередковано) для прихованого передавання інструкцій, які замінюють системний задум і змушують модель виконувати ненавмисні команди.

- **Model Evasion**: Ретельно створені вхідні дані змушують модель неправильно класифікувати, галюцинувати або виводити заборонений контент, підриваючи безпеку й довіру.

- **Розкриття чутливих даних**: Модель розкриває приватну або конфіденційну інформацію зі своїх навчальних даних чи контексту користувача, порушуючи вимоги приватності та нормативні вимоги.

- **Виведені чутливі дані**: Модель робить висновки про персональні характеристики, які ніколи не надавалися, створюючи нові ризики для приватності через inference.

- **Незахищений output моделі**: Необроблені відповіді передають користувачам або downstream-системам шкідливий code, misinformation чи неприйнятний контент.

- **Несанкціоновані дії**: Автономно інтегровані agents виконують ненавмисні операції у реальному світі (запис файлів, API-виклики, покупки тощо) без належного контролю користувача.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає комплексну структуру для розуміння ризиків, пов’язаних з AI-системами, та протидії їм. Вона класифікує різні attack techniques і tactics, які adversaries можуть використовувати проти AI-моделей, а також способи використання AI-систем для виконання різних атак.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Зловмисники викрадають активні session tokens або cloud API credentials і без дозволу викликають платні cloud-hosted LLM. Доступ часто перепродається через reverse proxies, які працюють від імені облікового запису жертви, наприклад deployments "oai-reverse-proxy". Наслідки включають фінансові збитки, використання моделі всупереч політиці та прив’язування дій до tenant жертви.

TTPs:
- Збирати tokens із заражених developer-машин або browsers; викрадати secrets CI/CD; купувати leaked cookies.
- Розгортати reverse proxy, який пересилає запити справжньому provider, приховуючи upstream key і multiplexing багатьох клієнтів.
- Зловживати endpoints прямого доступу до base-model, щоб обходити enterprise guardrails і rate limits.

Mitigations:
- Прив’язувати tokens до device fingerprint, діапазонів IP і client attestation; застосовувати короткі терміни дії та виконувати refresh через MFA.
- Мінімально обмежувати keys (без tool access, read-only, де це можливо); виконувати rotation у разі аномалій.
- Завершувати весь traffic на server-side за policy gateway, який застосовує safety filters, quotas для окремих маршрутів і tenant isolation.
- Відстежувати незвичні patterns використання (раптові spikes витрат, нетипові регіони, UA strings) і автоматично відкликати підозрілі sessions.
- Надавати перевагу mTLS або signed JWTs, виданим вашим IdP, замість довготривалих static API keys.

## Посилення захисту self-hosted LLM inference

Запуск локального LLM-сервера для конфіденційних даних створює іншу attack surface порівняно з cloud-hosted API: inference/debug endpoints можуть розкривати prompts, serving stack зазвичай відкриває reverse proxy, а device nodes GPU надають доступ до великих поверхонь `ioctl()`. Якщо ви оцінюєте або розгортаєте on-prem inference-сервіс, перевірте щонайменше наведені нижче аспекти.

### Витік prompt через debug і monitoring endpoints

Розглядайте inference API як **чутливий multi-user сервіс**. Debug або monitoring routes можуть розкривати вміст prompts, стан слотів, metadata моделі або інформацію про внутрішню queue. У `llama.cpp` endpoint `/slots` є особливо чутливим, оскільки розкриває стан окремих слотів і призначений лише для їх перевірки або керування.

- Розмістіть reverse proxy перед inference-сервером і **забороняйте все за замовчуванням**.
- Дозволяйте лише точні комбінації HTTP-методу + path, необхідні клієнту або UI.
- За можливості вимикайте introspection endpoints безпосередньо в backend, наприклад `llama-server --no-slots`.
- Прив’яжіть reverse proxy до `127.0.0.1` і відкривайте його через authenticated transport, наприклад SSH local port forwarding, замість публікації в LAN.

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

Якщо inference daemon підтримує прослуховування UNIX-сокета, надавайте йому перевагу перед TCP і запускайте контейнер **без мережевого стека**:
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
- `--network none` усуває вхідну/вихідну експозицію TCP/IP і запобігає використанню user-mode helpers, які інакше були б потрібні rootless-контейнерам.
- UNIX-сокет дає змогу використовувати POSIX permissions/ACLs для шляху до сокета як перший рівень контролю доступу.
- `--userns=keep-id` і rootless Podman зменшують наслідки container breakout, оскільки root у контейнері не є root на хості.
- Монтування моделей у режимі лише для читання зменшує ймовірність tampering моделі зсередини контейнера.

### Мінімізація GPU device nodes

Для inference із використанням GPU файли `/dev/nvidia*` є цінними локальними attack surfaces, оскільки вони відкривають великі обробники драйвера `ioctl()` і потенційно спільні шляхи керування пам’яттю GPU.

- Не залишайте `/dev/nvidia*` доступними для запису всім користувачам.
- Обмежте `nvidia`, `nvidiactl` і `nvidia-uvm` за допомогою `NVreg_DeviceFileUID/GID/Mode`, правил udev і ACLs, щоб лише зіставлений UID контейнера міг їх відкривати.
- Внесіть непотрібні модулі, такі як `nvidia_drm`, `nvidia_modeset` і `nvidia_peermem`, до blacklist на headless inference hosts.
- Завантажуйте під час boot лише потрібні модулі замість того, щоб дозволяти runtime opportunistically виконувати `modprobe` під час запуску inference.

Приклад:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Одним із важливих пунктів перевірки є **`/dev/nvidia-uvm`**. Навіть якщо workload явно не використовує `cudaMallocManaged()`, нові версії CUDA runtime все одно можуть вимагати `nvidia-uvm`. Оскільки цей пристрій є спільним і відповідає за керування віртуальною пам’яттю GPU, розглядайте його як поверхню витоку даних між tenant. Якщо inference backend це підтримує, Vulkan backend може бути цікавим компромісом, оскільки він може взагалі не вимагати надання `nvidia-uvm` контейнеру.

### LSM-ізоляція для inference workers

AppArmor/SELinux/seccomp слід використовувати як додатковий рівень захисту навколо inference-процесу:

- Дозволяйте лише спільні бібліотеки, шляхи до моделей, каталог сокетів і вузли пристроїв GPU, які фактично необхідні.
- Явно забороняйте високоризикові capabilities, такі як `sys_admin`, `sys_module`, `sys_rawio` і `sys_ptrace`.
- Залишайте каталог моделей доступним лише для читання, а шляхи з доступом на запис обмежте лише каталогами runtime-сокетів і кешу.
- Відстежуйте denial-логи, оскільки вони надають корисну telemetry для виявлення спроб model server або post-exploitation payload вийти за межі очікуваної поведінки.

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

Phantom squatting — це **еквівалент slopsquatting для доменів/URL**. Замість галюцинації назви неіснуючого пакета LLM галюцинує правдоподібний **портал, API, webhook, billing, SSO, download або support-домен** реального бренду, а зловмисник реєструє цей namespace до того, як його використає людина або агент.

Це важливо, оскільки в багатьох AI-assisted workflow результат моделі розглядається як **довірена залежність**:
- Розробники вставляють запропонований endpoint у код або CI/CD-інтеграції.
- AI-агенти автоматично отримують документацію, схеми, APK, ZIP або webhook-цілі.
- Згенеровані runbook або документи можуть містити fake URL так, ніби він є авторитетним.

### Offensive workflow

1. **Probe the hallucination surface**: ставте запитання, специфічні для бренду, про реалістичні workflow, наприклад портали `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` або `mobile app`.
2. **Normalize candidates**: розв'язуйте згенеровані URL, зводьте відповіді NXDOMAIN до батьківського domain, доступного для реєстрації, і дедуплікуйте prompt family. Prompt corpus має залишатися різноманітним, наприклад шляхом видалення майже дублікатів за **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: той самий fake domain з'являється за різних temperature, зокрема за низької temperature, наприклад `T=0.1`.
- **Cross-model consensus**: кілька сімейств LLM генерують той самий fake domain.
4. **Register and weaponize** батьківський domain, потім розміщуйте phishing, fake APK/ZIP downloads, credential harvesters, malicious docs або API endpoints, які збирають secrets/webhook payloads. **Pure domain-level hallucinations** найпростіше монетизувати, оскільки зловмисник контролює весь namespace; hallucinations субдоменів/шляхів також можна використати, якщо нормалізований батьківський domain не зареєстрований.
5. **Exploit the zero-reputation window**: щойно зареєстровані domains часто не мають історії blocklist, URL reputation і зрілої telemetry, тому можуть обходити controls, доки detections не наздоженуть їх. Зловмисники можуть подовжити це вікно за допомогою benign-відповідей лише для crawler, redirect cloaking, CAPTCHA gates або відкладеного payload staging.

### Why it is dangerous for agents

Для людини-жертви fake domain зазвичай усе ще потребує кліку та додаткової дії. В **agentic workflow** LLM може бути одночасно **lure** і **executor**: агент отримує hallucinated URL, завантажує його, аналізує відповідь, а потім може leak tokens, виконати instructions, завантажити dependency або передати poisoned data до CI/CD без будь-якої human review.

### Practical attacker prompts

Високоефективні prompts зазвичай виглядають як звичайні enterprise tasks, а не явні phishing lures:
- “Який payment sandbox URL для інтеграцій `<brand>`?”
- “Який webhook endpoint слід використати для build notifications `<brand>`?”
- “Де знаходиться employee benefits / billing / SSO portal для `<brand>`?”
- “Надай пряме завантаження Android APK або desktop client для `<brand>`.”

### Defensive inversion

Розглядайте це як proactive domain-monitoring problem, а не лише як prompt-injection problem:
- Створіть **brand prompt corpus** і періодично перевіряйте LLM, на які покладаються ваші users/agents.
- Зберігайте hallucinated URLs і відстежуйте, які з них стабільні за різних temperatures/models.
- Відстежуйте **Adversarial Exploitation Window (AEW)**: час між першою hallucination і реєстрацією зловмисником. Позитивний AEW означає, що defenders можуть заздалегідь зареєструвати domain, спрямувати його до sinkhole або заблокувати до weaponization.
- Відстежуйте переходи **NXDOMAIN → registered** для батьківських domains.
- Після реєстрації перевіряйте registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status і схожість brand assets.
- Додайте policy gates, щоб agents/developers **не довіряли LLM-generated domains за замовчуванням**: вимагайте allowlists, ownership validation, CT/RDAP checks або human approval перед першим використанням.

Це одночасно належить до кількох AI risk buckets: **AI supply-chain attack**, **insecure model output** і **rogue actions**, коли агенти автономно використовують hallucinated URL.

## References
- [Unit 42 – Ризики Code Assistant LLM: шкідливий вміст, зловживання та обман](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Огляд LLMJacking scheme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (перепродаж викраденого доступу до LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv – Deep-dive у розгортання on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README сервера llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Специфікація CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: домени, галюциновані AI, як вектор атаки на Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: як AI hallucinations спричиняють новий клас Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
