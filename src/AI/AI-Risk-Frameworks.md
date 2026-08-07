# Ризики AI

{{#include ../banners/hacktricks-training.md}}

## Топ-10 вразливостей Machine Learning за версією OWASP

Owasp визначила 10 основних вразливостей Machine Learning, які можуть впливати на AI-системи. Ці вразливості можуть призводити до різних проблем безпеки, зокрема отруєння даних, інверсії моделі та adversarial-атак. Розуміння цих вразливостей має вирішальне значення для побудови безпечних AI-систем.

Актуальний і детальний список 10 основних вразливостей Machine Learning наведено в проєкті [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Атака маніпуляції вхідними даними**: Атакер додає незначні, часто невидимі зміни до **вхідних даних**, щоб модель ухвалила неправильне рішення.\
*Приклад*: Кілька плям фарби на знаку STOP змушують безпілотний автомобіль "побачити" знак обмеження швидкості.

- **Атака отруєння даних**: **Навчальний набір** навмисно забруднюється шкідливими зразками, навчаючи модель небезпечних правил.\
*Приклад*: Бінарні файли malware позначаються як "benign" у навчальному корпусі антивіруса, завдяки чому схоже malware згодом обходить перевірку.

- **Атака інверсії моделі**: Досліджуючи вихідні дані, атакер створює **зворотну модель**, яка відновлює чутливі ознаки початкових входів.\
*Приклад*: Відтворення MRI-зображення пацієнта на основі прогнозів моделі виявлення раку.

- **Атака виведення належності**: Атакер перевіряє, чи використовувався **конкретний запис** під час навчання, аналізуючи відмінності у рівнях впевненості.\
*Приклад*: Підтвердження того, що банківська транзакція певної особи міститься в навчальних даних моделі виявлення шахрайства.

- **Крадіжка моделі**: Повторні запити дають атакеру змогу вивчити межі ухвалення рішень і **клонувати поведінку моделі** (та IP).\
*Приклад*: Збір достатньої кількості пар запитань і відповідей з API ML-as-a-Service для створення майже еквівалентної локальної моделі.

- **Атака на ланцюг постачання AI**: Компрометація будь-якого компонента (даних, бібліотек, попередньо навчених ваг, CI/CD) у **ML pipeline** для пошкодження наступних моделей.\
*Приклад*: Отруєна dependency з model hub встановлює backdoored модель аналізу тональності в багатьох застосунках.

- **Атака Transfer Learning**: Шкідлива логіка вбудовується в **попередньо навчену модель** і зберігається під час fine-tuning для завдання жертви.\
*Приклад*: Vision backbone із прихованим тригером продовжує змінювати мітки після адаптації для медичної візуалізації.

- **Зміщення моделі**: Непомітно упереджені або неправильно марковані дані **зміщують вихідні дані моделі** на користь цілей атакера.\
*Приклад*: Додавання "чистих" спам-листів, позначених як ham, щоб spam filter пропускав схожі майбутні листи.

- **Атака на цілісність вихідних даних**: Атакер **змінює прогнози моделі під час передавання**, не змінюючи саму модель, і вводить в оману наступні системи.\
*Приклад*: Заміна вердикту класифікатора malware з "malicious" на "benign" до того, як етап карантину файлу його побачить.

- **Отруєння моделі** --- Прямі цілеспрямовані зміни **параметрів моделі**, часто після отримання доступу на запис, для зміни її поведінки.\
*Приклад*: Коригування ваг моделі виявлення шахрайства у production, щоб транзакції з певних карток завжди схвалювалися.


## Ризики Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) від Google описує різні ризики, пов’язані з AI-системами:<sup>[[2]](#references)</sup>

- **Отруєння даних**: Зловмисники змінюють або додають навчальні дані чи дані для налаштування, щоб погіршити точність, вбудувати backdoor або спотворити результати, підриваючи цілісність моделі протягом усього життєвого циклу даних.

- **Несанкціоновані навчальні дані**: Використання захищених авторським правом, чутливих або несанкціонованих наборів даних створює юридичні, етичні та експлуатаційні ризики, оскільки модель навчається на даних, які їй ніколи не дозволяли використовувати.

- **Підміна джерела моделі**: Маніпуляції з кодом моделі, dependencies або вагами з боку ланцюга постачання чи інсайдера до або під час навчання можуть вбудувати приховану логіку, яка зберігається навіть після повторного навчання.

- **Надмірна обробка даних**: Слабкі засоби зберігання даних і контролю управління призводять до того, що системи зберігають або обробляють більше персональних даних, ніж необхідно, підвищуючи ризики витоку та недотримання вимог.

- **Ексфільтрація моделі**: Атакери викрадають файли/ваги моделі, що призводить до втрати інтелектуальної власності та уможливлює створення копій сервісів або подальші атаки.

- **Підміна розгортання моделі**: Атакери змінюють артефакти моделі або інфраструктуру її обслуговування, через що запущена модель відрізняється від перевіреної версії та потенційно має іншу поведінку.

- **Відмова в обслуговуванні ML**: Переповнення API або надсилання “sponge”-входів може вичерпати обчислювальні ресурси/енергію та вивести модель з ладу, наслідуючи класичні DoS-атаки.

- **Зворотна інженерія моделі**: Збираючи велику кількість пар входів і виходів, атакери можуть клонувати або дистилювати модель, стимулюючи створення імітаційних продуктів і спеціалізованих adversarial-атак.

- **Незахищений інтегрований компонент**: Вразливі plugins, agents або upstream-сервіси дають атакерам змогу впроваджувати код або підвищувати привілеї в AI pipeline.

- **Prompt Injection**: Створення prompts (безпосередньо або опосередковано) для прихованого передавання інструкцій, які перевизначають системний задум і змушують модель виконувати ненавмисні команди.

- **Ухилення від моделі**: Ретельно сформовані входи змушують модель неправильно класифікувати, галюцинувати або виводити заборонений контент, підриваючи безпеку та довіру.

- **Розкриття чутливих даних**: Модель розкриває приватну або конфіденційну інформацію зі своїх навчальних даних чи контексту користувача, порушуючи конфіденційність і нормативні вимоги.

- **Виведені чутливі дані**: Модель визначає персональні характеристики, які ніколи не надавалися, створюючи нові порушення конфіденційності через inference.

- **Незахищений вихід моделі**: Неочищені відповіді передають користувачам або наступним системам шкідливий код, дезінформацію чи неприйнятний контент.

- **Несанкціоновані дії**: Автономно інтегровані agents виконують ненавмисні операції у фізичному світі (запис файлів, виклики API, покупки тощо) без належного нагляду користувача.

## Матриця Mitre AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає комплексну структуру для розуміння та зниження ризиків, пов’язаних з AI-системами. Вона класифікує різні attack techniques і tactics, які adversaries можуть використовувати проти AI-моделей, а також способи використання AI-систем для виконання різних атак.<sup>[[3]](#references)</sup>

## LLMJacking (крадіжка токенів і перепродаж доступу до LLM, розміщених у Cloud)

Атакери викрадають активні session tokens або cloud API credentials і без дозволу викликають платні LLM, розміщені в Cloud. Доступ часто перепродається через reverse proxies, які працюють від імені облікового запису жертви, наприклад deployments "oai-reverse-proxy". Наслідки включають фінансові збитки, використання моделі всупереч політикам і приписування дій tenant жертви.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Збирати tokens із заражених машин розробників або браузерів; викрадати secrets CI/CD; купувати leaked cookies.<sup>[[5]](#references)</sup>
- Розгорнути reverse proxy, який пересилає запити справжньому provider, приховуючи upstream key і мультиплексуючи багатьох клієнтів.<sup>[[5]](#references)[[7]](#references)</sup>
- Зловживати прямими endpoints base-моделі, щоб обходити enterprise guardrails і rate limits.<sup>[[4]](#references)</sup>

Заходи протидії:
- Прив’язувати tokens до device fingerprint, діапазонів IP і client attestation; встановлювати короткий строк дії та оновлювати їх за допомогою MFA.
- Мінімально обмежувати keys (без доступу до tools, лише читання, де це можливо); виконувати rotation у разі аномалій.
- Завершувати весь трафік на стороні сервера за policy gateway, який застосовує safety filters, quotas для окремих routes та ізоляцію tenants.
- Відстежувати незвичайні шаблони використання (раптові сплески витрат, нетипові регіони, рядки UA) і автоматично відкликати підозрілі sessions.
- Надавати перевагу mTLS або підписаним JWTs, виданим вашим IdP, замість довгоживучих статичних API keys.

## Посилення безпеки Self-hosted LLM inference

Запуск локального LLM-сервера для конфіденційних даних створює іншу attack surface порівняно з API, розміщеними в Cloud: endpoints inference/debug можуть спричинити leak prompts, serving stack зазвичай відкриває reverse proxy, а device nodes GPU надають доступ до великих поверхонь `ioctl()`. Якщо ви оцінюєте або розгортаєте on-prem inference-сервіс, перевірте щонайменше наведені нижче аспекти.<sup>[[8]](#references)</sup>

### Витік prompts через endpoints debug і monitoring

Розглядайте inference API як **чутливий сервіс для багатьох користувачів**. Routes debug або monitoring можуть розкривати вміст prompts, стан slot, metadata моделі або внутрішню інформацію про queue. У `llama.cpp` endpoint `/slots` є особливо чутливим, оскільки розкриває стан окремих slot і призначений лише для перевірки/керування slot.<sup>[[8]](#references)</sup>

- Розмістіть reverse proxy перед inference-сервером і **забороняйте все за замовчуванням**.
- Дозволяйте лише точні комбінації HTTP method + path, необхідні клієнту/UI.
- За можливості вимкніть endpoints introspection безпосередньо в backend, наприклад `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Прив’яжіть reverse proxy до `127.0.0.1` і надавайте доступ через автентифікований transport, наприклад SSH local port forwarding, замість публікації в LAN.

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

Якщо inference daemon підтримує прослуховування UNIX-сокета, надавайте перевагу цьому варіанту перед TCP і запускайте контейнер із **відсутнім мережевим стеком**:<sup>[[8]](#references)</sup>
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
- `--userns=keep-id` і rootless Podman зменшують вплив container breakout, оскільки container root не є host root.
- Монтування моделей у режимі лише для читання зменшує ймовірність tampering моделі зсередини container.

### Мінімізація GPU device nodes

Для inference на GPU файли `/dev/nvidia*` є цінними локальними attack surfaces, оскільки вони відкривають великі обробники драйвера `ioctl()` і потенційно спільні шляхи керування пам’яттю GPU.<sup>[[8]](#references)</sup>

- Не залишайте `/dev/nvidia*` доступними для запису всім користувачам.
- Обмежте `nvidia`, `nvidiactl` і `nvidia-uvm` за допомогою `NVreg_DeviceFileUID/GID/Mode`, правил udev і ACLs, щоб лише зіставлений container UID міг відкривати їх.
- Відключіть непотрібні модулі, такі як `nvidia_drm`, `nvidia_modeset` і `nvidia_peermem`, на headless inference hosts.
- Попередньо завантажуйте лише потрібні модулі під час boot замість того, щоб дозволяти runtime opportunistically виконувати `modprobe` під час запуску inference.

Приклад:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Одним із важливих пунктів перевірки є **`/dev/nvidia-uvm`**. Навіть якщо workload явно не використовує `cudaMallocManaged()`, останні версії CUDA runtimes все одно можуть вимагати `nvidia-uvm`. Оскільки цей device є спільним і відповідає за керування віртуальною пам’яттю GPU, розглядайте його як surface для витоку даних між tenant'ами. Якщо inference backend це підтримує, Vulkan backend може бути цікавим компромісом, оскільки він може взагалі не вимагати надання `nvidia-uvm` контейнеру.<sup>[[8]](#references)</sup>

### LSM confinement для inference workers

AppArmor/SELinux/seccomp слід використовувати як defense in depth навколо inference process:<sup>[[8]](#references)</sup>

- Дозволяйте лише shared libraries, model paths, socket directory та GPU device nodes, які фактично потрібні.
- Явно забороняйте high-risk capabilities, такі як `sys_admin`, `sys_module`, `sys_rawio` та `sys_ptrace`.
- Залишайте model directory доступною лише для читання, а writable paths обмежте лише runtime socket/cache directories.
- Відстежуйте denial logs, оскільки вони надають корисну detection telemetry, коли model server або post-exploitation payload намагається вийти за межі очікуваної поведінки.

Приклад правил AppArmor для worker з GPU:
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
## Phantom Squatting: Домени, галюциновані LLM, як вектор AI supply-chain

Phantom squatting є **еквівалентом slopsquatting для доменів/URL**. Замість галюцинації неіснуючої назви пакета LLM галюцинує правдоподібний **портал, API, webhook, billing, SSO, download або support-домен** для реального бренду, а зловмисник реєструє цей namespace до того, як його використає людина або agent.<sup>[[12]](#references)[[13]](#references)</sup>

Це важливо, оскільки в багатьох AI-assisted workflow результат моделі розглядається як **довірена залежність**:
- Розробники вставляють запропонований endpoint у код або інтеграції CI/CD.
- AI agents автоматично отримують документацію, схеми, APK, ZIP або webhook targets.
- Згенеровані runbook або документація можуть містити fake URL так, ніби він є авторитетним.

### Offensive workflow

1. **Probe hallucination surface**: ставте brand-specific запитання про реалістичні workflow, наприклад портали `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` або `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: resolve згенерованих URL, зводьте відповіді NXDOMAIN до parent registerable domain і дедуплікуйте prompt families. Prompt corpora мають залишатися різноманітними, наприклад шляхом видалення near-duplicates із **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: той самий fake domain з’являється за різних temperature, зокрема за низької temperature, як `T=0.1`.
- **Cross-model consensus**: кілька сімейств LLM генерують той самий fake domain.
4. **Register and weaponize** parent domain, потім розміщуйте phishing, fake APK/ZIP downloads, credential harvesters, malicious docs або API endpoints, які збирають secrets/webhook payloads. **Pure domain-level hallucinations** найпростіше монетизувати, оскільки зловмисник контролює весь namespace; subdomain/path hallucinations також можна використати, якщо нормалізований parent залишається незареєстрованим.
5. **Exploit zero-reputation window**: нещодавно зареєстровані домени часто не мають історії у blocklist, URL reputation і зрілої telemetry, тому можуть обходити controls, доки detections не адаптуються. Зловмисники можуть подовжити це вікно за допомогою benign responses лише для crawler, redirect cloaking, CAPTCHA gates або відкладеного payload staging.

### Why it is dangerous for agents

Для людини-жертви fake domain зазвичай усе ще потребує кліку та додаткової дії. В **agentic workflow** LLM може бути одночасно **lure** та **executor**: agent отримує hallucinated URL, завантажує його, аналізує response, а потім може leak tokens, виконати instructions, завантажити dependency або передати poisoned data у CI/CD без будь-якої перевірки людиною.<sup>[[12]](#references)</sup>

### Practical attacker prompts

High-yield prompts зазвичай виглядають як звичайні enterprise tasks, а не як явні phishing lures:<sup>[[12]](#references)</sup>
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Розглядайте це як proactive domain-monitoring problem, а не лише як prompt-injection problem:<sup>[[12]](#references)</sup>
- Створіть **brand prompt corpus** і періодично перевіряйте LLM, на які покладаються ваші користувачі/agents.
- Зберігайте hallucinated URLs і відстежуйте, які з них є stable за різних temperatures/models.
- Відстежуйте **Adversarial Exploitation Window (AEW)**: час між першою hallucination та attacker registration. Позитивне значення AEW означає, що defenders можуть pre-register, sinkhole або pre-block домен до weaponization.
- Відстежуйте переходи **NXDOMAIN → registered** для parent domains.
- Після реєстрації перевіряйте registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status і схожість brand assets.
- Додайте policy gates, щоб agents/developers **не довіряли LLM-generated domains за замовчуванням**: вимагайте allowlists, ownership validation, CT/RDAP checks або human approval перед першим використанням.

Це одночасно відповідає кільком AI risk buckets: **AI supply-chain attack**, **insecure model output** і **rogue actions**, коли agents автономно використовують hallucinated URL.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
