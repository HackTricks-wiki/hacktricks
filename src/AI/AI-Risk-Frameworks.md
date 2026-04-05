# Ризики ШІ

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp визначив Top 10 уразливостей машинного навчання, які можуть впливати на системи ШІ. Ці уразливості можуть призводити до різних проблем із безпекою, включно з data poisoning, model inversion та adversarial attacks. Розуміння цих векторів атак критично для побудови захищених систем ШІ.

Для оновленого та детального переліку див. проєкт [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Атакувальник додає невеликі, часто непомітні зміни до **incoming data**, щоб модель прийняла неправильне рішення.\
*Приклад*: Кілька крапок фарби на stop‑sign змушують self‑driving car «побачити» знак обмеження швидкості.

- **Data Poisoning Attack**: **training set** навмисно забруднюють поганими зразками, навчаючи модель шкідливим правилам.\
*Приклад*: Бінарні файли malware маркують як «benign» у навчальному корпусі антивірусу, через що подібне malware пропускається пізніше.

- **Model Inversion Attack**: Пробуючи виходи, атакувальник створює **reverse model**, що реконструює чутливі характеристики оригінальних входів.\
*Приклад*: Відтворення MRI‑зображення пацієнта на основі прогнозів моделі для виявлення раку.

- **Membership Inference Attack**: Адверсар перевіряє, чи використовувався **specific record** під час навчання, помічаючи відмінності в довірі (confidence).\
*Приклад*: Підтвердження, що транзакція певної людини присутня в тренувальних даних моделі fraud‑detection.

- **Model Theft**: Повторні запити дозволяють атакувальнику вивчити межі прийняття рішень і **clone the model's behavior** (та інтелектуальну власність).\
*Приклад*: Зібрати достатньо Q&A пар з ML‑as‑a‑Service API, щоб побудувати локальний еквівалент моделі.

- **AI Supply‑Chain Attack**: Компрометація будь‑якого компонента (data, libraries, pre‑trained weights, CI/CD) у **ML pipeline** може зіпсувати downstream моделі.\
*Приклад*: Отруйна залежність на model‑hub встановлює backdoored sentiment‑analysis модель у багатьох додатках.

- **Transfer Learning Attack**: Зловмисна логіка закладається в **pre‑trained model** і переживає fine‑tuning для задачі жертви.\
*Приклад*: Vision backbone з прихованим тригером все ще міняє мітки після адаптації для medical imaging.

- **Model Skewing**: Тонко упереджені або неправильно марковані дані **shifts the model's outputs** на користь намірів атакувальника.\
*Приклад*: Інжекція «чистих» spam‑листів, помічених як ham, щоб spam‑фільтр пропускав схожі майбутні листи.

- **Output Integrity Attack**: Атакувальник **alters model predictions in transit**, а не саму модель, вводячи в оману downstream системи.\
*Приклад*: Зміна вердикту malware classifier з «malicious» на «benign» до того, як етап quarantine побачить файл.

- **Model Poisoning** --- Прямі, цілеспрямовані зміни до **model parameters** самих по собі, часто після отримання прав на запис, щоб змінити поведінку.\
*Приклад*: Тонка підміна ваг у production‑моделі fraud‑detection, щоб транзакції з певних карт завжди були схвалені.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) окреслює різні ризики, пов'язані із системами ШІ:

- **Data Poisoning**: Злочинці змінюють або інжектять training/tuning дані, щоб погіршити точність, закласти backdoors або спотворити результати, підриваючи цілісність моделі на всьому життєвому циклі даних.

- **Unauthorized Training Data**: Поглинання copyrighted, sensitive або неприпустимих датасетів створює юридичні, етичні та продуктивні ризики, оскільки модель вчиться на даних, які їй не дозволено використовувати.

- **Model Source Tampering**: Атаки на supply‑chain або інсайдерські зміни коду моделі, залежностей або weights до або під час навчання можуть вбудувати приховану логіку, що виживе навіть після retraining.

- **Excessive Data Handling**: Слабкі політики зберігання та управління даними призводять до того, що системи зберігають або обробляють більше персональних даних, ніж потрібно, підвищуючи експозицію та ризики відповідності.

- **Model Exfiltration**: Атакувальники викрадають model files/weights, спричиняючи втрату ІВ та дозволяючи створювати копії сервісів або подальші атаки.

- **Model Deployment Tampering**: Зловмисники змінюють артефакти моделі або інфраструктуру сервінгу, тому запущена модель відрізняється від перевіреної версії, потенційно змінюючи поведінку.

- **Denial of ML Service**: Перевантаження API або відправлення «sponge» input'ів може виснажити обчислювальні/енергетичні ресурси і вивести модель з ладу, аналогічно до класичних DoS‑атак.

- **Model Reverse Engineering**: Збираючи велику кількість input‑output пар, атакувальники можуть клонувати або distil модель, підживлюючи імітаційні продукти та кастомізовані adversarial атаки.

- **Insecure Integrated Component**: Вразливі плагіни, агенти або upstream сервіси дозволяють атакувальникам інжектити код або ескалювати привілеї в AI‑pipeline.

- **Prompt Injection**: Створення prompt'ів (напряму або опосередковано) для контрабанди інструкцій, що перевизначають системний намір, змушуючи модель виконувати небажані команди.

- **Model Evasion**: Уточнені входи змушують модель mis‑classify, hallucinate або виводити заборонений контент, підриваючи безпеку та довіру.

- **Sensitive Data Disclosure**: Модель розкриває приватну або конфіденційну інформацію з тренувальних даних чи контексту користувача, порушуючи приватність і нормативи.

- **Inferred Sensitive Data**: Модель виводить персональні атрибути, які ніколи не були надані, створюючи нові шкоди для приватності через інферування.

- **Insecure Model Output**: Ненадійні відповіді передають шкідливий код, дезінформацію або невідповідний контент користувачам чи downstream системам.

- **Rogue Actions**: Автономно інтегровані агенти виконують небажані реальні операції (запис файлів, API‑виклики, покупки тощо) без адекватного нагляду користувача.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) надає всебічну рамку для розуміння та пом'якшення ризиків, пов'язаних із системами ШІ. Вона категоризує різні техніки атак і тактики, які можуть використовуватися проти AI‑моделей, а також як використовувати AI‑системи для виконання різних атак.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Атакувальники крадуть активні session tokens або cloud API credentials і викликають платні, cloud‑hosted LLM без авторизації. Доступ часто перепродається через reverse proxies, що фронтують акаунт жертви, наприклад розгортання "oai-reverse-proxy". Наслідки включають фінансові втрати, неправильне використання моделі поза політикою та неправильне приписування активності орендарю жертви.

TTPs:
- Harvest tokens з заражених машин розробників або браузерів; викрадення CI/CD секретів; купівля leaked cookies.
- Поставити reverse proxy, який пересилає запити до справжнього провайдера, ховаючи upstream key і мультиплексуючи багатьох клієнтів.
- Зловживати direct base‑model endpoints, щоб обійти enterprise guardrails і rate limits.

Mitigations:
- Прив'язувати tokens до device fingerprint, IP‑діапазонів і client attestation; застосовувати короткі терміни дії і оновлення з MFA.
- Давати ключам мінімальні права (no tool access, read‑only там, де можливо); ротувати при аномаліях.
- Завершувати весь трафік на server‑side за policy gateway, що застосовує safety filters, по‑маршрутні квоти і tenant isolation.
- Моніторити незвичні шаблони використання (раптові стрибки витрат, атипові регіони, UA strings) і автоматично анулювати підозрілі сесії.
- Віддавати перевагу mTLS або підписаним JWTs, виданим вашим IdP, замість довгоживучих статичних API keys.

## Self-hosted LLM inference hardening

Запуск локального LLM server'а для конфіденційних даних створює іншу поверхню атаки, ніж cloud‑hosted API: inference/debug endpoints можуть lead до розкриття prompt'ів, serving stack зазвичай виставляє reverse proxy, а GPU device nodes дають доступ до великої площі `ioctl()`-інтерфейсів. Якщо ви оцінюєте або розгортаєте on‑prem inference service, перегляньте щонайменше наступні пункти.

### Prompt leakage via debug and monitoring endpoints

Розглядайте inference API як **multi-user sensitive service**. Debug або monitoring маршрути можуть відкривати вміст prompt'ів, slot state, model metadata або внутрішню інформацію черг. В `llama.cpp` endpoint `/slots` особливо чутливий, бо відкриває per‑slot state і призначений лише для інспекції/керування слотами.

- Помістіть reverse proxy перед inference server і **deny by default**.
- Дозвольте лише точно ті комбінації HTTP method + path, які потрібні клієнту/UI.
- Вимикайте introspection endpoints у бекенді коли можливо, наприклад `llama-server --no-slots`.
- Прив'яжіть reverse proxy до `127.0.0.1` і експонуйте його через аутентифікований транспорт, такий як SSH local port forwarding, замість публікації в LAN.

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
### Rootless контейнери без мережі та UNIX-сокетів

Якщо inference daemon підтримує прослуховування на UNIX-сокеті, віддавайте перевагу цьому замість TCP і запускайте контейнер з **no network stack**:
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
- `--network none` усуває експозицію вхідного/вихідного TCP/IP і уникає потреби в user-mode helpers, яких інакше вимагали б rootless containers.
- UNIX socket дозволяє використовувати POSIX permissions/ACLs на шляху сокета як перший рівень контролю доступу.
- `--userns=keep-id` та rootless Podman зменшують наслідки container breakout, оскільки container root не є host root.
- Read-only model mounts зменшують ймовірність модифікації моделі зсередини контейнера.

### GPU device-node minimization

Для GPU-backed inference файли `/dev/nvidia*` — цінні локальні вектори атаки, оскільки вони відкривають великі драйверні `ioctl()` обробники та потенційно спільні шляхи управління пам'яттю GPU.

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- Blacklist unnecessary modules such as `nvidia_drm`, `nvidia_modeset`, and `nvidia_peermem` on headless inference hosts.
- Preload only required modules at boot instead of letting the runtime opportunistically `modprobe` them during inference startup.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Важливий пункт перевірки — **`/dev/nvidia-uvm`**. Навіть якщо робоче навантаження явно не використовує `cudaMallocManaged()`, останні CUDA runtimes все ще можуть вимагати `nvidia-uvm`. Оскільки цей пристрій спільний і відповідає за керування віртуальною пам'яттю GPU, розглядайте його як поверхню потенційного розкриття даних між орендарями. Якщо inference backend це підтримує, Vulkan backend може бути цікавим компромісом, бо він може зовсім уникнути експонування `nvidia-uvm` всередині контейнера.

### LSM ізоляція для воркерів інференсу

AppArmor/SELinux/seccomp слід використовувати як багаторівневий захист навколо процесу інференсу:

- Дозволяти лише ті shared libraries, model paths, socket directory та GPU device nodes, які фактично потрібні.
- Явно забороняти високоризикові capabilities, такі як `sys_admin`, `sys_module`, `sys_rawio` та `sys_ptrace`.
- Тримати каталог моделей доступним лише для читання і обмежувати записувані шляхи тільки до runtime socket/cache директорій.
- Моніторити denial logs, оскільки вони дають корисну телеметрію для виявлення, коли model server або post-exploitation payload намагаються вийти за межі очікуваної поведінки.

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
## Посилання
- [Unit 42 – Ризики Code Assistant LLMs: шкідливий контент, зловживання та обман](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Огляд схеми LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (перепродаж вкраденого доступу до LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Глибоке занурення в розгортання on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) специфікація](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
