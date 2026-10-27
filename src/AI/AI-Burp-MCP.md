# Burp MCP: аналіз трафіку за допомогою LLM

{{#include ../banners/hacktricks-training.md}}

## Огляд

Розширення **MCP Server** для Burp може надавати перехоплений HTTP(S)-трафік MCP-сумісним LLM-клієнтам, щоб вони могли **аналізувати реальні запити/відповіді** для виявлення вразливостей і підготовки звітів. Використовуйте Burp як джерело достовірних даних: вдавайтеся до пасивного аналізу або цілеспрямованого повторного надсилання запитів зі зміною однієї змінної, а не до сліпого сканування.<sup>[[8]](#references)</sup>

## Архітектура

- **Burp MCP Server (BApp)** за замовчуванням прослуховує `127.0.0.1:9876` і надає доступ до перехопленого трафіку через MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** забезпечує міст між stdio (на стороні клієнта) та MCP SSE endpoint Burp.
- **Необов’язковий локальний reverse proxy** (Caddy) нормалізує заголовки для проходження суворих перевірок MCP handshake.
- **Клієнти/бекенди**: Codex CLI (cloud), Gemini CLI (cloud) або Ollama (local).

## Налаштування

### 1) Встановіть Burp MCP Server

Установіть **MCP Server** із Burp BApp Store і переконайтеся, що він прослуховує `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Витягніть proxy JAR

На вкладці MCP Server натисніть **Extract server proxy jar** і збережіть `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Налаштуйте MCP-клієнт (приклад із Codex)

Спрямуйте клієнт на proxy JAR і прямий SSE endpoint Burp. Вбудований proxy працює як міст stdio-to-SSE; він не замінює listener Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

Еквівалентна команда Codex: <sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Потім запустіть Codex і перелічіть інструменти MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Виправлення суворої перевірки Origin/заголовків за допомогою Caddy (за потреби)

Якщо handshake MCP не проходить через сувору перевірку `Origin` або додаткові заголовки, використайте локальний reverse proxy для нормалізації заголовків (це відповідає обхідному рішенню для проблеми суворої перевірки Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
  # lock Host/Origin to the Burp listener
  header_up Host "127.0.0.1:9876"
  header_up Origin "http://127.0.0.1:9876"

  # strip client headers that trigger Burp's 403 during SSE init
  header_up -User-Agent
  header_up -Accept
  header_up -Accept-Encoding
  header_up -Connection
}
EOF
```

Запустіть проксі та клієнт і змініть налаштований `--sse-url` на `http://127.0.0.1:19876` лише під час використання цього слухача Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Поєднайте стан браузера з доказами з proxy (Playwright MCP)

Зареєструйте Playwright MCP, щоб його браузер використовував proxy Burp. Це дає змогу агенту зіставляти відображений стан DOM/доступності з точною історією HTTP-запитів, яка його сформувала.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Налаштуйте адресу listener, перезапустіть Codex і скористайтеся `/mcp`, щоб перевірити обидві інтеграції. У прикладі вимкнено перевірку сертифікатів браузера, щоб HTTPS-перехопленню не заважав сертифікат, згенерований локально Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Автоматизація браузера з урахуванням проксі (OpenBurp)

З’єднання Burp MCP і шлях перехопленого браузерного трафіку — це окремі потоки даних. Сервіс MCP надає інструменти Burp на `127.0.0.1:9876`, тоді як окремий екземпляр Chromium надсилає свій HTTP(S)-трафік через проксі Burp на `127.0.0.1:8080`. Тому запити, безпосередньо згенеровані інструментом MCP, можуть не відображатися в **Proxy > HTTP history**; використовуйте браузер із проксі, коли потрібно спостерігати за запитом/відповіддю, редагувати їх або зберегти як доказ.<sup>[[2]](#references)[[9]](#references)</sup>

Клієнт із підтримкою SSE може безпосередньо зареєструвати Burp. Клієнт, що підтримує лише stdio, натомість може запустити проксі-JAR від PortSwigger. В обох випадках зареєструйте другий MCP для керування браузером і вкажіть вбудований Chromium у Burp (`BURP_CHROMIUM` — це локальний шлях до виконуваного файла):<sup>[[9]](#references)</sup>

```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
  --executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
  --executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors --isolated
```

Прапорець TLS-bypass приймає сертифікати, згенеровані проксі перехоплення, а `--isolated` не дає оцінюванню повторно використовувати звичайний профіль браузера оператора. Ізоляція захищає стан профілю, але **не є пісочницею безпеки**: контролер і далі може отримувати доступ до автентифікованих сеансів, відкритих у цьому тестовому браузері, а Burp MCP може розкривати конфіденційні запити, відповіді та конфігурацію.<sup>[[9]](#references)</sup>

Перш ніж налагоджувати клієнтський міст, окремо протестуйте SSE-слухач:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Здоровий listener повертає `Content-Type: text/event-stream`. Тайм-аут після отримання заголовків є очікуваним, оскільки SSE-потік залишається відкритим для майбутніх подій. Якщо клієнт і далі не працює, перевірте налаштований маршрут розширення: PortSwigger зазначає, що кінцевою точкою може бути кореневий шлях або `/sse` — залежно від клієнта й конфігурації розширення.<sup>[[9]](#references)[[7]](#references)</sup>

## Використання різних клієнтів

### Codex CLI

- Налаштуйте `~/.codex/config.toml`, як зазначено вище.
- Запустіть `codex`, а потім `/mcp`, щоб перевірити список інструментів Burp.

### Gemini CLI

Репозиторій **burp-mcp-agents** містить допоміжні засоби для запуску:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (локальна)

Скористайтеся наданим допоміжним засобом запуску та виберіть локальну модель:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Приклади локальних моделей і приблизні вимоги до VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Відтворення та валідація на основі доказів

Не дозволяйте агенту сприймати правдоподібне пояснення чи проміжну відповідь як доказ. Використовуйте запити/відповіді Burp і незалежно спостережуваний стан браузера, щоб кожен тест можна було спростувати.<sup>[[8]](#references)</sup>

1. Збережіть базову пару запит/відповідь і визначте точний компонент, контрольований атакувальником.
2. Для порівняння авторизації зафіксуйте той самий робочий процес окремо для обох облікових записів, перш ніж змінювати ідентифікатори, cookie чи токени.
3. Перш ніж відтворювати мутацію, запишіть гіпотезу, місце розташування доказів, очікуваний сигнал і результат, який її спростував би.
4. Змінюйте по одному компоненту за раз, зберігайте отриману пару й окремо позначайте безпосередні спостереження та висновки.
5. Відстежуйте кожного кандидата як `open`, `blocked`, `rejected` або `confirmed`; повертайтеся до нього лише тоді, коли нові докази змінюють механізм або передумову.
6. Підтвердьте контроль атакувальника, досяжність, відтворюваність, обхід обмежень, вплив і кінцевий стан застосунку. Перенаправлення чи успішний виклик інструмента не є доказом, якщо заявлена зміна стану відбувається далі в процесі.

Зберігайте деталі експлуатації на відповідній сторінці техніки. Наприклад, кандидати, пов’язані з повідомленнями браузера, належать до [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), а поведінка вибору ключа токена — до [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Стислий запис гіпотези допомагає паралельним агентам не повторювати ту саму привабливу гілку:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Первинний аналіз WebSocket-фреймів за допомогою Burp MCP

Офіційне розширення надає `get_proxy_websocket_history_regex` для пошуку лише для читання з пагінацією в історії WebSocket у Burp. Він приймає `regex`, `count` і `offset`; на відміну від `send_http1_request`, він не надсилає WebSocket-фрейм. Burp записує повідомлення в обох напрямках, навіть коли Intercept вимкнено, тому відфільтруйте історію, перш ніж передавати моделі невеликий набір релевантних фреймів.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Виконайте ту саму дію, що використовує WebSocket, у браузері, трафік якого проходить через Burp, із двома незалежно автентифікованими тестовими обліковими записами. Зберігайте разом кожне handshake-з’єднання, його cookies, ID з’єднання, напрямок фрейму та фрейми відповіді; подія від сервера до клієнта на з’єднанні першого облікового запису не є доказом того, що її отримав другий обліковий запис.
2. Виконайте пошук через `get_proxy_websocket_history_regex` з вузьким виразом, наприклад `(?i)(subscribe|room|tenant|objectId)`, `count: 20` і `offset: 0`. Змінюйте `offset`, щоб переглядати наступні збіги. Порівняйте ідентифікатор об’єкта або теми у вихідному фреймі з відповіддю на **тому самому з’єднанні**.
3. У **Proxy > WebSockets history** надішліть кандидатний вихідний фрейм у Repeater. Прив’яжіть його до відповідного відкритого з’єднання або перепідключіться, використавши handshake другого облікового запису. Змініть лише ідентифікатор об’єкта/теми та порівняйте отримані повідомлення сервера й стан застосунку з обома базовими сценаріями. Інструмент історії MCP не може виконати цей повтор; WebSocket Repeater дає змогу редагувати й повторно надсилати фрейми, а також перепідключатися.

Для специфічних для протоколу тестів, як-от cross-site WebSocket hijacking і перевірки авторизації тем брокера, див. [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Не вважайте успішне встановлення з’єднання або відлуння на боці клієнта доказом успішної підписки на захищений ресурс.

## Цільова позасмугова перевірка за допомогою Burp MCP

Burp Suite Professional надає `generate_collaborator_payload` і `get_collaborator_interactions` через офіційне розширення MCP. Поєднайте їх із `get_proxy_http_history_regex` та одним повторним запитом через `send_http1_request`, щоб перевірити підозріле завантаження URL на боці сервера без сканування всього цільового ресурсу. Burp може окремо запитати дозвіл на читання історії та надсилання запиту.<sup>[[2]](#references)[[10]](#references)</sup>

1. Відфільтруйте історію за запитом-кандидатом, що містить URL, наприклад із `url=`, `webhook` або `callback`. Збережіть початковий запит і відповідь. Інструмент історії приймає `regex`, `count` і `offset`; переглядайте результати сторінками, а не просіть модель перевірити кожен запис.<sup>[[10]](#references)</sup>
2. Згенеруйте новий Collaborator payload і збережіть повернений **payload ID**. Повторно надішліть перехоплений запит тому самому хосту й порту, змінивши лише кандидатний URL на HTTPS URL у домені цього payload. Для `send_http1_request` передайте повний HTTP/1.1-запит як `content`, а також `targetHostname`, `targetPort` і `usesHttps`; поля призначення ідентифікують **застосунок**, а не хост Collaborator.<sup>[[10]](#references)</sup>
3. Опитуйте `get_collaborator_interactions` із цим payload ID і зіставте час взаємодії з повторним запитом. Взаємодія HTTP підтверджує завантаження, тоді як сам лише DNS свідчить про розв’язання імені, але не про завершений HTTP-запит. Перевірте джерело взаємодії та заголовки запиту, щоб відрізнити вихідний трафік сервера від завантаження на боці браузера; потім повторіть перевірку з новим payload, щоб виключити сторонній трафік.<sup>[[10]](#references)[[11]](#references)</sup>

Інструмент запитів MCP повертає відповідь безпосередньо й не зобов’язаний додавати її до **Proxy > HTTP history**. Збережіть результат запиту й відповіді або скористайтеся браузером із проксі чи Repeater, щоб отримати артефакт з історії. Для вибору SSRF payload і подальших тестів скористайтеся [розділом про SSRF](../pentesting-web/ssrf-server-side-request-forgery/), а не вважайте позасмуговий callback доказом впливу на внутрішню мережу. Щоб протестувати сам MCP server, див. [тестування MCP server](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Набір промптів для пасивного аналізу

Репозиторій **burp-mcp-agents** містить шаблони промптів для аналізу трафіку Burp на основі доказів:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: широке пасивне виявлення вразливостей.
- `idor_hunter.md`: IDOR/BOLA, невідповідності об’єктів/тенантів і проблеми автентифікації.
- `auth_flow_mapper.md`: порівняння автентифікованих і неавтентифікованих шляхів.
- `ssrf_redirect_hunter.md`: кандидати на SSRF/open redirect у параметрах завантаження URL і ланцюжках перенаправлень.
- `logic_flaw_hunter.md`: логічні вразливості з кількома кроками.
- `session_scope_hunter.md`: неправильне використання аудиторії/обсягу дії токена.
- `rate_limit_abuse_hunter.md`: недоліки обмеження частоти запитів/захисту від зловживань.
- `report_writer.md`: підготовка звітів із фокусом на доказах.

## Додаткове маркування для атрибуції

Щоб позначати трафік Burp/LLM у журналах, додайте правило переписування заголовків (proxy або Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Нотатки з безпеки

- Віддавайте перевагу **локальним моделям**, якщо трафік містить конфіденційні дані.
- Передавайте лише мінімум доказів, потрібний для підтвердження знахідки.
- Вважайте Burp першоджерелом; використовуйте модель для **аналізу та звітування**, а не для сканування.

## Burp AI Agent (сортування за допомогою AI + інструменти MCP)

**Burp AI Agent** — це розширення Burp, яке поєднує локальні/хмарні LLM із пасивним/активним аналізом (62 класи вразливостей) і надає понад 53 інструменти MCP, щоб зовнішні клієнти MCP могли керувати Burp.<sup>[[5]](#references)</sup> Основні можливості:

- **Сортування через контекстне меню**: перехопіть трафік через Proxy, відкрийте **Proxy > HTTP History**, клацніть правою кнопкою миші запит → **Extensions > Burp AI Agent > Analyze this request**, щоб відкрити чат AI, прив’язаний до цього запиту/відповіді.
- **Backend-и** (вибираються окремо для кожного профілю):
  - Локальний HTTP: **Ollama**, **LM Studio**.
  - Віддалений HTTP: endpoint, сумісний із **OpenAI** (базова URL-адреса + назва моделі).
  - Хмарні CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` або `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (вхід залежить від провайдера).
- **Профілі агента**: шаблони prompt автоматично встановлюються в `~/.burp-ai-agent/AGENTS/`; додайте туди інші файли `*.md`, щоб створити власні сценарії аналізу/сканування.
- **MCP server**: увімкніть у **Settings > MCP Server**, щоб надати будь-якому клієнту MCP доступ до операцій Burp (понад 53 інструменти). Claude Desktop можна підключити до сервера, відредагувавши `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) або `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Налаштування приватності**: режими STRICT / BALANCED / OFF приховують конфіденційні дані запитів перед надсиланням віддаленим моделям; під час роботи із секретами віддавайте перевагу локальним backend-ам.
- **Журнал аудиту**: журнали JSONL із хешуванням SHA-256 для кожного запису, що забезпечує захищене від підробки відстеження дій AI/MCP.
- **Збірка/завантаження**: завантажте JAR релізу або зберіть за допомогою Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Операційні застереження: хмарні бекенди можуть викрадати cookie сесій/PII, якщо не ввімкнено режим конфіденційності; доступ до MCP дає змогу віддалено керувати Burp, тож обмежте його довіреними агентами та контролюйте журнал аудиту з хешем цілісності.



## References

- [1] [Інтеграція Burp MCP + Codex CLI та виправлення handshake у Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp-сервер Burp MCP](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Проблема суворої перевірки Origin/header у сервері PortSwigger MCP](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Агенти Burp MCP (workflow, засоби запуску, набір промптів)](https://github.com/six2dez/burp-mcp-agents)
- [5] [AI-агент Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Сервер MCP для PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Як використовувати Codex для дослідження Bug Bounty: широко досліджуйте, ретельно перевіряйте](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: оркестрація Burp Suite для Claude Code і Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Реалізації інструментів і параметри сервера PortSwigger MCP](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy — вразливості Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger — історія WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger — робота з повідомленнями WebSocket у Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
