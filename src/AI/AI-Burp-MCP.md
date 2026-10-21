# Burp MCP: аналіз трафіку за допомогою LLM

{{#include ../banners/hacktricks-training.md}}

## Огляд

Розширення **MCP Server** для Burp може надавати перехоплений HTTP(S)-трафік MCP-сумісним LLM-клієнтам, щоб вони могли **аналізувати реальні запити/відповіді** для виявлення вразливостей і підготовки звітів. Вважайте Burp першоджерелом істини: використовуйте пасивний аналіз або цілеспрямовані повторні запити зі зміною однієї змінної, а не сліпе сканування.<sup>[[8]](#references)</sup>

## Архітектура

- **Burp MCP Server (BApp)** за замовчуванням прослуховує `127.0.0.1:9876` і надає перехоплений трафік через MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** з'єднує stdio (на боці клієнта) з кінцевою точкою MCP SSE у Burp.
- **Необов'язковий локальний reverse proxy** (Caddy) нормалізує заголовки для суворих перевірок MCP handshake.
- **Клієнти/бекенди**: Codex CLI (cloud), Gemini CLI (cloud) або Ollama (local).

## Налаштування

### 1) Встановіть Burp MCP Server

Встановіть **MCP Server** із Burp BApp Store і переконайтеся, що він прослуховує `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Витягніть proxy JAR

На вкладці MCP Server натисніть **Extract server proxy jar** і збережіть `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Налаштуйте MCP-клієнт (приклад із Codex)

Спрямуйте клієнт на proxy JAR і безпосередньо на кінцеву точку SSE у Burp. Упакований proxy є мостом stdio-to-SSE; він не замінює listener Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

Еквівалентна команда Codex:<sup>[[7]](#references)[[8]](#references)</sup>

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

Якщо MCP handshake завершується помилкою через суворі перевірки `Origin` або додаткові заголовки, використайте локальний reverse proxy для нормалізації заголовків (це відповідає обхідному рішенню для проблеми суворої валідації Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

### 5) Зіставте стан браузера з даними проксі (Playwright MCP)

Налаштуйте Playwright MCP так, щоб браузер використовував проксі Burp. Це дає змогу агенту зіставляти відображений DOM і стан доступності з точними даними HTTP-історії, які їх сформували.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Змініть адресу listener, перезапустіть Codex і скористайтеся `/mcp`, щоб перевірити обидві інтеграції. У прикладі вимкнено перевірку помилок сертифікатів браузера, щоб HTTPS-перехопленню не заважав сертифікат, згенерований локально Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Автоматизація браузера з урахуванням проксі (OpenBurp)

З’єднання Burp MCP і перехоплений трафік браузера — це окремі потоки даних. Сервіс MCP надає інструменти Burp через `127.0.0.1:9876`, тоді як окремий екземпляр Chromium надсилає HTTP(S)-трафік через проксі Burp на `127.0.0.1:8080`. Тому запити, створені безпосередньо інструментом MCP, можуть бути відсутні в **Proxy > HTTP history**; використовуйте браузер, налаштований на проксі, коли запит/відповідь потрібно спостерігати, редагувати або зберігати як доказ.<sup>[[2]](#references)[[9]](#references)</sup>

Клієнт із підтримкою SSE може зареєструвати Burp безпосередньо. Клієнт, що підтримує лише stdio, може натомість запустити JAR-файл PortSwigger. В обох випадках зареєструйте другий MCP для керування браузером і вкажіть йому на вбудований Chromium у Burp (`BURP_CHROMIUM` — локальний шлях до виконуваного файла):<sup>[[9]](#references)</sup>

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

Прапорець TLS-bypass приймає сертифікати, згенеровані interception proxy, а `--isolated` не дає оцінюванню повторно використовувати звичайний профіль браузера оператора. Ізоляція захищає стан профілю, але **не є пісочницею безпеки**: controller усе ще може отримати доступ до автентифікованих сеансів, відкритих у цьому тестовому браузері, а Burp MCP може розкривати конфіденційні запити, відповіді та конфігурацію.<sup>[[9]](#references)</sup>

Перш ніж налагоджувати клієнтський міст, перевірте SSE listener окремо:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Здоровий listener повертає `Content-Type: text/event-stream`. Тайм-аут після отримання заголовків очікуваний, оскільки SSE-потік залишається відкритим для майбутніх подій. Якщо клієнт і далі не працює, перевірте налаштований маршрут розширення: PortSwigger зазначає, що кінцевою точкою може бути кореневий шлях або `/sse` — залежно від клієнта та конфігурації розширення.<sup>[[9]](#references)[[7]](#references)</sup>

## Використання різних клієнтів

### Codex CLI

- Налаштуйте `~/.codex/config.toml`, як описано вище.
- Запустіть `codex`, а потім введіть `/mcp`, щоб перевірити список інструментів Burp.

### Gemini CLI

Репозиторій **burp-mcp-agents** надає допоміжні засоби для запуску:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (локально)

Скористайтеся наданим допоміжним засобом запуску та виберіть локальну модель:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Приклади локальних моделей і приблизні вимоги до VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Відтворення та перевірка на основі доказів

Не дозволяйте агенту вважати правдоподібне пояснення чи проміжну відповідь доказом. Використовуйте запити/відповіді Burp і незалежно спостережуваний стан браузера, щоб зробити кожен тест спростовним.<sup>[[8]](#references)</sup>

1. Збережіть базову пару запит/відповідь і визначте точний компонент, контрольований атакувальником.
2. Для порівняння авторизації окремо зафіксуйте той самий робочий процес для обох облікових записів, перш ніж змінювати ідентифікатори, cookies чи токени.
3. Перш ніж відтворювати мутацію, запишіть гіпотезу, місце доказу, очікуваний сигнал і результат, який її спростував би.
4. Змінюйте по одному компоненту за раз, зберігайте отриману пару та чітко відокремлюйте безпосередні спостереження від висновків.
5. Позначайте кожного кандидата як `open`, `blocked`, `rejected` або `confirmed`; повертайтеся до нього лише тоді, коли нові докази змінюють механізм або передумову.
6. Підтвердьте контроль з боку атакувальника, досяжність, повторюваність, обхід обмежень, вплив і кінцевий стан застосунку. Перенаправлення чи успішний виклик інструмента не є доказом, якщо заявлена зміна стану відбувається далі.

Деталі експлуатації залишайте на відповідній сторінці техніки. Наприклад, кандидати, пов’язані з browser-message, належать до [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), а поведінка вибору ключа токена — до [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Стислий запис гіпотези допомагає паралельним агентам не повторювати ту саму спокусливу гілку:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Цільова позасмугова валідація за допомогою Burp MCP

Burp Suite Professional надає `generate_collaborator_payload` і `get_collaborator_interactions` через офіційне MCP-розширення. Поєднайте їх із `get_proxy_http_history_regex` і одним повторним запитом через `send_http1_request`, щоб перевірити підозрілий серверний запит URL, не скануючи всю ціль. Для читання історії та надсилання запиту Burp може вимагати окремого підтвердження.<sup>[[2]](#references)[[10]](#references)</sup>

1. Відфільтруйте історію за запитом, що містить URL-кандидат, наприклад із `url=`, `webhook` або `callback`. Збережіть оригінальні запит і відповідь. Інструмент історії приймає `regex`, `count` і `offset`; переглядайте результати сторінками, а не просіть модель перевірити кожен запис.<sup>[[10]](#references)</sup>
2. Згенеруйте новий payload Collaborator і збережіть отриманий **payload ID**. Повторіть перехоплений запит до того самого хоста й порту, змінивши лише URL-кандидат на HTTPS URL у домені цього payload. Для `send_http1_request` передайте повний запит HTTP/1.1 як `content`, а також `targetHostname`, `targetPort` і `usesHttps`; поля призначення вказують на **застосунок**, а не на хост Collaborator.<sup>[[10]](#references)</sup>
3. Перевірте `get_collaborator_interactions`, передавши цей payload ID, і зіставте час взаємодії з часом повторного запиту. HTTP-взаємодія свідчить про виконання запиту, тоді як сам лише DNS-запит показує розв'язання імені, але не завершений HTTP-запит. Перевірте джерело взаємодії та заголовки запиту, щоб відрізнити вихідний трафік сервера від завантаження у браузері, а потім повторіть тест із новим payload, щоб виключити сторонній трафік.<sup>[[10]](#references)[[11]](#references)</sup>

Інструмент запитів MCP повертає відповідь безпосередньо й не обов'язково додає її до **Proxy > HTTP history**. Збережіть результат запиту й відповіді або скористайтеся проксійованим браузером чи Repeater, щоб отримати артефакт, який зберігається в історії. Для вибору SSRF payload і подальших тестів скористайтеся [розділом про SSRF](../pentesting-web/ssrf-server-side-request-forgery/), а не вважайте позасмуговий callback доказом впливу на внутрішню мережу. Щоб перевірити сам MCP-сервер, див. [тестування MCP-сервера](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Набір промптів для пасивного аналізу

Репозиторій **burp-mcp-agents** містить шаблони промптів для аналізу трафіку Burp на основі доказів:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: широке виявлення вразливостей пасивним аналізом.
- `idor_hunter.md`: IDOR/BOLA, невідповідності об'єктів і орендарів, а також помилки автентифікації.
- `auth_flow_mapper.md`: порівняння автентифікованих і неавтентифікованих шляхів.
- `ssrf_redirect_hunter.md`: кандидати на SSRF/open redirect у параметрах отримання URL і ланцюжках перенаправлень.
- `logic_flaw_hunter.md`: багатокрокові логічні вразливості.
- `session_scope_hunter.md`: зловживання аудиторією/областю дії токена.
- `rate_limit_abuse_hunter.md`: недоліки обмеження частоти запитів і захисту від зловживань.
- `report_writer.md`: звітування з акцентом на доказах.

## Необов'язкове маркування для атрибуції

Щоб позначати трафік Burp/LLM у журналах, додайте правило переписування заголовків (у проксі або Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Примітки з безпеки

- Віддавайте перевагу **локальним моделям**, якщо трафік містить конфіденційні дані.
- Надавайте лише мінімально необхідні докази для підтвердження знахідки.
- Вважайте Burp єдиним достовірним джерелом; використовуйте модель для **аналізу та звітування**, а не сканування.

## Burp AI Agent (тріаж за допомогою AI + інструменти MCP)

**Burp AI Agent** — це розширення Burp, яке поєднує локальні/хмарні LLM із пасивним/активним аналізом (62 класи вразливостей) і надає понад 53 інструменти MCP, щоб зовнішні клієнти MCP могли керувати Burp.<sup>[[5]](#references)</sup> Основні можливості:

- **Тріаж через контекстне меню**: перехопіть трафік через Proxy, відкрийте **Proxy > HTTP History**, клацніть правою кнопкою миші запит → **Extensions > Burp AI Agent > Analyze this request**, щоб відкрити чат AI, прив’язаний до цього запиту/відповіді.
- **Backend-и** (можна вибрати для кожного профілю):
  - Локальний HTTP: **Ollama**, **LM Studio**.
  - Віддалений HTTP: endpoint, сумісний з **OpenAI** (базова URL-адреса + назва моделі).
  - Хмарні CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` або `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (вхід залежить від провайдера).
- **Профілі Agent**: шаблони промптів автоматично встановлюються в `~/.burp-ai-agent/AGENTS/`; додайте туди додаткові файли `*.md`, щоб створити власні сценарії аналізу/сканування.
- **MCP server**: увімкніть у **Settings > MCP Server**, щоб надавати операції Burp будь-якому клієнту MCP (понад 53 інструменти). Щоб підключити Claude Desktop до сервера, відредагуйте `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) або `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Налаштування приватності**: режими STRICT / BALANCED / OFF приховують конфіденційні дані запитів перед надсиланням їх віддаленим моделям; під час роботи із секретами віддавайте перевагу локальним backend-ам.
- **Журнал аудиту**: журнали JSONL з хешуванням SHA-256 для кожного запису, що забезпечує захищене від підробки відстеження дій AI/MCP.
- **Збірка/завантаження**: завантажте JAR-файл релізу або зберіть проєкт за допомогою Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Операційні застереження: хмарні backend-системи можуть викрадати session cookies/PII, якщо не ввімкнено режим конфіденційності; доступ до MCP надає віддалене керування Burp, тому обмежте доступ довіреними агентами та контролюйте журнал аудиту з хешами цілісності.



## References

- [1] [Інтеграція Burp MCP + Codex CLI та виправлення Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Проблема суворої перевірки Origin/header у PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Агенти Burp MCP (workflow, launchers, набір prompt)](https://github.com/six2dez/burp-mcp-agents)
- [5] [AI-агент Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Як використовувати Codex для дослідження Bug Bounty: широко досліджуйте, ретельно перевіряйте](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: оркестрація Burp Suite для Claude Code і Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Реалізації інструментів і параметри PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy — вразливості Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
