# Burp MCP: review трафіку за допомогою LLM

{{#include ../banners/hacktricks-training.md}}

## Огляд

Розширення **MCP Server** для Burp може надавати перехоплений HTTP(S)-трафік MCP-сумісним LLM-клієнтам, щоб вони могли **аналізувати реальні запити/відповіді** для виявлення вразливостей і підготовки чернеток звітів. Вважайте Burp джерелом істини: використовуйте пасивний аналіз або навмисні повторні запити зі зміною однієї змінної, а не сліпе сканування.<sup>[[8]](#references)</sup>

## Архітектура

- **Burp MCP Server (BApp)** за замовчуванням прослуховує `127.0.0.1:9876` і надає перехоплений трафік через MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** з'єднує stdio (на стороні клієнта) з MCP SSE endpoint Burp.
- **Необов'язковий локальний reverse proxy** (Caddy) нормалізує заголовки для строгих перевірок MCP handshake.
- **Клієнти/backend**: Codex CLI (cloud), Gemini CLI (cloud) або Ollama (local).

## Налаштування

### 1) Встановлення Burp MCP Server

Встановіть **MCP Server** з Burp BApp Store і переконайтеся, що він прослуховує `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Вилучення proxy JAR

На вкладці MCP Server натисніть **Extract server proxy jar** і збережіть `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Налаштування MCP-клієнта (приклад із Codex)

Вкажіть клієнту proxy JAR і прямий SSE endpoint Burp. Упакований proxy є мостом stdio-to-SSE; він не замінює listener Burp.<sup>[[7]](#references)</sup>
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
Потім запустіть Codex і перелічіть MCP tools:
```bash
codex
# inside Codex: /mcp
```
### 4) Виправлення суворої перевірки Origin/заголовків за допомогою Caddy (за потреби)

Якщо MCP handshake не вдається через суворі перевірки `Origin` або додаткові заголовки, використовуйте локальний reverse proxy для нормалізації заголовків (це відповідає workaround для проблеми суворої валідації Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Запустіть proxy і client та змініть налаштований `--sse-url` на `http://127.0.0.1:19876` лише під час використання цього Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Пов’яжіть стан browser із proxy-доказами (Playwright MCP)

Зареєструйте Playwright MCP, щоб його browser використовував proxy Burp. Це дає агенту змогу зіставляти відрендерений DOM/стан accessibility з точною HTTP-історією, яка його створила.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Адаптуйте адресу listener, перезапустіть Codex і використайте `/mcp`, щоб перевірити обидві інтеграції. У прикладі вимкнено помилки сертифікатів браузера, щоб HTTPS interception не блокувався локально згенерованим Burp сертифікатом.<sup>[[6]](#references)[[8]](#references)</sup>

## Автоматизація браузера з підтримкою proxy (OpenBurp)

З’єднання Burp MCP і шлях перехоплення браузера є окремими потоками даних. Сервіс MCP надає інструменти Burp через `127.0.0.1:9876`, тоді як спеціальний екземпляр Chromium надсилає свій HTTP(S)-трафік через proxy Burp на `127.0.0.1:8080`. Тому запити, створені безпосередньо інструментом MCP, можуть бути відсутні в **Proxy > HTTP history**; використовуйте браузер через proxy, коли запит/відповідь потрібно спостерігати, редагувати або зберегти як доказ.<sup>[[2]](#references)[[9]](#references)</sup>

Клієнт із підтримкою SSE може безпосередньо зареєструвати Burp. Клієнт, що підтримує лише stdio, може натомість запустити proxy JAR від PortSwigger. В обох випадках зареєструйте другий browser-control MCP і вкажіть його на вбудований Chromium Burp (`BURP_CHROMIUM` — це локальний шлях до виконуваного файлу):<sup>[[9]](#references)</sup>
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
Прапорець TLS-bypass допускає сертифікати, згенеровані interception proxy, тоді як `--isolated` не дозволяє assessment повторно використовувати звичайний профіль браузера оператора. Ізоляція захищає стан профілю, але **не є security sandbox**: controller все одно може отримувати доступ до authenticated sessions, відкритих у цьому тестовому браузері, а Burp MCP може розкривати чутливі requests, responses і configuration.<sup>[[9]](#references)</sup>

Перевірте SSE listener окремо, перш ніж налагоджувати client bridge:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Справний listener повертає `Content-Type: text/event-stream`. Тайм-аут після заголовків є очікуваним, оскільки SSE stream залишається відкритим для майбутніх подій. Якщо клієнт усе ще не працює, перевірте налаштований route extension: PortSwigger зазначає, що endpoint може бути root path або `/sse` залежно від клієнта та конфігурації extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Використання різних клієнтів

### Codex CLI

- Налаштуйте `~/.codex/config.toml`, як зазначено вище.
- Запустіть `codex`, потім `/mcp`, щоб перевірити список інструментів Burp.

### Gemini CLI

Репозиторій **burp-mcp-agents** надає допоміжні засоби запуску:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Скористайтеся наданим helper для запуску та виберіть локальну модель:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Приклади локальних моделей і приблизні потреби у VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Відтворення та валідація на основі доказів

Не дозволяйте агенту сприймати правдоподібне пояснення або проміжну відповідь як доказ. Використовуйте запити/відповіді Burp і незалежно перевірений стан браузера, щоб кожен тест можна було спростувати.<sup>[[8]](#references)</sup>

1. Збережіть пару базових запиту й відповіді та визначте точний компонент, контрольований атакувальником.
2. Для порівнянь авторизації незалежно перехопіть той самий workflow в обох облікових записах, перш ніж змінювати ідентифікатори, cookies або токени.
3. Перед повторним відтворенням зміни зафіксуйте гіпотезу, місце розташування доказу, очікуваний сигнал і результат, який її спростує.
4. Змінюйте один компонент за раз, зберігайте отриману пару та окремо позначайте безпосередні спостереження й висновки.
5. Відстежуйте кожен кандидат зі статусом `open`, `blocked`, `rejected` або `confirmed`; повертайтеся до нього лише тоді, коли нові докази змінюють механізм або необхідну передумову.
6. Підтверджуйте контроль атакувальника, досяжність, повторюваність, обхід обмежень, вплив і кінцевий стан застосунку. Перенаправлення або успішний виклик tool не є доказом, якщо заявлена зміна стану відбувається downstream.

Зберігайте деталі exploitation на відповідній сторінці техніки. Наприклад, кандидати, пов’язані з browser-message, належать до [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), а поведінка вибору ключа токена — до [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Компактний запис гіпотези допомагає паралельним агентам не повторювати ту саму привабливу гілку:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Набір промптів для пасивного аналізу

Репозиторій **burp-mcp-agents** містить шаблони промптів для аналізу трафіку Burp на основі доказів:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: широке виявлення пасивних вразливостей.
- `idor_hunter.md`: IDOR/BOLA, об’єкти, відхилення tenant і невідповідності авторизації.
- `auth_flow_mapper.md`: порівняння authenticated та unauthenticated шляхів.
- `ssrf_redirect_hunter.md`: кандидати на SSRF/open-redirect із параметрів URL fetch та ланцюжків redirect.
- `logic_flaw_hunter.md`: багатокрокові логічні вразливості.
- `session_scope_hunter.md`: неналежне використання audience/scope токенів.
- `rate_limit_abuse_hunter.md`: прогалини в throttling/захисті від зловживань.
- `report_writer.md`: підготовка звітів, орієнтованих на докази.

## Необов’язкове маркування атрибуції

Щоб позначати трафік Burp/LLM у логах, додайте перезапис заголовка (proxy або Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Примітки щодо безпеки

- Надавайте перевагу **локальним моделям**, коли traffic містить чутливі дані.
- Передавайте лише мінімально необхідні докази для finding.
- Вважайте Burp джерелом істини; використовуйте модель для **аналізу та звітування**, а не для сканування.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** — це розширення Burp, яке поєднує локальні/хмарні LLM із пасивним/активним аналізом (62 класи вразливостей) і надає понад 53 MCP tools, щоб зовнішні MCP-клієнти могли керувати Burp.<sup>[[5]](#references)</sup> Основні можливості:

- **Context-menu triage**: перехопіть traffic через Proxy, відкрийте **Proxy > HTTP History**, клацніть правою кнопкою миші запит → **Extensions > Burp AI Agent > Analyze this request**, щоб запустити AI-чат, прив’язаний до цього запиту/відповіді.
- **Backends** (вибираються для кожного профілю):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint, сумісний з **OpenAI** (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` або `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (вхід залежно від провайдера).
- **Agent profiles**: шаблони prompt автоматично встановлюються в `~/.burp-ai-agent/AGENTS/`; додайте туди додаткові файли `*.md`, щоб створити власну поведінку для аналізу/сканування.
- **MCP server**: увімкніть через **Settings > MCP Server**, щоб надати будь-якому MCP-клієнту доступ до операцій Burp (понад 53 tools). Claude Desktop можна підключити до сервера, відредагувавши `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) або `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: режими STRICT / BALANCED / OFF редагують чутливі дані запитів перед їх надсиланням до віддалених моделей; під час роботи із секретами надавайте перевагу локальним backends.
- **Audit logging**: журнали JSONL із хешуванням цілісності SHA-256 для кожного запису, що забезпечує захищену від підробки трасованість дій AI/MCP.
- **Build/load**: завантажте release JAR або зберіть за допомогою Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Операційні застереження: cloud backends можуть ексфільтрувати session cookies/PII, якщо privacy mode не ввімкнено; MCP exposure надає віддалену оркестрацію Burp, тому обмежте доступ довіреними агентами та контролюйте журнал аудиту з хешем цілісності.

## References

- [1] [Інтеграція Burp MCP + Codex CLI та виправлення handshake у Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Проблема суворої перевірки Origin/header у PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Як використовувати Codex для досліджень Bug Bounty: досліджуйте широко, ретельно перевіряйте](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: оркестрація Burp Suite для Claude Code і Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
