# Burp MCP: аналіз трафіку за допомогою LLM

{{#include ../banners/hacktricks-training.md}}

## Огляд

Розширення **MCP Server** для Burp може надавати перехоплений HTTP(S)-трафік MCP-сумісним LLM-клієнтам, щоб вони могли **аналізувати реальні запити/відповіді** для виявлення вразливостей і підготовки звітів. Використовуйте Burp як єдине достовірне джерело: застосовуйте пасивний аналіз або навмисні повторні відправлення з однією змінною замість сліпого сканування.<sup>[[8]](#references)</sup>

## Архітектура

- **Burp MCP Server (BApp)** за замовчуванням прослуховує `127.0.0.1:9876` і надає перехоплений трафік через MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** з'єднує stdio (на стороні клієнта) з MCP SSE endpoint Burp.
- **Необов'язковий локальний reverse proxy** (Caddy) нормалізує заголовки для суворих перевірок MCP handshake.
- **Клієнти/бекенди**: Codex CLI (cloud), Gemini CLI (cloud) або Ollama (local).

## Налаштування

### 1) Встановлення Burp MCP Server

Встановіть **MCP Server** з Burp BApp Store і переконайтеся, що він прослуховує `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Витягнення proxy JAR

На вкладці MCP Server натисніть **Extract server proxy jar** і збережіть `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Налаштування MCP-клієнта (приклад із Codex)

Вкажіть клієнту шлях до proxy JAR і прямого SSE endpoint Burp. Упакований proxy є мостом stdio-to-SSE; він не замінює listener Burp.<sup>[[7]](#references)</sup>
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

Якщо handshake MCP не проходить через суворі перевірки `Origin` або додаткові заголовки, використайте локальний reverse proxy для нормалізації заголовків (це відповідає workaround для проблеми суворої валідації Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
### 5) Поєднання стану браузера з доказами проксі (Playwright MCP)

Зареєструйте Playwright MCP, щоб його браузер використовував проксі Burp. Це дає змогу агенту співвідносити відображений DOM/стан доступності з точною HTTP-історією, яка його створила.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Адаптуйте адресу listener, перезапустіть Codex і використайте `/mcp`, щоб перевірити обидві інтеграції. У прикладі вимкнено помилки сертифікатів браузера, щоб HTTPS-перехоплення не блокувалося локально згенерованим сертифікатом Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Використання різних клієнтів

### Codex CLI

- Налаштуйте `~/.codex/config.toml`, як описано вище.
- Запустіть `codex`, потім `/mcp`, щоб перевірити список інструментів Burp.

### Gemini CLI

Репозиторій **burp-mcp-agents** містить допоміжні засоби запуску:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (локальна)

Використайте наданий допоміжний засіб запуску та виберіть локальну модель:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Приклади local models і приблизні потреби у VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Evidence-driven replay and validation

Не дозволяйте agent вважати правдоподібне пояснення або проміжну відповідь доказом. Використовуйте Burp requests/responses і незалежно спостережуваний стан browser, щоб кожен тест можна було спростувати.<sup>[[8]](#references)</sup>

1. Збережіть baseline request/response pair і визначте точний компонент, контрольований attacker.
2. Для порівнянь авторизації незалежно capture той самий workflow під обома accounts до зміни identifiers, cookies або tokens.
3. Перед replaying mutation запишіть hypothesis, location evidence, expected signal і результат, який її спростує.
4. Змінюйте один компонент за раз, зберігайте отриману pair і окремо позначайте direct observations та inference.
5. Відстежуйте кожного кандидата як `open`, `blocked`, `rejected` або `confirmed`; повертайтеся до нього лише тоді, коли нові evidence змінюють mechanism або prerequisite.
6. Підтвердіть attacker control, reachability, repeatability, constraint bypass, impact і фінальний application state. Redirect або успішний tool call не є доказом, якщо заявлена зміна state відбувається downstream.

Зберігайте деталі exploitation на відповідній сторінці technique. Наприклад, browser-message candidates належать до [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), тоді як поведінка token key-selection належить до [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Компактний запис hypothesis допомагає parallel agents не повторювати ту саму привабливу branch:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Набір prompt-ів для passive review

Репозиторій **burp-mcp-agents** містить шаблони prompt-ів для evidence-driven аналізу Burp traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: широке passive виявлення вразливостей.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift і auth mismatches.
- `auth_flow_mapper.md`: порівняння authenticated та unauthenticated paths.
- `ssrf_redirect_hunter.md`: кандидати на SSRF/open-redirect з URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: прогалини у throttling/abuse.
- `report_writer.md`: evidence-focused reporting.

## Необов'язкове tagging attribution

Щоб позначати Burp/LLM traffic у логах, додайте header rewrite (proxy або Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Нотатки щодо безпеки

- Віддавайте перевагу **локальним моделям**, коли трафік містить конфіденційні дані.
- Надсилайте лише мінімально необхідні докази для підтвердження знахідки.
- Використовуйте Burp як єдине джерело істини; застосовуйте модель для **аналізу та звітування**, а не для сканування.

## Burp AI Agent (тріаж за допомогою AI + MCP tools)

**Burp AI Agent** — це розширення Burp, яке поєднує локальні/хмарні LLM із пасивним/активним аналізом (62 класи вразливостей) і надає понад 53 MCP tools, щоб зовнішні MCP-клієнти могли керувати Burp.<sup>[[5]](#references)</sup> Основні можливості:

- **Тріаж через контекстне меню**: перехопіть трафік через Proxy, відкрийте **Proxy > HTTP History**, клацніть правою кнопкою миші запит → **Extensions > Burp AI Agent > Analyze this request**, щоб відкрити AI-чат, прив’язаний до цього запиту/відповіді.
- **Бекенди** (вибираються для кожного профілю):
- Локальний HTTP: **Ollama**, **LM Studio**.
- Віддалений HTTP: OpenAI-сумісний endpoint (base URL + назва моделі).
- Хмарні CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` або `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (вхід залежить від провайдера).
- **Профілі агентів**: шаблони промптів автоматично встановлюються в `~/.burp-ai-agent/AGENTS/`; додайте туди додаткові файли `*.md`, щоб додати власну поведінку для аналізу/сканування.
- **MCP server**: увімкніть через **Settings > MCP Server**, щоб надати будь-якому MCP-клієнту доступ до операцій Burp (понад 53 tools). Claude Desktop можна підключити до server, відредагувавши `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) або `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Контроль конфіденційності**: режими STRICT / BALANCED / OFF маскують конфіденційні дані запитів перед надсиланням до віддалених моделей; під час роботи із секретами віддавайте перевагу локальним бекендам.
- **Журнал аудиту**: журнали JSONL із хешуванням цілісності SHA-256 для кожного запису, що забезпечує відстежуваність дій AI/MCP із виявленням підробок.
- **Збірка/завантаження**: завантажте release JAR або виконайте збірку за допомогою Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Операційні застереження: хмарні бекенди можуть ексфільтрувати session cookies/PII, якщо не ввімкнено режим конфіденційності; доступ MCP дає можливість віддаленого керування Burp, тому обмежте доступ довіреними агентами та контролюйте цілісність audit log із хешуванням.

## References

- [1] [Інтеграція Burp MCP + Codex CLI та виправлення Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Проблема суворої перевірки Origin/header у PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Як використовувати Codex для досліджень Bug Bounty: широко досліджуйте, ретельно перевіряйте](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
