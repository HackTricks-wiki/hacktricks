# Burp MCP: Огляд трафіку за допомогою LLM

{{#include ../banners/hacktricks-training.md}}

## Огляд

Розширення Burp **MCP Server** може надавати перехоплений HTTP(S) трафік LLM-клієнтам, сумісним із MCP, щоб вони могли **аналізувати реальні запити/відповіді** для пасивного виявлення вразливостей і складання звітів. Мета — огляд, заснований на доказах (без fuzzing або blind scanning), де Burp залишається джерелом істини.

## Архітектура

- **Burp MCP Server (BApp)** прослуховує `127.0.0.1:9876` і надає перехоплений трафік через MCP.
- **MCP proxy JAR** з'єднує stdio (з боку клієнта) з MCP SSE endpoint Burp.
- **Optional local reverse proxy** (Caddy) нормалізує заголовки для суворих перевірок MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Налаштування

### 1) Встановіть Burp MCP Server

Встановіть **MCP Server** з Burp BApp Store і переконайтеся, що воно прослуховує `127.0.0.1:9876`.

### 2) Extract the proxy JAR

На вкладці MCP Server натисніть **Extract server proxy jar** і збережіть `mcp-proxy.jar`.

### 3) Налаштуйте MCP клієнта (приклад для Codex)

Вкажіть клієнту шлях до proxy JAR і SSE endpoint Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Я не маю доступу до вашої файлової системи та не можу виконувати Codex. Надішліть, будь ласка, вміст файлу src/AI/AI-Burp-MCP.md (або вставте потрібні розділи), і я перекладу англійський текст українською, зберігаючи всю надану markdown/html структуру. 

Якщо ви замість цього хочете просто загальний список MCP tools (без файлу), уточніть — під MCP ви маєте на увазі конкретну категорію у Burp (наприклад, Burp extensions для "MCP") чи інше? Я можу одразу надати типовий список інструментів після уточнення.
```bash
codex
# inside Codex: /mcp
```
### 4) Виправлення суворої валідації Origin/header за допомогою Caddy (якщо потрібно)

Якщо MCP handshake не проходить через суворі перевірки `Origin` або додаткові headers, використовуйте локальний reverse proxy для нормалізації headers (це відповідає workaround для проблеми суворої валідації MCP у Burp).
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
Запустіть proxy та client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Використання різних клієнтів

### Codex CLI

- Налаштуйте `~/.codex/config.toml`, як зазначено вище.
- Запустіть `codex`, потім `/mcp`, щоб перевірити список інструментів Burp.

### Gemini CLI

Репозиторій **burp-mcp-agents** містить допоміжні скрипти для запуску:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (локально)

Використайте наданий launcher helper та виберіть локальну модель:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Приклади локальних моделей та приблизні вимоги до VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack for passive review

Репозиторій **burp-mcp-agents** містить шаблони prompt для аналізу Burp-трафіку, орієнтованого на докази:

- `passive_hunter.md`: широке пасивне виявлення вразливостей.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift та auth mismatches.
- `auth_flow_mapper.md`: порівняння authenticated vs unauthenticated шляхів.
- `ssrf_redirect_hunter.md`: кандидати SSRF/open-redirect від URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: багатокрокові логічні помилки.
- `session_scope_hunter.md`: зловживання token audience/scope.
- `rate_limit_abuse_hunter.md`: прогалини в throttling/abuse.
- `report_writer.md`: звітування, орієнтоване на докази.

## Optional attribution tagging

Щоб позначати Burp/LLM трафік у логах, додайте перезапис заголовка (proxy або Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Примітки щодо безпеки

- Віддавайте перевагу **локальним моделям**, якщо трафік містить конфіденційні дані.
- Діліться лише мінімальною кількістю доказів, необхідних для підтвердження знахідки.
- Зберігайте Burp як джерело істини; використовуйте модель для **аналізу та звітності**, а не для сканування.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** — розширення для Burp, що поєднує локальні/хмарні LLM з пасивним/активним аналізом (62 класи вразливостей) та відкриває доступ до 53+ MCP tools, щоб зовнішні MCP clients могли оркеструвати Burp. Основні моменти:

- **Context-menu triage**: перехопіть трафік через Proxy, відкрийте **Proxy > HTTP History**, клацніть правою кнопкою запит → **Extensions > Burp AI Agent > Analyze this request**, щоб відкрити чат AI, прив'язаний до цього запиту/відповіді.
- **Backends** (вибираються для кожного профілю):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: шаблони prompt автоматично встановлюються в `~/.burp-ai-agent/AGENTS/`; додайте туди додаткові `*.md` файли, щоб додати кастомні поведінки аналізу/сканування.
- **MCP server**: увімкніть через **Settings > MCP Server**, щоб відкрити операції Burp для будь-якого MCP client (53+ tools). Claude Desktop можна вказати на сервер, відредагувавши `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) або `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF маскують конфіденційні дані запиту перед відправленням на віддалені моделі; віддавайте перевагу локальним бекендам при роботі зі секретами.
- **Audit logging**: JSONL логи з по-записовим SHA-256 хешуванням цілісності для виявлення підробок і простежуваності дій AI/MCP.
- **Build/load**: download the release JAR or build with Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Оперативні застереження: cloud backends можуть ексфільтрувати session cookies/PII, якщо не увімкнено privacy mode; експозиція MCP надає віддалену оркестрацію Burp — тож обмежте доступ лише довіреним agents і моніторьте integrity-hashed audit log.

## Посилання

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
