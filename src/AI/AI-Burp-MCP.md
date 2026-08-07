# Burp MCP: аналіз трафіку за допомогою LLM

{{#include ../banners/hacktricks-training.md}}

## Огляд

Розширення **MCP Server** для Burp може надавати перехоплений HTTP(S)-трафік MCP-сумісним LLM-клієнтам, щоб вони могли **аналізувати реальні запити/відповіді** для пасивного виявлення вразливостей і підготовки звітів. Мета полягає в evidence-driven аналізі (без fuzzing або blind scanning), при цьому Burp залишається джерелом істини.

## Архітектура

- **Burp MCP Server (BApp)** прослуховує `127.0.0.1:9876` і надає перехоплений трафік через MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** забезпечує взаємодію між stdio (на стороні клієнта) та MCP SSE endpoint Burp.
- **Необов'язковий локальний reverse proxy** (Caddy) нормалізує заголовки для суворих перевірок MCP handshake.
- **Клієнти/backend-системи**: Codex CLI (cloud), Gemini CLI (cloud) або Ollama (local).

## Налаштування

### 1) Встановіть Burp MCP Server

Встановіть **MCP Server** з Burp BApp Store і переконайтеся, що він прослуховує `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Витягніть proxy JAR

На вкладці MCP Server натисніть **Extract server proxy jar** і збережіть `mcp-proxy.jar`.

### 3) Налаштуйте MCP-клієнт (приклад із Codex)

Вкажіть клієнту шлях до proxy JAR і SSE endpoint Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Потім запустіть Codex і перегляньте список MCP tools:
```bash
codex
# inside Codex: /mcp
```
### 4) Виправлення суворої перевірки Origin/header за допомогою Caddy (якщо потрібно)

Якщо MCP handshake не вдається через суворі перевірки `Origin` або додаткові headers, використайте локальний reverse proxy для нормалізації headers (це відповідає workaround для проблеми суворої валідації Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Запустіть proxy та клієнт:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Використання різних клієнтів

### Codex CLI

- Налаштуйте `~/.codex/config.toml`, як описано вище.
- Запустіть `codex`, потім `/mcp`, щоб перевірити список інструментів Burp.

### Gemini CLI

Репозиторій **burp-mcp-agents** надає допоміжні засоби запуску:<sup>[[4]](#references)</sup>
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
Приклади локальних моделей і приблизні потреби у VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Набір промптів для пасивного аналізу

Репозиторій **burp-mcp-agents** містить шаблони промптів для аналізу трафіку Burp на основі доказів:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: широке виявлення вразливостей у пасивному режимі.
- `idor_hunter.md`: IDOR/BOLA/об’єкти/відхилення tenant і невідповідності авторизації.
- `auth_flow_mapper.md`: порівняння автентифікованих і неавтентифікованих шляхів.
- `ssrf_redirect_hunter.md`: кандидати на SSRF/open-redirect із параметрів отримання URL/ланцюжків перенаправлень.
- `logic_flaw_hunter.md`: логічні вразливості в багатокрокових процесах.
- `session_scope_hunter.md`: неправильне використання audience/scope токенів.
- `rate_limit_abuse_hunter.md`: недоліки throttling/захисту від зловживань.
- `report_writer.md`: підготовка звітів, зосереджених на доказах.

## Необов’язкове маркування атрибуції

Щоб позначати трафік Burp/LLM у журналах, додайте переписування заголовка (через proxy або Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Примітки щодо безпеки

- Надавайте перевагу **local models**, коли трафік містить конфіденційні дані.
- Передавайте лише мінімально необхідні докази для підтвердження знахідки.
- Використовуйте Burp як джерело достовірних даних; застосовуйте модель для **analysis and reporting**, а не для сканування.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** — це розширення Burp, яке поєднує локальні/хмарні LLM із пасивним/активним аналізом (62 класи вразливостей) і надає понад 53 MCP tools, щоб зовнішні MCP-клієнти могли керувати Burp.<sup>[[5]](#references)</sup> Основні можливості:

- **Context-menu triage**: перехопіть трафік через Proxy, відкрийте **Proxy > HTTP History**, клацніть правою кнопкою миші запит → **Extensions > Burp AI Agent > Analyze this request**, щоб запустити AI-чат, прив’язаний до цього запиту/відповіді.
- **Backends** (вибираються для кожного профілю):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint, сумісний з **OpenAI**, (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` або `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (вхід залежить від провайдера).
- **Agent profiles**: шаблони промптів автоматично встановлюються в `~/.burp-ai-agent/AGENTS/`; додайте туди додаткові файли `*.md`, щоб створити власні способи аналізу/сканування.
- **MCP server**: увімкніть через **Settings > MCP Server**, щоб надати будь-якому MCP-клієнту доступ до операцій Burp (понад 53 tools). Claude Desktop можна підключити до сервера, відредагувавши `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) або `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: режими STRICT / BALANCED / OFF приховують конфіденційні дані запитів перед надсиланням до remote models; під час роботи із секретами надавайте перевагу local backends.
- **Audit logging**: журнали JSONL із хешуванням цілісності SHA-256 для кожного запису, що забезпечує захищену від підробки відстежуваність дій AI/MCP.
- **Build/load**: завантажте release JAR або зберіть за допомогою Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Операційні застереження: хмарні бекенди можуть викрасти session cookies/PII, якщо не ввімкнено privacy mode; доступ до MCP надає віддалену оркестрацію Burp, тому обмежте доступ довіреними агентами та контролюйте журнал аудиту з хешем цілісності.

## Посилання

- [1] [Інтеграція Burp MCP + Codex CLI та виправлення handshake у Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Проблема суворої перевірки Origin/header у PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
