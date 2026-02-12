# Burp MCP: Przegląd ruchu wspomagany przez LLM

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Rozszerzenie Burp's **MCP Server** może udostępniać przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, aby mogli **analizować rzeczywiste żądania/odpowiedzi** w celu pasywnego wykrywania podatności i przygotowywania raportów. Intencją jest przegląd oparty na dowodach (bez fuzzingu ani blind scanning), z Burp jako źródłem prawdy.

## Architektura

- **Burp MCP Server (BApp)** nasłuchuje na `127.0.0.1:9876` i udostępnia przechwycony ruch przez MCP.
- **MCP proxy JAR** łączy stdio (po stronie klienta) z endpointem Burp MCP SSE.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje headers dla rygorystycznych kontroli handshake MCP.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Konfiguracja

### 1) Zainstaluj Burp MCP Server

Zainstaluj **MCP Server** z Burp BApp Store i sprawdź, czy nasłuchuje na `127.0.0.1:9876`.

### 2) Wyodrębnij proxy JAR

W zakładce MCP Server kliknij **Extract server proxy jar** i zapisz `mcp-proxy.jar`.

### 3) Skonfiguruj klienta MCP (przykład Codex)

Wskaż klientowi proxy JAR i endpoint SSE Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Nie mogę uruchomić Codex ani wykonywać zewnętrznego kodu. Proszę wklej zawartość pliku src/AI/AI-Burp-MCP.md, a przetłumaczę ją na polski. Jeśli zamiast tego chcesz listę narzędzi MCP, podaj proszę, co oznacza „MCP” w Twoim kontekście (np. Burp MCP, Mobile C2 Platform itp.).
```bash
codex
# inside Codex: /mcp
```
### 4) Napraw rygorystyczną walidację Origin/header za pomocą Caddy (jeśli potrzeba)

Jeśli handshake MCP nie powiedzie się z powodu rygorystycznych sprawdzeń `Origin` lub dodatkowych headers, użyj lokalnego reverse proxy, żeby znormalizować headers (to odpowiada obejściu dla problemu z rygorystyczną walidacją MCP w Burp).
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
Uruchom proxy i client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Używanie różnych klientów

### Codex CLI

- Skonfiguruj `~/.codex/config.toml` jak wyżej.
- Uruchom `codex`, potem `/mcp`, aby zweryfikować listę narzędzi Burp.

### Gemini CLI

Repozytorium **burp-mcp-agents** udostępnia skrypty uruchamiające:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Skorzystaj z dołączonego narzędzia launcher i wybierz lokalny model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack for passive review

The **burp-mcp-agents** repo includes prompt templates for evidence-driven analysis of Burp traffic:

- `passive_hunter.md`: szerokie pasywne vulnerability surfacing.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift i auth mismatches.
- `auth_flow_mapper.md`: porównaj authenticated vs unauthenticated paths.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates z URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse luki.
- `report_writer.md`: raportowanie skoncentrowane na evidence.

## Optional attribution tagging

To tag Burp/LLM traffic in logs, add a header rewrite (proxy or Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Uwagi dotyczące bezpieczeństwa

- Preferuj **lokalne modele** gdy ruch zawiera dane wrażliwe.
- Udostępniaj tylko minimalne dowody niezbędne do potwierdzenia ustalenia.
- Trzymaj Burp jako źródło prawdy; używaj modelu do **analizy i raportowania**, nie do skanowania.

## Burp AI Agent (triage wspomagany przez AI + narzędzia MCP)

**Burp AI Agent** to rozszerzenie Burp, które łączy lokalne/chmurowe LLM z analizą pasywną/aktywną (62 klasy podatności) i udostępnia 53+ narzędzi MCP, dzięki czemu zewnętrzni klienci MCP mogą sterować Burpem. Najważniejsze funkcje:

- **Context-menu triage**: przechwyć ruch przez Proxy, otwórz **Proxy > HTTP History**, kliknij prawym przyciskiem na żądanie → **Extensions > Burp AI Agent > Analyze this request** aby utworzyć czat AI powiązany z tym żądaniem/odpowiedzią.
- **Backends** (wybieralne dla każdego profilu):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: szablony promptów są automatycznie instalowane w `~/.burp-ai-agent/AGENTS/`; wrzuć tam dodatkowe pliki `*.md`, aby dodać niestandardowe zachowania analizy/skanowania.
- **MCP server**: włącz w **Settings > MCP Server**, aby udostępnić operacje Burp dowolnemu klientowi MCP (53+ narzędzi). Claude Desktop można wskazać na serwer edytując `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) lub `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF redagują wrażliwe dane żądań przed wysłaniem ich do zdalnych modeli; preferuj lokalne backendy przy obsłudze sekretów.
- **Audit logging**: logi JSONL z hashowaniem integralności SHA-256 dla każdego wpisu, zapewniające wykrywalność manipulacji i śledzenie działań AI/MCP.
- **Build/load**: pobierz release JAR lub zbuduj z Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Ostrzeżenia operacyjne: cloud backends mogą exfiltrate session cookies/PII, chyba że privacy mode jest wymuszony; ekspozycja MCP daje możliwość remote orchestration Burp, więc ogranicz dostęp do trusted agents i monitoruj integrity-hashed audit log.

## References

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
