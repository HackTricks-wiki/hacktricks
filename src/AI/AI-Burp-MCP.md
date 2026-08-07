# Burp MCP: przegląd ruchu wspomagany przez LLM

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Extension **MCP Server** dla Burp może udostępniać przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, dzięki czemu mogą one **analizować rzeczywiste żądania/odpowiedzi** w celu pasywnego wykrywania podatności i tworzenia wersji roboczych raportów. Celem jest przegląd oparty na dowodach (bez fuzzingu i skanowania w ciemno), przy zachowaniu Burp jako źródła prawdy.

## Architektura

- **Burp MCP Server (BApp)** nasłuchuje na `127.0.0.1:9876` i udostępnia przechwycony ruch przez MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** łączy stdio (po stronie klienta) z endpointem MCP SSE Burp.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje nagłówki na potrzeby rygorystycznych kontroli handshake MCP.
- **Klienci/backendy**: Codex CLI (cloud), Gemini CLI (cloud) lub Ollama (local).

## Konfiguracja

### 1) Instalacja Burp MCP Server

Zainstaluj **MCP Server** z Burp BApp Store i sprawdź, czy nasłuchuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Wyodrębnienie proxy JAR

Na karcie MCP Server kliknij **Extract server proxy jar** i zapisz plik `mcp-proxy.jar`.

### 3) Konfiguracja klienta MCP (przykład dla Codex)

Skonfiguruj klienta tak, aby korzystał z proxy JAR i endpointu SSE Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Następnie uruchom Codex i wyświetl listę narzędzi MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Napraw ścisłą walidację Origin/header za pomocą Caddy (jeśli potrzebne)

Jeśli handshake MCP kończy się niepowodzeniem z powodu ścisłych kontroli `Origin` lub dodatkowych headerów, użyj lokalnego reverse proxy do normalizacji headerów (odpowiada to obejściu problemu ścisłej walidacji Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Uruchom proxy i klienta:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Korzystanie z różnych klientów

### Codex CLI

- Skonfiguruj `~/.codex/config.toml` zgodnie z powyższymi instrukcjami.
- Uruchom `codex`, a następnie `/mcp`, aby zweryfikować listę narzędzi Burp.

### Gemini CLI

Repozytorium **burp-mcp-agents** udostępnia pomocnicze launchery:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Użyj dostarczonego helpera uruchamiającego i wybierz lokalny model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Przykładowe lokalne modele i przybliżone wymagania dotyczące VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack do pasywnego przeglądu

Repo **burp-mcp-agents** zawiera szablony promptów do analizy ruchu Burp opartej na dowodach:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: szerokie wykrywanie pasywnych podatności.
- `idor_hunter.md`: IDOR/BOLA, obiektów, rozbieżności tenantów i niezgodności uwierzytelniania.
- `auth_flow_mapper.md`: porównywanie ścieżek uwierzytelnionych i nieuwierzytelnionych.
- `ssrf_redirect_hunter.md`: kandydaci do SSRF/open-redirect na podstawie parametrów pobierania URL i łańcuchów przekierowań.
- `logic_flaw_hunter.md`: wieloetapowe błędy logiczne.
- `session_scope_hunter.md`: niewłaściwe użycie audience/scope tokenów.
- `rate_limit_abuse_hunter.md`: luki w throttlingu i ochronie przed abuse.
- `report_writer.md`: raportowanie skoncentrowane na dowodach.

## Opcjonalne tagowanie atrybucji

Aby tagować ruch Burp/LLM w logach, dodaj przepisanie nagłówka (proxy lub Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Uwagi dotyczące bezpieczeństwa

- Preferuj **lokalne modele**, gdy ruch zawiera wrażliwe dane.
- Udostępniaj tylko minimalną ilość dowodów wymaganą dla danego ustalenia.
- Traktuj Burp jako źródło prawdy; używaj modelu do **analizy i raportowania**, a nie do skanowania.

## Burp AI Agent (triage wspomagany przez AI + narzędzia MCP)

**Burp AI Agent** to rozszerzenie Burp, które łączy lokalne/chmurowe LLM z pasywną/aktywną analizą (62 klasy podatności) i udostępnia ponad 53 narzędzia MCP, dzięki czemu zewnętrzni klienci MCP mogą sterować Burp.<sup>[[5]](#references)</sup> Najważniejsze funkcje:

- **Triage z menu kontekstowego**: przechwyć ruch przez Proxy, otwórz **Proxy > HTTP History**, kliknij żądanie prawym przyciskiem myszy → **Extensions > Burp AI Agent > Analyze this request**, aby uruchomić czat AI powiązany z tym żądaniem/odpowiedzią.
- **Backends** (wybierane dla każdego profilu):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint zgodny z **OpenAI** (bazowy URL + nazwa modelu).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` lub `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (logowanie zależne od dostawcy).
- **Profile agentów**: szablony promptów są automatycznie instalowane w `~/.burp-ai-agent/AGENTS/`; umieść tam dodatkowe pliki `*.md`, aby dodać własne zachowania analizy/skanowania.
- **Serwer MCP**: włącz go przez **Settings > MCP Server**, aby udostępnić operacje Burp dowolnemu klientowi MCP (ponad 53 narzędzia). Claude Desktop można skonfigurować do korzystania z serwera, edytując `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) lub `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrola prywatności**: tryby STRICT / BALANCED / OFF usuwają wrażliwe dane z żądań przed wysłaniem ich do zdalnych modeli; podczas obsługi sekretów preferuj lokalne backends.
- **Logowanie audytowe**: logi JSONL z integralnościowym hashowaniem SHA-256 dla każdego wpisu, zapewniające śledzenie działań AI/MCP z wykrywaniem manipulacji.
- **Build/load**: pobierz wydany plik JAR lub zbuduj go przy użyciu Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Ostrzeżenia operacyjne: cloud backends mogą eksfiltrować session cookies/PII, jeśli nie wymusisz trybu prywatności; ekspozycja MCP umożliwia zdalną orkiestrację Burp, dlatego ogranicz dostęp do zaufanych agentów i monitoruj log audytowy z hashem integralności.

## Referencje

- [1] [Integracja Burp MCP + Codex CLI i poprawka handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem ze ścisłą walidacją Origin/header w serwerze MCP PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
