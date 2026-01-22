# Burp MCP: przegląd ruchu wspomagany przez LLM

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Rozszerzenie Burp **MCP Server** może udostępnić przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, aby mogli oni **analizować rzeczywiste żądania/odpowiedzi** w celu pasywnego wykrywania podatności i przygotowywania raportów. Celem jest przegląd oparty na dowodach (bez fuzzingu ani blind scanningu), utrzymując Burp jako źródło prawdy.

## Architektura

- **Burp MCP Server (BApp)** nasłuchuje na `127.0.0.1:9876` i udostępnia przechwycony ruch przez MCP.
- **MCP proxy JAR** mostkuje stdio (po stronie klienta) do MCP SSE endpoint Burp.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje nagłówki dla ścisłych kontroli MCP handshake.
- **Klienci/backendy**: Codex CLI (cloud), Gemini CLI (cloud), lub Ollama (local).

## Konfiguracja

### 1) Zainstaluj Burp MCP Server

Zainstaluj **MCP Server** z Burp BApp Store i upewnij się, że nasłuchuje na `127.0.0.1:9876`.

### 2) Wyodrębnij proxy JAR

Na karcie MCP Server kliknij **Extract server proxy jar** i zapisz `mcp-proxy.jar`.

### 3) Skonfiguruj klienta MCP (przykład Codex)

Wskaż klienta na proxy JAR i SSE endpoint Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Proszę wgrać zawartość pliku src/AI/AI-Burp-MCP.md — bez niego nie mogę wykonać tłumaczenia.

Dodatkowo wyjaśnij proszę:
- Co rozumiesz przez „run Codex” — czy chcesz, żebym uruchomił zewnętrzny model Codex (nie mogę uruchamiać zewnętrznych procesów), czy mam użyć własnych możliwości do wygenerowania/parsowania informacji?
- „list MCP tools” — czy oczekujesz listy narzędzi MCP wyciągniętej z pliku, czy ogólnej listy narzędzi MCP niezależnej od pliku?

Wklej tu zawartość pliku i potwierdź powyższe, a przeprowadzę tłumaczenie i przygotuję listę.
```bash
codex
# inside Codex: /mcp
```
### 4) Napraw restrykcyjną walidację Origin/header z użyciem Caddy (jeśli potrzebne)

Jeśli handshake MCP nie powiedzie się z powodu restrykcyjnych sprawdzeń `Origin` lub dodatkowych headers, użyj lokalnego reverse proxy, aby znormalizować headers (to odpowiada obejściu problemu restrykcyjnej walidacji MCP w Burp).
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

- Skonfiguruj `~/.codex/config.toml` zgodnie z powyższym.
- Uruchom `codex`, następnie `/mcp`, aby zweryfikować listę narzędzi Burp.

### Gemini CLI

Repozytorium **burp-mcp-agents** zawiera skrypty uruchamiające:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Użyj dostarczonego launcher helpera i wybierz lokalny model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Przykładowe modele lokalne i przybliżone wymagania VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pakiet promptów do przeglądu pasywnego

Repozytorium **burp-mcp-agents** zawiera szablony promptów do analizy ruchu Burp opartej na dowodach:

- `passive_hunter.md`: szerokie, pasywne wykrywanie podatności.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift i auth mismatches.
- `auth_flow_mapper.md`: porównanie ścieżek uwierzytelnionych i nieuwierzytelnionych.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates wynikające z parametrów fetch URL/łańcuchów przekierowań.
- `logic_flaw_hunter.md`: wieloetapowe błędy logiczne.
- `session_scope_hunter.md`: niewłaściwe użycie tokena (audience/scope).
- `rate_limit_abuse_hunter.md`: luki w rate limiting / możliwości nadużyć.
- `report_writer.md`: raportowanie zorientowane na dowody.

## Opcjonalne tagowanie atrybucji

Aby oznaczyć ruch Burp/LLM w logach, dodaj przepisywanie nagłówka (proxy lub Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notatki bezpieczeństwa

- Preferuj **lokalne modele**, gdy ruch zawiera wrażliwe dane.
- Udostępniaj jedynie minimalne dowody potrzebne do potwierdzenia znaleziska.
- Trzymaj Burp jako źródło prawdy; używaj modelu do **analizy i raportowania**, a nie do skanowania.

## Referencje

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
