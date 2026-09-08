# Burp MCP: przegląd ruchu wspomagany przez LLM

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Rozszerzenie **MCP Server** dla Burp może udostępniać przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, dzięki czemu mogą one **analizować rzeczywiste żądania/odpowiedzi** w celu wykrywania podatności i tworzenia wersji roboczych raportów. Burp powinien pozostać źródłem prawdy: używaj analizy pasywnej lub celowych powtórzeń z modyfikacją jednej zmiennej zamiast ślepego skanowania.<sup>[[8]](#references)</sup>

## Architektura

- **Burp MCP Server (BApp)** domyślnie nasłuchuje na `127.0.0.1:9876` i udostępnia przechwycony ruch za pośrednictwem MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** łączy stdio (po stronie klienta) z endpointem MCP SSE Burp.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje nagłówki na potrzeby rygorystycznych kontroli handshake MCP.
- **Klienci/backendy**: Codex CLI (cloud), Gemini CLI (cloud) lub Ollama (lokalnie).

## Konfiguracja

### 1) Instalacja Burp MCP Server

Zainstaluj **MCP Server** z Burp BApp Store i sprawdź, czy nasłuchuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Wyodrębnienie proxy JAR

Na karcie MCP Server kliknij **Extract server proxy jar** i zapisz plik `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Konfiguracja klienta MCP (przykład z Codex)

Skieruj klienta do proxy JAR i bezpośredniego endpointu SSE Burp. Dołączone proxy jest mostem stdio-to-SSE; nie zastępuje listenera Burp.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Odpowiednikiem polecenia Codex jest:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Następnie uruchom Codex i wyświetl listę MCP tools:
```bash
codex
# inside Codex: /mcp
```
### 4) Napraw ścisłą walidację Origin/headerów za pomocą Caddy (jeśli potrzebne)

Jeśli handshake MCP nie powiedzie się z powodu ścisłych kontroli `Origin` lub dodatkowych headerów, użyj lokalnego reverse proxy, aby ujednolicić headery (odpowiada to obejściu problemu ścisłej walidacji Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Uruchom proxy i klienta oraz zmień skonfigurowany `--sse-url` na `http://127.0.0.1:19876` wyłącznie podczas korzystania z tego listenera Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Połącz stan przeglądarki z dowodami z proxy (Playwright MCP)

Zarejestruj Playwright MCP tak, aby jego przeglądarka korzystała z proxy Burp. Dzięki temu agent może powiązać wyrenderowany stan DOM/accessibility z dokładną historią HTTP, która go wygenerowała.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Dostosuj adres listenera, uruchom ponownie Codex i użyj `/mcp`, aby zweryfikować obie integracje. Przykład wyłącza błędy certyfikatów przeglądarki, dzięki czemu przechwytywanie HTTPS nie jest blokowane przez lokalnie wygenerowany certyfikat Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Używanie różnych klientów

### Codex CLI

- Skonfiguruj `~/.codex/config.toml` jak wyżej.
- Uruchom `codex`, a następnie `/mcp`, aby zweryfikować listę narzędzi Burp.

### Gemini CLI

Repo **burp-mcp-agents** udostępnia pomocnicze launchery:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokalny)

Użyj dostarczonego narzędzia pomocniczego launchera i wybierz lokalny model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Przykładowe modele lokalne i przybliżone wymagania dotyczące VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Odtwarzanie i walidacja oparte na dowodach

Nie pozwól, aby agent traktował wiarygodne wyjaśnienie lub odpowiedź pośrednią jako dowód. Używaj requests/responses z Burp oraz niezależnie zaobserwowanego stanu browsera, aby każdy test był falsyfikowalny.<sup>[[8]](#references)</sup>

1. Zapisz bazową parę request/response i zidentyfikuj dokładny komponent kontrolowany przez attackera.
2. W przypadku porównań autoryzacji niezależnie przechwyć ten sam workflow na obu kontach, zanim zmodyfikujesz identyfikatory, cookies lub tokeny.
3. Przed odtworzeniem modyfikacji zapisz hipotezę, lokalizację dowodu, oczekiwany sygnał oraz wynik, który by ją obalił.
4. Modyfikuj jeden komponent naraz, zachowaj wynikową parę i oznaczaj bezpośrednie obserwacje oddzielnie od wniosków.
5. Śledź każdego kandydata jako `open`, `blocked`, `rejected` lub `confirmed`; wracaj do niego tylko wtedy, gdy nowe dowody zmienią mechanizm lub wymaganie wstępne.
6. Potwierdź kontrolę attackera, osiągalność, powtarzalność, obejście ograniczeń, wpływ oraz końcowy stan aplikacji. Redirect lub pomyślne wywołanie toola nie są dowodem, jeśli deklarowana zmiana stanu następuje downstream.

Szczegóły exploitation przechowuj na odpowiedniej stronie techniki. Na przykład kandydaci związani z browser-message należą do [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), a zachowanie związane z wyborem klucza tokena należy do [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Zwięzły zapis hipotezy zapobiega powtarzaniu przez równoległe agenty tej samej atrakcyjnej ścieżki:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Pakiet promptów do pasywnego przeglądu

Repozytorium **burp-mcp-agents** zawiera szablony promptów do analizy ruchu Burp opartej na dowodach:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: szerokie wykrywanie pasywnych podatności.
- `idor_hunter.md`: IDOR/BOLA, obiekty, rozbieżności tenantów i niezgodności autoryzacji.
- `auth_flow_mapper.md`: porównywanie ścieżek uwierzytelnionych i nieuwierzytelnionych.
- `ssrf_redirect_hunter.md`: kandydaci na SSRF/open redirect wynikający z parametrów pobierania URL i łańcuchów przekierowań.
- `logic_flaw_hunter.md`: wieloetapowe błędy logiki.
- `session_scope_hunter.md`: niewłaściwe użycie odbiorców/zakresów tokenów.
- `rate_limit_abuse_hunter.md`: luki w throttlingu i zabezpieczeniach przed nadużyciami.
- `report_writer.md`: raportowanie skoncentrowane na dowodach.

## Optional attribution tagging

Aby oznaczać ruch Burp/LLM w logach, dodaj przepisanie nagłówka (proxy lub Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Uwagi dotyczące bezpieczeństwa

- Preferuj **local models**, gdy ruch zawiera wrażliwe dane.
- Udostępniaj tylko minimalną ilość dowodów potrzebnych do potwierdzenia znaleziska.
- Traktuj Burp jako źródło prawdy; używaj modelu do **analizy i raportowania**, a nie do skanowania.

## Burp AI Agent (triage wspomagany przez AI + narzędzia MCP)

**Burp AI Agent** to rozszerzenie Burp, które łączy lokalne/chmurowe LLM-y z pasywną/aktywną analizą (62 klas podatności) i udostępnia ponad 53 narzędzia MCP, dzięki czemu zewnętrzni klienci MCP mogą sterować Burp.<sup>[[5]](#references)</sup> Najważniejsze funkcje:

- **Triage z menu kontekstowego**: przechwyć ruch przez Proxy, otwórz **Proxy > HTTP History**, kliknij prawym przyciskiem żądanie → **Extensions > Burp AI Agent > Analyze this request**, aby uruchomić czat AI powiązany z tym żądaniem/odpowiedzią.
- **Backends** (wybierane dla każdego profilu):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint zgodny z **OpenAI** (base URL + nazwa modelu).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` lub `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (logowanie zależne od providera).
- **Profile agentów**: szablony promptów są automatycznie instalowane w `~/.burp-ai-agent/AGENTS/`; umieść tam dodatkowe pliki `*.md`, aby dodać niestandardowe zachowania związane z analizą/skanowaniem.
- **Serwer MCP**: włącz go przez **Settings > MCP Server**, aby udostępnić operacje Burp dowolnemu klientowi MCP (ponad 53 narzędzia). Claude Desktop można wskazać na serwer, edytując `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) lub `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrola prywatności**: STRICT / BALANCED / OFF redagują wrażliwe dane żądań przed wysłaniem ich do zdalnych modeli; preferuj lokalne backends podczas przetwarzania sekretów.
- **Logowanie audytowe**: logi JSONL z haszowaniem integralności SHA-256 dla każdego wpisu, zapewniające odporność śladu działań AI/MCP na manipulacje.
- **Build/load**: pobierz release JAR lub zbuduj przy użyciu Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Przestrogi operacyjne: cloud backends mogą eksfiltrować session cookies/PII, chyba że wymuszony jest tryb prywatności; ekspozycja MCP zapewnia zdalną orkiestrację Burp, dlatego ogranicz dostęp do zaufanych agentów i monitoruj dziennik audytowy z hashem integralności.

## References

- [1] [Integracja Burp MCP + Codex CLI oraz poprawka handshake w Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem z rygorystyczną walidacją Origin/header w serwerze MCP PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agenci Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agent AI Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Serwer MCP PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Jak używać Codex do researchu Bug Bounty: eksploruj szeroko, weryfikuj rygorystycznie](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
