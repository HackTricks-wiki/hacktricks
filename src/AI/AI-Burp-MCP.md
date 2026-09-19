# Burp MCP: analiza ruchu wspomagana przez LLM

{{#include ../banners/hacktricks-training.md}}

## Omówienie

Rozszerzenie **MCP Server** dla Burp może udostępniać przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, aby mogły one **analizować rzeczywiste żądania/odpowiedzi** w celu wykrywania podatności i przygotowywania projektów raportów. Traktuj Burp jako źródło prawdy: korzystaj z analizy pasywnej lub celowych powtórzeń z jedną zmienną zamiast ślepego skanowania.<sup>[[8]](#references)</sup>

## Architektura

- **Burp MCP Server (BApp)** nasłuchuje domyślnie na `127.0.0.1:9876` i udostępnia przechwycony ruch za pośrednictwem MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** łączy stdio (po stronie klienta) z endpointem MCP SSE Burp.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje nagłówki na potrzeby rygorystycznych kontroli handshake MCP.
- **Klienci/backendy**: Codex CLI (cloud), Gemini CLI (cloud) lub Ollama (local).

## Konfiguracja

### 1) Zainstaluj Burp MCP Server

Zainstaluj **MCP Server** z Burp BApp Store i sprawdź, czy nasłuchuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Wyodrębnij proxy JAR

Na karcie MCP Server kliknij **Extract server proxy jar** i zapisz plik `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Skonfiguruj klienta MCP (przykład z Codex)

Wskaż klientowi proxy JAR oraz bezpośredni endpoint SSE Burp. Dołączone proxy jest mostem stdio-to-SSE; nie zastępuje listenera Burp.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Odpowiednikiem jest polecenie Codex:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Następnie uruchom Codex i wyświetl listę narzędzi MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Napraw ścisłą walidację Origin/header za pomocą Caddy (jeśli potrzebne)

Jeśli handshake MCP kończy się niepowodzeniem z powodu ścisłych kontroli `Origin` lub dodatkowych headers, użyj lokalnego reverse proxy do normalizacji headers (odpowiada to workaroundowi dla problemu ścisłej walidacji Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Uruchom proxy i klienta oraz zmień skonfigurowany parametr `--sse-url` na `http://127.0.0.1:19876` wyłącznie podczas korzystania z tego listenera Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Połącz stan przeglądarki z dowodami z proxy (Playwright MCP)

Skonfiguruj Playwright MCP tak, aby jego przeglądarka korzystała z proxy Burp. Dzięki temu agent może skorelować wyrenderowany stan DOM/accessibility z dokładną historią HTTP, która go wygenerowała.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Dostosuj adres nasłuchiwania, uruchom ponownie Codex i użyj `/mcp`, aby zweryfikować obie integracje. Przykład wyłącza błędy certyfikatu przeglądarki, dzięki czemu przechwytywanie HTTPS nie jest blokowane przez certyfikat generowany lokalnie przez Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatyzacja przeglądarki uwzględniająca proxy (OpenBurp)

Połączenie Burp MCP i przechwytywana ścieżka przeglądarki to oddzielne przepływy danych. Usługa MCP udostępnia narzędzia Burp na `127.0.0.1:9876`, natomiast dedykowana instancja Chromium wysyła ruch HTTP(S) przez proxy Burp na `127.0.0.1:8080`. Żądania generowane bezpośrednio przez narzędzie MCP mogą zatem nie pojawić się w **Proxy > HTTP history**; użyj przeglądarki skonfigurowanej z proxy, gdy żądanie/odpowiedź musi być obserwowalne, edytowalne lub zachowane jako dowód.<sup>[[2]](#references)[[9]](#references)</sup>

Klient z obsługą SSE może zarejestrować Burp bezpośrednio. Klient obsługujący wyłącznie stdio może zamiast tego uruchomić proxy JAR firmy PortSwigger. W obu przypadkach zarejestruj drugi browser-control MCP i wskaż w nim wbudowany Chromium Burp (`BURP_CHROMIUM` to lokalna ścieżka do pliku wykonywalnego):<sup>[[9]](#references)</sup>
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
Flaga TLS-bypass akceptuje certyfikaty wygenerowane przez proxy przechwytujące, natomiast `--isolated` uniemożliwia ponowne użycie przez assessment zwykłego profilu przeglądarki operatora. Izolacja chroni stan profilu, ale **nie jest sandboxem bezpieczeństwa**: kontroler nadal może uzyskać dostęp do uwierzytelnionych sesji otwartych w tej przeglądarce testowej, a Burp MCP może ujawniać poufne żądania, odpowiedzi i konfigurację.<sup>[[9]](#references)</sup>

Przed rozpoczęciem debugowania client bridge przetestuj niezależnie listener SSE:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Zdrowy listener zwraca `Content-Type: text/event-stream`. Timeout po otrzymaniu nagłówków jest oczekiwany, ponieważ strumień SSE pozostaje otwarty na przyszłe zdarzenia. Jeśli klient nadal nie działa, potwierdź skonfigurowaną route extension: PortSwigger informuje, że endpointem może być ścieżka główna lub `/sse`, zależnie od klienta i konfiguracji extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Using different clients

### Codex CLI

- Skonfiguruj `~/.codex/config.toml` jak powyżej.
- Uruchom `codex`, a następnie `/mcp`, aby zweryfikować listę narzędzi Burp.

### Gemini CLI

Repozytorium **burp-mcp-agents** udostępnia pomocnicze launchery:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokal)

Użyj dostarczonego helpera uruchamiającego i wybierz model lokalny:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Przykładowe lokalne modele i przybliżone wymagania dotyczące VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay i walidacja oparte na dowodach

Nie pozwól, aby agent traktował wiarygodne wyjaśnienie lub odpowiedź pośrednią jako dowód. Wykorzystuj requests/responses z Burp oraz niezależnie zaobserwowany stan browsera, aby każdy test można było sfalsyfikować.<sup>[[8]](#references)</sup>

1. Zapisz bazową parę request/response i zidentyfikuj dokładny komponent kontrolowany przez atakującego.
2. W przypadku porównań autoryzacji niezależnie przechwyć ten sam workflow na obu kontach, zanim zmodyfikujesz identyfikatory, cookies lub tokeny.
3. Przed ponownym odtworzeniem mutacji zapisz hipotezę, lokalizację dowodu, oczekiwany sygnał oraz wynik, który by ją obalił.
4. Modyfikuj jeden komponent naraz, zachowaj wynikową parę i oznaczaj bezpośrednie obserwacje oddzielnie od wnioskowania.
5. Śledź każdego kandydata jako `open`, `blocked`, `rejected` lub `confirmed`; wracaj do niego tylko wtedy, gdy nowe dowody zmienią mechanizm lub warunek wstępny.
6. Potwierdź kontrolę atakującego, osiągalność, powtarzalność, obejście ograniczenia, wpływ oraz końcowy stan aplikacji. Redirect lub pomyślne wywołanie narzędzia nie jest dowodem, jeśli deklarowana zmiana stanu następuje downstream.

Szczegóły exploitation przechowuj na odpowiedniej stronie techniki. Na przykład kandydaci dotyczący browser messages należą do [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), natomiast zachowanie związane z wyborem klucza tokena należy do [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Zwięzły zapis hipotezy zapobiega powtarzaniu tej samej atrakcyjnej ścieżki przez równoległych agentów:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Zestaw promptów do pasywnego przeglądu

Repozytorium **burp-mcp-agents** zawiera szablony promptów do analizy ruchu Burp opartej na dowodach:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: szerokie pasywne wykrywanie podatności.
- `idor_hunter.md`: IDOR/BOLA, rozbieżności obiektów/tenantów i niezgodności uwierzytelniania.
- `auth_flow_mapper.md`: porównywanie ścieżek uwierzytelnionych i nieuwierzytelnionych.
- `ssrf_redirect_hunter.md`: kandydaci do SSRF/open-redirect na podstawie parametrów pobierania URL/łańcuchów przekierowań.
- `logic_flaw_hunter.md`: wieloetapowe błędy logiki.
- `session_scope_hunter.md`: niewłaściwe użycie audience/scope tokenów.
- `rate_limit_abuse_hunter.md`: luki w throttlingu/nadużyciach.
- `report_writer.md`: raportowanie skoncentrowane na dowodach.

## Opcjonalne tagowanie atrybucji

Aby oznaczać ruch Burp/LLM w logach, dodaj przepisanie nagłówka (proxy lub Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Uwagi dotyczące bezpieczeństwa

- Preferuj **local models**, gdy ruch zawiera wrażliwe dane.
- Udostępniaj tylko minimalny zestaw dowodów potrzebny do potwierdzenia znaleziska.
- Traktuj Burp jako źródło prawdy; używaj modelu do **analysis and reporting**, a nie do skanowania.

## Burp AI Agent (triage wspomagane przez AI + narzędzia MCP)

**Burp AI Agent** to rozszerzenie Burp, które łączy local/cloud LLMs z analizą pasywną/aktywną (62 klasy podatności) i udostępnia ponad 53 narzędzia MCP, dzięki czemu zewnętrzne klienty MCP mogą sterować Burp.<sup>[[5]](#references)</sup> Najważniejsze funkcje:

- **Triage z menu kontekstowego**: przechwyć ruch przez Proxy, otwórz **Proxy > HTTP History**, kliknij prawym przyciskiem żądanie → **Extensions > Burp AI Agent > Analyze this request**, aby uruchomić czat AI powiązany z tym żądaniem/odpowiedzią.
- **Backends** (wybierane dla każdego profilu):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint zgodny z **OpenAI** (base URL + nazwa modelu).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` lub `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (logowanie zależne od providera).
- **Profile agentów**: szablony promptów są automatycznie instalowane w `~/.burp-ai-agent/AGENTS/`; umieść tam dodatkowe pliki `*.md`, aby dodać niestandardowe zachowania związane z analizą/skanowaniem.
- **Serwer MCP**: włącz go przez **Settings > MCP Server**, aby udostępnić operacje Burp dowolnemu klientowi MCP (ponad 53 narzędzia). Claude Desktop można skonfigurować do korzystania z serwera, edytując `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) lub `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrola prywatności**: STRICT / BALANCED / OFF redagują wrażliwe dane żądań przed wysłaniem ich do remote models; preferuj local backends podczas obsługi sekretów.
- **Logowanie audytowe**: logi JSONL z haszowaniem integralności SHA-256 dla każdego wpisu, zapewniające odporną na manipulacje identyfikowalność działań AI/MCP.
- **Build/load**: pobierz release JAR lub zbuduj przy użyciu Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Przestrogi operacyjne: backendy cloud mogą eksfiltrować ciasteczka sesji/PII, chyba że wymuszony jest tryb prywatności; ekspozycja MCP umożliwia zdalną orkiestrację Burp, dlatego ogranicz dostęp do zaufanych agentów i monitoruj dziennik audytowy z haszem integralności.

## References

- [1] [Integracja Burp MCP + Codex CLI i poprawka handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem ścisłej walidacji Origin/header w serwerze MCP PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agenci Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Serwer MCP PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Jak używać Codex do researchu Bug Bounty: szeroka eksploracja, rygorystyczna walidacja](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orkiestracja Burp Suite dla Claude Code i Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
