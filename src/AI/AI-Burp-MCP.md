# Burp MCP: przegląd ruchu wspomagany przez LLM

{{#include ../banners/hacktricks-training.md}}

## Przegląd

Rozszerzenie **MCP Server** w Burp może udostępniać przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, aby mogły **analizować rzeczywiste żądania i odpowiedzi** w celu wykrywania podatności i przygotowywania raportów. Burp pozostaje źródłem prawdy: korzystaj z analizy pasywnej lub celowo odtwarzaj żądania, zmieniając jedną zmienną naraz, zamiast przeprowadzać skanowanie na ślepo.<sup>[[8]](#references)</sup>

## Architektura

- **Burp MCP Server (BApp)** domyślnie nasłuchuje na `127.0.0.1:9876` i udostępnia przechwycony ruch przez MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** łączy stdio (po stronie klienta) z punktem końcowym MCP SSE w Burp.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje nagłówki na potrzeby rygorystycznej weryfikacji uzgadniania połączenia MCP.
- **Klienci/backendy**: Codex CLI (cloud), Gemini CLI (cloud) lub Ollama (local).

## Konfiguracja

### 1) Zainstaluj Burp MCP Server

Zainstaluj **MCP Server** z Burp BApp Store i sprawdź, czy nasłuchuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Wyodrębnij proxy JAR

Na karcie MCP Server kliknij **Wyodrębnij server proxy jar** i zapisz `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Skonfiguruj klienta MCP (przykład z Codex)

Wskaż klientowi proxy JAR i bezpośredni punkt końcowy SSE w Burp. Dołączone proxy to most stdio-to-SSE; nie zastępuje nasłuchującego serwera Burp.<sup>[[7]](#references)</sup>

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

### 4) Napraw ścisłą walidację nagłówka Origin (jeśli to konieczne) przy użyciu Caddy

Jeśli uzgadnianie MCP kończy się niepowodzeniem z powodu ścisłych kontroli nagłówka `Origin` lub dodatkowych nagłówków, użyj lokalnego reverse proxy, aby ujednolicić nagłówki (to obejście problemu ścisłej walidacji Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Uruchom proxy i klienta, a skonfigurowany parametr `--sse-url` zmień na `http://127.0.0.1:19876` tylko podczas korzystania z tego listenera Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Połącz stan przeglądarki z dowodami z proxy (Playwright MCP)

Skonfiguruj Playwright MCP tak, aby jego przeglądarka korzystała z proxy Burp. Dzięki temu agent może korelować wyrenderowany DOM i stan dostępności z dokładną historią HTTP, która je wygenerowała.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Dostosuj adres listenera, uruchom ponownie Codex i użyj `/mcp`, aby zweryfikować obie integracje. W przykładzie wyłączono błędy certyfikatów przeglądarki, aby przechwytywania HTTPS nie blokował lokalnie wygenerowany certyfikat Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatyzacja przeglądarki obsługująca proxy (OpenBurp)

Połączenie Burp MCP i przechwytywany ruch przeglądarki to oddzielne przepływy danych. Usługa MCP udostępnia narzędzia Burp pod adresem `127.0.0.1:9876`, natomiast dedykowana instancja Chromium przesyła ruch HTTP(S) przez proxy Burp pod adresem `127.0.0.1:8080`. Żądania generowane bezpośrednio przez narzędzie MCP mogą więc nie pojawić się w **Proxy > HTTP history**; korzystaj z przeglądarki skonfigurowanej do używania proxy, gdy żądanie lub odpowiedź muszą być widoczne, możliwe do edycji lub zachowane jako dowód.<sup>[[2]](#references)[[9]](#references)</sup>

Klient obsługujący SSE może zarejestrować Burp bezpośrednio. Klient obsługujący wyłącznie stdio może zamiast tego uruchomić proxy JAR firmy PortSwigger. W obu przypadkach zarejestruj drugi MCP do sterowania przeglądarką i wskaż w nim wbudowaną przeglądarkę Chromium Burp (`BURP_CHROMIUM` to lokalna ścieżka do pliku wykonywalnego):<sup>[[9]](#references)</sup>

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

Flaga TLS-bypass akceptuje certyfikaty wygenerowane przez proxy przechwytujące, a `--isolated` zapobiega ponownemu użyciu przez ocenę zwykłego profilu przeglądarki operatora. Izolacja chroni stan profilu, ale **nie jest piaskownicą bezpieczeństwa**: kontroler nadal może uzyskać dostęp do uwierzytelnionych sesji otwartych w tej przeglądarce testowej, a Burp MCP może ujawniać poufne żądania, odpowiedzi i konfigurację.<sup>[[9]](#references)</sup>

Przed debugowaniem mostka klienta przetestuj niezależnie listener SSE:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Sprawny listener zwraca `Content-Type: text/event-stream`. Timeout po otrzymaniu nagłówków jest oczekiwany, ponieważ strumień SSE pozostaje otwarty i czeka na przyszłe zdarzenia. Jeśli klient nadal nie działa, sprawdź skonfigurowaną trasę rozszerzenia: PortSwigger informuje, że endpoint może być ścieżką główną lub `/sse`, zależnie od klienta i konfiguracji rozszerzenia.<sup>[[9]](#references)[[7]](#references)</sup>

## Korzystanie z różnych klientów

### Codex CLI

- Skonfiguruj `~/.codex/config.toml` jak powyżej.
- Uruchom `codex`, a następnie `/mcp`, aby sprawdzić listę narzędzi Burp.

### Gemini CLI

Repozytorium **burp-mcp-agents** udostępnia pomocnicze skrypty uruchamiające:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (lokalnie)

Użyj dostarczonego pomocnika uruchamiającego i wybierz model lokalny:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Przykładowe modele lokalne i przybliżone zapotrzebowanie na VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Ponowne odtwarzanie i walidacja oparte na dowodach

Nie pozwól agentowi traktować wiarygodnego wyjaśnienia ani odpowiedzi pośredniej jako dowodu. Korzystaj z żądań i odpowiedzi Burp oraz niezależnie zaobserwowanego stanu przeglądarki, aby każdy test można było sfalsyfikować.<sup>[[8]](#references)</sup>

1. Zapisz bazową parę żądanie/odpowiedź i wskaż dokładny komponent kontrolowany przez atakującego.
2. Przy porównywaniu autoryzacji przechwyć osobno ten sam przebieg pracy dla obu kont przed zmianą identyfikatorów, ciasteczek lub tokenów.
3. Przed ponownym odtworzeniem zmodyfikowanego żądania zapisz hipotezę, lokalizację dowodów, oczekiwany sygnał oraz wynik, który by ją obalił.
4. Zmieniaj tylko jeden komponent naraz, zachowuj uzyskaną parę i oddzielaj bezpośrednie obserwacje od wniosków.
5. Oznaczaj każdy przypadek jako `open`, `blocked`, `rejected` lub `confirmed`; wracaj do niego tylko wtedy, gdy nowe dowody zmieniają mechanizm lub warunek wstępny.
6. Potwierdź kontrolę atakującego, osiągalność, powtarzalność, obejście ograniczeń, wpływ i końcowy stan aplikacji. Przekierowanie ani udane wywołanie narzędzia nie stanowią dowodu, jeśli deklarowana zmiana stanu następuje dalej w łańcuchu.

Szczegóły exploitation umieść na odpowiedniej stronie techniki. Na przykład przypadki dotyczące wiadomości przeglądarki opisz w [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), a zachowanie związane z wyborem klucza tokenu — w [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Zwięzły zapis hipotezy zapobiega powtarzaniu przez równoległe agenty tej samej kuszącej ścieżki:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Wstępna analiza ramek WebSocket za pomocą Burp MCP

Oficjalne rozszerzenie udostępnia `get_proxy_websocket_history_regex` do wyszukiwania tylko do odczytu w historii WebSocket Burp z paginacją. Przyjmuje `regex`, `count` i `offset`; w przeciwieństwie do `send_http1_request` nie wysyła ramki WebSocket. Burp zapisuje wiadomości w obu kierunkach, nawet gdy Intercept jest wyłączony, dlatego przefiltruj historię, zanim przekażesz modelowi niewielki zestaw istotnych ramek.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Wykonaj tę samą operację obsługiwaną przez WebSocket w przeglądarce przepuszczanej przez proxy Burp, używając dwóch niezależnie uwierzytelnionych kont testowych. Zachowaj razem każde handshake upgrade wraz z jego cookies, identyfikator połączenia, kierunek ramki i ramki odpowiedzi; zdarzenie z serwera do klienta na połączeniu pierwszego konta nie dowodzi, że otrzymało je drugie konto.
2. Przeszukaj `get_proxy_websocket_history_regex` za pomocą wąskiego wyrażenia, takiego jak `(?i)(subscribe|room|tenant|objectId)`, `count: 20` i `offset: 0`. Zwiększaj `offset`, aby sprawdzić późniejsze dopasowania. Porównaj identyfikator obiektu lub tematu w wychodzącej ramce z odpowiedzią na **tym samym połączeniu**.
3. W **Proxy > WebSockets history** wyślij podejrzaną wychodzącą ramkę do Repeater. Dołącz ją do odpowiedniego otwartego połączenia albo połącz się ponownie, używając handshake drugiego konta. Zmień tylko identyfikator obiektu/tematu i porównaj otrzymane komunikaty serwera oraz stan aplikacji z obydwoma wartościami bazowymi. Narzędzie historii MCP nie może wykonać takiego powtórzenia; WebSocket Repeater umożliwia edycję, ponowne wysłanie i ponowne nawiązanie połączenia ramek.

Aby wykonać testy specyficzne dla protokołu, takie jak cross-site WebSocket hijacking i autoryzacja tematów brokera, przejdź do sekcji [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Nie traktuj zaakceptowanego upgrade ani echa po stronie klienta jako dowodu, że chroniona subskrypcja się powiodła.

## Ukierunkowana walidacja out-of-band za pomocą Burp MCP

Burp Suite Professional udostępnia `generate_collaborator_payload` i `get_collaborator_interactions` za pośrednictwem oficjalnego rozszerzenia MCP. Połącz je z `get_proxy_http_history_regex` i pojedynczym powtórzeniem `send_http1_request`, aby przetestować podejrzane pobieranie URL po stronie serwera bez skanowania całego celu. Burp może wymagać osobnej zgody na odczyt historii i wysłanie żądania.<sup>[[2]](#references)[[10]](#references)</sup>

1. Przefiltruj historię w poszukiwaniu żądania zawierającego potencjalny URL, na przykład z `url=`, `webhook` lub `callback`. Zapisz oryginalne żądanie i odpowiedź. Narzędzie historii przyjmuje `regex`, `count` i `offset`; używaj paginacji zamiast prosić model o sprawdzenie każdego wpisu.<sup>[[10]](#references)</sup>
2. Wygeneruj nowy payload Collaborator i zachowaj zwrócony **identyfikator payloadu**. Powtórz przechwycone żądanie do tego samego hosta i portu, zmieniając tylko podejrzany URL na URL HTTPS w domenie tego payloadu. W przypadku `send_http1_request` przekaż kompletne żądanie HTTP/1.1 jako `content` wraz z `targetHostname`, `targetPort` i `usesHttps`; pola docelowe wskazują **aplikację**, a nie hosta Collaborator.<sup>[[10]](#references)</sup>
3. Odpytaj `get_collaborator_interactions` z tym identyfikatorem payloadu i skoreluj czas interakcji z powtórzeniem żądania. Interakcja HTTP potwierdza pobranie, natomiast sam DNS wskazuje jedynie na rozwiązanie nazwy, a nie na wykonanie pełnego żądania HTTP. Sprawdź źródło interakcji i nagłówki żądania, aby odróżnić ruch wychodzący serwera od ładowania po stronie przeglądarki, a następnie powtórz test z nowym payloadem, aby wykluczyć niezwiązany ruch.<sup>[[10]](#references)[[11]](#references)</sup>

Narzędzie żądań MCP zwraca odpowiedź bezpośrednio i nie musi dodawać jej do **Proxy > HTTP history**. Zachowaj wynik żądania/odpowiedzi lub użyj przeglądarki przepuszczanej przez proxy albo Repeater, aby uzyskać artefakt w historii. W kwestii doboru payloadów SSRF i dalszych testów skorzystaj z [rozdziału SSRF](../pentesting-web/ssrf-server-side-request-forgery/), zamiast traktować callback out-of-band jako dowód wpływu na sieć wewnętrzną. Informacje o testowaniu samego serwera MCP znajdziesz w sekcji [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Zestaw promptów do pasywnej analizy

Repozytorium **burp-mcp-agents** zawiera szablony promptów do analizy ruchu Burp opartej na dowodach:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: szerokie pasywne wykrywanie podatności.
- `idor_hunter.md`: rozbieżności IDOR/BOLA/obiektów/tenantów i niezgodności uwierzytelniania.
- `auth_flow_mapper.md`: porównywanie ścieżek uwierzytelnionych i nieuwierzytelnionych.
- `ssrf_redirect_hunter.md`: potencjalne SSRF/open redirect wynikające z parametrów pobierania URL i łańcuchów przekierowań.
- `logic_flaw_hunter.md`: wieloetapowe błędy logiki.
- `session_scope_hunter.md`: niewłaściwe użycie audience/scope tokenu.
- `rate_limit_abuse_hunter.md`: luki w ograniczaniu liczby żądań i ochronie przed nadużyciami.
- `report_writer.md`: raportowanie skupione na dowodach.

## Opcjonalne oznaczanie ruchu

Aby oznaczyć ruch Burp/LLM w logach, dodaj regułę przepisywania nagłówka (proxy lub Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Uwagi dotyczące bezpieczeństwa

- Preferuj **modele lokalne**, gdy ruch zawiera wrażliwe dane.
- Udostępniaj tylko minimalną ilość dowodów potrzebną do opisania znaleziska.
- Traktuj Burp jako źródło prawdy; używaj modelu do **analizy i raportowania**, a nie do skanowania.

## Burp AI Agent (triage wspomagane przez AI + narzędzia MCP)

**Burp AI Agent** to rozszerzenie Burp, które łączy lokalne/chmurowe LLM-y z pasywną/aktywną analizą (62 klasy podatności) i udostępnia ponad 53 narzędzia MCP, dzięki czemu zewnętrzne klienty MCP mogą sterować Burp.<sup>[[5]](#references)</sup> Najważniejsze funkcje:

- **Triage z menu kontekstowego**: przechwyć ruch przez Proxy, otwórz **Proxy > HTTP History**, kliknij prawym przyciskiem żądanie → **Extensions > Burp AI Agent > Analyze this request**, aby uruchomić czat AI powiązany z tym żądaniem/odpowiedzią.
- **Backendy** (wybierane dla każdego profilu):
  - Lokalny HTTP: **Ollama**, **LM Studio**.
  - Zdalny HTTP: endpoint zgodny z **OpenAI** (bazowy URL + nazwa modelu).
  - Chmurowe CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` lub `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (logowanie zależne od dostawcy).
- **Profile agenta**: szablony promptów są automatycznie instalowane w `~/.burp-ai-agent/AGENTS/`; dodaj tam dodatkowe pliki `*.md`, aby wprowadzić własne zachowania analityczne/skanujące.
- **Serwer MCP**: włącz go przez **Settings > MCP Server**, aby udostępnić operacje Burp dowolnemu klientowi MCP (ponad 53 narzędzia). Możesz wskazać ten serwer w Claude Desktop, edytując `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) lub `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrola prywatności**: tryby STRICT / BALANCED / OFF usuwają dane wrażliwe z żądań przed wysłaniem ich do modeli zdalnych; podczas pracy z sekretami preferuj lokalne backendy.
- **Rejestrowanie audytowe**: logi JSONL z hashowaniem SHA-256 każdego wpisu, zapewniające odporną na manipulacje identyfikowalność działań AI/MCP.
- **Budowanie/ładowanie**: pobierz JAR z wydaniem albo zbuduj przy użyciu Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Ostrzeżenia operacyjne: backendy chmurowe mogą eksfiltrować pliki cookie sesji/dane osobowe (PII), jeśli nie jest wymuszony tryb prywatności; udostępnienie MCP umożliwia zdalne sterowanie Burp, dlatego ogranicz dostęp do zaufanych agentów i monitoruj log audytu z hashem integralności.



## References

- [1] [Integracja Burp MCP + Codex CLI i poprawka handshake w Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem z rygorystyczną walidacją Origin/header w PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agenci Burp MCP (workflowy, launchery, zestaw promptów)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agent AI Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Jak używać Codex do badań bug bounty: szeroka eksploracja, rygorystyczna weryfikacja](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orkiestracja Burp Suite dla Claude Code i Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementacje narzędzi PortSwigger MCP Server i parametry](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - podatności Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - historia WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - praca z wiadomościami WebSocket w Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
