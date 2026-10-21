# Burp MCP: przegląd ruchu wspomagany przez LLM

{{#include ../banners/hacktricks-training.md}}

## Overview

Rozszerzenie **MCP Server** dla Burp może udostępniać przechwycony ruch HTTP(S) klientom LLM obsługującym MCP, aby mogły **analizować rzeczywiste żądania i odpowiedzi** w celu wykrywania podatności i przygotowywania raportów. Traktuj Burp jako źródło prawdy: korzystaj z analizy pasywnej lub celowo odtwarzaj żądania, zmieniając jedną zmienną naraz, zamiast przeprowadzać ślepe skanowanie.<sup>[[8]](#references)</sup>

## Architecture

- **Burp MCP Server (BApp)** domyślnie nasłuchuje na `127.0.0.1:9876` i udostępnia przechwycony ruch przez MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** pośredniczy między stdio (po stronie klienta) a punktem końcowym MCP SSE w Burp.
- **Opcjonalny lokalny reverse proxy** (Caddy) normalizuje nagłówki na potrzeby rygorystycznych kontroli handshake MCP.
- **Klienci/backendy**: Codex CLI (cloud), Gemini CLI (cloud) lub Ollama (local).

## Setup

### 1) Zainstaluj Burp MCP Server

Zainstaluj **MCP Server** ze sklepu Burp BApp Store i sprawdź, czy nasłuchuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Wyodrębnij proxy JAR

Na karcie MCP Server kliknij **Wyodrębnij proxy JAR serwera** i zapisz plik `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Skonfiguruj klienta MCP (przykład dla Codex)

Wskaż klientowi proxy JAR i bezpośredni punkt końcowy SSE Burp. Dołączone proxy pośredniczy między stdio a SSE; nie zastępuje listenera Burp.<sup>[[7]](#references)</sup>

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

Następnie uruchom Codex i wypisz narzędzia MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Napraw ścisłą walidację Origin/nagłówków za pomocą Caddy (jeśli to konieczne)

Jeśli handshake MCP nie powiedzie się z powodu ścisłych kontroli `Origin` lub dodatkowych nagłówków, użyj lokalnego reverse proxy do normalizacji nagłówków (to rozwiązanie odpowiada obejściu problemu ścisłej walidacji Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Uruchom proxy i klienta, a skonfigurowany `--sse-url` zmień na `http://127.0.0.1:19876` wyłącznie podczas korzystania z tego listenera Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Powiąż stan przeglądarki z dowodami z proxy (Playwright MCP)

Skonfiguruj Playwright MCP tak, aby jego przeglądarka korzystała z proxy Burp. Dzięki temu agent może powiązać wyrenderowany DOM i stan dostępności z dokładną historią HTTP, która je wygenerowała.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Dostosuj adres nasłuchiwania, uruchom ponownie Codex i użyj `/mcp`, aby zweryfikować obie integracje. W przykładzie wyłączono błędy certyfikatów przeglądarki, aby przechwytywanie HTTPS nie było blokowane przez certyfikat wygenerowany lokalnie przez Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatyzacja przeglądarki obsługująca proxy (OpenBurp)

Połączenie Burp MCP i przechwytywany ruch przeglądarki to osobne przepływy danych. Usługa MCP udostępnia narzędzia Burp pod adresem `127.0.0.1:9876`, natomiast dedykowana instancja Chromium kieruje ruch HTTP(S) przez proxy Burp pod adresem `127.0.0.1:8080`. Żądania wygenerowane bezpośrednio przez narzędzie MCP mogą więc nie pojawiać się w **Proxy > HTTP history**; użyj przeglądarki korzystającej z proxy, gdy żądanie lub odpowiedź muszą być widoczne, edytowalne albo zachowane jako dowód.<sup>[[2]](#references)[[9]](#references)</sup>

Klient obsługujący SSE może zarejestrować Burp bezpośrednio. Klient obsługujący wyłącznie stdio może zamiast tego uruchomić proxy JAR firmy PortSwigger. W obu przypadkach zarejestruj drugi MCP do sterowania przeglądarką i wskaż w nim wbudowane Chromium Burp (`BURP_CHROMIUM` to lokalna ścieżka do pliku wykonywalnego):<sup>[[9]](#references)</sup>

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

Flaga TLS-bypass akceptuje certyfikaty wygenerowane przez proxy przechwytujące, a `--isolated` zapobiega ponownemu użyciu przez narzędzie profilu przeglądarki operatora. Izolacja chroni stan profilu, ale **nie jest sandboxem bezpieczeństwa**: kontroler nadal może uzyskać dostęp do uwierzytelnionych sesji otwartych w przeglądarce testowej, a Burp MCP może ujawniać poufne żądania, odpowiedzi i konfigurację.<sup>[[9]](#references)</sup>

Przed rozpoczęciem debugowania mostu klienta przetestuj niezależnie listener SSE:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Zdrowy listener zwraca `Content-Type: text/event-stream`. Timeout po otrzymaniu nagłówków jest spodziewany, ponieważ strumień SSE pozostaje otwarty, aby odbierać przyszłe zdarzenia. Jeśli klient nadal nie działa, sprawdź skonfigurowaną trasę rozszerzenia: PortSwigger informuje, że endpoint może być ścieżką główną lub `/sse`, w zależności od klienta i konfiguracji rozszerzenia.<sup>[[9]](#references)[[7]](#references)</sup>

## Korzystanie z różnych klientów

### Codex CLI

- Skonfiguruj `~/.codex/config.toml` jak wyżej.
- Uruchom `codex`, a następnie `/mcp`, aby sprawdzić listę narzędzi Burp.

### Gemini CLI

Repozytorium **burp-mcp-agents** udostępnia pomocnicze skrypty uruchamiające:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (lokalnie)

Użyj dostarczonego helpera uruchamiającego i wybierz model lokalny:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Przykładowe modele lokalne i przybliżone zapotrzebowanie na VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Odtwarzanie i walidacja oparte na dowodach

Nie pozwól agentowi uznawać wiarygodnego wyjaśnienia ani odpowiedzi pośredniej za dowód. Wykorzystuj żądania i odpowiedzi Burp oraz niezależnie zaobserwowany stan przeglądarki, aby każdy test można było obalić.<sup>[[8]](#references)</sup>

1. Zapisz bazową parę żądanie/odpowiedź i wskaż dokładny komponent kontrolowany przez atakującego.
2. Przy porównywaniu uprawnień przechwyć ten sam proces niezależnie na obu kontach przed zmianą identyfikatorów, plików cookie lub tokenów.
3. Przed odtworzeniem zmodyfikowanego żądania zapisz hipotezę, lokalizację dowodu, oczekiwany sygnał oraz wynik, który by ją obalił.
4. Zmieniaj po jednym komponencie naraz, zachowuj uzyskaną parę i oddzielaj bezpośrednie obserwacje od wniosków.
5. Oznaczaj każdy przypadek jako `open`, `blocked`, `rejected` lub `confirmed`; wracaj do niego tylko wtedy, gdy nowe dowody zmienią mechanizm lub warunek wstępny.
6. Potwierdź kontrolę atakującego, osiągalność, powtarzalność, obejście ograniczeń, wpływ i końcowy stan aplikacji. Przekierowanie ani udane wywołanie narzędzia nie stanowią dowodu, jeśli deklarowana zmiana stanu następuje później.

Szczegóły exploitacji umieszczaj na odpowiedniej stronie techniki. Na przykład przypadki dotyczące wiadomości przeglądarki należą do [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), a zachowanie związane z wyborem klucza tokena — do [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Zwięzły zapis hipotez pomaga równoległym agentom uniknąć ponownego badania tej samej kuszącej ścieżki:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Ukierunkowana walidacja out-of-band za pomocą Burp MCP

Burp Suite Professional udostępnia funkcje `generate_collaborator_payload` i `get_collaborator_interactions` za pośrednictwem oficjalnego rozszerzenia MCP. Połącz je z `get_proxy_http_history_regex` i pojedynczym ponownym wysłaniem żądania przez `send_http1_request`, aby przetestować podejrzane pobieranie URL po stronie serwera bez skanowania całego celu. Burp może wymagać osobnej zgody na odczyt historii i wysłanie żądania.<sup>[[2]](#references)[[10]](#references)</sup>

1. Przefiltruj historię, aby znaleźć żądanie zawierające potencjalny URL, na przykład zawierające `url=`, `webhook` lub `callback`. Zapisz oryginalne żądanie i odpowiedź. Narzędzie historii przyjmuje parametry `regex`, `count` i `offset`; przeglądaj wyniki strona po stronie, zamiast prosić model o sprawdzenie każdego wpisu.<sup>[[10]](#references)</sup>
2. Wygeneruj nowy payload Collaborator i zachowaj zwrócony **identyfikator payloadu**. Ponownie wyślij przechwycone żądanie do tego samego hosta i portu, zmieniając wyłącznie podejrzany URL na URL HTTPS w domenie payloadu. W przypadku `send_http1_request` przekaż kompletne żądanie HTTP/1.1 jako `content`, a także `targetHostname`, `targetPort` i `usesHttps`; pola docelowe wskazują **aplikację**, a nie hosta Collaborator.<sup>[[10]](#references)</sup>
3. Odpytuj `get_collaborator_interactions`, używając tego identyfikatora payloadu, i skoreluj czas interakcji z ponownym wysłaniem żądania. Interakcja HTTP potwierdza pobranie, natomiast sam DNS wskazuje jedynie na rozwiązanie nazwy, a nie na zakończone żądanie HTTP. Sprawdź źródło interakcji i nagłówki żądania, aby odróżnić ruch wychodzący z serwera od ładowania po stronie przeglądarki, a następnie powtórz test z nowym payloadem, aby wykluczyć niezwiązany ruch.<sup>[[10]](#references)[[11]](#references)</sup>

Narzędzie żądań MCP zwraca odpowiedź bezpośrednio i nie musi dodawać jej do **Proxy > HTTP history**. Zachowaj wynik żądania i odpowiedzi albo użyj przeglądarki skonfigurowanej z proxy lub Repeater, aby uzyskać artefakt zapisany w historii. Przy wyborze payloadu SSRF i testach następczych skorzystaj z [rozdziału o SSRF](../pentesting-web/ssrf-server-side-request-forgery/), zamiast traktować callback out-of-band jako dowód wpływu na sieć wewnętrzną. Informacje o testowaniu samego serwera MCP znajdziesz w sekcji [Testowanie serwera MCP](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Zestaw promptów do pasywnej analizy

Repozytorium **burp-mcp-agents** zawiera szablony promptów do analizy ruchu Burp opartej na dowodach:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: szerokie pasywne wyszukiwanie podatności.
- `idor_hunter.md`: niespójności IDOR/BOLA, obiektów i tenantów oraz niezgodności uwierzytelniania.
- `auth_flow_mapper.md`: porównanie ścieżek uwierzytelnionych i nieuwierzytelnionych.
- `ssrf_redirect_hunter.md`: potencjalne SSRF i open redirect na podstawie parametrów pobierania URL i łańcuchów przekierowań.
- `logic_flaw_hunter.md`: wieloetapowe błędy logiki.
- `session_scope_hunter.md`: niewłaściwe użycie odbiorców i zakresów tokenów.
- `rate_limit_abuse_hunter.md`: luki w ograniczaniu częstotliwości i ochronie przed nadużyciami.
- `report_writer.md`: raportowanie oparte na dowodach.

## Opcjonalne tagowanie atrybucji

Aby oznaczać ruch Burp/LLM w logach, dodaj regułę przepisywania nagłówków (proxy lub Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Uwagi dotyczące bezpieczeństwa

- Preferuj **modele lokalne**, gdy ruch zawiera poufne dane.
- Udostępniaj tylko minimalną ilość dowodów potrzebną do potwierdzenia ustalenia.
- Traktuj Burp jako źródło prawdy; używaj modelu do **analizy i raportowania**, a nie do skanowania.

## Burp AI Agent (wspomagana przez AI wstępna analiza + narzędzia MCP)

**Burp AI Agent** to rozszerzenie Burp, które łączy lokalne/chmurowe LLM-y z pasywną/aktywną analizą (62 klasy podatności) i udostępnia ponad 53 narzędzia MCP, dzięki czemu zewnętrzni klienci MCP mogą zarządzać Burp.<sup>[[5]](#references)</sup> Najważniejsze funkcje:

- **Wstępna analiza z menu kontekstowego**: przechwyć ruch przez Proxy, otwórz **Proxy > HTTP History**, kliknij żądanie prawym przyciskiem myszy → **Extensions > Burp AI Agent > Analyze this request**, aby otworzyć czat AI powiązany z tym żądaniem/odpowiedzią.
- **Backendy** (wybierane dla każdego profilu):
  - Lokalny HTTP: **Ollama**, **LM Studio**.
  - Zdalny HTTP: zgodny z **OpenAI** endpoint (bazowy URL + nazwa modelu).
  - Chmurowe CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` lub `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (logowanie zależne od dostawcy).
- **Profile agenta**: szablony promptów są automatycznie instalowane w `~/.burp-ai-agent/AGENTS/`; dodaj tam dodatkowe pliki `*.md`, aby wprowadzić własne zachowania związane z analizą/skanowaniem.
- **Serwer MCP**: włącz go przez **Settings > MCP Server**, aby udostępnić operacje Burp dowolnemu klientowi MCP (ponad 53 narzędzia). Aby połączyć Claude Desktop z serwerem, edytuj `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) lub `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrola prywatności**: ustawienia STRICT / BALANCED / OFF usuwają wrażliwe dane z żądań przed wysłaniem ich do zdalnych modeli; podczas pracy z sekretami preferuj lokalne backendy.
- **Rejestrowanie audytowe**: logi JSONL z haszowaniem SHA-256 każdego wpisu, zapewniającym widoczność śladów działań AI/MCP i możliwość wykrycia manipulacji.
- **Budowanie/ładowanie**: pobierz JAR z wydaniem lub zbuduj przy użyciu Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Ostrzeżenia operacyjne: backendy chmurowe mogą eksfiltrować cookies sesji/PII, jeśli nie wymuszono trybu prywatności; dostęp MCP umożliwia zdalne sterowanie Burp, dlatego ogranicz go do zaufanych agentów i monitoruj integralność logu audytowego weryfikowaną hashem.



## References

- [1] [Integracja Burp MCP + Codex CLI i poprawka handshake w Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem ze ścisłą walidacją Origin/header w serwerze PortSwigger MCP](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agenci Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agent AI Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Serwer PortSwigger Burp Suite MCP](https://github.com/PortSwigger/mcp-server)
- [8] [Jak używać Codex do researchu Bug Bounty: szeroka eksploracja, rygorystyczna walidacja](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orkiestracja Burp Suite dla Claude Code i Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementacje narzędzi i parametry PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - podatności Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
