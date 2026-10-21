# Burp MCP: revisione del traffico assistita da LLM

{{#include ../banners/hacktricks-training.md}}

## Panoramica

L'estensione **MCP Server** di Burp può esporre il traffico HTTP(S) intercettato ai client LLM compatibili con MCP, in modo che possano **analizzare richieste/risposte reali** per individuare vulnerabilità e preparare bozze di report. Considera Burp la fonte di verità: usa l'analisi passiva o replay deliberati modificando una sola variabile alla volta, anziché fare scanning alla cieca.<sup>[[8]](#references)</sup>

## Architettura

- **Burp MCP Server (BApp)** è in ascolto su `127.0.0.1:9876` per impostazione predefinita ed espone il traffico intercettato tramite MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** collega stdio (lato client) all'endpoint MCP SSE di Burp.
- **Reverse proxy locale facoltativo** (Caddy) normalizza gli header per i controlli rigorosi dell'handshake MCP.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) o Ollama (locale).

## Configurazione

### 1) Installare Burp MCP Server

Installa **MCP Server** dal Burp BApp Store e verifica che sia in ascolto su `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Estrarre il proxy JAR

Nella scheda MCP Server, fai clic su **Extract server proxy jar** e salva `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurare un client MCP (esempio con Codex)

Indica al client il proxy JAR e l'endpoint SSE diretto di Burp. Il proxy incluso è un bridge da stdio a SSE; non sostituisce il listener di Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

Il comando Codex equivalente è:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Quindi esegui Codex ed elenca gli strumenti MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Correggere la validazione rigorosa di Origin/header con Caddy (se necessario)

Se l’handshake MCP fallisce a causa di controlli rigorosi su `Origin` o di header aggiuntivi, usa un reverse proxy locale per normalizzare gli header (questo corrisponde alla soluzione alternativa per il problema di validazione rigorosa di Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Avvia il proxy e il client e modifica `--sse-url` configurato in `http://127.0.0.1:19876` solo mentre utilizzi questo listener Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Associa lo stato del browser alle evidenze del proxy (Playwright MCP)

Configura Playwright MCP affinché il browser utilizzi il proxy di Burp. In questo modo, l'agente può correlare lo stato del DOM/accessibility renderizzato con la cronologia HTTP esatta che lo ha prodotto.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adatta l'indirizzo del listener, riavvia Codex e usa `/mcp` per verificare entrambe le integrazioni. L'esempio disabilita gli errori dei certificati del browser, così l'intercettazione HTTPS non viene bloccata dal certificato generato localmente da Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automazione del browser con supporto proxy (OpenBurp)

La connessione Burp MCP e il percorso del browser intercettato sono flussi di dati separati. Il servizio MCP espone gli strumenti Burp su `127.0.0.1:9876`, mentre un'istanza dedicata di Chromium invia il traffico HTTP(S) attraverso il proxy di Burp su `127.0.0.1:8080`. Le richieste generate direttamente da uno strumento MCP potrebbero quindi non comparire in **Proxy > HTTP history**; usa il browser instradato tramite proxy quando la richiesta/risposta deve essere osservabile, modificabile o conservata come prova.<sup>[[2]](#references)[[9]](#references)</sup>

Un client con supporto SSE può registrare direttamente Burp. Un client che supporta solo stdio può invece avviare il proxy JAR di PortSwigger. In entrambi i casi, registra un secondo MCP per il controllo del browser e indirizzalo al Chromium integrato in Burp (`BURP_CHROMIUM` è un percorso locale all'eseguibile):<sup>[[9]](#references)</sup>

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

Il flag TLS-bypass accetta i certificati generati dal proxy di intercettazione, mentre `--isolated` impedisce alla valutazione di riutilizzare il normale profilo del browser dell'operatore. L'isolamento protegge lo stato del profilo, ma **non è una sandbox di sicurezza**: il controller può comunque accedere alle sessioni autenticate aperte in quel browser di test, e Burp MCP può esporre richieste, risposte e configurazioni sensibili.<sup>[[9]](#references)</sup>

Verifica in modo indipendente il listener SSE prima di eseguire il debug del client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Un listener funzionante restituisce `Content-Type: text/event-stream`. È normale che si verifichi un timeout dopo gli header, perché uno stream SSE rimane aperto in attesa di eventi futuri. Se il client continua a non funzionare, verifica il percorso configurato per l’estensione: PortSwigger segnala che l’endpoint può essere il percorso radice o `/sse`, a seconda del client e della configurazione dell’estensione.<sup>[[9]](#references)[[7]](#references)</sup>

## Using different clients

### Codex CLI

- Configura `~/.codex/config.toml` come sopra.
- Esegui `codex`, poi `/mcp` per verificare l’elenco degli strumenti Burp.

### Gemini CLI

Il repo **burp-mcp-agents** fornisce helper per l’avvio:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (locale)

Usa l'helper di avvio fornito e seleziona un modello locale:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Esempi di modelli locali e requisiti approssimativi di VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay e convalida basati sulle evidenze

Non permettere all'agent di trattare una spiegazione plausibile o una risposta intermedia come una prova. Usa richieste/risposte di Burp e lo stato del browser osservato in modo indipendente per rendere falsificabile ogni test.<sup>[[8]](#references)</sup>

1. Salva una coppia di richiesta/risposta di baseline e identifica l'esatto componente controllato dall'attaccante.
2. Per i confronti di autorizzazione, acquisisci lo stesso workflow in modo indipendente con entrambi gli account prima di modificare identificatori, cookie o token.
3. Prima di riprodurre una modifica, registra l'ipotesi, la posizione dell'evidenza, il segnale atteso e il risultato che la confuterebbe.
4. Modifica un solo componente alla volta, conserva la coppia risultante e distingui le osservazioni dirette dalle inferenze.
5. Tieni traccia di ogni candidato come `open`, `blocked`, `rejected` o `confirmed`; riprendilo in esame solo quando nuove evidenze modificano il meccanismo o un prerequisito.
6. Conferma il controllo da parte dell'attaccante, la raggiungibilità, la ripetibilità, l'elusione dei vincoli, l'impatto e lo stato finale dell'applicazione. Un redirect o una chiamata riuscita a uno strumento non costituiscono una prova se il cambiamento di stato dichiarato avviene a valle.

Mantieni i dettagli dello sfruttamento nella pagina della tecnica pertinente. Ad esempio, i candidati relativi ai messaggi del browser appartengono a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), mentre il comportamento di selezione della chiave del token appartiene a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un registro compatto delle ipotesi evita che agenti in parallelo ripetano lo stesso ramo allettante:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Validazione out-of-band mirata con Burp MCP

Burp Suite Professional espone `generate_collaborator_payload` e `get_collaborator_interactions` tramite l'estensione MCP ufficiale. Combinali con `get_proxy_http_history_regex` e un singolo replay con `send_http1_request` per testare un sospetto recupero di URL lato server senza eseguire una scansione dell'intero target. Burp potrebbe richiedere un'approvazione separata per leggere la cronologia e inviare una richiesta.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtra la cronologia per una richiesta candidata che contenga un URL, ad esempio una contenente `url=`, `webhook` o `callback`. Salva la richiesta e la risposta originali. Lo strumento per la cronologia accetta `regex`, `count` e `offset`; usa la paginazione invece di chiedere al modello di esaminare ogni voce.<sup>[[10]](#references)</sup>
2. Genera un nuovo payload Collaborator e conserva il **payload ID** restituito. Riproduci la richiesta acquisita verso lo stesso host e la stessa porta, modificando solo l'URL candidato con un URL HTTPS sul dominio di quel payload. Per `send_http1_request`, passa la richiesta HTTP/1.1 completa come `content`, insieme a `targetHostname`, `targetPort` e `usesHttps`; i campi di destinazione identificano l'**applicazione**, non l'host Collaborator.<sup>[[10]](#references)</sup>
3. Interroga `get_collaborator_interactions` con quel payload ID e correla l'orario dell'interazione con il replay. Un'interazione HTTP è compatibile con un recupero, mentre la sola attività DNS indica una risoluzione, ma non una richiesta HTTP completata. Controlla la sorgente dell'interazione e gli header della richiesta per distinguere il traffico in uscita dal server dal caricamento lato browser, quindi ripeti il test con un nuovo payload per escludere traffico non correlato.<sup>[[10]](#references)[[11]](#references)</sup>

Lo strumento di richiesta MCP restituisce direttamente la risposta e potrebbe non inserirla in **Proxy > HTTP history**. Conserva il risultato della richiesta/risposta oppure usa il browser tramite proxy o Repeater per ottenere un artefatto registrato nella cronologia. Per la selezione dei payload SSRF e i test successivi, consulta il [capitolo SSRF](../pentesting-web/ssrf-server-side-request-forgery/) invece di considerare una callback out-of-band come prova di impatto sulla rete interna. Per testare il server MCP stesso, consulta [test dei server MCP](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Raccolta di prompt per la revisione passiva

Il repo **burp-mcp-agents** include modelli di prompt per l'analisi del traffico Burp basata su prove:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: individuazione passiva e ampia delle vulnerabilità.
- `idor_hunter.md`: IDOR/BOLA, derive di oggetti/tenant e discrepanze di autenticazione.
- `auth_flow_mapper.md`: confronto tra percorsi autenticati e non autenticati.
- `ssrf_redirect_hunter.md`: candidati SSRF/open redirect individuati tramite parametri di recupero URL/catene di redirect.
- `logic_flaw_hunter.md`: difetti logici multi-step.
- `session_scope_hunter.md`: uso improprio di audience/scope dei token.
- `rate_limit_abuse_hunter.md`: lacune nel throttling/abuso.
- `report_writer.md`: report incentrati sulle prove.

## Tag di attribuzione facoltativi

Per contrassegnare nei log il traffico Burp/LLM, aggiungi una riscrittura dell'header (proxy o Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Note sulla sicurezza

- Preferisci **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo le prove minime necessarie per una segnalazione.
- Considera Burp la fonte attendibile; usa il modello per **analisi e report**, non per la scansione.

## Burp AI Agent (triage assistito dall'AI + strumenti MCP)

**Burp AI Agent** è un'estensione di Burp che combina LLM locali/cloud con l'analisi passiva/attiva (62 classi di vulnerabilità) ed espone oltre 53 strumenti MCP, consentendo ai client MCP esterni di orchestrare Burp.<sup>[[5]](#references)</sup> Funzionalità principali:

- **Triage dal menu contestuale**: acquisisci il traffico tramite Proxy, apri **Proxy > HTTP History**, fai clic destro su una richiesta → **Extensions > Burp AI Agent > Analyze this request** per avviare una chat AI associata a quella richiesta/risposta.
- **Backend** (selezionabili per profilo):
  - HTTP locale: **Ollama**, **LM Studio**.
  - HTTP remoto: endpoint **compatibile con OpenAI** (URL di base + nome del modello).
  - CLI cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (accesso specifico del provider).
- **Profili agent**: i template dei prompt vengono installati automaticamente in `~/.burp-ai-agent/AGENTS/`; aggiungi altri file `*.md` in questa directory per introdurre comportamenti personalizzati di analisi/scansione.
- **Server MCP**: abilitalo da **Settings > MCP Server** per esporre le operazioni di Burp a qualsiasi client MCP (oltre 53 strumenti). Puoi configurare Claude Desktop per connettersi al server modificando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controlli della privacy**: STRICT / BALANCED / OFF oscurano i dati sensibili delle richieste prima di inviarle ai modelli remoti; preferisci backend locali quando gestisci segreti.
- **Registrazione degli audit**: log JSONL con hashing SHA-256 per ogni voce, per garantire la tracciabilità delle azioni AI/MCP e renderne evidenti le manomissioni.
- **Build/caricamento**: scarica il JAR della release oppure esegui la build con Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Precauzioni operative: i backend cloud possono esfiltrare cookie di sessione/PII, a meno che non venga applicata la privacy mode; l’esposizione di MCP consente l’orchestrazione remota di Burp, quindi limita l’accesso agli agenti fidati e monitora il log di audit con hash di integrità.



## References

- [1] [Integrazione di Burp MCP + Codex CLI e correzione dell’handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema di validazione rigorosa di Origin/header nel server MCP di PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agenti Burp MCP (workflow, launcher, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agente AI di Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Come usare Codex per la ricerca Bug Bounty: esplorare ampiamente, convalidare rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orchestrazione di Burp Suite per Claude Code e Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementazioni degli strumenti e parametri di PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Vulnerabilità Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
