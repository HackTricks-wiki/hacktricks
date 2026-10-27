# Burp MCP: revisione del traffico assistita da LLM

{{#include ../banners/hacktricks-training.md}}

## Panoramica

L’estensione **MCP Server** di Burp può esporre il traffico HTTP(S) intercettato ai client LLM compatibili con MCP, così che possano **analizzare richieste/risposte reali** per individuare vulnerabilità e preparare bozze di report. Considera Burp la fonte autorevole: usa l’analisi passiva o ripeti deliberatamente le richieste modificando una sola variabile alla volta, anziché eseguire scansioni alla cieca.<sup>[[8]](#references)</sup>

## Architettura

- **Burp MCP Server (BApp)** è in ascolto su `127.0.0.1:9876` per impostazione predefinita ed espone il traffico intercettato tramite MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** fa da ponte tra stdio (lato client) e l’endpoint MCP SSE di Burp.
- **Reverse proxy locale opzionale** (Caddy) normalizza gli header per i controlli rigorosi dell’handshake MCP.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) o Ollama (locale).

## Configurazione

### 1) Installa Burp MCP Server

Installa **MCP Server** dal Burp BApp Store e verifica che sia in ascolto su `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Estrai il proxy JAR

Nella scheda MCP Server, fai clic su **Estrai JAR del proxy server** e salva `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configura un client MCP (esempio con Codex)

Indica al client il proxy JAR e l’endpoint SSE diretto di Burp. Il proxy incluso funge da ponte da stdio a SSE; non sostituisce il listener di Burp.<sup>[[7]](#references)</sup>

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

Poi avvia Codex ed elenca gli strumenti MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Correggere la validazione rigorosa di Origin/header con Caddy (se necessario)

Se l’handshake MCP non riesce a causa di controlli rigorosi su `Origin` o di header aggiuntivi, usa un reverse proxy locale per normalizzare gli header (questa soluzione alternativa risolve il problema di validazione rigorosa di Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Avvia il proxy e il client e modifica l'`--sse-url` configurato in `http://127.0.0.1:19876` solo mentre utilizzi questo listener di Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Associa lo stato del browser alle prove del proxy (Playwright MCP)

Registra Playwright MCP in modo che il browser utilizzi il proxy di Burp. Questo consente all’agente di correlare lo stato DOM/accessibilità renderizzato con la cronologia HTTP esatta che lo ha prodotto.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adatta l'indirizzo del listener, riavvia Codex e usa `/mcp` per verificare entrambe le integrazioni. L'esempio disabilita gli errori dei certificati del browser, così l'intercettazione HTTPS non viene bloccata dal certificato generato localmente da Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automazione del browser consapevole del proxy (OpenBurp)

La connessione MCP di Burp e il percorso del browser intercettato sono flussi di dati separati. Il servizio MCP espone gli strumenti di Burp su `127.0.0.1:9876`, mentre un'istanza Chromium dedicata invia il proprio traffico HTTP(S) tramite il proxy di Burp su `127.0.0.1:8080`. Le richieste generate direttamente da uno strumento MCP potrebbero quindi non comparire in **Proxy > HTTP history**; usa il browser con proxy quando le richieste e le risposte devono essere osservabili, modificabili o conservate come prove.<sup>[[2]](#references)[[9]](#references)</sup>

Un client con supporto SSE può registrare Burp direttamente. Un client con solo stdio può invece avviare il JAR proxy di PortSwigger. In entrambi i casi, registra un secondo MCP per il controllo del browser e indirizzalo al Chromium integrato di Burp (`BURP_CHROMIUM` è il percorso di un eseguibile locale):<sup>[[9]](#references)</sup>

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

Il flag TLS-bypass accetta i certificati generati dall'interception proxy, mentre `--isolated` impedisce alla valutazione di riutilizzare il normale profilo del browser dell'operatore. L'isolamento protegge lo stato del profilo, ma **non è una security sandbox**: il controller può comunque accedere alle sessioni autenticate aperte in quel browser di test e Burp MCP può esporre richieste, risposte e configurazioni sensibili.<sup>[[9]](#references)</sup>

Verifica separatamente il listener SSE prima di eseguire il debug del client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Un listener funzionante restituisce `Content-Type: text/event-stream`. È previsto che si verifichi un timeout dopo gli header, perché uno stream SSE rimane aperto in attesa di eventi futuri. Se il client continua a non funzionare, verifica il percorso configurato per l'estensione: PortSwigger segnala che l'endpoint può essere il percorso root oppure `/sse`, a seconda della configurazione del client e dell'estensione.<sup>[[9]](#references)[[7]](#references)</sup>

## Uso di client diversi

### Codex CLI

- Configura `~/.codex/config.toml` come sopra.
- Esegui `codex`, poi `/mcp` per verificare l'elenco degli strumenti Burp.

### Gemini CLI

Il repo **burp-mcp-agents** fornisce helper per l'avvio:<sup>[[4]](#references)</sup>

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

Esempi di modelli locali e fabbisogno approssimativo di VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay e convalida basati su evidenze

Non lasciare che l’agent consideri una spiegazione plausibile o una risposta intermedia come una prova. Usa le richieste/risposte di Burp e lo stato del browser osservato in modo indipendente per rendere falsificabile ogni test.<sup>[[8]](#references)</sup>

1. Salva una coppia di richiesta/risposta di baseline e identifica l’esatto componente controllato dall’attaccante.
2. Per i confronti di autorizzazione, acquisisci lo stesso workflow in modo indipendente con entrambi gli account prima di modificare identificatori, cookie o token.
3. Prima di riprodurre una modifica, registra l’ipotesi, la posizione dell’evidenza, il segnale atteso e il risultato che la confuterebbe.
4. Modifica un solo componente alla volta, conserva la coppia risultante e distingui le osservazioni dirette dalle deduzioni.
5. Tieni traccia di ogni candidato con gli stati `open`, `blocked`, `rejected` o `confirmed`; riprendilo in esame solo quando nuove evidenze modificano il meccanismo o un prerequisito.
6. Conferma il controllo dell’attaccante, la raggiungibilità, la ripetibilità, l’elusione dei vincoli, l’impatto e lo stato finale dell’applicazione. Un redirect o una chiamata allo strumento riuscita non costituisce una prova se il cambiamento di stato dichiarato avviene in una fase successiva.

Mantieni i dettagli di exploitation nella pagina della tecnica pertinente. Ad esempio, i candidati relativi ai messaggi del browser appartengono a [Vulnerabilità PostMessage](../pentesting-web/postmessage-vulnerabilities/README.md), mentre il comportamento di selezione della chiave dei token appartiene a [Vulnerabilità JWT](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Una registrazione sintetica delle ipotesi evita che agent paralleli ripetano lo stesso ramo allettante:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Analisi preliminare dei frame WebSocket con Burp MCP

L'estensione ufficiale espone `get_proxy_websocket_history_regex` per effettuare ricerche in sola lettura e paginate nella cronologia WebSocket di Burp. Accetta `regex`, `count` e `offset`; a differenza di `send_http1_request`, non invia un frame WebSocket. Burp registra i messaggi in entrambe le direzioni anche quando Intercept è disattivato, quindi filtra la cronologia prima di fornire al modello un piccolo insieme di frame pertinenti.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Esegui la stessa azione basata su WebSocket tramite il browser con proxy Burp, usando due account di test autenticati in modo indipendente. Mantieni insieme ciascun handshake di upgrade e i relativi cookie, l'ID della connessione, la direzione del frame e i frame di risposta; un evento dal server al client sulla connessione del primo account non dimostra che il secondo account lo abbia ricevuto.
2. Cerca con `get_proxy_websocket_history_regex` usando un'espressione mirata, come `(?i)(subscribe|room|tenant|objectId)`, `count: 20` e `offset: 0`. Incrementa `offset` per esaminare i risultati successivi. Confronta l'identificatore dell'oggetto o del topic nel frame in uscita con la risposta sulla **stessa connessione**.
3. In **Proxy > WebSockets history**, invia il frame candidato in uscita a Repeater. Associalo alla connessione aperta appropriata oppure riconnettiti usando l'handshake del secondo account. Modifica solo l'identificatore dell'oggetto o del topic e confronta i messaggi del server e lo stato dell'applicazione risultanti con entrambe le baseline. Lo strumento MCP per la cronologia non può eseguire questo replay; WebSocket Repeater consente di modificare e reinviare i frame e di riconnettersi.

Per test specifici del protocollo, come il cross-site WebSocket hijacking e l'autorizzazione dei topic del broker, consulta [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Non considerare un upgrade accettato o un echo lato client come prova dell'avvenuta sottoscrizione a un canale protetto.

## Validazione mirata out-of-band con Burp MCP

Burp Suite Professional espone `generate_collaborator_payload` e `get_collaborator_interactions` tramite l'estensione MCP ufficiale. Combinali con `get_proxy_http_history_regex` e un singolo replay con `send_http1_request` per testare un sospetto recupero di URL lato server senza eseguire una scansione dell'intero target. Burp potrebbe richiedere approvazioni separate per leggere la cronologia e inviare una richiesta.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtra la cronologia per trovare una richiesta candidata che contenga un URL, ad esempio con `url=`, `webhook` o `callback`. Salva la richiesta e la risposta originali. Lo strumento per la cronologia accetta `regex`, `count` e `offset`; usa la paginazione invece di chiedere al modello di esaminare ogni voce.<sup>[[10]](#references)</sup>
2. Genera un nuovo payload Collaborator e conserva l'**ID payload** restituito. Riproduci la richiesta acquisita verso lo stesso host e la stessa porta, modificando solo l'URL candidato e sostituendolo con un URL HTTPS sul dominio del payload. Per `send_http1_request`, passa la richiesta HTTP/1.1 completa come `content`, insieme a `targetHostname`, `targetPort` e `usesHttps`; i campi di destinazione identificano l'**applicazione**, non l'host Collaborator.<sup>[[10]](#references)</sup>
3. Interroga `get_collaborator_interactions` con quell'ID payload e correla l'ora dell'interazione con il replay. Un'interazione HTTP indica un recupero, mentre la sola risoluzione DNS dimostra la risoluzione ma non il completamento di una richiesta HTTP. Verifica la sorgente dell'interazione e gli header della richiesta per distinguere il traffico in uscita dal server dal caricamento lato browser, quindi ripeti il test con un nuovo payload per escludere traffico non correlato.<sup>[[10]](#references)[[11]](#references)</sup>

Lo strumento MCP per le richieste restituisce direttamente la risposta e potrebbe non inserirla in **Proxy > HTTP history**. Conserva il risultato della richiesta e della risposta oppure usa il browser con proxy o Repeater per ottenere un riscontro registrato nella cronologia. Per la selezione dei payload SSRF e i test successivi, consulta il [capitolo SSRF](../pentesting-web/ssrf-server-side-request-forgery/) invece di considerare una callback out-of-band come prova di un impatto sulla rete interna. Per testare il server MCP stesso, consulta [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Raccolta di prompt per l'analisi passiva

Il repo **burp-mcp-agents** include modelli di prompt per analizzare il traffico Burp basandosi sulle evidenze:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: individuazione passiva di vulnerabilità a carattere generale.
- `idor_hunter.md`: discrepanze IDOR/BOLA, tra oggetti e tenant, e incongruenze di autenticazione.
- `auth_flow_mapper.md`: confronto tra percorsi autenticati e non autenticati.
- `ssrf_redirect_hunter.md`: candidati SSRF e open redirect ricavati da parametri di recupero URL o catene di redirect.
- `logic_flaw_hunter.md`: difetti logici a più passaggi.
- `session_scope_hunter.md`: uso improprio dell'audience o dello scope dei token.
- `rate_limit_abuse_hunter.md`: lacune nella limitazione delle richieste o nella prevenzione degli abusi.
- `report_writer.md`: stesura di report basati sulle evidenze.

## Attribuzione facoltativa tramite tag

Per contrassegnare nei log il traffico Burp/LLM, aggiungi una riscrittura degli header (proxy o Match/Replace di Burp):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Note sulla sicurezza

- Preferisci **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo le prove minime necessarie per una segnalazione.
- Considera Burp la fonte attendibile; usa il modello per **analisi e report**, non per la scansione.

## Burp AI Agent (triage assistito dall'AI + strumenti MCP)

**Burp AI Agent** è un'estensione di Burp che combina LLM locali/cloud con l'analisi passiva/attiva (62 classi di vulnerabilità) ed espone oltre 53 strumenti MCP per consentire ai client MCP esterni di orchestrare Burp.<sup>[[5]](#references)</sup> Funzionalità principali:

- **Triage dal menu contestuale**: cattura il traffico tramite Proxy, apri **Proxy > HTTP History**, fai clic con il pulsante destro su una richiesta → **Extensions > Burp AI Agent > Analyze this request** per avviare una chat AI associata a quella richiesta/risposta.
- **Backend** (selezionabili per profilo):
  - HTTP locale: **Ollama**, **LM Studio**.
  - HTTP remoto: endpoint **compatibile con OpenAI** (URL base + nome del modello).
  - CLI cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (accesso specifico del provider).
- **Profili agent**: i modelli di prompt vengono installati automaticamente in `~/.burp-ai-agent/AGENTS/`; aggiungi lì altri file `*.md` per introdurre comportamenti personalizzati di analisi/scansione.
- **Server MCP**: abilitalo tramite **Settings > MCP Server** per esporre le operazioni di Burp a qualsiasi client MCP (oltre 53 strumenti). Puoi configurare Claude Desktop per connettersi al server modificando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controlli della privacy**: STRICT / BALANCED / OFF oscurano i dati sensibili delle richieste prima di inviarle ai modelli remoti; preferisci i backend locali quando gestisci segreti.
- **Registrazione di audit**: log JSONL con hashing di integrità SHA-256 per ogni voce, per una tracciabilità delle azioni AI/MCP che renda evidenti le manomissioni.
- **Build/caricamento**: scarica il JAR della release oppure compila con Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Precauzioni operative: i backend cloud possono esfiltrare cookie di sessione/PII se non viene applicata la modalità privacy; l'esposizione di MCP consente l'orchestrazione remota di Burp, quindi limita l'accesso agli agenti fidati e monitora il log di audit con hash d'integrità.



## References

- [1] [Integrazione di Burp MCP + Codex CLI e correzione dell'handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema di validazione rigorosa di Origin/header del server MCP PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (flussi di lavoro, launcher, pacchetto di prompt)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Come usare Codex per la ricerca di bug bounty: esplorare ampiamente, convalidare rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orchestrazione di Burp Suite per Claude Code e Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementazioni degli strumenti e parametri del server MCP PortSwigger](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - vulnerabilità Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - cronologia di WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - lavorare con i messaggi WebSocket in Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
