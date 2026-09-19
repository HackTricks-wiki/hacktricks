# Burp MCP: revisione del traffico assistita da LLM

{{#include ../banners/hacktricks-training.md}}

## Panoramica

L'estensione **MCP Server** di Burp può esporre il traffico HTTP(S) intercettato ai client LLM compatibili con MCP, consentendo loro di **ragionare su richieste/risposte reali** per individuare vulnerabilità e redigere report. Mantieni Burp come fonte autorevole: usa l'analisi passiva o replay deliberati modificando una sola variabile alla volta, invece di eseguire scansioni alla cieca.<sup>[[8]](#references)</sup>

## Architettura

- **Burp MCP Server (BApp)** è in ascolto su `127.0.0.1:9876` per impostazione predefinita ed espone il traffico intercettato tramite MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** collega stdio (lato client) all'endpoint MCP SSE di Burp.
- **Reverse proxy locale opzionale** (Caddy) normalizza gli header per i controlli rigorosi dell'handshake MCP.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) oppure Ollama (locale).

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

Se l’handshake MCP fallisce a causa di controlli rigorosi su `Origin` o di header aggiuntivi, usa un reverse proxy locale per normalizzare gli header (questo corrisponde al workaround per il problema di validazione rigorosa di Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Avvia il proxy e il client e modifica il valore configurato di `--sse-url` in `http://127.0.0.1:19876` solo durante l'utilizzo di questo listener Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Associa lo stato del browser alle evidenze del proxy (Playwright MCP)

Registra Playwright MCP in modo che il suo browser utilizzi il proxy di Burp. Questo permette all'agent di correlare lo stato del DOM/accessibilità renderizzato con la cronologia HTTP esatta che lo ha prodotto.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Adatta l'indirizzo del listener, riavvia Codex e usa `/mcp` per verificare entrambe le integrazioni. L'esempio disabilita gli errori relativi ai certificati del browser, così l'intercettazione HTTPS non viene bloccata dal certificato generato localmente da Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automazione del browser compatibile con il proxy (OpenBurp)

La connessione Burp MCP e il percorso del browser intercettato sono flussi di dati separati. Il servizio MCP espone gli strumenti Burp su `127.0.0.1:9876`, mentre un'istanza Chromium dedicata invia il proprio traffico HTTP(S) attraverso il proxy di Burp su `127.0.0.1:8080`. Le richieste generate direttamente da uno strumento MCP potrebbero quindi non comparire in **Proxy > HTTP history**; usa il browser con proxy ogni volta che la richiesta/risposta deve essere osservabile, modificabile o conservata come evidenza.<sup>[[2]](#references)[[9]](#references)</sup>

Un client con supporto SSE può registrare Burp direttamente. Un client che supporta solo stdio può invece avviare il proxy JAR di PortSwigger. In entrambi i casi, registra un secondo browser-control MCP e indirizzalo al Chromium integrato di Burp (`BURP_CHROMIUM` è un percorso verso un eseguibile locale):<sup>[[9]](#references)</sup>
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
Il flag TLS-bypass accetta i certificati generati dal proxy di intercettazione, mentre `--isolated` impedisce all'assessment di riutilizzare il normale profilo del browser dell'operatore. L'isolamento protegge lo stato del profilo, ma **non è una sandbox di sicurezza**: il controller può comunque accedere alle sessioni autenticate aperte in quel browser di test, e Burp MCP può esporre richieste, risposte e configurazioni sensibili.<sup>[[9]](#references)</sup>

Testa il listener SSE in modo indipendente prima di eseguire il debug del client bridge:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Un listener funzionante restituisce `Content-Type: text/event-stream`. Un timeout dopo gli header è previsto, perché uno stream SSE rimane aperto per eventi futuri. Se il client continua a non funzionare, verifica la route configurata dell'estensione: PortSwigger indica che l'endpoint può essere il percorso radice o `/sse`, a seconda del client e della configurazione dell'estensione.<sup>[[9]](#references)[[7]](#references)</sup>

## Utilizzo di client diversi

### Codex CLI

- Configura `~/.codex/config.toml` come indicato sopra.
- Avvia `codex`, quindi esegui `/mcp` per verificare l'elenco degli strumenti Burp.

### Gemini CLI

Il repo **burp-mcp-agents** fornisce helper di avvio:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Usa l'helper di avvio fornito e seleziona un modello locale:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Esempi di modelli locali e fabbisogno approssimativo di VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay e validazione basati sulle evidenze

Non consentire all'agente di trattare una spiegazione plausibile o una risposta intermedia come una prova. Usa richieste/risposte di Burp e lo stato del browser osservato indipendentemente per rendere ogni test falsificabile.<sup>[[8]](#references)</sup>

1. Salva una coppia di richiesta/risposta baseline e identifica l'esatto componente controllato dall'attacker.
2. Per i confronti di autorizzazione, acquisisci lo stesso workflow in modo indipendente con entrambi gli account prima di modificare identificatori, cookie o token.
3. Prima di riprodurre una mutazione, registra l'ipotesi, la posizione dell'evidenza, il segnale previsto e il risultato che la smentirebbe.
4. Modifica un solo componente alla volta, conserva la coppia risultante ed etichetta separatamente le osservazioni dirette e le inferenze.
5. Tieni traccia di ogni candidato come `open`, `blocked`, `rejected` o `confirmed`; rivalutalo solo quando nuove evidenze modificano il meccanismo o un prerequisito.
6. Conferma il controllo dell'attacker, la raggiungibilità, la ripetibilità, il bypass dei vincoli, l'impatto e lo stato finale dell'applicazione. Un redirect o una chiamata al tool riuscita non costituiscono una prova se il cambiamento di stato dichiarato avviene downstream.

Mantieni i dettagli dell'exploitation nella pagina della tecnica pertinente. Ad esempio, i candidati relativi ai messaggi del browser appartengono a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), mentre il comportamento di selezione delle chiavi dei token appartiene a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un record compatto dell'ipotesi impedisce agli agenti paralleli di ripetere lo stesso ramo allettante:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt pack per la revisione passiva

Il repo **burp-mcp-agents** include template di prompt per l'analisi basata sulle evidenze del traffico Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: individuazione passiva ampia delle vulnerabilità.
- `idor_hunter.md`: IDOR/BOLA, oggetti, tenant drift e discrepanze di autenticazione.
- `auth_flow_mapper.md`: confronto tra percorsi autenticati e non autenticati.
- `ssrf_redirect_hunter.md`: candidati SSRF/open-redirect derivati da parametri di URL fetch e catene di redirect.
- `logic_flaw_hunter.md`: difetti logici multi-step.
- `session_scope_hunter.md`: uso improprio dell'audience/scope dei token.
- `rate_limit_abuse_hunter.md`: lacune nel throttling e nell'abuso.
- `report_writer.md`: reporting incentrato sulle evidenze.

## Tagging opzionale dell'attribuzione

Per contrassegnare il traffico Burp/LLM nei log, aggiungi una regola di riscrittura dell'header (proxy o Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Note sulla sicurezza

- Preferisci i **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo le evidenze minime necessarie per un finding.
- Considera Burp la fonte di verità; usa il modello per **analisi e reporting**, non per lo scanning.

## Burp AI Agent (triage assistito dall'AI + strumenti MCP)

**Burp AI Agent** è un'estensione di Burp che combina LLM locali/cloud con l'analisi passiva/attiva (62 classi di vulnerabilità) ed espone oltre 53 strumenti MCP, consentendo ai client MCP esterni di orchestrare Burp.<sup>[[5]](#references)</sup> Punti salienti:

- **Triage dal menu contestuale**: cattura il traffico tramite Proxy, apri **Proxy > HTTP History**, fai clic con il tasto destro su una richiesta → **Extensions > Burp AI Agent > Analyze this request** per avviare una chat AI associata a quella richiesta/risposta.
- **Backends** (selezionabili per profilo):
- HTTP locale: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint compatibile con **OpenAI** (base URL + nome del modello).
- Cloud CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` oppure `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login specifico del provider).
- **Profili dell'Agent**: template di prompt installati automaticamente in `~/.burp-ai-agent/AGENTS/`; inserisci lì file `*.md` aggiuntivi per aggiungere comportamenti personalizzati di analisi/scanning.
- **Server MCP**: abilitalo tramite **Settings > MCP Server** per esporre le operazioni di Burp a qualsiasi client MCP (oltre 53 strumenti). Claude Desktop può essere configurato per collegarsi al server modificando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) oppure `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controlli della privacy**: STRICT / BALANCED / OFF redigono i dati sensibili delle richieste prima di inviarli ai modelli remoti; preferisci i backend locali quando gestisci segreti.
- **Audit logging**: log JSONL con hashing di integrità SHA-256 per ogni voce, a supporto della tracciabilità a prova di manomissione delle azioni AI/MCP.
- **Build/caricamento**: scarica il JAR della release oppure esegui la build con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Avvertenze operative: i backend cloud possono esfiltrare cookie di sessione/PII a meno che non venga applicata la modalità privacy; l'esposizione di MCP concede l'orchestrazione remota di Burp, quindi limita l'accesso agli agenti attendibili e monitora il log di audit con hash di integrità.

## References

- [1] [Integrazione di Burp MCP + Codex CLI e correzione dell'handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema di validazione strict di Origin/header nel server MCP di PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflow, launcher, pacchetto di prompt)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Come usare Codex per la ricerca di Bug Bounty: esplorare ampiamente, validare rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orchestrazione di Burp Suite per Claude Code e Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
