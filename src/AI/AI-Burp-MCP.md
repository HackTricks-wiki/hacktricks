# Burp MCP: revisione del traffico assistita da LLM

{{#include ../banners/hacktricks-training.md}}

## Panoramica

L'estensione **MCP Server** di Burp può esporre il traffico HTTP(S) intercettato ai client LLM compatibili con MCP, consentendo loro di **ragionare su richieste/risposte reali** per la scoperta di vulnerabilità e la stesura di report. Mantieni Burp come fonte di verità: usa l'analisi passiva o replay deliberati di una sola variabile alla volta invece di uno scanning cieco.<sup>[[8]](#references)</sup>

## Architettura

- **Burp MCP Server (BApp)** è in ascolto su `127.0.0.1:9876` per impostazione predefinita ed espone il traffico intercettato tramite MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** collega stdio (lato client) all'endpoint MCP SSE di Burp.
- **Reverse proxy locale opzionale** (Caddy) normalizza gli header per i rigorosi controlli di handshake di MCP.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) o Ollama (locale).

## Configurazione

### 1) Installare Burp MCP Server

Installa **MCP Server** dal Burp BApp Store e verifica che sia in ascolto su `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Estrarre il proxy JAR

Nella scheda MCP Server, fai clic su **Extract server proxy jar** e salva `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurare un client MCP (esempio con Codex)

Indica al client il proxy JAR e l'endpoint SSE diretto di Burp. Il proxy incluso nel pacchetto è un bridge da stdio a SSE; non sostituisce il listener di Burp.<sup>[[7]](#references)</sup>
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
### 4) Correggere la validazione strict di Origin/header con Caddy (se necessario)

Se l’handshake MCP fallisce a causa di controlli strict su `Origin` o di header aggiuntivi, usa un proxy inverso locale per normalizzare gli header (questo corrisponde al workaround per il problema di validazione strict di Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Avvia il proxy e il client e modifica l’`--sse-url` configurato in `http://127.0.0.1:19876` solo durante l’utilizzo di questo listener di Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Associa lo stato del browser alle evidenze del proxy (Playwright MCP)

Registra Playwright MCP in modo che il suo browser utilizzi il proxy di Burp. Questo consente all'agent di correlare lo stato del DOM/accessibility visualizzato con la cronologia HTTP esatta che lo ha prodotto.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Adatta l’indirizzo del listener, riavvia Codex e usa `/mcp` per verificare entrambe le integrazioni. L’esempio disabilita gli errori relativi ai certificati del browser, in modo che l’intercettazione HTTPS non venga bloccata dal certificato generato localmente da Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Utilizzo di client diversi

### Codex CLI

- Configura `~/.codex/config.toml` come sopra.
- Esegui `codex`, quindi `/mcp` per verificare l’elenco degli strumenti di Burp.

### Gemini CLI

Il repository **burp-mcp-agents** fornisce helper di avvio:<sup>[[4]](#references)</sup>
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

## Replay e validazione basati sulle evidenze

Non permettere all'agent di trattare una spiegazione plausibile o una risposta intermedia come una prova. Usa richieste/risposte di Burp e lo stato del browser osservato in modo indipendente per rendere ogni test falsificabile.<sup>[[8]](#references)</sup>

1. Salva una coppia richiesta/risposta di base e identifica l'esatto componente controllato dall'attacker.
2. Per i confronti di autorizzazione, acquisisci in modo indipendente lo stesso workflow con entrambi gli account prima di modificare identificatori, cookie o token.
3. Prima di riprodurre una modifica, registra l'ipotesi, la posizione dell'evidenza, il segnale atteso e il risultato che la smentirebbe.
4. Modifica un solo componente alla volta, conserva la coppia risultante ed etichetta separatamente le osservazioni dirette dalle inferenze.
5. Tieni traccia di ogni candidato come `open`, `blocked`, `rejected` o `confirmed`; rivalutalo solo quando nuove evidenze modificano il meccanismo o un prerequisito.
6. Conferma il controllo da parte dell'attacker, la raggiungibilità, la ripetibilità, l'elusione dei vincoli, l'impatto e lo stato finale dell'applicazione. Un redirect o una chiamata allo strumento completata con successo non costituisce una prova se il cambiamento di stato dichiarato avviene downstream.

Mantieni i dettagli dell'exploitation nella pagina della tecnica pertinente. Ad esempio, i candidati relativi ai messaggi del browser appartengono a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), mentre il comportamento di selezione delle chiavi dei token appartiene a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un record compatto delle ipotesi impedisce agli agent paralleli di ripetere lo stesso percorso allettante:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt pack per la revisione passiva

Il repository **burp-mcp-agents** include template di prompt per l'analisi evidence-driven del traffico Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: individuazione passiva ad ampio spettro delle vulnerabilità.
- `idor_hunter.md`: IDOR/BOLA, object/tenant drift e discrepanze di autenticazione.
- `auth_flow_mapper.md`: confronto tra percorsi autenticati e non autenticati.
- `ssrf_redirect_hunter.md`: candidati SSRF/open-redirect derivati da parametri di URL fetch e catene di redirect.
- `logic_flaw_hunter.md`: difetti logici multi-step.
- `session_scope_hunter.md`: uso improprio dell'audience/scope dei token.
- `rate_limit_abuse_hunter.md`: lacune nel throttling e nell'abuse prevention.
- `report_writer.md`: reporting incentrato sulle evidenze.

## Tagging opzionale dell'attribuzione

Per applicare un tag al traffico Burp/LLM nei log, aggiungi una riscrittura dell'header (proxy o Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Note sulla sicurezza

- Preferisci **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo le prove minime necessarie per un finding.
- Mantieni Burp come fonte di verità; usa il modello per **l'analisi e il reporting**, non per lo scanning.

## Burp AI Agent (triage assistito dall'AI + strumenti MCP)

**Burp AI Agent** è un'estensione di Burp che combina LLM locali/cloud con l'analisi passiva/attiva (62 classi di vulnerabilità) ed espone oltre 53 strumenti MCP, consentendo ai client MCP esterni di orchestrare Burp.<sup>[[5]](#references)</sup> Punti salienti:

- **Triage dal menu contestuale**: cattura il traffico tramite Proxy, apri **Proxy > HTTP History**, fai clic destro su una richiesta → **Extensions > Burp AI Agent > Analyze this request** per avviare una chat AI associata a quella richiesta/risposta.
- **Backend** (selezionabili per profilo):
- HTTP locale: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint compatibile con **OpenAI** (base URL + nome del modello).
- CLI cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login specifico del provider).
- **Profili dell'agent**: template di prompt installati automaticamente in `~/.burp-ai-agent/AGENTS/`; inserisci ulteriori file `*.md` per aggiungere comportamenti personalizzati di analisi/scanning.
- **Server MCP**: abilitalo tramite **Settings > MCP Server** per esporre le operazioni di Burp a qualsiasi client MCP (oltre 53 strumenti). Claude Desktop può essere configurato per puntare al server modificando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controlli della privacy**: STRICT / BALANCED / OFF oscurano i dati sensibili delle richieste prima di inviarli ai modelli remoti; preferisci i backend locali quando gestisci secret.
- **Audit logging**: log JSONL con hashing di integrità SHA-256 per ogni voce, a garanzia di una tracciabilità a prova di manomissione delle azioni AI/MCP.
- **Build/load**: scarica il JAR della release oppure esegui la build con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Avvertenze operative: i backend cloud possono esfiltrare cookie di sessione/PII a meno che non venga applicata la privacy mode; l'esposizione di MCP consente l'orchestrazione remota di Burp, quindi limita l'accesso agli agenti trusted e monitora l'integrità del log di audit con hash.

## References

- [1] [Integrazione di Burp MCP + Codex CLI e correzione dell'handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema di validazione strict di Origin/header nel server MCP di PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflow, launcher, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Come utilizzare Codex per la ricerca Bug Bounty: esplorare ampiamente, validare rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
