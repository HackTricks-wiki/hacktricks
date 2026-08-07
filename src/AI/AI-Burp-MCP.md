# Burp MCP: revisione del traffico assistita da LLM

{{#include ../banners/hacktricks-training.md}}

## Panoramica

L'estensione **MCP Server** di Burp può esporre il traffico HTTP(S) intercettato ai client LLM compatibili con MCP, consentendo loro di **ragionare su richieste/risposte reali** per la scoperta passiva delle vulnerabilità e la stesura di report. L'obiettivo è una revisione basata sulle evidenze (senza fuzzing o scanning alla cieca), mantenendo Burp come fonte di verità.

## Architettura

- **Burp MCP Server (BApp)** ascolta su `127.0.0.1:9876` ed espone il traffico intercettato tramite MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** collega lo stdio (lato client) all'endpoint MCP SSE di Burp.
- **Reverse proxy locale opzionale** (Caddy) normalizza gli header per i rigorosi controlli dell'handshake MCP.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) oppure Ollama (locale).

## Configurazione

### 1) Installare Burp MCP Server

Installare **MCP Server** dal Burp BApp Store e verificare che sia in ascolto su `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Estrarre il proxy JAR

Nella scheda MCP Server, fare clic su **Extract server proxy jar** e salvare `mcp-proxy.jar`.

### 3) Configurare un client MCP (esempio con Codex)

Indicare al client il proxy JAR e l'endpoint SSE di Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Quindi esegui Codex ed elenca gli strumenti MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Correggere la validazione rigorosa di Origin/header con Caddy (se necessario)

Se l'handshake MCP non riesce a causa di controlli rigorosi su `Origin` o di intestazioni aggiuntive, usa un reverse proxy locale per normalizzare le intestazioni (questa è la soluzione alternativa per il problema di validazione rigorosa di Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Avvia il proxy e il client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Utilizzo di client diversi

### Codex CLI

- Configura `~/.codex/config.toml` come sopra.
- Esegui `codex`, quindi `/mcp` per verificare l'elenco degli strumenti Burp.

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
Esempi di modelli locali e requisiti approssimativi di VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack per la revisione passiva

Il repo **burp-mcp-agents** include template di prompt per l'analisi basata sulle evidenze del traffico Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ampia individuazione passiva delle vulnerabilità.
- `idor_hunter.md`: IDOR/BOLA, drift di oggetti/tenant e discrepanze di autenticazione.
- `auth_flow_mapper.md`: confronto tra percorsi autenticati e non autenticati.
- `ssrf_redirect_hunter.md`: potenziali SSRF/open redirect derivanti da parametri di URL fetch e catene di redirect.
- `logic_flaw_hunter.md`: difetti logici multi-step.
- `session_scope_hunter.md`: uso improprio di audience/scope dei token.
- `rate_limit_abuse_hunter.md`: lacune nel throttling e nella prevenzione degli abusi.
- `report_writer.md`: report focalizzati sulle evidenze.

## Tagging di attribuzione opzionale

Per taggare il traffico Burp/LLM nei log, aggiungi una riscrittura dell'header (proxy o Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Note di sicurezza

- Preferisci i **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo le evidenze minime necessarie per un finding.
- Mantieni Burp come fonte di verità; usa il modello per **analisi e reporting**, non per lo scanning.

## Burp AI Agent (triage assistito dall'AI + strumenti MCP)

**Burp AI Agent** è un'estensione di Burp che combina LLM locali/cloud con analisi passiva/attiva (62 classi di vulnerabilità) ed espone oltre 53 strumenti MCP, consentendo ai client MCP esterni di orchestrare Burp.<sup>[[5]](#references)</sup> Punti salienti:

- **Triage dal menu contestuale**: cattura il traffico tramite Proxy, apri **Proxy > HTTP History**, fai clic destro su una richiesta → **Extensions > Burp AI Agent > Analyze this request** per avviare una chat AI associata a quella richiesta/risposta.
- **Backends** (selezionabili per profilo):
- HTTP locale: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint **OpenAI-compatible** (base URL + nome del modello).
- CLI cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login specifico del provider).
- **Profili degli agent**: template di prompt installati automaticamente in `~/.burp-ai-agent/AGENTS/`; inserisci ulteriori file `*.md` per aggiungere comportamenti personalizzati di analisi/scanning.
- **Server MCP**: abilitalo tramite **Settings > MCP Server** per esporre le operazioni di Burp a qualsiasi client MCP (oltre 53 strumenti). Claude Desktop può essere configurato per puntare al server modificando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controlli della privacy**: STRICT / BALANCED / OFF redigono i dati sensibili delle richieste prima di inviarli ai modelli remoti; preferisci i backend locali quando gestisci i secrets.
- **Audit logging**: log JSONL con hashing di integrità SHA-256 per ogni voce, per una tracciabilità a prova di manomissione delle azioni AI/MCP.
- **Build/caricamento**: scarica il JAR della release oppure esegui la build con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Avvertenze operative: i cloud backends possono esfiltrare cookie di sessione/PII a meno che non venga applicata la privacy mode; l'esposizione di MCP consente l'orchestrazione remota di Burp, quindi limita l'accesso agli agenti considerati affidabili e monitora l'audit log con hash di integrità.

## Riferimenti

- [1] [Integrazione di Burp MCP + Codex CLI e correzione dell'handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema di validazione strict di Origin/header nel server MCP di PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflow, launcher, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
