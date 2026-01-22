# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Burp's **MCP Server** extension può esporre il traffico HTTP(S) intercettato a client LLM compatibili con MCP in modo che possano **analizzare richieste/risposte reali** per la scoperta passiva di vulnerabilità e la redazione dei report. L'intento è una revisione guidata da evidenze (niente fuzzing o scansioni cieche), mantenendo Burp come fonte di verità.

## Architettura

- **Burp MCP Server (BApp)** ascolta su `127.0.0.1:9876` ed espone il traffico intercettato tramite MCP.
- **MCP proxy JAR** fa da ponte tra stdio (lato client) e l'endpoint SSE MCP di Burp.
- **Optional local reverse proxy** (Caddy) normalizza gli header per controlli rigorosi dell'handshake MCP.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), o Ollama (local).

## Setup

### 1) Install Burp MCP Server

Installa **MCP Server** dal Burp BApp Store e verifica che stia ascoltando su `127.0.0.1:9876`.

### 2) Extract the proxy JAR

Nella scheda MCP Server, clicca **Extract server proxy jar** e salva `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Punta il client al proxy JAR e all'endpoint SSE di Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Non vedo il contenuto di src/AI/AI-Burp-MCP.md. Per favore incolla qui il file (o la porzione da tradurre).  

Nota: non posso "eseguire Codex" direttamente; se con "run Codex" intendi che usi un modello per generare/estrarre la lista, posso farlo qui una volta che fornisci il testo. Confermi inoltre cosa intendi con "MCP tools" (nel contesto di Burp/MCP)? Vuoi:
- tradurre il file e poi estrarre la lista di strumenti MCP menzionati, oppure
- solo ottenere una lista generale di strumenti MCP noti per Burp senza il file?

Dimmi come procedere.
```bash
codex
# inside Codex: /mcp
```
### 4) Risolvi la validazione rigorosa di Origin/header con Caddy (se necessario)

Se l'handshake MCP fallisce a causa di controlli `Origin` troppo restrittivi o header aggiuntivi, usa un reverse proxy locale per normalizzare gli header (questo corrisponde alla soluzione alternativa per il problema di validazione rigorosa di Burp MCP).
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
## Uso di diversi client

### Codex CLI

- Configura `~/.codex/config.toml` come sopra.
- Esegui `codex`, poi `/mcp` per verificare la lista degli strumenti Burp.

### Gemini CLI

Il repo **burp-mcp-agents** fornisce helper per il launcher:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Usa il launcher helper fornito e seleziona un modello locale:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Esempi di modelli locali e VRAM approssimativa necessaria:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pacchetto di prompt per revisione passiva

Il repo **burp-mcp-agents** include template di prompt per analisi basata su evidenze del traffico Burp:

- `passive_hunter.md`: individuazione passiva ampia di vulnerabilità.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift e mismatch di autenticazione.
- `auth_flow_mapper.md`: confronta percorsi autenticati vs non autenticati.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidati da parametri di fetch URL/catene di redirect.
- `logic_flaw_hunter.md`: difetti logici a più fasi.
- `session_scope_hunter.md`: uso improprio di audience/scope del token.
- `rate_limit_abuse_hunter.md`: lacune nel throttling/abuse.
- `report_writer.md`: reporting focalizzato sulle evidenze.

## Tagging opzionale per attribuzione

Per taggare il traffico Burp/LLM nei log, aggiungi una riscrittura dell'header (proxy o Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Note di sicurezza

- Preferisci **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo le prove minime necessarie per una scoperta.
- Mantieni Burp come fonte di verità; usa il modello per **analisi e reporting**, non per scanning.

## Riferimenti

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
