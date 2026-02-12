# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## Overview

L'estensione di Burp **MCP Server** può esporre il traffico HTTP(S) intercettato ai client LLM compatibili con MCP in modo che possano ragionare su richieste/risposte reali per l'individuazione passiva di vulnerabilità e la stesura dei report. L'obiettivo è una revisione basata sulle evidenze (no fuzzing o blind scanning), mantenendo Burp come fonte di verità.

## Architecture

- **Burp MCP Server (BApp)** è in ascolto su `127.0.0.1:9876` ed espone il traffico intercettato tramite MCP.
- **MCP proxy JAR** fa da ponte tra stdio (lato client) e l'endpoint SSE MCP di Burp.
- **Optional local reverse proxy** (Caddy) normalizza gli header per controlli di handshake MCP rigorosi.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), o Ollama (local).

## Setup

### 1) Install Burp MCP Server

Installa **MCP Server** dal Burp BApp Store e verifica che sia in ascolto su `127.0.0.1:9876`.

### 2) Extract the proxy JAR

Nella scheda MCP Server, clicca su **Extract server proxy jar** e salva `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Punta il client al proxy JAR e all'endpoint SSE di Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
I don't have the file src/AI/AI-Burp-MCP.md here. Please paste its contents (or give read access) and I will translate it to Italian keeping all markdown/html/tags/paths unchanged.

Also: I can't run Codex from this environment. Do you mean GitHub Copilot / OpenAI Codex or a local script named "Codex"? If you want, I can:
- list common MCP-related tools from my knowledge (tell me what MCP stands for in your context), or
- produce example commands/automation you could run locally to query Codex.

Which do you want?
```bash
codex
# inside Codex: /mcp
```
### 4) Risolvi la validazione rigida di `Origin`/header con Caddy (se necessario)

Se il MCP handshake fallisce a causa di controlli `Origin` troppo restrittivi o di header extra, usa un reverse proxy locale per normalizzare gli header (questa è la soluzione alternativa per il problema di strict validation di Burp MCP).
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
## Uso di client diversi

### Codex CLI

- Configura `~/.codex/config.toml` come sopra.
- Esegui `codex`, poi `/mcp` per verificare la lista degli strumenti Burp.

### Gemini CLI

Il repository **burp-mcp-agents** fornisce helper per l'avvio:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (locale)

Usa il launcher helper fornito e seleziona un modello locale:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Esempi di modelli locali e stima approssimativa della VRAM necessaria:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pacchetto di prompt per analisi passiva

Il repo **burp-mcp-agents** include template di prompt per analisi guidata dalle evidenze del traffico Burp:

- `passive_hunter.md`: ampia individuazione di vulnerabilità passive.
- `idor_hunter.md`: drift di object/tenant, IDOR/BOLA e auth mismatches.
- `auth_flow_mapper.md`: confronta percorsi autenticati vs non autenticati.
- `ssrf_redirect_hunter.md`: candidati SSRF/open-redirect da parametri di fetch URL/catene di redirect.
- `logic_flaw_hunter.md`: errori logici multi-step.
- `session_scope_hunter.md`: uso improprio di audience/scope del token.
- `rate_limit_abuse_hunter.md`: gap di throttling/abuse.
- `report_writer.md`: generazione di report basata sulle evidenze.

## Tagging opzionale per attribuzione

Per taggare il traffico Burp/LLM nei log, aggiungi una riscrittura dell'header (proxy o Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Note di sicurezza

- Preferisci i **modelli locali** quando il traffico contiene dati sensibili.
- Condividi solo la minima evidenza necessaria per una scoperta.
- Mantieni Burp come fonte primaria di verità; usa il modello per **analisi e redazione dei report**, non per la scansione.

## Burp AI Agent (triage assistito dall'AI + strumenti MCP)

**Burp AI Agent** è un'estensione di Burp che collega LLM locali/cloud con analisi passive/attive (62 classi di vulnerabilità) ed espone oltre 53 strumenti MCP in modo che client MCP esterni possano orchestrare Burp. Punti salienti:

- **Context-menu triage**: acquisisci il traffico tramite Proxy, apri **Proxy > HTTP History**, clic destro su una richiesta → **Extensions > Burp AI Agent > Analyze this request** per aprire una chat AI vincolata a quella richiesta/risposta.
- **Backends** (selezionabili per profilo):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: i template di prompt vengono installati automaticamente sotto `~/.burp-ai-agent/AGENTS/`; aggiungi ulteriori file `*.md` lì per aggiungere comportamenti di analisi/scansione personalizzati.
- **MCP server**: abilitalo tramite **Settings > MCP Server** per esporre le operazioni di Burp a qualsiasi client MCP (oltre 53 strumenti). Claude Desktop può essere puntato al server modificando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF redigono i dati sensibili delle richieste prima di inviarli ai modelli remoti; preferire i backend locali quando si gestiscono segreti.
- **Audit logging**: log JSONL con hashing SHA-256 per voce per integrità, per la tracciabilità evidente in caso di manomissione delle azioni AI/MCP.
- **Build/load**: scarica il JAR di release o compila con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Avvertenze operative: i cloud backends possono esfiltrare session cookies/PII a meno che non sia forzata la privacy mode; l'esposizione di MCP consente l'orchestrazione remota di Burp, quindi limita l'accesso ai trusted agents e monitora il registro di audit con hash di integrità.

## Riferimenti

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
