# Burp MCP: LLM-asistirana revizija saobraćaja

{{#include ../banners/hacktricks-training.md}}

## Overview

Burp's **MCP Server** extension može izložiti presretnuti HTTP(S) saobraćaj MCP-kompatibilnim LLM klijentima kako bi mogli **da rezoniraju preko stvarnih zahteva/odgovora** za pasivno otkrivanje ranjivosti i sastavljanje izveštaja. Cilj je revizija zasnovana na dokazima (ne fuzzing ni blind scanning), pri čemu Burp ostaje izvor istine.

## Architecture

- **Burp MCP Server (BApp)** osluškuje na `127.0.0.1:9876` i izlaže presretnuti saobraćaj putem MCP.
- **MCP proxy JAR** povezuje stdio (klijentska strana) sa Burp-ovim MCP SSE endpointom.
- **Optional local reverse proxy** (Caddy) normalizuje header-e radi strožih provera MCP handshake-a.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Setup

### 1) Install Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store i proverite da li osluškuje na `127.0.0.1:9876`.

### 2) Extract the proxy JAR

U kartici MCP Server kliknite **Extract server proxy jar** i sačuvajte `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Podesite klijenta da koristi proxy JAR i Burp-ov SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Ne mogu da pokrenem Codex niti da izvršavam spoljne alate. Pošaljite sadržaj fajla src/AI/AI-Burp-MCP.md koji želite da prevedem, pa ću ga prevesti na srpski zadržavajući tačno istu markdown i html sintaksu. Ako umesto toga želite samo da navedem poznate MCP alate iz opšteg znanja, potvrdite i ja ću ih navesti.
```bash
codex
# inside Codex: /mcp
```
### 4) Ispravi strogu Origin/header validaciju sa Caddy (po potrebi)

Ako MCP handshake ne uspe zbog strogih `Origin` provera ili dodatnih headers, koristi lokalni reverse proxy da normalizuje headers (ovo odgovara zaobilaznom rešenju za problem stroge validacije Burp MCP-a).
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
Pokrenite proxy i client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Korišćenje različitih klijenata

### Codex CLI

- Konfigurišite `~/.codex/config.toml` kao gore.
- Pokrenite `codex`, zatim `/mcp` da proverite listu Burp alata.

### Gemini CLI

Repo **burp-mcp-agents** pruža skripte za pokretanje:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokalno)

Koristite priloženi pomoćnik za pokretanje i izaberite lokalni model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Paket promptova za pasivni pregled

Repo **burp-mcp-agents** sadrži prompt template-e za analizu Burp saobraćaja zasnovanu na dokazima:

- `passive_hunter.md`: široko pasivno otkrivanje ranjivosti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift i neslaganja u autentifikaciji.
- `auth_flow_mapper.md`: uporedi autentifikovane i neautentifikovane puteve.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect kandidati iz URL fetch parametara/lanaca redirekcija.
- `logic_flaw_hunter.md`: višestepeni logički propusti.
- `session_scope_hunter.md`: zloupotreba audience/scope tokena.
- `rate_limit_abuse_hunter.md`: propusti u throttling-u/ograničenju brzine i zloupotrebe.
- `report_writer.md`: izveštavanje fokusirano na dokaze.

## Opcionalno označavanje atribucije

Da biste označili Burp/LLM saobraćaj u logovima, dodajte prepravku zaglavlja (proxy ili Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Napomene o bezbednosti

- Prioritet dajte **lokalnim modelima** kada saobraćaj sadrži osetljive podatke.
- Delite samo minimum dokaza potrebnih za nalaz.
- Zadržite Burp kao izvor istine; koristite model za **analizu i izveštavanje**, a ne za skeniranje.

## Burp AI Agent (AI-asistirana trijaža + MCP alati)

**Burp AI Agent** je Burp ekstenzija koja povezuje lokalne/cloud LLMs sa pasivnom/aktivnom analizom (62 klase ranjivosti) i izlaže 53+ MCP alata tako da eksterni MCP klijenti mogu orkestrirati Burp. Istaknuto:

- **Trijaža iz kontekstnog menija**: snimite saobraćaj putem Proxy, otvorite **Proxy > HTTP History**, kliknite desnim tasterom na zahtev → **Extensions > Burp AI Agent > Analyze this request** da otvorite AI chat vezan za taj zahtev/odgovor.
- **Backends** (izbor po profilu):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates se automatski instaliraju pod `~/.burp-ai-agent/AGENTS/`; ubacite dodatne `*.md` fajlove tamo da dodate prilagođena ponašanja za analizu/skeniranje.
- **MCP server**: omogućite preko **Settings > MCP Server** da izložite Burp operacije bilo kom MCP klijentu (53+ alata). Claude Desktop se može usmeriti na server uređivanjem `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ili `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF maskiraju osetljive podatke iz zahteva pre slanja udaljenim modelima; prioritet dajte lokalnim backend-ovima kada rukujete tajnama.
- **Audit logging**: JSONL logovi sa per-entry SHA-256 heširanjem za integritet, radi otkrivanja neovlašćenih izmena i trasabilnosti AI/MCP akcija.
- **Build/load**: preuzmite release JAR ili build-ujte sa Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operativna upozorenja: cloud backends mogu eksfiltrirati session cookies/PII osim ako nije omogućen privacy mode; izlaganje MCP-a omogućava udaljnu orkestraciju Burp-a, zato ograničite pristup samo pouzdanim agentima i pratite audit log zaštićen integritetnim hash-om.

## Reference

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
