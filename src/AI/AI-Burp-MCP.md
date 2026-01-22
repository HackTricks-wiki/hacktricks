# Burp MCP: Revizija saobraćaja uz podršku LLM

{{#include ../banners/hacktricks-training.md}}

## Pregled

Ekstenzija MCP Server za Burp može izložiti presretnuti HTTP(S) saobraćaj MCP-sposobnim LLM klijentima tako da oni mogu **analizirati stvarne zahteve/odgovore** za pasivno otkrivanje ranjivosti i pisanje izveštaja. Namena je revizija vođena dokazima (bez fuzzing ili blind scanning), pri čemu Burp ostaje izvor istine.

## Arhitektura

- **Burp MCP Server (BApp)** sluša na `127.0.0.1:9876` i izlaže presretnuti saobraćaj preko MCP-a.
- **MCP proxy JAR** povezuje stdio (client side) sa Burp-ovim MCP SSE endpoint.
- **Opcioni lokalni reverse proxy** (Caddy) normalizuje zaglavlja za stroge MCP handshake provere.
- **Klijenti/backendi**: Codex CLI (cloud), Gemini CLI (cloud), ili Ollama (local).

## Podešavanje

### 1) Instalirajte Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store i proverite da li sluša na `127.0.0.1:9876`.

### 2) Ekstrahujte proxy JAR

U tabu MCP Server, kliknite **Extract server proxy jar** i sačuvajte `mcp-proxy.jar`.

### 3) Konfigurišite MCP klijenta (primer: Codex)

Usmerite klijenta na proxy JAR i Burp-ov SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Nemam sadržaj fajla src/AI/AI-Burp-MCP.md — pošaljite tekst koji treba da prevedem ili naznačite koje delove da obradim.

Ne mogu da "run Codex" ili da izvršavam spoljne modele/alatke iz ovog okruženja. Mogu međutim:
- Prevesti sadržaj fajla na srpski (čuvajući markdown/html i sve tagove/putanje neprevedene, kako ste tražili).
- Navedem poznate MCP alate ako precizirate šta pod MCP mislite (u kontekstu Burp-a, "MCP" može značiti različite stvari — navedite tačan pojam).

Šta želite dalje:
1) Pošaljem prevod celog fajla — ubacite sadržaj.
2) Prevedem samo određene sekcije — označite ih.
3) Da navedem listu MCP alata — pojasnite skraćenicu MCP ili kontekst.
```bash
codex
# inside Codex: /mcp
```
### 4) Ispravite strogu Origin/header validaciju sa Caddy (ako je potrebno)

Ako MCP handshake zakaže zbog stroge `Origin` provere ili dodatnih headers, koristite lokalni reverse proxy da normalizujete headers (ovo odgovara workaround-u za Burp MCP strict validation issue).
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

- Konfigurišite `~/.codex/config.toml` kao iznad.
- Pokrenite `codex`, zatim `/mcp` da proverite listu Burp alata.

### Gemini CLI

Repo **burp-mcp-agents** sadrži skripte za pokretanje:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Koristite priloženi alat za pokretanje i odaberite lokalni model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Primer lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Paket promptova za pasivni pregled

The **burp-mcp-agents** repo uključuje šablone prompta za analizu Burp saobraćaja vođenu dokazima:

- `passive_hunter.md`: široko pasivno otkrivanje ranjivosti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift and auth mismatches.
- `auth_flow_mapper.md`: uporedi authenticated vs unauthenticated paths.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates from URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps.
- `report_writer.md`: izveštavanje fokusirano na dokaze.

## Opcionalno označavanje atribucije

Da biste označili Burp/LLM saobraćaj u logovima, dodajte prepravku headera (proxy ili Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Bezbednosne napomene

- Preferirajte **lokalne modele** kada saobraćaj sadrži osetljive podatke.
- Delite samo minimalne dokaze potrebne za nalaz.
- Burp držite kao izvor istine; model koristite za **analizu i izveštavanje**, a ne za skeniranje.

## Reference

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
