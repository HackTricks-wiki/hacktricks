# Burp MCP: pregled saobraćaja uz pomoć LLM-a

{{#include ../banners/hacktricks-training.md}}

## Pregled

Burp-ova ekstenzija **MCP Server** može da izloži presretnuti HTTP(S) saobraćaj MCP-capable LLM klijentima, kako bi mogli da **analiziraju stvarne zahteve/odgovore** radi pasivnog otkrivanja ranjivosti i izrade nacrta izveštaja. Cilj je pregled zasnovan na dokazima (bez fuzzing-a ili slepog skeniranja), pri čemu Burp ostaje izvor istine.

## Arhitektura

- **Burp MCP Server (BApp)** osluškuje na `127.0.0.1:9876` i izlaže presretnuti saobraćaj putem MCP-a.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** povezuje stdio (na strani klijenta) sa Burp-ovom MCP SSE krajnjom tačkom.
- **Opcioni lokalni reverse proxy** (Caddy) normalizuje zaglavlja za stroge provere MCP handshake-a.
- **Klijenti/backend-i**: Codex CLI (cloud), Gemini CLI (cloud) ili Ollama (lokalno).

## Podešavanje

### 1) Instalirajte Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store-a i proverite da osluškuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Izdvojite proxy JAR

Na kartici MCP Server kliknite na **Extract server proxy jar** i sačuvajte `mcp-proxy.jar`.

### 3) Konfigurišite MCP klijent (primer sa Codex-om)

Usmerite klijent na proxy JAR i Burp-ovu SSE krajnju tačku:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Zatim pokrenite Codex i izlistajte MCP alate:
```bash
codex
# inside Codex: /mcp
```
### 4) Popravite strogu Origin/header validaciju pomoću Caddy-ja (ako je potrebno)

Ako MCP handshake ne uspe zbog strogih `Origin` provera ili dodatnih header-a, koristite lokalni reverse proxy da normalizujete header-e (ovo odgovara workaround-u za problem sa strogom Burp MCP validacijom).<sup>[[1]](#references)[[3]](#references)</sup>
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
Pokrenite proxy i klijent:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Korišćenje različitih klijenata

### Codex CLI

- Konfigurišite `~/.codex/config.toml` kao što je navedeno iznad.
- Pokrenite `codex`, zatim `/mcp` da proverite listu Burp alata.

### Gemini CLI

Repozitorijum **burp-mcp-agents** pruža pomoćne launchere:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Koristite obezbeđeni launcher helper i izaberite lokalni model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Primeri lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Paket promptova za pasivni pregled

Repo **burp-mcp-agents** uključuje šablone promptova za analizu Burp saobraćaja zasnovanu na dokazima:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: široko otkrivanje pasivnih ranjivosti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift i nepodudarnosti u autorizaciji.
- `auth_flow_mapper.md`: poređenje autentifikovanih i neautentifikovanih putanja.
- `ssrf_redirect_hunter.md`: kandidati za SSRF/open-redirect na osnovu parametara za preuzimanje URL-ova i lanaca redirekcija.
- `logic_flaw_hunter.md`: logičke greške u više koraka.
- `session_scope_hunter.md`: zloupotreba audience/scope vrednosti tokena.
- `rate_limit_abuse_hunter.md`: propusti u throttling-u i sprečavanju zloupotrebe.
- `report_writer.md`: izveštavanje fokusirano na dokaze.

## Opciono označavanje atribucije

Da biste označili Burp/LLM saobraćaj u logovima, dodajte header rewrite (proxy ili Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Bezbednosne napomene

- Prednost dajte **lokalnim modelima** kada saobraćaj sadrži osetljive podatke.
- Delite samo minimalne dokaze potrebne za nalaz.
- Neka Burp bude izvor istine; koristite model za **analizu i izveštavanje**, a ne za skeniranje.

## Burp AI Agent (AI-potpomognuti triage + MCP alati)

**Burp AI Agent** je Burp ekstenzija koja povezuje lokalne/cloud LLM-ove sa pasivnom/aktivnom analizom (62 klase ranjivosti) i izlaže više od 53 MCP alata, tako da eksterni MCP klijenti mogu da orkestriraju Burp.<sup>[[5]](#references)</sup> Najvažnije funkcije:

- **Triage putem kontekstnog menija**: uhvatite saobraćaj preko Proxy-ja, otvorite **Proxy > HTTP History**, kliknite desnim tasterom na zahtev → **Extensions > Burp AI Agent > Analyze this request** da biste pokrenuli AI chat povezan sa tim zahtevom/odgovorom.
- **Backendi** (mogu se izabrati po profilu):
- Lokalni HTTP: **Ollama**, **LM Studio**.
- Udaljeni HTTP: endpoint kompatibilan sa **OpenAI** (base URL + naziv modela).
- Cloud CLI-jevi: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ili `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (prijavljivanje specifično za provider).
- **Agent profili**: prompt šabloni se automatski instaliraju u `~/.burp-ai-agent/AGENTS/`; dodajte dodatne `*.md` datoteke tamo da biste dodali prilagođena ponašanja za analizu/skeniranje.
- **MCP server**: omogućite ga preko **Settings > MCP Server** da biste izložili Burp operacije bilo kom MCP klijentu (više od 53 alata). Claude Desktop se može usmeriti na server uređivanjem datoteke `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ili `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrole privatnosti**: STRICT / BALANCED / OFF uklanjaju osetljive podatke iz zahteva pre njihovog slanja udaljenim modelima; prednost dajte lokalnim backendima pri radu sa tajnama.
- **Audit logging**: JSONL logovi sa SHA-256 hashiranjem integriteta za svaki unos, što obezbeđuje sledljivost AI/MCP radnji uz evidentiranje neovlašćenih izmena.
- **Build/load**: preuzmite release JAR ili ga izgradite pomoću Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operativne mere opreza: cloud backends mogu eksfiltrirati session cookies/PII osim ako je privacy mode nametnut; MCP exposure omogućava remote orchestration Burp-a, zato ograničite pristup trusted agents i nadzirite audit log sa integrity hash-om.

## Reference

- [1] [Integracija Burp MCP + Codex CLI i ispravka Caddy handshake-a](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem sa strict Origin/header validation u PortSwigger MCP serveru](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
