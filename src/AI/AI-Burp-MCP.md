# Burp MCP: pregled saobraćaja uz pomoć LLM-a

{{#include ../banners/hacktricks-training.md}}

## Pregled

Burp-ova ekstenzija **MCP Server** može da izloži presretnuti HTTP(S) saobraćaj MCP-capable LLM klijentima, kako bi mogli da **analiziraju stvarne zahteve/odgovore** radi otkrivanja ranjivosti i izrade nacrta izveštaja. Burp treba da ostane izvor konačne istine: koristite pasivnu analizu ili namerna ponavljanja sa promenom jedne promenljive, umesto slepog skeniranja.<sup>[[8]](#references)</sup>

## Arhitektura

- **Burp MCP Server (BApp)** podrazumevano osluškuje na `127.0.0.1:9876` i izlaže presretnuti saobraćaj putem MCP-a.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** povezuje stdio (na strani klijenta) sa Burp-ovom MCP SSE krajnjom tačkom.
- **Opcioni lokalni reverse proxy** (Caddy) normalizuje zaglavlja za stroge provere MCP handshake-a.
- **Klijenti/backend-i**: Codex CLI (cloud), Gemini CLI (cloud) ili Ollama (lokalno).

## Podešavanje

### 1) Instalirajte Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store-a i proverite da osluškuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Izdvojite proxy JAR

Na kartici MCP Server kliknite na **Extract server proxy jar** i sačuvajte `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Konfigurišite MCP klijent (primer sa Codex-om)

Usmerite klijent na proxy JAR i Burp-ovu direktnu SSE krajnju tačku. Upakovani proxy je stdio-to-SSE bridge; on ne zamenjuje Burp listener.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Ekvivalentna Codex komanda je:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Zatim pokrenite Codex i izlistajte MCP tools:
```bash
codex
# inside Codex: /mcp
```
### 4) Otklonite strogu Origin/header validaciju pomoću Caddy-ja (ako je potrebno)

Ako MCP handshake ne uspe zbog strogih `Origin` provera ili dodatnih headera, koristite lokalni reverse proxy za normalizaciju headera (ovo odgovara workaround-u za problem sa strogom validacijom Burp MCP-a).<sup>[[1]](#references)[[3]](#references)</sup>
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
Pokrenite proxy i klijent i promenite konfigurisani `--sse-url` na `http://127.0.0.1:19876` samo dok koristite ovaj Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Uparite stanje browsera sa dokazima iz proxy-ja (Playwright MCP)

Registrujte Playwright MCP tako da njegov browser koristi Burp proxy. Ovo omogućava agentu da poveže renderovano DOM/accessibility stanje sa tačnom HTTP istorijom koja ga je generisala.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Prilagodite adresu listenera, restartujte Codex i koristite `/mcp` da proverite obe integracije. Primer onemogućava greške browser sertifikata, tako da HTTPS interception ne bude blokiran Burp-ovim lokalno generisanim sertifikatom.<sup>[[6]](#references)[[8]](#references)</sup>

## Korišćenje različitih klijenata

### Codex CLI

- Konfigurišite `~/.codex/config.toml` kao što je navedeno iznad.
- Pokrenite `codex`, zatim `/mcp` da proverite listu Burp alata.

### Gemini CLI

Repo **burp-mcp-agents** obezbeđuje pomoćne launchere:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokalni)

Koristite priloženi pomoćni pokretač i izaberite lokalni model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Primeri lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay i validacija zasnovani na dokazima

Ne dozvolite agentu da verovatno objašnjenje ili međukorak odgovora tretira kao dokaz. Koristite Burp requests/responses i nezavisno posmatrano stanje browsera kako bi svaki test mogao da se opovrgne.<sup>[[8]](#references)</sup>

1. Sačuvajte početni par request/response i identifikujte tačnu komponentu kojom napadač upravlja.
2. Za poređenja autorizacije, nezavisno snimite isti workflow sa oba naloga pre menjanja identifikatora, kolačića ili tokena.
3. Pre replay-a neke izmene zabeležite hipotezu, lokaciju dokaza, očekivani signal i rezultat koji bi je opovrgao.
4. Menjajte jednu komponentu po jednu, sačuvajte dobijeni par i odvojeno označite direktna zapažanja od zaključivanja.
5. Pratite svaki kandidat kao `open`, `blocked`, `rejected` ili `confirmed`; ponovo ga razmatrajte samo kada novi dokaz promeni mehanizam ili preduslov.
6. Potvrdite kontrolu napadača, dostupnost, ponovljivost, zaobilaženje ograničenja, uticaj i konačno stanje aplikacije. Redirect ili uspešan poziv alata nisu dokaz ako se navodna promena stanja dešava downstream.

Detalje exploitation-a zadržite na relevantnoj technique stranici. Na primer, browser-message kandidati pripadaju stranici [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), dok ponašanje izbora ključa tokena pripada stranici [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Kompaktan zapis hipoteze sprečava paralelne agente da ponavljaju isti privlačni pravac:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Paket promptova za pasivni pregled

Repo **burp-mcp-agents** uključuje template-e promptova za analizu Burp saobraćaja zasnovanu na dokazima:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: široko pasivno otkrivanje ranjivosti.
- `idor_hunter.md`: IDOR/BOLA drift objekata/tenant-a i nepodudarnosti autentikacije.
- `auth_flow_mapper.md`: poređenje autentikovanih i neautentikovanih putanja.
- `ssrf_redirect_hunter.md`: kandidati za SSRF/open-redirect na osnovu URL fetch parametara/redirect chain-ova.
- `logic_flaw_hunter.md`: višekoračne logičke greške.
- `session_scope_hunter.md`: zloupotreba token audience/scope.
- `rate_limit_abuse_hunter.md`: praznine u throttling-u/zaštiti od abuse-a.
- `report_writer.md`: izveštavanje usmereno na dokaze.

## Opciono označavanje attribution-a

Da biste označili Burp/LLM saobraćaj u logovima, dodajte header rewrite (proxy ili Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Bezbednosne napomene

- Prednost dajte **lokalnim modelima** kada saobraćaj sadrži osetljive podatke.
- Delite samo minimum dokaza potrebnih za nalaz.
- Burp neka bude izvor istine; koristite model za **analizu i izveštavanje**, a ne za skeniranje.

## Burp AI Agent (AI-potpomognuta trijaža + MCP alati)

**Burp AI Agent** je Burp ekstenzija koja povezuje lokalne/cloud LLM-ove sa pasivnom/aktivnom analizom (62 klase ranjivosti) i izlaže više od 53 MCP alata kako bi eksterni MCP klijenti mogli da orkestriraju Burp.<sup>[[5]](#references)</sup> Najvažnije funkcije:

- **Trijaža iz kontekstualnog menija**: uhvatite saobraćaj preko Proxy-ja, otvorite **Proxy > HTTP History**, kliknite desnim tasterom na zahtev → **Extensions > Burp AI Agent > Analyze this request** da biste pokrenuli AI chat povezan sa tim zahtevom/odgovorom.
- **Backends** (biraju se po profilu):
- Lokalni HTTP: **Ollama**, **LM Studio**.
- Udaljeni HTTP: endpoint kompatibilan sa **OpenAI** (osnovni URL + naziv modela).
- Cloud CLI-ji: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ili `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (prijavljivanje specifično za provajdera).
- **Agent profili**: templates upita se automatski instaliraju u `~/.burp-ai-agent/AGENTS/`; dodajte dodatne `*.md` datoteke da biste uključili prilagođena ponašanja za analizu/skeniranje.
- **MCP server**: omogućite ga preko **Settings > MCP Server** da biste Burp operacije izložili bilo kom MCP klijentu (više od 53 alata). Claude Desktop može da se usmeri na server izmenom datoteke `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ili `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrole privatnosti**: STRICT / BALANCED / OFF uklanjaju osetljive podatke iz zahteva pre slanja udaljenim modelima; koristite lokalne backends kada obrađujete tajne.
- **Audit logging**: JSONL logovi sa SHA-256 hashiranjem integriteta za svaki unos, radi sledljivosti AI/MCP akcija koja omogućava uočavanje neovlašćenih izmena.
- **Build/load**: preuzmite release JAR ili ga izgradite pomoću Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operativne mere opreza: cloud backend-i mogu eksfiltrirati session cookies/PII osim ako se ne nametne privacy mode; MCP izloženost omogućava remote orchestration Burp-a, zato ograničite pristup na pouzdane agents i nadgledajte audit log sa hash-om integriteta.

## References

- [1] [Burp MCP + Codex CLI integracija i Caddy handshake popravka](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem sa strogom Origin/header validacijom PortSwigger MCP servera](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Kako koristiti Codex za Bug Bounty istraživanje: istražujte široko, validirajte rigorozno](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
