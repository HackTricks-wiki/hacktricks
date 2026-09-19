# Burp MCP: LLM-potpomognuti pregled saobraćaja

{{#include ../banners/hacktricks-training.md}}

## Pregled

Burp-ova ekstenzija **MCP Server** može da izloži presretnuti HTTP(S) saobraćaj MCP-capable LLM klijentima, kako bi mogli da **analiziraju stvarne zahteve/odgovore** radi otkrivanja ranjivosti i izrade nacrta izveštaja. Burp treba da ostane source of truth: koristite pasivnu analizu ili namerna ponavljanja sa jednom promenljivom, umesto slepog skeniranja.<sup>[[8]](#references)</sup>

## Arhitektura

- **Burp MCP Server (BApp)** podrazumevano sluša na `127.0.0.1:9876` i izlaže presretnuti saobraćaj putem MCP-a.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** povezuje stdio (na strani klijenta) sa Burp-ovim MCP SSE endpointom.
- **OpcionI lokalni reverse proxy** (Caddy) normalizuje headere radi provera strogog MCP handshake-a.
- **Klijenti/backend-i**: Codex CLI (cloud), Gemini CLI (cloud) ili Ollama (lokalno).

## Podešavanje

### 1) Instalirajte Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store-a i proverite da li sluša na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Izdvojite proxy JAR

Na kartici MCP Server kliknite na **Extract server proxy jar** i sačuvajte `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Konfigurišite MCP klijenta (primer sa Codex-om)

Usmerite klijenta na proxy JAR i Burp-ov direktni SSE endpoint. Upakovani proxy je stdio-to-SSE bridge; ne zamenjuje Burp listener.<sup>[[7]](#references)</sup>
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
Zatim pokrenite Codex i izlistajte MCP alate:
```bash
codex
# inside Codex: /mcp
```
### 4) Ispravi strogu validaciju Origin/header-a pomoću Caddy-ja (ako je potrebno)

Ako MCP handshake ne uspe zbog strogih `Origin` provera ili dodatnih header-a, koristi lokalni reverse proxy za normalizaciju header-a (ovo odgovara workaround-u za problem sa strogom validacijom Burp MCP-a).<sup>[[1]](#references)[[3]](#references)</sup>
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
Pokrenite proxy i client i promenite podešeni `--sse-url` na `http://127.0.0.1:19876` samo dok koristite ovaj Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Uparite stanje browsera sa proxy dokazima (Playwright MCP)

Registrujte Playwright MCP tako da njegov browser koristi Burp proxy. To agentu omogućava da poveže renderovano DOM/accessibility stanje sa tačnom HTTP istorijom koja ga je proizvela.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Prilagodite adresu listenera, restartujte Codex i koristite `/mcp` da proverite obe integracije. Primer onemogućava greške browsera pri proveri sertifikata, tako da HTTPS interception ne bude blokiran Burp-ovim lokalno generisanim sertifikatom.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatizacija browsera s podrškom za proxy (OpenBurp)

Burp MCP veza i putanja browsera kroz koji se saobraćaj presreće predstavljaju odvojene tokove podataka. MCP servis izlaže Burp alate na `127.0.0.1:9876`, dok namenski Chromium instanc šalje svoj HTTP(S) saobraćaj kroz Burp-ov proxy na `127.0.0.1:8080`. Zahtevi generisani direktno MCP alatom zato mogu izostati iz **Proxy > HTTP history**; koristite browser sa proxy podrškom kada zahtev/odgovor mora biti vidljiv, izmenjiv ili sačuvan kao dokaz.<sup>[[2]](#references)[[9]](#references)</sup>

Klijent sa SSE podrškom može direktno registrovati Burp. Klijent koji podržava samo stdio može umesto toga pokrenuti PortSwigger-ov proxy JAR. U oba slučaja registrujte drugi MCP za kontrolu browsera i usmerite ga na Burp-ov ugrađeni Chromium (`BURP_CHROMIUM` je lokalna putanja do izvršne datoteke):<sup>[[9]](#references)</sup>
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
TLS-bypass zastavica prihvata sertifikate koje generiše interception proxy, dok `--isolated` sprečava da assessment ponovo koristi uobičajeni profil browsera operatera. Izolacija štiti stanje profila, ali **nije security sandbox**: controller i dalje može da pristupi autentifikovanim sesijama otvorenim u tom testnom browseru, a Burp MCP može da izloži osetljive zahteve, odgovore i konfiguraciju.<sup>[[9]](#references)</sup>

Nezavisno testirajte SSE listener pre otklanjanja problema sa client bridge-om:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Ispravan listener vraća `Content-Type: text/event-stream`. Timeout nakon zaglavlja je očekivan jer SSE stream ostaje otvoren za buduće događaje. Ako client i dalje ne radi, proverite konfigurisanu rutu extension-a: PortSwigger navodi da endpoint može biti root putanja ili `/sse`, u zavisnosti od client-a i konfiguracije extension-a.<sup>[[9]](#references)[[7]](#references)</sup>

## Korišćenje različitih klijenata

### Codex CLI

- Konfigurišite `~/.codex/config.toml` kao što je navedeno iznad.
- Pokrenite `codex`, zatim `/mcp` da biste proverili listu Burp tools.

### Gemini CLI

Repo **burp-mcp-agents** pruža pomoćne launcher-e:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Koristi obezbeđeni launcher helper i izaberi lokalni model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Primeri lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Reprodukcija i validacija zasnovane na dokazima

Ne dozvolite agentu da verodostojno objašnjenje ili međurezultat tretira kao dokaz. Koristite Burp zahteve/odgovore i nezavisno posmatrano stanje browsera kako bi svaki test mogao da se opovrgne.<sup>[[8]](#references)</sup>

1. Sačuvajte par osnovnog zahteva/odgovora i identifikujte tačnu komponentu pod kontrolom napadača.
2. Za poređenja autorizacije, nezavisno snimite isti workflow pod oba naloga pre menjanja identifikatora, cookies-a ili tokena.
3. Pre replay-a mutacije zabeležite hipotezu, lokaciju dokaza, očekivani signal i rezultat koji bi je opovrgao.
4. Menjajte jednu komponentu odjednom, sačuvajte dobijeni par i jasno odvojite direktna zapažanja od zaključivanja.
5. Pratite svaki kandidat kao `open`, `blocked`, `rejected` ili `confirmed`; ponovo ga razmatrajte samo kada novi dokaz promeni mehanizam ili preduslov.
6. Potvrdite kontrolu napadača, dostupnost, ponovljivost, zaobilaženje ograničenja, uticaj i konačno stanje aplikacije. Redirect ili uspešan poziv alata nisu dokaz ako se navodna promena stanja dešava downstream.

Detalje exploitation-a zadržite na relevantnoj technique stranici. Na primer, browser-message kandidati pripadaju stranici [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), dok ponašanje izbora ključa tokena pripada stranici [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Sažet zapis hipoteze sprečava paralelne agente da ponavljaju istu privlačnu granu:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Paket promptova za pasivni pregled

Repo **burp-mcp-agents** uključuje šablone promptova za analizu Burp saobraćaja zasnovanu na dokazima:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: široko otkrivanje pasivnih ranjivosti.
- `idor_hunter.md`: IDOR/BOLA, pomeranje objekata/tenant-a i nepodudarnosti u autentikaciji.
- `auth_flow_mapper.md`: poređenje autentifikovanih i neautentifikovanih putanja.
- `ssrf_redirect_hunter.md`: kandidati za SSRF/open-redirect iz URL fetch parametara/lanaca preusmeravanja.
- `logic_flaw_hunter.md`: višekoračni logički propusti.
- `session_scope_hunter.md`: zloupotreba audience/scope vrednosti tokena.
- `rate_limit_abuse_hunter.md`: propusti u throttling-u i zaštiti od zloupotrebe.
- `report_writer.md`: izveštavanje usmereno na dokaze.

## Opciono označavanje atribucije

Da biste označili Burp/LLM saobraćaj u logovima, dodajte prepisivanje header-a (proxy ili Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Bezbednosne napomene

- Dajte prednost **lokalnim modelima** kada saobraćaj sadrži osetljive podatke.
- Delite samo minimum dokaza potrebnih za nalaz.
- Neka Burp bude izvor istine; koristite model za **analizu i izveštavanje**, a ne za skeniranje.

## Burp AI Agent (AI-potpomognuta trijaža + MCP alati)

**Burp AI Agent** je Burp ekstenzija koja povezuje lokalne/cloud LLM-ove sa pasivnom/aktivnom analizom (62 klase ranjivosti) i izlaže više od 53 MCP alata, tako da eksterni MCP klijenti mogu da orkestriraju Burp.<sup>[[5]](#references)</sup> Najvažnije funkcije:

- **Trijaža iz kontekstnog menija**: uhvatite saobraćaj preko Proxy-ja, otvorite **Proxy > HTTP History**, kliknite desnim tasterom na zahtev → **Extensions > Burp AI Agent > Analyze this request** da biste pokrenuli AI chat povezan sa tim zahtevom/odgovorom.
- **Backend-i** (biraju se po profilu):
- Lokalni HTTP: **Ollama**, **LM Studio**.
- Udaljeni HTTP: endpoint kompatibilan sa **OpenAI**-jem (osnovni URL + naziv modela).
- Cloud CLI-jevi: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ili `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (prijava specifična za provajdera).
- **Profili agenata**: šabloni promptova se automatski instaliraju u `~/.burp-ai-agent/AGENTS/`; dodajte dodatne `*.md` datoteke tamo da biste dodali prilagođena ponašanja za analizu/skeniranje.
- **MCP server**: omogućite ga preko **Settings > MCP Server** da biste izložili Burp operacije bilo kom MCP klijentu (više od 53 alata). Claude Desktop se može usmeriti na server uređivanjem datoteke `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ili `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrole privatnosti**: STRICT / BALANCED / OFF uklanjaju osetljive podatke iz zahteva pre slanja udaljenim modelima; dajte prednost lokalnim backend-ima pri rukovanju tajnama.
- **Evidentiranje revizije**: JSONL dnevnici sa SHA-256 heširanjem integriteta za svaki unos, što obezbeđuje sledljivost AI/MCP radnji uz dokazivanje naknadnog menjanja.
- **Build/load**: preuzmite release JAR ili ga izgradite pomoću Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operativne mere opreza: cloud backend-i mogu eksfiltrirati session cookies/PII osim ako nije nametnut privacy mode; MCP exposure omogućava remote orchestration Burp-a, zato ograničite pristup na pouzdane agente i nadgledajte integrity-hashed audit log.

## References

- [1] [Burp MCP + Codex CLI integracija i ispravka Caddy handshake-a](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem sa strogom Origin/header validacijom PortSwigger MCP servera](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Kako koristiti Codex za Bug Bounty istraživanje: istražujte široko, rigorozno validirajte](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp Suite orchestration za Claude Code i Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
