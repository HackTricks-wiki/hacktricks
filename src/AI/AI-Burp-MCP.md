# Burp MCP: LLM-ondersteunde verkeershersiening

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Burp se **MCP Server**-uitbreiding kan onderskepte HTTP(S)-verkeer aan MCP-bekwame LLM-kliënte blootstel, sodat hulle oor **werklike versoeke/antwoorde** kan redeneer vir kwesbaarheidsontdekking en die opstel van verslae. Hou Burp as die bron van waarheid: gebruik passiewe ontleding of doelbewuste herhalings met een veranderlike, eerder as blinde skandering.<sup>[[8]](#references)</sup>

## Argitektuur

- **Burp MCP Server (BApp)** luister by verstek op `127.0.0.1:9876` en stel onderskepte verkeer via MCP bloot.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** koppel stdio (aan die kliëntkant) aan Burp se MCP SSE-endpunt.
- **Opsionele plaaslike reverse proxy** (Caddy) normaliseer headers vir streng MCP-handdrukkontroles.
- **Kliënte/backends**: Codex CLI (cloud), Gemini CLI (cloud), of Ollama (plaaslik).

## Opstelling

### 1) Installeer Burp MCP Server

Installeer **MCP Server** vanaf die Burp BApp Store en verifieer dat dit op `127.0.0.1:9876` luister.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Ekstraheer die proxy JAR

Klik in die MCP Server-oortjie op **Extract server proxy jar** en stoor `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Stel 'n MCP-kliënt op (Codex-voorbeeld)

Wys die kliënt na die proxy JAR en Burp se direkte SSE-endpoint. Die verpakte proxy is 'n stdio-na-SSE-bridge; dit vervang nie die Burp-listener nie.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Die ekwivalente Codex-opdrag is:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Voer dan Codex uit en lys MCP tools:
```bash
codex
# inside Codex: /mcp
```
### 4) Stel streng Origin/header-validasie met Caddy reg (indien nodig)

Indien die MCP-handshake weens streng `Origin`-checks of ekstra headers misluk, gebruik ’n plaaslike reverse proxy om headers te normaliseer (dit stem ooreen met die workaround vir die Burp MCP-strengvalidasieprobleem).<sup>[[1]](#references)[[3]](#references)</sup>
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
Begin die proxy en client, en verander die gekonfigureerde `--sse-url` na `http://127.0.0.1:19876` slegs terwyl hierdie Caddy listener gebruik word:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Koppel blaaierstatus aan proxy-bewyse (Playwright MCP)

Registreer Playwright MCP sodat sy blaaier Burp se proxy gebruik. Dit stel die agent in staat om die weergegee DOM-/toeganklikheidstatus te korreleer met die presiese HTTP-geskiedenis wat dit voortgebring het.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Pas die listener-adres aan, herbegin Codex en gebruik `/mcp` om albei integrasies te verifieer. Die voorbeeld deaktiveer blaaier-sertifikaatfoute sodat HTTPS-interception nie deur Burp se plaaslik gegenereerde sertifikaat geblokkeer word nie.<sup>[[6]](#references)[[8]](#references)</sup>

## Using different clients

### Codex CLI

- Stel `~/.codex/config.toml` soos hierbo op.
- Begin `codex`, en gebruik dan `/mcp` om die lys van Burp tools te verifieer.

### Gemini CLI

Die **burp-mcp-agents**-repo verskaf launcher-hulpmiddels:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (plaaslik)

Gebruik die verskafde launcher-helper en kies ’n plaaslike model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Voorbeeld van plaaslike models en benaderde VRAM-behoeftes:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Bewysgedrewe herhaling en validering

Moenie toelaat dat die agent ’n aanneemlike verduideliking of ’n tussentydse reaksie as bewys beskou nie. Gebruik Burp-versoeke/-antwoorde en onafhanklik waargenome blaaierstatus om elke toets falsifiseerbaar te maak.<sup>[[8]](#references)</sup>

1. Stoor ’n basislyn-versoek/-antwoord-paar en identifiseer die presiese komponent wat deur die aanvaller beheer word.
2. Vir magtigingsvergelykings, neem dieselfde workflow onafhanklik onder albei accounts vas voordat identifiseerders, cookies of tokens gewysig word.
3. Teken die hipotese, bewysposisie, verwagte sein en die resultaat wat dit sou weerlê aan voordat ’n mutasie herhaal word.
4. Wysig een komponent op ’n slag, bewaar die resulterende paar en merk direkte waarnemings apart van afleidings.
5. Volg elke kandidaat as `open`, `blocked`, `rejected` of `confirmed`; hersien dit slegs wanneer nuwe bewyse die meganisme of ’n voorvereiste verander.
6. Bevestig aanvallerbeheer, bereikbaarheid, herhaalbaarheid, omseiling van beperkings, impak en die finale application state. ’n Redirect of suksesvolle tool call is nie bewys nie indien die beweerde statusverandering stroomaf plaasvind.

Hou die exploitation-besonderhede op die relevante technique page. Browser-message-kandidate hoort byvoorbeeld in [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), terwyl token key-selection-gedrag in [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) hoort.<sup>[[8]](#references)</sup>

’n Kompakte hipoteseverslag voorkom dat parallelle agents dieselfde aantreklike vertakking herhaal:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt pack vir passiewe review

Die **burp-mcp-agents** repo bevat prompt templates vir bewysgedrewe ontleding van Burp-verkeer:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breë passiewe vulnerability-surfacing.
- `idor_hunter.md`: IDOR/BOLA/object/tenant-drift en auth-mismatches.
- `auth_flow_mapper.md`: vergelyk geauthentiseerde en ongeauthentiseerde paths.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect-kandidate vanuit URL-fetch-params/redirect chains.
- `logic_flaw_hunter.md`: multi-stap logic flaws.
- `session_scope_hunter.md`: token audience/scope-misbruik.
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps.
- `report_writer.md`: evidence-gefokusde reporting.

## Opsionele attribution tagging

Om Burp/LLM-verkeer in logs te tag, voeg 'n header rewrite (proxy of Burp Match/Replace) by:<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Veiligheidsnotas

- Verkies **local models** wanneer verkeer sensitiewe data bevat.
- Deel slegs die minimum bewyse wat vir ’n bevinding nodig is.
- Hou Burp as die bron van waarheid; gebruik die model vir **analysis and reporting**, nie vir scanning nie.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** is ’n Burp-uitbreiding wat plaaslike/cloud LLMs met passiewe/aktiewe analysis (62 vulnerability classes) koppel en 53+ MCP tools beskikbaar stel sodat eksterne MCP-kliënte Burp kan orkestreer.<sup>[[5]](#references)</sup> Hoogtepunte:

- **Context-menu triage**: vang verkeer vas via Proxy, open **Proxy > HTTP History**, klik met die regtermuisknoppie op ’n request → **Extensions > Burp AI Agent > Analyze this request** om ’n AI-chat te begin wat aan daardie request/response gekoppel is.
- **Backends** (kiesbaar per profiel):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` of `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates word outomaties onder `~/.burp-ai-agent/AGENTS/` geïnstalleer; plaas ekstra `*.md`-lêers daar om custom analysis/scanning-gedrag by te voeg.
- **MCP server**: aktiveer via **Settings > MCP Server** om Burp-bewerkings aan enige MCP-kliënt beskikbaar te stel (53+ tools). Claude Desktop kan na die server gewys word deur `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) of `%APPDATA%\Claude\claude_desktop_config.json` (Windows) te wysig.
- **Privacy controls**: STRICT / BALANCED / OFF redigeer sensitiewe request-data voordat dit na remote models gestuur word; verkies plaaslike backends wanneer secrets hanteer word.
- **Audit logging**: JSONL-logs met SHA-256-integriteitshashing per inskrywing vir peuterduidelike naspeurbaarheid van AI/MCP-aksies.
- **Build/load**: laai die release JAR af of bou met Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operasionele waarskuwings: cloud backends kan sessiekoekies/PII exfiltrate tensy privaatheidsmodus afgedwing word; MCP-blootstelling verleen remote orchestrering van Burp, dus beperk toegang tot vertroude agents en monitor die integriteitshashed ouditlog.

## References

- [1] [Burp MCP + Codex CLI-integrasie en Caddy-handshake-regstelling](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server-streng Origin/header-valideringskwessie](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Hoe om Codex vir Bug Bounty-navorsing te gebruik: verken breed, valideer streng](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
