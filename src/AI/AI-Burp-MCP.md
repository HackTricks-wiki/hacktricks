# Burp MCP: Traffic review με υποβοήθηση LLM

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Το extension **MCP Server** του Burp μπορεί να εκθέσει intercepted HTTP(S) traffic σε MCP-capable LLM clients, ώστε να μπορούν να κάνουν **reason over real requests/responses** για passive vulnerability discovery και σύνταξη αναφορών. Στόχος είναι το evidence-driven review (χωρίς fuzzing ή blind scanning), με το Burp ως source of truth.

## Αρχιτεκτονική

- Το **Burp MCP Server (BApp)** ακούει στο `127.0.0.1:9876` και εκθέτει intercepted traffic μέσω MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- Το **MCP proxy JAR** γεφυρώνει το stdio (client side) με το Burp MCP SSE endpoint.
- **Προαιρετικό local reverse proxy** (Caddy) κανονικοποιεί headers για strict MCP handshake checks.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud) ή Ollama (local).

## Εγκατάσταση

### 1) Εγκατάσταση του Burp MCP Server

Εγκαταστήστε το **MCP Server** από το Burp BApp Store και επαληθεύστε ότι ακούει στο `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Εξαγωγή του proxy JAR

Στην καρτέλα MCP Server, κάντε κλικ στο **Extract server proxy jar** και αποθηκεύστε το `mcp-proxy.jar`.

### 3) Ρύθμιση ενός MCP client (παράδειγμα με Codex)

Κατευθύνετε τον client στο proxy JAR και στο Burp SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Στη συνέχεια εκτέλεσε το Codex και απαρίθμησε τα εργαλεία MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Διόρθωση του strict validation των Origin/headers με Caddy (αν χρειάζεται)

Αν το MCP handshake αποτύχει λόγω αυστηρών ελέγχων του `Origin` ή επιπλέον headers, χρησιμοποιήστε ένα local reverse proxy για την κανονικοποίηση των headers (αυτό αντιστοιχεί στο workaround για το strict validation issue του Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Εκκινήστε το proxy και το client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Χρήση διαφορετικών clients

### Codex CLI

- Ρυθμίστε το `~/.codex/config.toml` όπως παραπάνω.
- Εκτελέστε το `codex` και, στη συνέχεια, το `/mcp` για να επαληθεύσετε τη λίστα εργαλείων του Burp.

### Gemini CLI

Το repo **burp-mcp-agents** παρέχει βοηθητικά launchers:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (τοπικό)

Χρησιμοποίησε το παρεχόμενο launcher helper και επίλεξε ένα τοπικό model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Παραδείγματα local models και κατά προσέγγιση ανάγκες σε VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack για passive review

Το repo **burp-mcp-agents** περιλαμβάνει prompt templates για evidence-driven analysis του Burp traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ευρεία passive αναζήτηση vulnerabilities.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift και auth mismatches.
- `auth_flow_mapper.md`: σύγκριση authenticated και unauthenticated paths.
- `ssrf_redirect_hunter.md`: υποψήφια SSRF/open-redirect από URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: misuse του token audience/scope.
- `rate_limit_abuse_hunter.md`: gaps σε throttling/abuse.
- `report_writer.md`: evidence-focused reporting.

## Optional attribution tagging

Για να κάνετε tag το Burp/LLM traffic στα logs, προσθέστε ένα header rewrite (proxy ή Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Σημειώσεις ασφάλειας

- Προτιμήστε **local models** όταν η κίνηση περιέχει ευαίσθητα δεδομένα.
- Κοινοποιείτε μόνο τα ελάχιστα απαραίτητα evidence για ένα finding.
- Διατηρείτε το Burp ως source of truth· χρησιμοποιείτε το model για **analysis and reporting**, όχι για scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

Το **Burp AI Agent** είναι ένα Burp extension που συνδυάζει local/cloud LLMs με passive/active analysis (62 vulnerability classes) και εκθέτει 53+ MCP tools, ώστε εξωτερικοί MCP clients να μπορούν να ενορχηστρώνουν το Burp.<sup>[[5]](#references)</sup> Βασικά χαρακτηριστικά:

- **Context-menu triage**: καταγράψτε traffic μέσω Proxy, ανοίξτε το **Proxy > HTTP History**, κάντε δεξί κλικ σε ένα request → **Extensions > Burp AI Agent > Analyze this request** για να ξεκινήσετε ένα AI chat συνδεδεμένο με το συγκεκριμένο request/response.
- **Backends** (επιλέξιμα ανά profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint συμβατό με **OpenAI** (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ή `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates που εγκαθίστανται αυτόματα στο `~/.burp-ai-agent/AGENTS/`· τοποθετήστε εκεί επιπλέον αρχεία `*.md` για να προσθέσετε custom analysis/scanning behaviors.
- **MCP server**: ενεργοποιήστε το μέσω **Settings > MCP Server** για να εκθέσετε λειτουργίες του Burp σε οποιοδήποτε MCP client (53+ tools). Το Claude Desktop μπορεί να συνδεθεί στον server μέσω επεξεργασίας του `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ή του `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: τα STRICT / BALANCED / OFF redacts sensitive request data πριν από την αποστολή του σε remote models· προτιμάτε local backends όταν διαχειρίζεστε secrets.
- **Audit logging**: JSONL logs με SHA-256 integrity hashing ανά entry για tamper-evident traceability των AI/MCP actions.
- **Build/load**: κατεβάστε το release JAR ή κάντε build με Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Λειτουργικές προειδοποιήσεις: τα cloud backends ενδέχεται να κάνουν exfiltrate session cookies/PII, εκτός εάν επιβάλλεται privacy mode· η έκθεση του MCP παρέχει remote orchestration του Burp, επομένως περιορίστε την πρόσβαση σε trusted agents και παρακολουθείτε το audit log με integrity hash.

## Αναφορές

- [1] [Ενσωμάτωση Burp MCP + Codex CLI και επιδιόρθωση handshake στο Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Ζήτημα αυστηρής επικύρωσης Origin/header στον PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
