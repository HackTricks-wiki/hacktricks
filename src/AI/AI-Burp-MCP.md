# Burp MCP: Ανασκόπηση κυκλοφορίας με υποβοήθηση LLM

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Η επέκταση **MCP Server** του Burp μπορεί να εκθέσει υποκλεπτόμενη κυκλοφορία HTTP(S) σε MCP-capable LLM clients ώστε να μπορούν να **reason over real requests/responses** για παθητική ανακάλυψη ευπαθειών και σύνταξη αναφορών. Ο σκοπός είναι μια ανασκόπηση καθοδηγούμενη από αποδείξεις (no fuzzing or blind scanning), διατηρώντας το Burp ως την πηγή αλήθειας.

## Αρχιτεκτονική

- **Burp MCP Server (BApp)** ακούει στο `127.0.0.1:9876` και εκθέτει την υποκλεπτόμενη κυκλοφορία μέσω MCP.
- **MCP proxy JAR** γεφυρώνει το stdio (client side) με το Burp's MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) κανονικοποιεί headers για αυστηρούς ελέγχους MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Ρύθμιση

### 1) Εγκατάσταση Burp MCP Server

Εγκαταστήστε το **MCP Server** από το Burp BApp Store και επιβεβαιώστε ότι ακούει στο `127.0.0.1:9876`.

### 2) Εξαγωγή του proxy JAR

Στην καρτέλα MCP Server, κάντε κλικ στο **Extract server proxy jar** και αποθηκεύστε το `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Point the client to the proxy JAR and Burp's SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Δεν βλέπω το περιεχόμενο του αρχείου src/AI/AI-Burp-MCP.md. Στείλε μου το κείμενο ή επικόλλησέ το εδώ.

Επίσης διευκρίνισε τι εννοείς με "run Codex": να χρησιμοποιήσω OpenAI Codex για εξαγωγή/ανάλυση; Να τρέξω κάποιο τοπικό script; Θέλεις:
- μόνο τη μετάφραση του αρχείου στα Ελληνικά και μετά τη λίστα MCP tools, ή
- να εξάγω πρώτα τη λίστα MCP tools με Codex και μετά να μεταφράσω το υπόλοιπο;

Πες μου ποια επιλογή προτιμάς και στείλε το περιεχόμενο του αρχείου.
```bash
codex
# inside Codex: /mcp
```
### 4) Διόρθωση αυστηρού ελέγχου Origin/header με Caddy (εάν χρειάζεται)

Εάν το MCP handshake αποτύχει λόγω αυστηρών ελέγχων του `Origin` ή λόγω επιπλέον headers, χρησιμοποιήστε έναν τοπικό reverse proxy για να κανονικοποιήσετε τα headers (αυτό αντιστοιχεί στην παράκαμψη για το πρόβλημα αυστηρής επαλήθευσης του Burp MCP).
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
Ξεκινήστε τον proxy και τον client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Χρήση διαφορετικών πελατών

### Codex CLI

- Διαμορφώστε `~/.codex/config.toml` όπως παραπάνω.
- Εκτελέστε `codex`, στη συνέχεια `/mcp` για να επαληθεύσετε τη λίστα εργαλείων Burp.

### Gemini CLI

Το repo **burp-mcp-agents** παρέχει βοηθητικά προγράμματα εκκίνησης:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (τοπικό)

Χρησιμοποιήστε τον παρεχόμενο βοηθό εκκίνησης και επιλέξτε ένα τοπικό μοντέλο:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Παραδείγματα τοπικών μοντέλων και περίπου απαιτήσεις VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Πακέτο prompt για παθητική ανασκόπηση

Το αποθετήριο **burp-mcp-agents** περιλαμβάνει πρότυπα prompt για ανάλυση βασισμένη σε αποδεικτικά στοιχεία της κίνησης Burp:

- `passive_hunter.md`: ευρεία ανάδειξη παθητικών ευπαθειών.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift και auth mismatches.
- `auth_flow_mapper.md`: σύγκριση authenticated vs unauthenticated μονοπατιών.
- `ssrf_redirect_hunter.md`: υποψήφιοι SSRF/open-redirect από URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: logic flaws πολλαπλών βημάτων.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse κενά.
- `report_writer.md`: αναφορές εστιασμένες σε αποδεικτικά στοιχεία.

## Προαιρετική σήμανση attribution

Για να επισημάνετε την κίνηση Burp/LLM στα logs, προσθέστε ένα header rewrite (proxy ή Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Σημειώσεις ασφάλειας

- Προτιμήστε **τοπικά μοντέλα** όταν η κίνηση περιέχει ευαίσθητα δεδομένα.
- Μοιραστείτε μόνο τα ελάχιστα αποδεικτικά στοιχεία που απαιτούνται για ένα εύρημα.
- Διατηρήστε το Burp ως πηγή αλήθειας· χρησιμοποιήστε το μοντέλο για **ανάλυση και αναφορά**, όχι για σάρωση.

## Burp AI Agent (AI-assisted triage + εργαλεία MCP)

**Burp AI Agent** είναι μια επέκταση του Burp που συνδυάζει local/cloud LLMs με passive/active analysis (62 vulnerability classes) και εκθέτει 53+ MCP tools ώστε εξωτερικοί MCP clients να μπορούν να ορχηστρώσουν το Burp. Επισημάνσεις:

- **Context-menu triage**: capture traffic via Proxy, open **Proxy > HTTP History**, right-click a request → **Extensions > Burp AI Agent > Analyze this request** to spawn an AI chat bound to that request/response.
- **Backends** (επιλέξιμα ανά προφίλ):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates auto-installed under `~/.burp-ai-agent/AGENTS/`; drop extra `*.md` files there to add custom analysis/scanning behaviors.
- **MCP server**: enable via **Settings > MCP Server** to expose Burp operations to any MCP client (53+ tools). Claude Desktop can be pointed at the server by editing `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF redact sensitive request data before sending it to remote models; prefer local backends when handling secrets.
- **Audit logging**: JSONL logs with per-entry SHA-256 integrity hashing for tamper-evident traceability of AI/MCP actions.
- **Build/load**: download the release JAR or build with Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Προφυλάξεις λειτουργίας: cloud backends μπορεί να εξάγουν session cookies/PII εκτός αν επιβληθεί privacy mode; η έκθεση του MCP επιτρέπει απομακρυσμένη ορχήστρωση του Burp, επομένως περιορίστε την πρόσβαση σε trusted agents και παρακολουθήστε το integrity-hashed audit log.

## Αναφορές

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
