# Burp MCP: έλεγχος traffic με υποβοήθηση LLM

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Το extension **MCP Server** του Burp μπορεί να εκθέσει HTTP(S) traffic που έχει intercepted σε MCP-capable LLM clients, ώστε να μπορούν να **αναλύουν πραγματικά requests/responses** για ανακάλυψη vulnerabilities και σύνταξη drafts αναφορών. Διατηρήστε το Burp ως source of truth: χρησιμοποιείτε passive analysis ή σκόπιμα replays με αλλαγή μίας μεταβλητής, αντί για blind scanning.<sup>[[8]](#references)</sup>

## Αρχιτεκτονική

- Ο **Burp MCP Server (BApp)** ακούει από προεπιλογή στο `127.0.0.1:9876` και εκθέτει intercepted traffic μέσω MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Το **MCP proxy JAR** γεφυρώνει το stdio (client side) με το MCP SSE endpoint του Burp.
- Το **προαιρετικό local reverse proxy** (Caddy) κανονικοποιεί τα headers για αυστηρούς ελέγχους MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud) ή Ollama (local).

## Ρύθμιση

### 1) Εγκατάσταση του Burp MCP Server

Εγκαταστήστε το **MCP Server** από το Burp BApp Store και επαληθεύστε ότι ακούει στο `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Εξαγωγή του proxy JAR

Στην καρτέλα MCP Server, κάντε κλικ στο **Extract server proxy jar** και αποθηκεύστε το `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Ρύθμιση ενός MCP client (παράδειγμα Codex)

Κατευθύνετε τον client στο proxy JAR και στο άμεσο SSE endpoint του Burp. Το packaged proxy είναι μια γέφυρα stdio-to-SSE· δεν αντικαθιστά τον Burp listener.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Η αντίστοιχη εντολή Codex είναι:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Στη συνέχεια εκτέλεσε το Codex και απαρίθμησε τα εργαλεία MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Διόρθωση αυστηρής επικύρωσης Origin/header με Caddy (αν χρειάζεται)

Αν το MCP handshake αποτύχει λόγω αυστηρών ελέγχων του `Origin` ή επιπλέον headers, χρησιμοποιήστε ένα local reverse proxy για την κανονικοποίηση των headers (αυτό αντιστοιχεί στο workaround για το ζήτημα αυστηρής επικύρωσης του Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Ξεκινήστε το proxy και τον client και αλλάξτε το ρυθμισμένο `--sse-url` σε `http://127.0.0.1:19876` μόνο κατά τη χρήση αυτού του Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Συσχετίστε την κατάσταση του browser με evidence από το proxy (Playwright MCP)

Καταχωρίστε το Playwright MCP ώστε ο browser του να χρησιμοποιεί το proxy του Burp. Αυτό επιτρέπει στο agent να συσχετίζει την κατάσταση του rendered DOM/accessibility με το ακριβές HTTP history που τη δημιούργησε.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Προσαρμόστε τη διεύθυνση του listener, κάντε επανεκκίνηση του Codex και χρησιμοποιήστε το `/mcp` για να επαληθεύσετε και τις δύο integrations. Το παράδειγμα απενεργοποιεί τα σφάλματα πιστοποιητικών του browser, ώστε η HTTPS interception να μην αποκλείεται από το certificate που δημιουργείται τοπικά από το Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Χρήση διαφορετικών clients

### Codex CLI

- Ρυθμίστε το `~/.codex/config.toml` όπως παραπάνω.
- Εκτελέστε το `codex` και, στη συνέχεια, το `/mcp` για να επαληθεύσετε τη λίστα των Burp tools.

### Gemini CLI

Το repo **burp-mcp-agents** παρέχει launcher helpers:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (τοπικό)

Χρησιμοποιήστε το παρεχόμενο helper εκκίνησης και επιλέξτε ένα τοπικό model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Παραδείγματα local models και κατά προσέγγιση απαιτήσεις VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay και validation βασισμένα σε evidence

Μην επιτρέπετε στον agent να θεωρεί μια plausible explanation ή ένα intermediate response ως proof. Χρησιμοποιήστε Burp requests/responses και independently observed browser state, ώστε κάθε test να μπορεί να διαψευστεί.<sup>[[8]](#references)</sup>

1. Αποθηκεύστε ένα baseline request/response pair και εντοπίστε το ακριβές attacker-controlled component.
2. Για authorization comparisons, κάντε capture του ίδιου workflow independently και στους δύο λογαριασμούς, πριν τροποποιήσετε identifiers, cookies ή tokens.
3. Πριν κάνετε replay μιας mutation, καταγράψτε το hypothesis, τη θέση του evidence, το expected signal και το αποτέλεσμα που θα το διέψευδε.
4. Κάντε mutate ένα component κάθε φορά, διατηρήστε το resulting pair και επισημάνετε ξεχωριστά τα direct observations από τα inferences.
5. Παρακολουθήστε κάθε candidate ως `open`, `blocked`, `rejected` ή `confirmed`. Επανεξετάστε τον μόνο όταν νέο evidence αλλάζει το mechanism ή ένα prerequisite.
6. Επιβεβαιώστε το attacker control, το reachability, το repeatability, το constraint bypass, το impact και το τελικό application state. Ένα redirect ή ένα successful tool call δεν αποτελεί proof, αν η claimed state change πραγματοποιείται downstream.

Διατηρήστε τις exploitation details στη σχετική technique page. Για παράδειγμα, τα browser-message candidates ανήκουν στο [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), ενώ η συμπεριφορά token key-selection ανήκει στο [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Ένα compact hypothesis record εμποδίζει parallel agents να επαναλαμβάνουν το ίδιο attractive branch:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Πακέτο prompts για passive review

Το repo **burp-mcp-agents** περιλαμβάνει πρότυπα prompts για ανάλυση Burp traffic βάσει αποδεικτικών στοιχείων:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ευρεία παθητική ανίχνευση vulnerabilities.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift και ασυμφωνίες authentication.
- `auth_flow_mapper.md`: σύγκριση authenticated και unauthenticated paths.
- `ssrf_redirect_hunter.md`: υποψήφια SSRF/open-redirect από URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: logic flaws πολλαπλών βημάτων.
- `session_scope_hunter.md`: κακή χρήση token audience/scope.
- `rate_limit_abuse_hunter.md`: κενά σε throttling/abuse.
- `report_writer.md`: reporting με έμφαση στα evidence.

## Προαιρετικό attribution tagging

Για να προσθέσετε tag σε Burp/LLM traffic στα logs, προσθέστε ένα header rewrite (proxy ή Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Σημειώσεις ασφάλειας

- Προτιμήστε **local models** όταν η κίνηση περιέχει ευαίσθητα δεδομένα.
- Κοινοποιείτε μόνο τα ελάχιστα απαραίτητα στοιχεία για ένα εύρημα.
- Διατηρείτε το Burp ως source of truth· χρησιμοποιείτε το model για **analysis and reporting**, όχι για scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

Το **Burp AI Agent** είναι ένα Burp extension που συνδυάζει local/cloud LLMs με passive/active analysis (62 κλάσεις ευπαθειών) και εκθέτει περισσότερα από 53 MCP tools, ώστε εξωτερικοί MCP clients να μπορούν να ενορχηστρώνουν το Burp.<sup>[[5]](#references)</sup> Κύρια σημεία:

- **Context-menu triage**: καταγράψτε traffic μέσω Proxy, ανοίξτε το **Proxy > HTTP History**, κάντε δεξί κλικ σε ένα request → **Extensions > Burp AI Agent > Analyze this request** για να ξεκινήσετε ένα AI chat συνδεδεμένο με το συγκεκριμένο request/response.
- **Backends** (επιλέξιμα ανά profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint συμβατό με **OpenAI** (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ή `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates που εγκαθίστανται αυτόματα στο `~/.burp-ai-agent/AGENTS/`· τοποθετήστε επιπλέον αρχεία `*.md` εκεί για να προσθέσετε custom analysis/scanning behaviors.
- **MCP server**: ενεργοποιήστε το μέσω **Settings > MCP Server** για να εκθέσετε λειτουργίες του Burp σε οποιοδήποτε MCP client (περισσότερα από 53 tools). Το Claude Desktop μπορεί να συνδεθεί στον server μέσω επεξεργασίας του `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ή του `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: τα STRICT / BALANCED / OFF redacts sensitive request data πριν από την αποστολή του σε remote models· προτιμήστε local backends όταν διαχειρίζεστε secrets.
- **Audit logging**: JSONL logs με SHA-256 integrity hashing ανά entry, για tamper-evident traceability των ενεργειών AI/MCP.
- **Build/load**: κατεβάστε το release JAR ή κάντε build με Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Προειδοποιήσεις λειτουργίας: τα cloud backends ενδέχεται να κάνουν exfiltrate session cookies/PII, εκτός εάν επιβάλλεται privacy mode· η έκθεση του MCP παρέχει remote orchestration του Burp, επομένως περιορίστε την πρόσβαση σε trusted agents και παρακολουθείτε το integrity-hashed audit log.

## References

- [1] [Ενσωμάτωση Burp MCP + Codex CLI και διόρθωση handshake του Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Πρόβλημα αυστηρής επικύρωσης Origin/header στον MCP server του PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Πώς να χρησιμοποιήσετε το Codex για έρευνα Bug Bounty: εξερευνήστε ευρέως, επικυρώστε αυστηρά](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
