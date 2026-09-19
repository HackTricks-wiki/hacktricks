# Burp MCP: review traffic με υποβοήθηση LLM

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Το extension **MCP Server** του Burp μπορεί να εκθέσει intercepted HTTP(S) traffic σε MCP-capable LLM clients, ώστε να μπορούν να κάνουν **reason over real requests/responses** για vulnerability discovery και σύνταξη αναφορών. Διατηρήστε το Burp ως source of truth: χρησιμοποιήστε passive analysis ή deliberate replays με αλλαγή μίας μεταβλητής, αντί για blind scanning.<sup>[[8]](#references)</sup>

## Αρχιτεκτονική

- Το **Burp MCP Server (BApp)** ακούει από προεπιλογή στο `127.0.0.1:9876` και εκθέτει intercepted traffic μέσω MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Το **MCP proxy JAR** γεφυρώνει το stdio (client side) με το MCP SSE endpoint του Burp.
- **Προαιρετικό local reverse proxy** (Caddy) κανονικοποιεί τα headers για αυστηρούς ελέγχους MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud) ή Ollama (local).

## Ρύθμιση

### 1) Εγκατάσταση του Burp MCP Server

Εγκαταστήστε το **MCP Server** από το Burp BApp Store και επαληθεύστε ότι ακούει στο `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Εξαγωγή του proxy JAR

Στην καρτέλα MCP Server, κάντε κλικ στο **Extract server proxy jar** και αποθηκεύστε το `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Διαμόρφωση ενός MCP client (παράδειγμα με Codex)

Κατευθύνετε τον client στο proxy JAR και στο direct SSE endpoint του Burp. Το packaged proxy είναι γέφυρα stdio-to-SSE· δεν αντικαθιστά τον Burp listener.<sup>[[7]](#references)</sup>
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
Στη συνέχεια, εκτέλεσε το Codex και εμφάνισε τα εργαλεία MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Διόρθωση αυστηρής επικύρωσης Origin/headers με Caddy (αν χρειάζεται)

Αν το MCP handshake αποτυγχάνει λόγω αυστηρών ελέγχων του `Origin` ή επιπλέον headers, χρησιμοποιήστε ένα local reverse proxy για την κανονικοποίηση των headers (αυτό αντιστοιχεί στο workaround για το πρόβλημα αυστηρής επικύρωσης του Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Εκκίνησε το proxy και τον client και άλλαξε το ρυθμισμένο `--sse-url` σε `http://127.0.0.1:19876` μόνο κατά τη χρήση αυτού του Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Συσχέτιση της κατάστασης του browser με τα στοιχεία του proxy (Playwright MCP)

Καταχωρίστε το Playwright MCP ώστε ο browser του να χρησιμοποιεί το proxy του Burp. Αυτό επιτρέπει στον agent να συσχετίζει την αποδιδόμενη κατάσταση του DOM/της προσβασιμότητας με το ακριβές HTTP history που τη δημιούργησε.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Προσαρμόστε τη διεύθυνση listener, επανεκκινήστε το Codex και χρησιμοποιήστε το `/mcp` για να επαληθεύσετε και τις δύο integrations. Το παράδειγμα απενεργοποιεί τα σφάλματα πιστοποιητικών του browser, ώστε η HTTPS interception να μην αποκλείεται από το τοπικά παραγόμενο πιστοποιητικό του Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Αυτοματοποίηση browser με επίγνωση proxy (OpenBurp)

Η σύνδεση Burp MCP και η διαδρομή του intercepted browser είναι ξεχωριστές ροές δεδομένων. Η υπηρεσία MCP εκθέτει τα εργαλεία του Burp στο `127.0.0.1:9876`, ενώ ένα αποκλειστικό instance του Chromium στέλνει την HTTP(S) κίνησή του μέσω του proxy του Burp στο `127.0.0.1:8080`. Επομένως, requests που δημιουργούνται απευθείας από ένα MCP tool ενδέχεται να απουσιάζουν από το **Proxy > HTTP history**· χρησιμοποιήστε τον proxied browser όταν το request/response πρέπει να είναι παρατηρήσιμο, επεξεργάσιμο ή να διατηρηθεί ως evidence.<sup>[[2]](#references)[[9]](#references)</sup>

Ένα client με υποστήριξη SSE μπορεί να κάνει απευθείας register το Burp. Ένα client που υποστηρίζει μόνο stdio μπορεί, αντί γι' αυτό, να εκκινήσει το proxy JAR της PortSwigger. Και στις δύο περιπτώσεις, κάντε register ένα δεύτερο browser-control MCP και κατευθύνετέ το στο embedded Chromium του Burp (`BURP_CHROMIUM` είναι local executable path):<sup>[[9]](#references)</sup>
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
Το flag `TLS-bypass` αποδέχεται certificates που δημιουργούνται από το interception proxy, ενώ το `--isolated` αποτρέπει την assessment από το να επαναχρησιμοποιεί το κανονικό browser profile του operator. Η απομόνωση προστατεύει την κατάσταση του profile, αλλά **δεν αποτελεί security sandbox**: ο controller μπορεί να έχει πρόσβαση σε authenticated sessions που έχουν ανοίξει σε αυτό το test browser, ενώ το Burp MCP μπορεί να εκθέσει ευαίσθητα requests, responses και configuration.<sup>[[9]](#references)</sup>

Test το SSE listener ανεξάρτητα πριν κάνεις debugging στο client bridge:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Ένας healthy listener επιστρέφει `Content-Type: text/event-stream`. Ένα timeout μετά τις headers είναι αναμενόμενο, επειδή ένα SSE stream παραμένει ανοιχτό για μελλοντικά events. Αν ο client εξακολουθεί να αποτυγχάνει, επιβεβαιώστε το configured route του extension: η PortSwigger σημειώνει ότι το endpoint μπορεί να είναι το root path ή το `/sse`, ανάλογα με τον client και το configuration του extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Χρήση διαφορετικών clients

### Codex CLI

- Ρυθμίστε το `~/.codex/config.toml` όπως παραπάνω.
- Εκτελέστε το `codex` και στη συνέχεια το `/mcp` για να επαληθεύσετε τη λίστα των Burp tools.

### Gemini CLI

Το repo **burp-mcp-agents** παρέχει βοηθητικά launchers:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (τοπικό)

Χρησιμοποιήστε το παρεχόμενο βοηθητικό πρόγραμμα εκκίνησης και επιλέξτε ένα τοπικό model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Παραδείγματα local models και κατά προσέγγιση απαιτήσεις VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay και validation βάσει evidence

Μην αφήνετε τον agent να θεωρεί μια εύλογη εξήγηση ή μια ενδιάμεση απόκριση ως proof. Χρησιμοποιήστε Burp requests/responses και ανεξάρτητα παρατηρούμενη κατάσταση του browser, ώστε κάθε test να μπορεί να διαψευστεί.<sup>[[8]](#references)</sup>

1. Αποθηκεύστε ένα baseline request/response pair και εντοπίστε το ακριβές component που ελέγχεται από τον attacker.
2. Για συγκρίσεις authorization, καταγράψτε ανεξάρτητα το ίδιο workflow και με τους δύο accounts, πριν τροποποιήσετε identifiers, cookies ή tokens.
3. Πριν κάνετε replay μιας μετάλλαξης, καταγράψτε το hypothesis, τη θέση του evidence, το αναμενόμενο signal και το αποτέλεσμα που θα το διέψευδε.
4. Τροποποιείτε ένα component κάθε φορά, διατηρείτε το resulting pair και επισημαίνετε ξεχωριστά τις άμεσες παρατηρήσεις από τα inferences.
5. Παρακολουθείτε κάθε candidate ως `open`, `blocked`, `rejected` ή `confirmed`. Επανεξετάστε τον μόνο όταν νέο evidence αλλάζει το mechanism ή ένα prerequisite.
6. Επιβεβαιώστε τον έλεγχο από τον attacker, το reachability, το repeatability, το constraint bypass, το impact και την τελική application state. Ένα redirect ή ένα επιτυχές tool call δεν αποτελεί proof, αν η claimed state change πραγματοποιείται downstream.

Διατηρήστε τις λεπτομέρειες του exploitation στη σχετική technique page. Για παράδειγμα, οι browser-message candidates ανήκουν στο [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), ενώ η συμπεριφορά επιλογής token key ανήκει στο [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Ένα σύντομο hypothesis record εμποδίζει τους parallel agents να επαναλαμβάνουν το ίδιο ελκυστικό branch:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt pack για παθητικό review

Το repo **burp-mcp-agents** περιλαμβάνει prompt templates για evidence-driven ανάλυση Burp traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ευρεία παθητική ανίχνευση vulnerabilities.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift και ασυμφωνίες authentication.
- `auth_flow_mapper.md`: σύγκριση authenticated και unauthenticated paths.
- `ssrf_redirect_hunter.md`: υποψήφιες περιπτώσεις SSRF/open-redirect από URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: κακή χρήση token audience/scope.
- `rate_limit_abuse_hunter.md`: κενά σε throttling/abuse.
- `report_writer.md`: reporting με έμφαση στα evidence.

## Προαιρετικό attribution tagging

Για να επισημαίνετε Burp/LLM traffic στα logs, προσθέστε ένα header rewrite (proxy ή Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Σημειώσεις ασφαλείας

- Προτιμάτε **local models** όταν η κίνηση περιέχει ευαίσθητα δεδομένα.
- Κοινοποιείτε μόνο τα ελάχιστα απαραίτητα στοιχεία για ένα εύρημα.
- Διατηρείτε το Burp ως την κύρια πηγή αλήθειας· χρησιμοποιείτε το model για **analysis and reporting**, όχι για scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

Το **Burp AI Agent** είναι ένα Burp extension που συνδυάζει local/cloud LLMs με passive/active analysis (62 vulnerability classes) και εκθέτει περισσότερα από 53 MCP tools, ώστε εξωτερικά MCP clients να μπορούν να ενορχηστρώνουν το Burp.<sup>[[5]](#references)</sup> Κύρια χαρακτηριστικά:

- **Context-menu triage**: καταγράψτε traffic μέσω Proxy, ανοίξτε το **Proxy > HTTP History**, κάντε δεξί κλικ σε ένα request → **Extensions > Burp AI Agent > Analyze this request** για να ξεκινήσετε ένα AI chat συνδεδεμένο με το συγκεκριμένο request/response.
- **Backends** (επιλέξιμα ανά profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ή `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates εγκαθίστανται αυτόματα στο `~/.burp-ai-agent/AGENTS/`· προσθέστε επιπλέον αρχεία `*.md` εκεί για να προσθέσετε custom analysis/scanning behaviors.
- **MCP server**: ενεργοποιήστε το μέσω **Settings > MCP Server** για να εκθέσετε λειτουργίες του Burp σε οποιοδήποτε MCP client (περισσότερα από 53 tools). Το Claude Desktop μπορεί να συνδεθεί στον server μέσω επεξεργασίας του `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ή του `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: τα STRICT / BALANCED / OFF redacts ευαίσθητα request data πριν από την αποστολή τους σε remote models· προτιμάτε local backends όταν χειρίζεστε secrets.
- **Audit logging**: JSONL logs με SHA-256 integrity hashing ανά entry για tamper-evident traceability των AI/MCP actions.
- **Build/load**: κατεβάστε το release JAR ή κάντε build με Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Προειδοποιήσεις λειτουργίας: τα cloud backends ενδέχεται να κάνουν exfiltrate session cookies/PII, εκτός εάν επιβάλλεται το privacy mode· η έκθεση του MCP παρέχει απομακρυσμένη ενορχήστρωση του Burp, επομένως περιορίστε την πρόσβαση σε έμπιστους agents και παρακολουθείτε το audit log με integrity hash.

## References

- [1] [Ενσωμάτωση Burp MCP + Codex CLI και επιδιόρθωση handshake στο Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Ζήτημα αυστηρής επικύρωσης Origin/header στον MCP server του PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Πώς να χρησιμοποιείτε το Codex για έρευνα Bug Bounty: εξερευνήστε ευρέως, επικυρώστε αυστηρά](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: ενορχήστρωση του Burp Suite για Claude Code και Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
