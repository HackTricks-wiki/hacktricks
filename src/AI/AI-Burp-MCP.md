# Burp MCP: Έλεγχος traffic με τη βοήθεια LLM

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Η επέκταση **MCP Server** του Burp μπορεί να εκθέτει το HTTP(S) traffic που έχει υποκλαπεί σε clients LLM με υποστήριξη MCP, ώστε να μπορούν να **αναλύουν πραγματικά requests/responses** για τον εντοπισμό ευπαθειών και τη σύνταξη αναφορών. Χρησιμοποιείτε το Burp ως πηγή αλήθειας: προτιμήστε παθητική ανάλυση ή ελεγχόμενες επαναλήψεις με αλλαγή μίας μεταβλητής κάθε φορά, αντί για τυφλό scanning.<sup>[[8]](#references)</sup>

## Αρχιτεκτονική

- Ο **Burp MCP Server (BApp)** ακούει από προεπιλογή στη διεύθυνση `127.0.0.1:9876` και εκθέτει το traffic που έχει υποκλαπεί μέσω MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Το **MCP proxy JAR** γεφυρώνει το stdio (πλευρά client) με το MCP SSE endpoint του Burp.
- Ένας **προαιρετικός τοπικός reverse proxy** (Caddy) κανονικοποιεί τα headers για αυστηρούς ελέγχους του MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud) ή Ollama (local).

## Ρύθμιση

### 1) Εγκαταστήστε το Burp MCP Server

Εγκαταστήστε το **MCP Server** από το Burp BApp Store και επαληθεύστε ότι ακούει στη διεύθυνση `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Εξαγάγετε το proxy JAR

Στην καρτέλα MCP Server, κάντε κλικ στο **Extract server proxy jar** και αποθηκεύστε το `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Ρυθμίστε έναν MCP client (παράδειγμα με Codex)

Ορίστε στο client τη διαδρομή προς το proxy JAR και το απευθείας SSE endpoint του Burp. Το ενσωματωμένο proxy λειτουργεί ως γέφυρα stdio-to-SSE· δεν αντικαθιστά τον listener του Burp.<sup>[[7]](#references)</sup>

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

Στη συνέχεια, εκτελέστε το Codex και παραθέστε τα εργαλεία MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Διόρθωση αυστηρής επικύρωσης Origin/header με Caddy (αν χρειάζεται)

Αν το handshake του MCP αποτύχει λόγω αυστηρών ελέγχων Origin ή επιπλέον headers, χρησιμοποιήστε έναν τοπικό reverse proxy για την κανονικοποίηση των headers (αυτός είναι ο ίδιος τρόπος αντιμετώπισης του προβλήματος αυστηρής επικύρωσης του Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Εκκινήστε το proxy και τον client και αλλάξτε το διαμορφωμένο `--sse-url` σε `http://127.0.0.1:19876` μόνο κατά τη χρήση αυτού του Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Συσχετίστε την κατάσταση του browser με τα στοιχεία του proxy (Playwright MCP)

Καταχωρίστε το Playwright MCP, ώστε το browser του να χρησιμοποιεί το proxy του Burp. Έτσι, ο agent μπορεί να συσχετίζει την κατάσταση του αποδοσμένου DOM/της προσβασιμότητας με το ακριβές ιστορικό HTTP που την προκάλεσε.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Προσαρμόστε τη διεύθυνση του listener, επανεκκινήστε το Codex και χρησιμοποιήστε το `/mcp` για να επαληθεύσετε και τις δύο ενσωματώσεις. Το παράδειγμα απενεργοποιεί τα σφάλματα πιστοποιητικών του browser, ώστε η HTTPS interception να μην αποκλείεται από το πιστοποιητικό που δημιουργεί τοπικά το Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Αυτοματοποίηση browser με υποστήριξη proxy (OpenBurp)

Η σύνδεση Burp MCP και η διαδρομή του browser που υποβάλλεται σε interception είναι ξεχωριστές ροές δεδομένων. Η υπηρεσία MCP διαθέτει τα εργαλεία του Burp στη διεύθυνση `127.0.0.1:9876`, ενώ μια αποκλειστική παρουσία Chromium στέλνει την κίνηση HTTP(S) μέσω του proxy του Burp στη διεύθυνση `127.0.0.1:8080`. Επομένως, αιτήματα που δημιουργούνται απευθείας από ένα εργαλείο MCP ενδέχεται να μην εμφανίζονται στο **Proxy > HTTP history**· χρησιμοποιήστε τον browser που περνά από το proxy όποτε πρέπει να είναι ορατό, επεξεργάσιμο ή να διατηρηθεί ως αποδεικτικό στοιχείο το αίτημα/η απόκριση.<sup>[[2]](#references)[[9]](#references)</sup>

Ένας client με υποστήριξη SSE μπορεί να καταχωρίσει απευθείας το Burp. Αν ο client υποστηρίζει μόνο stdio, μπορεί να εκκινήσει το proxy JAR της PortSwigger. Και στις δύο περιπτώσεις, καταχωρίστε ένα δεύτερο MCP ελέγχου browser και κατευθύνετέ το στο ενσωματωμένο Chromium του Burp (`BURP_CHROMIUM` είναι μια τοπική διαδρομή εκτελέσιμου αρχείου):<sup>[[9]](#references)</sup>

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

Η σημαία TLS-bypass αποδέχεται πιστοποιητικά που δημιουργούνται από το proxy υποκλοπής, ενώ το `--isolated` αποτρέπει την επαναχρησιμοποίηση του κανονικού προφίλ περιήγησης του χειριστή κατά την αξιολόγηση. Η απομόνωση προστατεύει την κατάσταση του προφίλ, αλλά **δεν αποτελεί sandbox ασφαλείας**: ο controller εξακολουθεί να έχει πρόσβαση σε αυθεντικοποιημένες συνεδρίες που έχουν ανοιχτεί σε αυτό το πρόγραμμα περιήγησης δοκιμών, ενώ το Burp MCP μπορεί να εκθέσει ευαίσθητα αιτήματα, αποκρίσεις και ρυθμίσεις.<sup>[[9]](#references)</sup>

Δοκιμάστε ανεξάρτητα τον listener SSE πριν από την αντιμετώπιση προβλημάτων του client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Ένας υγιής listener επιστρέφει `Content-Type: text/event-stream`. Είναι αναμενόμενο να υπάρξει timeout μετά τις κεφαλίδες, επειδή ένα SSE stream παραμένει ανοιχτό για μελλοντικά events. Αν ο client εξακολουθεί να αποτυγχάνει, επιβεβαιώστε τη διαδρομή που έχει ρυθμιστεί στην επέκταση: η PortSwigger σημειώνει ότι το endpoint μπορεί να είναι το root path ή το `/sse`, ανάλογα με τον client και τη ρύθμιση της επέκτασης.<sup>[[9]](#references)[[7]](#references)</sup>

## Χρήση διαφορετικών clients

### Codex CLI

- Ρυθμίστε το `~/.codex/config.toml` όπως παραπάνω.
- Εκτελέστε το `codex` και έπειτα το `/mcp` για να επαληθεύσετε τη λίστα εργαλείων του Burp.

### Gemini CLI

Το repo **burp-mcp-agents** παρέχει βοηθητικά προγράμματα εκκίνησης:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (τοπικό)

Χρησιμοποιήστε το παρεχόμενο βοηθητικό πρόγραμμα εκκίνησης και επιλέξτε ένα τοπικό μοντέλο:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Παραδείγματα τοπικών μοντέλων και κατά προσέγγιση απαιτήσεις VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Επαναλήψεις και επικύρωση με βάση τα στοιχεία

Μην αφήνετε τον agent να αντιμετωπίζει μια εύλογη εξήγηση ή μια ενδιάμεση απόκριση ως απόδειξη. Χρησιμοποιήστε αιτήματα/αποκρίσεις του Burp και την κατάσταση του browser που παρατηρήσατε ανεξάρτητα, ώστε κάθε δοκιμή να μπορεί να διαψευστεί.<sup>[[8]](#references)</sup>

1. Αποθηκεύστε ένα ζεύγος αρχικού αιτήματος/απόκρισης και εντοπίστε το ακριβές στοιχείο που ελέγχεται από τον attacker.
2. Για συγκρίσεις εξουσιοδότησης, καταγράψτε την ίδια ροή εργασίας ανεξάρτητα και στους δύο λογαριασμούς, προτού τροποποιήσετε αναγνωριστικά, cookies ή tokens.
3. Πριν επαναλάβετε μια τροποποίηση, καταγράψτε την υπόθεση, τη θέση των στοιχείων, το αναμενόμενο σήμα και το αποτέλεσμα που θα την αναιρούσε.
4. Τροποποιήστε ένα στοιχείο κάθε φορά, διατηρήστε το ζεύγος που προκύπτει και διαχωρίστε τις άμεσες παρατηρήσεις από τα συμπεράσματα.
5. Παρακολουθήστε κάθε υποψήφιο ως `open`, `blocked`, `rejected` ή `confirmed`· επανεξετάστε τον μόνο όταν νέα στοιχεία αλλάζουν τον μηχανισμό ή κάποια προϋπόθεση.
6. Επιβεβαιώστε τον έλεγχο από τον attacker, την προσβασιμότητα, την επαναληψιμότητα, την παράκαμψη περιορισμών, τον αντίκτυπο και την τελική κατάσταση της εφαρμογής. Μια ανακατεύθυνση ή μια επιτυχής κλήση εργαλείου δεν αποτελεί απόδειξη, αν η υποτιθέμενη αλλαγή κατάστασης συμβαίνει σε επόμενο στάδιο.

Διατηρήστε τις λεπτομέρειες εκμετάλλευσης στην αντίστοιχη σελίδα τεχνικής. Για παράδειγμα, τα πιθανά προβλήματα με μηνύματα browser ανήκουν στο [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), ενώ η συμπεριφορά επιλογής κλειδιού token ανήκει στο [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Μια σύντομη καταγραφή υποθέσεων αποτρέπει την επανάληψη του ίδιου δελεαστικού μονοπατιού από παράλληλους agents:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Στοχευμένη επικύρωση out-of-band με Burp MCP

Το Burp Suite Professional εκθέτει τις `generate_collaborator_payload` και `get_collaborator_interactions` μέσω της επίσημης επέκτασης MCP. Συνδυάστε τις με τις `get_proxy_http_history_regex` και μία επανάληψη αιτήματος μέσω `send_http1_request`, για να ελέγξετε αν υπάρχει υποψία ανάκτησης URL από την πλευρά του server, χωρίς να σαρώσετε ολόκληρο τον στόχο. Το Burp μπορεί να απαιτεί ξεχωριστή έγκριση για ανάγνωση του history και αποστολή αιτήματος.<sup>[[2]](#references)[[10]](#references)</sup>

1. Φιλτράρετε το history για ένα υποψήφιο αίτημα που περιέχει URL, όπως ένα με `url=`, `webhook` ή `callback`. Αποθηκεύστε το αρχικό request και response. Το εργαλείο history δέχεται `regex`, `count` και `offset`· χρησιμοποιήστε σελιδοποίηση αντί να ζητήσετε από το μοντέλο να εξετάσει κάθε καταχώριση.<sup>[[10]](#references)</sup>
2. Δημιουργήστε ένα νέο Collaborator payload και κρατήστε το **payload ID** που επιστρέφεται. Επαναλάβετε το αίτημα που καταγράψατε προς τον ίδιο host και port, αλλάζοντας μόνο το υποψήφιο URL σε ένα HTTPS URL κάτω από το domain του payload. Για το `send_http1_request`, δώστε ολόκληρο το HTTP/1.1 request ως `content`, μαζί με τα `targetHostname`, `targetPort` και `usesHttps`· τα πεδία προορισμού προσδιορίζουν την **εφαρμογή**, όχι τον host του Collaborator.<sup>[[10]](#references)</sup>
3. Ελέγξτε περιοδικά το `get_collaborator_interactions` με αυτό το payload ID και συσχετίστε τον χρόνο της αλληλεπίδρασης με την επανάληψη του αιτήματος. Μια αλληλεπίδραση HTTP αποτελεί ένδειξη ανάκτησης, ενώ μόνο το DNS δείχνει επίλυση ονόματος και όχι ολοκληρωμένο HTTP request. Ελέγξτε την πηγή της αλληλεπίδρασης και τις κεφαλίδες του request, ώστε να διακρίνετε την εξερχόμενη κίνηση του server από τη φόρτωση από την πλευρά του browser. Στη συνέχεια, επαναλάβετε με νέο payload για να αποκλείσετε άσχετη κίνηση.<sup>[[10]](#references)[[11]](#references)</sup>

Το εργαλείο αιτημάτων MCP επιστρέφει απευθείας το response και δεν είναι απαραίτητο να το καταγράψει στο **Proxy > HTTP history**. Διατηρήστε το αποτέλεσμα του request/response ή χρησιμοποιήστε browser μέσω proxy ή το Repeater για τεκμήριο που καταγράφεται στο history. Για την επιλογή SSRF payload και τις επόμενες δοκιμές, χρησιμοποιήστε το [κεφάλαιο SSRF](../pentesting-web/ssrf-server-side-request-forgery/) αντί να θεωρήσετε ότι μια out-of-band callback αποδεικνύει επίπτωση στο εσωτερικό δίκτυο. Για δοκιμές του ίδιου του MCP server, δείτε τη [δοκιμή MCP server](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Πακέτο prompts για παθητική ανασκόπηση

Το repo **burp-mcp-agents** περιλαμβάνει πρότυπα prompt για ανάλυση της κίνησης του Burp με βάση τεκμήρια:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ευρεία παθητική ανάδειξη ευπαθειών.
- `idor_hunter.md`: IDOR/BOLA/αποκλίσεις σε αντικείμενα ή tenants και ασυμφωνίες ελέγχου ταυτότητας.
- `auth_flow_mapper.md`: σύγκριση διαδρομών με και χωρίς έλεγχο ταυτότητας.
- `ssrf_redirect_hunter.md`: υποψήφιες περιπτώσεις SSRF/open-redirect από παραμέτρους ανάκτησης URL και αλυσίδες ανακατεύθυνσης.
- `logic_flaw_hunter.md`: λογικά σφάλματα πολλαπλών βημάτων.
- `session_scope_hunter.md`: κακή χρήση κοινού ή εύρους token.
- `rate_limit_abuse_hunter.md`: κενά στον περιορισμό ρυθμού ή στην αποτροπή κατάχρησης.
- `report_writer.md`: σύνταξη αναφορών με έμφαση στα τεκμήρια.

## Προαιρετική προσθήκη ετικέτας απόδοσης

Για να προσθέσετε ετικέτα στην κίνηση Burp/LLM στα logs, προσθέστε έναν κανόνα επανεγγραφής κεφαλίδας (proxy ή Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Σημειώσεις ασφαλείας

- Προτιμήστε **local models** όταν η κίνηση περιέχει ευαίσθητα δεδομένα.
- Κοινοποιείτε μόνο τα ελάχιστα απαραίτητα στοιχεία για ένα εύρημα.
- Διατηρείτε το Burp ως πηγή αλήθειας· χρησιμοποιείτε το μοντέλο για **ανάλυση και σύνταξη αναφορών**, όχι για σάρωση.

## Burp AI Agent (διαλογή με τη βοήθεια AI + εργαλεία MCP)

Το **Burp AI Agent** είναι μια επέκταση του Burp που συνδυάζει local/cloud LLMs με παθητική/ενεργητική ανάλυση (62 κλάσεις ευπαθειών) και παρέχει πάνω από 53 εργαλεία MCP, ώστε εξωτερικοί MCP clients να μπορούν να ενορχηστρώνουν το Burp.<sup>[[5]](#references)</sup> Βασικά χαρακτηριστικά:

- **Διαλογή μέσω μενού περιβάλλοντος**: καταγράψτε την κίνηση μέσω του Proxy, ανοίξτε το **Proxy > HTTP History**, κάντε δεξί κλικ σε ένα αίτημα → **Extensions > Burp AI Agent > Analyze this request** για να ξεκινήσετε μια συνομιλία AI συνδεδεμένη με το συγκεκριμένο αίτημα/απόκριση.
- **Backends** (επιλέγονται ανά προφίλ):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: endpoint συμβατό με **OpenAI** (base URL + όνομα μοντέλου).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ή `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (σύνδεση ανάλογα με τον πάροχο).
- **Agent profiles**: τα πρότυπα prompt εγκαθίστανται αυτόματα στο `~/.burp-ai-agent/AGENTS/`· τοποθετήστε εκεί επιπλέον αρχεία `*.md` για να προσθέσετε προσαρμοσμένες συμπεριφορές ανάλυσης/σάρωσης.
- **MCP server**: ενεργοποιήστε τον από το **Settings > MCP Server** για να διαθέσετε λειτουργίες του Burp σε οποιονδήποτε MCP client (πάνω από 53 εργαλεία). Μπορείτε να συνδέσετε το Claude Desktop στον server τροποποιώντας το `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ή το `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Έλεγχοι απορρήτου**: οι λειτουργίες STRICT / BALANCED / OFF αποκρύπτουν ευαίσθητα δεδομένα αιτημάτων πριν από την αποστολή τους σε remote models· προτιμήστε local backends όταν διαχειρίζεστε μυστικά.
- **Καταγραφή ελέγχου**: αρχεία καταγραφής JSONL με κατακερματισμό ακεραιότητας SHA-256 για κάθε καταχώριση, ώστε να υπάρχει ανιχνεύσιμη ιχνηλασιμότητα ενεργειών AI/MCP με αποδεικτικά στοιχεία αλλοίωσης.
- **Build/load**: κατεβάστε το JAR της έκδοσης ή κάντε build με Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Λειτουργικές προφυλάξεις: τα cloud backends ενδέχεται να κάνουν exfiltrate session cookies/PII, εκτός αν επιβάλλεται η λειτουργία απορρήτου· η έκθεση του MCP παρέχει δυνατότητα απομακρυσμένου συντονισμού του Burp, επομένως περιορίστε την πρόσβαση σε έμπιστους agents και παρακολουθείτε το audit log με hash ακεραιότητας.



## References

- [1] [Ενσωμάτωση Burp MCP + Codex CLI και διόρθωση του Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Ζήτημα αυστηρής επικύρωσης Origin/header στον MCP server του PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, πακέτο prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Πώς να χρησιμοποιήσετε το Codex για έρευνα Bug Bounty: ευρεία διερεύνηση, αυστηρή επικύρωση](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: συντονισμός του Burp Suite για Claude Code και Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Υλοποιήσεις εργαλείων και παράμετροι του PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Ευπάθειες Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
