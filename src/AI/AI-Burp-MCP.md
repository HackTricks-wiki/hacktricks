# Burp MCP: Έλεγχος κίνησης με τη βοήθεια LLM

{{#include ../banners/hacktricks-training.md}}

## Επισκόπηση

Η επέκταση **MCP Server** του Burp μπορεί να εκθέτει την υποκλαπείσα κίνηση HTTP(S) σε clients LLM που υποστηρίζουν MCP, ώστε να μπορούν να **αναλύουν πραγματικά αιτήματα/αποκρίσεις** για τον εντοπισμό ευπαθειών και τη σύνταξη αναφορών. Κρατήστε το Burp ως την αξιόπιστη πηγή: χρησιμοποιήστε παθητική ανάλυση ή ελεγχόμενα replays με αλλαγή μίας μεταβλητής κάθε φορά, αντί για τυφλή σάρωση.<sup>[[8]](#references)</sup>

## Αρχιτεκτονική

- Ο **Burp MCP Server (BApp)** ακούει από προεπιλογή στη διεύθυνση `127.0.0.1:9876` και εκθέτει την υποκλαπείσα κίνηση μέσω MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Το **MCP proxy JAR** γεφυρώνει το stdio (πλευρά client) με το MCP SSE endpoint του Burp.
- **Προαιρετικός τοπικός reverse proxy** (Caddy) κανονικοποιεί τις κεφαλίδες για αυστηρούς ελέγχους χειραψίας MCP.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud) ή Ollama (τοπικά).

## Ρύθμιση

### 1) Εγκατάσταση του Burp MCP Server

Εγκαταστήστε το **MCP Server** από το Burp BApp Store και επαληθεύστε ότι ακούει στη διεύθυνση `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Εξαγωγή του proxy JAR

Στην καρτέλα MCP Server, κάντε κλικ στο **Extract server proxy jar** και αποθηκεύστε το `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Διαμόρφωση client MCP (παράδειγμα Codex)

Ορίστε ως προορισμό του client το proxy JAR και το απευθείας SSE endpoint του Burp. Το πακεταρισμένο proxy λειτουργεί ως γέφυρα stdio-to-SSE· δεν αντικαθιστά τον listener του Burp.<sup>[[7]](#references)</sup>

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

Στη συνέχεια, εκτελέστε το Codex και εμφανίστε τα εργαλεία MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Διόρθωση αυστηρής επικύρωσης Origin/header με το Caddy (αν χρειάζεται)

Αν αποτύχει το MCP handshake λόγω αυστηρών ελέγχων `Origin` ή πρόσθετων headers, χρησιμοποιήστε έναν τοπικό reverse proxy για την κανονικοποίηση των headers (αυτό αντιστοιχεί στη λύση παράκαμψης για το ζήτημα αυστηρής επικύρωσης του Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Εκκινήστε τον proxy και τον client και αλλάξτε το ρυθμισμένο `--sse-url` σε `http://127.0.0.1:19876` μόνο όταν χρησιμοποιείτε αυτόν τον listener του Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Συνδυάστε την κατάσταση του browser με τα στοιχεία του proxy (Playwright MCP)

Ρυθμίστε το Playwright MCP ώστε ο browser του να χρησιμοποιεί το proxy του Burp. Έτσι, ο agent μπορεί να συσχετίζει την κατάσταση του DOM και της προσβασιμότητας που εμφανίζεται με το ακριβές ιστορικό HTTP που την παρήγαγε.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Προσαρμόστε τη διεύθυνση του listener, επανεκκινήστε το Codex και χρησιμοποιήστε το `/mcp` για να επαληθεύσετε και τις δύο ενσωματώσεις. Το παράδειγμα απενεργοποιεί τα σφάλματα πιστοποιητικών του browser, ώστε η HTTPS interception να μην εμποδίζεται από το πιστοποιητικό που δημιουργεί τοπικά το Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Αυτοματοποίηση browser με υποστήριξη proxy (OpenBurp)

Η σύνδεση Burp MCP και η διαδρομή του browser μέσω interception είναι ξεχωριστές ροές δεδομένων. Η υπηρεσία MCP εκθέτει τα εργαλεία του Burp στη διεύθυνση `127.0.0.1:9876`, ενώ ένα ειδικό instance του Chromium στέλνει την HTTP(S) κίνησή του μέσω του proxy του Burp στη διεύθυνση `127.0.0.1:8080`. Επομένως, αιτήματα που δημιουργούνται απευθείας από ένα εργαλείο MCP μπορεί να μην εμφανίζονται στο **Proxy > HTTP history**· χρησιμοποιήστε τον browser μέσω proxy όποτε πρέπει να είναι ορατό, επεξεργάσιμο ή να διατηρηθεί ως αποδεικτικό στοιχείο το αίτημα/η απόκριση.<sup>[[2]](#references)[[9]](#references)</sup>

Ένας client με υποστήριξη SSE μπορεί να καταχωρίσει απευθείας το Burp. Ένας client που υποστηρίζει μόνο stdio μπορεί αντί γι' αυτό να εκκινήσει το proxy JAR της PortSwigger. Και στις δύο περιπτώσεις, καταχωρίστε ένα δεύτερο MCP για τον έλεγχο του browser και συνδέστε το με το ενσωματωμένο Chromium του Burp (το `BURP_CHROMIUM` είναι μια τοπική διαδρομή εκτελέσιμου αρχείου):<sup>[[9]](#references)</sup>

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

Η σημαία TLS-bypass δέχεται πιστοποιητικά που δημιουργούνται από το proxy παρεμβολής, ενώ το `--isolated` εμποδίζει την αξιολόγηση να επαναχρησιμοποιήσει το συνηθισμένο προφίλ browser του χειριστή. Η απομόνωση προστατεύει την κατάσταση του προφίλ, αλλά **δεν αποτελεί sandbox ασφαλείας**: ο controller εξακολουθεί να έχει πρόσβαση σε authenticated sessions που έχουν ανοιχτεί σε αυτόν τον browser δοκιμών, ενώ το Burp MCP μπορεί να εκθέσει ευαίσθητα requests, responses και ρυθμίσεις.<sup>[[9]](#references)</sup>

Ελέγξτε ανεξάρτητα τον listener SSE πριν διερευνήσετε προβλήματα στο client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Ένας υγιής listener επιστρέφει `Content-Type: text/event-stream`. Είναι αναμενόμενο να υπάρξει timeout μετά τις κεφαλίδες, καθώς ένα SSE stream παραμένει ανοιχτό για μελλοντικά συμβάντα. Αν ο client εξακολουθεί να αποτυγχάνει, επιβεβαιώστε τη διαδρομή που έχει ρυθμιστεί στην επέκταση: η PortSwigger σημειώνει ότι το endpoint μπορεί να είναι η διαδρομή root ή `/sse`, ανάλογα με τον client και τη ρύθμιση της επέκτασης.<sup>[[9]](#references)[[7]](#references)</sup>

## Χρήση διαφορετικών clients

### Codex CLI

- Ρυθμίστε το `~/.codex/config.toml` όπως παραπάνω.
- Εκτελέστε το `codex` και έπειτα το `/mcp` για να επαληθεύσετε τη λίστα εργαλείων Burp.

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

## Replay και επικύρωση βάσει αποδεικτικών στοιχείων

Μην αφήνετε τον agent να θεωρεί μια εύλογη εξήγηση ή μια ενδιάμεση απόκριση ως απόδειξη. Χρησιμοποιείτε αιτήματα/αποκρίσεις του Burp και την κατάσταση του browser που παρατηρείτε ανεξάρτητα, ώστε κάθε δοκιμή να μπορεί να διαψευστεί.<sup>[[8]](#references)</sup>

1. Αποθηκεύστε ένα αρχικό ζεύγος αιτήματος/απόκρισης και προσδιορίστε το ακριβές στοιχείο που ελέγχεται από τον επιτιθέμενο.
2. Για συγκρίσεις εξουσιοδότησης, καταγράψτε ανεξάρτητα την ίδια ροή εργασίας και με τους δύο λογαριασμούς πριν τροποποιήσετε αναγνωριστικά, cookies ή tokens.
3. Πριν επαναλάβετε μια τροποποίηση, καταγράψτε την υπόθεση, τη θέση των αποδεικτικών στοιχείων, το αναμενόμενο σήμα και το αποτέλεσμα που θα τη διέψευδε.
4. Τροποποιείτε ένα στοιχείο κάθε φορά, διατηρείτε το ζεύγος που προκύπτει και επισημαίνετε ξεχωριστά τις άμεσες παρατηρήσεις και τα συμπεράσματα.
5. Καταγράφετε κάθε υποψήφια περίπτωση ως `open`, `blocked`, `rejected` ή `confirmed`· επανεξετάζετέ την μόνο όταν νέα αποδεικτικά στοιχεία αλλάζουν τον μηχανισμό ή κάποια προϋπόθεση.
6. Επιβεβαιώνετε τον έλεγχο από τον επιτιθέμενο, την προσβασιμότητα, την επαναληψιμότητα, την παράκαμψη περιορισμών, τον αντίκτυπο και την τελική κατάσταση της εφαρμογής. Μια ανακατεύθυνση ή μια επιτυχής κλήση εργαλείου δεν αποτελεί απόδειξη αν η υποτιθέμενη αλλαγή κατάστασης γίνεται σε επόμενο στάδιο.

Διατηρείτε τις λεπτομέρειες εκμετάλλευσης στη σχετική σελίδα τεχνικής. Για παράδειγμα, οι υποψήφιες περιπτώσεις browser-message ανήκουν στο [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), ενώ η συμπεριφορά επιλογής κλειδιού token ανήκει στο [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Μια συνοπτική καταγραφή υπόθεσης βοηθά τους παράλληλους agents να μην επαναλαμβάνουν την ίδια δελεαστική διαδρομή:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Διαλογή WebSocket frames με Burp MCP

Η επίσημη επέκταση παρέχει το `get_proxy_websocket_history_regex` για αναζητήσεις μόνο για ανάγνωση, με σελιδοποίηση, στο ιστορικό WebSocket του Burp. Δέχεται τα `regex`, `count` και `offset`· σε αντίθεση με το `send_http1_request`, δεν στέλνει WebSocket frame. Το Burp καταγράφει μηνύματα και προς τις δύο κατευθύνσεις, ακόμη κι όταν το Intercept είναι απενεργοποιημένο, επομένως φιλτράρετε το ιστορικό πριν δώσετε στο μοντέλο ένα μικρό σύνολο σχετικών frames.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Εκτελέστε την ίδια ενέργεια που βασίζεται σε WebSocket μέσω του browser που περνά από το Burp proxy, χρησιμοποιώντας δύο ανεξάρτητα αυθεντικοποιημένους δοκιμαστικούς λογαριασμούς. Διατηρήστε μαζί κάθε handshake αναβάθμισης σύνδεσης και τα cookies του, το connection ID, την κατεύθυνση του frame και τα frames απόκρισης· ένα συμβάν από διακομιστή προς πελάτη στη σύνδεση του πρώτου λογαριασμού δεν αποδεικνύει ότι το έλαβε ο δεύτερος λογαριασμός.
2. Αναζητήστε στο `get_proxy_websocket_history_regex` με μια συγκεκριμένη έκφραση, όπως `(?i)(subscribe|room|tenant|objectId)`, `count: 20` και `offset: 0`. Αυξήστε το `offset` για να εξετάσετε μεταγενέστερα αποτελέσματα. Συγκρίνετε το αναγνωριστικό αντικειμένου ή topic του εξερχόμενου frame με την απόκριση στην **ίδια σύνδεση**.
3. Στο **Proxy > WebSockets history**, στείλτε το υποψήφιο εξερχόμενο frame στο Repeater. Συνδέστε το στην κατάλληλη ανοιχτή σύνδεση ή επανασυνδεθείτε χρησιμοποιώντας το handshake του δεύτερου λογαριασμού. Αλλάξτε μόνο το αναγνωριστικό αντικειμένου ή topic και συγκρίνετε τα μηνύματα του διακομιστή και την κατάσταση της εφαρμογής με τις δύο γραμμές βάσης. Το εργαλείο ιστορικού MCP δεν μπορεί να εκτελέσει αυτήν την επανάληψη· το WebSocket Repeater μπορεί να επεξεργαστεί, να ξαναστείλει και να επανασυνδέσει frames.

Για δοκιμές ειδικές για το πρωτόκολλο, όπως cross-site WebSocket hijacking και εξουσιοδότηση topic broker, συνεχίστε στην ενότητα [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Μην εκλαμβάνετε ένα αποδεκτό upgrade ή ένα echo στην πλευρά του client ως απόδειξη ότι πέτυχε μια προστατευμένη εγγραφή.

## Στοχευμένη επικύρωση out-of-band με Burp MCP

Το Burp Suite Professional παρέχει τα `generate_collaborator_payload` και `get_collaborator_interactions` μέσω της επίσημης επέκτασης MCP. Συνδυάστε τα με το `get_proxy_http_history_regex` και μία επανάληψη με `send_http1_request` για να ελέγξετε μια ύποπτη ανάκτηση URL από την πλευρά του διακομιστή, χωρίς να σαρώσετε ολόκληρο τον στόχο. Το Burp ενδέχεται να απαιτεί ξεχωριστή έγκριση για την ανάγνωση του ιστορικού και την αποστολή αιτήματος.<sup>[[2]](#references)[[10]](#references)</sup>

1. Φιλτράρετε το ιστορικό για ένα υποψήφιο αίτημα που περιέχει URL, όπως ένα με `url=`, `webhook` ή `callback`. Αποθηκεύστε το αρχικό αίτημα και την απόκριση. Το εργαλείο ιστορικού δέχεται τα `regex`, `count` και `offset`· χρησιμοποιήστε σελιδοποίηση αντί να ζητήσετε από το μοντέλο να εξετάσει κάθε εγγραφή.<sup>[[10]](#references)</sup>
2. Δημιουργήστε ένα νέο Collaborator payload και διατηρήστε το **payload ID** που επιστρέφεται. Επαναλάβετε το καταγεγραμμένο αίτημα προς τον ίδιο host και port, αλλάζοντας μόνο το υποψήφιο URL σε ένα HTTPS URL κάτω από το συγκεκριμένο payload domain. Για το `send_http1_request`, περάστε ολόκληρο το αίτημα HTTP/1.1 ως `content`, μαζί με τα `targetHostname`, `targetPort` και `usesHttps`· τα πεδία προορισμού προσδιορίζουν την **εφαρμογή**, όχι τον host του Collaborator.<sup>[[10]](#references)</sup>
3. Κάντε polling στο `get_collaborator_interactions` με αυτό το payload ID και συσχετίστε την ώρα της αλληλεπίδρασης με την επανάληψη. Μια αλληλεπίδραση HTTP υποστηρίζει ότι έγινε ανάκτηση, ενώ μόνο DNS υποδεικνύει επίλυση ονόματος, όχι ολοκληρωμένο αίτημα HTTP. Ελέγξτε την πηγή της αλληλεπίδρασης και τις κεφαλίδες του αιτήματος για να ξεχωρίσετε την εξερχόμενη κίνηση του διακομιστή από τη φόρτωση στην πλευρά του browser και, στη συνέχεια, επαναλάβετε με νέο payload για να αποκλείσετε άσχετη κίνηση.<sup>[[10]](#references)[[11]](#references)</sup>

Το εργαλείο αιτημάτων MCP επιστρέφει απευθείας την απόκριση και ενδέχεται να μην καταχωρίσει το αίτημα στο **Proxy > HTTP history**. Διατηρήστε το αποτέλεσμα αιτήματος/απόκρισης ή χρησιμοποιήστε τον browser που περνά από το proxy ή το Repeater για τεκμήριο που βασίζεται στο ιστορικό. Για την επιλογή SSRF payloads και τις επακόλουθες δοκιμές, χρησιμοποιήστε το [κεφάλαιο SSRF](../pentesting-web/ssrf-server-side-request-forgery/) αντί να θεωρήσετε ότι ένα out-of-band callback αποδεικνύει επίπτωση στο εσωτερικό δίκτυο. Για δοκιμές του ίδιου του MCP server, δείτε τη [δοκιμή MCP server](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Prompt pack για παθητική επισκόπηση

Το repo **burp-mcp-agents** περιλαμβάνει πρότυπα prompt για ανάλυση της κίνησης Burp με βάση τα τεκμήρια:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ευρεία παθητική ανάδειξη ευπαθειών.
- `idor_hunter.md`: αποκλίσεις IDOR/BOLA/αντικειμένου/tenant και ασυμφωνίες αυθεντικοποίησης.
- `auth_flow_mapper.md`: σύγκριση αυθεντικοποιημένων και μη αυθεντικοποιημένων διαδρομών.
- `ssrf_redirect_hunter.md`: υποψήφιες περιπτώσεις SSRF/open-redirect από παραμέτρους ανάκτησης URL/αλυσίδες ανακατευθύνσεων.
- `logic_flaw_hunter.md`: λογικά σφάλματα πολλών βημάτων.
- `session_scope_hunter.md`: κακή χρήση audience/scope token.
- `rate_limit_abuse_hunter.md`: κενά περιορισμού ρυθμού/κατάχρησης.
- `report_writer.md`: σύνταξη αναφορών με έμφαση στα τεκμήρια.

## Προαιρετική προσθήκη ετικέτας απόδοσης

Για να προσθέσετε ετικέτα στην κίνηση Burp/LLM στα logs, προσθέστε έναν κανόνα επανεγγραφής κεφαλίδας (proxy ή Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Σημειώσεις ασφάλειας

- Προτιμήστε **local models** όταν η κίνηση περιέχει ευαίσθητα δεδομένα.
- Κοινοποιείτε μόνο τα ελάχιστα απαραίτητα αποδεικτικά στοιχεία για ένα εύρημα.
- Διατηρείτε το Burp ως την πηγή αλήθειας· χρησιμοποιείτε το μοντέλο για **ανάλυση και αναφορά**, όχι για scanning.

## Burp AI Agent (διαλογή με τη βοήθεια AI + εργαλεία MCP)

Το **Burp AI Agent** είναι ένα extension του Burp που συνδυάζει local/cloud LLMs με παθητική/ενεργή ανάλυση (62 κατηγορίες ευπαθειών) και παρέχει 53+ εργαλεία MCP, ώστε εξωτερικοί MCP clients να μπορούν να ενορχηστρώνουν το Burp.<sup>[[5]](#references)</sup> Κύρια χαρακτηριστικά:

- **Διαλογή από το μενού περιβάλλοντος**: καταγράψτε κίνηση μέσω του Proxy, ανοίξτε το **Proxy > HTTP History**, κάντε δεξί κλικ σε ένα request → **Extensions > Burp AI Agent > Analyze this request** για να ανοίξετε μια συνομιλία AI συνδεδεμένη με το συγκεκριμένο request/response.
- **Backends** (επιλέγονται ανά profile):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: endpoint συμβατό με **OpenAI** (base URL + όνομα μοντέλου).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ή `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (σύνδεση ανάλογα με τον provider).
- **Προφίλ agent**: τα πρότυπα prompt εγκαθίστανται αυτόματα στο `~/.burp-ai-agent/AGENTS/`· τοποθετήστε εκεί επιπλέον αρχεία `*.md` για να προσθέσετε προσαρμοσμένες συμπεριφορές ανάλυσης/scanning.
- **MCP server**: ενεργοποιήστε τον μέσω του **Settings > MCP Server** για να διαθέσετε λειτουργίες του Burp σε οποιονδήποτε MCP client (53+ εργαλεία). Μπορείτε να συνδέσετε το Claude Desktop στον server τροποποιώντας το `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ή το `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Έλεγχοι ιδιωτικότητας**: οι ρυθμίσεις STRICT / BALANCED / OFF αποκρύπτουν ευαίσθητα δεδομένα request πριν από την αποστολή τους σε remote models· προτιμήστε local backends όταν διαχειρίζεστε secrets.
- **Καταγραφή ελέγχου**: αρχεία καταγραφής JSONL με κατακερματισμό ακεραιότητας SHA-256 ανά εγγραφή, για ανιχνεύσιμη παραβίαση ιχνηλασιμότητα ενεργειών AI/MCP.
- **Build/load**: κατεβάστε το JAR της έκδοσης ή κάντε build με Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Προφυλάξεις λειτουργίας: τα cloud backends ενδέχεται να διαρρεύσουν session cookies/PII, εκτός αν είναι ενεργοποιημένη η λειτουργία απορρήτου· η έκθεση του MCP παρέχει δυνατότητα απομακρυσμένου orchestration του Burp, επομένως περιορίστε την πρόσβαση σε έμπιστους agents και παρακολουθείτε το αρχείο καταγραφής ελέγχου με hash ακεραιότητας.



## References

- [1] [Ενσωμάτωση Burp MCP + Codex CLI και διόρθωση handshake του Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp του Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Ζήτημα αυστηρής επικύρωσης Origin/header στον MCP server του PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [MCP Server του PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Πώς να χρησιμοποιήσετε το Codex για έρευνα Bug Bounty: ευρεία διερεύνηση, αυστηρή επικύρωση](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orchestration του Burp Suite για Claude Code και Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Υλοποιήσεις εργαλείων και παράμετροι του MCP Server του PortSwigger](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - ευπάθειες Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - ιστορικό WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Εργασία με μηνύματα WebSocket στο Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
