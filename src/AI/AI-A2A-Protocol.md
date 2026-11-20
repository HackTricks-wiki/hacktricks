# Ασφάλεια πρωτοκόλλου A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το A2A

Το A2A (Agent2Agent) είναι ένα ανοιχτό πρωτόκολλο που επιτρέπει σε έναν AI agent να εντοπίζει έναν άλλο agent και να του αναθέτει εργασία μέσω HTTP. Το MCP συνδέει έναν agent με **tools και δεδομένα**· το A2A συνδέει έναν agent με **άλλους agents**, οι οποίοι είναι συνήθως απομακρυσμένες υπηρεσίες που ανήκουν σε άλλη ομάδα ή εταιρεία. Ένας A2A server είναι ένα web API με έναν LLM agent στο παρασκήνιο, επομένως τα ίδια τα αντικείμενα του πρωτοκόλλου (agent cards, tasks, webhooks ειδοποιήσεων push, extended cards) προσθέτουν συγκεκριμένους ελέγχους authentication, IDOR και SSRF σε έναν συνηθισμένο έλεγχο API.<sup>[[1]](#references)[[2]](#references)</sup>

Τα κύρια στοιχεία είναι:

- **Agent Card:** ένα έγγραφο JSON που περιγράφει τον agent: όνομα, περιγραφή, skills, URL υπηρεσίας/υπηρεσιών, υποστηριζόμενα transports, δυνατότητες (streaming, ειδοποιήσεις push, extended card) και τα `securitySchemes` που πρέπει να χρησιμοποιήσει ο client. Δημοσιεύεται στο `https://<host>/.well-known/agent-card.json`. Οι παλαιότερες εγκαταστάσεις που ακολουθούν την προδιαγραφή 0.2.x χρησιμοποιούν το `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** η μονάδα εργασίας. Ένα μήνυμα δημιουργεί ένα task (με `id` που δημιουργεί ο server και ένα `contextId`), και στη συνέχεια ο client το διαβάζει, το ακυρώνει ή εγγράφεται για ενημερώσεις σχετικά με αυτό.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 μέσω HTTP (με SSE για streaming), gRPC και μια σύνδεση REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentication:** τα διαπιστευτήρια μπαίνουν στις HTTP headers (για παράδειγμα, `Authorization: Bearer ...`), ποτέ μέσα στο JSON-RPC payload. Η agent card αναφέρει ποιο scheme απαιτείται.<sup>[[1]](#references)</sup>

Τα ονόματα των methods άλλαξαν μεταξύ των εκδόσεων, επομένως δοκιμάστε και τα δύο σύνολα:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Λειτουργία | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Αποστολή μηνύματος | `message/send` | `SendMessage` | `POST /message:send` |
| Αποστολή με streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Λήψη task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Λίστα tasks | - | `ListTasks` | `GET /tasks` |
| Ακύρωση task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Διαμόρφωση ειδοποιήσεων push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3)· HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Η προδιαγραφή 1.0 χρησιμοποιεί την header `A2A-Version` (ή μια παράμετρο αιτήματος) για να επιλέξει την έκδοση, ενώ τα αιτήματα χωρίς αυτήν αντιμετωπίζονται ως έκδοση 0.3.<sup>[[1]](#references)</sup>

## Ανακάλυψη

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Από την κάρτα, σημειώστε:

- Κάθε `url` υπηρεσίας: στην έκδοση 1.0 βρίσκονται στο `supportedInterfaces`, ενώ παλαιότερες κάρτες μπορεί να εκθέτουν ένα `url` στο κορυφαίο επίπεδο. Καταγράψτε κάθε endpoint και transport, συμπεριλαμβανομένων των εσωτερικών hostnames, των staging URLs και των εναλλακτικών ports.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: δείχνουν τι μπορεί να κάνει ο agent και ποια εργαλεία ή δεδομένα βρίσκονται πίσω του.
- `securitySchemes` / `security`: αν είναι κενά ή απουσιάζουν, πιθανότατα ο agent προορίζεται για κλήση χωρίς credentials.
- `capabilities.pushNotifications` και `capabilities.extendedAgentCard` (στην έκδοση 0.3 `supportsAuthenticatedExtendedCard`).

Το spec αναφέρει ότι η δημόσια κάρτα δεν πρέπει να περιέχει credentials ή λεπτομέρειες εσωτερικής υλοποίησης, επομένως τα εσωτερικά URLs, τα keys ή οι λεπτομερείς λίστες εργαλείων σε μια δημόσια κάρτα αποτελούν ήδη εύρημα.<sup>[[1]](#references)</sup>

### Σύγκρουση ονομάτων Agent Card σε host πολλών agents

Το `name` μιας κάρτας είναι μια ετικέτα αναγνώσιμη από άνθρωπο, όχι μια σταθερή ταυτότητα δρομολόγησης.<sup>[[1]](#references)[[5]](#references)</sup> Αν ένας host καταχωρίσει δύο διαφορετικά remote peers με το ίδιο τοπικό όνομα, το agent tree, το παραγόμενο όνομα εργαλείου, το client map ή το broker route μπορεί να στείλει μια εργασία που προορίζεται για το έμπιστο peer στο άλλο peer.<sup>[[5]](#references)</sup> Αυτό απαιτεί το peer που ελέγχει ο attacker να γίνει δεκτό στον **ίδιο χώρο ονομάτων δρομολόγησης**· η δημοσίευση μιας διπλότυπης κάρτας στο Internet από μόνη της δεν αρκεί.<sup>[[5]](#references)</sup>

Ελέγξτε τη διαδρομή **από την αποδοχή έως τη διανομή** του host χρησιμοποιώντας δύο peers που ελέγχετε, διαφορετικά URLs και έναν ακίνδυνο marker:<sup>[[5]](#references)</sup>

1. Καταγράψτε την κάρτα, το origin και τον τοπικό selector του έμπιστου peer. Καταχωρίστε ένα δεύτερο peer του οποίου η κάρτα έχει το ίδιο `name`, αλλά το URL του δείχνει σε endpoint που ελέγχετε.
2. Ενεργοποιήστε τη λειτουργία που επιλέγει το έμπιστο peer βάσει ονόματος. Δοκιμάστε και τις δύο σειρές καταχώρισης και, αν τα ονόματα γίνονται αναγνωριστικά εργαλείων, τη συνήθη κανονικοποίηση ονομάτων του host. Καταγράψτε ποιο endpoint λαμβάνει τον marker και ποιος agent επιστρέφει την απάντηση.
3. Αλλάξτε μόνο το όνομα της δεύτερης κάρτας και επαναλάβετε. Αν ένα αίτημα φτάσει στο δεύτερο endpoint μόνο στην περίπτωση σύγκρουσης, αυτό αποδεικνύει διανομή σε λάθος peer. Ελέγξτε ξεχωριστά αν μεταφέρθηκε πράγματι ευαίσθητο context ή credential· η σύγκρουση ονομάτων από μόνη της **δεν** αποδεικνύει μεταφορά credentials ή εξουσίας χρήσης εργαλείων.

Αν ο caller απευθύνεται σε ένα σταθερό endpoint δεσμευμένο στο origin, αντί να επιλύει ένα όνομα κάρτας, αυτή η δοκιμή δεν εφαρμόζεται.<sup>[[5]](#references)</sup> Για τις επόμενες κακόβουλες απαντήσεις peer και τον αντίκτυπο του prompt injection, ακολουθήστε τη [Μεθοδολογία Ασφάλειας AI Agent](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Δοκιμή A2A endpoints

### Υποβολή εργασίας χωρίς authentication

Στείλτε ένα ελάχιστο μήνυμα χωρίς credentials σε κάθε `url` που αναφέρεται στην κάρτα:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Ένα αποτέλεσμα `Task` ή `Message` με `PONG`, όταν η κάρτα δηλώνει ένα security scheme, σημαίνει ότι δεν επιβάλλεται authentication στο RPC endpoint (ενδέχεται να επιβάλλεται μόνο στο UI ή στην κάρτα). Αν η κάρτα δεν δηλώνει κανένα scheme, ελέγξτε σε τι έχουν πρόσβαση τα skills του agent: ένας agent χωρίς authentication που μπορεί να διαβάσει εσωτερικά δεδομένα ή να καλέσει εργαλεία ισοδυναμεί με ένα unauthenticated API για αυτά τα εργαλεία.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Η προδιαγραφή απαιτεί από τον server να ελέγχει, σε κάθε request, αν ο caller έχει πρόσβαση στο task, και να περιορίζει το `ListTasks` στα tasks του caller ακόμα και όταν δεν δίνεται κανένα φίλτρο.<sup>[[1]](#references)</sup> Ελέγξτε το με δύο identities (A και B):

1. Ως A, δημιουργήστε ένα task και αποθηκεύστε τα `id` και `contextId` του.
2. Ως B (ή χωρίς credentials), καλέστε `tasks/get` / `GetTask` με το `id` του A και, στη συνέχεια, το `ListTasks` χωρίς παραμέτρους.
3. Δοκιμάστε επίσης τα cancel και subscribe στο task του A, και στείλτε ένα νέο message ως B που περιλαμβάνει το `taskId` ή το `contextId` του A (έτσι το κείμενο του B θα προστεθεί στη συνομιλία του A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Ευάλωτο: Ο B λαμβάνει το ιστορικό, τα artifacts ή την κατάσταση του A, ή μπορεί να αλλάξει το task του A. Ασφαλές: επιστρέφεται `TaskNotFoundError`, χωρίς διαφορά μεταξύ «υπάρχει αλλά δεν είναι δικό σου» και «δεν υπάρχει».<sup>[[1]](#references)</sup> Τα Task IDs είναι συχνά UUID, οπότε αναζήτησέ τα σε σημεία όπου κάνουν leak (shared links, logs, push notification payloads, μηνύματα σφάλματος).

### SSRF μέσω webhook push notification

Όταν το `capabilities.pushNotifications` είναι true, ο client δίνει στον agent ένα webhook URL και ο agent αργότερα στέλνει αιτήματα `POST` με ενημερώσεις task σε αυτό το URL. Το spec λέει ότι οι agents πρέπει να απορρίπτουν private ranges, localhost και link-local διευθύνσεις, και να χρησιμοποιούν allowlists.<sup>[[1]](#references)</sup> Δημιούργησε ένα task, καταχώρισε ένα push notification config του οποίου το `url` δείχνει στο OAST host σου για να επιβεβαιώσεις τα εξερχόμενα αιτήματα και, στη συνέχεια (μόνο αν το επιτρέπει το scope), δοκίμασε εσωτερικούς στόχους όπως `http://127.0.0.1:<port>/` ή `http://169.254.169.254/`. Σύγκρινε τα σφάλματα και τους χρόνους απόκρισης για να χαρτογραφήσεις εσωτερικές υπηρεσίες. Ο agent προσθέτει επίσης το configured authentication header σε αυτά τα αιτήματα, οπότε έλεγξε ότι δεν αποστέλλεται σε host που έχει επιλέξει attacker, όταν μπορείς να αλλάξεις το URL του config άλλου χρήστη. Δες [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Τα File-URL Parts ως δεύτερο σημείο εισόδου SSRF

Το A2A 1.0 επιτρέπει σε ένα μήνυμα ή artifact να περιέχει αναφορά σε αρχείο ως `Part` με `url` (το 0.3 χρησιμοποιεί `kind: "file"` και `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Το πρωτόκολλο μεταφέρει την αναφορά· η ανάκτησή της είναι συμπεριφορά της εφαρμογής και όχι απαίτηση του A2A SDK.<sup>[[6]](#references)</sup> Αυτό είναι ξεχωριστό από το URL του callback push notification παραπάνω. Δοκίμασε και τις δύο κατευθύνσεις: ένα αρχείο που παρέχει ο client και στέλνεται σε A2A server, και ένα file URL που επιστρέφεται από peer χαμηλότερου trust σε orchestrator.<sup>[[1]](#references)[[6]](#references)</sup>

Για ένα εξουσιοδοτημένο endpoint 1.0 JSON-RPC, αντικατάστησε το κανονικό text part με ένα URL σε μοναδικό OAST path και έλεγξε **ποιο component** κάνει το αίτημα:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Μόνο αν ο παραλήπτης κάνει dereference, δοκιμάστε εσωτερικούς προορισμούς εντός του πεδίου, ανακατευθύνσεις και αλλαγές στην επίλυση DNS χρησιμοποιώντας τη [ροή εργασίας SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Ένα έγκυρο `Part` ή μια επιτυχής απόκριση εργασίας από μόνο του δεν αποδεικνύει SSRF· επιβεβαιώστε ότι έγινε ανάκτηση στον προορισμό και αν το περιεχόμενο που ανακτήθηκε φτάνει στον agent.<sup>[[6]](#references)</sup>

### Πρόσβαση σε εκτεταμένη κάρτα agent

Το `GetExtendedAgentCard` πρέπει να απαιτεί authentication και μπορεί να επιστρέψει περισσότερες δεξιότητες και ρυθμίσεις από τη δημόσια κάρτα.<sup>[[1]](#references)</sup> Καλέστε το χωρίς διαπιστευτήρια και με ταυτότητα χαμηλών δικαιωμάτων και συγκρίνετε το αποτέλεσμα με τη δημόσια κάρτα.

### Ρυθμίσεις ειδοποιήσεων push και διαρροές διαπιστευτηρίων κατά την εργασία

Οι ρυθμίσεις ειδοποιήσεων push αποθηκεύουν ένα URL webhook και τα διαπιστευτήρια που στέλνει ο agent σε αυτό. Η προδιαγραφή απαιτεί κάθε λειτουργία ρύθμισης ειδοποιήσεων push (create, get, list, delete) να επαληθεύει ότι ο καλών έχει δικαίωμα πρόσβασης στην εργασία.<sup>[[1]](#references)</sup> Επαναλάβετε σε αυτές τις διαδρομές τη δοκιμή με τις δύο ταυτότητες από την [ενότητα task IDOR](#task-idor-tasksget-gettask-cancel-subscribe). Μια ρύθμιση άλλου χρήστη που είναι αναγνώσιμη διαρρέει ένα token webhook, ενώ μια ρύθμιση που είναι εγγράψιμη ανακατευθύνει τις ενημερώσεις εργασίας του χρήστη στον δικό σας host.

Όταν ένας agent χρειάζεται επιπλέον εξουσιοδότηση κατά τη διάρκεια μιας εργασίας, μεταφέρει την εργασία στην κατάσταση `TASK_STATE_AUTH_REQUIRED`. Ο client μπορεί να διευθετήσει την εξουσιοδότηση εκτός ζώνης· η προδιαγραφή ορίζει ότι οι agents πρέπει να λαμβάνουν διαπιστευτήρια εκτός ζώνης, εκτός αν έχει συμφωνηθεί μηχανισμός εντός ζώνης. Η ανταλλαγή εντός ζώνης μπορεί να μεταφέρει ένα διαπιστευτήριο μέσω μιας αλυσίδας agents A2A και να το εκθέσει σε κάθε agent αυτής της αλυσίδας.<sup>[[1]](#references)</sup> Σε δοκιμή orchestrator, ελέγξτε αν ένα διαπιστευτήριο που δίνει ο χρήστης για έναν downstream agent εμφανίζεται σε μηνύματα, artifacts ή στο ιστορικό εργασίας, στα οποία μπορούν να έχουν πρόσβαση άλλοι agents (ή άλλοι χρήστες μέσω task IDOR).

Τα πεδία της κάρτας agent και τα αποτελέσματα εργασιών αποτελούν επίσης μη έμπιστη είσοδο για τον agent που τα καλεί. Δοκιμάστε τα με τις τεχνικές έμμεσης prompt injection στο [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) και τους ελέγχους εμπιστοσύνης μεταξύ agents στο [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Προδιαγραφή Πρωτοκόλλου A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Ιστολόγιο Google Developers — Ανακοίνωση του Πρωτοκόλλου Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Προδιαγραφή A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Προδιαγραφή A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Επιθέσεις σύγκρουσης ονομάτων agent σε συστήματα πολλαπλών agents](https://arxiv.org/abs/2609.27624)
- [6] [Οδηγός ασφάλειας A2A .NET SDK](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Οδηγός μετάβασης A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
