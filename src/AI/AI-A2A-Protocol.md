# Ασφάλεια του πρωτοκόλλου A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το A2A

Το A2A (Agent2Agent) είναι ένα ανοιχτό πρωτόκολλο που επιτρέπει σε έναν AI agent να ανακαλύπτει άλλους agents και να τους αναθέτει εργασίες μέσω HTTP. Το MCP συνδέει έναν agent με **εργαλεία και δεδομένα**· το A2A συνδέει έναν agent με **άλλους agents**, οι οποίοι είναι συνήθως απομακρυσμένες υπηρεσίες που ανήκουν σε άλλη ομάδα ή εταιρεία. Ένας διακομιστής A2A είναι ένα web API με έναν LLM agent στο παρασκήνιο, επομένως τα αντικείμενα του ίδιου του πρωτοκόλλου (agent cards, tasks, push-notification webhooks, extended cards) προσθέτουν συγκεκριμένους ελέγχους για authentication, IDOR και SSRF σε έναν τυπικό έλεγχο API.<sup>[[1]](#references)[[2]](#references)</sup>

Τα κύρια στοιχεία είναι:

- **Agent Card:** ένα έγγραφο JSON που περιγράφει τον agent: όνομα, περιγραφή, δεξιότητες, URL υπηρεσιών, υποστηριζόμενα transports, δυνατότητες (streaming, push notifications, extended card) και τα `securitySchemes` που πρέπει να χρησιμοποιήσει ο client. Δημοσιεύεται στη διεύθυνση `https://<host>/.well-known/agent-card.json`. Παλαιότερες εγκαταστάσεις που ακολουθούν το spec 0.2.x χρησιμοποιούν το `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** η μονάδα εργασίας. Ένα μήνυμα δημιουργεί ένα task (με `id` και `contextId` που δημιουργούνται από τον server), και ο client μπορεί αργότερα να το διαβάσει, να το ακυρώσει ή να εγγραφεί σε αυτό.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 μέσω HTTP (με SSE για streaming), gRPC και ένα REST binding HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentication:** τα διαπιστευτήρια μεταφέρονται σε HTTP headers (για παράδειγμα, `Authorization: Bearer ...`), ποτέ μέσα στο payload JSON-RPC. Το agent card καθορίζει ποιο scheme απαιτείται.<sup>[[1]](#references)</sup>

Τα ονόματα των μεθόδων άλλαξαν μεταξύ των εκδόσεων, οπότε δοκιμάστε και τα δύο σύνολα:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Λειτουργία | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Αποστολή μηνύματος | `message/send` | `SendMessage` | `POST /message:send` |
| Αποστολή με streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Λήψη task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Λίστα tasks | - | `ListTasks` | `GET /tasks` |
| Ακύρωση task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Ρύθμιση push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Το spec 1.0 χρησιμοποιεί το header `A2A-Version` (ή μια παράμετρο αιτήματος) για την επιλογή της έκδοσης, ενώ τα αιτήματα χωρίς αυτό αντιμετωπίζονται ως 0.3.<sup>[[1]](#references)</sup>

## Ανακάλυψη

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Από την κάρτα, σημειώστε:

- Κάθε `url` υπηρεσίας (συχνά ένα εσωτερικό hostname, ένα staging URL ή μια διαφορετική θύρα από αυτή του δημόσιου site).
- `skills`: δείχνουν τι μπορεί να κάνει ο agent και ποια εργαλεία ή δεδομένα βρίσκονται πίσω του.
- `securitySchemes` / `security`: αν είναι κενά ή απουσιάζουν, ο agent πιθανότατα προορίζεται να καλείται χωρίς credentials.
- `capabilities.pushNotifications` και `capabilities.extendedAgentCard` (στην έκδοση 0.3, `supportsAuthenticatedExtendedCard`).

Η προδιαγραφή αναφέρει ότι η δημόσια κάρτα δεν πρέπει να περιέχει credentials ή εσωτερικές λεπτομέρειες υλοποίησης, επομένως τα εσωτερικά URL, τα κλειδιά ή οι λεπτομερείς λίστες εργαλείων σε μια δημόσια κάρτα αποτελούν ήδη εύρημα.<sup>[[1]](#references)</sup>

## Έλεγχος A2A endpoints

### Υποβολή task χωρίς authentication

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

Ένα αποτέλεσμα `Task` ή `Message` με `PONG`, όταν η κάρτα δηλώνει ένα security scheme, σημαίνει ότι ο έλεγχος ταυτότητας δεν επιβάλλεται στο RPC endpoint (ενδέχεται να επιβάλλεται μόνο στο UI ή στην κάρτα). Αν η κάρτα δεν δηλώνει scheme, ελέγξτε τι μπορούν να προσπελάσουν τα skills του agent: ένας agent χωρίς έλεγχο ταυτότητας που μπορεί να διαβάζει εσωτερικά δεδομένα ή να καλεί εργαλεία ισοδυναμεί με ένα API χωρίς έλεγχο ταυτότητας για αυτά τα εργαλεία.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Η προδιαγραφή απαιτεί από τον server να ελέγχει, σε κάθε αίτημα, ότι ο καλών μπορεί να έχει πρόσβαση στο task, καθώς και να περιορίζει το `ListTasks` στα task του καλούντος, ακόμη και όταν δεν παρέχεται φίλτρο.<sup>[[1]](#references)</sup> Δοκιμάστε το με δύο ταυτότητες (A και B):

1. Ως A, δημιουργήστε ένα task και αποθηκεύστε τα `id` και `contextId` του.
2. Ως B (ή χωρίς διαπιστευτήρια), καλέστε το `tasks/get` / `GetTask` με το `id` του A και, στη συνέχεια, το `ListTasks` χωρίς παραμέτρους.
3. Δοκιμάστε επίσης να ακυρώσετε το task του A και να εγγραφείτε σε αυτό, καθώς και να στείλετε ένα νέο μήνυμα ως B που περιλαμβάνει το `taskId` ή το `contextId` του A (έτσι το κείμενο του B θα προστεθεί στη συνομιλία του A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Ευάλωτο: Το B λαμβάνει το ιστορικό, τα artifacts ή την κατάσταση του A ή μπορεί να αλλάξει το task του A. Ασφαλές: επιστρέφεται ένα `TaskNotFoundError`, χωρίς να διακρίνεται η περίπτωση «υπάρχει αλλά δεν είναι δικό σου» από την περίπτωση «δεν υπάρχει».<sup>[[1]](#references)</sup> Τα Task IDs είναι συχνά UUID, οπότε αναζητήστε τα σε σημεία όπου κάνουν leak (κοινόχρηστοι σύνδεσμοι, logs, payloads ειδοποιήσεων push, μηνύματα σφάλματος).

### SSRF στο webhook ειδοποιήσεων push

Όταν το `capabilities.pushNotifications` είναι true, ο client δίνει στον agent ένα URL webhook και στη συνέχεια ο agent στέλνει αιτήματα `POST` με ενημερώσεις task σε αυτό το URL. Η προδιαγραφή αναφέρει ότι οι agents πρέπει να απορρίπτουν ιδιωτικά ranges, localhost και link-local διευθύνσεις, καθώς και να χρησιμοποιούν allowlists.<sup>[[1]](#references)</sup> Δημιουργήστε ένα task, καταχωρίστε μια ρύθμιση ειδοποιήσεων push με `url` που δείχνει στον OAST host σας για να επιβεβαιώσετε τα εξερχόμενα αιτήματα και, έπειτα (μόνο αν το επιτρέπει το scope), δοκιμάστε εσωτερικούς στόχους όπως `http://127.0.0.1:<port>/` ή `http://169.254.169.254/`. Συγκρίνετε τα σφάλματα και τους χρόνους απόκρισης για να χαρτογραφήσετε εσωτερικές υπηρεσίες. Ο agent προσθέτει επίσης την καθορισμένη κεφαλίδα authentication σε αυτά τα αιτήματα, γι' αυτό ελέγξτε ότι δεν αποστέλλεται σε host που έχει επιλέξει ο attacker, όταν μπορείτε να αλλάξετε το URL της ρύθμισης άλλου χρήστη. Δείτε το [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Πρόσβαση στην εκτεταμένη κάρτα agent

Το `GetExtendedAgentCard` πρέπει να απαιτεί authentication και μπορεί να επιστρέφει περισσότερα skills και ρυθμίσεις από τη δημόσια κάρτα.<sup>[[1]](#references)</sup> Καλέστε το χωρίς credentials και με identity χαμηλών προνομίων και συγκρίνετε το αποτέλεσμα με τη δημόσια κάρτα.

### Ρύθμιση ειδοποιήσεων push και διαρροές credentials εντός task

Οι ρυθμίσεις ειδοποιήσεων push αποθηκεύουν ένα URL webhook και τα credentials που στέλνει ο agent σε αυτό. Η προδιαγραφή απαιτεί κάθε λειτουργία ρύθμισης ειδοποιήσεων push (create, get, list, delete) να επαληθεύει ότι ο caller μπορεί να έχει πρόσβαση στο task.<sup>[[1]](#references)</sup> Επαναλάβετε σε αυτά τα routes τη δοκιμή με δύο identities από την [ενότητα task IDOR](#task-idor-tasksget-gettask-cancel-subscribe). Μια ρύθμιση άλλου χρήστη που είναι αναγνώσιμη κάνει leak ένα webhook token, ενώ μια εγγράψιμη ρύθμιση ανακατευθύνει τις ενημερώσεις task αυτού του χρήστη στον host σας.

Όταν ένας agent χρειάζεται πρόσθετη εξουσιοδότηση κατά τη διάρκεια ενός task, μεταφέρει το task στην κατάσταση `TASK_STATE_AUTH_REQUIRED`. Ο client μπορεί να διευθετήσει την εξουσιοδότηση out of band· η προδιαγραφή αναφέρει ότι οι agents πρέπει να λαμβάνουν credentials out of band, εκτός αν έχει συμφωνηθεί μηχανισμός in-band. Η ανταλλαγή in-band μπορεί να μεταφέρει ένα credential μέσω μιας αλυσίδας A2A agents και να το εκθέσει σε κάθε agent αυτής της αλυσίδας.<sup>[[1]](#references)</sup> Σε μια δοκιμή orchestrator, ελέγξτε αν ένα credential που δίνει ο χρήστης για έναν downstream agent εμφανίζεται σε μηνύματα, artifacts ή στο ιστορικό task, στα οποία μπορούν να έχουν πρόσβαση άλλοι agents (ή άλλοι χρήστες μέσω task IDOR).

Τα πεδία της κάρτας agent και τα αποτελέσματα των task είναι επίσης μη έμπιστες είσοδοι για τον agent που τα καλεί. Δοκιμάστε τα με τις τεχνικές έμμεσης prompt injection στο [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) και τους ελέγχους εμπιστοσύνης μεταξύ agents στο [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Προδιαγραφή πρωτοκόλλου A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Ιστολόγιο Google Developers — Ανακοίνωση του πρωτοκόλλου Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Προδιαγραφή A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Προδιαγραφή A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
