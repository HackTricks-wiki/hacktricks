# Κίνδυνοι AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Οwasp έχει εντοπίσει τις κορυφαίες 10 ευπάθειες μηχανικής μάθησης που μπορούν να επηρεάσουν συστήματα AI. Αυτές οι ευπάθειες μπορούν να οδηγήσουν σε διάφορα ζητήματα ασφάλειας, συμπεριλαμβανομένου poisoning δεδομένων, model inversion και adversarial attacks. Η κατανόηση αυτών των ευπαθειών είναι κρίσιμη για την κατασκευή ασφαλών συστημάτων AI.

Για μια ενημερωμένη και λεπτομερή λίστα των top 10 machine learning vulnerabilities, ανατρέξτε στο [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Ένας επιτιθέμενος προσθέτει μικρές, συχνά αόρατες αλλαγές στα **incoming data** ώστε το μοντέλο να παίρνει λάθος απόφαση.\
*Παράδειγμα*: Μερικές σταγόνες μπογιάς σε ένα stop‑sign ξεγελούν ένα self‑driving αυτοκίνητο ώστε να "βλέπει" ένα speed‑limit sign.

- **Data Poisoning Attack**: Το **training set** μολύνεται σκόπιμα με κακά δείγματα, διδάσκοντας στο μοντέλο βλαβερούς κανόνες.\
*Παράδειγμα*: Malware binaries ετικετοποιούνται λανθασμένα ως "benign" σε ένα antivirus training corpus, επιτρέποντας σε παρόμοιο malware να περάσει αργότερα.

- **Model Inversion Attack**: Με το probing των outputs, ένας επιτιθέμενος κατασκευάζει ένα **reverse model** που ανασυγκροτεί ευαίσθητα χαρακτηριστικά των αρχικών inputs.\
*Παράδειγμα*: Επαναδημιουργία της εικόνας MRI ενός ασθενή από τις προβλέψεις ενός cancer‑detection μοντέλου.

- **Membership Inference Attack**: Ο αντίπαλος ελέγχει εάν μια **specific record** χρησιμοποιήθηκε κατά την εκπαίδευση εντοπίζοντας διαφορές στην εμπιστοσύνη (confidence).\
*Παράδειγμα*: Επιβεβαίωση ότι μια τραπεζική συναλλαγή ενός ατόμου εμφανίζεται στα training data ενός fraud‑detection μοντέλου.

- **Model Theft**: Επαναλαμβανόμενα queries επιτρέπουν σε έναν επιτιθέμενο να μάθει decision boundaries και να **clone the model's behavior** (και IP).\
*Παράδειγμα*: Συλλογή αρκετών Q&A ζευγών από ένα ML‑as‑a‑Service API για να δημιουργηθεί ένα σχεδόν ισοδύναμο τοπικό μοντέλο.

- **AI Supply‑Chain Attack**: Παραβίαση οποιουδήποτε συστατικού (data, libraries, pre‑trained weights, CI/CD) στην **ML pipeline** για να μολυνθούν downstream models.\
*Παράδειγμα*: Μια poisoned dependency σε ένα model‑hub εγκαθιστά ένα backdoored sentiment‑analysis model σε πολλές εφαρμογές.

- **Transfer Learning Attack**: Κακόβουλη λογική φυτεύεται σε ένα **pre‑trained model** και επιβιώνει μετά το fine‑tuning για το task του θύματος.\
*Παράδειγμα*: Ένα vision backbone με ένα κρυφό trigger εξακολουθεί να αλλάζει ετικέτες μετά την προσαρμογή του σε medical imaging.

- **Model Skewing**: Λεπτοί προκατειλημμένα ή λανθασμένα επισημασμένα δεδομένα **μετατοπίζουν τα outputs του μοντέλου** προς όφελος της ατζέντας του επιτιθέμενου.\
*Παράδειγμα*: Εισαγωγή "clean" spam emails ετικετοποιημένων ως ham ώστε ένα spam filter να επιτρέπει παρόμοια μελλοντικά emails.

- **Output Integrity Attack**: Ο επιτιθέμενος **τροποποιεί τις προβλέψεις του μοντέλου σε transit**, όχι το ίδιο το μοντέλο, ξεγελώντας downstream συστήματα.\
*Παράδειγμα*: Αλλαγή της verdict ενός malware classifier από "malicious" σε "benign" πριν το στάδιο καραντίνας αρχείων το δει.

- **Model Poisoning** --- Άμεσες, στοχευμένες αλλαγές στις **παραμέτρους του μοντέλου** οι οποίες συχνά γίνονται μετά από απόκτηση write access, για να αλλάξει η συμπεριφορά.\
*Παράδειγμα*: Τροποποίηση των weights σε ένα fraud‑detection μοντέλο σε production ώστε συναλλαγές από συγκεκριμένες κάρτες να εγκρίνονται πάντα.


## Google SAIF Risks

Το [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) της Google περιγράφει διάφορους κινδύνους που σχετίζονται με συστήματα AI:

- **Data Poisoning**: Κακόβουλοι παράγοντες τροποποιούν ή εγχέουν training/tuning data για να υποβαθμίσουν την ακρίβεια, να εμφυτεύσουν backdoors ή να skewάρουν αποτελέσματα, υπονομεύοντας την ακεραιότητα του μοντέλου σε ολόκληρο το data‑lifecycle.

- **Unauthorized Training Data**: Η εισαγωγή copyrighted, sensitive ή μη εξουσιοδοτημένων datasets δημιουργεί νομικές, ηθικές και αποδοτικές ευθύνες επειδή το μοντέλο μαθαίνει από δεδομένα που δεν επιτρεπόταν να χρησιμοποιήσει.

- **Model Source Tampering**: Supply‑chain ή insider manipulation του model code, dependencies ή weights πριν ή κατά τη διάρκεια της εκπαίδευσης μπορεί να ενσωματώσει κρυφή λογική που επιμένει ακόμη και μετά το retraining.

- **Excessive Data Handling**: Αδύναμοι έλεγχοι data‑retention και governance οδηγούν τα συστήματα να αποθηκεύουν ή να επεξεργάζονται περισσότερα προσωπικά δεδομένα από τα απαραίτητα, αυξάνοντας την έκθεση και τον κίνδυνο συμμόρφωσης.

- **Model Exfiltration**: Επιτιθέμενοι κλέβουν model files/weights, προκαλώντας απώλεια intellectual property και επιτρέποντας copy‑cat υπηρεσίες ή επόμενες επιθέσεις.

- **Model Deployment Tampering**: Αντίπαλοι τροποποιούν model artifacts ή serving infrastructure ώστε το running model να διαφέρει από την εγκεκριμένη έκδοση, πιθανώς αλλάζοντας τη συμπεριφορά.

- **Denial of ML Service**: Πλημμύρα APIs ή αποστολή “sponge” inputs μπορεί να εξαντλήσει compute/energy και να ρίξει το μοντέλο offline, μιμούμενο κλασικές DoS επιθέσεις.

- **Model Reverse Engineering**: Συλλέγοντας μεγάλο αριθμό input‑output ζευγών, οι επιτιθέμενοι μπορούν να clone ή να distil το μοντέλο, τροφοδοτώντας imitation προϊόντα και εξατομικευμένες adversarial επιθέσεις.

- **Insecure Integrated Component**: Ευπαθή plugins, agents ή upstream services επιτρέπουν σε επιτιθέμενους να εγχύσουν κώδικα ή να ανεβάσουν προνόμια μέσα στο AI pipeline.

- **Prompt Injection**: Σύνθεση prompts (άμεσα ή έμμεσα) για να smuggle instructions που υπερκαλύπτουν το system intent, αναγκάζοντας το μοντέλο να εκτελέσει ανεπιθύμητες εντολές.

- **Model Evasion**: Εισροές σχεδιασμένες με προσοχή ενεργοποιούν το μοντέλο να mis‑classify, να hallucinate ή να παράγει απαγορευμένο περιεχόμενο, υπονομεύοντας την ασφάλεια και την εμπιστοσύνη.

- **Sensitive Data Disclosure**: Το μοντέλο αποκαλύπτει ιδιωτικές ή εμπιστευτικές πληροφορίες από τα training data ή το user context, παραβιάζοντας την ιδιωτικότητα και κανονισμούς.

- **Inferred Sensitive Data**: Το μοντέλο συμπεραίνει προσωπικά χαρακτηριστικά που ποτέ δεν παρέχονταν, δημιουργώντας νέες ζημιές στην ιδιωτικότητα μέσω inference.

- **Insecure Model Output**: Μη‑sanitized responses μεταβιβάζουν επιβλαβή code, misinformation ή ακατάλληλο περιεχόμενο σε χρήστες ή downstream systems.

- **Rogue Actions**: Αυτονομημένοι agents που ενσωματώνονται εκτελούν ανεπιθύμητες πραγματικές ενέργειες (file writes, API calls, purchases, κ.λπ.) χωρίς επαρκή επίβλεψη χρήστη.


## Mitre AI ATLAS Matrix

Το [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) παρέχει ένα συνολικό πλαίσιο για την κατανόηση και την ελαχιστοποίηση των κινδύνων που συνδέονται με συστήματα AI. Κατηγοριοποιεί διάφορες τεχνικές και tactics που μπορεί να χρησιμοποιήσουν οι αντίπαλοι κατά των AI models και επίσης πώς να χρησιμοποιήσουν συστήματα AI για την εκτέλεση διαφορετικών επιθέσεων.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Επιτιθέμενοι κλέβουν ενεργά session tokens ή cloud API credentials και καλούν πληρωμένα, cloud-hosted LLMs χωρίς εξουσιοδότηση. Η πρόσβαση συχνά μεταπωλείται μέσω reverse proxies που παρεμβάλλονται μπροστά από τον λογαριασμό του θύματος, π.χ. "oai-reverse-proxy" deployments. Οι συνέπειες περιλαμβάνουν οικονομική απώλεια, κακή χρήση του μοντέλου εκτός πολιτικών και attribution στον tenant του θύματος.

TTPs:
- Harvest tokens από μολυσμένα developer machines ή browsers; κλέψτε CI/CD secrets; αγοράστε leaked cookies.
- Στήστε έναν reverse proxy που προωθεί requests στον πραγματικό provider, κρύβοντας το upstream key και multiplexing πολλούς πελάτες.
- Κακοποιήστε άμεσα base‑model endpoints για να παρακάμψετε enterprise guardrails και rate limits.

Mitigations:
- Bind tokens σε device fingerprint, IP ranges, και client attestation; επιβάλετε σύντομες λήξεις και refresh με MFA.
- Scope keys ελάχιστα (no tool access, read‑only όπου εφαρμόζεται); rotate σε περίπτωση ανωμαλίας.
- Τερματίστε όλη την κίνηση server‑side πίσω από policy gateway που εφαρμόζει safety filters, per‑route quotas, και tenant isolation.
- Monitor για ασυνήθιστα usage patterns (ξαφνικά spikes δαπανών, atypical regions, UA strings) και auto‑revoke suspicious sessions.
- Προτιμήστε mTLS ή signed JWTs εκδομένα από το IdP σας αντί για long‑lived static API keys.

## Self-hosted LLM inference hardening

Η εκτέλεση ενός τοπικού LLM server για εμπιστευτικά δεδομένα δημιουργεί μια διαφορετική επιφάνεια επίθεσης από τα cloud-hosted APIs: inference/debug endpoints μπορεί να leak prompts, το serving stack συνήθως εκθέτει έναν reverse proxy, και τα GPU device nodes δίνουν πρόσβαση σε μεγάλα ioctl() surfaces. Εάν αξιολογείτε ή αναπτύσσετε μια on‑prem inference service, ελέγξτε τουλάχιστον τα παρακάτω σημεία.

### Prompt leakage via debug and monitoring endpoints

Θεωρήστε το inference API ως μια **multi-user sensitive service**. Debug ή monitoring routes μπορούν να εκθέσουν τα περιεχόμενα των prompts, slot state, model metadata ή πληροφορίες εσωτερικής ουράς. Σε `llama.cpp`, το `/slots` endpoint είναι ιδιαίτερα ευαίσθητο επειδή εκθέτει per‑slot state και προορίζεται μόνο για slot inspection/management.

- Τοποθετήστε έναν reverse proxy μπροστά από τον inference server και **deny by default**.
- Επιτρέψτε μόνο τις ακριβείς συνδυαστικές HTTP method + path συνδιαμορφώσεις που χρειάζεται ο client/UI.
- Απενεργοποιήστε introspection endpoints στο backend οπουδήποτε είναι δυνατό, για παράδειγμα `llama-server --no-slots`.
- Bind το reverse proxy σε `127.0.0.1` και εκθέστε το μέσω authenticated transport όπως SSH local port forwarding αντί να το δημοσιεύσετε στο LAN.

Παράδειγμα allowlist με nginx:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Rootless containers χωρίς δίκτυο και UNIX sockets

Αν το inference daemon υποστηρίζει ακρόαση σε UNIX socket, προτίμησέ το αντί για TCP και εκτέλεσε το container με **no network stack**:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Οφέλη:
- `--network none` αφαιρεί την έκθεση TCP/IP εισερχόμενων/εξερχόμενων και αποφεύγει τους user-mode helpers που διαφορετικά θα χρειάζονταν τα rootless containers.
- Ένας UNIX socket σάς επιτρέπει να χρησιμοποιήσετε POSIX permissions/ACLs στην διαδρομή του socket ως το πρώτο επίπεδο ελέγχου πρόσβασης.
- `--userns=keep-id` και rootless Podman μειώνουν το αντίκτυπο ενός container breakout επειδή το container root δεν είναι host root.
- Read-only model mounts μειώνουν την πιθανότητα model tampering από το εσωτερικό του container.

### Ελαχιστοποίηση κόμβων συσκευής GPU

Για GPU-backed inference, τα αρχεία `/dev/nvidia*` είναι high-value local attack surfaces επειδή εκθέτουν μεγάλους driver `ioctl()` handlers και ενδεχομένως shared GPU memory-management paths.

- Μην αφήνετε τα `/dev/nvidia*` world writable.
- Περιορίστε τα `nvidia`, `nvidiactl`, και `nvidia-uvm` με `NVreg_DeviceFileUID/GID/Mode`, udev rules, και ACLs ώστε μόνο το mapped container UID να μπορεί να τα ανοίξει.
- Βάλτε blacklist μη απαραίτητα modules όπως `nvidia_drm`, `nvidia_modeset`, και `nvidia_peermem` σε headless inference hosts.
- Προφορτώστε μόνο τα required modules κατά το boot αντί να αφήσετε το runtime να τα `modprobe` ευκαιριακά κατά το inference startup.

Παράδειγμα:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ένα σημαντικό σημείο ανασκόπησης είναι **`/dev/nvidia-uvm`**. Ακόμη κι αν το workload δεν χρησιμοποιεί ρητά τη `cudaMallocManaged()`, οι πρόσφατες CUDA runtimes ενδέχεται να απαιτούν ακόμα το `nvidia-uvm`. Εφόσον αυτή η συσκευή είναι κοινόχρηστη και χειρίζεται τη διαχείριση εικονικής μνήμης της GPU, αντιμετωπίστε την ως επιφάνεια έκθεσης δεδομένων μεταξύ tenants. Αν το inference backend το υποστηρίζει, ένα Vulkan backend μπορεί να είναι ένας ενδιαφέρων συμβιβασμός επειδή μπορεί να αποφύγει την έκθεση του `nvidia-uvm` στο container καθόλου.

### Περιορισμός LSM για inference workers

AppArmor/SELinux/seccomp πρέπει να χρησιμοποιούνται ως άμυνα σε βάθος γύρω από τη διαδικασία inference:

- Να επιτρέπονται μόνο οι κοινόχρηστες βιβλιοθήκες, οι διαδρομές των μοντέλων, ο κατάλογος socket και οι κόμβοι συσκευής GPU που είναι πραγματικά απαραίτητοι.
- Αρνηθείτε ρητά τις δυνατότητες υψηλού κινδύνου όπως `sys_admin`, `sys_module`, `sys_rawio`, και `sys_ptrace`.
- Κρατήστε τον κατάλογο του μοντέλου μόνο για ανάγνωση και περιορίστε τα εγγράψιμα μονοπάτια μόνο στους καταλόγους socket/cache του runtime.
- Παρακολουθείτε τα denial logs επειδή παρέχουν χρήσιμη τηλεμετρία ανίχνευσης όταν ο model server ή ένα post-exploitation payload προσπαθήσει να ξεφύγει από την αναμενόμενη συμπεριφορά του.

Παράδειγμα κανόνων AppArmor για έναν worker με υποστήριξη GPU:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Αναφορές
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
