# Κίνδυνοι AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Η Owasp έχει εντοπίσει τις κορυφαίες 10 ευπάθειες σε machine learning που μπορούν να επηρεάσουν συστήματα AI. Αυτές οι ευπάθειες μπορούν να οδηγήσουν σε διάφορα ζητήματα ασφάλειας, όπως data poisoning, model inversion και adversarial attacks. Η κατανόηση αυτών των ευπαθειών είναι κρίσιμη για την κατασκευή ασφαλών συστημάτων AI.

Για μια ενημερωμένη και λεπτομερή λίστα με τις κορυφαίες 10 machine learning vulnerabilities, ανατρέξτε στο [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Ένας επιτιθέμενος προσθέτει μικρές, συχνά αόρατες αλλαγές σε **incoming data** ώστε το μοντέλο να πάρει λανθασμένη απόφαση.\
*Παράδειγμα*: Μερικές πιτσιλιές χρώματος σε ένα stop‑sign ξεγελούν ένα self‑driving car ώστε να "δεί" ένα speed‑limit sign.

- **Data Poisoning Attack**: Το **training set** μολύνεται εσκεμμένα με κακές δειγματοληψίες, μαθαίνοντας στο μοντέλο επιβλαβείς κανόνες.\
*Παράδειγμα*: Malware binaries χαρακτηρίζονται λανθασμένα ως "benign" σε ένα antivirus training corpus, επιτρέποντας σε παρόμοιο malware να περάσει αργότερα.

- **Model Inversion Attack**: Με probing των outputs, ένας επιτιθέμενος κατασκευάζει ένα **reverse model** που ανακατασκευάζει ευαίσθητα χαρακτηριστικά των αρχικών inputs.\
*Παράδειγμα*: Επαναδημιουργία της MRI εικόνας ενός ασθενούς από τις προβλέψεις ενός cancer‑detection model.

- **Membership Inference Attack**: Ο αντίπαλος ελέγχει αν ένα **specific record** χρησιμοποιήθηκε κατά την εκπαίδευση εντοπίζοντας διαφορές στην confidence.\
*Παράδειγμα*: Επιβεβαίωση ότι μια τραπεζική συναλλαγή ενός ατόμου εμφανίζεται στο training data ενός fraud‑detection model.

- **Model Theft**: Επαναλαμβανόμενα queries επιτρέπουν σε έναν επιτιθέμενο να μάθει decision boundaries και να **clone the model's behavior** (και IP).\
*Παράδειγμα*: Συλλογή αρκετών Q&A pairs από ένα ML‑as‑a‑Service API για να χτιστεί ένα σχεδόν ισοδύναμο local model.

- **AI Supply‑Chain Attack**: Παραβίαση οποιουδήποτε component (data, libraries, pre‑trained weights, CI/CD) στην ML pipeline για να μολύνει downstream μοντέλα.\
*Παράδειγμα*: Μια poisoned dependency σε ένα model‑hub εγκαθιστά ένα backdoored sentiment‑analysis model σε πολλές εφαρμογές.

- **Transfer Learning Attack**: Κακόβουλη λογική φυτεύεται σε ένα **pre‑trained model** και επιβιώνει μετά το fine‑tuning για το task του θύματος.\
*Παράδειγμα*: Μια vision backbone με κρυφό trigger εξακολουθεί να αλλάζει labels αφού προσαρμοστεί για medical imaging.

- **Model Skewing**: Λεπτοί προκατειλημμένοι ή λανθασμένα επισημασμένοι δεδομένα **μετατοπίζουν τα outputs του μοντέλου** ώστε να ευνοούν την ατζέντα του επιτιθέμενου.\
*Παράδειγμα*: Ένεση "clean" spam emails επισημασμένων ως ham ώστε ένα spam filter να αφήνει παρόμοια μελλοντικά emails να περνούν.

- **Output Integrity Attack**: Ο επιτιθέμενος **τροποποιεί τις προβλέψεις του μοντέλου εντός της μεταφοράς (in transit)**, όχι το ίδιο το μοντέλο, εξαπατώντας downstream συστήματα.\
*Παράδειγμα*: Αλλαγή της απόφασης ενός malware classifier από "malicious" σε "benign" πριν το στάδιο file‑quarantine το δει.

- **Model Poisoning** --- Άμεσες, στοχευμένες αλλαγές στις **παραμέτρους του μοντέλου** οι οποίες γίνονται συνήθως αφού αποκτηθεί δικαίωμα εγγραφής, για να αλλοιώσουν τη συμπεριφορά.\
*Παράδειγμα*: Τροποποίηση weights σε ένα fraud‑detection model σε production ώστε οι συναλλαγές από κάρτες ενός συγκεκριμένου τύπου να εγκρίνονται πάντα.

## Google SAIF Risks

Το [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) της Google περιγράφει διάφορους κινδύνους που συνδέονται με συστήματα AI:

- **Data Poisoning**: Κακόβουλοι παράγοντες τροποποιούν ή εισάγουν training/tuning data για να μειώσουν την accuracy, να εμφυτεύσουν backdoors ή να skewάρουν αποτελέσματα, υπονομεύοντας την ακεραιότητα του μοντέλου σε ολόκληρο τον κύκλο ζωής των δεδομένων.

- **Unauthorized Training Data**: Εισαγωγή copyrighted, ευαίσθητων ή μη εξουσιοδοτημένων datasets δημιουργεί νομικές, ηθικές και απόδοσης ευθύνες γιατί το μοντέλο μαθαίνει από δεδομένα που δεν είχε δικαίωμα να χρησιμοποιήσει.

- **Model Source Tampering**: Supply‑chain ή insider χειραγωγία του model code, dependencies ή weights πριν ή κατά την εκπαίδευση μπορεί να ενσωματώσει κρυφή λογική που επιμένει ακόμα και μετά από retraining.

- **Excessive Data Handling**: Αδύναμος έλεγχος data‑retention και governance οδηγεί τα συστήματα να αποθηκεύουν ή να επεξεργάζονται περισσότερα προσωπικά δεδομένα από όσα χρειάζονται, αυξάνοντας την έκθεση και τον compliance κίνδυνο.

- **Model Exfiltration**: Επιτιθέμενοι κλέβουν model files/weights, προκαλώντας απώλεια πνευματικής ιδιοκτησίας και επιτρέποντας copy‑cat services ή επακόλουθες επιθέσεις.

- **Model Deployment Tampering**: Αντίπαλοι τροποποιούν artifacts ή serving infrastructure ώστε το running model να διαφέρει από την εγκεκριμένη έκδοση, αλλάζοντας πιθανώς τη συμπεριφορά.

- **Denial of ML Service**: Flooding APIs ή αποστολή “sponge” inputs μπορεί να εξαντλήσει compute/energy και να ρίξει το μοντέλο offline, μιμούμενο κλασικές DoS επιθέσεις.

- **Model Reverse Engineering**: Συλλέγοντας μεγάλο αριθμό input‑output pairs, οι επιτιθέμενοι μπορούν να clone ή να distil το μοντέλο, τροφοδοτώντας imitation προϊόντα και εξατομικευμένες adversarial επιθέσεις.

- **Insecure Integrated Component**: Ευάλωτα plugins, agents ή upstream services επιτρέπουν στους επιτιθέμενους να εισάγουν κώδικα ή να αυξήσουν προνόμια μέσα στην AI pipeline.

- **Prompt Injection**: Κατασκευή prompts (άμεσα ή έμμεσα) για να κρυφτούν οδηγίες που υπερισχύουν του system intent, αναγκάζοντας το μοντέλο να εκτελέσει μη προβλεπόμενες εντολές.

- **Model Evasion**: Προσεκτικά σχεδιασμένα inputs προκαλούν το μοντέλο να mis‑classify, να hallucinate ή να παράγει απαγορευμένο περιεχόμενο, υποσκάπτοντας ασφάλεια και εμπιστοσύνη.

- **Sensitive Data Disclosure**: Το μοντέλο αποκαλύπτει ιδιωτικές ή εμπιστευτικές πληροφορίες από το training data ή το user context, παραβιάζοντας την ιδιωτικότητα και κανονισμούς.

- **Inferred Sensitive Data**: Το μοντέλο εξαπολύει προσωπικά χαρακτηριστικά που ποτέ δεν παρέχονταν, δημιουργώντας νέα privacy βλάβη μέσω inference.

- **Insecure Model Output**: Μη‑sanitized responses περνούν επιβλαβή code, misinformation ή ακατάλληλο περιεχόμενο σε χρήστες ή downstream συστήματα.

- **Rogue Actions**: Αυτοματοποιημένα ενσωματωμένοι agents εκτελούν απρόβλεπτες real‑world ενέργειες (γραφές σε αρχεία, API κλήσεις, αγορές κ.λπ.) χωρίς επαρκή user oversight.

## Mitre AI ATLAS Matrix

Το [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) προσφέρει ένα ολοκληρωμένο πλαίσιο για την κατανόηση και την απομείωση κινδύνων που σχετίζονται με συστήματα AI. Κατηγοριοποιεί διάφορες τεχνικές και tactics επιθέσεων που οι αντίπαλοι μπορούν να χρησιμοποιήσουν εναντίον AI μοντέλων και επίσης πώς να χρησιμοποιήσουν AI συστήματα για την εκτέλεση διαφορετικών επιθέσεων.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Επιτιθέμενοι κλέβουν ενεργά session tokens ή cloud API credentials και επικαλούνται πληρωμένα, cloud‑hosted LLMs χωρίς εξουσιοδότηση. Η πρόσβαση συχνά επαναπωλείται μέσω reverse proxies που frontάρουν τον λογαριασμό του θύματος, π.χ. deployments τύπου "oai-reverse-proxy". Οι συνέπειες περιλαμβάνουν οικονομική ζημία, κατάχρηση του μοντέλου εκτός policy και attribution στον tenant‑θύμα.

TTPs:
- Harvest tokens από μολυσμένα developer machines ή browsers; κλέψτε CI/CD secrets; αγοράστε leaked cookies.
- Stand up ένα reverse proxy που προωθεί requests στον γνήσιο provider, κρύβοντας το upstream key και multiplexing πολλούς πελάτες.
- Abuse direct base‑model endpoints για να παρακάμψετε enterprise guardrails και rate limits.

Mitigations:
- Bind tokens σε device fingerprint, IP ranges, και client attestation; επιβάλετε short expirations και refresh με MFA.
- Scope keys ελάχιστα (no tool access, read‑only όπου εφαρμόζεται); rotate σε ανωμαλίες.
- Terminate όλη την κίνηση server‑side πίσω από ένα policy gateway που επιβάλλει safety filters, per‑route quotas, και tenant isolation.
- Monitor για ασυνήθιστα usage patterns (sudden spend spikes, atypical regions, UA strings) και auto‑revoke suspicious sessions.
- Προτιμήστε mTLS ή signed JWTs εκδομένα από το IdP σας αντί για long‑lived static API keys.

## Self-hosted LLM inference hardening

Η λειτουργία ενός local LLM server για confidential δεδομένα δημιουργεί διαφορετική επιφάνεια επίθεσης σε σύγκριση με cloud‑hosted APIs: inference/debug endpoints μπορεί να leak prompts, το serving stack συνήθως εκθέτει ένα reverse proxy, και οι GPU device nodes δίνουν πρόσβαση σε μεγάλες ioctl() επιφάνειες. Εάν αξιολογείτε ή αναπτύσσετε μια on‑prem inference υπηρεσία, ελέγξτε τουλάχιστον τα παρακάτω σημεία.

### Prompt leakage via debug and monitoring endpoints

Θεωρήστε το inference API ως ένα **multi‑user sensitive service**. Debug ή monitoring routes μπορούν να leak περιεχόμενο prompts, slot state, model metadata, ή εσωτερικές πληροφορίες queue. Στο `llama.cpp`, το `/slots` endpoint είναι ιδιαίτερα ευαίσθητο επειδή εκθέτει per‑slot state και προορίζεται μόνο για slot inspection/management.

- Βάλτε έναν reverse proxy μπροστά από τον inference server και **deny by default**.
- Επιτρέψτε μόνο ακριβώς τις HTTP method + path συνδυασμούς που χρειάζεται ο client/UI.
- Απενεργοποιήστε introspection endpoints στο backend όπου είναι δυνατό, για παράδειγμα `llama-server --no-slots`.
- Bindάρετε το reverse proxy στο `127.0.0.1` και εκθέστε το μέσω ενός authenticated transport όπως SSH local port forwarding αντί να το δημοσιεύσετε στο LAN.

Example allowlist with nginx:
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

Εάν το inference daemon υποστηρίζει ακρόαση σε UNIX socket, προτιμήστε αυτό αντί για TCP και τρέξτε το container χωρίς **στοίβα δικτύου**:
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
- `--network none` αφαιρεί την έκθεση TCP/IP εισερχόμενων/εξερχόμενων και αποφεύγει τα user-mode helpers που διαφορετικά θα χρειάζονταν οι rootless containers.
- Ένα UNIX socket σας επιτρέπει να χρησιμοποιήσετε POSIX permissions/ACLs στη διαδρομή του socket ως πρώτο επίπεδο ελέγχου πρόσβασης.
- `--userns=keep-id` και rootless Podman μειώνουν τον αντίκτυπο ενός container breakout επειδή το container root δεν είναι host root.
- Read-only model mounts μειώνουν την πιθανότητα model tampering από μέσα στο container.

### Ελαχιστοποίηση device-node για GPU

Για GPU-backed inference, τα αρχεία `/dev/nvidia*` είναι τοπικές επιφάνειες επίθεσης μεγάλης αξίας επειδή εκθέτουν μεγάλους `ioctl()` χειριστές του driver και ενδεχομένως κοινόχρηστους μηχανισμούς διαχείρισης μνήμης της GPU.

- Do not leave `/dev/nvidia*` world writable.
- Περιορίστε `nvidia`, `nvidiactl` και `nvidia-uvm` με `NVreg_DeviceFileUID/GID/Mode`, κανόνες udev και ACLs ώστε μόνο το mapped container UID να μπορεί να τα ανοίξει.
- Blacklist μη απαραίτητα modules όπως `nvidia_drm`, `nvidia_modeset` και `nvidia_peermem` σε headless inference hosts.
- Preload μόνο τα απαιτούμενα modules κατά το boot αντί να αφήνετε το runtime να τα `modprobe` ευκαιριακά κατά την εκκίνηση του inference.

Παράδειγμα:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ένα σημαντικό σημείο ελέγχου είναι το **`/dev/nvidia-uvm`**. Ακόμα κι αν το φορτίο εργασίας δεν χρησιμοποιεί ρητά την `cudaMallocManaged()`, τα πρόσφατα CUDA runtimes μπορεί να απαιτούν ακόμα το `nvidia-uvm`. Εφόσον αυτή η συσκευή είναι κοινόχρηστη και αναλαμβάνει τη διαχείριση της εικονικής μνήμης της GPU, αντιμετωπίστε την ως επιφάνεια έκθεσης δεδομένων μεταξύ tenants. Αν το inference backend το υποστηρίζει, ένα Vulkan backend μπορεί να είναι ένας ενδιαφέρων συμβιβασμός επειδή μπορεί να αποφύγει την έκθεση του `nvidia-uvm` στο container εντελώς.

### Περιορισμός LSM για διεργασίες inference

AppArmor/SELinux/seccomp πρέπει να χρησιμοποιούνται ως αμυντική στρατηγική πολλαπλών επιπέδων γύρω από τη διαδικασία inference:

- Να επιτρέπονται μόνο οι κοινόχρηστες βιβλιοθήκες, οι διαδρομές μοντέλων, ο κατάλογος socket και οι κόμβοι συσκευής GPU που είναι πραγματικά απαραίτητοι.
- Αρνηθείτε ρητά τις υψηλού κινδύνου δυνατότητες όπως `sys_admin`, `sys_module`, `sys_rawio`, και `sys_ptrace`.
- Κρατήστε τον κατάλογο μοντέλων μόνο για ανάγνωση και περιορίστε τα εγγράψιμα μονοπάτια μόνο στους καταλόγους socket/cache του runtime.
- Παρακολουθείτε τα denial logs επειδή παρέχουν χρήσιμη τηλεμετρία ανίχνευσης όταν ο model server ή ένα post-exploitation payload προσπαθεί να διαφύγει από την αναμενόμενη συμπεριφορά.

Παράδειγμα κανόνων AppArmor για worker με υποστήριξη GPU:
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
