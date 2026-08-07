# Κίνδυνοι AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Το Owasp έχει προσδιορίσει τις 10 σημαντικότερες machine learning vulnerabilities που μπορούν να επηρεάσουν τα AI systems. Αυτές οι vulnerabilities μπορούν να οδηγήσουν σε διάφορα security issues, όπως data poisoning, model inversion και adversarial attacks. Η κατανόηση αυτών των vulnerabilities είναι κρίσιμη για τη δημιουργία ασφαλών AI systems.

Για μια ενημερωμένη και λεπτομερή λίστα των 10 σημαντικότερων machine learning vulnerabilities, ανατρέξτε στο project [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Ένας attacker προσθέτει μικρές, συχνά αόρατες αλλαγές στα **εισερχόμενα δεδομένα**, ώστε το model να πάρει τη λάθος απόφαση.\
*Παράδειγμα*: Μερικές πιτσιλιές μπογιάς σε μια πινακίδα STOP ξεγελούν ένα self-driving car ώστε να "δει" πινακίδα ορίου ταχύτητας.

- **Data Poisoning Attack**: Το **training set** μολύνεται σκόπιμα με κακά δείγματα, διδάσκοντας στο model επιβλαβείς κανόνες.\
*Παράδειγμα*: Binaries malware επισημαίνονται λανθασμένα ως "benign" σε ένα antivirus training corpus, επιτρέποντας σε παρόμοιο malware να περνά αργότερα.

- **Model Inversion Attack**: Εξετάζοντας τα outputs, ένας attacker δημιουργεί ένα **reverse model** που ανακατασκευάζει ευαίσθητα χαρακτηριστικά των αρχικών inputs.\
*Παράδειγμα*: Αναδημιουργία της εικόνας MRI ενός ασθενούς από τις predictions ενός model ανίχνευσης καρκίνου.

- **Membership Inference Attack**: Ο adversary ελέγχει αν ένα **συγκεκριμένο record** χρησιμοποιήθηκε κατά το training, εντοπίζοντας διαφορές στο confidence.\
*Παράδειγμα*: Επιβεβαίωση ότι μια τραπεζική συναλλαγή ενός ατόμου υπάρχει στα training data ενός model ανίχνευσης απάτης.

- **Model Theft**: Τα επαναλαμβανόμενα queries επιτρέπουν σε έναν attacker να μάθει τα decision boundaries και να **κλωνοποιήσει τη συμπεριφορά του model** (και το IP).\
*Παράδειγμα*: Συλλογή αρκετών Q&A pairs από ένα ML-as-a-Service API για τη δημιουργία ενός σχεδόν ισοδύναμου local model.

- **AI Supply-Chain Attack**: Παραβίαση οποιουδήποτε component (data, libraries, pre-trained weights, CI/CD) στο **ML pipeline**, ώστε να καταστραφούν τα downstream models.\
*Παράδειγμα*: Μια poisoned dependency σε model-hub εγκαθιστά ένα backdoored model ανάλυσης συναισθήματος σε πολλές εφαρμογές.

- **Transfer Learning Attack**: Κακόβουλη λογική εμφυτεύεται σε ένα **pre-trained model** και επιβιώνει από το fine-tuning για το task του θύματος.\
*Παράδειγμα*: Ένα vision backbone με κρυφό trigger συνεχίζει να αλλάζει τα labels αφού προσαρμοστεί για medical imaging.

- **Model Skewing**: Διακριτικά biased ή mislabeled data **μετατοπίζουν τα outputs του model** προς όφελος της ατζέντας του attacker.\
*Παράδειγμα*: Εισαγωγή "καθαρών" spam emails με label ham, ώστε ένα spam filter να επιτρέπει παρόμοια μελλοντικά emails.

- **Output Integrity Attack**: Ο attacker **αλλάζει τις predictions του model κατά τη μεταφορά**, χωρίς να τροποποιεί το ίδιο το model, ξεγελώντας τα downstream systems.\
*Παράδειγμα*: Αλλαγή της verdict ενός malware classifier από "malicious" σε "benign" πριν το στάδιο file-quarantine τη δει.

- **Model Poisoning** --- Άμεσες, στοχευμένες αλλαγές στα ίδια τα **model parameters**, συχνά αφού αποκτηθεί write access, για την τροποποίηση της συμπεριφοράς.\
*Παράδειγμα*: Τροποποίηση των weights ενός model ανίχνευσης απάτης σε production, ώστε οι συναλλαγές από συγκεκριμένες κάρτες να εγκρίνονται πάντα.


## Google SAIF Risks

Το [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) της Google περιγράφει διάφορους κινδύνους που σχετίζονται με AI systems:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Κακόβουλοι actors τροποποιούν ή εισάγουν training/tuning data για να μειώσουν την ακρίβεια, να εμφυτεύσουν backdoors ή να παραμορφώσουν τα αποτελέσματα, υπονομεύοντας την ακεραιότητα του model σε ολόκληρο τον κύκλο ζωής των data.

- **Unauthorized Training Data**: Η εισαγωγή copyrighted, ευαίσθητων ή μη επιτρεπόμενων datasets δημιουργεί νομικές, ηθικές και performance liabilities, επειδή το model μαθαίνει από data που δεν επιτρεπόταν ποτέ να χρησιμοποιήσει.

- **Model Source Tampering**: Supply-chain ή insider manipulation του model code, των dependencies ή των weights πριν ή κατά το training μπορεί να ενσωματώσει κρυφή λογική που παραμένει ακόμη και μετά το retraining.

- **Excessive Data Handling**: Ανεπαρκείς έλεγχοι data-retention και governance οδηγούν τα systems στην αποθήκευση ή επεξεργασία περισσότερων personal data από όσα είναι απαραίτητα, αυξάνοντας την έκθεση και το compliance risk.

- **Model Exfiltration**: Attackers κλέβουν model files/weights, προκαλώντας απώλεια intellectual property και επιτρέποντας copy-cat services ή follow-on attacks.

- **Model Deployment Tampering**: Adversaries τροποποιούν model artifacts ή τη serving infrastructure, ώστε το model που εκτελείται να διαφέρει από την ελεγμένη έκδοση, αλλάζοντας ενδεχομένως τη συμπεριφορά του.

- **Denial of ML Service**: Η πλημμύρα APIs ή η αποστολή “sponge” inputs μπορεί να εξαντλήσει compute/energy και να θέσει το model εκτός λειτουργίας, όπως στις κλασικές DoS attacks.

- **Model Reverse Engineering**: Συλλέγοντας μεγάλο αριθμό input-output pairs, οι attackers μπορούν να κλωνοποιήσουν ή να κάνουν distil το model, τροφοδοτώντας imitation products και customized adversarial attacks.

- **Insecure Integrated Component**: Ευάλωτα plugins, agents ή upstream services επιτρέπουν σε attackers να εισάγουν code ή να κάνουν privilege escalation μέσα στο AI pipeline.

- **Prompt Injection**: Η δημιουργία prompts, άμεσα ή έμμεσα, για την εισαγωγή instructions που παρακάμπτουν τον σκοπό του system, κάνοντας το model να εκτελεί ανεπιθύμητες commands.

- **Model Evasion**: Προσεκτικά σχεδιασμένα inputs κάνουν το model να mis-classify, να κάνει hallucinate ή να παράγει μη επιτρεπόμενο content, υπονομεύοντας την ασφάλεια και την εμπιστοσύνη.

- **Sensitive Data Disclosure**: Το model αποκαλύπτει private ή confidential information από τα training data ή το user context, παραβιάζοντας το privacy και τους κανονισμούς.

- **Inferred Sensitive Data**: Το model συμπεραίνει personal attributes που δεν δόθηκαν ποτέ, δημιουργώντας νέες παραβιάσεις privacy μέσω inference.

- **Insecure Model Output**: Μη sanitized responses μεταφέρουν harmful code, misinformation ή inappropriate content σε users ή downstream systems.

- **Rogue Actions**: Agents που έχουν ενσωματωθεί αυτόνομα εκτελούν ανεπιθύμητες ενέργειες στον πραγματικό κόσμο (file writes, API calls, αγορές κ.λπ.) χωρίς επαρκή user oversight.

## Mitre AI ATLAS Matrix

Το [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) παρέχει ένα ολοκληρωμένο framework για την κατανόηση και τον μετριασμό των risks που σχετίζονται με AI systems. Κατηγοριοποιεί διάφορες attack techniques και tactics που μπορεί να χρησιμοποιήσουν adversaries εναντίον AI models, καθώς και τρόπους χρήσης AI systems για την εκτέλεση διαφορετικών attacks.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers κλέβουν ενεργά session tokens ή cloud API credentials και καλούν επί πληρωμή, cloud-hosted LLMs χωρίς authorization. Η πρόσβαση συχνά μεταπωλείται μέσω reverse proxies που λειτουργούν μπροστά από το account του θύματος, π.χ. deployments "oai-reverse-proxy". Οι συνέπειες περιλαμβάνουν οικονομική απώλεια, misuse του model εκτός policy και attribution στο tenant του θύματος.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Συλλογή tokens από infected developer machines ή browsers· κλοπή CI/CD secrets· αγορά leaked cookies.<sup>[[5]](#references)</sup>
- Δημιουργία reverse proxy που προωθεί requests στον αυθεντικό provider, αποκρύπτει το upstream key και κάνει multiplexing πολλών customers.<sup>[[5]](#references)[[7]](#references)</sup>
- Κατάχρηση direct base-model endpoints για παράκαμψη των enterprise guardrails και των rate limits.<sup>[[4]](#references)</sup>

Mitigations:
- Σύνδεση των tokens με device fingerprint, IP ranges και client attestation· επιβολή σύντομων expirations και refresh με MFA.
- Περιορισμός των keys στο ελάχιστο (χωρίς tool access, read-only όπου εφαρμόζεται)· rotation σε περίπτωση anomaly.
- Τερματισμός όλης της traffic server-side πίσω από policy gateway που επιβάλλει safety filters, per-route quotas και tenant isolation.
- Παρακολούθηση για unusual usage patterns (αιφνίδιες αυξήσεις spend, atypical regions, UA strings) και auto-revoke ύποπτων sessions.
- Προτίμηση mTLS ή signed JWTs που εκδίδονται από το IdP σας αντί για long-lived static API keys.

## Hardening self-hosted LLM inference

Η εκτέλεση local LLM server για confidential data δημιουργεί διαφορετικό attack surface από τα cloud-hosted APIs: τα inference/debug endpoints μπορεί να κάνουν leak prompts, το serving stack συνήθως εκθέτει reverse proxy και τα GPU device nodes παρέχουν πρόσβαση σε μεγάλες `ioctl()` surfaces. Αν αξιολογείτε ή αναπτύσσετε on-prem inference service, ελέγξτε τουλάχιστον τα ακόλουθα σημεία.<sup>[[8]](#references)</sup>

### Prompt leakage μέσω debug και monitoring endpoints

Αντιμετωπίστε το inference API ως **multi-user sensitive service**. Τα debug ή monitoring routes μπορούν να εκθέσουν prompt contents, slot state, model metadata ή πληροφορίες για την internal queue. Στο `llama.cpp`, το endpoint `/slots` είναι ιδιαίτερα ευαίσθητο, επειδή εκθέτει per-slot state και προορίζεται μόνο για slot inspection/management.<sup>[[8]](#references)</sup>

- Τοποθετήστε reverse proxy μπροστά από τον inference server και εφαρμόστε **deny by default**.
- Επιτρέψτε μόνο τα ακριβή ζεύγη HTTP method + path που χρειάζεται ο client/UI.
- Απενεργοποιήστε τα introspection endpoints στο backend, όπου είναι δυνατό, για παράδειγμα `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Κάντε bind το reverse proxy στο `127.0.0.1` και εκθέστε το μέσω authenticated transport, όπως SSH local port forwarding, αντί να το δημοσιεύσετε στο LAN.

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
### Rootless containers χωρίς network και UNIX sockets

Αν το inference daemon υποστηρίζει ακρόαση σε UNIX socket, προτιμήστε το αντί για TCP και εκτελέστε το container με **no network stack**:<sup>[[8]](#references)</sup>
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
- Το `--network none` καταργεί την εισερχόμενη/εξερχόμενη έκθεση μέσω TCP/IP και αποφεύγει user-mode helpers που διαφορετικά θα χρειάζονταν τα rootless containers.
- Ένα UNIX socket σάς επιτρέπει να χρησιμοποιείτε POSIX permissions/ACLs στη διαδρομή του socket ως πρώτο επίπεδο ελέγχου πρόσβασης.
- Τα `--userns=keep-id` και το rootless Podman μειώνουν τον αντίκτυπο ενός container breakout, επειδή το root του container δεν είναι το root του host.
- Τα read-only model mounts μειώνουν την πιθανότητα tampering του model από το εσωτερικό του container.

### Ελαχιστοποίηση GPU device-nodes

Για inference με GPU, τα αρχεία `/dev/nvidia*` αποτελούν local attack surfaces υψηλής αξίας, επειδή εκθέτουν μεγάλους driver `ioctl()` handlers και δυνητικά κοινόχρηστα μονοπάτια διαχείρισης GPU memory.<sup>[[8]](#references)</sup>

- Μην αφήνετε τα `/dev/nvidia*` writable από όλους.
- Περιορίστε τα `nvidia`, `nvidiactl` και `nvidia-uvm` με `NVreg_DeviceFileUID/GID/Mode`, udev rules και ACLs, ώστε μόνο το mapped container UID να μπορεί να τα ανοίξει.
- Κάντε blacklist περιττών modules, όπως τα `nvidia_drm`, `nvidia_modeset` και `nvidia_peermem`, σε headless inference hosts.
- Κάντε preload μόνο των απαιτούμενων modules κατά την εκκίνηση, αντί να επιτρέπετε στο runtime να εκτελεί opportunistically `modprobe` κατά την εκκίνηση του inference.

Παράδειγμα:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ένα σημαντικό σημείο ελέγχου είναι το **`/dev/nvidia-uvm`**. Ακόμη και αν το workload δεν χρησιμοποιεί ρητά το `cudaMallocManaged()`, τα πρόσφατα CUDA runtimes ενδέχεται να απαιτούν το `nvidia-uvm`. Επειδή αυτή η συσκευή είναι shared και διαχειρίζεται τη virtual memory της GPU, αντιμετωπίστε την ως επιφάνεια έκθεσης δεδομένων μεταξύ tenants. Αν το inference backend το υποστηρίζει, ένα Vulkan backend μπορεί να αποτελεί ενδιαφέρον trade-off, επειδή ενδέχεται να αποφεύγει εντελώς την έκθεση του `nvidia-uvm` στο container.<sup>[[8]](#references)</sup>

### Περιορισμός μέσω LSM για inference workers

Τα AppArmor/SELinux/seccomp θα πρέπει να χρησιμοποιούνται ως defense in depth γύρω από τη διεργασία inference:<sup>[[8]](#references)</sup>

- Επιτρέψτε μόνο τις shared libraries, τα model paths, τον socket directory και τα GPU device nodes που απαιτούνται πραγματικά.
- Απαγορεύστε ρητά capabilities υψηλού κινδύνου, όπως τα `sys_admin`, `sys_module`, `sys_rawio` και `sys_ptrace`.
- Διατηρήστε το model directory read-only και περιορίστε τα writable paths αποκλειστικά στους runtime socket/cache directories.
- Παρακολουθείτε τα denial logs, επειδή παρέχουν χρήσιμα detection telemetry όταν ο model server ή ένα post-exploitation payload προσπαθεί να διαφύγει από την αναμενόμενη συμπεριφορά του.

Παράδειγμα κανόνων AppArmor για έναν GPU-backed worker:
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
## Phantom Squatting: Domains που δημιουργούνται από παραισθήσεις LLM ως διάνυσμα AI Supply-Chain

Το Phantom squatting είναι το **ισοδύναμο domain/URL του slopsquatting**. Αντί να δημιουργεί μέσω παραισθήσεων ένα ανύπαρκτο όνομα package, το LLM δημιουργεί μέσω παραισθήσεων ένα εύλογο **portal, API, webhook, billing, SSO, download ή support domain** για ένα πραγματικό brand, και ένας attacker καταχωρίζει αυτό το namespace πριν το χρησιμοποιήσει κάποιος άνθρωπος ή agent.<sup>[[12]](#references)[[13]](#references)</sup>

Αυτό έχει σημασία επειδή σε πολλές AI-assisted ροές εργασίας το output του model αντιμετωπίζεται ως **trusted dependency**:
- Οι developers επικολλούν το προτεινόμενο endpoint σε κώδικα ή CI/CD integrations.
- Οι AI agents κάνουν αυτόματα fetch documentation, schemas, APKs, ZIPs ή webhook targets.
- Τα generated runbooks ή docs μπορούν να ενσωματώσουν το fake URL σαν να ήταν authoritative.

### Offensive workflow

1. **Probe την επιφάνεια των hallucinations**: κάντε brand-specific ερωτήσεις σχετικά με ρεαλιστικές ροές εργασίας, όπως `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ή `mobile app` portals.<sup>[[12]](#references)</sup>
2. **Normalize τους candidates**: κάντε resolve τα generated URLs, μετατρέψτε τις απαντήσεις NXDOMAIN στο parent registerable domain και κάντε deduplicate τις prompt families. Τα prompt corpora πρέπει να παραμένουν diverse, για παράδειγμα αφαιρώντας near-duplicates με **Jaccard similarity**.
3. **Δώστε προτεραιότητα σε προβλέψιμα hallucinations**:
- **Thermal Hallucination Persistence (THP)**: το ίδιο fake domain εμφανίζεται σε διαφορετικές θερμοκρασίες, συμπεριλαμβανομένης χαμηλής θερμοκρασίας όπως `T=0.1`.
- **Cross-model consensus**: πολλές οικογένειες LLM δημιουργούν το ίδιο fake domain.
4. **Κάντε register και weaponize** το parent domain και, στη συνέχεια, φιλοξενήστε phishing, fake APK/ZIP downloads, credential harvesters, malicious docs ή API endpoints που συλλέγουν secrets/webhook payloads. Οι **pure domain-level hallucinations** είναι οι ευκολότερες για monetization, επειδή ο attacker ελέγχει ολόκληρο το namespace· τα subdomain/path hallucinations μπορούν επίσης να γίνουν αντικείμενο abuse όταν το normalized parent δεν είναι καταχωρισμένο.
5. **Εκμεταλλευτείτε το zero-reputation window**: τα newly registered domains συχνά δεν έχουν blocklist history, URL reputation και mature telemetry, επομένως μπορούν να παρακάμψουν τα controls μέχρι να προλάβουν να ενημερωθούν τα detections. Οι attackers μπορούν να επιμηκύνουν αυτό το window με benign responses μόνο για crawlers, redirect cloaking, CAPTCHA gates ή delayed payload staging.

### Γιατί είναι επικίνδυνο για agents

Για ένα human victim, το fake domain συνήθως απαιτεί ένα click και μία ακόμη ενέργεια. Σε ένα **agentic workflow**, το LLM μπορεί να είναι ταυτόχρονα το **lure** και ο **executor**: ο agent λαμβάνει το hallucinated URL, κάνει fetch σε αυτό, κάνει parse την response και στη συνέχεια μπορεί να κάνει leak tokens, να εκτελέσει instructions, να κατεβάσει ένα dependency ή να προωθήσει poisoned data σε CI/CD χωρίς human review.<sup>[[12]](#references)</sup>

### Practical attacker prompts

Τα high-yield prompts συνήθως μοιάζουν με κανονικές enterprise εργασίες αντί για explicit phishing lures:<sup>[[12]](#references)</sup>
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Αντιμετωπίστε το ως proactive domain-monitoring πρόβλημα και όχι μόνο ως prompt-injection πρόβλημα:<sup>[[12]](#references)</sup>
- Δημιουργήστε ένα **brand prompt corpus** και κάντε περιοδικά probe στα LLMs στα οποία βασίζονται οι users/agents σας.
- Αποθηκεύστε τα hallucinated URLs και παρακολουθήστε ποια παραμένουν stable σε διαφορετικές θερμοκρασίες/models.
- Παρακολουθήστε το **Adversarial Exploitation Window (AEW)**: τον χρόνο μεταξύ του πρώτου hallucination και του attacker registration. Θετικό AEW σημαίνει ότι οι defenders μπορούν να κάνουν pre-register, sinkhole ή pre-block πριν από το weaponization.
- Παρακολουθήστε τις μεταβάσεις **NXDOMAIN → registered** για τα parent domains.
- Μετά την καταχώριση, κάντε triage τον registrar, την creation date, τους nameservers, το privacy shielding, το page content, τα screenshots, το parked-page status και το brand-asset similarity.
- Προσθέστε policy gates, ώστε οι agents/developers να **μην εμπιστεύονται από προεπιλογή domains που δημιουργούνται από LLM**: απαιτήστε allowlists, ownership validation, CT/RDAP checks ή human approval πριν από την πρώτη χρήση.

Αυτό εντάσσεται ταυτόχρονα σε αρκετές AI risk categories: **AI supply-chain attack**, **insecure model output** και **rogue actions**, όταν οι agents καταναλώνουν αυτόνομα το hallucinated URL.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
