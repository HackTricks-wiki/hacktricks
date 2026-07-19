# Κίνδυνοι AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Το Owasp έχει εντοπίσει τις 10 κορυφαίες machine learning vulnerabilities που μπορούν να επηρεάσουν τα AI systems. Αυτές οι vulnerabilities μπορούν να οδηγήσουν σε διάφορα security issues, όπως data poisoning, model inversion και adversarial attacks. Η κατανόηση αυτών των vulnerabilities είναι κρίσιμη για τη δημιουργία ασφαλών AI systems.

Για μια ενημερωμένη και λεπτομερή λίστα με τις 10 κορυφαίες machine learning vulnerabilities, ανατρέξτε στο project [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Ένας attacker προσθέτει μικροσκοπικές, συχνά αόρατες αλλαγές στα **incoming data**, ώστε το model να πάρει λάθος απόφαση.\
*Παράδειγμα*: Μερικές κηλίδες μπογιάς σε ένα stop sign ξεγελούν ένα self-driving car ώστε να «δει» ένα speed-limit sign.

- **Data Poisoning Attack**: Το **training set** μολύνεται σκόπιμα με κακά samples, διδάσκοντας στο model επιβλαβείς κανόνες.\
*Παράδειγμα*: Malware binaries επισημαίνονται λανθασμένα ως "benign" σε ένα antivirus training corpus, επιτρέποντας σε παρόμοιο malware να παρακάμψει τον έλεγχο αργότερα.

- **Model Inversion Attack**: Με probing των outputs, ένας attacker δημιουργεί ένα **reverse model** που ανακατασκευάζει ευαίσθητα χαρακτηριστικά των αρχικών inputs.\
*Παράδειγμα*: Αναδημιουργία της MRI εικόνας ενός ασθενούς από τις προβλέψεις ενός cancer-detection model.

- **Membership Inference Attack**: Ο adversary ελέγχει αν ένα **specific record** χρησιμοποιήθηκε κατά το training, εντοπίζοντας διαφορές στο confidence.\
*Παράδειγμα*: Επιβεβαίωση ότι μια τραπεζική συναλλαγή ενός ατόμου εμφανίζεται στα training data ενός fraud-detection model.

- **Model Theft**: Τα επαναλαμβανόμενα queries επιτρέπουν σε έναν attacker να μάθει τα decision boundaries και να **clone τη συμπεριφορά του model** (και το IP).\
*Παράδειγμα*: Συλλογή αρκετών Q&A pairs από ένα ML-as-a-Service API για τη δημιουργία ενός σχεδόν ισοδύναμου local model.

- **AI Supply-Chain Attack**: Η παραβίαση οποιουδήποτε component (data, libraries, pre-trained weights, CI/CD) στο **ML pipeline** μπορεί να καταστρέψει τα downstream models.\
*Παράδειγμα*: Ένα poisoned dependency σε model-hub εγκαθιστά ένα backdoored sentiment-analysis model σε πολλές εφαρμογές.

- **Transfer Learning Attack**: Κακόβουλη λογική τοποθετείται σε ένα **pre-trained model** και επιβιώνει του fine-tuning για το task του θύματος.\
*Παράδειγμα*: Ένα vision backbone με κρυφό trigger συνεχίζει να αντιστρέφει τα labels μετά την προσαρμογή του για medical imaging.

- **Model Skewing**: Διακριτικά biased ή mislabeled data **μετατοπίζουν τα outputs του model** ώστε να ευνοούν την ατζέντα του attacker.\
*Παράδειγμα*: Εισαγωγή "clean" spam emails με label ham, ώστε ένα spam filter να επιτρέπει παρόμοια μελλοντικά emails.

- **Output Integrity Attack**: Ο attacker **αλλάζει τις προβλέψεις του model κατά τη μεταφορά**, χωρίς να τροποποιεί το ίδιο το model, ξεγελώντας τα downstream systems.\
*Παράδειγμα*: Αλλαγή του verdict ενός malware classifier από "malicious" σε "benign" πριν το δει το file-quarantine stage.

- **Model Poisoning** --- Άμεσες, στοχευμένες αλλαγές στα **model parameters**, συχνά μετά την απόκτηση write access, για την αλλαγή της συμπεριφοράς.\
*Παράδειγμα*: Τροποποίηση των weights ενός fraud-detection model σε production, ώστε οι συναλλαγές από συγκεκριμένες κάρτες να εγκρίνονται πάντα.


## Κίνδυνοι Google SAIF

Το [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) της Google περιγράφει διάφορους κινδύνους που σχετίζονται με τα AI systems:

- **Data Poisoning**: Κακόβουλοι actors τροποποιούν ή εισάγουν training/tuning data για να μειώσουν την ακρίβεια, να εγκαταστήσουν backdoors ή να αλλοιώσουν τα αποτελέσματα, υπονομεύοντας την ακεραιότητα του model σε ολόκληρο τον data-lifecycle.

- **Unauthorized Training Data**: Η εισαγωγή copyrighted, ευαίσθητων ή μη επιτρεπόμενων datasets δημιουργεί νομικές, ηθικές και performance liabilities, επειδή το model μαθαίνει από data που δεν επιτρεπόταν ποτέ να χρησιμοποιήσει.

- **Model Source Tampering**: Supply-chain ή insider manipulation του model code, των dependencies ή των weights πριν ή κατά τη διάρκεια του training μπορεί να ενσωματώσει κρυφή λογική που παραμένει ακόμη και μετά το retraining.

- **Excessive Data Handling**: Αδύναμοι έλεγχοι data-retention και governance οδηγούν τα systems στην αποθήκευση ή επεξεργασία περισσότερων personal data από όσα είναι απαραίτητα, αυξάνοντας το exposure και το compliance risk.

- **Model Exfiltration**: Attackers κλέβουν model files/weights, προκαλώντας απώλεια intellectual property και επιτρέποντας copy-cat services ή follow-on attacks.

- **Model Deployment Tampering**: Adversaries τροποποιούν model artifacts ή serving infrastructure, ώστε το running model να διαφέρει από την ελεγμένη έκδοση, αλλάζοντας ενδεχομένως τη συμπεριφορά του.

- **Denial of ML Service**: Η πλημμύρα APIs ή η αποστολή “sponge” inputs μπορεί να εξαντλήσει compute/energy και να θέσει το model εκτός λειτουργίας, όπως στα κλασικά DoS attacks.

- **Model Reverse Engineering**: Συλλέγοντας μεγάλο αριθμό input-output pairs, οι attackers μπορούν να κάνουν clone ή distil το model, τροφοδοτώντας imitation products και customized adversarial attacks.

- **Insecure Integrated Component**: Ευάλωτα plugins, agents ή upstream services επιτρέπουν στους attackers να εισάγουν code ή να κάνουν privilege escalation μέσα στο AI pipeline.

- **Prompt Injection**: Η δημιουργία prompts, άμεσα ή έμμεσα, για τη διοχέτευση instructions που παρακάμπτουν το system intent, κάνοντας το model να εκτελεί unintended commands.

- **Model Evasion**: Carefully designed inputs κάνουν το model να mis-classify, να hallucinate ή να παράγει disallowed content, υπονομεύοντας την ασφάλεια και την εμπιστοσύνη.

- **Sensitive Data Disclosure**: Το model αποκαλύπτει private ή confidential information από τα training data ή το user context, παραβιάζοντας το privacy και τους regulations.

- **Inferred Sensitive Data**: Το model συμπεραίνει προσωπικά attributes που δεν δόθηκαν ποτέ, δημιουργώντας νέες παραβιάσεις privacy μέσω inference.

- **Insecure Model Output**: Unsanitized responses μεταφέρουν harmful code, misinformation ή inappropriate content σε users ή downstream systems.

- **Rogue Actions**: Autonomously-integrated agents εκτελούν unintended real-world operations (file writes, API calls, purchases κ.λπ.) χωρίς επαρκή user oversight.

## Mitre AI ATLAS Matrix

Το [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) παρέχει ένα ολοκληρωμένο framework για την κατανόηση και τον περιορισμό των risks που σχετίζονται με AI systems. Κατηγοριοποιεί διάφορες attack techniques και tactics που μπορεί να χρησιμοποιήσουν οι adversaries εναντίον AI models, καθώς και τρόπους χρήσης AI systems για την εκτέλεση διαφορετικών attacks.

## LLMJacking (Κλοπή Token και μεταπώληση πρόσβασης σε Cloud-hosted LLM)

Οι Attackers κλέβουν active session tokens ή cloud API credentials και καλούν paid, cloud-hosted LLMs χωρίς authorization. Η πρόσβαση συχνά μεταπωλείται μέσω reverse proxies που λειτουργούν μπροστά από τον λογαριασμό του θύματος, π.χ. deployments του "oai-reverse-proxy". Οι συνέπειες περιλαμβάνουν financial loss, misuse του model εκτός policy και attribution στον tenant του θύματος.

TTPs:
- Συλλογή tokens από infected developer machines ή browsers, κλοπή CI/CD secrets και αγορά leaked cookies.
- Δημιουργία reverse proxy που προωθεί requests στον genuine provider, αποκρύπτοντας το upstream key και εξυπηρετώντας πολλούς customers.
- Abuse των direct base-model endpoints για παράκαμψη των enterprise guardrails και των rate limits.

Mitigations:
- Σύνδεση των tokens με device fingerprint, IP ranges και client attestation· επιβολή σύντομων expirations και refresh με MFA.
- Περιορισμός των keys στο ελάχιστο (χωρίς tool access, read-only όπου εφαρμόζεται) και rotation σε περίπτωση anomaly.
- Τερματισμός όλης της traffic server-side πίσω από policy gateway που επιβάλλει safety filters, per-route quotas και tenant isolation.
- Παρακολούθηση για unusual usage patterns (ξαφνικές spend spikes, atypical regions, UA strings) και αυτόματο revoke ύποπτων sessions.
- Προτίμηση mTLS ή signed JWTs που εκδίδονται από το IdP σας αντί για long-lived static API keys.

## Hardening self-hosted LLM inference

Η εκτέλεση ενός local LLM server για confidential data δημιουργεί διαφορετικό attack surface από τα cloud-hosted APIs: τα inference/debug endpoints μπορεί να προκαλέσουν leak prompts, το serving stack συνήθως εκθέτει ένα reverse proxy και τα GPU device nodes παρέχουν πρόσβαση σε μεγάλες επιφάνειες `ioctl()`. Αν αξιολογείτε ή αναπτύσσετε ένα on-prem inference service, ελέγξτε τουλάχιστον τα ακόλουθα σημεία.

### Prompt leakage μέσω debug και monitoring endpoints

Αντιμετωπίστε το inference API ως **multi-user sensitive service**. Τα debug ή monitoring routes μπορεί να εκθέσουν prompt contents, slot state, model metadata ή internal queue information. Στο `llama.cpp`, το endpoint `/slots` είναι ιδιαίτερα ευαίσθητο, επειδή εκθέτει per-slot state και προορίζεται μόνο για slot inspection/management.

- Τοποθετήστε ένα reverse proxy μπροστά από τον inference server και εφαρμόστε **deny by default**.
- Επιτρέψτε μόνο τα ακριβή HTTP method + path combinations που απαιτούνται από το client/UI.
- Απενεργοποιήστε τα introspection endpoints στο ίδιο το backend όποτε είναι δυνατό, για παράδειγμα `llama-server --no-slots`.
- Κάντε bind το reverse proxy στο `127.0.0.1` και εκθέστε το μέσω authenticated transport, όπως SSH local port forwarding, αντί να το δημοσιεύσετε στο LAN.

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
### Rootless containers χωρίς network και UNIX sockets

Εάν το inference daemon υποστηρίζει listening σε UNIX socket, προτιμήστε το αντί για TCP και εκτελέστε το container με **no network stack**:
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
- Το `--network none` αφαιρεί την εισερχόμενη/εξερχόμενη έκθεση TCP/IP και αποφεύγει user-mode helpers που διαφορετικά θα χρειάζονταν τα rootless containers.
- Ένα UNIX socket σάς επιτρέπει να χρησιμοποιείτε POSIX permissions/ACLs στη διαδρομή του socket ως πρώτο επίπεδο access control.
- Τα `--userns=keep-id` και τα rootless Podman μειώνουν τον αντίκτυπο ενός container breakout, επειδή το root του container δεν είναι το root του host.
- Τα read-only model mounts μειώνουν την πιθανότητα tampering του model από το εσωτερικό του container.

### Ελαχιστοποίηση GPU device-nodes

Για GPU-backed inference, τα αρχεία `/dev/nvidia*` είναι local attack surfaces υψηλής αξίας, επειδή εκθέτουν μεγάλους driver `ioctl()` handlers και δυνητικά κοινόχρηστα GPU memory-management paths.

- Μην αφήνετε τα `/dev/nvidia*` writable από όλους.
- Περιορίστε τα `nvidia`, `nvidiactl` και `nvidia-uvm` με `NVreg_DeviceFileUID/GID/Mode`, udev rules και ACLs, ώστε να μπορούν να τα ανοίγουν μόνο τα mapped container UIDs.
- Κάντε blacklist περιττά modules, όπως τα `nvidia_drm`, `nvidia_modeset` και `nvidia_peermem`, σε headless inference hosts.
- Κάντε preload μόνο τα απαιτούμενα modules κατά το boot, αντί να επιτρέπετε στο runtime να εκτελεί opportunistic `modprobe` κατά το inference startup.

Παράδειγμα:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ένα σημαντικό σημείο ελέγχου είναι το **`/dev/nvidia-uvm`**. Ακόμη και αν το workload δεν χρησιμοποιεί ρητά τη `cudaMallocManaged()`, τα πρόσφατα CUDA runtimes ενδέχεται και πάλι να απαιτούν το `nvidia-uvm`. Επειδή αυτή η συσκευή είναι shared και διαχειρίζεται τη virtual memory της GPU, αντιμετωπίστε την ως επιφάνεια cross-tenant data exposure. Αν το inference backend το υποστηρίζει, ένα Vulkan backend μπορεί να αποτελεί ενδιαφέρον trade-off, επειδή ενδέχεται να αποφεύγει εντελώς την έκθεση του `nvidia-uvm` στο container.

### Περιορισμός μέσω LSM για inference workers

Τα AppArmor/SELinux/seccomp θα πρέπει να χρησιμοποιούνται ως defense in depth γύρω από τη διαδικασία inference:

- Επιτρέψτε μόνο τις shared libraries, τα model paths, τον socket directory και τα GPU device nodes που απαιτούνται στην πράξη.
- Αποκλείστε ρητά capabilities υψηλού κινδύνου, όπως τα `sys_admin`, `sys_module`, `sys_rawio` και `sys_ptrace`.
- Διατηρήστε το model directory read-only και περιορίστε τα writable paths μόνο στα runtime socket/cache directories.
- Παρακολουθείτε τα denial logs, επειδή παρέχουν χρήσιμα detection telemetry όταν ο model server ή ένα post-exploitation payload επιχειρεί να ξεφύγει από την αναμενόμενη συμπεριφορά του.

Παράδειγμα κανόνων AppArmor για worker με GPU:
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
## Phantom Squatting: Domains που έχουν δημιουργηθεί μέσω LLM-Hallucination ως διάνυσμα AI Supply-Chain

Το Phantom squatting είναι το **αντίστοιχο domain/URL του slopsquatting**. Αντί να δημιουργεί μέσω hallucination ένα ανύπαρκτο όνομα package, το LLM δημιουργεί μέσω hallucination ένα εύλογο **portal, API, webhook, billing, SSO, download ή support domain** για ένα πραγματικό brand, και ένας attacker καταχωρεί αυτό το namespace προτού το χρησιμοποιήσει άνθρωπος ή agent.

Αυτό έχει σημασία επειδή σε πολλά AI-assisted workflows το output του μοντέλου αντιμετωπίζεται ως **trusted dependency**:
- Οι developers επικολλούν το προτεινόμενο endpoint σε κώδικα ή CI/CD integrations.
- Οι AI agents κάνουν αυτόματα fetch documentation, schemas, APKs, ZIPs ή webhook targets.
- Τα παραγόμενα runbooks ή docs μπορεί να ενσωματώνουν το fake URL σαν να ήταν authoritative.

### Offensive workflow

1. **Probe το hallucination surface**: κάντε brand-specific ερωτήσεις σχετικά με ρεαλιστικά workflows, όπως `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ή `mobile app` portals.
2. **Normalize τους candidates**: κάντε resolve τα generated URLs, συμπτύξτε τις NXDOMAIN responses στο parent registerable domain και αφαιρέστε τα duplicates από τις prompt families. Τα prompt corpora πρέπει να παραμένουν diverse, για παράδειγμα αφαιρώντας near-duplicates με **Jaccard similarity**.
3. **Δώστε προτεραιότητα σε predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: το ίδιο fake domain εμφανίζεται σε διαφορετικές θερμοκρασίες, ακόμη και σε χαμηλή θερμοκρασία όπως `T=0.1`.
- **Cross-model consensus**: πολλές οικογένειες LLM δημιουργούν το ίδιο fake domain.
4. **Κάντε register και weaponize** το parent domain και στη συνέχεια φιλοξενήστε phishing, fake APK/ZIP downloads, credential harvesters, malicious docs ή API endpoints που συλλέγουν secrets/webhook payloads. Οι **pure domain-level hallucinations** είναι οι ευκολότερες για monetization, επειδή ο attacker ελέγχει ολόκληρο το namespace· τα subdomain/path hallucinations μπορούν επίσης να χρησιμοποιηθούν καταχρηστικά όταν το normalized parent δεν είναι καταχωρημένο.
5. **Εκμεταλλευτείτε το zero-reputation window**: τα newly registered domains συχνά δεν διαθέτουν blocklist history, URL reputation και mature telemetry, επομένως μπορούν να παρακάμψουν τα controls μέχρι να προλάβουν να ενημερωθούν τα detections. Οι attackers μπορούν να παρατείνουν αυτό το window με benign responses μόνο για crawlers, redirect cloaking, CAPTCHA gates ή delayed payload staging.

### Γιατί είναι επικίνδυνο για agents

Για ένα ανθρώπινο θύμα, το fake domain συνήθως απαιτεί ακόμη ένα click και μια επιπλέον ενέργεια. Σε ένα **agentic workflow**, το LLM μπορεί να είναι ταυτόχρονα το **lure** και ο **executor**: ο agent λαμβάνει το hallucinated URL, κάνει fetch σε αυτό, αναλύει την response και μπορεί στη συνέχεια να κάνει leak tokens, να εκτελέσει instructions, να κατεβάσει ένα dependency ή να εισαγάγει poisoned data σε CI/CD χωρίς κανέναν human review.

### Practical attacker prompts

Τα high-yield prompts συνήθως μοιάζουν με κανονικές enterprise tasks αντί για explicit phishing lures:
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Αντιμετωπίστε το ως proactive domain-monitoring problem και όχι μόνο ως prompt-injection problem:
- Δημιουργήστε ένα **brand prompt corpus** και κάντε περιοδικά probe στα LLMs από τα οποία εξαρτώνται οι users/agents σας.
- Αποθηκεύστε τα hallucinated URLs και παρακολουθήστε ποια παραμένουν stable σε διαφορετικές temperatures/models.
- Παρακολουθήστε το **Adversarial Exploitation Window (AEW)**: τον χρόνο μεταξύ του πρώτου hallucination και του attacker registration. Θετικό AEW σημαίνει ότι οι defenders μπορούν να κάνουν pre-register, sinkhole ή pre-block πριν από το weaponization.
- Παρακολουθήστε τις μεταβάσεις **NXDOMAIN → registered** για τα parent domains.
- Κατά την καταχώρηση, κάντε triage στον registrar, την creation date, τους nameservers, το privacy shielding, το page content, τα screenshots, το parked-page status και την ομοιότητα των brand assets.
- Προσθέστε policy gates ώστε οι agents/developers να **μην εμπιστεύονται LLM-generated domains by default**: απαιτήστε allowlists, ownership validation, CT/RDAP checks ή human approval πριν από την πρώτη χρήση.

Αυτό εντάσσεται ταυτόχρονα σε αρκετά AI risk buckets: **AI supply-chain attack**, **insecure model output** και **rogue actions**, όταν οι agents καταναλώνουν αυτόνομα το hallucinated URL.

## Αναφορές
- [Unit 42 – Οι κίνδυνοι των Code Assistant LLMs: Επιβλαβές περιεχόμενο, κακή χρήση και εξαπάτηση](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Επισκόπηση του LLMJacking scheme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: Πώς τα AI Hallucinations τροφοδοτούν μια νέα κατηγορία Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
