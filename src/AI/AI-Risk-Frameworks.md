# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Το Owasp έχει εντοπίσει τις 10 κορυφαίες machine learning vulnerabilities που μπορούν να επηρεάσουν τα AI systems. Αυτές οι vulnerabilities μπορούν να οδηγήσουν σε διάφορα security issues, όπως data poisoning, model inversion και adversarial attacks. Η κατανόηση αυτών των vulnerabilities είναι κρίσιμη για τη δημιουργία ασφαλών AI systems.

Για μια ενημερωμένη και λεπτομερή λίστα των 10 κορυφαίων machine learning vulnerabilities, ανατρέξτε στο project [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Ένας attacker προσθέτει μικροσκοπικές, συχνά αόρατες αλλαγές στα **incoming data**, ώστε το model να λάβει λανθασμένη απόφαση.\
*Example*: Μερικές κηλίδες μπογιάς σε μια πινακίδα stop ξεγελούν ένα self-driving car ώστε να "δει" μια πινακίδα ορίου ταχύτητας.

- **Data Poisoning Attack**: Το **training set** μολύνεται σκόπιμα με κακά samples, διδάσκοντας στο model επιβλαβείς κανόνες.\
*Example*: Malware binaries επισημαίνονται λανθασμένα ως "benign" σε ένα antivirus training corpus, επιτρέποντας σε παρόμοιο malware να περάσει αργότερα.

- **Model Inversion Attack**: Μέσω probing των outputs, ένας attacker δημιουργεί ένα **reverse model** που ανακατασκευάζει ευαίσθητα χαρακτηριστικά των αρχικών inputs.\
*Example*: Αναδημιουργία της MRI εικόνας ενός ασθενούς από τις predictions ενός cancer-detection model.

- **Membership Inference Attack**: Ο adversary ελέγχει αν ένα **specific record** χρησιμοποιήθηκε κατά το training, εντοπίζοντας διαφορές στο confidence.\
*Example*: Επιβεβαίωση ότι μια τραπεζική συναλλαγή ενός ατόμου περιλαμβάνεται στα training data ενός fraud-detection model.

- **Model Theft**: Τα επαναλαμβανόμενα queries επιτρέπουν σε έναν attacker να μάθει τα decision boundaries και να **clone the model's behavior** (και το IP του).\
*Example*: Συλλογή αρκετών Q&A pairs από ένα ML-as-a-Service API για τη δημιουργία ενός σχεδόν ισοδύναμου local model.

- **AI Supply-Chain Attack**: Η παραβίαση οποιουδήποτε component (data, libraries, pre-trained weights, CI/CD) στο **ML pipeline** μπορεί να αλλοιώσει τα downstream models.\
*Example*: Ένα poisoned dependency σε model-hub εγκαθιστά ένα backdoored sentiment-analysis model σε πολλές apps.

- **Transfer Learning Attack**: Κακόβουλη λογική τοποθετείται σε ένα **pre-trained model** και επιβιώνει από το fine-tuning για το task του θύματος.\
*Example*: Ένα vision backbone με κρυφό trigger συνεχίζει να αντιστρέφει τα labels αφού προσαρμοστεί για medical imaging.

- **Model Skewing**: Διακριτικά biased ή mislabeled data **μετατοπίζουν τα outputs του model** ώστε να ευνοούν την ατζέντα του attacker.\
*Example*: Εισαγωγή "clean" spam emails με label ham, ώστε ένα spam filter να επιτρέπει παρόμοια μελλοντικά emails.

- **Output Integrity Attack**: Ο attacker **αλλάζει τις predictions του model κατά τη μεταφορά**, όχι το ίδιο το model, εξαπατώντας τα downstream systems.\
*Example*: Αλλαγή του verdict ενός malware classifier από "malicious" σε "benign" πριν το δει το file-quarantine stage.

- **Model Poisoning** --- Άμεσες, στοχευμένες αλλαγές στα ίδια τα **model parameters**, συνήθως μετά την απόκτηση write access, για την αλλαγή της συμπεριφοράς.\
*Example*: Τροποποίηση των weights ενός fraud-detection model σε production, ώστε οι συναλλαγές από ορισμένες κάρτες να εγκρίνονται πάντα.


## Google SAIF Risks

Το [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) της Google περιγράφει διάφορους risks που σχετίζονται με AI systems:

- **Data Poisoning**: Κακόβουλοι actors τροποποιούν ή εισάγουν training/tuning data για να υποβαθμίσουν την ακρίβεια, να εγκαταστήσουν backdoors ή να στρεβλώσουν τα αποτελέσματα, υπονομεύοντας την ακεραιότητα του model σε ολόκληρο τον κύκλο ζωής των data.

- **Unauthorized Training Data**: Η εισαγωγή copyrighted, sensitive ή μη επιτρεπόμενων datasets δημιουργεί legal, ethical και performance liabilities, επειδή το model μαθαίνει από data που δεν επιτρεπόταν ποτέ να χρησιμοποιήσει.

- **Model Source Tampering**: Supply-chain ή insider manipulation του model code, των dependencies ή των weights πριν ή κατά το training μπορεί να ενσωματώσει hidden logic που παραμένει ακόμη και μετά το retraining.

- **Excessive Data Handling**: Αδύναμοι έλεγχοι data-retention και governance οδηγούν τα systems στην αποθήκευση ή επεξεργασία περισσότερων personal data από όσα είναι απαραίτητα, αυξάνοντας το exposure και το compliance risk.

- **Model Exfiltration**: Attackers κλέβουν model files/weights, προκαλώντας απώλεια intellectual property και επιτρέποντας copy-cat services ή follow-on attacks.

- **Model Deployment Tampering**: Adversaries τροποποιούν model artifacts ή serving infrastructure, ώστε το running model να διαφέρει από την ελεγμένη έκδοση, αλλάζοντας ενδεχομένως τη συμπεριφορά του.

- **Denial of ML Service**: Η πλημμύρα των APIs ή η αποστολή “sponge” inputs μπορεί να εξαντλήσει compute/energy και να θέσει το model εκτός λειτουργίας, όπως στις κλασικές DoS attacks.

- **Model Reverse Engineering**: Συλλέγοντας μεγάλο αριθμό input-output pairs, οι attackers μπορούν να κάνουν clone ή distil το model, τροφοδοτώντας imitation products και customized adversarial attacks.

- **Insecure Integrated Component**: Vulnerable plugins, agents ή upstream services επιτρέπουν σε attackers να εισάγουν code ή να κάνουν privilege escalation μέσα στο AI pipeline.

- **Prompt Injection**: Η δημιουργία prompts (άμεσα ή έμμεσα) για τη μεταφορά instructions που παρακάμπτουν το system intent, κάνοντας το model να εκτελεί unintended commands.

- **Model Evasion**: Carefully designed inputs προκαλούν στο model mis-classification, hallucination ή output disallowed content, διαβρώνοντας την ασφάλεια και την εμπιστοσύνη.

- **Sensitive Data Disclosure**: Το model αποκαλύπτει private ή confidential information από τα training data ή το user context, παραβιάζοντας το privacy και τους regulations.

- **Inferred Sensitive Data**: Το model συμπεραίνει personal attributes που δεν παρασχέθηκαν ποτέ, δημιουργώντας νέες παραβιάσεις privacy μέσω inference.

- **Insecure Model Output**: Μη sanitized responses μεταφέρουν harmful code, misinformation ή inappropriate content σε users ή downstream systems.

- **Rogue Actions**: Autonomously-integrated agents εκτελούν unintended real-world operations (file writes, API calls, purchases κ.λπ.) χωρίς επαρκές user oversight.

## Mitre AI ATLAS Matrix

Το [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) παρέχει ένα comprehensive framework για την κατανόηση και τον μετριασμό των risks που σχετίζονται με AI systems. Κατηγοριοποιεί διάφορες attack techniques και tactics που μπορεί να χρησιμοποιήσουν οι adversaries εναντίον AI models, καθώς και τρόπους χρήσης AI systems για την εκτέλεση διαφορετικών attacks.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers κλέβουν ενεργά session tokens ή cloud API credentials και καλούν επί πληρωμή, cloud-hosted LLMs χωρίς authorization. Η πρόσβαση συχνά μεταπωλείται μέσω reverse proxies που λειτουργούν μπροστά από το account του θύματος, π.χ. deployments του "oai-reverse-proxy". Οι συνέπειες περιλαμβάνουν financial loss, model misuse εκτός policy και απόδοση της ευθύνης στον victim tenant.

TTPs:
- Συλλογή tokens από infected developer machines ή browsers· κλοπή CI/CD secrets· αγορά leaked cookies.
- Δημιουργία reverse proxy που προωθεί requests στον genuine provider, αποκρύπτει το upstream key και εξυπηρετεί πολλούς customers.
- Κατάχρηση direct base-model endpoints για παράκαμψη enterprise guardrails και rate limits.

Mitigations:
- Σύνδεση tokens με device fingerprint, IP ranges και client attestation· επιβολή σύντομων expirations και refresh με MFA.
- Περιορισμός των keys στο ελάχιστο (χωρίς tool access, read-only όπου εφαρμόζεται)· rotation σε περίπτωση anomaly.
- Τερματισμός όλης της traffic server-side πίσω από policy gateway που επιβάλλει safety filters, per-route quotas και tenant isolation.
- Monitoring για unusual usage patterns (ξαφνικές spend spikes, atypical regions, UA strings) και auto-revoke ύποπτων sessions.
- Προτίμηση mTLS ή signed JWTs που εκδίδονται από το IdP σας αντί για long-lived static API keys.

## Self-hosted LLM inference hardening

Η εκτέλεση ενός local LLM server για confidential data δημιουργεί διαφορετικό attack surface από τα cloud-hosted APIs: τα inference/debug endpoints μπορεί να κάνουν leak prompts, το serving stack συνήθως εκθέτει ένα reverse proxy και τα GPU device nodes παρέχουν πρόσβαση σε μεγάλες επιφάνειες `ioctl()`. Αν αξιολογείτε ή αναπτύσσετε μια on-prem inference service, εξετάστε τουλάχιστον τα παρακάτω σημεία.

### Prompt leakage via debug and monitoring endpoints

Αντιμετωπίστε το inference API ως **multi-user sensitive service**. Τα debug ή monitoring routes μπορεί να εκθέσουν prompt contents, slot state, model metadata ή internal queue information. Στο `llama.cpp`, το `/slots` endpoint είναι ιδιαίτερα ευαίσθητο, επειδή εκθέτει per-slot state και προορίζεται μόνο για slot inspection/management.

- Τοποθετήστε ένα reverse proxy μπροστά από τον inference server και **deny by default**.
- Κάντε allowlist μόνο των ακριβών συνδυασμών HTTP method + path που χρειάζονται από τον client/UI.
- Απενεργοποιήστε τα introspection endpoints στο ίδιο το backend όποτε είναι δυνατό, για παράδειγμα `llama-server --no-slots`.
- Κάντε bind το reverse proxy στο `127.0.0.1` και εκθέστε το μέσω ενός authenticated transport, όπως SSH local port forwarding, αντί να το δημοσιεύσετε στο LAN.

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

Αν το inference daemon υποστηρίζει ακρόαση σε UNIX socket, προτιμήστε το αντί για TCP και εκτελέστε το container με **no network stack**:
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
Πλεονεκτήματα:
- Το `--network none` αφαιρεί την εισερχόμενη/εξερχόμενη έκθεση TCP/IP και αποφεύγει user-mode helpers που διαφορετικά θα χρειάζονταν τα rootless containers.
- Ένα UNIX socket σάς επιτρέπει να χρησιμοποιείτε POSIX permissions/ACLs στη διαδρομή του socket ως πρώτο επίπεδο access control.
- Τα `--userns=keep-id` και το rootless Podman μειώνουν τον αντίκτυπο ενός container breakout, επειδή το root του container δεν είναι το root του host.
- Τα read-only model mounts μειώνουν την πιθανότητα tampering των models μέσα από το container.

### Ελαχιστοποίηση GPU device nodes

Για GPU-backed inference, τα αρχεία `/dev/nvidia*` είναι high-value local attack surfaces, επειδή εκθέτουν μεγάλους driver `ioctl()` handlers και δυνητικά κοινόχρηστες διαδρομές GPU memory-management.

- Μην αφήνετε τα `/dev/nvidia*` world writable.
- Περιορίστε τα `nvidia`, `nvidiactl` και `nvidia-uvm` με `NVreg_DeviceFileUID/GID/Mode`, udev rules και ACLs, ώστε μόνο το mapped container UID να μπορεί να τα ανοίξει.
- Κάντε blacklist τα μη απαραίτητα modules, όπως τα `nvidia_drm`, `nvidia_modeset` και `nvidia_peermem`, σε headless inference hosts.
- Κάντε preload μόνο των απαιτούμενων modules κατά το boot, αντί να επιτρέπετε στο runtime να εκτελεί opportunistic `modprobe` κατά την εκκίνηση του inference.

Παράδειγμα:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ένα σημαντικό σημείο ελέγχου είναι το **`/dev/nvidia-uvm`**. Ακόμη και αν το workload δεν χρησιμοποιεί ρητά το `cudaMallocManaged()`, τα πρόσφατα CUDA runtimes ενδέχεται να απαιτούν το `nvidia-uvm`. Επειδή αυτή η συσκευή είναι κοινόχρηστη και διαχειρίζεται τη virtual memory της GPU, αντιμετωπίστε την ως επιφάνεια cross-tenant data exposure. Αν το inference backend το υποστηρίζει, ένα Vulkan backend μπορεί να αποτελέσει ενδιαφέρον trade-off, επειδή ενδέχεται να αποφεύγει εντελώς την έκθεση του `nvidia-uvm` στο container.

### LSM confinement για inference workers

Τα AppArmor/SELinux/seccomp θα πρέπει να χρησιμοποιούνται ως defense in depth γύρω από τη διεργασία inference:

- Επιτρέψτε μόνο τις shared libraries, τα model paths, τον socket directory και τα GPU device nodes που απαιτούνται πραγματικά.
- Απαγορεύστε ρητά capabilities υψηλού κινδύνου, όπως `sys_admin`, `sys_module`, `sys_rawio` και `sys_ptrace`.
- Διατηρήστε το model directory ως read-only και περιορίστε τα writable paths αποκλειστικά στους runtime socket/cache directories.
- Παρακολουθείτε τα denial logs, επειδή παρέχουν χρήσιμα detection telemetry όταν ο model server ή ένα post-exploitation payload προσπαθεί να διαφύγει από την αναμενόμενη συμπεριφορά του.

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
## Phantom Squatting: Domains που έχει «φανταστεί» ένα LLM ως διάνυσμα AI Supply-Chain

Το Phantom squatting είναι το **αντίστοιχο domain/URL του slopsquatting**. Αντί να «φαντάζεται» ένα ανύπαρκτο όνομα package, το LLM «φαντάζεται» ένα εύλογο **portal, API, webhook, billing, SSO, download ή support domain** για ένα πραγματικό brand, και ένας attacker καταχωρίζει αυτό το namespace πριν το χρησιμοποιήσει άνθρωπος ή agent.

Αυτό έχει σημασία επειδή σε πολλά AI-assisted workflows η έξοδος του model αντιμετωπίζεται ως **trusted dependency**:
- Οι developers επικολλούν το προτεινόμενο endpoint σε κώδικα ή CI/CD integrations.
- Οι AI agents κάνουν αυτόματα fetch documentation, schemas, APKs, ZIPs ή webhook targets.
- Τα generated runbooks ή docs μπορεί να ενσωματώνουν το fake URL σαν να ήταν authoritative.

### Offensive workflow

1. **Probe το hallucination surface**: κάντε brand-specific ερωτήσεις σχετικά με ρεαλιστικά workflows, όπως `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ή `mobile app` portals.
2. **Normalize τους candidates**: κάντε resolve τα generated URLs, μετατρέψτε τις απαντήσεις NXDOMAIN στο parent registerable domain και αφαιρέστε τα duplicates από τις prompt families. Τα prompt corpora πρέπει να παραμένουν diverse, για παράδειγμα απορρίπτοντας near-duplicates με **Jaccard similarity**.
3. **Prioritize τις προβλέψιμες hallucinations**:
- **Thermal Hallucination Persistence (THP)**: το ίδιο fake domain εμφανίζεται σε διαφορετικές θερμοκρασίες, ακόμη και σε χαμηλή θερμοκρασία όπως `T=0.1`.
- **Cross-model consensus**: πολλές οικογένειες LLM παράγουν το ίδιο fake domain.
4. **Κάντε register και weaponize** το parent domain και στη συνέχεια φιλοξενήστε phishing, fake APK/ZIP downloads, credential harvesters, malicious docs ή API endpoints που συλλέγουν secrets/webhook payloads. Οι **pure domain-level hallucinations** είναι οι ευκολότερες για monetization, επειδή ο attacker ελέγχει ολόκληρο το namespace· οι subdomain/path hallucinations μπορούν επίσης να γίνουν abuse όταν το normalized parent δεν είναι registered.
5. **Εκμεταλλευτείτε το zero-reputation window**: τα newly registered domains συχνά δεν έχουν blocklist history, URL reputation ή ώριμο telemetry, οπότε μπορούν να παρακάμψουν τα controls μέχρι να προλάβουν να ενημερωθούν τα detections. Οι attackers μπορούν να παρατείνουν αυτό το window με benign responses μόνο για crawlers, redirect cloaking, CAPTCHA gates ή delayed payload staging.

### Γιατί είναι επικίνδυνο για agents

Για ένα ανθρώπινο victim, το fake domain συνήθως απαιτεί ακόμη ένα click και μια επιπλέον ενέργεια. Σε ένα **agentic workflow**, το LLM μπορεί να είναι ταυτόχρονα το **lure** και ο **executor**: ο agent λαμβάνει το hallucinated URL, κάνει fetch σε αυτό, αναλύει την απάντηση και μπορεί στη συνέχεια να κάνει leak tokens, να εκτελέσει instructions, να κατεβάσει ένα dependency ή να εισαγάγει poisoned data στο CI/CD χωρίς human review.

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
- Παρακολουθήστε το **Adversarial Exploitation Window (AEW)**: τον χρόνο μεταξύ του πρώτου hallucination και της registration από τον attacker. Θετικό AEW σημαίνει ότι οι defenders μπορούν να κάνουν pre-register, sinkhole ή pre-block πριν από το weaponization.
- Παρακολουθήστε τις μεταβάσεις **NXDOMAIN → registered** για τα parent domains.
- Κατά την registration, ελέγξτε τον registrar, την creation date, τους nameservers, το privacy shielding, το page content, τα screenshots, το parked-page status και την ομοιότητα με brand assets.
- Προσθέστε policy gates ώστε οι agents/developers να **μην εμπιστεύονται domains που έχουν δημιουργηθεί από LLM by default**: απαιτήστε allowlists, ownership validation, CT/RDAP checks ή human approval πριν από την πρώτη χρήση.

Αυτό εμπίπτει ταυτόχρονα σε αρκετές AI risk categories: **AI supply-chain attack**, **insecure model output** και **rogue actions**, όταν agents καταναλώνουν αυτόνομα το hallucinated URL.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
