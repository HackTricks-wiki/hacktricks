# Rischi AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilità del Machine Learning

OWASP ha identificato le prime 10 vulnerabilità del machine learning che possono influenzare i sistemi AI. Queste vulnerabilità possono portare a vari problemi di sicurezza, inclusi data poisoning, model inversion e adversarial attacks. Comprendere queste vulnerabilità è cruciale per costruire sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle top 10 vulnerabilità del machine learning, fare riferimento al progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso** in modo che il modello prenda la decisione sbagliata.\
*Esempio*: Alcuni schizzi di vernice su un segnale di stop ingannano un'auto self‑driving facendole "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: Il **training set** viene deliberatamente inquinato con campioni dannosi, insegnando al modello regole nocive.\
*Esempio*: File binari di malware vengono etichettati come "benign" in un corpus di training per antivirus, permettendo a malware simili di passare in seguito.

- **Model Inversion Attack**: Interrogando le uscite, un attaccante costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente a partire dalle predizioni di un modello di rilevamento del cancro.

- **Membership Inference Attack**: L'avversario verifica se un **record specifico** è stato usato durante il training individuando differenze di confidenza.\
*Esempio*: Confermare che la transazione bancaria di una persona appare nei dati di training di un modello di rilevamento frodi.

- **Model Theft**: Query ripetute permettono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: Raccogliere abbastanza coppie Q&A da un'API ML‑as‑a‑Service per costruire un modello locale quasi equivalente.

- **AI Supply‑Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre‑trained, CI/CD) nella **ML pipeline** per corrompere i modelli a valle.\
*Esempio*: Una dipendenza avvelenata su un model‑hub installa un modello di sentiment‑analysis backdoored su molte app.

- **Transfer Learning Attack**: Logica malevola viene piantata in un **modello pre‑trained** e sopravvive al fine‑tuning sul task della vittima.\
*Esempio*: Un vision backbone con un trigger nascosto continua a invertire le label dopo essere stato adattato per imaging medico.

- **Model Skewing**: Dati sottilmente distorti o etichettati male **spostano le uscite del modello** per favorire l'agenda dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettate come ham in modo che un filtro antispam lasci passare email simili in futuro.

- **Output Integrity Attack**: L'attaccante **manomette le predizioni del modello in transito**, non il modello stesso, ingannando i sistemi a valle.\
*Esempio*: Cambiare il verdetto "malicious" di un classifier di malware in "benign" prima che la fase di quarantine dei file lo veda.

- **Model Poisoning** --- Modifiche dirette e mirate ai **parametri del modello** stessi, spesso dopo aver ottenuto accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello di rilevamento frodi in produzione in modo che le transazioni da determinate carte siano sempre approvate.


## Google SAIF - Rischi

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google elenca vari rischi associati ai sistemi AI:

- **Data Poisoning**: Attori malintenzionati alterano o iniettano dati di training/tuning per degradare l'accuratezza, impiantare backdoor o distorcere i risultati, compromettendo l'integrità del modello lungo tutto il ciclo di vita dei dati.

- **Unauthorized Training Data**: L'ingestione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e di performance perché il modello apprende da dati che non avrebbe dovuto usare.

- **Model Source Tampering**: Manipolazione della supply‑chain o insider di codice del modello, dipendenze o pesi prima o durante l'addestramento può inserire logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: Controlli deboli su retention e governance dei dati portano i sistemi a conservare o trattare più dati personali del necessario, aumentando l'esposizione e il rischio di compliance.

- **Model Exfiltration**: Attaccanti rubano file/pesi del modello, causando perdita di proprietà intellettuale e abilitando servizi imitativi o attacchi successivi.

- **Model Deployment Tampering**: Avversari modificano artefatti del modello o infrastrutture di serving in modo che il modello in esecuzione differisca dalla versione verificata, potenzialmente cambiandone il comportamento.

- **Denial of ML Service**: Saturare le API o inviare input “sponge” può esaurire compute/energia e mettere offline il modello, replicando classici attacchi DoS.

- **Model Reverse Engineering**: Raccogliendo grandi quantità di coppie input‑output, gli attaccanti possono clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: Plugin vulnerabili, agent o servizi upstream consentono agli attaccanti di iniettare codice o escalation di privilegi all'interno della pipeline AI.

- **Prompt Injection**: Creare prompt (direttamente o indirettamente) per contrabbandare istruzioni che sovrascrivono l'intento del sistema, inducendo il modello a eseguire comandi non voluti.

- **Model Evasion**: Input appositamente studiati inducono il modello a misclassificare, a hallucinare o a produrre contenuti non consentiti, erodendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o riservate dal suo training data o dal contesto utente, violando privacy e regolamentazioni.

- **Inferred Sensitive Data**: Il modello deduce attributi personali mai forniti, creando nuovi danni alla privacy attraverso l'inferenza.

- **Insecure Model Output**: Risposte non sanificate passano codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi a valle.

- **Rogue Actions**: Agenti integrati autonomamente eseguono operazioni reali indesiderate (scrittura di file, chiamate API, acquisti, ecc.) senza adeguata supervisione utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework comprensivo per comprendere e mitigare i rischi associati ai sistemi AI. Classifica varie tecniche e tattiche d'attacco che gli avversari possono usare contro i modelli AI e anche come usare sistemi AI per compiere diversi attacchi.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers steal active session tokens or cloud API credentials and invoke paid, cloud-hosted LLMs without authorization. Access is often resold via reverse proxies that front the victim’s account, e.g. "oai-reverse-proxy" deployments. Consequences include financial loss, model misuse outside policy, and attribution to the victim tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## Rafforzamento dell'inferenza LLM self-hosted

Eseguire un server LLM locale per dati confidenziali crea una superficie d'attacco diversa rispetto alle API cloud-hosted: gli endpoint di inference/debug possono causare leak dei prompt, lo stack di serving solitamente espone un reverse proxy, e i device node GPU danno accesso a una vasta superficie di `ioctl()`. Se stai valutando o distribuendo un servizio di inferenza on‑prem, rivedi almeno i seguenti punti.

### Prompt leakage via debug and monitoring endpoints

Considera l'API di inferenza come un **multi-user sensitive service**. Le rotte di debug o monitoring possono esporre il contenuto dei prompt, lo stato degli slot, i metadata del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato per‑slot ed è pensato solo per ispezione/gestione degli slot.

- Metti un reverse proxy davanti al server di inferenza e **deny by default**.
- Allowlist solo le esatte combinazioni di HTTP method + path necessarie al client/UI.
- Disabilita gli endpoint di introspezione nel backend stesso ogni volta che è possibile, per esempio `llama-server --no-slots`.
- Bind il reverse proxy a `127.0.0.1` ed esponilo tramite un trasporto autenticato come SSH local port forwarding invece di pubblicarlo sulla LAN.

Esempio di allowlist con nginx:
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
### Rootless containers senza network e UNIX sockets

Se l'inference daemon supporta l'ascolto su una UNIX socket, preferiscilo a TCP ed esegui il container con **no network stack**:
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
Vantaggi:
- `--network none` rimuove l'esposizione TCP/IP in ingresso/uscita e evita user-mode helpers che i container rootless altrimenti richiederebbero.
- Un socket UNIX permette di usare permessi/ACL POSIX sul percorso del socket come primo livello di controllo accessi.
- `--userns=keep-id` e rootless Podman riducono l'impatto di un container breakout perché il root del container non è il root dell'host.
- I mount del modello in sola lettura riducono la probabilità di manomissione del modello dall'interno del container.

### Minimizzazione dei device node GPU

Per l'inferenza supportata da GPU, i file `/dev/nvidia*` sono superfici d'attacco locali ad alto valore perché espongono grandi handler del driver `ioctl()` e potenzialmente percorsi condivisi di gestione della memoria GPU.

- Non lasciare `/dev/nvidia*` scrivibili da tutti.
- Restringere `nvidia`, `nvidiactl`, e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev, e ACL in modo che solo lo UID mappato del container possa aprirli.
- Mettere in blacklist moduli non necessari come `nvidia_drm`, `nvidia_modeset`, e `nvidia_peermem` sugli host di inferenza headless.
- Precaricare solo i moduli richiesti all'avvio invece di lasciare che il runtime li carichi in modo opportunistico con `modprobe` durante l'avvio dell'inferenza.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto di verifica importante è **`/dev/nvidia-uvm`**. Anche se il carico di lavoro non usa esplicitamente `cudaMallocManaged()`, le runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, trattalo come una superficie di esposizione dei dati tra tenant. Se il backend di inference lo supporta, un backend Vulkan può essere un compromesso interessante perché può evitare di esporre `nvidia-uvm` al container.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp dovrebbero essere utilizzati come difesa in profondità attorno al processo di inference:

- Permettere solo le librerie condivise, i percorsi dei modelli, la directory dei socket e i device node GPU effettivamente necessari.
- Negare esplicitamente capacità ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenere la directory del modello in sola lettura e limitare i percorsi scrivibili alle sole directory di socket/cache del runtime.
- Monitorare i denial logs perché forniscono telemetria di rilevamento utile quando il model server o un post-exploitation payload tenta di sfuggire al comportamento previsto.

Example AppArmor rules for a GPU-backed worker:
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
## Riferimenti
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
