# Rischi dell'AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificato le 10 principali vulnerabilità di machine learning che possono colpire i sistemi di AI. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e attacchi adversarial. Comprendere queste vulnerabilità è fondamentale per costruire sistemi di AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità di machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso**, inducendo il modello a prendere la decisione sbagliata.\
*Esempio*: Alcune macchie di vernice su un segnale di stop ingannano un'auto a guida autonoma, facendole "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: Il **training set** viene deliberatamente contaminato con campioni dannosi, insegnando al modello regole pericolose.\
*Esempio*: I binari di malware vengono etichettati erroneamente come "benign" in un corpus di training per antivirus, consentendo a malware simili di eludere i controlli successivi.

- **Model Inversion Attack**: Analizzando le risposte, un attaccante costruisce un **reverse model** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente a partire dalle predizioni di un modello per il rilevamento del cancro.

- **Membership Inference Attack**: L'avversario verifica se un **record specifico** è stato usato durante il training individuando differenze nel livello di confidenza.\
*Esempio*: Confermare che una transazione bancaria di una persona compaia nei dati di training di un modello per il rilevamento delle frodi.

- **Model Theft**: Query ripetute consentono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la relativa IP).\
*Esempio*: Raccogliere un numero sufficiente di coppie di domande e risposte da un'API ML-as-a-Service per costruire un modello locale quasi equivalente.

- **AI Supply-Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre-trained, CI/CD) nella **ML pipeline** per corrompere i modelli a valle.\
*Esempio*: Una dipendenza compromessa di un model-hub installa un modello di sentiment analysis con una backdoor in numerose app.

- **Transfer Learning Attack**: Una logica dannosa viene inserita in un **pre-trained model** e sopravvive al fine-tuning sull'attività della vittima.\
*Esempio*: Un backbone per computer vision con un trigger nascosto continua a invertire le etichette dopo essere stato adattato all'imaging medico.

- **Model Skewing**: Dati sottilmente distorti o etichettati erroneamente **spostano gli output del modello** a favore dell'agenda dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettate come ham, così che un filtro antispam consenta il passaggio di email future simili.

- **Output Integrity Attack**: L'attaccante **modifica le predizioni del modello durante il transito**, senza modificare il modello stesso, ingannando i sistemi a valle.\
*Esempio*: Modificare il verdetto "malicious" di un classificatore di malware in "benign" prima che la fase di quarantena del file lo rilevi.

- **Model Poisoning** --- Modifiche dirette e mirate agli stessi **parametri del modello**, spesso dopo aver ottenuto accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello per il rilevamento delle frodi in produzione in modo che le transazioni provenienti da determinate carte vengano sempre approvate.


## Google SAIF Risks

La [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google illustra diversi rischi associati ai sistemi di AI:

- **Data Poisoning**: Attori malevoli modificano o iniettano dati di training/tuning per ridurre l'accuratezza, inserire backdoor o distorcere i risultati, compromettendo l'integrità del modello nell'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: L'acquisizione di dataset coperti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e relative alle prestazioni, perché il modello apprende da dati che non era autorizzato a utilizzare.

- **Model Source Tampering**: La manipolazione, da parte della supply chain o di un insider, del codice del modello, delle dipendenze o dei pesi prima o durante il training può incorporare logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: Controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando l'esposizione e i rischi di conformità.

- **Model Exfiltration**: Gli attaccanti rubano i file o i pesi del modello, causando la perdita della proprietà intellettuale e consentendo la creazione di servizi copiati o attacchi successivi.

- **Model Deployment Tampering**: Gli avversari modificano gli artefatti del modello o l'infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e alterandone potenzialmente il comportamento.

- **Denial of ML Service**: Inondare le API o inviare input “sponge” può esaurire risorse computazionali ed energia e portare il modello offline, riproducendo i classici attacchi DoS.

- **Model Reverse Engineering**: Raccogliendo grandi quantità di coppie input-output, gli attaccanti possono clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: Plugin, agenti o servizi upstream vulnerabili consentono agli attaccanti di iniettare codice o aumentare i privilegi all'interno della pipeline di AI.

- **Prompt Injection**: Creare prompt, direttamente o indirettamente, per introdurre di nascosto istruzioni che sovrascrivono l'intento del sistema, inducendo il modello a eseguire comandi non previsti.

- **Model Evasion**: Input progettati con attenzione inducono il modello a classificare erroneamente, generare hallucination o produrre contenuti vietati, compromettendo sicurezza e affidabilità.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o riservate provenienti dai dati di training o dal contesto dell'utente, violando privacy e normative.

- **Inferred Sensitive Data**: Il modello deduce attributi personali che non sono mai stati forniti, creando nuovi danni alla privacy tramite inferenza.

- **Insecure Model Output**: Risposte non sanificate trasmettono codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi a valle.

- **Rogue Actions**: Agenti integrati autonomamente eseguono operazioni indesiderate nel mondo reale (scrittura di file, chiamate API, acquisti, ecc.) senza un'adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi di AI. Classifica diverse tecniche e tattiche di attacco che gli avversari possono utilizzare contro i modelli di AI, nonché i modi in cui i sistemi di AI possono essere usati per eseguire diversi attacchi.


## LLMJacking (Furto di token e rivendita dell'accesso a LLM ospitati nel cloud)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano LLM a pagamento ospitati nel cloud senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxy che fungono da interfaccia per l'account della vittima, ad esempio deployment di "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso improprio del modello al di fuori delle policy e attribuzione delle attività al tenant della vittima.

TTPs:
- Raccogliere token da macchine o browser di sviluppatori infetti; rubare segreti CI/CD; acquistare cookie oggetto di leak.
- Configurare un reverse proxy che inoltra le richieste al provider autentico, nascondendo la chiave upstream e multiplexando molti clienti.
- Abusare degli endpoint direct base-model per aggirare i guardrail enterprise e i rate limit.

Mitigazioni:
- Vincolare i token al fingerprint del dispositivo, agli intervalli IP e alla client attestation; applicare scadenze brevi ed eseguire il refresh con MFA.
- Limitare al minimo lo scope delle chiavi (nessun accesso agli strumenti, sola lettura ove applicabile); eseguire la rotazione in caso di anomalie.
- Terminare tutto il traffico lato server dietro un policy gateway che applichi safety filter, quote per route e isolamento dei tenant.
- Monitorare pattern di utilizzo insoliti (picchi improvvisi di spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a chiavi API statiche di lunga durata.

## Hardening dell'inferenza di LLM self-hosted

L'esecuzione di un server LLM locale per dati riservati crea una attack surface diversa rispetto alle API ospitate nel cloud: gli endpoint di inferenza/debug possono causare leak dei prompt, lo stack di serving espone generalmente un reverse proxy e i device node della GPU consentono l'accesso a grandi superfici `ioctl()`. Se stai valutando o implementando un servizio di inferenza on-prem, verifica almeno i seguenti punti.

### Prompt leakage tramite endpoint di debug e monitoraggio

Tratta l'API di inferenza come un **servizio sensibile multiutente**. Le route di debug o monitoraggio possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato dei singoli slot ed è destinato esclusivamente all'ispezione o alla gestione degli slot.

- Inserisci un reverse proxy davanti al server di inferenza e **nega tutto per impostazione predefinita**.
- Consenti esclusivamente le combinazioni esatte di metodo HTTP + path necessarie al client/UI.
- Disabilita gli endpoint di introspezione direttamente nel backend quando possibile, ad esempio `llama-server --no-slots`.
- Associa il reverse proxy a `127.0.0.1` ed esponilo tramite un transport autenticato, come il port forwarding locale SSH, invece di pubblicarlo sulla LAN.

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
### Container rootless senza rete e socket UNIX

Se il daemon di inferenza supporta l'ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container con **nessuno stack di rete**:
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
- `--network none` rimuove l'esposizione TCP/IP in entrata e in uscita ed evita gli helper in user-mode che i container rootless altrimenti richiederebbero.
- Un socket UNIX consente di usare i permessi/ACL POSIX sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di un container breakout, perché il root del container non è il root dell'host.
- I mount dei modelli in sola lettura riducono la possibilità di manomissione dei modelli dall'interno del container.

### Minimizzazione dei device-node della GPU

Per l'inference basata su GPU, i file `/dev/nvidia*` sono superfici di attacco locali di alto valore, perché espongono grandi handler `ioctl()` del driver e potenzialmente percorsi condivisi di gestione della memoria della GPU.

- Non lasciare `/dev/nvidia*` scrivibili da tutti.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo lo UID mappato del container possa aprirli.
- Inserisci nella blacklist i moduli non necessari, come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, sugli host di inference headless.
- Precarica solo i moduli necessari all'avvio, invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inference.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante della revisione è **`/dev/nvidia-uvm`**. Anche se il workload non utilizza esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, trattatelo come una superficie di esposizione dei dati cross-tenant. Se il backend di inferenza lo supporta, un backend Vulkan può rappresentare un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.

### Confinamento LSM per gli inference worker

AppArmor/SELinux/seccomp dovrebbero essere utilizzati come defense in depth attorno al processo di inferenza:

- Consentire solo le shared library, i percorsi dei modelli, la directory dei socket e i nodi device GPU effettivamente necessari.
- Negare esplicitamente capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenere la directory dei modelli in sola lettura e limitare i percorsi scrivibili alle sole directory dei socket/cache del runtime.
- Monitorare i log dei dinieghi, perché forniscono telemetria utile per il rilevamento quando il model server o un payload di post-exploitation tenta di evadere dal comportamento previsto.

Esempio di regole AppArmor per un worker con GPU:
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
## Phantom Squatting: domini allucinati dagli LLM come vettore per la supply chain dell'AI

Il phantom squatting è l'**equivalente domain/URL dello slopsquatting**. Invece di allucinare il nome di un package inesistente, l'LLM allucina un **dominio plausibile per un portale, un'API, un webhook, la fatturazione, SSO, il download o il supporto** di un brand reale, e un attacker registra quello spazio dei nomi prima che un essere umano o un agent lo utilizzi.

Questo è importante perché, in molti workflow assistiti dall'AI, l'output del modello viene trattato come una **dipendenza trusted**:
- Gli sviluppatori incollano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agent AI recuperano automaticamente documentazione, schemi, APK, ZIP o target webhook.
- Runbook o documentazione generati possono incorporare il fake URL come se fosse autorevole.

### Workflow offensivo

1. **Sondare la superficie delle allucinazioni**: porre domande specifiche sul brand relative a workflow realistici, come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.
2. **Normalizzare i candidati**: risolvere gli URL generati, ricondurre le risposte NXDOMAIN al parent registerable domain e deduplicare le famiglie di prompt. I corpora di prompt devono rimanere diversificati, ad esempio eliminando i quasi duplicati con la **similarità di Jaccard**.
3. **Dare priorità alle allucinazioni prevedibili**:
- **Thermal Hallucination Persistence (THP)**: lo stesso fake domain compare a temperature diverse, inclusa una temperatura bassa come `T=0.1`.
- **Consenso tra modelli**: più famiglie di LLM generano lo stesso fake domain.
4. **Registrare e weaponize** il parent domain, quindi ospitare phishing, fake APK/ZIP download, credential harvester, documenti malevoli o endpoint API che raccolgono secret/payload webhook. Le **allucinazioni pure a livello di dominio** sono le più facili da monetizzare perché l'attacker controlla l'intero namespace; le allucinazioni di subdomain/path possono comunque essere abusate quando il parent normalizzato non è registrato.
5. **Sfruttare la finestra di zero reputation**: i domini registrati di recente spesso non hanno una cronologia nelle blocklist, URL reputation o telemetria consolidata, quindi possono bypassare i controlli finché le detection non si aggiornano. Gli attacker possono estendere questa finestra usando risposte innocue solo per i crawler, redirect cloaking, CAPTCHA gate o staging ritardato dei payload.

### Perché è pericoloso per gli agent

Per una vittima umana, il fake domain di solito richiede comunque un click e un'ulteriore azione. In un **workflow agentic**, l'LLM può essere sia il **lure** sia l'**executor**: l'agent riceve l'URL allucinato, lo recupera, analizza la risposta e può quindi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati nella CI/CD senza alcuna revisione umana.

### Prompt offensivi pratici

I prompt ad alto rendimento di solito sembrano normali task aziendali, invece di esche di phishing esplicite:
- “Qual è l'URL del payment sandbox per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le build notification di `<brand>`?”
- “Dove si trova il portale employee benefits / billing / SSO di `<brand>`?”
- “Dammi il download diretto dell'APK Android o del desktop client di `<brand>`.”

### Inversione difensiva

Trattare il problema come una questione di domain monitoring proattivo, non solo come un problema di prompt injection:
- Creare un **brand prompt corpus** e sondare periodicamente gli LLM sui quali fanno affidamento gli utenti/gli agent.
- Memorizzare gli URL allucinati e monitorare quali rimangono stabili tra temperature/modelli.
- Monitorare l'**Adversarial Exploitation Window (AEW)**: il tempo tra la prima allucinazione e la registrazione da parte dell'attacker. Un AEW positivo indica che i defender possono effettuare una pre-registrazione, un sinkhole o un pre-block prima della weaponization.
- Monitorare le transizioni **NXDOMAIN → registered** per i parent domain.
- Al momento della registrazione, analizzare registrar, data di creazione, nameserver, privacy shielding, contenuto della pagina, screenshot, stato della parked page e similarità degli asset del brand.
- Aggiungere policy gate affinché agent/sviluppatori **non si fidino di default dei domini generati dagli LLM**: richiedere allowlist, validazione della proprietà, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo rientra contemporaneamente in diversi ambiti di rischio dell'AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando gli agent consumano autonomamente l'URL allucinato.

## Riferimenti
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
