# Rischi dell'AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificato le 10 principali vulnerabilità di machine learning che possono colpire i sistemi di AI. Queste vulnerabilità possono portare a diversi problemi di sicurezza, tra cui data poisoning, model inversion e adversarial attacks. Comprendere queste vulnerabilità è fondamentale per creare sistemi di AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità di machine learning, fare riferimento al progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso**, inducendo il modello a prendere la decisione sbagliata.\
*Esempio*: Alcune macchie di vernice su un segnale di stop ingannano un'auto a guida autonoma, inducendola a "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: Il **training set** viene deliberatamente contaminato con campioni errati, insegnando al modello regole dannose.\
*Esempio*: I binari di malware vengono etichettati erroneamente come "benign" in un corpus di training per antivirus, consentendo a malware simili di superare i controlli successivi.

- **Model Inversion Attack**: Analizzando gli output, un attaccante crea un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente dalle predizioni di un modello per il rilevamento del cancro.

- **Membership Inference Attack**: L'avversario verifica se un **record specifico** è stato utilizzato durante il training osservando le differenze nei livelli di confidenza.\
*Esempio*: Confermare che una transazione bancaria di una persona compaia nei dati di training di un modello per il rilevamento delle frodi.

- **Model Theft**: Query ripetute consentono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la relativa IP).\
*Esempio*: Raccogliere un numero sufficiente di coppie Q&A da un'API ML-as-a-Service per creare un modello locale quasi equivalente.

- **AI Supply-Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre-trained, CI/CD) nella **ML pipeline** per corrompere i modelli downstream.\
*Esempio*: Una dipendenza compromessa proveniente da un model-hub installa un modello di sentiment analysis con una backdoor in numerose app.

- **Transfer Learning Attack**: Una logica malevola viene inserita in un **modello pre-trained** e sopravvive al fine-tuning sul task della vittima.\
*Esempio*: Un vision backbone con un trigger nascosto continua a modificare le etichette dopo essere stato adattato all'imaging medico.

- **Model Skewing**: Dati sottilmente distorti o etichettati erroneamente **spostano gli output del modello** a favore dell'agenda dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettate come ham, in modo che un filtro antispam consenta il passaggio di email future simili.

- **Output Integrity Attack**: L'attaccante **modifica le predizioni del modello durante il transito**, senza modificare il modello stesso, ingannando i sistemi downstream.\
*Esempio*: Modificare il verdetto "malicious" di un classificatore di malware in "benign" prima che la fase di quarantena del file lo visualizzi.

- **Model Poisoning** --- Modifiche dirette e mirate agli stessi **parametri del modello**, spesso dopo aver ottenuto l'accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello per il rilevamento delle frodi in produzione, in modo che le transazioni provenienti da determinate carte vengano sempre approvate.


## Google SAIF Risks

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive diversi rischi associati ai sistemi di AI:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Attori malevoli modificano o iniettano dati di training/tuning per ridurre l'accuratezza, introdurre backdoor o distorcere i risultati, compromettendo l'integrità del modello durante l'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: L'acquisizione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e relative alle prestazioni, perché il modello apprende da dati che non era autorizzato a utilizzare.

- **Model Source Tampering**: La manipolazione della supply chain o da parte di insider del codice del modello, delle dipendenze o dei pesi prima o durante il training può inserire logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: Controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando il rischio di esposizione e di non conformità.

- **Model Exfiltration**: Gli attaccanti rubano file/pesi del modello, causando la perdita della proprietà intellettuale e consentendo la creazione di servizi copia o attacchi successivi.

- **Model Deployment Tampering**: Gli avversari modificano gli artefatti del modello o l'infrastruttura di serving, in modo che il modello in esecuzione differisca dalla versione verificata, alterandone potenzialmente il comportamento.

- **Denial of ML Service**: Inondare le API o inviare input “sponge” può esaurire risorse di calcolo/energia e portare il modello offline, in modo analogo ai classici attacchi DoS.

- **Model Reverse Engineering**: Raccogliendo grandi quantità di coppie input-output, gli attaccanti possono clonare o distillare il modello, favorendo prodotti imitativi e adversarial attacks personalizzati.

- **Insecure Integrated Component**: Plugin, agenti o servizi upstream vulnerabili consentono agli attaccanti di iniettare codice o aumentare i privilegi all'interno della pipeline di AI.

- **Prompt Injection**: Creare prompt, direttamente o indirettamente, per introdurre di nascosto istruzioni che sovrascrivono l'intento del sistema, inducendo il modello a eseguire comandi non previsti.

- **Model Evasion**: Input progettati con attenzione inducono il modello a classificare erroneamente, generare hallucination o produrre contenuti non consentiti, erodendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o riservate provenienti dai dati di training o dal contesto dell'utente, violando privacy e normative.

- **Inferred Sensitive Data**: Il modello deduce attributi personali che non sono mai stati forniti, creando nuovi danni alla privacy attraverso l'inferenza.

- **Insecure Model Output**: Risposte non sanificate trasmettono codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi downstream.

- **Rogue Actions**: Agenti integrati autonomamente eseguono operazioni reali non previste (scrittura di file, chiamate API, acquisti, ecc.) senza un'adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi di AI. Classifica varie tecniche e tattiche di attacco che gli avversari possono utilizzare contro i modelli di AI e mostra anche come utilizzare i sistemi di AI per eseguire diversi attacchi.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano LLM a pagamento, ospitati sul cloud, senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxy che utilizzano l'account della vittima, ad esempio implementazioni di "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso improprio del modello al di fuori delle policy e attribuzione al tenant della vittima.<sup>[[2]](#references)[[3]](#references)</sup>

TTP:
- Raccogliere token da macchine degli sviluppatori o browser infetti; rubare segreti CI/CD; acquistare cookie in leak.
- Configurare un reverse proxy che inoltra le richieste al provider reale, nascondendo la chiave upstream e multiplexando numerosi clienti.
- Abusare degli endpoint direct base-model per aggirare i guardrail enterprise e i rate limit.

Mitigazioni:
- Vincolare i token al fingerprint del dispositivo, agli intervalli IP e alla client attestation; applicare scadenze brevi e rinnovare con MFA.
- Limitare al minimo lo scope delle chiavi (nessun accesso agli strumenti, sola lettura ove applicabile); eseguire la rotazione in caso di anomalie.
- Terminare tutto il traffico lato server dietro un policy gateway che applichi safety filter, quote per route e isolamento dei tenant.
- Monitorare pattern di utilizzo insoliti (picchi improvvisi di spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a API key statiche di lunga durata.

## Hardening dell'inferenza LLM self-hosted

Eseguire un server LLM locale per dati riservati crea una attack surface diversa rispetto alle API ospitate sul cloud: gli endpoint di inferenza/debug possono causare leak dei prompt, lo serving stack espone solitamente un reverse proxy e i device node GPU forniscono accesso a grandi superfici `ioctl()`. Se si sta valutando o implementando un servizio di inferenza on-prem, esaminare almeno i seguenti punti.<sup>[[4]](#references)</sup>

### Prompt leakage tramite endpoint di debug e monitoring

Trattare l'API di inferenza come un **servizio sensibile multiutente**. Le route di debug o monitoring possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato per slot ed è destinato esclusivamente all'ispezione/gestione degli slot.<sup>[[4]](#references)[[5]](#references)</sup>

- Posizionare un reverse proxy davanti al server di inferenza e **negare per impostazione predefinita**.
- Consentire solo le combinazioni esatte di metodo HTTP + path necessarie al client/UI.
- Disabilitare gli endpoint di introspezione direttamente nel backend quando possibile, ad esempio `llama-server --no-slots`.
- Associare il reverse proxy a `127.0.0.1` ed esporlo tramite un transport autenticato come il port forwarding locale SSH, invece di pubblicarlo sulla LAN.

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

Se il demone di inferenza supporta l'ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container con **nessuno stack di rete**:
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
- `--network none` rimuove l'esposizione TCP/IP in ingresso/uscita ed evita gli user-mode helpers di cui i container rootless avrebbero altrimenti bisogno.
- Un UNIX socket consente di usare i permessi POSIX/ACL sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di un container breakout, perché il root del container non è il root dell'host.
- I mount dei modelli in sola lettura riducono la possibilità di manomissione dei modelli dall'interno del container.

### Minimizzazione dei device node della GPU

Per l'inference basata su GPU, i file `/dev/nvidia*` sono superfici di attacco locali di grande valore, perché espongono grandi gestori `ioctl()` del driver e percorsi potenzialmente condivisi per la gestione della memoria della GPU.<sup>[[4]](#references)</sup>

- Non lasciare `/dev/nvidia*` scrivibili da chiunque.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo l'UID del container mappato possa aprirli.
- Inserisci nella blacklist i moduli non necessari, come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, sugli host di inference headless.
- Precarica all'avvio solo i moduli necessari, invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inference.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante da verificare è **`/dev/nvidia-uvm`**. Anche se il workload non utilizza esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, consideralo una superficie di esposizione dei dati tra tenant. Se il backend di inference lo supporta, un backend Vulkan può rappresentare un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.

### Confinamento LSM per gli inference worker

AppArmor/SELinux/seccomp dovrebbero essere utilizzati come difesa a strati intorno al processo di inference:<sup>[[4]](#references)</sup>

- Consenti solo le shared libraries, i percorsi dei model, la directory dei socket e i device GPU effettivamente necessari.
- Nega esplicitamente capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la directory dei model in sola lettura e limita i percorsi scrivibili esclusivamente alle directory dei socket/cache di runtime.
- Monitora i log dei denial, perché forniscono utili dati di rilevamento quando il model server o un payload di post-exploitation tenta di evadere dal comportamento previsto.

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

Phantom squatting è l'**equivalente dominio/URL dello slopsquatting**. Invece di allucinare il nome di un package inesistente, l'LLM allucina un plausibile **dominio per portale, API, webhook, pagamenti, SSO, download o supporto** di un brand reale, e un attacker registra quel namespace prima che un essere umano o un agent lo utilizzi.<sup>[[8]](#references)[[9]](#references)</sup>

Questo è importante perché in molti workflow assistiti dall'AI l'output del modello viene trattato come una **dipendenza affidabile**:
- Gli sviluppatori copiano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agent AI recuperano automaticamente documentazione, schemi, APK, ZIP o target webhook.
- I runbook o i documenti generati possono incorporare il fake URL come se fosse autorevole.

### Workflow offensivo

1. **Sonda la superficie delle allucinazioni**: poni domande specifiche sul brand riguardo a workflow realistici, come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.
2. **Normalizza i candidati**: risolvi gli URL generati, riduci le risposte NXDOMAIN al parent domain registrabile e deduplica le famiglie di prompt. I prompt corpus dovrebbero rimanere diversificati, ad esempio eliminando i quasi-duplicati con la **similarità di Jaccard**.
3. **Dai priorità alle allucinazioni prevedibili**:
- **Thermal Hallucination Persistence (THP)**: lo stesso fake domain compare a temperature diverse, inclusa una temperatura bassa come `T=0.1`.
- **Consenso tra modelli**: più famiglie di LLM generano lo stesso fake domain.
4. **Registra e weaponize** il parent domain, quindi ospita phishing, fake APK/ZIP download, credential harvester, documenti malevoli o endpoint API che raccolgono secret/payload webhook. Le **allucinazioni esclusivamente a livello di dominio** sono le più facili da monetizzare perché l'attacker controlla l'intero namespace; le allucinazioni di subdomain/path possono comunque essere sfruttate quando il parent normalizzato non è registrato.
5. **Sfrutta la finestra di reputazione zero**: i domini registrati di recente spesso non hanno uno storico nelle blocklist, URL reputation o telemetria consolidata, quindi possono bypassare i controlli finché le detection non si aggiornano. Gli attacker possono estendere questa finestra usando risposte benigne visibili solo ai crawler, redirect cloaking, CAPTCHA gate o staging ritardato del payload.

### Perché è pericoloso per gli agent

Per una vittima umana, il fake domain di solito richiede comunque un click e un'ulteriore azione. In un **workflow agentic**, l'LLM può essere sia il **lure** sia l'**executor**: l'agent riceve l'URL allucinato, lo recupera, analizza la risposta e potrebbe quindi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati in CI/CD senza alcuna revisione umana.<sup>[[8]](#references)</sup>

### Prompt offensivi pratici

I prompt ad alto rendimento di solito assomigliano a normali task aziendali, invece di essere lure di phishing espliciti:
- “Qual è l'URL del payment sandbox per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le build notifications di `<brand>`?”
- “Dove si trova il portale employee benefits / billing / SSO di `<brand>`?”
- “Dammi il download diretto dell'Android APK o del desktop client di `<brand>`.”

### Inversione difensiva

Considera questo un problema di domain monitoring proattivo, non solo un problema di prompt injection:
- Crea un **brand prompt corpus** e sonda periodicamente gli LLM su cui fanno affidamento i tuoi utenti/agent.
- Memorizza gli URL allucinati e monitora quali rimangono stabili tra temperature e modelli.
- Monitora l'**Adversarial Exploitation Window (AEW)**: il tempo tra la prima allucinazione e la registrazione da parte dell'attacker. Un AEW positivo significa che i defender possono effettuare una preregistrazione, un sinkhole o un pre-block prima della weaponization.
- Monitora le transizioni **NXDOMAIN → registered** per i parent domain.
- Al momento della registrazione, analizza registrar, data di creazione, nameserver, privacy shielding, contenuto della pagina, screenshot, stato della parked page e similarità degli asset del brand.
- Aggiungi policy gate affinché agent/sviluppatori **non si fidino dei domini generati dagli LLM per impostazione predefinita**: richiedi allowlist, validazione della proprietà, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo rientra contemporaneamente in diversi ambiti di rischio dell'AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando gli agent consumano autonomamente l'URL allucinato.

## Riferimenti
- [1] [Unit 42 – I rischi degli LLM Code Assistant: contenuti dannosi, uso improprio e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (rivendita di accesso LLM rubato)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Analisi approfondita del deployment di un server LLM on-premise con privilegi ridotti](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Quadlet Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [Specifiche CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: domini allucinati dall'AI come vettore per la software supply chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: come le allucinazioni dell'AI alimentano una nuova classe di supply-chain attack](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
