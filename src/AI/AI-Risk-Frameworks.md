# Rischi AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificato le 10 principali vulnerabilità di machine learning che possono colpire i sistemi AI. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e adversarial attacks. Comprendere queste vulnerabilità è fondamentale per creare sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità di machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attacker aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso**, inducendo il modello a prendere la decisione sbagliata.\
*Esempio*: Alcuni puntini di vernice su un segnale di stop inducono una self-driving car a "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: Il **training set** viene deliberatamente contaminato con campioni errati, insegnando al modello regole dannose.\
*Esempio*: I file binari di malware vengono etichettati erroneamente come "benign" in un corpus di training per antivirus, permettendo a malware simili di superare i controlli successivi.

- **Model Inversion Attack**: Analizzando gli output, un attacker costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente a partire dalle predizioni di un modello per il rilevamento del cancro.

- **Membership Inference Attack**: L'adversary verifica se un **record specifico** è stato usato durante il training osservando le differenze nel livello di confidenza.\
*Esempio*: Confermare che una transazione bancaria di una persona compaia nei dati di training di un modello per il rilevamento delle frodi.

- **Model Theft**: Query ripetute permettono a un attacker di apprendere i decision boundaries e **clonare il comportamento del modello** (e la relativa IP).\
*Esempio*: Raccogliere un numero sufficiente di coppie Q&A da un'API ML-as-a-Service per creare un modello locale quasi equivalente.

- **AI Supply-Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pre-trained weights, CI/CD) nella **pipeline ML** per corrompere i modelli downstream.\
*Esempio*: Una dependency avvelenata su un model hub installa un modello di sentiment analysis con backdoor in numerose applicazioni.

- **Transfer Learning Attack**: Una logica dannosa viene inserita in un **pre-trained model** e sopravvive al fine-tuning sul task della vittima.\
*Esempio*: Un vision backbone con un trigger nascosto continua a invertire le label dopo essere stato adattato all'imaging medico.

- **Model Skewing**: Dati leggermente biased o etichettati erroneamente **spostano gli output del modello** a favore dell'obiettivo dell'attacker.\
*Esempio*: Inserire email di spam "pulite" etichettate come ham, così che un filtro antispam permetta il passaggio di email future simili.

- **Output Integrity Attack**: L'attacker **modifica le predizioni del modello durante il transito**, senza modificare il modello stesso, ingannando i sistemi downstream.\
*Esempio*: Modificare il verdetto "malicious" di un malware classifier in "benign" prima che la fase di quarantena del file lo riceva.

- **Model Poisoning** --- Modifiche dirette e mirate agli stessi **parametri del modello**, spesso dopo aver ottenuto accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello per il rilevamento delle frodi in produzione, in modo che le transazioni provenienti da determinate carte vengano sempre approvate.


## Google SAIF Risks

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework) di Google descrive diversi rischi associati ai sistemi AI:

- **Data Poisoning**: Attori malicious modificano o inseriscono dati di training/tuning per ridurre l'accuratezza, introdurre backdoor o alterare i risultati, compromettendo l'integrità del modello durante l'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: L'acquisizione di dataset coperti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e relative alle prestazioni, perché il modello apprende da dati per i quali non era mai stato autorizzato all'uso.

- **Model Source Tampering**: La manipolazione, da parte della supply chain o di insider, del codice del modello, delle dependencies o dei pesi prima o durante il training può incorporare logica nascosta che persiste anche dopo il retraining.

- **Excessive Data Handling**: Controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando l'esposizione e il rischio di non conformità.

- **Model Exfiltration**: Gli attacker rubano i file o i pesi del modello, causando la perdita della proprietà intellettuale e consentendo la creazione di servizi copia o attacchi successivi.

- **Model Deployment Tampering**: Gli adversary modificano gli artifact del modello o l'infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e alterandone potenzialmente il comportamento.

- **Denial of ML Service**: Inondare le API o inviare input “sponge” può esaurire risorse di calcolo/energia e rendere il modello offline, replicando i classici attacchi DoS.

- **Model Reverse Engineering**: Raccogliendo grandi quantità di coppie input-output, gli attacker possono clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: Plugin, agent o servizi upstream vulnerabili permettono agli attacker di iniettare codice o fare privilege escalation all'interno della pipeline AI.

- **Prompt Injection**: Creare prompt, direttamente o indirettamente, per inserire di nascosto istruzioni che sovrascrivono l'intento del sistema, facendo eseguire al modello comandi non previsti.

- **Model Evasion**: Input progettati con attenzione inducono il modello a classificare erroneamente, generare hallucination o produrre contenuti non consentiti, compromettendo sicurezza e affidabilità.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o confidenziali provenienti dai dati di training o dal contesto dell'utente, violando privacy e normative.

- **Inferred Sensitive Data**: Il modello deduce attributi personali mai forniti, creando nuovi danni alla privacy attraverso l'inferenza.

- **Insecure Model Output**: Risposte non sanificate trasferiscono codice dannoso, misinformation o contenuti inappropriati agli utenti o ai sistemi downstream.

- **Rogue Actions**: Agent integrati autonomamente eseguono operazioni reali non previste (scrittura di file, chiamate API, acquisti, ecc.) senza un'adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi AI. Classifica diverse tecniche e tattiche di attacco che gli adversary possono usare contro i modelli AI e descrive anche come utilizzare i sistemi AI per eseguire diversi attacchi.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Gli attacker rubano token di sessione attivi o credenziali API cloud e invocano LLM a pagamento ospitati nel cloud senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxy che espongono l'account della vittima, ad esempio deployment "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso improprio del modello al di fuori delle policy e attribuzione al tenant della vittima.

TTPs:
- Raccolgono token da developer machine o browser infetti; rubano secret CI/CD; acquistano cookie leaked.
- Configurano un reverse proxy che inoltra le richieste al provider autentico, nascondendo la chiave upstream e multiplexando molti clienti.
- Abusano degli endpoint direct base-model per bypassare i guardrail enterprise e i rate limit.

Mitigations:
- Associare i token al device fingerprint, agli intervalli IP e alla client attestation; imporre scadenze brevi ed eseguire il refresh con MFA.
- Limitare al minimo lo scope delle chiavi (nessun accesso agli strumenti, sola lettura dove applicabile); eseguire la rotazione in caso di anomalie.
- Terminare tutto il traffico lato server dietro un policy gateway che imponga safety filter, quote per route e isolamento dei tenant.
- Monitorare pattern di utilizzo insoliti (improvvisi picchi di spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a API key statiche di lunga durata.

## Self-hosted LLM inference hardening

L'esecuzione di un server LLM locale per dati confidenziali crea una attack surface diversa rispetto alle API ospitate nel cloud: gli endpoint di inference/debug possono causare leak dei prompt, lo serving stack solitamente espone un reverse proxy e i device node GPU forniscono accesso a grandi superfici `ioctl()`. Se stai valutando o effettuando il deployment di un servizio di inference on-prem, verifica almeno i seguenti punti.

### Prompt leakage via debug and monitoring endpoints

Tratta l'inference API come un **servizio sensibile multi-utente**. Le route di debug o monitoring possono esporre contenuti dei prompt, stato degli slot, metadata del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato per slot ed è destinato esclusivamente all'ispezione/gestione degli slot.

- Inserisci un reverse proxy davanti al server di inference e **nega tutto per impostazione predefinita**.
- Inserisci nella allowlist solo le combinazioni esatte di metodo HTTP + path necessarie al client/UI.
- Disabilita gli endpoint di introspection direttamente nel backend quando possibile, ad esempio `llama-server --no-slots`.
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

Se il daemon di inference supporta l'ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container senza alcuno **stack di rete**:
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
- Un socket UNIX consente di usare permessi/ACL POSIX sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e rootless Podman riducono l'impatto di un container breakout perché il root del container non è il root dell'host.
- I mount dei modelli in sola lettura riducono la possibilità di manomissione dei modelli dall'interno del container.

### Minimizzazione dei device-node GPU

Per l'inference con GPU, i file `/dev/nvidia*` sono superfici di attacco locali di grande valore perché espongono grandi handler `ioctl()` del driver e percorsi potenzialmente condivisi per la gestione della memoria GPU.

- Non lasciare `/dev/nvidia*` scrivibili da chiunque.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo l'UID mappato del container possa aprirli.
- Inserisci nella blacklist i moduli non necessari, come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, sugli host headless per l'inference.
- Precarica solo i moduli necessari all'avvio invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inference.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un importante punto di revisione è **`/dev/nvidia-uvm`**. Anche se il workload non utilizza esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, trattalo come una superficie di esposizione dei dati cross-tenant. Se il backend di inferenza lo supporta, un backend Vulkan può rappresentare un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.

### Confinamento LSM per gli inference worker

AppArmor/SELinux/seccomp dovrebbero essere utilizzati come defense in depth intorno al processo di inferenza:

- Consenti solo le librerie condivise, i percorsi dei modelli, la directory dei socket e i device GPU effettivamente necessari.
- Nega esplicitamente capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la directory dei modelli in sola lettura e limita i percorsi scrivibili alle sole directory dei socket/runtime e della cache.
- Monitora i log dei dinieghi, perché forniscono una telemetria utile per il rilevamento quando il model server o un payload di post-exploitation tenta di evadere dal comportamento previsto.

Esempio di regole AppArmor per un worker con supporto GPU:
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

Il phantom squatting è l'**equivalente dominio/URL dello slopsquatting**. Invece di allucinare un nome di pacchetto inesistente, l'LLM allucina un **dominio plausibile per un portale, un'API, un webhook, la fatturazione, l'SSO, il download o il supporto** di un brand reale, e un attacker registra quello spazio dei nomi prima che un essere umano o un agente lo utilizzi.

Questo è importante perché in molti workflow assistiti dall'AI l'output del modello viene trattato come una **dipendenza trusted**:
- Gli sviluppatori incollano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agenti AI recuperano automaticamente documentazione, schemi, APK, ZIP o target webhook.
- Runbook o documentazione generati possono incorporare il fake URL come se fosse autorevole.

### Workflow offensivo

1. **Sonda la superficie delle allucinazioni**: poni domande specifiche sul brand relative a workflow realistici, come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.
2. **Normalizza i candidati**: risolvi gli URL generati, riduci le risposte NXDOMAIN al parent registerable domain e deduplica le famiglie di prompt. I corpora di prompt devono rimanere diversificati, ad esempio eliminando i quasi-duplicati con la **similarità di Jaccard**.
3. **Dai priorità alle allucinazioni prevedibili**:
- **Thermal Hallucination Persistence (THP)**: lo stesso fake domain compare a diverse temperature, inclusa una temperatura bassa come `T=0.1`.
- **Consenso tra modelli**: più famiglie di LLM generano lo stesso fake domain.
4. **Registra e weaponize** il parent domain, quindi ospita phishing, fake APK/ZIP, credential harvester, documenti malevoli o endpoint API che raccolgono secret/payload webhook. Le **allucinazioni esclusivamente a livello di dominio** sono le più semplici da monetizzare perché l'attacker controlla l'intero namespace; le allucinazioni di sottodominio/percorso possono comunque essere abusate quando il parent normalizzato non è registrato.
5. **Sfrutta la finestra a reputazione zero**: i domini appena registrati spesso non hanno una cronologia nelle blocklist, reputazione URL o telemetria matura, quindi possono bypassare i controlli finché le detection non si aggiornano. Gli attacker possono estendere questa finestra usando risposte benigne solo per i crawler, redirect cloaking, CAPTCHA gate o staging ritardato del payload.

### Perché è pericoloso per gli agenti

Per una vittima umana, il fake domain di solito richiede comunque un click e un'azione aggiuntiva. In un **workflow agentico**, l'LLM può essere sia l'**esca** sia l'**esecutore**: l'agente riceve l'URL allucinato, lo recupera, analizza la risposta e potrebbe poi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati nella CI/CD senza alcuna revisione umana.

### Prompt offensivi pratici

I prompt ad alto rendimento di solito assomigliano a normali task aziendali, invece che a esche di phishing esplicite:
- “Qual è l'URL della payment sandbox per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le notifiche di build di `<brand>`?”
- “Dov'è il portale employee benefits / billing / SSO di `<brand>`?”
- “Dammi il download diretto dell'APK Android o del client desktop di `<brand>`.”

### Inversione difensiva

Tratta il problema come un'attività di monitoraggio proattivo dei domini, non solo come un problema di prompt injection:
- Crea un **corpus di prompt per brand** e sonda periodicamente gli LLM sui quali fanno affidamento i tuoi utenti/agenti.
- Memorizza gli URL allucinati e monitora quali rimangono stabili tra temperature/modelli.
- Monitora l'**Adversarial Exploitation Window (AEW)**: il tempo tra la prima allucinazione e la registrazione da parte dell'attacker. Un AEW positivo significa che i difensori possono effettuare una pre-registrazione, un sinkhole o un pre-block prima della weaponization.
- Monitora le transizioni **NXDOMAIN → registrato** per i parent domain.
- Al momento della registrazione, analizza registrar, data di creazione, nameserver, privacy shielding, contenuto della pagina, screenshot, stato della pagina parcheggiata e similarità con gli asset del brand.
- Aggiungi policy gate affinché agenti/sviluppatori **non considerino trusted per impostazione predefinita i domini generati dagli LLM**: richiedi allowlist, validazione della proprietà, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo rientra contemporaneamente in diverse categorie di rischio dell'AI: **attacco alla supply chain dell'AI**, **output del modello non sicuro** e **azioni rogue** quando gli agenti consumano autonomamente l'URL allucinato.

## Riferimenti
- [Unit 42 – I rischi degli LLM Code Assistant: contenuti dannosi, abuso e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (rivendita dell'accesso LLM rubato)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Analisi approfondita del deployment di un server LLM on-premise con privilegi ridotti](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Quadlet Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Specifiche CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: domini allucinati dall'AI come vettore per la supply chain del software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: come le allucinazioni dell'AI alimentano una nuova classe di attacchi alla supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
