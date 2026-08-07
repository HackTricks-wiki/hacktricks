# Rischi dell'AI

{{#include ../banners/hacktricks-training.md}}

## Top 10 OWASP delle vulnerabilità del Machine Learning

Owasp ha identificato le 10 principali vulnerabilità del machine learning che possono interessare i sistemi di AI. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e attacchi adversarial. Comprendere queste vulnerabilità è fondamentale per realizzare sistemi di AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità del machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso** affinché il modello prenda la decisione sbagliata.\
*Esempio*: Alcune macchie di vernice su un segnale di stop confondono un'auto a guida autonoma, facendole "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: Il **training set** viene deliberatamente contaminato con campioni errati, insegnando al modello regole dannose.\
*Esempio*: I binari di malware vengono etichettati erroneamente come "benigni" in un corpus di training per antivirus, permettendo a malware simili di eludere i controlli in seguito.

- **Model Inversion Attack**: Analizzando gli output, un attaccante costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente dalle predizioni di un modello per il rilevamento del cancro.

- **Membership Inference Attack**: L'avversario verifica se un **record specifico** è stato utilizzato durante il training osservando le differenze nei livelli di confidenza.\
*Esempio*: Confermare che una transazione bancaria di una persona compaia nei dati di training di un modello per il rilevamento delle frodi.

- **Model Theft**: Query ripetute permettono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la relativa IP).\
*Esempio*: Raccogliere un numero sufficiente di coppie di domande e risposte da un'API ML-as-a-Service per costruire un modello locale quasi equivalente.

- **AI Supply-Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre-addestrati, CI/CD) nella **pipeline ML** per corrompere i modelli downstream.\
*Esempio*: Una dipendenza avvelenata su un model hub installa un modello di sentiment analysis contenente una backdoor in numerose app.

- **Transfer Learning Attack**: Una logica dannosa viene inserita in un **modello pre-addestrato** e sopravvive al fine-tuning sul task della vittima.\
*Esempio*: Un backbone per la computer vision con un trigger nascosto continua a modificare le label dopo essere stato adattato all'imaging medico.

- **Model Skewing**: Dati sottilmente distorti o etichettati erroneamente **spostano gli output del modello** a favore dell'obiettivo dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettate come ham, in modo che un filtro antispam permetta il passaggio di email future simili.

- **Output Integrity Attack**: L'attaccante **modifica le predizioni del modello durante il transito**, senza alterare il modello stesso, ingannando i sistemi downstream.\
*Esempio*: Modificare il verdetto "malicious" di un classificatore di malware in "benign" prima che la fase di quarantena del file lo riceva.

- **Model Poisoning** --- Modifiche dirette e mirate agli **iperparametri del modello**, spesso dopo aver ottenuto accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello per il rilevamento delle frodi in produzione affinché le transazioni effettuate con determinate carte vengano sempre approvate.


## Rischi Google SAIF

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive diversi rischi associati ai sistemi di AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Attori malintenzionati alterano o iniettano dati di training/tuning per ridurre la precisione, inserire backdoor o distorcere i risultati, compromettendo l'integrità del modello durante l'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: L'acquisizione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e relative alle prestazioni, perché il modello apprende da dati per i quali non era autorizzato all'utilizzo.

- **Model Source Tampering**: La manipolazione da parte della supply chain o di insider del codice del modello, delle dipendenze o dei pesi, prima o durante il training, può inserire logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: Controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando l'esposizione e il rischio di non conformità.

- **Model Exfiltration**: Gli attaccanti rubano i file o i pesi del modello, causando la perdita della proprietà intellettuale e consentendo la creazione di servizi copia o attacchi successivi.

- **Model Deployment Tampering**: Gli avversari modificano gli artefatti del modello o l'infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e possa potenzialmente modificarne il comportamento.

- **Denial of ML Service**: Inondare le API o inviare input "sponge" può esaurire le risorse di calcolo o l'energia e rendere il modello non disponibile, replicando i classici attacchi DoS.

- **Model Reverse Engineering**: Raccogliendo grandi quantità di coppie input-output, gli attaccanti possono clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: Plugin, agent o servizi upstream vulnerabili permettono agli attaccanti di iniettare codice o aumentare i privilegi all'interno della pipeline AI.

- **Prompt Injection**: La creazione diretta o indiretta di prompt consente di introdurre furtivamente istruzioni che sovrascrivono l'intento del sistema, inducendo il modello a eseguire comandi non previsti.

- **Model Evasion**: Input progettati con attenzione inducono il modello a classificare erroneamente, avere allucinazioni o produrre contenuti non consentiti, compromettendo sicurezza e affidabilità.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o riservate presenti nei dati di training o nel contesto dell'utente, violando privacy e normative.

- **Inferred Sensitive Data**: Il modello deduce attributi personali che non erano mai stati forniti, creando nuovi danni alla privacy attraverso l'inferenza.

- **Insecure Model Output**: Risposte non sanificate trasmettono codice dannoso, misinformation o contenuti inappropriati agli utenti o ai sistemi downstream.

- **Rogue Actions**: Agent integrati autonomamente eseguono operazioni reali non previste (scrittura di file, chiamate API, acquisti, ecc.) senza un'adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi di AI. Classifica diverse tecniche e tattiche di attacco che gli avversari possono utilizzare contro i modelli di AI, oltre a descrivere come utilizzare i sistemi di AI per eseguire diversi attacchi.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano LLM a pagamento ospitati sul cloud senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxy che antepongono l'account della vittima, ad esempio deployment di "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso improprio del modello al di fuori delle policy e attribuzione al tenant della vittima.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Raccolta di token da macchine o browser di sviluppatori infetti; furto di secret CI/CD; acquisto di cookie oggetto di leak.<sup>[[5]](#references)</sup>
- Configurazione di un reverse proxy che inoltra le richieste al provider autentico, nascondendo la upstream key e multiplexando numerosi clienti.<sup>[[5]](#references)[[7]](#references)</sup>
- Abuso degli endpoint direct base-model per aggirare i guardrail enterprise e i rate limit.<sup>[[4]](#references)</sup>

Mitigazioni:
- Associare i token al fingerprint del dispositivo, agli intervalli IP e all'attestazione del client; imporre scadenze brevi ed effettuare il refresh con MFA.
- Limitare al minimo lo scope delle key (nessun accesso agli strumenti, sola lettura ove applicabile); effettuare la rotazione in caso di anomalie.
- Terminare tutto il traffico lato server dietro un policy gateway che imponga safety filter, quote per route e isolamento dei tenant.
- Monitorare pattern di utilizzo insoliti (picchi improvvisi di spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a API key statiche di lunga durata.

## Hardening dell'inferenza LLM self-hosted

L'esecuzione di un server LLM locale per dati riservati crea una superficie di attacco diversa rispetto alle API ospitate sul cloud: gli endpoint di inferenza/debug possono esporre i prompt, lo stack di serving solitamente espone un reverse proxy e i device node GPU forniscono accesso a grandi superfici `ioctl()`. Se stai valutando o implementando un servizio di inferenza on-prem, esamina almeno i seguenti punti.<sup>[[8]](#references)</sup>

### Prompt leakage tramite endpoint di debug e monitoraggio

Tratta l'API di inferenza come un **servizio sensibile multiutente**. Le route di debug o monitoraggio possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato per-slot ed è pensato esclusivamente per l'ispezione o la gestione degli slot.<sup>[[8]](#references)</sup>

- Posiziona un reverse proxy davanti al server di inferenza e **nega per impostazione predefinita**.
- Inserisci in allowlist solo le combinazioni esatte di metodo HTTP + path necessarie al client/UI.
- Disabilita gli endpoint di introspezione direttamente nel backend ogni volta che è possibile, ad esempio `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Associa il reverse proxy a `127.0.0.1` ed esponilo tramite un transport autenticato come il port forwarding locale SSH, invece di pubblicarlo sulla LAN.

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

Se il demone di inferenza supporta l'ascolto su un socket UNIX, preferitelo a TCP ed eseguite il container con **nessuno stack di rete**:<sup>[[8]](#references)</sup>
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
- `--network none` rimuove l'esposizione TCP/IP in entrata/uscita ed evita gli helper in user-mode di cui avrebbero altrimenti bisogno i container rootless.
- Un socket UNIX consente di usare i permessi POSIX/ACL sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di un breakout del container, perché il root del container non è il root dell'host.
- I mount dei modelli in sola lettura riducono la probabilità di manomissione dei modelli dall'interno del container.

### Minimizzazione dei device-node della GPU

Per l'inferenza supportata da GPU, i file `/dev/nvidia*` sono superfici di attacco locali di alto valore, perché espongono grandi handler `ioctl()` del driver e potenzialmente percorsi condivisi di gestione della memoria della GPU.<sup>[[8]](#references)</sup>

- Non lasciare `/dev/nvidia*` scrivibili da chiunque.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo l'UID del container mappato possa aprirli.
- Metti in blacklist i moduli non necessari, come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, sugli host di inferenza headless.
- Precarica solo i moduli necessari all'avvio, invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inferenza.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante da verificare è **`/dev/nvidia-uvm`**. Anche se il workload non utilizza esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, consideralo una superficie di esposizione dei dati tra tenant. Se il backend di inference lo supporta, un backend Vulkan può rappresentare un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.<sup>[[8]](#references)</sup>

### Confinamento LSM per i worker di inference

AppArmor/SELinux/seccomp dovrebbero essere utilizzati come difesa in profondità attorno al processo di inference:<sup>[[8]](#references)</sup>

- Consenti solo le shared libraries, i model paths, la socket directory e i GPU device nodes effettivamente necessari.
- Nega esplicitamente capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la model directory in sola lettura e limita i writable paths alle sole runtime socket/cache directories.
- Monitora i log dei dinieghi, perché forniscono dati utili per il rilevamento quando il model server o un post-exploitation payload tenta di evadere dal comportamento previsto.

Esempio di regole AppArmor per un worker basato su GPU:
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
## Phantom Squatting: domini allucinati dagli LLM come vettore per la AI supply-chain

Phantom squatting è l'**equivalente domain/URL dello slopsquatting**. Invece di allucinare il nome di un package inesistente, l'LLM allucina un plausibile **dominio per portali, API, webhook, billing, SSO, download o support** associato a un brand reale, e un attacker registra quel namespace prima che un essere umano o un agent lo utilizzi.<sup>[[12]](#references)[[13]](#references)</sup>

Questo è importante perché in molti workflow assistiti dall'AI l'output del modello viene trattato come una **dipendenza trusted**:
- Gli sviluppatori incollano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli AI agent recuperano automaticamente documentazione, schema, APK, ZIP o target webhook.
- I runbook o i documenti generati possono incorporare il falso URL come se fosse autorevole.

### Flusso di lavoro offensivo

1. **Sonda la superficie delle allucinazioni**: poni domande specifiche sul brand relative a workflow realistici, come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizza i candidati**: risolvi gli URL generati, riduci le risposte NXDOMAIN al parent domain registrabile e deduplica le famiglie di prompt. I corpus di prompt dovrebbero rimanere diversificati, ad esempio eliminando i quasi-duplicati con la **similarità di Jaccard**.
3. **Dai priorità alle allucinazioni prevedibili**:
- **Thermal Hallucination Persistence (THP)**: lo stesso dominio falso appare a diverse temperature, inclusa una temperatura bassa come `T=0.1`.
- **Consenso cross-model**: più famiglie di LLM generano lo stesso dominio falso.
4. **Registra e weaponize** il parent domain, quindi ospita phishing, falsi download di APK/ZIP, credential harvester, documenti malevoli o endpoint API che raccolgono segreti/payload webhook. Le **allucinazioni esclusivamente a livello di dominio** sono le più facili da monetizzare perché l'attacker controlla l'intero namespace; le allucinazioni relative a subdomain/path possono comunque essere abusate quando il parent normalizzato non è registrato.
5. **Sfrutta la zero-reputation window**: i domini appena registrati spesso non hanno una cronologia nei blocklist, URL reputation o telemetria matura, quindi possono aggirare i controlli finché le detection non si aggiornano. Gli attacker possono estendere questa finestra usando risposte benigne solo per i crawler, redirect cloaking, CAPTCHA gate o delayed payload staging.

### Perché è pericoloso per gli agent

Per una vittima umana, il dominio falso richiede solitamente un click e un'azione aggiuntiva. In un **workflow agentic**, l'LLM può essere sia il **lure** sia l'**executor**: l'agent riceve l'URL allucinato, lo recupera, analizza la risposta e può poi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati nella CI/CD senza alcuna revisione umana.<sup>[[12]](#references)</sup>

### Prompt offensivi pratici

I prompt ad alto rendimento di solito assomigliano a normali attività enterprise invece che a lure di phishing espliciti:<sup>[[12]](#references)</sup>
- “Qual è l'URL del payment sandbox per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le notifiche di build di `<brand>`?”
- “Dove si trova il portale employee benefits / billing / SSO di `<brand>`?”
- “Dammi il download diretto dell'APK Android o del client desktop per `<brand>`.”

### Inversione difensiva

Considera il problema come un'attività di domain monitoring proattivo, non solo come un problema di prompt injection:<sup>[[12]](#references)</sup>
- Crea un **brand prompt corpus** e sonda periodicamente gli LLM su cui fanno affidamento i tuoi utenti/agent.
- Memorizza gli URL allucinati e monitora quali rimangono stabili tra temperature e modelli.
- Monitora l'**Adversarial Exploitation Window (AEW)**: il tempo tra la prima allucinazione e la registrazione da parte dell'attacker. Un AEW positivo significa che i defender possono registrare preventivamente, creare un sinkhole o applicare un pre-block prima della weaponization.
- Monitora le transizioni **NXDOMAIN → registered** per i parent domain.
- Al momento della registrazione, analizza registrar, data di creazione, nameserver, privacy shielding, contenuto della pagina, screenshot, stato della pagina parcheggiata e similarità con gli asset del brand.
- Aggiungi policy gate affinché agent e sviluppatori **non considerino trusted per impostazione predefinita i domini generati dagli LLM**: richiedi allowlist, validazione della proprietà, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo fenomeno rientra contemporaneamente in diverse categorie di rischio AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando gli agent consumano autonomamente l'URL allucinato.

## Riferimenti

- [1] [Le 10 principali vulnerabilità del Machine Learning secondo OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rischi](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – I rischi degli LLM Code Assistant: contenuti dannosi, abuso e deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenziali Cloud rubate utilizzate in un nuovo attacco AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (rivendita di accesso LLM rubato)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analisi approfondita del deployment di un server LLM on-premise con privilegi ridotti](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlet Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifiche CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domini allucinati dall'AI come vettore per la Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: come le allucinazioni dell'AI alimentano una nuova classe di supply-chain attack](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
