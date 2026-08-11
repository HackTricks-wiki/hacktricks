# Rischi dell'AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificato le 10 principali vulnerabilità di machine learning che possono colpire i sistemi di AI. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e adversarial attacks. Comprendere queste vulnerabilità è fondamentale per creare sistemi di AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità di machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso**, inducendo il modello a prendere la decisione sbagliata.\
*Esempio*: alcune macchie di vernice su un segnale di stop ingannano un'auto a guida autonoma, facendole "vedere" un segnale con il limite di velocità.

- **Data Poisoning Attack**: il **training set** viene contaminato deliberatamente con campioni dannosi, insegnando al modello regole pericolose.\
*Esempio*: i file binari di malware vengono etichettati erroneamente come "benigni" in un corpus di training per antivirus, consentendo a malware simili di eludere i controlli successivi.

- **Model Inversion Attack**: analizzando gli output, un attaccante costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: ricreare l'immagine MRI di un paziente a partire dalle predizioni di un modello per il rilevamento del cancro.

- **Membership Inference Attack**: l'avversario verifica se un **record specifico** è stato usato durante il training, individuando differenze nei livelli di confidenza.\
*Esempio*: confermare che una transazione bancaria di una persona compare nei dati di training di un modello per il rilevamento delle frodi.

- **Model Theft**: l'interrogazione ripetuta consente a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la relativa IP).\
*Esempio*: raccogliere un numero sufficiente di coppie di domande e risposte da un'API ML-as-a-Service per creare un modello locale quasi equivalente.

- **AI Supply-Chain Attack**: compromettere qualsiasi componente (dati, librerie, pesi pre-trained, CI/CD) nella **pipeline ML** per corrompere i modelli downstream.\
*Esempio*: una dependency avvelenata su un model hub installa un modello di sentiment analysis contenente una backdoor in numerose app.

- **Transfer Learning Attack**: una logica dannosa viene inserita in un **modello pre-trained** e sopravvive al fine-tuning sull'attività della vittima.\
*Esempio*: un backbone per la computer vision con un trigger nascosto continua a invertire le etichette dopo essere stato adattato all'imaging medico.

- **Model Skewing**: dati sottilmente distorti o etichettati erroneamente **spostano gli output del modello** per favorire l'obiettivo dell'attaccante.\
*Esempio*: inserire email spam "pulite" etichettate come ham, così che un filtro antispam lasci passare email future simili.

- **Output Integrity Attack**: l'attaccante **modifica le predizioni del modello durante il transito**, senza alterare il modello stesso, ingannando i sistemi downstream.\
*Esempio*: modificare il verdetto "malicious" di un classificatore di malware in "benign" prima che la fase di quarantena del file lo riceva.

- **Model Poisoning** --- Modifiche dirette e mirate agli **stessi parametri del modello**, spesso dopo aver ottenuto l'accesso in scrittura, per alterarne il comportamento.\
*Esempio*: modificare i pesi di un modello per il rilevamento delle frodi in produzione, così che le transazioni provenienti da determinate carte vengano sempre approvate.


## Rischi Google SAIF

La [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive diversi rischi associati ai sistemi di AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: attori malintenzionati alterano o inseriscono dati di training/tuning per ridurre la precisione, impiantare backdoor o distorcere i risultati, compromettendo l'integrità del modello durante l'intero ciclo di vita dei dati.

- **Dati di training non autorizzati**: l'acquisizione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e relative alle prestazioni, perché il modello apprende da dati che non gli era consentito utilizzare.

- **Manomissione della sorgente del modello**: la manipolazione della supply chain o da parte di insider del codice del modello, delle dependencies o dei pesi, prima o durante il training, può incorporare logica nascosta che persiste anche dopo il retraining.

- **Gestione eccessiva dei dati**: controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando l'esposizione e il rischio di non conformità.

- **Esfiltrazione del modello**: gli attaccanti rubano file o pesi del modello, causando la perdita della proprietà intellettuale e consentendo la creazione di servizi copia o attacchi successivi.

- **Manomissione del deployment del modello**: gli avversari modificano gli artefatti del modello o l'infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e possa alterarne il comportamento.

- **Denial of ML Service**: il flooding delle API o l'invio di input “sponge” può esaurire le risorse di calcolo/energia e rendere il modello offline, come nei classici attacchi DoS.

- **Reverse Engineering del modello**: raccogliendo grandi quantità di coppie input-output, gli attaccanti possono clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Componente integrato non sicuro**: plugin, agenti o servizi upstream vulnerabili consentono agli attaccanti di iniettare codice o effettuare privilege escalation nella pipeline di AI.

- **Prompt Injection**: la creazione di prompt, direttamente o indirettamente, consente di inserire istruzioni che sovrascrivono l'intento del sistema, inducendo il modello a eseguire comandi non previsti.

- **Model Evasion**: input progettati con attenzione inducono il modello a classificare erroneamente, generare hallucinations o produrre contenuti non consentiti, erodendo sicurezza e fiducia.

- **Divulgazione di dati sensibili**: il modello rivela informazioni private o riservate provenienti dai dati di training o dal contesto dell'utente, violando privacy e normative.

- **Dati sensibili inferiti**: il modello deduce attributi personali che non erano mai stati forniti, creando nuovi danni alla privacy tramite inferenza.

- **Output del modello non sicuro**: risposte non sanificate trasmettono codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi downstream.

- **Azioni rogue**: agenti integrati autonomamente eseguono operazioni reali non previste (scrittura di file, chiamate API, acquisti, ecc.) senza un'adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi di AI. Classifica diverse tecniche e tattiche di attacco che gli avversari possono utilizzare contro i modelli di AI, oltre a descrivere come usare i sistemi di AI per eseguire diversi attacchi.<sup>[[3]](#references)</sup>

## LLMJacking (Furto di token e rivendita dell'accesso a LLM ospitati nel cloud)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano LLM a pagamento ospitati nel cloud senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxy che si presentano come account della vittima, ad esempio tramite deployment "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso improprio del modello al di fuori delle policy e attribuzione delle attività al tenant della vittima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- Raccolta di token da macchine o browser di sviluppatori infetti; furto di secret CI/CD; acquisto di cookie leaked.<sup>[[5]](#references)</sup>
- Configurazione di un reverse proxy che inoltra le richieste al provider autentico, nascondendo la chiave upstream e multiplexando numerosi clienti.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuso degli endpoint direct base-model per aggirare i guardrail enterprise e i rate limit.<sup>[[4]](#references)</sup>

Mitigazioni:
- Vincolare i token al fingerprint del dispositivo, agli intervalli IP e alla client attestation; imporre scadenze brevi ed eseguire il refresh con MFA.
- Limitare al minimo lo scope delle chiavi (nessun accesso agli strumenti, sola lettura quando applicabile); effettuare la rotazione in caso di anomalie.
- Terminare tutto il traffico lato server dietro un policy gateway che imponga safety filter, quote per route e isolamento dei tenant.
- Monitorare pattern di utilizzo insoliti (picchi improvvisi di spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a chiavi API statiche di lunga durata.

## Hardening dell'inference di LLM self-hosted

L'esecuzione di un server LLM locale per dati riservati crea una superficie di attacco diversa da quella delle API ospitate nel cloud: gli endpoint di inference/debug possono causare leak dei prompt, lo stack di serving espone normalmente un reverse proxy e i device node della GPU offrono accesso a grandi superfici `ioctl()`. Se stai valutando o implementando un servizio di inference on-prem, esamina almeno i seguenti punti.<sup>[[8]](#references)</sup>

### Leak dei prompt tramite endpoint di debug e monitoraggio

Tratta l'API di inference come un **servizio sensibile multiutente**. Le route di debug o monitoraggio possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato di ogni slot ed è destinato esclusivamente all'ispezione/gestione degli slot.<sup>[[8]](#references)</sup>

- Posiziona un reverse proxy davanti al server di inference e **nega tutto per impostazione predefinita**.
- Consenti solo le combinazioni esatte di metodo HTTP + path necessarie al client/UI.
- Disabilita gli endpoint di introspection direttamente nel backend quando possibile, ad esempio `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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

Se il demone di inferenza supporta l'ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container con **nessuno stack di rete**:<sup>[[8]](#references)</sup>
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
- `--network none` rimuove l'esposizione TCP/IP in entrata/in uscita ed evita gli helper in user mode che i container rootless richiederebbero altrimenti.
- Un socket UNIX consente di usare i permessi/ACL POSIX sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di un container breakout, perché il root del container non è il root dell'host.
- I mount dei modelli in sola lettura riducono la possibilità di manomissione dei modelli dall'interno del container.

Per i deployment persistenti, le stesse restrizioni possono essere espresse come unità Podman Quadlet. Se l'accesso alla GPU viene delegato tramite la Container Device Interface, mantieni la specifica del device CDI il più restrittiva possibile invece di esporre ogni nodo dell'acceleratore.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimizzazione dei device node della GPU

Per l'inference basata su GPU, i file `/dev/nvidia*` sono superfici di attacco locali di alto valore, perché espongono grandi handler `ioctl()` del driver e potenzialmente percorsi condivisi per la gestione della memoria della GPU.<sup>[[8]](#references)</sup>

- Non lasciare `/dev/nvidia*` scrivibili da tutti.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo lo UID del container mappato possa aprirli.
- Inserisci nella blacklist i moduli non necessari come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem` sugli host di inference headless.
- Precarica all'avvio solo i moduli necessari invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inference.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante della revisione è **`/dev/nvidia-uvm`**. Anche se il workload non usa esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, trattalo come una superficie di esposizione dei dati tra tenant. Se l'inference backend lo supporta, un backend Vulkan può rappresentare un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.<sup>[[8]](#references)</sup>

### Confinamento LSM per gli inference worker

AppArmor/SELinux/seccomp dovrebbero essere utilizzati come defense in depth intorno al processo di inference:<sup>[[8]](#references)</sup>

- Consenti solo le shared library, i model path, la directory dei socket e i device node della GPU effettivamente necessari.
- Nega esplicitamente le capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la directory del modello in sola lettura e limita i path scrivibili esclusivamente alle directory dei socket/cache del runtime.
- Monitora i log dei dinieghi, perché forniscono una telemetria utile per il rilevamento quando il model server o un payload di post-exploitation tenta di evadere dal comportamento previsto.

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
## Phantom Squatting: i domini allucinati dagli LLM come vettore per la supply chain dell'AI

Il phantom squatting è l'**equivalente dominio/URL dello slopsquatting**. Invece di allucinare un nome di package inesistente, l'LLM allucina un **dominio plausibile per portali, API, webhook, fatturazione, SSO, download o supporto** di un brand reale, e un attaccante registra quello spazio dei nomi prima che venga usato da una persona o da un agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Questo è importante perché in molti workflow assistiti dall'AI l'output del modello viene trattato come una **dipendenza affidabile**:
- Gli sviluppatori incollano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agent AI recuperano automaticamente documentazione, schemi, APK, ZIP o destinazioni webhook.
- Runbook o documentazione generati possono incorporare l'URL falso come se fosse autorevole.

### Workflow offensivo

1. **Sonda la superficie delle allucinazioni**: poni domande specifiche sul brand relative a workflow realistici come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizza i candidati**: risolvi gli URL generati, riduci le risposte NXDOMAIN al dominio registrabile parent e deduplica le famiglie di prompt. I corpus di prompt devono rimanere diversificati, ad esempio eliminando i quasi-duplicati con la **similarità di Jaccard**.
3. **Dai priorità alle allucinazioni prevedibili**:
- **Thermal Hallucination Persistence (THP)**: lo stesso dominio falso appare a diverse temperature, inclusa una temperatura bassa come `T=0.1`.
- **Consenso tra modelli**: più famiglie di LLM generano lo stesso dominio falso.
4. **Registra e weaponizza** il dominio parent, quindi ospita phishing, download di APK/ZIP falsi, credential harvester, documenti malevoli o endpoint API che raccolgono segreti/payload webhook. Le **allucinazioni pure a livello di dominio** sono le più facili da monetizzare perché l'attaccante controlla l'intero spazio dei nomi; le allucinazioni di sottodominio/percorso possono comunque essere sfruttate quando il parent normalizzato non è registrato.
5. **Sfrutta la finestra a reputazione zero**: i domini appena registrati spesso non hanno una cronologia nelle blocklist, reputazione URL o telemetria consolidata, quindi possono eludere i controlli finché le rilevazioni non si adeguano. Gli attaccanti possono estendere questa finestra usando risposte benigne visibili solo ai crawler, redirect cloaking, CAPTCHA gate o staging ritardato dei payload.

### Perché è pericoloso per gli agent

Per una vittima umana, il dominio falso di solito richiede comunque un clic e un'azione aggiuntiva. In un **workflow agentico**, l'LLM può essere sia l'**esca** sia l'**esecutore**: l'agent riceve l'URL allucinato, lo recupera, analizza la risposta e potrebbe quindi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati nella CI/CD senza alcuna revisione umana.<sup>[[12]](#references)</sup>

### Prompt pratici per l'attaccante

I prompt ad alto rendimento di solito assomigliano a normali task aziendali invece di esche di phishing esplicite:<sup>[[12]](#references)</sup>
- “Qual è l'URL della payment sandbox per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le notifiche di build di `<brand>`?”
- “Dov'è il portale employee benefits / billing / SSO per `<brand>`?”
- “Dammi il download diretto dell'APK Android o del client desktop per `<brand>`.”

### Inversione difensiva

Tratta questo problema come un'attività proattiva di monitoraggio dei domini, non solo come un problema di prompt injection:<sup>[[12]](#references)</sup>
- Crea un **corpus di prompt per brand** e sonda periodicamente gli LLM su cui fanno affidamento i tuoi utenti/agent.
- Archivia gli URL allucinati e monitora quali rimangono stabili tra temperature/modelli.
- Monitora l'**Adversarial Exploitation Window (AEW)**: il tempo tra la prima allucinazione e la registrazione da parte dell'attaccante. Un AEW positivo significa che i difensori possono pre-registrare, fare sinkhole o bloccare preventivamente il dominio prima della weaponization.
- Monitora le transizioni **NXDOMAIN → registrato** per i domini parent.
- Al momento della registrazione, analizza registrar, data di creazione, nameserver, privacy shielding, contenuto della pagina, screenshot, stato della pagina parcheggiata e somiglianza con gli asset del brand.
- Aggiungi policy gate affinché agent/sviluppatori **non considerino attendibili per impostazione predefinita i domini generati dagli LLM**: richiedi allowlist, validazione della proprietà, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo rientra contemporaneamente in diverse categorie di rischio dell'AI: **attacco alla supply chain dell'AI**, **output del modello non sicuro** e **azioni rogue** quando gli agent consumano autonomamente l'URL allucinato.

## References

- [1] [Le 10 principali vulnerabilità del Machine Learning secondo OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rischi](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice delle minacce MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – I rischi degli LLM Code Assistant: contenuti dannosi, uso improprio e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenziali Cloud rubate usate in un nuovo attacco AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (rivendita dell'accesso LLM rubato)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analisi approfondita del deployment di un server LLM on-premise con privilegi limitati](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlet Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifica CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domini allucinati dall'AI come vettore per la supply chain del software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: come le allucinazioni dell'AI alimentano una nuova classe di attacchi alla supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
