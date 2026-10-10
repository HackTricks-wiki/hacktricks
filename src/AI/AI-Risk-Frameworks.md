# Rischi dell’AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP ha identificato le 10 principali vulnerabilità del machine learning che possono interessare i sistemi AI. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e attacchi adversarial. Comprenderle è fondamentale per creare sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità del machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso** per indurre il modello a prendere una decisione errata.\
    *Esempio*: alcune macchie di vernice su un segnale di stop inducono un’auto a guida autonoma a "vedere" un limite di velocità.

- **Data Poisoning Attack**: il **training set** viene deliberatamente contaminato con campioni dannosi, insegnando al modello regole nocive.\
*Esempio*: i binari di malware vengono etichettati come "benigni" nel corpus di training di un antivirus, permettendo a malware simili di eludere i controlli in seguito.

- **Model Inversion Attack**: analizzando le risposte, un attaccante crea un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: ricreare la risonanza magnetica di un paziente a partire dalle previsioni di un modello di rilevamento del cancro.

- **Membership Inference Attack**: l’avversario verifica se un **record specifico** è stato usato durante il training, rilevando differenze nei livelli di confidenza.\
*Esempio*: confermare che una persona compare nei dati di training di un modello di rilevamento delle frodi tramite transazioni bancarie.

- **Model Theft**: interrogazioni ripetute consentono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: raccogliere abbastanza coppie di domande e risposte da un’API ML-as-a-Service per creare un modello locale quasi equivalente.

- **AI Supply‑Chain Attack**: compromettere qualsiasi componente (dati, librerie, pesi pre-trained, CI/CD) della **pipeline ML** per corrompere i modelli a valle.\
*Esempio*: una dipendenza avvelenata su un model hub installa un modello di analisi del sentiment con una backdoor in molte app.

- **Transfer Learning Attack**: una logica malevola viene inserita in un **modello pre-trained** e sopravvive al fine-tuning per il task della vittima.\
*Esempio*: una rete vision con un trigger nascosto continua a modificare le etichette anche dopo essere stata adattata all’imaging medico.

- **Model Skewing**: dati sottilmente distorti o etichettati in modo errato **alterano gli output del modello** a favore degli obiettivi dell’attaccante.\
*Esempio*: iniettare email di spam "pulite" etichettate come ham, così che un filtro antispam lasci passare email simili in futuro.

- **Output Integrity Attack**: l’attaccante **altera le previsioni del modello durante il transito**, senza modificare il modello stesso, ingannando i sistemi a valle.\
*Esempio*: modificare il verdetto "malicious" di un classificatore di malware in "benign" prima che venga elaborato dal sistema di quarantena dei file.

- **Model Poisoning** --- Modifiche dirette e mirate agli **iperparametri del modello**, spesso dopo aver ottenuto l’accesso in scrittura, per alterarne il comportamento.\
*Esempio*: modificare i pesi di un modello di rilevamento delle frodi in produzione, in modo che le transazioni di determinate carte vengano sempre approvate.


## Rischi di Google SAIF

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive diversi rischi associati ai sistemi AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: attori malevoli alterano o iniettano dati di training o tuning per ridurre la precisione, inserire backdoor o distorcere i risultati, compromettendo l’integrità del modello durante l’intero ciclo di vita dei dati.

- **Unauthorized Training Data**: l’uso di dataset protetti da copyright, sensibili o non autorizzati comporta rischi legali, etici e prestazionali, perché il modello apprende da dati che non era autorizzato a usare.

- **Model Source Tampering**: la manipolazione della supply chain o da parte di insider del codice del modello, delle dipendenze o dei pesi, prima o durante il training, può introdurre logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a conservare o elaborare più dati personali del necessario, aumentando i rischi di esposizione e di non conformità.

- **Model Exfiltration**: gli attaccanti rubano i file o i pesi del modello, causando la perdita di proprietà intellettuale e consentendo la creazione di servizi imitativi o attacchi successivi.

- **Model Deployment Tampering**: gli avversari modificano gli artifact del modello o l’infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e alterandone potenzialmente il comportamento.

- **Denial of ML Service**: sommergere le API di richieste o inviare input “sponge” può esaurire le risorse di calcolo o energia e mettere offline il modello, come nei classici attacchi DoS.

- **Model Reverse Engineering**: raccogliendo un gran numero di coppie input-output, gli attaccanti possono clonare o distillare il modello, favorendo prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: plugin, agenti o servizi upstream vulnerabili consentono agli attaccanti di iniettare codice o aumentare i privilegi all’interno della pipeline AI.

- **Prompt Injection**: creare prompt, in modo diretto o indiretto, per inserire di nascosto istruzioni che prevalgono sulle intenzioni del sistema e inducono il modello a eseguire comandi non previsti.

- **Model Evasion**: input progettati con cura inducono il modello a classificare in modo errato, allucinare o generare contenuti non consentiti, compromettendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: il modello rivela informazioni private o riservate contenute nei dati di training o nel contesto dell’utente, violando la privacy e le normative.

- **Inferred Sensitive Data**: il modello deduce attributi personali mai forniti, creando nuovi danni alla privacy tramite inferenza.

- **Insecure Model Output**: risposte non sanificate forniscono agli utenti o ai sistemi a valle codice dannoso, disinformazione o contenuti inappropriati.

- **Rogue Actions**: agenti integrati in modo autonomo eseguono operazioni nel mondo reale non previste (scrittura di file, chiamate API, acquisti, ecc.) senza un’adeguata supervisione dell’utente.

## Matrice MITRE AI ATLAS

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) offre un framework completo per comprendere e mitigare i rischi associati ai sistemi AI. Classifica le diverse tecniche di attacco e tattiche che gli avversari possono usare contro i modelli AI, nonché i modi in cui i sistemi AI possono essere usati per eseguire diversi attacchi.<sup>[[3]](#references)</sup>

## LLMJacking (furto di token e rivendita dell’accesso a LLM ospitati nel cloud)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano senza autorizzazione LLM a pagamento ospitati nel cloud. Spesso l’accesso viene rivenduto tramite reverse proxy che si appoggiano all’account della vittima, ad esempio installazioni di "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso del modello al di fuori delle policy e attribuzione delle attività al tenant della vittima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- Raccolta di token da computer di sviluppatori o browser infetti; furto di segreti CI/CD; acquisto di cookie leak.<sup>[[5]](#references)</sup>
- Configurazione di un reverse proxy che inoltra le richieste al provider autentico, nasconde la chiave upstream e distribuisce le richieste tra molti clienti.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuso diretto degli endpoint base-model per aggirare le misure di protezione enterprise e i limiti di frequenza.<sup>[[4]](#references)</sup>

Mitigazioni:
- Associare i token all’impronta digitale del dispositivo, agli intervalli IP e all’attestazione del client; imporre scadenze brevi e aggiornare i token con MFA.
- Limitare al minimo l’ambito delle chiavi (senza accesso agli strumenti, in sola lettura ove applicabile); ruotarle in caso di anomalie.
- Terminare tutto il traffico lato server dietro un policy gateway che applichi filtri di sicurezza, quote per route e isolamento dei tenant.
- Monitorare i pattern di utilizzo insoliti (impennate improvvise della spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a chiavi API statiche di lunga durata.

## Hardening dell’inferenza LLM self-hosted

Eseguire un server LLM locale per dati riservati crea una superficie di attacco diversa rispetto alle API ospitate nel cloud: gli endpoint di inferenza e debug possono causare leak dei prompt, lo stack di serving espone solitamente un reverse proxy e i nodi dispositivo GPU offrono accesso a un’ampia superficie `ioctl()`. Se stai valutando o distribuendo un servizio di inferenza on-prem, esamina almeno i seguenti aspetti.<sup>[[8]](#references)</sup>

### Prompt leakage tramite endpoint di debug e monitoraggio

Considera l’API di inferenza un **servizio sensibile multiutente**. Le route di debug o monitoraggio possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l’endpoint `/slots` è particolarmente sensibile perché espone lo stato dei singoli slot ed è destinato esclusivamente all’ispezione e alla gestione degli slot.<sup>[[8]](#references)</sup>

- Posiziona un reverse proxy davanti al server di inferenza e **nega l’accesso per impostazione predefinita**.
- Inserisci nell’allowlist solo le combinazioni esatte di metodo HTTP e path necessarie al client/UI.
- Disabilita gli endpoint di introspezione nel backend, ove possibile, ad esempio con `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Associa il reverse proxy a `127.0.0.1` ed esponilo tramite un canale di trasporto autenticato, come il port forwarding locale SSH, anziché pubblicarlo sulla LAN.

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

Se il demone di inferenza supporta l'ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container senza **stack di rete**:<sup>[[8]](#references)</sup>

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

Benefici:
- `--network none` rimuove l'esposizione TCP/IP in ingresso e in uscita ed evita gli helper in user mode che altrimenti sarebbero necessari ai container rootless.
- Un socket UNIX consente di usare le autorizzazioni POSIX/ACL sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di un breakout del container, perché l'utente root nel container non è root sull'host.
- I mount dei modelli in sola lettura riducono la possibilità che i modelli vengano manomessi dall'interno del container.

Per i deployment persistenti, le stesse restrizioni possono essere espresse come unità Podman Quadlet. Se l'accesso alla GPU viene delegato tramite Container Device Interface, mantieni la specifica del dispositivo CDI il più limitata possibile, invece di esporre tutti i nodi dell'acceleratore.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Riduzione al minimo dei nodi di dispositivo GPU

Per l'inferenza basata su GPU, i file `/dev/nvidia*` sono superfici di attacco locali di grande valore, perché espongono ampi handler `ioctl()` del driver e percorsi potenzialmente condivisi per la gestione della memoria GPU.<sup>[[8]](#references)</sup>

- Non lasciare `/dev/nvidia*` scrivibili da tutti.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo l'UID del container mappato possa aprirli.
- Inserisci nella blacklist i moduli non necessari, come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, sugli host di inferenza headless.
- Precarica solo i moduli necessari all'avvio, invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inferenza.

Esempio:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un importante punto da verificare è **`/dev/nvidia-uvm`**. Anche se il workload non usa esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo dispositivo è condiviso e gestisce la memoria virtuale della GPU, consideralo una superficie di esposizione dei dati tra tenant. Se il backend di inferenza lo supporta, un backend Vulkan può essere un compromesso interessante perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.<sup>[[8]](#references)</sup>

### Confinamento LSM per i worker di inferenza

AppArmor/SELinux/seccomp dovrebbero essere usati come difesa in profondità per il processo di inferenza:<sup>[[8]](#references)</sup>

- Consenti solo le librerie condivise, i percorsi dei modelli, la directory dei socket e i nodi dei dispositivi GPU effettivamente necessari.
- Nega esplicitamente le capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la directory dei modelli in sola lettura e limita i percorsi scrivibili alle sole directory dei socket e della cache di runtime.
- Monitora i log dei dinieghi, perché forniscono dati di telemetria utili per il rilevamento quando il server del modello o un payload di post-exploitation tenta di evadere dal comportamento previsto.

Esempio di regole AppArmor per un worker che usa una GPU:

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

## Phantom Squatting: domini allucinati dagli LLM come vettore per gli attacchi alla supply chain dell'AI

Il phantom squatting è l’**equivalente, per domini/URL, dello slopsquatting**. Invece di allucinare un nome di pacchetto inesistente, l’LLM allucina un **dominio plausibile per un portale, un’API, un webhook, la fatturazione, l’SSO, i download o il supporto** di un brand reale, e un attaccante registra quello spazio dei nomi prima che lo usi una persona o un agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Questo è importante perché in molti workflow assistiti dall'AI l'output del modello viene trattato come una **dipendenza attendibile**:
- Gli sviluppatori incollano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agent AI recuperano automaticamente documentazione, schemi, APK, ZIP o destinazioni webhook.
- I runbook o i documenti generati possono includere l'URL falso come se fosse autorevole.

### Workflow offensivo

1. **Esamina la superficie di allucinazione**: poni domande specifiche sul brand relative a workflow realistici, come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizza i candidati**: risolvi gli URL generati, riduci le risposte NXDOMAIN al dominio padre registrabile e deduplica le famiglie di prompt. I corpus di prompt dovrebbero rimanere diversificati; ad esempio, eliminando i quasi duplicati con la **similarità di Jaccard**.
3. **Dai priorità alle allucinazioni prevedibili**:
   - **Thermal Hallucination Persistence (THP)**: lo stesso dominio falso compare a diverse temperature, anche a temperature basse come `T=0.1`.
   - **Consenso tra modelli**: più famiglie di LLM generano lo stesso dominio falso.
4. **Registra e arma** il dominio padre, poi ospita pagine di phishing, download di APK/ZIP falsi, sistemi per la raccolta di credenziali, documenti malevoli o endpoint API che raccolgono segreti/payload webhook. Le **allucinazioni limitate al dominio** sono le più facili da monetizzare perché l'attaccante controlla l'intero spazio dei nomi; le allucinazioni di sottodomini/percorsi possono comunque essere sfruttate quando il dominio padre normalizzato non è registrato.
5. **Sfrutta la finestra a reputazione zero**: i domini appena registrati spesso non hanno precedenti nelle blocklist, reputazione URL o telemetria consolidata, quindi possono eludere i controlli finché i sistemi di rilevamento non si aggiornano. Gli attaccanti possono prolungare questa finestra mostrando risposte innocue solo ai crawler, usando cloaking con redirect, CAPTCHA o posticipando la distribuzione del payload.

### Perché è pericoloso per gli agent

Per una vittima umana, di solito il dominio falso richiede comunque un clic e un'ulteriore azione. In un **workflow agentico**, l'LLM può essere sia l'**esca** sia l'**esecutore**: l'agent riceve l'URL allucinato, lo recupera, analizza la risposta e può quindi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati in CI/CD senza alcuna revisione umana.<sup>[[12]](#references)</sup>

### Prompt pratici per gli attaccanti

I prompt ad alto rendimento assomigliano di solito a normali attività aziendali, anziché a esche di phishing esplicite:<sup>[[12]](#references)</sup>
- “Qual è l'URL della sandbox di pagamento per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le notifiche di build di `<brand>`?”
- “Dov'è il portale benefit per dipendenti / fatturazione / SSO di `<brand>`?”
- “Dammi il link diretto per scaricare l'APK Android o il client desktop di `<brand>`.”

### Inversione difensiva

Considera il problema come un'attività proattiva di monitoraggio dei domini, non solo come un problema di prompt injection:<sup>[[12]](#references)</sup>
- Crea un **corpus di prompt per brand** e interroga periodicamente gli LLM su cui fanno affidamento gli utenti/gli agent.
- Memorizza gli URL allucinati e monitora quali rimangono stabili tra temperature/modelli.
- Monitora la **Adversarial Exploitation Window (AEW)**: il tempo tra la prima allucinazione e la registrazione da parte dell'attaccante. Un'AEW positiva significa che i difensori possono pre-registrare, mettere in sinkhole o bloccare preventivamente il dominio prima che venga armato.
- Monitora le transizioni **NXDOMAIN → registrato** per i domini padre.
- Al momento della registrazione, esamina registrar, data di creazione, nameserver, protezione della privacy, contenuto della pagina, screenshot, stato di pagina parcheggiata e somiglianza con gli asset del brand.
- Aggiungi controlli di policy affinché gli agent/gli sviluppatori **non si fidino per impostazione predefinita dei domini generati dagli LLM**: richiedi allowlist, convalida della titolarità, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo rientra contemporaneamente in diverse categorie di rischio AI: **attacco alla supply chain dell'AI**, **output del modello non sicuro** e **azioni rogue** quando gli agent consumano autonomamente l'URL allucinato.

## References

- [1] [Le 10 principali vulnerabilità del machine learning secondo OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rischi](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice delle minacce MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – I rischi degli LLM Code Assistant: contenuti dannosi, uso improprio e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenziali cloud rubate utilizzate in un nuovo attacco AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (rivendita di accessi LLM rubati)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Approfondimento sulla distribuzione di un server LLM on-premise con privilegi limitati](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlet di Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifica CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domini allucinati dall'AI come vettore per gli attacchi alla supply chain del software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: come le allucinazioni dell'AI alimentano una nuova categoria di attacchi alla supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
