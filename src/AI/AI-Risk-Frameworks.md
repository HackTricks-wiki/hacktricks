# Rischi dell'AI

{{#include ../banners/hacktricks-training.md}}

## Le 10 principali vulnerabilità del machine learning secondo OWASP

OWASP ha identificato le 10 principali vulnerabilità del machine learning che possono interessare i sistemi AI. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e attacchi adversarial. Comprendere queste vulnerabilità è fondamentale per realizzare sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità del machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Attacco di manipolazione dell'input**: un aggressore apporta piccole modifiche, spesso invisibili, ai **dati in ingresso** per indurre il modello a prendere la decisione sbagliata.\
    *Esempio*: alcune macchie di vernice su un segnale di stop inducono un'auto a guida autonoma a "vedere" un segnale di limite di velocità.

- **Attacco di data poisoning**: il **training set** viene deliberatamente contaminato con campioni dannosi, insegnando al modello regole nocive.\
*Esempio*: i file binari di malware vengono etichettati erroneamente come "benigni" in un corpus di training per antivirus, consentendo a malware simili di eludere i controlli in seguito.

- **Attacco di model inversion**: esaminando gli output, un aggressore costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: ricreare l'immagine MRI di un paziente a partire dalle previsioni di un modello di rilevamento del cancro.

- **Attacco di membership inference**: l'avversario verifica se uno **specifico record** è stato usato durante il training rilevando differenze nel livello di confidenza.\
*Esempio*: confermare che una transazione bancaria di una persona compaia nei dati di training di un modello di rilevamento delle frodi.

- **Furto del modello**: interrogazioni ripetute consentono all'aggressore di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: raccogliere abbastanza coppie di domande e risposte da un'API ML-as-a-Service per creare un modello locale quasi equivalente.

- **Attacco alla supply chain AI**: compromettere un qualsiasi componente (dati, librerie, pesi pre-addestrati, CI/CD) della **pipeline ML** per corrompere i modelli a valle.\
*Esempio*: una dipendenza avvelenata su un model hub installa un modello di sentiment analysis con una backdoor in numerose app.

- **Attacco di transfer learning**: una logica malevola viene inserita in un **modello pre-addestrato** e sopravvive al fine-tuning per il compito della vittima.\
*Esempio*: un modello vision con un trigger nascosto continua a modificare le etichette anche dopo essere stato adattato all'imaging medico.

- **Distorsione del modello**: dati sottilmente distorti o etichettati in modo errato **spostano gli output del modello** a favore degli obiettivi dell'aggressore.\
*Esempio*: inserire email di spam "pulite" etichettate come ham affinché un filtro antispam lasci passare email simili in futuro.

- **Attacco all'integrità dell'output**: l'aggressore **modifica le previsioni del modello durante il transito**, senza alterare il modello, ingannando i sistemi a valle.\
*Esempio*: modificare il verdetto "maligno" di un classificatore di malware in "benigno" prima che venga rilevato dalla fase di quarantena dei file.

- **Avvelenamento del modello** --- Modifiche dirette e mirate agli **stessi parametri del modello**, spesso dopo aver ottenuto l'accesso in scrittura, per alterarne il comportamento.\
*Esempio*: modificare i pesi di un modello di rilevamento delle frodi in produzione affinché le transazioni effettuate con determinate carte vengano sempre approvate.


## Rischi Google SAIF

Il framework [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive diversi rischi associati ai sistemi AI:<sup>[[2]](#references)</sup>

- **Data poisoning**: attori malevoli alterano o inseriscono dati di training o tuning per ridurre la precisione, installare backdoor o distorcere i risultati, compromettendo l'integrità del modello lungo l'intero ciclo di vita dei dati.

- **Dati di training non autorizzati**: l'acquisizione di dataset protetti da copyright, sensibili o non autorizzati comporta rischi legali, etici e prestazionali, perché il modello apprende da dati che non avrebbe dovuto usare.

- **Manomissione del codice sorgente del modello**: la manipolazione, da parte di insider o attraverso la supply chain, del codice, delle dipendenze o dei pesi del modello, prima o durante il training, può inserire logiche nascoste che persistono anche dopo il retraining.

- **Gestione eccessiva dei dati**: controlli deboli sulla conservazione e sulla governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando l'esposizione e i rischi di conformità.

- **Esfiltrazione del modello**: gli aggressori rubano i file o i pesi del modello, causando la perdita di proprietà intellettuale e consentendo la creazione di servizi imitativi o attacchi successivi.

- **Manomissione della distribuzione del modello**: gli avversari modificano gli artefatti del modello o l'infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e potenzialmente alterandone il comportamento.

- **Denial of ML service**: inondare le API o inviare input "sponge" può esaurire le risorse di calcolo e l'energia, mettendo il modello offline, come nei classici attacchi DoS.

- **Reverse engineering del modello**: raccogliendo un gran numero di coppie input-output, gli aggressori possono clonare o distillare il modello, favorendo prodotti imitativi e attacchi adversarial personalizzati.

- **Componente integrato non sicuro**: plugin, agenti o servizi upstream vulnerabili consentono agli aggressori di inserire codice o aumentare i privilegi all'interno della pipeline AI.

- **Prompt injection**: creare prompt, direttamente o indirettamente, per introdurre di nascosto istruzioni che prevalgono sull'intento del sistema e inducono il modello a eseguire comandi non previsti.

- **Evasione del modello**: input creati con cura inducono il modello a classificare erroneamente, allucinare o generare contenuti non consentiti, minando sicurezza e fiducia.

- **Divulgazione di dati sensibili**: il modello rivela informazioni private o riservate provenienti dai dati di training o dal contesto dell'utente, violando la privacy e le normative.

- **Dati sensibili dedotti**: il modello deduce attributi personali mai forniti, creando nuovi rischi per la privacy tramite inferenza.

- **Output del modello non sicuro**: risposte non sanificate trasmettono codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi a valle.

- **Azioni non autorizzate**: agenti integrati in modo autonomo eseguono operazioni nel mondo reale non previste (scrittura di file, chiamate API, acquisti ecc.) senza un'adeguata supervisione dell'utente.

## Matrice MITRE AI ATLAS

La [matrice MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi AI. Classifica le varie tattiche e tecniche di attacco che gli avversari possono usare contro i modelli AI e mostra anche come usare i sistemi AI per eseguire diversi attacchi.<sup>[[3]](#references)</sup>

## LLMJacking (furto di token e rivendita dell'accesso a LLM ospitati nel cloud)

Gli aggressori rubano token di sessione attivi o credenziali API cloud e invocano senza autorizzazione LLM a pagamento ospitati nel cloud. Spesso l'accesso viene rivenduto tramite reverse proxy che si appoggiano all'account della vittima, ad esempio deployment di "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso improprio del modello al di fuori delle policy e attribuzione delle attività al tenant della vittima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- Raccogliere token da macchine di sviluppatori o browser infetti; rubare secret CI/CD; acquistare cookie leak.<sup>[[5]](#references)</sup>
- Configurare un reverse proxy che inoltra le richieste al provider autentico, nasconde la chiave upstream e smista le richieste di numerosi clienti.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusare degli endpoint diretti del modello base per aggirare le misure di protezione e i limiti di frequenza aziendali.<sup>[[4]](#references)</sup>

Mitigazioni:
- Associare i token all'impronta digitale del dispositivo, agli intervalli IP e all'attestazione del client; imporre scadenze brevi e rinnovarli con MFA.
- Limitare al minimo l'ambito delle chiavi (nessun accesso agli strumenti, sola lettura ove applicabile); ruotarle in caso di anomalie.
- Terminare tutto il traffico lato server dietro un gateway di policy che applichi filtri di sicurezza, quote per route e isolamento dei tenant.
- Monitorare eventuali pattern di utilizzo insoliti (improvvisi picchi di spesa, regioni atipiche, stringhe UA) e revocare automaticamente le sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a chiavi API statiche di lunga durata.

## Rafforzamento dell'inferenza di LLM self-hosted

L'esecuzione di un server LLM locale per dati riservati crea una superficie di attacco diversa da quella delle API ospitate nel cloud: gli endpoint di inferenza e debug possono esporre i prompt, lo stack di serving di solito espone un reverse proxy e i nodi dei dispositivi GPU consentono l'accesso a numerose superfici `ioctl()`. Se stai valutando o distribuendo un servizio di inferenza on-prem, esamina almeno i punti seguenti.<sup>[[8]](#references)</sup>

### Leak dei prompt tramite endpoint di debug e monitoraggio

Considera l'API di inferenza come un **servizio sensibile multiutente**. Le route di debug o monitoraggio possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato dei singoli slot ed è destinato esclusivamente all'ispezione e alla gestione degli slot.<sup>[[8]](#references)</sup>

Per il fingerprinting black-box e il testing dei model runner esposti e dei servizi AI correlati, consulta [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Metti un reverse proxy davanti al server di inferenza e **nega tutto per impostazione predefinita**.
- Consenti solo le combinazioni esatte di metodo HTTP e percorso necessarie al client/UI.
- Disabilita gli endpoint di introspezione direttamente nel backend ogni volta che è possibile, ad esempio `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Associa il reverse proxy a `127.0.0.1` ed esponilo tramite un trasporto autenticato, come il port forwarding locale SSH, invece di pubblicarlo sulla LAN.

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

Se il daemon di inferenza supporta l'ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container **senza stack di rete**:<sup>[[8]](#references)</sup>

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
- `--network none` elimina l'esposizione TCP/IP in ingresso e in uscita ed evita gli helper in modalità utente che altrimenti sarebbero necessari ai container rootless.
- Un socket UNIX consente di usare le autorizzazioni POSIX/ACL sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di una container breakout, perché root nel container non equivale a root sull'host.
- I mount dei modelli in sola lettura riducono la possibilità di manomettere i modelli dall'interno del container.

Per i deployment persistenti, è possibile esprimere le stesse restrizioni con unità Podman Quadlet. Se l'accesso alla GPU viene delegato tramite Container Device Interface, mantenete la specifica del dispositivo CDI il più possibile circoscritta invece di esporre tutti i nodi dell'acceleratore.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Riduzione al minimo dei nodi dispositivo GPU

Per l'inferenza basata su GPU, i file `/dev/nvidia*` sono superfici di attacco locali di grande valore, perché espongono handler `ioctl()` estesi e percorsi potenzialmente condivisi per la gestione della memoria GPU.<sup>[[8]](#references)</sup>

- Non lasciate `/dev/nvidia*` scrivibili da chiunque.
- Limitate `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo l'UID del container mappato possa aprirli.
- Inserite nella blacklist moduli non necessari come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem` sugli host di inferenza headless.
- Precaricate solo i moduli necessari all'avvio, invece di consentire al runtime di eseguire opportunisticamente `modprobe` durante l'avvio dell'inferenza.

Esempio:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un punto importante da verificare è **`/dev/nvidia-uvm`**. Anche se il workload non usa esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo dispositivo è condiviso e gestisce la memoria virtuale della GPU, consideralo una superficie di esposizione dei dati tra tenant. Se il backend di inferenza lo supporta, un backend Vulkan può rappresentare un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.<sup>[[8]](#references)</sup>

### Confinamento LSM per i worker di inferenza

AppArmor/SELinux/seccomp dovrebbero essere usati come difesa a più livelli intorno al processo di inferenza:<sup>[[8]](#references)</sup>

- Consenti solo le librerie condivise, i percorsi dei modelli, la directory dei socket e i nodi dei dispositivi GPU effettivamente necessari.
- Nega esplicitamente le capability ad alto rischio, come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la directory dei modelli in sola lettura e limita i percorsi scrivibili alle sole directory dei socket e della cache di runtime.
- Monitora i log delle operazioni negate, perché forniscono utili dati di telemetria per il rilevamento quando il server del modello o un payload di post-exploitation tenta di evadere il comportamento previsto.

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

## Phantom Squatting: domini allucinati dagli LLM come vettore per la supply chain dell'IA

Il phantom squatting è l'**equivalente di slopsquatting per domini/URL**. Invece di allucinare il nome di un pacchetto inesistente, l'LLM allucina un **dominio di portale, API, webhook, fatturazione, SSO, download o supporto** plausibile per un brand reale, e un attaccante registra quello spazio dei nomi prima che venga usato da una persona o un agente.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Questo è importante perché in molti flussi di lavoro assistiti dall'IA l'output del modello viene trattato come una **dipendenza attendibile**:
- Gli sviluppatori incollano l'endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agenti IA recuperano automaticamente documentazione, schemi, APK, ZIP o destinazioni webhook.
- Le procedure operative o la documentazione generate possono incorporare il falso URL come se fosse autorevole.

### Flusso di attacco

1. **Esplora la superficie di allucinazione**: poni domande specifiche sul brand riguardo a flussi di lavoro realistici, come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizza i candidati**: risolvi gli URL generati, riconduci le risposte NXDOMAIN al dominio registrabile padre e deduplica le famiglie di prompt. I corpora di prompt dovrebbero restare diversificati, ad esempio eliminando i quasi-duplicati tramite la **similarità di Jaccard**.
3. **Assegna priorità alle allucinazioni prevedibili**:
   - **Thermal Hallucination Persistence (THP)**: lo stesso dominio falso compare a diverse temperature, anche a temperature basse come `T=0.1`.
   - **Consenso tra modelli**: più famiglie di LLM generano lo stesso dominio falso.
4. **Registra e arma** il dominio padre, quindi ospita pagine di phishing, download di APK/ZIP falsi, sistemi per raccogliere credenziali, documenti malevoli o endpoint API che raccolgono segreti/payload webhook. Le **allucinazioni a livello di dominio puro** sono le più facili da monetizzare perché l'attaccante controlla l'intero spazio dei nomi; le allucinazioni di sottodominio/percorso possono comunque essere sfruttate se il dominio padre normalizzato non è registrato.
5. **Sfrutta la finestra senza reputazione**: i domini appena registrati spesso non hanno uno storico nelle blocklist, reputazione URL o telemetria consolidata, quindi possono eludere i controlli finché i sistemi di rilevamento non si aggiornano. Gli attaccanti possono prolungare questa finestra mostrando risposte innocue solo ai crawler, usando cloaking con redirect, CAPTCHA o distribuendo il payload in ritardo.

### Perché è pericoloso per gli agenti

Per una vittima umana, il falso dominio richiede di solito un clic e un'altra azione. In un **flusso di lavoro agentico**, l'LLM può essere sia l'**esca** sia l'**esecutore**: l'agente riceve l'URL allucinato, lo recupera, analizza la risposta e potrebbe poi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati in CI/CD senza alcuna revisione umana.<sup>[[12]](#references)</sup>

### Prompt pratici per gli attaccanti

I prompt più efficaci di solito sembrano normali attività aziendali anziché espliciti tentativi di phishing:<sup>[[12]](#references)</sup>
- “Qual è l'URL della sandbox di pagamento per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le notifiche di build di `<brand>`?”
- “Dove si trova il portale per benefit dipendenti/fatturazione/SSO di `<brand>`?”
- “Dammi il link diretto per scaricare l'APK Android o il client desktop di `<brand>`.”

### Inversione difensiva

Consideralo un problema di monitoraggio proattivo dei domini, non solo un problema di prompt injection:<sup>[[12]](#references)</sup>
- Crea un **corpus di prompt sui brand** e testa periodicamente gli LLM su cui fanno affidamento gli utenti/gli agenti.
- Memorizza gli URL allucinati e monitora quali restano stabili tra temperature e modelli.
- Monitora la **Adversarial Exploitation Window (AEW)**: il tempo che intercorre tra la prima allucinazione e la registrazione da parte dell'attaccante. Un AEW positivo significa che i difensori possono registrare in anticipo, effettuare sinkhole o bloccare il dominio prima che venga armato.
- Monitora le transizioni **NXDOMAIN → registrato** per i domini padre.
- Dopo la registrazione, esamina registrar, data di creazione, nameserver, protezione della privacy, contenuto della pagina, screenshot, stato della pagina parcheggiata e somiglianza con gli asset del brand.
- Aggiungi controlli di policy affinché gli agenti/gli sviluppatori **non si fidino per impostazione predefinita dei domini generati dagli LLM**: richiedi allowlist, convalida della proprietà, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo fenomeno rientra in più categorie di rischio dell'IA: **attacco alla supply chain dell'IA**, **output del modello non sicuro** e **azioni rogue** quando gli agenti utilizzano autonomamente l'URL allucinato.

## References

- [1] [OWASP Top 10 delle vulnerabilità del machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rischi](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice delle minacce MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – I rischi degli LLM per gli assistenti di programmazione: contenuti dannosi, uso improprio e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenziali cloud rubate usate in un nuovo attacco IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (rivendita di accessi LLM rubati)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analisi approfondita della distribuzione di un server LLM on-premise con privilegi ridotti](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlet Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifica della Container Device Interface (CDI) della CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domini allucinati dall'IA come vettore per la supply chain del software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: come le allucinazioni dell'IA alimentano una nuova classe di attacchi alla supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
