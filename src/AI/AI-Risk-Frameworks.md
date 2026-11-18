# Rischi dell'IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP ha identificato le 10 principali vulnerabilità del machine learning che possono interessare i sistemi di IA. Queste vulnerabilità possono causare diversi problemi di sicurezza, tra cui data poisoning, model inversion e attacchi adversarial. Comprenderle è fondamentale per realizzare sistemi di IA sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità del machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: un attaccante apporta piccole modifiche, spesso invisibili, ai **dati in ingresso** per indurre il modello a prendere una decisione errata.\
    *Esempio*: alcune macchie di vernice su un segnale di stop inducono un'auto a guida autonoma a "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: il **training set** viene deliberatamente contaminato con campioni errati, insegnando al modello regole dannose.\
*Esempio*: in un corpus di training per antivirus, alcuni file binari malware vengono etichettati come "benigni", permettendo a malware simili di eludere i controlli in seguito.

- **Model Inversion Attack**: analizzando le risposte, un attaccante crea un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: ricreare l'immagine MRI di un paziente a partire dalle previsioni di un modello di rilevamento del cancro.

- **Membership Inference Attack**: l'attaccante verifica se un **record specifico** è stato usato durante il training, individuando differenze nei livelli di confidenza.\
*Esempio*: confermare che una transazione bancaria di una persona compare nei dati di training di un modello di rilevamento delle frodi.

- **Model Theft**: interrogazioni ripetute consentono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: raccogliere un numero sufficiente di coppie di domande e risposte da un'API ML-as-a-Service per creare un modello locale quasi equivalente.

- **AI Supply‑Chain Attack**: compromettere qualsiasi componente della **pipeline ML** (dati, librerie, pesi pre-addestrati, CI/CD) per corrompere i modelli a valle.\
*Esempio*: una dipendenza avvelenata da un model hub installa un modello di analisi del sentiment con una backdoor in numerose app.

- **Transfer Learning Attack**: una logica malevola viene inserita in un **modello pre-addestrato** e sopravvive al fine-tuning per il task della vittima.\
*Esempio*: un backbone per la visione con un trigger nascosto continua a modificare le etichette anche dopo essere stato adattato all'imaging medico.

- **Model Skewing**: dati distorti o etichettati in modo errato **alterano le risposte del modello** per favorire gli obiettivi dell'attaccante.\
*Esempio*: iniettare email spam "pulite" etichettate come posta legittima, così che un filtro antispam lasci passare email simili in futuro.

- **Output Integrity Attack**: l'attaccante **modifica le previsioni del modello durante la trasmissione**, senza modificare il modello stesso, ingannando i sistemi a valle.\
*Esempio*: modificare il verdetto "malicious" di un classificatore di malware in "benign" prima che venga elaborato dal sistema di quarantena dei file.

- **Model Poisoning** --- modifiche dirette e mirate ai **parametri del modello**, spesso dopo aver ottenuto l'accesso in scrittura, per alterarne il comportamento.\
*Esempio*: modificare i pesi di un modello di rilevamento delle frodi in produzione affinché le transazioni effettuate con determinate carte vengano sempre approvate.


## Rischi SAIF di Google

Il framework [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive diversi rischi associati ai sistemi di IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: attori malevoli alterano o iniettano dati di training o tuning per ridurre la precisione, inserire backdoor o distorcere i risultati, compromettendo l'integrità del modello durante l'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: l'uso di dataset protetti da copyright, sensibili o non autorizzati comporta rischi legali, etici e prestazionali, perché il modello apprende da dati che non aveva il permesso di utilizzare.

- **Model Source Tampering**: la manipolazione del codice, delle dipendenze o dei pesi del modello, prima o durante il training, da parte di attori della supply chain o di personale interno può inserire logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: controlli deboli sulla conservazione e sulla governance dei dati inducono i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando i rischi di esposizione e di non conformità.

- **Model Exfiltration**: gli attaccanti sottraggono i file o i pesi del modello, causando la perdita di proprietà intellettuale e consentendo la creazione di servizi imitativi o attacchi successivi.

- **Model Deployment Tampering**: gli attaccanti modificano gli artefatti del modello o l'infrastruttura di serving, facendo sì che il modello in esecuzione differisca dalla versione verificata e alterandone potenzialmente il comportamento.

- **Denial of ML Service**: inondare le API di richieste o inviare input "spugna" può esaurire risorse di calcolo ed energia, mettendo offline il modello, come negli attacchi DoS tradizionali.

- **Model Reverse Engineering**: raccogliendo un gran numero di coppie input-output, gli attaccanti possono clonare o distillare il modello, favorendo prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: plugin, agenti o servizi upstream vulnerabili consentono agli attaccanti di iniettare codice o aumentare i privilegi nella pipeline di IA.

- **Prompt Injection**: creare prompt, direttamente o indirettamente, per inserire istruzioni che prevalgono sull'intento del sistema e inducono il modello a eseguire comandi non previsti.

- **Model Evasion**: input progettati con cura inducono il modello a classificare in modo errato, generare allucinazioni o produrre contenuti non consentiti, compromettendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: il modello rivela informazioni private o riservate presenti nei dati di training o nel contesto utente, violando la privacy e le normative.

- **Inferred Sensitive Data**: il modello deduce attributi personali mai forniti, creando nuovi danni alla privacy attraverso inferenze.

- **Insecure Model Output**: risposte non sanificate trasmettono agli utenti o ai sistemi a valle codice dannoso, disinformazione o contenuti inappropriati.

- **Rogue Actions**: agenti integrati in modo autonomo eseguono operazioni nel mondo reale non previste (scrittura di file, chiamate API, acquisti, ecc.) senza un'adeguata supervisione dell'utente.

## Matrice MITRE AI ATLAS

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi di IA. Classifica diverse tecniche e tattiche di attacco che gli avversari possono usare contro i modelli di IA e descrive anche come utilizzare i sistemi di IA per eseguire diversi attacchi.<sup>[[3]](#references)</sup>

## LLMJacking (furto di token e rivendita dell'accesso a LLM ospitati nel cloud)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano senza autorizzazione LLM a pagamento ospitati nel cloud. Spesso l'accesso viene rivenduto tramite reverse proxy che instradano le richieste attraverso l'account della vittima, ad esempio installazioni di "oai-reverse-proxy". Le conseguenze includono perdite finanziarie, uso del modello in violazione delle policy e attribuzione dell'attività al tenant della vittima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- Raccolta di token da computer di sviluppatori o browser infetti; furto di segreti CI/CD; acquisto di cookie trapelati.<sup>[[5]](#references)</sup>
- Creazione di un reverse proxy che inoltra le richieste al provider autentico, nascondendo la chiave upstream e servendo più clienti.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuso degli endpoint diretti del modello di base per eludere le misure di protezione aziendali e i limiti di frequenza.<sup>[[4]](#references)</sup>

**Riutilizzo di una chiave API sull'host:** dopo aver compromesso un host, un impianto può inviare richieste API al modello direttamente dall'host della vittima e inoltrare le risposte tramite C2, senza esportare una chiave API cloud né avviare una CLI AI locale. Nell'handler osservato, una chiave fornita da C2 ha la precedenza; solo se è assente l'impianto legge `OPENAI_API_KEY` dall'ambiente del proprio processo. Pertanto, per usare l'account della vittima è necessaria una chiave valida accessibile a quel processo e l'accesso all'API del modello. Il prompt dell'operatore viene inviato all'API Chat Completions, mentre l'output del modello e l'utilizzo dei token vengono restituiti tramite C2. Questo può consumare l'accesso a pagamento al modello della vittima senza eseguire gli strumenti AI dello sviluppatore, a differenza dell'abuso della [configurazione della CLI AI locale o di MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Mitigazioni:
- Associa i token all'impronta digitale del dispositivo, agli intervalli IP e all'attestazione del client; imposta scadenze brevi e richiedi MFA per il rinnovo.
- Limita al minimo l'ambito delle chiavi (nessun accesso agli strumenti, sola lettura ove applicabile); ruotale in caso di anomalie.
- Instrada tutto il traffico lato server attraverso un policy gateway che applica filtri di sicurezza, quote per route e isolamento dei tenant.
- Monitora i modelli di utilizzo insoliti (improvvisi picchi di spesa, regioni atipiche, stringhe UA) e revoca automaticamente le sessioni sospette.
- Preferisci mTLS o JWT firmati emessi dal tuo IdP alle chiavi API statiche di lunga durata.

## Rafforzamento dell'inferenza LLM self-hosted

L'esecuzione di un server LLM locale per dati riservati presenta una superficie di attacco diversa rispetto alle API ospitate nel cloud: gli endpoint di inferenza o debug possono esporre i prompt, lo stack di serving di solito espone un reverse proxy e i nodi dei dispositivi GPU offrono accesso a numerose interfacce `ioctl()`. Se stai valutando o distribuendo un servizio di inferenza on-prem, verifica almeno i seguenti aspetti.<sup>[[8]](#references)</sup>

### Esposizione dei prompt tramite endpoint di debug e monitoraggio

Considera l'API di inferenza un **servizio sensibile multiutente**. Le route di debug o monitoraggio possono esporre il contenuto dei prompt, lo stato degli slot, i metadati del modello o informazioni sulle code interne. In `llama.cpp`, l'endpoint `/slots` è particolarmente sensibile perché espone lo stato dei singoli slot ed è destinato esclusivamente all'ispezione o alla gestione degli slot.<sup>[[8]](#references)</sup>

Per il fingerprinting black-box e il test dei model runner esposti e dei relativi servizi di IA, consulta [Servizi di IA self-hosted esposti](AI-Exposed-Self-Hosted-AI-Services.md).

- Metti un reverse proxy davanti al server di inferenza e **nega tutto per impostazione predefinita**.
- Inserisci in allowlist solo le esatte combinazioni di metodo HTTP e percorso necessarie al client/UI.
- Disabilita, ove possibile, gli endpoint di introspezione nel backend stesso, ad esempio con `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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

Se il daemon di inferenza supporta l’ascolto su un socket UNIX, preferiscilo a TCP ed esegui il container con **nessuno stack di rete**:<sup>[[8]](#references)</sup>

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
- `--network none` elimina l'esposizione TCP/IP in ingresso/uscita ed evita gli helper in modalità utente di cui i container rootless avrebbero altrimenti bisogno.
- Un socket UNIX consente di usare le autorizzazioni/ACL POSIX sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e Podman rootless riducono l'impatto di un container breakout, perché root nel container non è root sull'host.
- I mount dei modelli in sola lettura riducono il rischio di manomissione dei modelli dall'interno del container.

Per i deployment persistenti, le stesse restrizioni possono essere espresse tramite unità Podman Quadlet. Se l'accesso alla GPU viene delegato tramite Container Device Interface, restringi il più possibile la specifica del dispositivo CDI invece di esporre tutti i nodi dell'acceleratore.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Riduzione al minimo dei nodi dispositivo GPU

Per l'inferenza basata su GPU, i file `/dev/nvidia*` sono superfici di attacco locali di grande valore, perché espongono ampi handler `ioctl()` del driver e potenzialmente percorsi condivisi di gestione della memoria GPU.<sup>[[8]](#references)</sup>

- Non lasciare `/dev/nvidia*` scrivibili da tutti.
- Limita `nvidia`, `nvidiactl` e `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, regole udev e ACL, in modo che solo l'UID del container mappato possa aprirli.
- Disabilita i moduli non necessari, come `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, sugli host per l'inferenza headless.
- Precarica solo i moduli necessari all'avvio invece di lasciare che il runtime esegua opportunisticamente `modprobe` durante l'avvio dell'inferenza.

Esempio:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un importante punto da verificare è **`/dev/nvidia-uvm`**. Anche se il workload non usa esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo dispositivo è condiviso e gestisce la memoria virtuale della GPU, consideralo una superficie di esposizione dei dati tra tenant. Se il backend di inferenza lo supporta, un backend Vulkan può essere un compromesso interessante, perché potrebbe evitare del tutto di esporre `nvidia-uvm` al container.<sup>[[8]](#references)</sup>

### Confinamento LSM per i worker di inferenza

AppArmor/SELinux/seccomp dovrebbero essere usati come difesa in profondità attorno al processo di inferenza:<sup>[[8]](#references)</sup>

- Consenti solo le librerie condivise, i percorsi dei modelli, la directory dei socket e i nodi dei dispositivi GPU effettivamente necessari.
- Nega esplicitamente capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantieni la directory dei modelli in sola lettura e limita i percorsi scrivibili alle sole directory dei socket/cache del runtime.
- Monitora i log delle negazioni, perché forniscono telemetria utile per il rilevamento quando il model server o un payload post-exploitation tenta di evadere dal comportamento previsto.

Esempio di regole AppArmor per un worker che usa la GPU:

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

Il phantom squatting è l’**equivalente, per domini/URL, dello slopsquatting**. Invece di allucinare il nome di un pacchetto inesistente, l’LLM allucina un plausibile **dominio per portali, API, webhook, fatturazione, SSO, download o supporto** di un brand reale, e un attaccante registra quello spazio dei nomi prima che venga usato da una persona o da un agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

È importante perché in molti workflow assistiti dall’AI l’output del modello viene trattato come una **dipendenza attendibile**:
- Gli sviluppatori inseriscono l’endpoint suggerito nel codice o nelle integrazioni CI/CD.
- Gli agent AI recuperano automaticamente documentazione, schemi, APK, ZIP o destinazioni webhook.
- Le procedure operative o la documentazione generate possono includere l’URL falso come se fosse autorevole.

### Workflow offensivo

1. **Esplorare la superficie delle allucinazioni**: porre domande specifiche sul brand riguardo a workflow realistici come portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizzare i candidati**: risolvere gli URL generati, ricondurre le risposte NXDOMAIN al dominio registrabile principale e deduplicare le famiglie di prompt. I corpora di prompt dovrebbero rimanere diversificati, ad esempio eliminando i quasi duplicati con la **similarità di Jaccard**.
3. **Dare priorità alle allucinazioni prevedibili**:
   - **Persistenza termica delle allucinazioni (THP)**: lo stesso dominio falso compare a diverse temperature, anche a temperature basse come `T=0.1`.
   - **Consenso tra modelli**: più famiglie di LLM generano lo stesso dominio falso.
4. **Registrare e armare** il dominio principale, poi ospitarvi pagine di phishing, download di APK/ZIP falsi, sistemi per acquisire credenziali, documenti malevoli o endpoint API che raccolgono segreti/payload webhook. Le **allucinazioni esclusivamente a livello di dominio** sono le più facili da monetizzare perché l’attaccante controlla l’intero spazio dei nomi; le allucinazioni di sottodomini/percorsi possono comunque essere sfruttate quando il dominio principale normalizzato non è registrato.
5. **Sfruttare la finestra senza reputazione**: i domini appena registrati spesso non hanno precedenti nelle blocklist, reputazione URL né telemetria consolidata, quindi possono aggirare i controlli finché i sistemi di rilevamento non si aggiornano. Gli attaccanti possono prolungare questa finestra mostrando risposte innocue solo ai crawler, usando cloaking con reindirizzamenti, CAPTCHA o distribuendo il payload in un secondo momento.

### Perché è pericoloso per gli agent

Per una vittima umana, il dominio falso richiede in genere un clic e un’ulteriore azione. In un **workflow agentico**, l’LLM può essere sia l’**esca** sia l’**esecutore**: l’agent riceve l’URL allucinato, lo recupera, analizza la risposta e può poi fare leak di token, eseguire istruzioni, scaricare una dipendenza o inserire dati avvelenati in CI/CD senza alcuna revisione umana.<sup>[[12]](#references)</sup>

### Prompt pratici per gli attaccanti

I prompt più efficaci sembrano normali attività aziendali, non esche di phishing esplicite:<sup>[[12]](#references)</sup>
- “Qual è l’URL del sandbox di pagamento per le integrazioni di `<brand>`?”
- “Quale endpoint webhook devo usare per le notifiche di build di `<brand>`?”
- “Dov’è il portale benefit per i dipendenti / di fatturazione / SSO di `<brand>`?”
- “Dammi il link diretto per scaricare l’APK Android o il client desktop di `<brand>`.”

### Inversione difensiva

Consideralo un problema di monitoraggio proattivo dei domini, non solo di prompt injection:<sup>[[12]](#references)</sup>
- Crea un **corpus di prompt sui brand** e interroga periodicamente gli LLM su cui fanno affidamento gli utenti/gli agent.
- Memorizza gli URL allucinati e monitora quali sono stabili tra temperature e modelli.
- Monitora la **Finestra di sfruttamento avversario (AEW)**: il tempo che intercorre tra la prima allucinazione e la registrazione da parte dell’attaccante. Un’AEW positiva significa che i difensori possono registrare in anticipo, effettuare un sinkhole o bloccare il dominio prima che venga armato.
- Monitora le transizioni **NXDOMAIN → registrato** per i domini principali.
- Alla registrazione, esamina registrar, data di creazione, nameserver, protezione della privacy, contenuto della pagina, screenshot, stato della pagina parcheggiata e somiglianza con gli asset del brand.
- Aggiungi controlli di policy affinché agent/sviluppatori **non si fidino per impostazione predefinita dei domini generati dagli LLM**: richiedi allowlist, verifica della titolarità, controlli CT/RDAP o approvazione umana prima del primo utilizzo.

Questo rientra contemporaneamente in diverse categorie di rischio dell’AI: **attacco alla supply chain dell’AI**, **output del modello insicuro** e **azioni non autorizzate** quando gli agent consumano autonomamente l’URL allucinato.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Le 10 principali vulnerabilità del machine learning secondo OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rischi](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice delle minacce MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – I rischi degli LLM per l’assistenza alla programmazione: contenuti dannosi, uso improprio e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenziali cloud rubate usate in un nuovo attacco AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (rivendita di accessi LLM rubati)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analisi approfondita della distribuzione di un server LLM on-premise con privilegi limitati](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del server llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlet Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifiche CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domini allucinati dall’AI come vettore per la supply chain software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: come le allucinazioni dell’AI alimentano una nuova classe di attacchi alla supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: il nuovo framework di command-and-control abilitato dall’AI](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
