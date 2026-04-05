# Rischi AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilità del Machine Learning

Owasp ha identificato le prime 10 vulnerabilità del machine learning che possono influire sui sistemi AI. Queste vulnerabilità possono portare a vari problemi di sicurezza, inclusi data poisoning, model inversion e adversarial attacks. Comprendere queste vulnerabilità è cruciale per costruire sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle top 10 vulnerabilità del machine learning, consulta il progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaccante aggiunge piccole, spesso invisibili modifiche ai **dati in ingresso** in modo che il modello prenda la decisione sbagliata.\
*Esempio*: Alcune macchie di vernice su un cartello di stop ingannano un'auto a guida autonoma facendole "vedere" un cartello di limite di velocità.

- **Data Poisoning Attack**: Il **set di addestramento** viene deliberatamente inquinato con campioni dannosi, insegnando al modello regole nocive.\
*Esempio*: Binarî di malware vengono etichettati come "benign" in un corpus di addestramento per antivirus, permettendo a malware simili di superare i controlli in seguito.

- **Model Inversion Attack**: Interrogando le uscite, un attaccante costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente dalle predizioni di un modello per la rilevazione del cancro.

- **Membership Inference Attack**: L'avversario verifica se un **record specifico** è stato usato durante l'addestramento osservando differenze di confidenza.\
*Esempio*: Confermare che le transazioni bancarie di una persona compaiono nei dati di addestramento di un modello di rilevamento frodi.

- **Model Theft**: Query ripetute permettono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: Raccogliere abbastanza coppie Q&A da un'API ML‑as‑a‑Service per costruire un modello locale quasi equivalente.

- **AI Supply‑Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre-addestrati, CI/CD) nella **pipeline ML** per corrompere i modelli a valle.\
*Esempio*: Una dipendenza avvelenata su un model‑hub installa un modello di analisi del sentiment backdoored in molte app.

- **Transfer Learning Attack**: Logica malevola viene impiantata in un **modello pre-addestrato** e sopravvive al fine‑tuning sul compito della vittima.\
*Esempio*: Un backbone di visione con un trigger nascosto continua a invertire le etichette anche dopo essere stato adattato per imaging medico.

- **Model Skewing**: Dati sottilmente distorti o etichettati erroneamente **spostano le uscite del modello** per favorire l'agenda dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettate come ham così che un filtro antispam lasci passare email simili in futuro.

- **Output Integrity Attack**: L'attaccante **manomette le predizioni del modello in transito**, non il modello stesso, ingannando i sistemi a valle.\
*Esempio*: Cambiare il verdetto "malicious" di un classificatore di malware in "benign" prima che la fase di quarantena del file lo veda.

- **Model Poisoning** --- Modifiche dirette e mirate ai **parametri del modello** stessi, spesso dopo aver ottenuto accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello di rilevamento frodi in produzione in modo che le transazioni da certe carte vengano sempre approvate.

## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) descrive vari rischi associati ai sistemi AI:

- **Data Poisoning**: Attori malintenzionati alterano o iniettano dati di training/tuning per degradare l'accuratezza, impiantare backdoor o distorcere i risultati, compromettendo l'integrità del modello lungo tutto il ciclo di vita dei dati.

- **Unauthorized Training Data**: Ingestione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e di performance perché il modello impara da dati che non avrebbe dovuto usare.

- **Model Source Tampering**: Manipolazioni nella supply‑chain o da insider del codice del modello, delle dipendenze o dei pesi prima o durante l'addestramento possono incorporare logiche nascoste che persistono anche dopo il retraining.

- **Excessive Data Handling**: Controlli deboli sulla retention e governance dei dati portano i sistemi a memorizzare o processare più dati personali del necessario, aumentando esposizione e rischi di compliance.

- **Model Exfiltration**: Gli attaccanti rubano file/pesi del modello, causando perdita di proprietà intellettuale e abilitando servizi imitativi o attacchi successivi.

- **Model Deployment Tampering**: Avversari modificano artefatti del modello o l'infrastruttura di serving così che il modello in esecuzione differisca dalla versione verificata, potenzialmente cambiandone il comportamento.

- **Denial of ML Service**: Saturare le API o inviare input “sponge” può esaurire compute/energia e mettere il modello offline, rispecchiando attacchi DoS classici.

- **Model Reverse Engineering**: Raccolta massiva di coppie input-output permette agli attaccanti di clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: Plugin, agent o servizi upstream vulnerabili permettono agli attaccanti di iniettare codice o scalare privilegi nella pipeline AI.

- **Prompt Injection**: Costruire prompt (direttamente o indirettamente) per contrabbandare istruzioni che sovrascrivono l'intento del sistema, inducendo il modello a eseguire comandi non voluti.

- **Model Evasion**: Input progettati con cura inducono il modello a misclassificare, hallucinate o produrre contenuti non consentiti, erodendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o confidenziali dai dati di training o dal contesto utente, violando privacy e regolamentazioni.

- **Inferred Sensitive Data**: Il modello deduce attributi personali mai forniti, creando nuovi danni alla privacy tramite inferenza.

- **Insecure Model Output**: Risposte non sanificate passano codice dannoso, misinformation o contenuti inappropriati agli utenti o a sistemi downstream.

- **Rogue Actions**: Agenti integrati in modo autonomo eseguono operazioni reali non intenzionate (scritture su file, chiamate API, acquisti, ecc.) senza adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework comprensivo per capire e mitigare i rischi associati ai sistemi AI. Classifica varie tecniche e tattiche d'attacco che gli avversari possono usare contro i modelli AI e anche come utilizzare sistemi AI per eseguire diversi attacchi.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Gli attaccanti rubano token di sessione attivi o credenziali API cloud e invocano LLM cloud-hosted a pagamento senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxies che frontano l'account della vittima, es. deployment "oai-reverse-proxy". Le conseguenze includono perdita finanziaria, uso improprio del modello fuori dalle policy e attribuzione all'organizzazione vittima.

TTPs:
- Raccogliere token da macchine di sviluppatori infette o browser; rubare segreti CI/CD; buy leaked cookies.
- Mettere su un reverse proxy che inoltra le richieste al provider genuino, nascondendo l'upstream key e multiplexando molti clienti.
- Abuse direct base-model endpoints per bypassare enterprise guardrails e rate limits.

Mitigations:
- Legare i token a device fingerprint, range IP e client attestation; imporre scadenze brevi e refresh con MFA.
- Limitare le chiavi al minimo indispensabile (no accesso a strumenti, read-only dove applicabile); ruotare in caso di anomalie.
- Terminate tutto il traffico lato server dietro a un policy gateway che applichi filtri di sicurezza, quote per-route e isolamento dei tenant.
- Monitorare pattern di uso insoliti (impennate improvvise di spesa, regioni atipiche, UA strings) e auto‑revocare sessioni sospette.
- Preferire mTLS o JWT firmati emessi dal proprio IdP rispetto a long‑lived static API keys.

## Self-hosted LLM inference hardening

Eseguire un server LLM locale per dati confidenziali crea una superficie di attacco diversa rispetto alle API cloud-hosted: gli endpoint di inference/debug possono leak prompts, lo stack di serving solitamente espone un reverse proxy e i nodi GPU danno accesso a estese superfici `ioctl()`. Se stai valutando o distribuendo un servizio di inference on-prem, rivedi almeno i punti seguenti.

### Prompt leakage via debug and monitoring endpoints

Treat the inference API as a **multi-user sensitive service**. Debug or monitoring routes can expose prompt contents, slot state, model metadata, or internal queue information. In `llama.cpp`, the `/slots` endpoint is especially sensitive because it exposes per-slot state and is only meant for slot inspection/management.

- Metti un reverse proxy davanti al server di inference e rifiuta per impostazione predefinita.
- Consenti solo le esatte combinazioni di HTTP method + path necessarie al client/UI.
- Disabilita gli introspection endpoints nel backend stesso quando possibile, per esempio `llama-server --no-slots`.
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

Se l'inference daemon supporta l'ascolto su un UNIX socket, preferiscilo rispetto a TCP ed esegui il container con **no network stack**:
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
- `--network none` rimuove l'esposizione TCP/IP in ingresso/uscita e evita user-mode helpers di cui i container rootless altrimenti avrebbero bisogno.
- Un socket UNIX permette di usare permessi/ACL POSIX sul percorso del socket come primo livello di controllo degli accessi.
- `--userns=keep-id` e rootless Podman riducono l'impatto di un container breakout perché il root del container non è il root dell'host.
- I mount del modello in sola lettura riducono la probabilità di manomissione del modello dall'interno del container.

### Minimizzazione dei device-node GPU

Per l'inferenza su GPU, i file `/dev/nvidia*` sono superfici di attacco locali ad alto valore perché espongono ampi gestori `ioctl()` del driver e potenzialmente percorsi condivisi di gestione della memoria GPU.

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- Blacklist unnecessary modules such as `nvidia_drm`, `nvidia_modeset`, and `nvidia_peermem` on headless inference hosts.
- Preload only required modules at boot instead of letting the runtime opportunistically `modprobe` them during inference startup.

Esempio:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante da verificare è **`/dev/nvidia-uvm`**. Anche se il workload non utilizza esplicitamente `cudaMallocManaged()`, i runtime CUDA recenti potrebbero comunque richiedere `nvidia-uvm`. Poiché questo device è condiviso e gestisce la memoria virtuale della GPU, trattalo come una superficie di esposizione dei dati cross-tenant. Se il backend di inferenza lo supporta, un backend Vulkan può essere un compromesso interessante perché potrebbe evitare di esporre `nvidia-uvm` al container del tutto.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp dovrebbero essere usati come difesa in profondità attorno al processo di inferenza:

- Consentire solo le librerie condivise, i percorsi dei modelli, la directory dei socket e i device node della GPU effettivamente necessari.
- Negare esplicitamente capability ad alto rischio come `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenere la directory dei modelli in sola lettura e limitare i percorsi scrivibili solo alle directory di socket/cache del runtime.
- Monitorare i denial logs perché forniscono telemetria utile per il rilevamento quando il model server o un payload post-exploitation tenta di evadere il comportamento previsto.

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
- [Unit 42 – I rischi dei Code Assistant LLMs: contenuti dannosi, uso improprio e inganno](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Panoramica dello schema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (rivendita di accesso LLM rubato)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Analisi approfondita della distribuzione di un server LLM on-premise con privilegi ridotti](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Specifica CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
