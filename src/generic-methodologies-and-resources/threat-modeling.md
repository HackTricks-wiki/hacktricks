# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

Benvenuto nella guida completa di HackTricks sul Threat Modeling! Intraprendi un'esplorazione di questo aspetto cruciale della cybersecurity, in cui identifichiamo, comprendiamo e sviluppiamo strategie contro le potenziali vulnerabilità di un sistema. Questa guida funge da percorso passo-passo ricco di esempi reali, software utili e spiegazioni facili da comprendere. È ideale sia per i principianti sia per i professionisti esperti che desiderano rafforzare le proprie difese di cybersecurity.

### Scenari comunemente utilizzati

1. **Sviluppo software**: come parte del Secure Software Development Life Cycle (SSDLC), il Threat Modeling aiuta a **identificare le potenziali fonti di vulnerabilità** nelle prime fasi dello sviluppo.
2. **Penetration Testing**: il framework Penetration Testing Execution Standard (PTES) richiede il **Threat Modeling per comprendere le vulnerabilità del sistema** prima di eseguire il test.

### Threat Model in breve

Un Threat Model è generalmente rappresentato da un diagramma, un'immagine o un'altra forma di rappresentazione visiva che descrive l'architettura pianificata o la struttura esistente di un'applicazione. È simile a un **data flow diagram**, ma la differenza principale risiede nella sua progettazione orientata alla sicurezza.

I Threat Model presentano spesso elementi contrassegnati in rosso, a simboleggiare potenziali vulnerabilità, rischi o barriere. Per semplificare il processo di identificazione dei rischi, viene utilizzata la triade CIA (Confidentiality, Integrity, Availability), che costituisce la base di molte metodologie di Threat Modeling, tra cui STRIDE, una delle più comuni. Tuttavia, la metodologia scelta può variare in base al contesto e ai requisiti specifici.

### La triade CIA

La triade CIA è un modello ampiamente riconosciuto nel campo della sicurezza delle informazioni e indica Confidentiality, Integrity e Availability. Questi tre pilastri costituiscono la base su cui vengono costruite molte misure e policy di sicurezza, comprese le metodologie di Threat Modeling.

1. **Confidentiality**: garantire che i dati o il sistema non siano accessibili a soggetti non autorizzati. Questo è un aspetto centrale della sicurezza e richiede controlli di accesso appropriati, crittografia e altre misure per prevenire i data breach.
2. **Integrity**: accuratezza, coerenza e affidabilità dei dati durante il loro ciclo di vita. Questo principio garantisce che i dati non vengano modificati o manomessi da soggetti non autorizzati. Spesso prevede l'uso di checksum, hashing e altri metodi di verifica dei dati.
3. **Availability**: garantire che dati e servizi siano accessibili agli utenti autorizzati quando necessario. Questo comporta spesso ridondanza, fault tolerance e configurazioni high-availability per mantenere i sistemi operativi anche in caso di interruzioni.

### Metodologie di Threat Modeling

1. **STRIDE**: sviluppato da Microsoft, STRIDE è un acronimo di **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Ogni categoria rappresenta un tipo di minaccia e questa metodologia viene comunemente utilizzata nella fase di progettazione di un programma o sistema per identificare le potenziali minacce.
2. **DREAD**: è un'altra metodologia di Microsoft utilizzata per la valutazione dei rischi delle minacce identificate. DREAD sta per **Damage potential, Reproducibility, Exploitability, Affected users e Discoverability**. A ciascuno di questi fattori viene assegnato un punteggio e il risultato viene utilizzato per stabilire la priorità delle minacce identificate.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): è una metodologia **risk-centric** articolata in sette fasi. Include la definizione e l'identificazione degli obiettivi di sicurezza, la creazione di un ambito tecnico, la scomposizione dell'applicazione, l'analisi delle minacce, l'analisi delle vulnerabilità e la valutazione del rischio/triage.
4. **Trike**: è una metodologia basata sul rischio che si concentra sulla difesa degli asset. Parte da una prospettiva di **risk management** e analizza minacce e vulnerabilità in tale contesto.
5. **VAST** (Visual, Agile e Simple Threat modeling): questo approccio mira a essere più accessibile e si integra negli ambienti di sviluppo Agile. Combina elementi delle altre metodologie e si concentra sulle **rappresentazioni visive delle minacce**.
6. **OCTAVE** (Operationally Critical Threat, Asset e Vulnerability Evaluation): sviluppato dal CERT Coordination Center, questo framework è orientato alla **valutazione del rischio organizzativo anziché di sistemi o software specifici**.

## Tools

Sono disponibili diversi tools e soluzioni software che possono **assistere** nella creazione e nella gestione dei Threat Model. Eccone alcuni che potresti prendere in considerazione.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Uno spider/crawler web GUI avanzato, multipiattaforma e ricco di funzionalità, destinato ai professionisti della cybersecurity. Spider Suite può essere utilizzato per la mappatura e l'analisi della attack surface.

**Utilizzo**

1. Scegli un URL ed esegui il Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualizza il Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un progetto open-source di OWASP, Threat Dragon è un'applicazione web e desktop che include la creazione di diagrammi di sistema e un rule engine per generare automaticamente minacce/mitigazioni.

**Utilizzo**

1. Crea un nuovo progetto

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A volte potrebbe apparire così:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Avvia un nuovo progetto

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salva il nuovo progetto

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crea il tuo modello

Puoi utilizzare tools come SpiderSuite Crawler per trarre ispirazione; un modello di base potrebbe essere simile a questo

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Una breve spiegazione delle entità:

- Process (l'entità stessa, come un Webserver o una funzionalità web)
- Actor (una persona, come un Website Visitor, un User o un Administrator)
- Data Flow Line (indicatore dell'interazione)
- Trust Boundary (segmenti o ambiti di rete differenti)
- Store (elementi in cui vengono archiviati i dati, come i Database)

5. Crea una minaccia (passaggio 1)

Per prima cosa devi scegliere il layer a cui desideri aggiungere una minaccia

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ora puoi creare la minaccia

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tieni presente che esiste una differenza tra Actor Threats e Process Threats. Se aggiungessi una minaccia a un Actor, potresti scegliere solo "Spoofing" e "Repudiation". Tuttavia, nel nostro esempio aggiungiamo una minaccia a un'entità Process, quindi nella finestra di creazione della minaccia vedremo quanto segue:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fatto

Il modello completato dovrebbe apparire più o meno così. Questo è il modo per creare un semplice Threat Model con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Si tratta di un tool gratuito di Microsoft che aiuta a individuare le minacce nella fase di progettazione dei progetti software. Utilizza la metodologia STRIDE ed è particolarmente adatto a chi sviluppa sullo stack Microsoft.

{{#include ../banners/hacktricks-training.md}}
