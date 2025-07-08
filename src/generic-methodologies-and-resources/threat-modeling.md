# Threat Modeling

{{#include /banners/hacktricks-training.md}}

## Threat Modeling

Benvenuto nella guida completa di HackTricks sul Threat Modeling! Inizia un'esplorazione di questo aspetto critico della cybersecurity, dove identifichiamo, comprendiamo e strategizziamo contro potenziali vulnerabilità in un sistema. Questo thread funge da guida passo-passo ricca di esempi del mondo reale, software utili e spiegazioni facili da comprendere. Ideale sia per i principianti che per i professionisti esperti che cercano di rafforzare le loro difese di cybersecurity.

### Commonly Used Scenarios

1. **Sviluppo Software**: Come parte del Ciclo di Vita dello Sviluppo Software Sicuro (SSDLC), il threat modeling aiuta a **identificare potenziali fonti di vulnerabilità** nelle fasi iniziali dello sviluppo.
2. **Penetration Testing**: Il framework del Penetration Testing Execution Standard (PTES) richiede **il threat modeling per comprendere le vulnerabilità del sistema** prima di eseguire il test.

### Threat Model in a Nutshell

Un Threat Model è tipicamente rappresentato come un diagramma, un'immagine o un'altra forma di illustrazione visiva che descrive l'architettura pianificata o la costruzione esistente di un'applicazione. Somiglia a un **diagramma di flusso dei dati**, ma la principale distinzione risiede nel suo design orientato alla sicurezza.

I threat model presentano spesso elementi contrassegnati in rosso, che simboleggiano potenziali vulnerabilità, rischi o barriere. Per semplificare il processo di identificazione dei rischi, viene impiegato il triade CIA (Confidenzialità, Integrità, Disponibilità), che forma la base di molte metodologie di threat modeling, con STRIDE che è una delle più comuni. Tuttavia, la metodologia scelta può variare a seconda del contesto specifico e dei requisiti.

### The CIA Triad

La triade CIA è un modello ampiamente riconosciuto nel campo della sicurezza delle informazioni, che sta per Confidenzialità, Integrità e Disponibilità. Questi tre pilastri formano la base su cui sono costruite molte misure e politiche di sicurezza, comprese le metodologie di threat modeling.

1. **Confidenzialità**: Garantire che i dati o il sistema non siano accessibili da parte di individui non autorizzati. Questo è un aspetto centrale della sicurezza, che richiede controlli di accesso appropriati, crittografia e altre misure per prevenire le violazioni dei dati.
2. **Integrità**: L'accuratezza, la coerenza e l'affidabilità dei dati nel loro ciclo di vita. Questo principio garantisce che i dati non vengano alterati o manomessi da parti non autorizzate. Spesso coinvolge checksum, hashing e altri metodi di verifica dei dati.
3. **Disponibilità**: Questo garantisce che i dati e i servizi siano accessibili agli utenti autorizzati quando necessario. Questo spesso implica ridondanza, tolleranza ai guasti e configurazioni ad alta disponibilità per mantenere i sistemi operativi anche di fronte a interruzioni.

### Threat Modeling Methodlogies

1. **STRIDE**: Sviluppato da Microsoft, STRIDE è un acronimo per **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Ogni categoria rappresenta un tipo di minaccia, e questa metodologia è comunemente utilizzata nella fase di design di un programma o sistema per identificare potenziali minacce.
2. **DREAD**: Questa è un'altra metodologia di Microsoft utilizzata per la valutazione del rischio delle minacce identificate. DREAD sta per **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Ognuno di questi fattori viene valutato, e il risultato viene utilizzato per dare priorità alle minacce identificate.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Questa è una metodologia **centrata sul rischio** in sette fasi. Include la definizione e l'identificazione degli obiettivi di sicurezza, la creazione di un ambito tecnico, la decomposizione dell'applicazione, l'analisi delle minacce, l'analisi delle vulnerabilità e la valutazione del rischio/trattamento.
4. **Trike**: Questa è una metodologia basata sul rischio che si concentra sulla difesa degli asset. Parte da una prospettiva di **gestione del rischio** e analizza minacce e vulnerabilità in quel contesto.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Questo approccio mira a essere più accessibile e si integra negli ambienti di sviluppo Agile. Combina elementi delle altre metodologie e si concentra su **rappresentazioni visive delle minacce**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Sviluppato dal CERT Coordination Center, questo framework è orientato verso **la valutazione del rischio organizzativo piuttosto che sistemi o software specifici**.

## Tools

Ci sono diversi strumenti e soluzioni software disponibili che possono **assistere** nella creazione e gestione dei threat model. Ecco alcuni che potresti considerare.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un avanzato spider/crawler GUI multipiattaforma e multifunzionale per professionisti della cybersecurity. Spider Suite può essere utilizzato per la mappatura e l'analisi della superficie di attacco.

**Usage**

1. Scegli un URL e Crawla

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualizza il Grafico

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un progetto open-source di OWASP, Threat Dragon è sia un'applicazione web che desktop che include diagrammi di sistema e un motore di regole per generare automaticamente minacce/mitigazioni.

**Usage**

1. Crea Nuovo Progetto

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A volte potrebbe apparire così:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Avvia Nuovo Progetto

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salva Il Nuovo Progetto

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crea il tuo modello

Puoi utilizzare strumenti come SpiderSuite Crawler per darti ispirazione, un modello di base potrebbe apparire così

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Solo un po' di spiegazione sulle entità:

- Processo (L'entità stessa come Webserver o funzionalità web)
- Attore (Una persona come un visitatore del sito, utente o amministratore)
- Linea di Flusso Dati (Indicatore di interazione)
- Confine di Fiducia (Segmenti o ambiti di rete diversi.)
- Archiviazione (Luoghi dove i dati sono archiviati come Database)

5. Crea una Minaccia (Passo 1)

Prima devi scegliere il livello a cui desideri aggiungere una minaccia

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ora puoi creare la minaccia

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tieni presente che c'è una differenza tra Minacce degli Attori e Minacce dei Processi. Se aggiungi una minaccia a un Attore, potrai scegliere solo "Spoofing" e "Repudiation". Tuttavia, nel nostro esempio aggiungiamo una minaccia a un'entità di Processo, quindi vedremo questo nella casella di creazione della minaccia:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fatto

Ora il tuo modello finito dovrebbe apparire così. E questo è come crei un semplice threat model con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Questo è uno strumento gratuito di Microsoft che aiuta a trovare minacce nella fase di design dei progetti software. Utilizza la metodologia STRIDE ed è particolarmente adatto per coloro che sviluppano sulla stack di Microsoft.


{{#include /banners/hacktricks-training.md}}
