# Threat Modeling

Benvenuti nella guida completa di HackTricks al Threat Modeling! Intraprendete un'esplorazione di questo aspetto critico della cybersecurity, in cui identifichiamo, comprendiamo e sviluppiamo strategie contro le potenziali vulnerabilità di un sistema. Questa guida funge da percorso passo dopo passo, ricco di esempi reali, software utili e spiegazioni facili da comprendere. È ideale sia per i principianti sia per i professionisti esperti che desiderano rafforzare le proprie difese di cybersecurity.

### Scenari comunemente utilizzati

1. **Sviluppo software**: nell'ambito del Secure Software Development Life Cycle (SSDLC), il threat modeling aiuta a **identificare le potenziali fonti di vulnerabilità** nelle prime fasi dello sviluppo.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: il Penetration Testing Execution Standard (PTES) considera il threat modeling necessario per una corretta esecuzione e richiede la documentazione degli asset aziendali, dei processi aziendali, delle comunità di minacce e delle loro capacità.<sup>[[2]](#references)</sup>

### Threat Model in breve

Un threat model è generalmente rappresentato da un diagramma, un'immagine o un'altra rappresentazione visiva di un'architettura pianificata o di un'applicazione esistente. I diagrammi di flusso dei dati (DFD) sono un metodo comune per modellare un sistema e le sue interazioni, mentre il threat modeling aggiunge un'analisi incentrata sulla sicurezza.<sup>[[1]](#references)</sup>

Nel Microsoft Threat Modeling Tool, le linee rosse tratteggiate indicano i trust boundary; altri strumenti possono utilizzare convenzioni visive differenti.<sup>[[4]](#references)</sup> Per semplificare l'identificazione dei rischi, i team possono utilizzare la triade CIA (Confidentiality, Integrity, Availability) o le categorie di minacce STRIDE, ma la metodologia appropriata dipende dal contesto e dai requisiti del progetto.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### La triade CIA

La triade CIA è un modello di information security ampiamente riconosciuto, che sta per Confidentiality, Integrity e Availability. Queste proprietà sono comunemente utilizzate per descrivere gli obiettivi di sicurezza relativi a dati e sistemi.<sup>[[3]](#references)</sup>

1. **Confidentiality**: garantire che i dati o il sistema non siano accessibili da persone non autorizzate. Questo è un aspetto centrale della sicurezza e richiede controlli degli accessi appropriati, encryption e altre misure per prevenire data breach.
2. **Integrity**: l'accuratezza, la coerenza e l'affidabilità dei dati durante il loro ciclo di vita. Questo principio garantisce che i dati non vengano modificati o manomessi da soggetti non autorizzati. Spesso comprende checksum, hashing e altri metodi di verifica dei dati.
3. **Availability**: garantire che dati e servizi siano accessibili agli utenti autorizzati quando necessario. Ciò richiede spesso ridondanza, fault tolerance e configurazioni ad alta disponibilità per mantenere i sistemi operativi anche in caso di interruzioni.

### Metodologie di Threat Modeling

1. **STRIDE**: l'approccio STRIDE di Microsoft classifica le minacce software come **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Queste categorie aiutano gli analisti a identificare le possibili minacce in ogni punto vulnerabile di un progetto.<sup>[[5]](#references)</sup>
2. **DREAD**: questo approccio di valutazione di Microsoft assegna un punteggio alle minacce utilizzando **Damage, Reproducibility, Exploitability, Affected users e Discoverability**. Il punteggio risultante può aiutare a stabilire la priorità delle minacce da mitigare.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): è una metodologia **risk-centric** articolata in sette fasi, che comprende obiettivi, ambito tecnico, scomposizione dell'applicazione, analisi delle minacce, analisi delle vulnerabilità e delle debolezze, attack modeling e analisi del rischio/impatto.<sup>[[8]](#references)</sup>
4. **Trike**: questo framework di security audit affronta il threat modeling da una prospettiva di **risk-management** e difensiva.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): questo metodo enfatizza threat model scalabili e utilizzabili per le viste applicative e operative e può integrarsi con i cicli di vita di sviluppo e DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): creato dalla CERT Division del Software Engineering Institute della Carnegie Mellon, OCTAVE è un metodo strategico di valutazione e pianificazione basato sul rischio, focalizzato sul rischio organizzativo anziché esclusivamente sulla tecnologia.<sup>[[10]](#references)</sup>

## Tools

Sono disponibili diversi tools e soluzioni software che possono **assistere** nella creazione e nella gestione dei threat model. Eccone alcuni che potreste prendere in considerazione.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite è un web crawler multipiattaforma per professionisti della sicurezza che supporta l'attack-surface mapping, l'endpoint discovery e l'analisi delle web application.<sup>[[6]](#references)</sup>

**Utilizzo**

1. Scegliete un URL ed eseguite il Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualizzate il Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon è un'applicazione gratuita, open-source e multipiattaforma per il threat modeling, che consente di disegnare diagrammi, suggerire minacce e registrare le mitigazioni. È disponibile come applicazione web e desktop.<sup>[[7]](#references)</sup>

**Utilizzo**

1. Create un nuovo progetto

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A volte potrebbe apparire così:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Avviate il nuovo progetto

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salvate il nuovo progetto

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Create il vostro model

Potete utilizzare tools come SpiderSuite Crawler per trarre ispirazione; un model di base potrebbe essere simile a questo

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Ecco una breve spiegazione delle entità:

- Process (l'entità stessa, come un Webserver o una funzionalità web)
- Actor (una persona, come un visitatore del sito web, un utente o un amministratore)
- Data Flow Line (indicatore dell'interazione)
- Trust Boundary (segmenti o ambiti di rete differenti)
- Store (elementi in cui vengono memorizzati i dati, come i database)

5. Create una Threat (Passaggio 1)

Per prima cosa dovete scegliere il layer a cui desiderate aggiungere una threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ora potete creare la threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tenete presente che esiste una differenza tra Actor Threats e Process Threats. Se aggiungete una threat a un Actor, potrete scegliere solo "Spoofing" e "Repudiation". Tuttavia, nel nostro esempio aggiungiamo una threat a un'entità Process, quindi visualizzeremo quanto segue nel riquadro di creazione della threat:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Completato

Ora il vostro model completato dovrebbe apparire più o meno così. Questo è il modo per creare un semplice threat model con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Il Microsoft Threat Modeling Tool è un tool gratuito scaricabile per l'analisi della progettazione software. Il suo workflow crea un diagramma, identifica le minacce e supporta la mitigazione e la validazione utilizzando l'approccio STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Fondamenti della sicurezza - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Introduzione al Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling for Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Threat Modeling PASTA: spiegazione delle 7 fasi](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Documento sulla metodologia Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: riepilogo dei metodi disponibili](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
