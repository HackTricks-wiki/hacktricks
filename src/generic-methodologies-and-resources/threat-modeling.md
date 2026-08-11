# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

Benvenuti nella guida completa di HackTricks sul Threat Modeling! Esplorate questo aspetto fondamentale della cybersecurity, in cui identifichiamo, comprendiamo e sviluppiamo strategie contro le potenziali vulnerabilità presenti in un sistema. Questa guida offre un percorso passo passo ricco di esempi reali, software utili e spiegazioni facili da comprendere. È ideale sia per principianti sia per professionisti esperti che desiderano rafforzare le proprie difese di cybersecurity.

### Scenari comunemente utilizzati

1. **Sviluppo software**: nell'ambito del Secure Software Development Life Cycle (SSDLC), il threat modeling aiuta a **identificare le potenziali fonti di vulnerabilità** nelle prime fasi dello sviluppo.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: il Penetration Testing Execution Standard (PTES) considera il threat modeling necessario per una corretta esecuzione e richiede di documentare gli asset aziendali, i processi aziendali, le comunità di minacce e le relative capacità.<sup>[[2]](#references)</sup>

### Threat Model in breve

Un threat model è generalmente rappresentato da un diagramma, un'immagine o un'altra illustrazione visiva di un'architettura pianificata o di un'applicazione esistente. I diagrammi di flusso dei dati (DFD) sono un modo comune per modellare un sistema e le sue interazioni, mentre il threat modeling aggiunge un'analisi incentrata sulla sicurezza.<sup>[[1]](#references)</sup>

Nel Threat Modeling Tool di Microsoft, le linee rosse tratteggiate indicano i confini di trust; altri tool possono utilizzare convenzioni visive diverse.<sup>[[4]](#references)</sup> Per semplificare l'identificazione dei rischi, i team possono utilizzare la triade CIA (Confidentiality, Integrity, Availability) o le categorie di minacce STRIDE, ma la metodologia appropriata dipende dal contesto e dai requisiti del progetto.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### La triade CIA

La triade CIA è un modello di information security ampiamente riconosciuto, il cui acronimo sta per Confidentiality, Integrity e Availability. Queste proprietà vengono comunemente utilizzate per descrivere gli obiettivi di sicurezza relativi a dati e sistemi.<sup>[[3]](#references)</sup>

1. **Confidentiality**: garantire che i dati o il sistema non siano accessibili a persone non autorizzate. Si tratta di un aspetto centrale della sicurezza, che richiede controlli di accesso appropriati, crittografia e altre misure per prevenire le violazioni dei dati.
2. **Integrity**: l'accuratezza, la coerenza e l'affidabilità dei dati durante il loro ciclo di vita. Questo principio garantisce che i dati non vengano modificati o manomessi da soggetti non autorizzati. Spesso include checksum, hashing e altri metodi di verifica dei dati.
3. **Availability**: garantisce che dati e servizi siano accessibili agli utenti autorizzati quando necessario. Spesso richiede ridondanza, fault tolerance e configurazioni ad alta disponibilità per mantenere i sistemi operativi anche in caso di interruzioni.

### Metodologie di Threat Modeling

1. **STRIDE**: l'approccio STRIDE di Microsoft categorizza le minacce software come **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service ed Elevation of Privilege**. Queste categorie aiutano gli analisti a identificare le possibili minacce in ogni punto vulnerabile di un progetto.<sup>[[5]](#references)</sup>
2. **DREAD**: questo approccio di valutazione di Microsoft assegna un punteggio alle minacce utilizzando **Damage, Reproducibility, Exploitability, Affected users e Discoverability**. Il punteggio risultante può aiutare a stabilire la priorità delle minacce da mitigare.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): è una metodologia **risk-centric** in sette fasi che comprende obiettivi, ambito tecnico, scomposizione dell'applicazione, analisi delle minacce, analisi delle vulnerabilità e delle debolezze, attack modeling e analisi del rischio/impatto.<sup>[[8]](#references)</sup>
4. **Trike**: questo framework di security audit affronta il threat modeling da una prospettiva di **risk-management** e difensiva.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): questo metodo enfatizza threat model scalabili e utilizzabili per le viste applicative e operative e può integrarsi con i cicli di vita di sviluppo e DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): creato dalla CERT Division del Software Engineering Institute della Carnegie Mellon, OCTAVE è un metodo strategico di valutazione e pianificazione basato sul rischio, incentrato sul rischio organizzativo più che sulla sola tecnologia.<sup>[[10]](#references)</sup>

## Tools

Sono disponibili diversi tool e soluzioni software che possono **aiutare** nella creazione e nella gestione dei threat model. Eccone alcuni che potreste prendere in considerazione.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite è un web crawler multipiattaforma per professionisti della sicurezza che supporta l'attack-surface mapping, l'endpoint discovery e l'analisi delle web application.<sup>[[6]](#references)</sup>

**Utilizzo**

1. Scegliete un URL ed eseguite il Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualizzate il Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon è un'applicazione di threat modeling gratuita, open source e multipiattaforma, per disegnare diagrammi, suggerire minacce e registrare le mitigazioni. È disponibile come applicazione web e desktop.<sup>[[7]](#references)</sup>

**Utilizzo**

1. Create un New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A volte potrebbe apparire così:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Avviate il New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salvate il New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Create il vostro modello

Potete utilizzare tool come SpiderSuite Crawler per trarre ispirazione; un modello di base potrebbe avere un aspetto simile a questo:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Una breve spiegazione delle entità:

- Process (l'entità stessa, come un Webserver o una funzionalità web)
- Actor (una persona, come un Website Visitor, un User o un Administrator)
- Data Flow Line (indicatore di interazione)
- Trust Boundary (segmenti o ambiti di rete differenti)
- Store (elementi in cui vengono memorizzati i dati, come i Database)

5. Create una Threat (Step 1)

Per prima cosa dovete scegliere il layer a cui desiderate aggiungere una minaccia

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ora potete creare la minaccia

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tenete presente che esiste una differenza tra Actor Threats e Process Threats. Se aggiungete una minaccia a un Actor, potrete scegliere solo "Spoofing" e "Repudiation". Tuttavia, nel nostro esempio aggiungiamo una minaccia a un'entità Process, quindi visualizzeremo quanto segue nel riquadro di creazione della minaccia:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fine

Ora il modello completato dovrebbe avere un aspetto simile a questo. Questo è il modo per creare un semplice threat model con OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Il Threat Modeling Tool di Microsoft è un tool scaricabile gratuitamente per l'analisi del design software. Il suo workflow crea un diagramma, identifica le minacce e supporta la mitigazione e la validazione utilizzando l'approccio STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - Lo standard di esecuzione del Penetration Testing](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Fondamenti di sicurezza - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Introduzione al Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling per i driver - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Threat Modeling PASTA: spiegazione delle 7 fasi](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Documento sulla metodologia Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: un riepilogo dei metodi disponibili](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
