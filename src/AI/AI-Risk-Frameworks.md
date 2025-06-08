# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificato le 10 principali vulnerabilità del machine learning che possono influenzare i sistemi AI. Queste vulnerabilità possono portare a vari problemi di sicurezza, inclusi avvelenamento dei dati, inversione del modello e attacchi avversariali. Comprendere queste vulnerabilità è cruciale per costruire sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle 10 principali vulnerabilità del machine learning, fare riferimento al progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaccante aggiunge piccole, spesso invisibili modifiche ai **dati in arrivo** affinché il modello prenda la decisione sbagliata.\
*Esempio*: Alcuni spruzzi di vernice su un segnale di stop ingannano un'auto a guida autonoma facendole "vedere" un segnale di limite di velocità.

- **Data Poisoning Attack**: Il **set di addestramento** è deliberatamente inquinato con campioni errati, insegnando al modello regole dannose.\
*Esempio*: I file binari di malware sono etichettati erroneamente come "benigni" in un corpus di addestramento antivirus, permettendo a malware simili di passare inosservati in seguito.

- **Model Inversion Attack**: Probing degli output, un attaccante costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente dalle previsioni di un modello di rilevamento del cancro.

- **Membership Inference Attack**: L'avversario verifica se un **record specifico** è stato utilizzato durante l'addestramento individuando differenze di confidenza.\
*Esempio*: Confermare che una transazione bancaria di una persona appare nei dati di addestramento di un modello di rilevamento delle frodi.

- **Model Theft**: Query ripetute consentono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: Raccolta di un numero sufficiente di coppie di domande e risposte da un'API ML-as-a-Service per costruire un modello locale quasi equivalente.

- **AI Supply‑Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre-addestrati, CI/CD) nel **pipeline ML** per corrompere i modelli a valle.\
*Esempio*: Una dipendenza avvelenata su un modello-hub installa un modello di analisi del sentiment con backdoor in molte app.

- **Transfer Learning Attack**: Logica malevola è piantata in un **modello pre-addestrato** e sopravvive al fine-tuning sul compito della vittima.\
*Esempio*: Un backbone visivo con un trigger nascosto continua a cambiare etichette dopo essere stato adattato per l'imaging medico.

- **Model Skewing**: Dati sottilmente distorti o etichettati erroneamente **spostano gli output del modello** a favore dell'agenda dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettate come ham affinché un filtro antispam lasci passare email simili in futuro.

- **Output Integrity Attack**: L'attaccante **modifica le previsioni del modello in transito**, non il modello stesso, ingannando i sistemi a valle.\
*Esempio*: Cambiare il verdetto "maligno" di un classificatore di malware in "benigno" prima che la fase di quarantena del file lo veda.

- **Model Poisoning** --- Modifiche dirette e mirate ai **parametri del modello** stessi, spesso dopo aver ottenuto accesso in scrittura, per alterare il comportamento.\
*Esempio*: Modificare i pesi su un modello di rilevamento delle frodi in produzione affinché le transazioni di determinate carte siano sempre approvate.


## Google SAIF Risks

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google delinea vari rischi associati ai sistemi AI:

- **Data Poisoning**: Attori malevoli alterano o iniettano dati di addestramento/tuning per degradare l'accuratezza, impiantare backdoor o distorcere i risultati, minando l'integrità del modello durante l'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: L'ingestione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e di prestazione perché il modello apprende da dati che non avrebbe mai dovuto utilizzare.

- **Model Source Tampering**: Manipolazione della catena di fornitura o interna del codice del modello, delle dipendenze o dei pesi prima o durante l'addestramento può incorporare logica nascosta che persiste anche dopo il riaddestramento.

- **Excessive Data Handling**: Controlli deboli sulla conservazione e governance dei dati portano i sistemi a memorizzare o elaborare più dati personali del necessario, aumentando l'esposizione e il rischio di conformità.

- **Model Exfiltration**: Gli attaccanti rubano file/pesi del modello, causando perdita di proprietà intellettuale e abilitando servizi imitativi o attacchi successivi.

- **Model Deployment Tampering**: Gli avversari modificano artefatti del modello o infrastrutture di servizio affinché il modello in esecuzione differisca dalla versione verificata, potenzialmente cambiando comportamento.

- **Denial of ML Service**: Inondare le API o inviare input "spugna" può esaurire le risorse di calcolo/energia e mettere offline il modello, rispecchiando attacchi DoS classici.

- **Model Reverse Engineering**: Raccolta di un gran numero di coppie input-output, gli attaccanti possono clonare o distillare il modello, alimentando prodotti imitativi e attacchi avversariali personalizzati.

- **Insecure Integrated Component**: Plugin, agenti o servizi upstream vulnerabili consentono agli attaccanti di iniettare codice o elevare privilegi all'interno del pipeline AI.

- **Prompt Injection**: Creare prompt (direttamente o indirettamente) per contrabbandare istruzioni che sovrascrivono l'intento del sistema, facendo eseguire al modello comandi non intenzionati.

- **Model Evasion**: Input progettati con attenzione attivano il modello per classificare erroneamente, allucinare o produrre contenuti non consentiti, erodendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o riservate dai suoi dati di addestramento o dal contesto utente, violando la privacy e le normative.

- **Inferred Sensitive Data**: Il modello deduce attributi personali che non sono mai stati forniti, creando nuovi danni alla privacy attraverso l'inferenza.

- **Insecure Model Output**: Risposte non sanificate trasmettono codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi a valle.

- **Rogue Actions**: Agenti integrati autonomamente eseguono operazioni reali non intenzionate (scritture di file, chiamate API, acquisti, ecc.) senza un adeguato controllo dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework completo per comprendere e mitigare i rischi associati ai sistemi AI. Categorizza varie tecniche e tattiche di attacco che gli avversari possono utilizzare contro i modelli AI e anche come utilizzare i sistemi AI per eseguire diversi attacchi.


{{#include ../banners/hacktricks-training.md}}
