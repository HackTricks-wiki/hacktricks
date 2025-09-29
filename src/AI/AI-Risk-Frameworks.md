# Rischi AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilità del Machine Learning

Owasp ha identificato le prime 10 vulnerabilità del machine learning che possono colpire i sistemi AI. Queste vulnerabilità possono portare a vari problemi di sicurezza, inclusi data poisoning, model inversion e attacchi adversarial. Comprendere queste vulnerabilità è fondamentale per costruire sistemi AI sicuri.

Per un elenco aggiornato e dettagliato delle top 10 machine learning vulnerabilities, facci riferimento al progetto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaccante aggiunge piccole modifiche, spesso invisibili, ai **dati in ingresso** in modo che il modello prenda la decisione sbagliata.\
*Esempio*: Alcune macchioline di vernice su un segnale di stop ingannano un'auto a guida autonoma facendole "vedere" un cartello di limite di velocità.

- **Data Poisoning Attack**: Il **set di addestramento** viene deliberatamente inquinato con campioni malevoli, insegnando al modello regole dannose.\
*Esempio*: Binarî di malware etichettati erroneamente come "benign" in un corpus per antivirus, permettendo a malware simili di passare inosservati.

- **Model Inversion Attack**: Interrogando le uscite, un attaccante costruisce un **modello inverso** che ricostruisce caratteristiche sensibili degli input originali.\
*Esempio*: Ricreare l'immagine MRI di un paziente a partire dalle predizioni di un modello per la rilevazione del cancro.

- **Membership Inference Attack**: L'avversario testa se un **record specifico** è stato usato durante l'addestramento individuando differenze di confidence.\
*Esempio*: Confermare che una transazione bancaria di una persona appare nel dataset di training di un modello di rilevamento frodi.

- **Model Theft**: Interrogazioni ripetute permettono a un attaccante di apprendere i confini decisionali e **clonare il comportamento del modello** (e la proprietà intellettuale).\
*Esempio*: Raccogliere abbastanza coppie Q&A da un'API ML‑as‑a‑Service per costruire un modello locale quasi equivalente.

- **AI Supply‑Chain Attack**: Compromettere qualsiasi componente (dati, librerie, pesi pre-addestrati, CI/CD) nella **ML pipeline** per corrompere i modelli a valle.\
*Esempio*: Una dipendenza avvelenata su un model‑hub installa un modello di sentiment‑analysis backdoored in molte app.

- **Transfer Learning Attack**: Logica malevola viene piantata in un **modello pre‑addestrato** e sopravvive al fine‑tuning sul task della vittima.\
*Esempio*: Un backbone di visione con un trigger nascosto continua a invertire le etichette dopo essere stato adattato per imaging medicale.

- **Model Skewing**: Dati sottilmente distorti o etichettati male **spostano le uscite del modello** a favore dell'agenda dell'attaccante.\
*Esempio*: Iniettare email di spam "pulite" etichettandole come ham in modo che un filtro anti‑spam lasci passare email simili in futuro.

- **Output Integrity Attack**: L'attaccante **modifica le predizioni del modello in transito**, non il modello stesso, ingannando i sistemi a valle.\
*Esempio*: Ribaltare il verdetto "malicious" di un classifier di malware in "benign" prima che la fase di quarantena del file lo veda.

- **Model Poisoning** --- Modifiche dirette e mirate ai **parametri del modello** stessi, spesso dopo aver ottenuto accesso in scrittura, per alterarne il comportamento.\
*Esempio*: Modificare i pesi di un modello di rilevamento frodi in produzione in modo che le transazioni provenienti da certe carte siano sempre approvate.


## Rischi SAIF di Google

Il [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) di Google descrive vari rischi associati ai sistemi AI:

- **Data Poisoning**: Attori malintenzionati alterano o iniettano dati di training/tuning per degradare l'accuratezza, impiantare backdoor o distorcere i risultati, minando l'integrità del modello lungo l'intero ciclo di vita dei dati.

- **Unauthorized Training Data**: L'ingestione di dataset protetti da copyright, sensibili o non autorizzati crea responsabilità legali, etiche e di performance perché il modello apprende da dati che non avrebbe dovuto usare.

- **Model Source Tampering**: Manipolazioni nella supply‑chain o da insider del codice del modello, delle dipendenze o dei pesi prima o durante l'addestramento possono inserire logiche nascoste che persistono anche dopo un retraining.

- **Excessive Data Handling**: Controlli deboli sulla retention e sulla governance dei dati portano i sistemi a memorizzare o processare più dati personali del necessario, aumentando l'esposizione e il rischio di compliance.

- **Model Exfiltration**: Gli attaccanti rubano file/pesi del modello, causando perdita di proprietà intellettuale e abilitando servizi imitativi o attacchi successivi.

- **Model Deployment Tampering**: Gli avversari modificano artefatti del modello o l'infrastruttura di serving in modo che il modello in esecuzione sia diverso dalla versione verificata, potenzialmente cambiandone il comportamento.

- **Denial of ML Service**: Inondare API o inviare input "sponge" può esaurire compute/energia e mandare il modello offline, specchiando attacchi DoS classici.

- **Model Reverse Engineering**: Raccolta massiva di coppie input‑output permette agli attaccanti di clonare o distillare il modello, alimentando prodotti imitativi e attacchi adversarial personalizzati.

- **Insecure Integrated Component**: Plugin, agenti o servizi upstream vulnerabili permettono agli attaccanti di iniettare codice o incrementare privilegi nella pipeline AI.

- **Prompt Injection**: Creare prompt (direttamente o indirettamente) per introdurre istruzioni che sovrascrivono l'intento di sistema, inducendo il modello a eseguire comandi non voluti.

- **Model Evasion**: Input attentamente progettati inducono il modello a misclassificare, a generare hallucination o a produrre contenuti vietati, erodendo sicurezza e fiducia.

- **Sensitive Data Disclosure**: Il modello rivela informazioni private o confidenziali provenienti dai dati di training o dal contesto utente, violando privacy e normative.

- **Inferred Sensitive Data**: Il modello deduce attributi personali mai forniti, creando nuovi danni alla privacy tramite inferenza.

- **Insecure Model Output**: Risposte non sanitizzate passano codice dannoso, disinformazione o contenuti inappropriati agli utenti o ai sistemi a valle.

- **Rogue Actions**: Agenti integrati autonomamente eseguono operazioni reali non volute (scrittura di file, chiamate API, acquisti, ecc.) senza adeguata supervisione dell'utente.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornisce un framework comprensivo per comprendere e mitigare i rischi associati ai sistemi AI. Classifica varie tecniche e tattiche d'attacco che gli avversari possono usare contro i modelli AI e anche come usare i sistemi AI per eseguire diversi attacchi.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Gli attaccanti rubano session tokens attivi o credenziali API cloud e invocano LLM cloud a pagamento senza autorizzazione. L'accesso viene spesso rivenduto tramite reverse proxies che fanno da front per l'account della vittima, es. deploy di "oai-reverse-proxy". Le conseguenze includono perdita finanziaria, uso improprio del modello oltre le policy e attribuzione al tenant vittima.

TTPs:
- Harvest tokens da macchine di sviluppatori o browser infetti; rubare segreti CI/CD; comprare cookie leaked.
- Stand up un reverse proxy che inoltra le richieste al provider genuino, nascondendo la chiave upstream e multiplexando molti clienti.
- Abuse direct base-model endpoints per bypassare enterprise guardrails e rate limits.

Mitigations:
- Bind tokens al device fingerprint, a range IP e a client attestation; imporre short expirations e refresh con MFA.
- Scope keys minimamente (no tool access, read‑only dove applicabile); rotate su anomalie.
- Terminate tutto il traffico server‑side dietro un policy gateway che applica filtri di safety, quote per-route e tenant isolation.
- Monitorare pattern d'uso insoliti (improvvisi spike di spesa, regioni atipiche, UA strings) e auto‑revoke sessioni sospette.
- Preferire mTLS o signed JWTs rilasciati dal tuo IdP rispetto a long‑lived static API keys.

## Riferimenti
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
