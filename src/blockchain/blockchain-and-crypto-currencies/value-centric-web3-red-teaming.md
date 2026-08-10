# Red Teaming Web3 incentrato sul valore (MITRE AADAPT)

Il framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categorizza le azioni e le tecniche avversarie rivolte ai sistemi di digital asset.<sup>[[1]](#references)</sup> Trattalo come una **base per il threat-modeling**: enumera ogni componente in grado di creare, prezzare, autorizzare o instradare asset, mappa questi punti di contatto sulle tecniche AADAPT e poi sviluppa scenari di red team che misurino se l'ambiente è in grado di resistere a perdite economiche irreversibili.

## 1. Inventariare i componenti che contengono valore
Crea una mappa di tutto ciò che può influenzare lo stato del valore, anche se off-chain.<sup>[[2]](#references)</sup>

- **Servizi di signing custodial** (cluster HSM/KMS, Vault/KMaaS, API di signing usate da bot o job di back-office). Registra gli ID delle chiavi, le policy, le identità di automazione e i workflow di approvazione.
- **Percorsi di amministrazione e upgrade** dei contratti (proxy admin, timelock di governance, chiavi di emergency pause, registri dei parametri). Includi chi/che cosa può chiamarli e con quale quorum o ritardo.
- **Logica dei protocolli on-chain** che gestisce lending, AMM, vault, staking, bridge o rail di settlement. Documenta gli invarianti presupposti (prezzi degli oracle, rapporti di collateralizzazione, frequenza di ribilanciamento…).
- **Automazione off-chain** che costruisce transazioni (bot di market-making, pipeline CI/CD, cron job, funzioni serverless). Spesso detiene API key o service principal in grado di richiedere firme.
- **Oracle e data feed** (composizione degli aggregator, quorum, soglie di deviazione, frequenza di aggiornamento). Nota ogni upstream utilizzato dalla logica automatizzata di gestione del rischio.
- **Bridge e router cross-chain** (contratti lock/mint, relayer, job di settlement) che collegano chain o stack custodial.

Deliverable: un diagramma dei flussi di valore che mostri come si muovono gli asset, chi autorizza i movimenti e quali segnali esterni influenzano la logica di business.

## 2. Mappare i componenti sui comportamenti AADAPT
Traduce la tassonomia AADAPT in candidati concreti di attacco per ogni componente.<sup>[[2]](#references)</sup>

| Componente | Focus AADAPT principale |
| --- | --- |
| Ecosistemi di signing/KMS | Furto di credenziali, bypass delle policy, abuso del signing, takeover della governance |
| Oracle/feed | Poisoning degli input, manipolazione dell'aggregazione, elusione delle soglie di deviazione |
| Protocolli on-chain | Manipolazione economica tramite flash loan, violazione degli invarianti, riconfigurazione dei parametri |
| Pipeline di automazione | Compromissione delle identità di bot/CI, replay di batch, deployment non autorizzato |
| Bridge/router | Elusione cross-chain, laundering tramite hop rapidi, desincronizzazione del settlement |

Questa mappatura garantisce che vengano testati non solo i contratti, ma anche ogni identità o automazione in grado di orientare indirettamente il valore.

## 3. Dare priorità in base alla fattibilità per l'attaccante e all'impatto sul business

1. **Debolezze operative**: credenziali CI esposte, ruoli IAM con privilegi eccessivi, policy KMS configurate erroneamente, account di automazione in grado di richiedere firme arbitrarie, bucket pubblici con configurazioni dei bridge, ecc.
2. **Debolezze specifiche del valore**: parametri fragili degli oracle, contratti upgradable senza approvazioni multi-party, liquidità sensibile ai flash loan, azioni di governance che bypassano i timelock.

Gestisci la coda come farebbe un avversario: inizia dai foothold operativi che potrebbero avere successo oggi, poi passa ai percorsi profondi di manipolazione dei protocolli e dell'economia.<sup>[[2]](#references)</sup>

## 4. Eseguire in ambienti controllati e realistici rispetto alla produzione
- **Mainnet forkate / testnet isolate**: replica bytecode, storage e liquidità affinché i percorsi con flash loan, le derive degli oracle e i flussi dei bridge possano essere eseguiti end-to-end senza toccare fondi reali.<sup>[[2]](#references)</sup>
- **Pianificazione del blast radius**: definisci circuit breaker, moduli in pausa, runbook di rollback e chiavi admin riservate ai test prima di far detonare uno scenario.
- **Coordinamento degli stakeholder**: informa custodian, operatori degli oracle, partner dei bridge e compliance, affinché i loro team di monitoring si aspettino il traffico.
- **Approvazione legale**: documenta scope, autorizzazione e condizioni di arresto quando le simulazioni potrebbero attraversare rail regolamentati.

## 5. Telemetria allineata alle tecniche AADAPT
Strumenta i flussi di telemetria affinché ogni scenario produca dati di detection utilizzabili.<sup>[[2]](#references)</sup>

- **Trace a livello di chain**: grafi completi delle chiamate, utilizzo del gas, nonce delle transazioni e timestamp dei blocchi, per ricostruire bundle di flash loan, strutture simili alla reentrancy e hop tra contratti.
- **Log applicativi/API**: collega ogni tx on-chain a un'identità umana o di automazione (ID di sessione, client OAuth, API key, ID del job CI), includendo IP e metodi di autenticazione.
- **Log KMS/HSM**: ID della chiave, principal chiamante, risultato della policy, indirizzo di destinazione e codici motivo per ogni firma. Definisci una baseline per le finestre di modifica e le operazioni ad alto rischio.
- **Metadata di oracle/feed**: composizione della fonte dati per ogni aggiornamento, valore riportato, deviazione dalle medie mobili, soglie attivate e percorsi di failover utilizzati.
- **Trace di bridge/swap**: correla gli eventi lock/mint/unlock tra le chain con correlation ID, chain ID, identità del relayer e tempistiche degli hop.
- **Indicatori di anomalia**: metriche derivate come picchi di slippage, rapporti di collateralizzazione anomali, densità di gas insolita o velocità cross-chain.

Applica a tutto scenario ID o synthetic user ID, così gli analisti possono allineare gli osservabili con la tecnica AADAPT sottoposta a test.

## 6. Ciclo purple team e metriche di maturità
1. Esegui lo scenario nell'ambiente controllato e acquisisci le detection (alert, dashboard, responder contattati).<sup>[[2]](#references)</sup>
2. Mappa ogni passaggio sulle tecniche AADAPT specifiche e sugli osservabili prodotti nei piani chain/app/KMS/oracle/bridge.
3. Formula e implementa ipotesi di detection (regole basate su soglie, ricerche di correlazione, controlli degli invarianti).
4. Ripeti l'esecuzione finché il mean time to detect (MTTD) e il mean time to contain (MTTC) rientrano nelle tolleranze del business e i playbook bloccano in modo affidabile la perdita di valore.

Monitora la maturità del programma su tre assi:<sup>[[2]](#references)</sup>
- **Visibilità**: ogni percorso di valore critico dispone di telemetria in ciascun piano.
- **Coverage**: proporzione delle tecniche AADAPT prioritarie esercitate end-to-end.
- **Response**: capacità di mettere in pausa i contratti, revocare le chiavi o bloccare i flussi prima di una perdita irreversibile.

Milestone tipiche: (1) inventario completo del valore e mappatura AADAPT, (2) primo scenario end-to-end con detection implementate, (3) cicli purple team trimestrali che ampliano la coverage e riducono MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Template di scenario
Utilizza questi blueprint ripetibili per progettare simulazioni che si mappano direttamente sui comportamenti AADAPT.<sup>[[2]](#references)</sup>

### Scenario A – Manipolazione economica tramite flash loan
- **Obiettivo**: prendere in prestito capitale temporaneo all'interno di una singola transazione per distorcere prezzi/liquidità degli AMM e attivare borrow, liquidazioni o mint a prezzi errati prima della restituzione.
- **Esecuzione**:
1. Forka la chain target e alimenta i pool con liquidità simile a quella di produzione.
2. Prendi in prestito un valore nozionale elevato tramite flash loan.
3. Esegui swap calibrati per superare i confini di prezzo o soglia utilizzati dalla logica di lending, vault o derivati.
4. Invoca il contratto vittima immediatamente dopo la distorsione (borrow, liquidate, mint) e restituisci il flash loan.
- **Misurazione**: la violazione dell'invariante ha avuto successo? Sono stati attivati i monitor di slippage/deviazione del prezzo, i circuit breaker o gli hook di governance pause? Quanto tempo è trascorso prima che gli analytics segnalassero il pattern anomalo del grafo di gas/chiamate?

### Scenario B – Poisoning di oracle/data feed
- **Obiettivo**: determinare se feed manipolati possano attivare azioni automatizzate distruttive (liquidazioni di massa, settlement errati).
- **Esecuzione**:
1. Nel fork/testnet, implementa un feed malevolo oppure modifica i pesi dell'aggregator, il quorum o la frequenza di aggiornamento oltre la deviazione tollerata.
2. Lascia che i contratti dipendenti consumino i valori avvelenati ed eseguano la loro logica standard.
- **Misurazione**: alert out-of-band a livello di feed, attivazione dell'oracle di fallback, applicazione dei limiti min/max e latenza tra l'inizio dell'anomalia e la risposta dell'operatore.

### Scenario C – Abuso di credenziali/signing
- **Obiettivo**: verificare se la compromissione di un singolo signer o di un'identità di automazione consenta upgrade non autorizzati, modifiche dei parametri o drenaggi della treasury.
- **Esecuzione**:
1. Enumera le identità con diritti di signing sensibili (operatori, token CI, service account che invocano KMS/HSM, partecipanti multisig).
2. Simula la compromissione (riutilizza le loro credenziali/chiavi entro lo scope del lab).
3. Tenta azioni privilegiate: esegui l'upgrade dei proxy, modifica i parametri di rischio, effettua il mint/metti in pausa gli asset oppure attiva proposte di governance.
- **Misurazione**: i log KMS/HSM generano alert di anomalia (ora del giorno, variazione della destinazione, raffica di operazioni ad alto rischio)? Le policy o le soglie multisig impediscono l'abuso unilaterale? Sono applicati throttle/rate limit o approvazioni aggiuntive?

### Scenario D – Elusione cross-chain e lacune di tracciabilità
- **Obiettivo**: valutare quanto efficacemente i defender riescano a tracciare e interdire asset sottoposti rapidamente a laundering attraverso bridge, router DEX e hop privacy.
- **Esecuzione**:
1. Collega operazioni lock/mint attraverso bridge comuni, intervalla swap/mixer a ogni hop e mantieni correlation ID per ogni hop.
2. Accelera i trasferimenti per sottoporre a stress la latenza del monitoring (multi-hop in pochi minuti o blocchi).
- **Misurazione**: tempo necessario per correlare gli eventi tra telemetria e chain analytics commerciali, completezza del percorso ricostruito, capacità di identificare i choke point per il freezing durante un incidente reale e accuratezza degli alert relativi a velocità/valore cross-chain anomali.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
