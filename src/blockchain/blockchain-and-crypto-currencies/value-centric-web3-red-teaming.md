# Red Teaming Web3 incentrato sul valore (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

La matrice MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) descrive i comportamenti degli attacker che manipolano il valore digitale, anziché limitarsi all'infrastruttura. Considerala come una **struttura portante per il threat modeling**: enumera ogni componente in grado di creare, valutare, autorizzare o instradare asset, associa questi punti di contatto alle tecniche AADAPT e quindi sviluppa scenari di red team per misurare se l'ambiente è in grado di resistere a perdite economiche irreversibili.

## 1. Inventariare i componenti che rappresentano valore
Crea una mappa di tutto ciò che può influenzare lo stato del valore, anche se off-chain.<sup>[[1]](#references)</sup>

- **Servizi di signing custodial** (cluster HSM/KMS, Vault/KMaaS, API di signing utilizzate da bot o processi di back-office). Raccogli key ID, policy, identità di automazione e workflow di approvazione.
- **Percorsi di amministrazione e upgrade** dei contratti (proxy admin, timelock di governance, chiavi di emergency pause, registri dei parametri). Includi chi/che cosa può invocarli e in base a quale quorum o ritardo.
- **Logica dei protocolli on-chain** che gestisce lending, AMM, vault, staking, bridge o rail di settlement. Documenta gli invarianti presupposti (prezzi degli oracle, rapporti di collateralizzazione, cadenza del rebalance…).
- **Automazione off-chain** che costruisce transazioni (bot di market-making, pipeline CI/CD, cron job, funzioni serverless). Spesso contengono API key o service principal in grado di richiedere firme.
- **Oracle e data feed** (composizione degli aggregator, quorum, soglie di deviazione, cadenza degli aggiornamenti). Annota ogni upstream da cui dipende la logica automatizzata di gestione del rischio.
- **Bridge e router cross-chain** (contratti di lock/mint, relayer, processi di settlement) che collegano chain o stack custodial.

Deliverable: un diagramma del flusso del valore che mostri come si muovono gli asset, chi autorizza i movimenti e quali segnali esterni influenzano la logica di business.

## 2. Associare i componenti ai comportamenti AADAPT
Traduce la tassonomia AADAPT in candidati concreti di attacco per ogni componente.<sup>[[1]](#references)</sup>

| Componente | Focus AADAPT principale |
| --- | --- |
| Ecosistemi signing/KMS | Furto di credenziali, bypass delle policy, abuso del signing, takeover della governance |
| Oracle/feed | Poisoning degli input, manipolazione dell'aggregazione, elusione delle soglie di deviazione |
| Protocolli on-chain | Manipolazione economica tramite flash loan, violazione degli invarianti, riconfigurazione dei parametri |
| Pipeline di automazione | Identità bot/CI compromesse, replay di batch, deployment non autorizzato |
| Bridge/router | Elusione cross-chain, laundering tramite hop rapidi, desincronizzazione del settlement |

Questa mappatura garantisce che vengano testati non solo i contratti, ma anche ogni identità o automazione in grado di dirigere indirettamente il valore.

## 3. Stabilire le priorità in base alla fattibilità per l'attacker e all'impatto sul business

1. **Debolezze operative**: credenziali CI esposte, ruoli IAM con privilegi eccessivi, policy KMS configurate erroneamente, account di automazione in grado di richiedere firme arbitrarie, bucket pubblici contenenti configurazioni dei bridge, ecc.
2. **Debolezze specifiche del valore**: parametri oracle fragili, contratti upgradable senza approvazioni multi-party, liquidità sensibile ai flash loan, azioni di governance che bypassano i timelock.

Gestisci la coda come farebbe un avversario: inizia dagli accessi operativi iniziali che potrebbero avere successo oggi, quindi procedi verso percorsi complessi di manipolazione del protocollo o dell'economia.<sup>[[1]](#references)</sup>

## 4. Eseguire i test in ambienti controllati e realistici rispetto alla produzione
- **Mainnet forked / testnet isolate**: replica bytecode, storage e liquidità affinché i percorsi con flash loan, le variazioni degli oracle e i flussi dei bridge vengano eseguiti end-to-end senza toccare fondi reali.<sup>[[1]](#references)</sup>
- **Pianificazione del blast radius**: definisci circuit breaker, moduli pausable, runbook di rollback e chiavi admin solo per i test prima di attivare uno scenario.
- **Coordinamento degli stakeholder**: informa custodian, operatori degli oracle, partner dei bridge e compliance, affinché i loro team di monitoring si aspettino questo traffico.
- **Approvazione legale**: documenta ambito, autorizzazione e condizioni di arresto quando le simulazioni potrebbero attraversare rail regolamentati.

## 5. Telemetria allineata alle tecniche AADAPT
Strumenta i flussi di telemetria affinché ogni scenario produca dati utili per il rilevamento.<sup>[[1]](#references)</sup>

- **Trace a livello chain**: grafi completi delle chiamate, utilizzo del gas, nonce delle transazioni, timestamp dei blocchi, per ricostruire bundle con flash loan, strutture simili alla reentrancy e hop tra contratti.
- **Log applicativi/API**: collega ogni tx on-chain a un'identità umana o di automazione (session ID, client OAuth, API key, CI job ID), includendo IP e metodi di autenticazione.
- **Log KMS/HSM**: key ID, principal chiamante, risultato della policy, indirizzo di destinazione e reason code per ogni firma. Definisci una baseline delle finestre di modifica e delle operazioni ad alto rischio.
- **Metadati degli oracle/feed**: composizione della sorgente dati per ogni aggiornamento, valore riportato, deviazione dalle medie mobili, soglie attivate e percorsi di failover utilizzati.
- **Trace di bridge/swap**: correla gli eventi di lock/mint/unlock tra le chain con correlation ID, chain ID, identità del relayer e tempistiche degli hop.
- **Indicatori di anomalia**: metriche derivate come picchi di slippage, rapporti di collateralizzazione anomali, densità di gas insolita o velocità cross-chain.

Applica ovunque scenario ID o synthetic user ID, così gli analisti possono allineare gli elementi osservabili alla tecnica AADAPT in fase di test.

## 6. Ciclo purple team e metriche di maturità
1. Esegui lo scenario nell'ambiente controllato e raccogli i rilevamenti (alert, dashboard, responder avvisati).<sup>[[1]](#references)</sup>
2. Associa ogni passaggio alle tecniche AADAPT specifiche e agli elementi osservabili prodotti nei piani chain/app/KMS/oracle/bridge.
3. Formula e implementa ipotesi di rilevamento (regole basate su soglie, ricerche di correlazione, controlli degli invarianti).
4. Ripeti l'esecuzione finché il mean time to detect (MTTD) e il mean time to contain (MTTC) non rispettano le tolleranze del business e i playbook non riescono ad arrestare in modo affidabile la perdita di valore.

Monitora la maturità del programma su tre assi:<sup>[[1]](#references)</sup>
- **Visibilità**: ogni percorso critico del valore dispone di telemetria in ciascun piano.
- **Coverage**: proporzione delle tecniche AADAPT prioritarie testate end-to-end.
- **Response**: capacità di mettere in pausa i contratti, revocare le chiavi o bloccare i flussi prima di una perdita irreversibile.

Traguardi tipici: (1) inventario completo del valore e mappatura AADAPT, (2) primo scenario end-to-end con rilevamenti implementati, (3) cicli purple team trimestrali che ampliano la coverage e riducono MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Template di scenario
Utilizza questi blueprint ripetibili per progettare simulazioni direttamente associabili ai comportamenti AADAPT.<sup>[[1]](#references)</sup>

### Scenario A – Manipolazione economica tramite flash loan
- **Obiettivo**: prendere in prestito capitale temporaneo all'interno di una singola transazione per alterare prezzi/liquidità degli AMM e attivare borrow, liquidation o mint a prezzi errati prima della restituzione.
- **Esecuzione**:
1. Effettua il fork della chain target e popola i pool con liquidità simile a quella di produzione.
2. Prendi in prestito un notional elevato tramite flash loan.
3. Esegui swap calibrati per oltrepassare i confini di prezzo o di soglia utilizzati dalla logica di lending, vault o derivati.
4. Invoca il contratto vittima subito dopo la distorsione (borrow, liquidate, mint) e restituisci il flash loan.
- **Misurazione**: la violazione dell'invariante ha avuto successo? Sono stati attivati i monitor di slippage/deviation del prezzo, i circuit breaker o gli hook di governance pause? Quanto tempo è servito agli analytics per segnalare il pattern anomalo di gas/call graph?

### Scenario B – Poisoning dell'oracle/data feed
- **Obiettivo**: determinare se feed manipolati possono attivare azioni automatizzate distruttive (liquidation di massa, settlement errati).
- **Esecuzione**:
1. Nel fork/testnet, esegui il deployment di un feed malevolo oppure modifica pesi, quorum o cadenza di aggiornamento dell'aggregator oltre la deviazione tollerata.
2. Lascia che i contratti dipendenti consumino i valori avvelenati ed eseguano la loro logica standard.
- **Misurazione**: alert out-of-band a livello feed, attivazione dell'oracle di fallback, applicazione dei limiti min/max e latenza tra l'inizio dell'anomalia e la risposta dell'operatore.

### Scenario C – Abuso di credenziali/signing
- **Obiettivo**: testare se la compromissione di un singolo signer o di un'identità di automazione consente upgrade, modifiche dei parametri o drain del treasury non autorizzati.
- **Esecuzione**:
1. Enumera le identità con diritti di signing sensibili (operatori, token CI, service account che invocano KMS/HSM, partecipanti al multisig).
2. Simula la compromissione (riutilizza le loro credenziali/chiavi entro l'ambito del laboratorio).
3. Tenta azioni privilegiate: esegui l'upgrade dei proxy, modifica i parametri di rischio, esegui il mint o la pause degli asset oppure attiva proposte di governance.
- **Misurazione**: i log KMS/HSM generano alert di anomalia (orario, variazione della destinazione, raffica di operazioni ad alto rischio)? Le policy o le soglie del multisig impediscono l'abuso unilaterale? Sono applicati throttle/rate limit o approvazioni aggiuntive?

### Scenario D – Elusione cross-chain e lacune di tracciabilità
- **Obiettivo**: valutare quanto efficacemente i defender riescano a tracciare e bloccare asset trasferiti rapidamente attraverso bridge, router DEX e hop di privacy.
- **Esecuzione**:
1. Collega operazioni di lock/mint attraverso bridge comuni, intercalando swap/mixer a ogni hop e mantenendo correlation ID per ciascun hop.
2. Accelera i trasferimenti per sottoporre a stress la latenza del monitoring (multi-hop nell'arco di pochi minuti o blocchi).
- **Misurazione**: tempo necessario per correlare gli eventi tra la telemetria e i commercial chain analytics, completezza del percorso ricostruito, capacità di identificare i choke point per il freezing durante un incidente reale e precisione degli alert relativi a velocità/valore cross-chain anomali.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
