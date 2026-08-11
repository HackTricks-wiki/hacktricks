# Red Teaming Web3 incentrato sul valore (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Il framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categorizza azioni e tecniche avversarie rivolte ai sistemi di asset digitali.<sup>[[1]](#references)</sup> Consideralo una **base per il threat modeling**: enumera ogni componente in grado di creare, valutare, autorizzare o instradare asset, associa questi punti di contatto alle tecniche AADAPT e poi definisci scenari di red team per misurare se l'ambiente è in grado di resistere a perdite economiche irreversibili.

## 1. Inventariare i componenti che gestiscono valore
Crea una mappa di tutto ciò che può influenzare lo stato del valore, anche se off-chain.<sup>[[2]](#references)</sup>

- **Servizi di firma custodial** (cluster HSM/KMS, Vault/KMaaS, API di firma usate da bot o processi di back-office). Registra key ID, policy, identità di automazione e workflow di approvazione.
- **Percorsi di amministrazione e upgrade** dei contratti (proxy admin, timelock di governance, chiavi per la pausa di emergenza, registri dei parametri). Includi chi/cosa può chiamarli e in base a quale quorum o ritardo.
- **Logica dei protocolli on-chain** che gestisce lending, AMM, vault, staking, bridge o infrastrutture di settlement. Documenta gli invarianti presupposti (prezzi degli oracle, rapporti di collateralizzazione, frequenza del rebalance…).
- **Automazione off-chain** che costruisce transazioni (bot di market-making, pipeline CI/CD, cron job, funzioni serverless). Spesso contengono API key o service principal in grado di richiedere firme.
- **Oracle e data feed** (composizione dell'aggregator, quorum, soglie di deviazione, frequenza degli aggiornamenti). Annota ogni upstream utilizzato dalla logica automatizzata di gestione del rischio.
- **Bridge e router cross-chain** (contratti lock/mint, relayer, processi di settlement) che collegano chain o stack custodial.

Deliverable: un diagramma dei flussi di valore che mostri come si muovono gli asset, chi autorizza i movimenti e quali segnali esterni influenzano la logica di business.

## 2. Mappare i componenti ai comportamenti AADAPT
Traduce la tassonomia AADAPT in candidati concreti per gli attacchi, per ogni componente.<sup>[[2]](#references)</sup>

| Componente | Focus AADAPT principale |
| --- | --- |
| Ecosistemi di signing/KMS | Furto di credenziali, policy bypass, signing-abuse, takeover della governance |
| Oracle/feed | Input poisoning, manipolazione dell'aggregazione, elusione delle soglie di deviazione |
| Protocolli on-chain | Manipolazione economica tramite flash-loan, violazione degli invarianti, riconfigurazione dei parametri |
| Pipeline di automazione | Identità bot/CI compromesse, replay di batch, deployment non autorizzato |
| Bridge/router | Elusione cross-chain, laundering tramite hop rapidi, desincronizzazione del settlement |

Questa mappatura garantisce che vengano testati non solo i contratti, ma anche ogni identità/automazione in grado di indirizzare indirettamente il valore.

## 3. Stabilire le priorità in base alla fattibilità per l'attaccante e all'impatto sul business

1. **Debolezze operative**: credenziali CI esposte, ruoli IAM con privilegi eccessivi, policy KMS configurate in modo errato, account di automazione in grado di richiedere firme arbitrarie, bucket pubblici con configurazioni dei bridge, ecc.
2. **Debolezze specifiche del valore**: parametri fragili degli oracle, contratti upgradable senza approvazioni multi-party, liquidità sensibile ai flash-loan, azioni di governance che bypassano i timelock.

Gestisci la coda come farebbe un avversario: inizia dai foothold operativi che potrebbero avere successo oggi, quindi passa ai percorsi complessi di manipolazione dei protocolli e dell'economia.<sup>[[2]](#references)</sup>

## 4. Eseguire i test in ambienti controllati e realistici rispetto alla produzione
- **Mainnet forked / testnet isolate**: replica bytecode, storage e liquidità affinché i percorsi basati su flash-loan, le derive degli oracle e i flussi dei bridge possano essere eseguiti end-to-end senza toccare fondi reali.<sup>[[2]](#references)</sup>
- **Pianificazione del blast radius**: definisci circuit breaker, moduli pausable, runbook di rollback e chiavi admin esclusivamente per i test prima di detonare uno scenario.
- **Coordinamento degli stakeholder**: informa custodian, operatori degli oracle, partner dei bridge e compliance, affinché i loro team di monitoring si aspettino il traffico.
- **Approvazione legale**: documenta scope, autorizzazione e condizioni di arresto quando le simulazioni potrebbero attraversare infrastrutture regolamentate.

## 5. Telemetria allineata alle tecniche AADAPT
Strumenta i flussi di telemetria affinché ogni scenario produca dati utili per il rilevamento.<sup>[[2]](#references)</sup>

- **Tracce a livello di chain**: grafi completi delle chiamate, consumo di gas, nonce delle transazioni, timestamp dei blocchi, per ricostruire bundle di flash-loan, strutture simili alla reentrancy e hop tra contratti.
- **Log applicativi/API**: associa ogni tx on-chain a un'identità umana o di automazione (session ID, client OAuth, API key, ID del job CI), includendo IP e metodi di autenticazione.
- **Log KMS/HSM**: key ID, principal chiamante, risultato della policy, indirizzo di destinazione e codici motivazione per ogni firma. Crea una baseline delle finestre di modifica e delle operazioni ad alto rischio.
- **Metadati degli oracle/feed**: composizione della fonte dati per ogni aggiornamento, valore riportato, deviazione dalle medie mobili, soglie attivate e percorsi di failover utilizzati.
- **Tracce di bridge/swap**: correla gli eventi lock/mint/unlock tra le chain con correlation ID, chain ID, identità del relayer e tempistiche degli hop.
- **Indicatori di anomalia**: metriche derivate come picchi di slippage, rapporti di collateralizzazione anomali, densità di gas insolita o velocità cross-chain.

Applica ovunque scenario ID o synthetic user ID, affinché gli analisti possano allineare gli indicatori osservabili alla tecnica AADAPT testata.

## 6. Ciclo purple-team e metriche di maturità
1. Esegui lo scenario nell'ambiente controllato e raccogli i rilevamenti (alert, dashboard, responder contattati).<sup>[[2]](#references)</sup>
2. Associa ogni passaggio alle tecniche AADAPT specifiche e agli indicatori osservabili prodotti nei piani chain/app/KMS/oracle/bridge.
3. Formula e implementa ipotesi di rilevamento (regole basate su soglie, ricerche di correlazione, verifiche degli invarianti).
4. Ripeti il test finché il mean time to detect (MTTD) e il mean time to contain (MTTC) non rientrano nelle tolleranze del business e i playbook non interrompono in modo affidabile la perdita di valore.

Monitora la maturità del programma su tre assi:<sup>[[2]](#references)</sup>
- **Visibilità**: ogni percorso critico del valore dispone di telemetria in ciascun piano.
- **Copertura**: proporzione delle tecniche AADAPT prioritarie testate end-to-end.
- **Risposta**: capacità di mettere in pausa i contratti, revocare le chiavi o bloccare i flussi prima di una perdita irreversibile.

Milestone tipiche: (1) inventario completo del valore + mappatura AADAPT, (2) primo scenario end-to-end con rilevamenti implementati, (3) cicli purple-team trimestrali che ampliano la copertura e riducono MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Template per gli scenari
Usa questi blueprint ripetibili per progettare simulazioni direttamente mappate ai comportamenti AADAPT.<sup>[[2]](#references)</sup>

### Scenario A – Manipolazione economica tramite flash-loan
- **Obiettivo**: prendere in prestito capitale temporaneo all'interno di una singola transazione per distorcere prezzi/liquidità degli AMM e attivare borrow, liquidazioni o mint a prezzo errato prima del rimborso.
- **Esecuzione**:
1. Esegui il fork della chain target e alimenta i pool con liquidità simile a quella di produzione.
2. Prendi in prestito un notional elevato tramite flash loan.
3. Esegui swap calibrati per superare i confini di prezzo/soglia utilizzati dalla logica di lending, vault o derivati.
4. Invoca il contratto vittima immediatamente dopo la distorsione (borrow, liquidate, mint) e rimborsa il flash loan.
- **Misurazione**: La violazione dell'invariante è riuscita? Sono stati attivati i monitor di slippage/deviazione del prezzo, i circuit breaker o gli hook di pausa della governance? Quanto tempo è servito prima che gli analytics segnalassero il pattern anomalo di gas/grafo delle chiamate?

### Scenario B – Poisoning di oracle/data feed
- **Obiettivo**: determinare se feed manipolati possano attivare azioni automatizzate distruttive (liquidazioni di massa, settlement errati).
- **Esecuzione**:
1. Nel fork/testnet, esegui il deployment di un feed malevolo oppure modifica i pesi dell'aggregator, il quorum o la frequenza degli aggiornamenti oltre la deviazione tollerata.
2. Lascia che i contratti dipendenti consumino i valori avvelenati ed eseguano la loro logica standard.
- **Misurazione**: Alert out-of-band a livello di feed, attivazione dell'oracle di fallback, applicazione dei limiti min/max e latenza tra l'inizio dell'anomalia e la risposta dell'operatore.

### Scenario C – Abuso di credenziali/firme
- **Obiettivo**: verificare se la compromissione di un singolo signer o di un'identità di automazione consenta upgrade non autorizzati, modifiche dei parametri o drain del treasury.
- **Esecuzione**:
1. Enumera le identità con diritti di signing sensibili (operatori, token CI, service account che invocano KMS/HSM, partecipanti multisig).
2. Simula la compromissione (riutilizza le loro credenziali/chiavi entro lo scope del laboratorio).
3. Tenta azioni privilegiate: esegui l'upgrade dei proxy, modifica i parametri di rischio, esegui il mint/pausa degli asset o attiva proposte di governance.
- **Misurazione**: I log KMS/HSM generano alert di anomalia (orario, variazione della destinazione, raffica di operazioni ad alto rischio)? Le policy o le soglie multisig impediscono l'abuso unilaterale? Sono applicati throttle/rate limit o approvazioni aggiuntive?

### Scenario D – Elusione cross-chain e lacune di tracciabilità
- **Obiettivo**: valutare quanto efficacemente i defender riescano a tracciare e bloccare asset rapidamente riciclati attraverso bridge, router DEX e hop di privacy.
- **Esecuzione**:
1. Collega operazioni lock/mint attraverso bridge comuni, alterna swap/mixer a ogni hop e mantieni correlation ID per ciascun hop.
2. Accelera i trasferimenti per mettere sotto pressione la latenza del monitoring (multi-hop in pochi minuti/blocchi).
- **Misurazione**: Tempo necessario per correlare gli eventi tra la telemetria e gli analytics commerciali delle chain, completezza del percorso ricostruito, capacità di identificare choke point per il freeze durante un incidente reale e fedeltà degli alert relativi a velocità/valore cross-chain anomali.

## References

- [1] [Framework di cyber threat AADAPT(TM) per gli asset digitali (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Il framework MITRE AADAPT come roadmap per il Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
