# Red teaming Web3 incentrato sul valore (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Il framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categorizza le azioni e le tecniche avversarie rivolte ai sistemi di asset digitali.<sup>[[1]](#references)</sup> Usalo come **struttura portante per il threat modeling**: elenca ogni componente in grado di creare, valutare, autorizzare o instradare asset, associa questi punti di contatto alle tecniche AADAPT e crea scenari di red team per verificare se l’ambiente è in grado di resistere a perdite economiche irreversibili.

## 1. Inventariare i componenti che detengono valore
Mappa tutto ciò che può influenzare lo stato del valore, anche se è off-chain.<sup>[[2]](#references)</sup>

- **Servizi di firma custodial** (cluster HSM/KMS, Vault/KMaaS, API di firma usate da bot o job di back-office). Registra gli ID delle chiavi, le policy, le identità di automazione e i flussi di approvazione.
- **Percorsi di amministrazione e upgrade** dei contratti (admin dei proxy, timelock di governance, chiavi di pausa d’emergenza, registri dei parametri). Includi chi o cosa può invocarli e con quale quorum o ritardo.
- **Logica di protocollo on-chain** che gestisce lending, AMM, vault, staking, bridge o rail di settlement. Documenta gli invarianti presupposti (prezzi degli oracoli, rapporti di collateralizzazione, cadenza dei ribilanciamenti…).
- **Automazione off-chain** che crea transazioni (bot di market making, pipeline CI/CD, cron job, funzioni serverless). Spesso dispone di API key o service principal che possono richiedere firme.
- **Oracoli e feed di dati** (composizione degli aggregatori, quorum, soglie di deviazione, cadenza degli aggiornamenti). Annota ogni fonte upstream utilizzata dalla logica di rischio automatizzata.
- **Bridge e router cross-chain** (contratti lock/mint, relayer, job di settlement) che collegano chain o stack custodial.

Risultato: un diagramma dei flussi di valore che mostri come si spostano gli asset, chi autorizza gli spostamenti e quali segnali esterni influenzano la logica di business.

## 2. Mappare i componenti ai comportamenti AADAPT
Traduci la tassonomia AADAPT in concrete possibilità di attacco per ciascun componente.<sup>[[2]](#references)</sup>

| Componente | Focus AADAPT principale |
| --- | --- |
| Infrastrutture di signing/KMS | Furto di credenziali, bypass delle policy, abuso delle firme, takeover della governance |
| Oracoli/feed | Avvelenamento degli input, manipolazione dell’aggregazione, elusione delle soglie di deviazione |
| Protocolli on-chain | Manipolazione economica con flash loan, violazione degli invarianti, riconfigurazione dei parametri |
| Pipeline di automazione | Compromissione di identità di bot/CI, replay di batch, deployment non autorizzato |
| Bridge/router | Elusione cross-chain, riciclaggio tramite hop rapidi, desincronizzazione del settlement |

Questa mappatura assicura che vengano testati non solo i contratti, ma anche tutte le identità e automazioni in grado di indirizzare indirettamente il valore.

## 3. Stabilire le priorità in base alla fattibilità per l’attaccante e all’impatto sul business

1. **Debolezze operative**: credenziali CI esposte, ruoli IAM con privilegi eccessivi, policy KMS configurate male, account di automazione in grado di richiedere firme arbitrarie, bucket pubblici con configurazioni dei bridge e così via.
2. **Debolezze specifiche del valore**: parametri fragili degli oracoli, contratti aggiornabili senza approvazioni di più parti, liquidità vulnerabile ai flash loan, azioni di governance che aggirano i timelock.

Procedi nella coda come farebbe un avversario: parti dai punti d’appoggio operativi che potrebbero funzionare oggi, poi passa ai percorsi più complessi di manipolazione del protocollo e dell’economia.<sup>[[2]](#references)</sup>

## 4. Eseguire in ambienti controllati e realistici per la produzione
- **Mainnet forkate / testnet isolate**: replica bytecode, storage e liquidità, così che i percorsi con flash loan, le derive degli oracoli e i flussi dei bridge possano essere eseguiti end-to-end senza toccare fondi reali.<sup>[[2]](#references)</sup>
- **Pianificazione del blast radius**: definisci circuit breaker, moduli sospendibili, procedure di rollback e chiavi admin solo per i test prima di innescare uno scenario.
- **Coordinamento degli stakeholder**: avvisa custodian, operatori degli oracoli, partner dei bridge e team compliance, affinché i loro team di monitoraggio si aspettino il traffico.
- **Approvazione legale**: documenta ambito, autorizzazione e condizioni di arresto per le simulazioni che potrebbero coinvolgere rail regolamentati.

## 5. Telemetria allineata alle tecniche AADAPT
Strumenta i flussi di telemetria affinché ogni scenario produca dati utili al rilevamento.<sup>[[2]](#references)</sup>

- **Tracce a livello di chain**: grafi completi delle chiamate, consumo di gas, nonce delle transazioni, timestamp dei blocchi, per ricostruire bundle di flash loan, strutture simili alla reentrancy e hop tra contratti.
- **Log di applicazioni/API**: collega ogni tx on-chain a un’identità umana o di automazione (ID di sessione, client OAuth, API key, ID del job CI), includendo IP e metodi di autenticazione.
- **Log KMS/HSM**: ID della chiave, principal chiamante, esito della policy, indirizzo di destinazione e codici motivazionali per ogni firma. Definisci le finestre di modifica di riferimento e le operazioni ad alto rischio.
- **Metadati di oracoli/feed**: composizione delle fonti di dati per ogni aggiornamento, valore segnalato, deviazione dalle medie mobili, soglie attivate e percorsi di failover usati.
- **Tracce di bridge/swap**: correla gli eventi lock/mint/unlock tra chain con ID di correlazione, ID delle chain, identità del relayer e tempistiche degli hop.
- **Indicatori di anomalia**: metriche derivate, come picchi di slippage, rapporti di collateralizzazione anomali, densità di gas insolita o velocità cross-chain.

Aggiungi a tutto gli ID degli scenari o ID utente sintetici, affinché gli analisti possano associare gli elementi osservabili alla tecnica AADAPT testata.

## 6. Ciclo purple team e metriche di maturità
1. Esegui lo scenario nell’ambiente controllato e raccogli i rilevamenti (alert, dashboard, notifiche ai responder).<sup>[[2]](#references)</sup>
2. Associa ogni passaggio alle tecniche AADAPT specifiche e agli elementi osservabili nei piani chain/app/KMS/oracle/bridge.
3. Formula e implementa ipotesi di rilevamento (regole basate su soglie, ricerche di correlazione, controlli degli invarianti).
4. Ripeti finché il mean time to detect (MTTD) e il mean time to contain (MTTC) rientrano nelle soglie aziendali e i playbook arrestano in modo affidabile la perdita di valore.

Monitora la maturità del programma su tre assi:<sup>[[2]](#references)</sup>
- **Visibilità**: ogni percorso di valore critico dispone di telemetria in ciascun piano.
- **Copertura**: percentuale delle tecniche AADAPT prioritarie testate end-to-end.
- **Risposta**: capacità di sospendere i contratti, revocare le chiavi o bloccare i flussi prima di una perdita irreversibile.

Traguardi tipici: (1) inventario del valore e mappatura AADAPT completati, (2) primo scenario end-to-end con rilevamenti implementati, (3) cicli purple team trimestrali che ampliano la copertura e riducono MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Modelli di scenario
Usa questi schemi ripetibili per progettare simulazioni direttamente riconducibili ai comportamenti AADAPT.<sup>[[2]](#references)</sup>

### Scenario A – Manipolazione economica con flash loan
- **Obiettivo**: prendere in prestito capitale temporaneo all’interno di una singola transazione per alterare prezzi/liquidità di un AMM e attivare prestiti, liquidazioni o mint a prezzi errati prima di rimborsare il prestito.
- **Esecuzione**:
  1. Fai un fork della chain target e inizializza i pool con liquidità simile a quella di produzione.
  2. Prendi in prestito un importo elevato tramite flash loan.
  3. Esegui swap calibrati per superare le soglie di prezzo a cui si affidano la logica di lending, vault o derivati.
  4. Invoca il contratto vittima subito dopo la distorsione (prestito, liquidazione, mint) e rimborsa il flash loan.
- **Misurazione**: La violazione dell’invariante è riuscita? Sono stati attivati i monitor di slippage/deviazione dei prezzi, i circuit breaker o i meccanismi di pausa della governance? Quanto tempo è servito agli strumenti di analytics per rilevare il pattern anomalo nel grafo di gas/chiamate?

### Scenario B – Avvelenamento dell’oracolo/feed di dati
- **Obiettivo**: determinare se feed manipolati possano attivare azioni automatizzate distruttive (liquidazioni di massa, settlement errati).
- **Esecuzione**:
  1. Nel fork/testnet, implementa un feed malevolo oppure modifica pesi, quorum o cadenza degli aggiornamenti dell’aggregatore oltre le deviazioni tollerate.
  2. Lascia che i contratti dipendenti acquisiscano i valori avvelenati ed eseguano la loro logica standard.
- **Misurazione**: Alert fuori banda a livello di feed, attivazione dell’oracolo di fallback, applicazione dei limiti min/max e latenza tra l’inizio dell’anomalia e la risposta dell’operatore.

### Scenario C – Abuso di credenziali/firme
- **Obiettivo**: verificare se la compromissione di un singolo signer o di un’identità di automazione consenta upgrade non autorizzati, modifiche dei parametri o drenaggi della treasury.
- **Esecuzione**:
  1. Elenca le identità con privilegi di firma sensibili (operatori, token CI, service account che invocano KMS/HSM, partecipanti multisig).
  2. Simula la compromissione (riutilizzando le loro credenziali/chiavi entro l’ambito del lab).
  3. Tenta azioni privilegiate: aggiornare i proxy, modificare i parametri di rischio, mintare/sospendere asset o avviare proposte di governance.
- **Misurazione**: I log KMS/HSM generano alert di anomalia (orario, variazione della destinazione, picchi di operazioni ad alto rischio)? Le policy o le soglie multisig possono impedire l’abuso unilaterale? Sono applicati limiti di frequenza o approvazioni aggiuntive?

### Scenario D – Elusione cross-chain e lacune di tracciabilità
- **Obiettivo**: valutare quanto efficacemente i difensori riescano a tracciare e intercettare asset riciclati rapidamente tramite bridge, router DEX e hop di privacy.
- **Esecuzione**:
  1. Combina operazioni lock/mint tra bridge comuni, alterna swap/mixer a ogni hop e mantieni gli ID di correlazione per ciascun hop.
  2. Accelera i trasferimenti per mettere sotto pressione la latenza del monitoraggio (più hop in pochi minuti/blocchi).
- **Misurazione**: Tempo necessario per correlare gli eventi tra telemetria e strumenti commerciali di analisi delle chain, completezza del percorso ricostruito, capacità di identificare i punti di blocco in un incidente reale e precisione degli alert per velocità/valore cross-chain anomali.

## References

- [1] [Framework di cyber threat AADAPT(TM) per gli asset digitali (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Il framework MITRE AADAPT come roadmap per il red team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
