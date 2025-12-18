# Red Teaming Web3 incentrato sul valore (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

La matrice MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) cattura i comportamenti degli attacker che manipolano il valore digitale piuttosto che solo l’infrastruttura. Considerala come una **spina dorsale per il threat-modeling**: enumera ogni componente che può mintare, priceggiare, autorizzare o instradare asset, mappa quei touchpoint alle tecniche AADAPT e poi progetta scenari di red-team che misurino se l’ambiente può resistere a perdite economiche irreversibili.

## 1. Inventario dei componenti che detengono valore
Costruisci una mappa di tutto ciò che può influenzare lo stato del valore, anche se è off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Cattura key ID, policy, identità di automazione e workflow di approvazione.
- **Admin & upgrade paths** per contract (proxy admins, governance timelocks, emergency pause keys, parameter registries). Includi chi/cosa può chiamarli e con quale quorum o delay.
- **On-chain protocol logic** che gestisce lending, AMMs, vaults, staking, bridges o settlement rails. Documenta le invarianti che assumono (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** che costruisce transazioni (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Questi spesso contengono API keys o service principals che possono richiedere signature.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Nota ogni upstream su cui fanno affidamento le logiche di rischio automatizzate.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) che collegano chain o stack custodiali.

Deliverable: un diagramma del flusso del valore che mostri come gli asset si muovono, chi autorizza il movimento e quali segnali esterni influenzano la business logic.

## 2. Mappa dei componenti ai comportamenti AADAPT
Traduci la tassonomia AADAPT in candidati di attacco concreti per componente.

| Componente | Focus AADAPT principale |
| --- | --- |
| Signing/KMS estates | furto di credenziali, bypass delle policy, signing-abuse, presa di controllo della governance |
| Oracles/feeds | avvelenamento degli input, manipolazione dell’aggregazione, evasione delle soglie di deviazione |
| On-chain protocols | Flash-loan economic manipulation, rottura degli invarianti, riconfigurazione dei parametri |
| Automation pipelines | identità bot/CI compromesse, batch replay, deploy non autorizzato |
| Bridges/routers | evasione cross-chain, riciclaggio rapido su più hop, desincronizzazione dei settlement |

Questa mappatura assicura che tu testi non solo i contract, ma ogni identità/automazione che può indirettamente indirizzare valore.

## 3. Prioritizza in base alla fattibilità dell’attacker vs. impatto sul business

1. **Debolezze operative**: credenziali CI esposte, ruoli IAM eccessivamente privilegiati, policy KMS mal configurate, account di automazione che possono richiedere signature arbitrarie, bucket pubblici con config di bridge, ecc.
2. **Debolezze specifiche del valore**: parametri oracle fragili, contract upgradabili senza approvazioni multi-party, liquidità sensibile a flash-loan, azioni di governance che bypassano timelock.

Lavora la coda come un avversario: inizia dalle foothold operative che potrebbero riuscire oggi, poi procedi verso percorsi profondi di manipolazione del protocollo/economici.

## 4. Esegui in ambienti controllati e realistici per la produzione
- **Forked mainnets / isolated testnets**: replica bytecode, storage e liquidity in modo che flash-loan path, deriva degli oracle e flow dei bridge girino end-to-end senza toccare fondi reali.
- **Blast-radius planning**: definisci circuit breakers, moduli pausable, runbook di rollback e admin key per test prima di detonare uno scenario.
- **Stakeholder coordination**: avvisa custodians, oracle operators, bridge partners e compliance così i loro team di monitoring si aspettano il traffico.
- **Legal sign-off**: documenta scope, autorizzazione e condizioni di stop quando le simulazioni potrebbero attraversare rail regolamentati.

## 5. Telemetria allineata alle tecniche AADAPT
Instrumenta i flussi di telemetria in modo che ogni scenario produca dati di detection utilizzabili.

- **Chain-level traces**: full call graphs, utilizzo gas, nonces delle transazioni, timestamps dei blocchi — per ricostruire flash-loan bundle, strutture simili a reentrancy e hop cross-contract.
- **Application/API logs**: collega ogni tx on-chain a un’identità umana o di automazione (session ID, OAuth client, API key, CI job ID) con IP e metodi di auth.
- **KMS/HSM logs**: key ID, caller principal, risultato della policy, destination address e reason codes per ogni signature. Baseline delle finestre di cambiamento e operazioni ad alto rischio.
- **Oracle/feed metadata**: per-update composizione delle sorgenti dati, valore riportato, deviazione dalle medie mobili, soglie attivate e percorsi di failover esercitati.
- **Bridge/swap traces**: correlare lock/mint/unlock eventi across chain con correlation ID, chain ID, relayer identity e timing dei hop.
- **Anomaly markers**: metriche derivate come spike di slippage, rapporti di collateralizzazione anomali, insolita densità di gas o cross-chain velocity anomala.

Tagga tutto con scenario ID o synthetic user ID così gli analisti possono allineare gli osservabili alla tecnica AADAPT esercitata.

## 6. Purple-team loop e metriche di maturità
1. Esegui lo scenario nell’ambiente controllato e cattura le detection (alert, dashboard, responder pagati).
2. Mappa ogni step alle specifiche tecniche AADAPT più gli osservabili prodotti nei piani chain/app/KMS/oracle/bridge.
3. Formula e deploya ipotesi di detection (regole di soglia, ricerche di correlazione, check di invariant).
4. Rilancia fino a quando mean time to detect (MTTD) e mean time to contain (MTTC) incontrano le tolleranze di business e i playbook fermano in modo affidabile la perdita di valore.

Traccia la maturità del programma su tre assi:
- **Visibility**: ogni percorso critico del valore ha telemetria in ciascun piano.
- **Coverage**: proporzione delle tecniche AADAPT prioritarie esercitate end-to-end.
- **Response**: capacità di mettere in pausa contract, revocare key o bloccare flow prima di una perdita irreversibile.

Milestone tipiche: (1) inventario del valore completato + mappatura AADAPT, (2) primo scenario end-to-end con detection implementate, (3) cicli purple-team trimestrali che espandono la coverage e riducono MTTD/MTTC.

## 7. Template di scenario
Usa questi blueprint ripetibili per progettare simulazioni che mappano direttamente ai comportamenti AADAPT.

### Scenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction to distort AMM prices/liquidity and trigger mispriced borrows, liquidations, or mints before repaying.
- **Execution**:
1. Fork the target chain and seed pools with production-like liquidity.
2. Borrow large notional via flash loan.
3. Perform calibrated swaps to cross price/threshold boundaries relied on by lending, vault, or derivative logic.
4. Invoke the victim contract immediately after the distortion (borrow, liquidate, mint) and repay the flash loan.
- **Measurement**: Did the invariant violation succeed? Were slippage/price-deviation monitors, circuit breakers, or governance pause hooks triggered? How long until analytics flagged the abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: determine whether manipulated feeds can trigger destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. In the fork/testnet, deploy a malicious feed or adjust aggregator weights/quorum/update cadence beyond tolerated deviation.
2. Let dependent contracts consume the poisoned values and execute their standard logic.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, and latency between anomaly onset and operator response.

### Scenario C – Credential/signing abuse
- **Objective**: test whether compromising a single signer or automation identity enables unauthorized upgrades, parameter changes, or treasury drains.
- **Execution**:
1. Enumerate identities with sensitive signing rights (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants).
2. Simulate compromise (re-use their credentials/keys within the lab scope).
3. Attempt privileged actions: upgrade proxies, change risk parameters, mint/pause assets, or trigger governance proposals.
- **Measurement**: Do KMS/HSM logs raise anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Can policies or multisig thresholds prevent unilateral abuse? Are throttles/rate limits or additional approvals enforced?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: evaluate how well defenders can trace and interdict assets rapidly laundered across bridges, DEX routers, and privacy hops.
- **Execution**:
1. Chain together lock/mint operations across common bridges, interleave swaps/mixers on each hop, and maintain per-hop correlation IDs.
2. Accelerate transfers to stress monitoring latency (multi-hop within minutes/blocks).
- **Measurement**: Time to correlate events across telemetry + commercial chain analytics, completeness of the reconstructed path, ability to identify choke points for freezing in a real incident, and alert fidelity for abnormal cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
