# Waarde-gesentreerde Web3 Red Teaming (MITRE AADAPT)

Die MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT)-raamwerk kategoriseer adversarial actions en techniques wat digitale-batestelsels teiken.<sup>[[1]](#references)</sup> Behandel dit as ’n **ruggraat vir threat modeling**: lys elke komponent wat bates kan mint, prys, magtig of roeteer, karteer daardie raakpunte na AADAPT-techniques, en dryf dan red-team-scenario’s wat meet of die omgewing onomkeerbare ekonomiese verlies kan weerstaan.

## 1. Inventariseer waarde-draende komponente
Bou ’n kaart van alles wat die waardetoestand kan beïnvloed, selfs al is dit off-chain.<sup>[[2]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs wat deur bots of back-office jobs gebruik word). Leg key IDs, policies, automation identities en approval workflows vas.
- **Admin- en upgrade-paaie** vir contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Sluit in wie/wat dit kan aanroep, en onder watter quorum of delay.
- **On-chain protocol logic** wat lending, AMMs, vaults, staking, bridges of settlement rails hanteer. Dokumenteer die invariants wat hulle aanvaar (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** wat transactions bou (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Hulle hou dikwels API keys of service principals wat signatures kan versoek.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Let op elke upstream waarvan geoutomatiseerde risk logic afhanklik is.
- **Bridges en cross-chain routers** (lock/mint contracts, relayers, settlement jobs) wat chains of custodial stacks verbind.

Aflewerbare resultaat: ’n value-flow diagram wat wys hoe bates beweeg, wie beweging magtig, en watter eksterne seine business logic beïnvloed.

## 2. Karteer komponente na AADAPT-gedrag
Vertaal die AADAPT-taxonomy na konkrete attack candidates per komponent.<sup>[[2]](#references)</sup>

| Komponent | Primêre AADAPT-fokus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Hierdie kartering verseker dat jy nie net die contracts toets nie, maar ook elke identity/automation wat waarde indirek kan stuur.

## 3. Prioritiseer volgens attacker feasibility teenoor business impact

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts wat arbitrary signatures kan versoek, public buckets met bridge configs, ens.
2. **Value-specific weaknesses**: fragile oracle parameters, upgradable contracts sonder multi-party approvals, flash-loan-sensitive liquidity, governance actions wat timelocks omseil.

Werk deur die queue soos ’n adversary: begin met die operational footholds wat vandag kan slaag, en vorder dan na diep protocol/economic manipulation paths.<sup>[[2]](#references)</sup>

## 4. Voer uit in beheerde, production-realistic omgewings
- **Forked mainnets / isolated testnets**: repliseer bytecode, storage en liquidity sodat flash-loan paths, oracle drifts en bridge flows end-to-end kan loop sonder om regte fondse aan te raak.<sup>[[2]](#references)</sup>
- **Blast-radius planning**: definieer circuit breakers, pausable modules, rollback runbooks en test-only admin keys voordat ’n scenario geaktiveer word.
- **Stakeholder coordination**: stel custodians, oracle operators, bridge partners en compliance in kennis sodat hul monitoring teams die traffic verwag.
- **Legal sign-off**: dokumenteer scope, authorization en stop conditions wanneer simulations gereguleerde rails kan kruis.

## 5. Telemetry belyn met AADAPT-techniques
Instrumenteer telemetry streams sodat elke scenario actionable detection data lewer.<sup>[[2]](#references)</sup>

- **Chain-level traces**: volledige call graphs, gas usage, transaction nonces en block timestamps—om flash-loan bundles, reentrancy-like structures en cross-contract hops te rekonstrueer.
- **Application/API logs**: koppel elke on-chain tx terug aan ’n human- of automation-identity (session ID, OAuth client, API key, CI job ID) met IPs en auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address en reason codes vir elke signature. Stel ’n baseline vir change windows en high-risk operations.
- **Oracle/feed metadata**: per-update data source composition, reported value, deviation van rolling averages, thresholds wat geaktiveer is, en failover paths wat gebruik is.
- **Bridge/swap traces**: korreleer lock/mint/unlock-events oor chains met correlation IDs, chain IDs, relayer identity en hop timing.
- **Anomaly markers**: afgeleide metrics soos slippage spikes, abnormal collateralization ratios, unusual gas density of cross-chain velocity.

Tag alles met scenario IDs of synthetic user IDs sodat analysts observables kan belyn met die AADAPT-technique wat getoets word.

## 6. Purple-team-loop & maturity metrics
1. Voer die scenario in die beheerde omgewing uit en vang detections vas (alerts, dashboards, responders wat gepage word).<sup>[[2]](#references)</sup>
2. Karteer elke stap na die spesifieke AADAPT-techniques plus die observables wat in die chain/app/KMS/oracle/bridge planes geproduseer word.
3. Formuleer en deploy detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Herhaal totdat mean time to detect (MTTD) en mean time to contain (MTTC) binne business tolerances val en playbooks die waardeverlies betroubaar stop.

Volg program maturity op drie asse:<sup>[[2]](#references)</sup>
- **Visibility**: elke kritieke value path het telemetry in elke plane.
- **Coverage**: proporsie van geprioritiseerde AADAPT-techniques wat end-to-end getoets is.
- **Response**: vermoë om contracts te pause, keys te revoke of flows te freeze voordat onomkeerbare verlies plaasvind.

Tipiese milestones: (1) voltooide value inventory + AADAPT mapping, (2) eerste end-to-end-scenario met detections geïmplementeer, (3) kwartaallikse purple-team-cycles wat coverage uitbrei en MTTD/MTTC verlaag.<sup>[[2]](#references)</sup>

## 7. Scenario templates
Gebruik hierdie herhaalbare blueprints om simulations te ontwerp wat direk met AADAPT-gedrag karteer.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: leen transient capital binne een transaction om AMM-prices/liquidity te verdraai en misprysde borrows, liquidations of mints te trigger voordat dit terugbetaal word.
- **Execution**:
1. Fork die target chain en seed pools met production-like liquidity.
2. Leen groot notional via flash loan.
3. Voer calibrated swaps uit om price/threshold boundaries te kruis waarop lending-, vault- of derivative-logic staatmaak.
4. Invoke die victim contract onmiddellik ná die distortion (borrow, liquidate, mint) en repay die flash loan.
- **Measurement**: Het die invariant violation geslaag? Is slippage/price-deviation monitors, circuit breakers of governance pause hooks getrigger? Hoe lank totdat analytics die abnormale gas/call-graph-patroon gemerk het?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: bepaal of manipulated feeds destructive automated actions kan trigger (mass liquidations, incorrect settlements).
- **Execution**:
1. Deploy in die fork/testnet ’n malicious feed, of pas aggregator weights/quorum/update cadence aan tot buite die tolerated deviation.
2. Laat afhanklike contracts die poisoned values consume en hul standard logic uitvoer.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, en latency tussen anomaly onset en operator response.

### Scenario C – Credential/signing abuse
- **Objective**: toets of die compromise van ’n enkele signer of automation identity unauthorized upgrades, parameter changes of treasury drains moontlik maak.
- **Execution**:
1. Enumerate identities met sensitive signing rights (operators, CI tokens, service accounts wat KMS/HSM invoke, multisig participants).
2. Simuleer compromise (hergebruik hul credentials/keys binne die lab scope).
3. Attempt privileged actions: upgrade proxies, change risk parameters, mint/pause assets of trigger governance proposals.
- **Measurement**: Genereer KMS/HSM logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Kan policies of multisig thresholds unilateral abuse voorkom? Word throttles/rate limits of additional approvals afgedwing?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: evalueer hoe goed defenders bates kan trace en vinnig kan interdict wat deur bridges, DEX routers en privacy hops gelaunder word.
- **Execution**:
1. Chain lock/mint-operations oor algemene bridges aanmekaar, interleave swaps/mixers op elke hop, en behou per-hop correlation IDs.
2. Versnel transfers om monitoring latency te stres (multi-hop binne minute/blocks).
- **Measurement**: Tyd om events oor telemetry + commercial chain analytics te korreleer, volledigheid van die gerekonstueerde path, vermoë om choke points vir freezing in ’n werklike incident te identifiseer, en alert fidelity vir abnormal cross-chain velocity/value.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
