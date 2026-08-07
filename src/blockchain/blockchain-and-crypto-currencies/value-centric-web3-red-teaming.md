# Waarde-gesentreerde Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Die MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT)-matriks leg aanvallergedrag vas wat digitale waarde manipuleer eerder as slegs infrastruktuur. Behandel dit as ’n **grondslag vir threat modeling**: lys elke komponent wat bates kan mint, prys, magtig of roeteer, koppel daardie raakpunte aan AADAPT-tegnieke, en dryf dan red-team-scenario’s wat meet of die omgewing onomkeerbare ekonomiese verlies kan weerstaan.

## 1. Inventariseer waarde-draende komponente
Bou ’n kaart van alles wat die waardetoestand kan beïnvloed, selfs al is dit off-chain.<sup>[[1]](#references)</sup>

- **Custodial signing services** (HSM/KMS-klusters, Vault/KMaaS, signing APIs wat deur bots of back-office-take gebruik word). Leg key IDs, policies, automation-identiteite en approval-workflows vas.
- **Admin- & upgrade-paaie** vir kontrakte (proxy-admins, governance-timelocks, emergency pause keys, parameter-registers). Sluit in wie/wat hulle kan oproep, en onder watter quorum of vertraging.
- **On-chain-protokollogika** wat lending, AMMs, vaults, staking, bridges of settlement rails hanteer. Dokumenteer die invariants waarop hulle staatmaak (oracle-pryse, collateral ratios, rebalance cadence…).
- **Off-chain-automation** wat transaksies bou (market-making-bots, CI/CD-pipelines, cron-jobs, serverless functions). Hulle hou dikwels API-keys of service principals wat signatures kan aanvra.
- **Oracles & data feeds** (aggregator-samestelling, quorum, deviation thresholds, update cadence). Noteer elke upstream waarop geoutomatiseerde risk logic staatmaak.
- **Bridges en cross-chain routers** (lock/mint-kontrakte, relayers, settlement-jobs) wat chains of custodial stacks aan mekaar koppel.

Aflewerbare resultaat: ’n waarde-vloeidiagram wat wys hoe bates beweeg, wie beweging magtig, en watter eksterne seine business logic beïnvloed.

## 2. Koppel komponente aan AADAPT-gedrag
Vertaal die AADAPT-taksonomie na konkrete attack candidates per komponent.<sup>[[1]](#references)</sup>

| Komponent | Primêre AADAPT-fokus |
| --- | --- |
| Signing/KMS-estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain-protokolle | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation-pipelines | Compromised bot/CI-identiteite, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Hierdie kartering verseker dat jy nie net die kontrakte toets nie, maar elke identity/automation wat waarde indirek kan stuur.

## 3. Prioritiseer volgens aanvallerhaalbaarheid teenoor besigheidsimpak

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts wat arbitrêre signatures kan aanvra, public buckets met bridge-configs, ens.
2. **Value-specific weaknesses**: fragile oracle parameters, upgradable contracts sonder multi-party approvals, flash-loan-sensitive liquidity, governance actions wat timelocks omseil.

Werk die queue soos ’n aanvaller: begin met die operational footholds wat vandag suksesvol kan wees, en vorder dan na diep protocol/economic manipulation-paaie.<sup>[[1]](#references)</sup>

## 4. Voer uit in beheerde, produksie-realistiese omgewings
- **Forked mainnets / geïsoleerde testnets**: repliseer bytecode, storage en liquidity sodat flash-loan-paaie, oracle-drifts en bridge-flows end-to-end kan loop sonder om werklike fondse aan te raak.<sup>[[1]](#references)</sup>
- **Blast-radius-beplanning**: definieer circuit breakers, pausable modules, rollback-runbooks en test-only admin keys voordat ’n scenario laat ontplof word.
- **Stakeholder-koördinering**: stel custodians, oracle-operators, bridge-partners en compliance in kennis sodat hulle monitoring-spanne die verkeer verwag.
- **Legal sign-off**: dokumenteer scope, authorization en stop conditions wanneer simulasies gereguleerde rails kan kruis.

## 5. Telemetry wat met AADAPT-tegnieke belyn is
Instrumenteer telemetry-strome sodat elke scenario bruikbare detection data produseer.<sup>[[1]](#references)</sup>

- **Chain-level traces**: volledige call graphs, gas usage, transaction nonces, block timestamps—om flash-loan-bundles, reentrancy-like structures en cross-contract hops te rekonstrueer.
- **Application/API logs**: koppel elke on-chain tx terug aan ’n mens- of automation-identity (session ID, OAuth client, API key, CI job ID) met IPs en auth methods.
- **KMS/HSM-logs**: key ID, caller principal, policy result, destination address en reason codes vir elke signature. Stel ’n baseline vir change windows en high-risk operations.
- **Oracle/feed-metadata**: per-update data-source composition, reported value, deviation van rolling averages, thresholds wat geaktiveer is, en failover-paaie wat gebruik is.
- **Bridge/swap-traces**: korreleer lock/mint/unlock-events oor chains heen met correlation IDs, chain IDs, relayer identity en hop timing.
- **Anomaly markers**: afgeleide metrics soos slippage spikes, abnormale collateralization ratios, ongewone gas density, of cross-chain velocity.

Tag alles met scenario IDs of synthetic user IDs sodat analysts observables kan belyn met die AADAPT-tegniek wat getoets word.

## 6. Purple-team-loop & maturity metrics
1. Voer die scenario in die beheerde omgewing uit en neem detections vas (alerts, dashboards, responders wat gepage word).<sup>[[1]](#references)</sup>
2. Koppel elke stap aan die spesifieke AADAPT-tegnieke plus die observables wat in die chain/app/KMS/oracle/bridge-planes geproduseer word.
3. Formuleer en implementeer detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Herhaal totdat mean time to detect (MTTD) en mean time to contain (MTTC) aan besigheidstoleransies voldoen en playbooks die waardeverlies betroubaar stop.

Volg program maturity op drie asse:<sup>[[1]](#references)</sup>
- **Visibility**: elke kritieke waardepad het telemetry in elke plane.
- **Coverage**: proporsie van geprioritiseerde AADAPT-tegnieke wat end-to-end getoets is.
- **Response**: vermoë om contracts te pause, keys te revoke, of flows te freeze voordat onomkeerbare verlies plaasvind.

Tipiese milestones: (1) voltooide waarde-inventory + AADAPT-kartering, (2) eerste end-to-end-scenario met geïmplementeerde detections, (3) kwartaallikse purple-team-siklusse wat coverage uitbrei en MTTD/MTTC verlaag.<sup>[[1]](#references)</sup>

## 7. Scenario templates
Gebruik hierdie herhaalbare blueprints om simulasies te ontwerp wat direk met AADAPT-gedrag gekarteer word.<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Doelwit**: leen transient capital binne een transaksie om AMM-pryse/liquidity te verdraai en misgeprysde borrows, liquidations of mints te aktiveer voordat die lening terugbetaal word.
- **Uitvoering**:
1. Fork die target chain en seed pools met produksie-gelyke liquidity.
2. Leen ’n groot notional via flash loan.
3. Voer gekalibreerde swaps uit om prys-/threshold-grense te kruis waarop lending-, vault- of derivative-logic staatmaak.
4. Roep die victim contract onmiddellik ná die distortion aan (borrow, liquidate, mint) en betaal die flash loan terug.
- **Meting**: Het die invariant violation geslaag? Is slippage/price-deviation-monitors, circuit breakers of governance pause hooks geaktiveer? Hoe lank het dit geneem voordat analytics die abnormale gas/call-graph-pattern gemerk het?

### Scenario B – Oracle/data-feed poisoning
- **Doelwit**: bepaal of manipulated feeds destruktiewe geoutomatiseerde aksies kan aktiveer (mass liquidations, incorrect settlements).
- **Uitvoering**:
1. Deploy in die fork/testnet ’n malicious feed of pas aggregator weights/quorum/update cadence aan tot buite die tolerated deviation.
2. Laat afhanklike contracts die poisoned values verbruik en hul standard logic uitvoer.
- **Meting**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, en latency tussen anomaly onset en operator response.

### Scenario C – Credential/signing abuse
- **Doelwit**: toets of die kompromittering van ’n enkele signer of automation identity unauthorized upgrades, parameter changes of treasury drains moontlik maak.
- **Uitvoering**:
1. Enumerate identities met sensitiewe signing rights (operators, CI tokens, service accounts wat KMS/HSM oproep, multisig participants).
2. Simuleer compromise (hergebruik hul credentials/keys binne die lab-scope).
3. Probeer privileged actions: upgrade proxies, change risk parameters, mint/pause assets, of trigger governance proposals.
- **Meting**: Genereer KMS/HSM-logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Kan policies of multisig thresholds unilateral abuse voorkom? Word throttles/rate limits of additional approvals afgedwing?

### Scenario D – Cross-chain evasion & traceability gaps
- **Doelwit**: evalueer hoe goed defenders assets kan traceer en interdict wat vinnig deur bridges, DEX-routers en privacy hops gelaunder word.
- **Uitvoering**:
1. Chain lock/mint-operations oor algemene bridges aan mekaar, voeg swaps/mixers op elke hop tussenin, en handhaaf per-hop correlation IDs.
2. Versnel transfers om monitoring latency te strest (multi-hop binne minute/blocks).
- **Meting**: Tyd om events oor telemetry + commercial chain analytics te korreleer, volledigheid van die gerekonstrueerde path, vermoë om choke points vir freezing in ’n werklike incident te identifiseer, en alert fidelity vir abnormale cross-chain velocity/value.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
