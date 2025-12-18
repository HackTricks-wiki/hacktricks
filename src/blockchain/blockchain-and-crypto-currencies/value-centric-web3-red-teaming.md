# Waarde-gesentreerde Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Die MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix vang aanvallersgedrag vas wat digitale waarde manipuleer eerder as net infrastruktuur. Behandel dit as 'n bedreigingsmodellering-ruggraat: lys elke komponent wat assets kan mint, prys, magtig, of roeteer, koppel daardie raakpunte aan AADAPT-tegnieke, en ontwikkel dan red-team scenario's wat meet of die omgewing irreversible ekonomiese verlies kan weerstaan.

## 1. Inventariseer waarde-draende komponente
Bou 'n kaart van alles wat die waardetoestand kan beïnvloed, selfs al is dit off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Vang sleutel-ID's, beleid, automatiseringsidentiteite, en goedkeuringswerkvloei op.
- **Admin & upgrade paths** vir kontrakte (proxy admins, governance timelocks, emergency pause keys, parameter registries). Sluit in wie/wat dit kan aanroep, en onder watter quorum of vertraging.
- **On-chain protocol logic** wat lending, AMMs, vaults, staking, bridges, of settlement rails hanteer. Dokumenteer die invariants wat hulle aanvaar (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** wat transaksies bou (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Hierdie hou dikwels API sleutels of service principals wat signatures kan versoek.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Let op elke upstream waarop geoutomatiseerde risikologika staatmaak.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) wat kettings of custodial stacks aan mekaar koppel.

Aflewering: 'n waarde-vloeidiagram wat wys hoe assets beweeg, wie beweging magtig, en watter eksterne seine besigheidslogika beïnvloed.

## 2. Kaart komponente na AADAPT-gedraginge
Vertaal die AADAPT-taksonomie in konkrete aanvalskandidate per komponent.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Hierdie kaart verseker dat jy nie net die kontrakte toets nie, maar ook elke identiteit/automatisering wat indirek waarde kan stuur.

## 3. Prioritiseer volgens aanvallerfeasibility vs. sake-impak

1. **Operational weaknesses**: blootgestelde CI credentials, oortree-privilegeerde IAM-rolle, verkeerd geconfigureerde KMS policies, automatiseringsrekeninge wat arbitrêre signatures kan versoek, publieke buckets met bridge-konfigurasies, ens.
2. **Value-specific weaknesses**: brose oracle-parameters, upgradable kontrakte sonder multi-party goedkeurings, flash-loan sensitiewe liquidity, governance-aksies wat timelocks omseil.

Werk die tou soos 'n vyand: begin met die operasionele voetvaste punte wat vandag kan slaag, en beweeg dan in na diepprotokol/ekonomiese manipulasieroute.

## 4. Voer uit in beheerde, produksie-realistiese omgewings
- **Forked mainnets / isolated testnets**: repliseer bytecode, storage, en liquiditeit sodat flash-loan paths, oracle drifts, en bridge flows end-to-end werk sonder om werklike fondse te raak.
- **Blast-radius planning**: definieer circuit breakers, pausable modules, rollback runbooks, en test-only admin keys voordat jy 'n scenario detoneer.
- **Stakeholder coordination**: verwittig custodians, oracle operators, bridge partners, en compliance sodat hul monitoring spanne die verkeer verwag.
- **Legal sign-off**: dokumenteer scope, authorization, en stopvoorwaardes wanneer simulasies gereguleerde rels kan kruis.

## 5. Telemetry gealigneer met AADAPT-tegnieke
Instrumeer telemetry strome sodat elke scenario aksie-ryke detections lewer.

- **Chain-level traces**: volledige call graphs, gas usage, transaction nonces, block timestamps—to reconstruct flash-loan bundles, reentrancy-like structures, and cross-contract hops.
- **Application/API logs**: koppel elke on-chain tx terug na 'n mens of automatiseringsidentiteit (session ID, OAuth client, API key, CI job ID) met IP's en auth-metodes.
- **KMS/HSM logs**: sleutel-ID, caller principal, policy result, destination address, en reason codes vir elke signature. Baseline change windows en hoë-risiko operasies.
- **Oracle/feed metadata**: per-update data source composition, reported value, deviation from rolling averages, thresholds triggered, en failover paths exercised.
- **Bridge/swap traces**: korreleer lock/mint/unlock events oor kettings met correlation IDs, chain IDs, relayer identity, en hop timing.
- **Anomaly markers**: afgeleide metrieks soos slippage spikes, abnormale collateralization ratios, vreemde gas density, of cross-chain velocity.

Merk alles met scenario IDs of sintetiese user IDs sodat ontleders observables met die AADAPT-tegniek wat geoefen is, kan bely.

## 6. Purple-team loop & maturity metrics
1. Voer die scenario in die beheerde omgewing uit en vang detections (alerts, dashboards, responders gepaag).
2. Koppel elke stap aan die spesifieke AADAPT-tegnieke plus die observables wat in chain/app/KMS/oracle/bridge planes geproduseer is.
3. Formuleer en implementeer detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Herhaal totdat mean time to detect (MTTD) en mean time to contain (MTTC) aan sake-toleransies voldoen en playbooks betroubaar die waardeverlies stop.

Volg programvolwassenheid op drie asse:
- **Visibility**: elke kritieke waardepad het telemetry in elke vlak.
- **Coverage**: verhouding van geprioritiseerde AADAPT-tegnieke wat end-to-end geoefen is.
- **Response**: vermoë om kontrakte te pauseer, sleutels te herroep, of vloei te vries voordat irreversible verlies plaasvind.

Tipiese mylpale: (1) voltooide waardeinventaris + AADAPT-kartering, (2) eerste end-to-end scenario met detections geïmplementeer, (3) kwartaal-agtige purple-team siklusse wat dekking uitbrei en MTTD/MTTC verlaag.

## 7. Scenario templates
Gebruik hierdie herhaalbare bloudrukke om simulasies te ontwerp wat direk aan AADAPT-gedraginge koppel.

### Scenario A – Flash-loan economic manipulation
- **Objective**: leen tydelike kapitaal binne een transaksie om AMM prices/liquidity te verteer en misgeprysde borrows, liquidations, of mints te veroorsaak voordat terugbetaal word.
- **Execution**:
1. Fork die teiken-ketting en seed pools met produksie-agtige liquidity.
2. Borrow large notional via flash loan.
3. Voer gekalibreerde swaps uit om prys-/drempelgrense te kruis waarop lending, vault, of derivative logic staatmaak.
4. Roep die slagofferkontrak onmiddellik na die verstoring aan (borrow, liquidate, mint) en betaal die flash loan terug.
- **Measurement**: Het die invariant-violasie geslaag? Is slippage/price-deviation monitors, circuit breakers, of governance pause hooks getrigger? Hoe lank voordat analytics die abnormale gas/call graph patroon gevlag het?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: bepaal of gemanipuleerde feeds vernietigende geoutomatiseerde aksies kan veroorsaak (mass liquidations, incorrect settlements).
- **Execution**:
1. In die fork/testnet, deploy 'n kwaadwillige feed of pas aggregator weights/quorum/update cadence aan buite die geduldigde deviatie.
2. Laat afhanklike kontrakte die vergiftigde waardes verbruik en hul standaardlogika uitvoer.
- **Measurement**: Feed-vlak out-of-band alerts, fallback oracle activation, min/max bound enforcement, en latensie tussen anomalie-aanvang en operator-reaksie.

### Scenario C – Credential/signing abuse
- **Objective**: toets of die kompromittering van 'n enkele signer of automatiseringsidentiteit onbevoegde upgrades, parameterveranderings, of treasury drains moontlik maak.
- **Execution**:
1. Enumereer identiteite met sensitiewe signing regte (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants).
2. Simuleer kompromittering (hergebruik hul credentials/keys binne die lab-scope).
3. Probeer bevoorrechte aksies: upgrade proxies, verander risk parameters, mint/pause assets, of trigger governance proposals.
- **Measurement**: Lig KMS/HSM logs anomalie-alerts op (time-of-day, destination drift, burst of high-risk operations)? Kan beleidsreëls of multisig-drempels eenwoordige misbruik voorkom? Word throttles/rate limits of addisionele goedkeurings afgedwing?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: evalueer hoe goed verdedigers assets kan opspoor en interdikte wat vinnig oor bridges, DEX routers, en privacy hops gewas word.
- **Execution**:
1. Ketting lock/mint operasies oor algemene bridges, interleef swaps/mixers op elke hop, en handhaaf per-hop correlation IDs.
2. Versnel transfers om monitoring latensie te stress (multi-hop binne minute/blocks).
- **Measurement**: Tyd om gebeure oor telemetry + commercial chain analytics te korreleer, volledigheid van die herbouvde pad, vermoë om choke points te identifiseer vir vries in 'n werklike insident, en alert fideliteit vir abnormale cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
