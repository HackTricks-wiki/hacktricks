# Web3 Red Teaming fokusiran na vrednost (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrica beleži ponašanja napadača koja manipulišu digitalnom vrednošću, a ne samo infrastrukturom. Smatrajte je za **okosnicu modelovanja pretnji**: nabrojite svaku komponentu koja može mintovati, određivati cenu, autorizovati ili rutirati aktive, mapirajte te tačke pristupa na AADAPT tehnike i zatim kreirajte red-team scenarije koji mere da li okruženje može da odoli ireverzibilnom ekonomskom gubitku.

## 1. Inventar komponenti koje nose vrednost
Napravite mapu svega što može da utiče na stanje vrednosti, čak i ako je off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Zabeležite key ID-e, politike, automation identitete i approval workflows.
- **Admin & upgrade paths** za kontrakte (proxy admins, governance timelocks, emergency pause keys, parameter registries). Uključite ko/šta može da ih pozove i pod kojim quorumom ili kašnjenjem.
- **On-chain protocol logic** koja rukuje lending, AMMs, vaults, staking, bridges, ili settlement rails. Dokumentujte invarijante koje pretpostavljaju (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** koja gradi transakcije (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Ovi često drže API ključeve ili service principals koji mogu da zahtevaju potpise.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Zabeležite svaki upstream na koji se oslanja automated risk logic.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) koji povezuju chain-ove ili custodial stackove.

Deliverable: value-flow dijagram koji pokazuje kako se asseti kreću, ko autorizuje kretanje i koji eksterni signali utiču na poslovnu logiku.

## 2. Mapirajte komponente na AADAPT ponašanja
Prevedite AADAPT taksonomiju u konkretne kandidature napada po komponenti.

| Komponenta | Primarni AADAPT fokus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Ova mapa osigurava da testirate ne samo kontrakte, već i svaki identity/automation koji može indirektno da usmeri vrednost.

## 3. Prioritizujte po izvodljivosti napadača naspram poslovnog uticaja

1. **Operativne slabosti**: izloženi CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts koje mogu da zatraže arbitrary signatures, public buckets sa bridge konfiguracijama, itd.
2. **Slabosti specifične za vrednost**: krhki oracle parameters, upgradable contracts bez multi-party approvals, flash-loan osetljiva likvidnost, governance akcije koje zaobilaze timelocks.

Radite kroz queue kao adversary: počnite sa operativnim poprištima koja mogu uspeti danas, zatim pređite u duboke puteve manipulacije protokolom/ekonomijom.

## 4. Izvršite u kontrolisanim, production-realistic okruženjima
- **Forked mainnets / isolated testnets**: replicirajte bytecode, storage i liquidity tako da flash-loan paths, oracle drifts i bridge flows rade end-to-end bez dodirivanja realnih sredstava.
- **Blast-radius planning**: definišite circuit breakers, pausable modules, rollback runbooks i test-only admin keys pre nego što detonirate scenario.
- **Stakeholder coordination**: obavestite custodians, oracle operators, bridge partners i compliance kako bi njihovi monitoring timovi očekivali taj saobraćaj.
- **Legal sign-off**: dokumentujte scope, authorization i stop conditions kada simulacije mogu da pređu regulisana rails.

## 5. Telemetrija usklađena sa AADAPT tehnikama
Instrumentujte telemetry tokove tako da svaki scenario proizvede akcioni detekcioni podatak.

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps—to rekonstruisati flash-loan bundles, reentrancy-like strukture i cross-contract hops.
- **Application/API logs**: povežite svaku on-chain tx nazad do human ili automation identity (session ID, OAuth client, API key, CI job ID) sa IP adresama i auth metodama.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address i reason codes za svaki potpis. Baseline change windows i high-risk operations.
- **Oracle/feed metadata**: per-update data source composition, reported value, deviation from rolling averages, thresholds triggered i failover paths exercised.
- **Bridge/swap traces**: korrelirajte lock/mint/unlock događaje preko chain-ova sa correlation IDs, chain IDs, relayer identity i hop timing.
- **Anomaly markers**: izvedeni metrički indikatori kao što su slippage spikes, abnormal collateralization ratios, neobična gas density ili cross-chain velocity.

Tagujte sve sa scenario IDs ili synthetic user IDs kako bi analitičari mogli da usklade observables sa AADAPT tehnikom koja se vežba.

## 6. Purple-team loop & metrički nivo zrelosti
1. Pokrenite scenario u kontrolisanom okruženju i zabeležite detekcije (alerts, dashboards, responders paged).
2. Mapirajte svaki korak na specifične AADAPT tehnike plus observables proizvedene u chain/app/KMS/oracle/bridge domenima.
3. Formulišite i implementirajte detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Ponovite dok mean time to detect (MTTD) i mean time to contain (MTTC) ne zadovolje poslovne tolerancije i dok playbooks pouzdano ne zaustave gubitak vrednosti.

Pratite zrelost programa na tri ose:
- **Vidljivost**: svaki kritični value path ima telemetry u svakom domenu.
- **Pokriće**: odnos prioritetizovanih AADAPT tehnika koje su vežbane end-to-end.
- **Odgovor**: sposobnost da se pauziraju kontrakti, opozovu ključevi ili zamrznu tokovi pre nego što dođe do ireverzibilnog gubitka.

Tipične prekretnice: (1) kompletiran value inventory + AADAPT mapping, (2) prvi end-to-end scenario sa implementiranim detekcijama, (3) kvartalni purple-team ciklusi koji proširuju pokriće i smanjuju MTTD/MTTC.

## 7. Template-i scenarija
Koristite ove ponovljive blueprint-e da dizajnirate simulacije koje se direktno mapiraju na AADAPT ponašanja.

### Scenario A – Flash-loan ekonomska manipulacija
- **Objective**: pozajmiti privremeni kapital unutar jedne transakcije da bi se iskrivile AMM cene/likvidnost i izazvale pogrešno ocenjeni borrow-ovi, liquidations ili mint-ovi pre nego što se isplati.
- **Execution**:
1. Forkujte ciljanu mrežu i seed-ujte pool-ove sa produkcijski-sličnom likvidnošću.
2. Pozajmite veliki notional preko flash loan-a.
3. Izvedite kalibrisane swap-ove da pređete granice cena/threshold-a na koje se oslanjaju lending, vault ili derivative logika.
4. Pozovite victim contract odmah nakon distorzije (borrow, liquidate, mint) i vratite flash loan.
- **Measurement**: Da li je došlo do kršenja invarijante? Da li su slippage/price-deviation monitora, circuit breakers ili governance pause hook-ovi pokrenuti? Koliko je vremena prošlo dok analytics nije označio abnormalan gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: utvrditi da li manipulisani feed-ovi mogu da okinu destruktivne automatske akcije (masovne likvidacije, netačna settlement-a).
- **Execution**:
1. U fork/testnet okruženju, deploy-ujte malicious feed ili prilagodite aggregator weights/quorum/update cadence preko tolerisanog devijacionog praga.
2. Dozvolite dependent kontraktima da konzumiraju poison-ovane vrednosti i izvrše svoju standardnu logiku.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, sprovođenje min/max bound-ova i latencija između početka anomalije i operator response-a.

### Scenario C – Credential/signing abuse
- **Objective**: testirati da li kompromitovanje jednog signera ili automation identity omogućava neautorizovane upgrade-e, promene parametara ili ispumpavanje trezora.
- **Execution**:
1. Enumerišite identity sa osetljivim signing pravima (operators, CI tokens, service accounts koji pozivaju KMS/HSM, multisig participants).
2. Simulirajte kompromis (ponovno upotrebite njihove credentials/keys u lab scope-u).
3. Pokušajte privilegovane akcije: upgrade proxies, promena risk parameters, mint/pause assets, ili iniciranje governance proposals.
- **Measurement**: Da li KMS/HSM logs podižu anomaly alerts (vreme dana, destination drift, burst visokorizičnih operacija)? Mogu li politike ili multisig thresholds da spreče unilateralnu zloupotrebu? Postoje li throttle-i/rate limit-i ili dodatna odobrenja?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: oceniti koliko dobro branitelji mogu da prate i interdiktuju aktive koje se brzo peru preko bridges, DEX routers i privacy hop-ova.
- **Execution**:
1. Povežite lock/mint operacije preko uobičajenih bridges, prepletite swaps/mixere na svakom hop-u i održavajte per-hop correlation IDs.
2. Ubrzajte transfere da biste opteretili monitoring latency (multi-hop unutar minuta/blocks).
- **Measurement**: Vreme za korrelaciju događaja preko telemetrije + komercijalne chain analitike, potpunost rekonstruisanog puta, sposobnost identifikovanja choke point-ova za zamrzavanje u realnom incidentu, i fidelity alert-a za abnormalnu cross-chain velocity/value.

## Reference

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
