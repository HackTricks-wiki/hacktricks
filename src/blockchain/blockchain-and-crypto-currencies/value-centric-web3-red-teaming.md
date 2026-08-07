# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrica beleži ponašanja napadača koji manipulišu digitalnom vrednošću, a ne samo infrastrukturom. Tretirajte je kao **osnovu za modelovanje pretnji**: popišite svaku komponentu koja može da kreira, određuje cenu, autorizuje ili usmerava sredstva, mapirajte te dodirne tačke na AADAPT tehnike, a zatim pokrenite red-team scenarije koji mere da li okruženje može da se odupre nepovratnom ekonomskom gubitku.

## 1. Popis komponenti koje nose vrednost
Napravite mapu svega što može da utiče na stanje vrednosti, čak i ako je off-chain.<sup>[[1]](#references)</sup>

- **Custodial signing services** (HSM/KMS klasteri, Vault/KMaaS, signing API-ji koje koriste botovi ili back-office poslovi). Zabeležite ID-jeve ključeva, policies, automation identitete i approval workflows.
- **Admin & upgrade paths** za contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Uključite ko/šta može da ih pozove i pod kojim quorum-om ili delay-em.
- **On-chain protocol logic** koja obrađuje lending, AMM-ove, vault-ove, staking, bridges ili settlement rails. Dokumentujte invariants na koje se oslanjaju (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** koja konstruiše transakcije (market-making botovi, CI/CD pipelines, cron jobs, serverless functions). Oni često poseduju API keys ili service principals koji mogu da zahtevaju signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Zabeležite svaki upstream izvor na koji se oslanja automated risk logic.
- **Bridges i cross-chain routers** (lock/mint contracts, relayers, settlement jobs) koji povezuju chains ili custodial stacks.

Rezultat: dijagram toka vrednosti koji prikazuje kako se sredstva kreću, ko autorizuje kretanje i koji eksterni signali utiču na business logic.

## 2. Mapiranje komponenti na AADAPT ponašanja
Prevedite AADAPT taksonomiju u konkretne attack candidates za svaku komponentu.<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Ovo mapiranje obezbeđuje da ne testirate samo contracts, već i svaki identity/automation koji može indirektno da usmerava vrednost.

## 3. Prioritizacija prema izvodljivosti za napadača i poslovnom uticaju

1. **Operational weaknesses**: izloženi CI credentials, previše privilegovane IAM roles, pogrešno konfigurisane KMS policies, automation accounts koji mogu da zahtevaju proizvoljne signatures, public buckets sa bridge configs itd.
2. **Value-specific weaknesses**: krhki oracle parameters, upgradable contracts bez multi-party approvals, flash-loan sensitive liquidity, governance actions koje zaobilaze timelocks.

Radite kroz queue kao adversary: počnite od operational footholds koji bi mogli da uspeju danas, a zatim pređite na složene protocol/economic manipulation paths.<sup>[[1]](#references)</sup>

## 4. Izvršavanje u kontrolisanim okruženjima realističnim za produkciju
- **Forked mainnets / isolated testnets**: reprodukujte bytecode, storage i liquidity kako bi flash-loan paths, oracle drifts i bridge flows radili end-to-end bez dodirivanja stvarnih sredstava.<sup>[[1]](#references)</sup>
- **Blast-radius planning**: definišite circuit breakers, pausable modules, rollback runbooks i test-only admin keys pre aktiviranja scenarija.
- **Stakeholder coordination**: obavestite custodians, oracle operators, bridge partners i compliance kako bi njihovi monitoring timovi očekivali saobraćaj.
- **Legal sign-off**: dokumentujte scope, authorization i stop conditions kada bi simulations mogle da zahvate regulated rails.

## 5. Telemetrija usklađena sa AADAPT tehnikama
Instrumentišite telemetry streams tako da svaki scenario proizvodi upotrebljive detection data.<sup>[[1]](#references)</sup>

- **Chain-level traces**: kompletni call graphs, gas usage, transaction nonces, block timestamps — za rekonstrukciju flash-loan bundles, reentrancy-like structures i cross-contract hops.
- **Application/API logs**: povežite svaki on-chain tx sa human ili automation identity-em (session ID, OAuth client, API key, CI job ID), uz IP adrese i auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address i reason codes za svaki signature. Uspostavite baseline za change windows i high-risk operations.
- **Oracle/feed metadata**: composition data source-a po update-u, reported value, deviation od rolling averages, aktivirani thresholds i iskorišćeni failover paths.
- **Bridge/swap traces**: korelišite lock/mint/unlock events između chains pomoću correlation IDs, chain IDs, relayer identity-ja i hop timing-a.
- **Anomaly markers**: izvedene metrics kao što su slippage spikes, abnormal collateralization ratios, unusual gas density ili cross-chain velocity.

Označite sve scenario IDs ili synthetic user IDs kako bi analysts mogli da usklade observables sa AADAPT tehnikom koja se testira.

## 6. Purple-team loop & maturity metrics
1. Pokrenite scenario u kontrolisanom okruženju i zabeležite detections (alerts, dashboards, responders paged).<sup>[[1]](#references)</sup>
2. Mapirajte svaki korak na konkretne AADAPT techniques i observables proizvedene u chain/app/KMS/oracle/bridge planes.
3. Formulišite i implementirajte detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Ponovo pokrećite scenario dok mean time to detect (MTTD) i mean time to contain (MTTC) ne budu u okviru business tolerances i dok playbooks pouzdano ne zaustave gubitak vrednosti.

Pratite zrelost programa kroz tri ose:<sup>[[1]](#references)</sup>
- **Visibility**: svaki critical value path ima telemetry u svakom plane-u.
- **Coverage**: udeo prioritizovanih AADAPT techniques koje su testirane end-to-end.
- **Response**: sposobnost da se contracts pauziraju, keys opozovu ili flows zamrznu pre nepovratnog gubitka.

Tipične milestones: (1) završen value inventory + AADAPT mapping, (2) prvi end-to-end scenario sa implementiranim detections, (3) quarterly purple-team cycles koje proširuju coverage i smanjuju MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Scenario templates
Koristite ove ponovljive blueprints za dizajniranje simulations koje se direktno mapiraju na AADAPT behaviors.<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: pozajmiti privremeni kapital unutar jedne transakcije radi izobličavanja AMM prices/liquidity i pokretanja pogrešno obračunatih borrows, liquidations ili mints pre vraćanja sredstava.
- **Execution**:
1. Forkujte target chain i napunite pools liquidity-jem sličnim produkcionom.
2. Pozajmite veliki notional putem flash loan-a.
3. Izvršite kalibrisane swaps kako biste prešli price/threshold boundaries na koje se oslanjaju lending, vault ili derivative logic.
4. Pozovite victim contract odmah nakon distorzije (borrow, liquidate, mint) i vratite flash loan.
- **Measurement**: Da li je invariant violation uspešno izveden? Da li su slippage/price-deviation monitors, circuit breakers ili governance pause hooks aktivirani? Koliko je vremena bilo potrebno da analytics označi abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: utvrditi da li manipulated feeds mogu da pokrenu destruktivne automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. U fork/testnet okruženju deployujte malicious feed ili podesite aggregator weights/quorum/update cadence izvan tolerisanog deviation-a.
2. Dozvolite dependent contracts da koriste poisoned values i izvrše svoju standardnu logic.
- **Measurement**: Out-of-band alerts na nivou feed-a, activation fallback oracle-a, primena min/max bounds i latency između pojave anomalije i reakcije operatora.

### Scenario C – Credential/signing abuse
- **Objective**: testirati da li compromise jednog signer-a ili automation identity-ja omogućava unauthorized upgrades, parameter changes ili treasury drains.
- **Execution**:
1. Popišite identities sa sensitive signing rights (operators, CI tokens, service accounts koji pozivaju KMS/HSM, multisig participants).
2. Simulirajte compromise (ponovo koristite njihove credentials/keys unutar lab scope-a).
3. Pokušajte privileged actions: upgrade proxies, promenite risk parameters, mint/pause assets ili pokrenite governance proposals.
- **Measurement**: Da li KMS/HSM logs podižu anomaly alerts (time-of-day, destination drift, burst high-risk operations)? Mogu li policies ili multisig thresholds sprečiti unilateral abuse? Da li su throttles/rate limits ili additional approvals primenjeni?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: proceniti koliko dobro defenders mogu da prate i brzo zaustave sredstva koja se launder-uju kroz bridges, DEX routers i privacy hops.
- **Execution**:
1. Povežite lock/mint operations kroz common bridges, ubacite swaps/mixers na svaki hop i održavajte correlation IDs za svaki hop.
2. Ubrzajte transfers kako biste opteretili monitoring latency (multi-hop u roku od nekoliko minuta/blocks).
- **Measurement**: Vreme potrebno za korelaciju events kroz telemetry + commercial chain analytics, potpunost reconstructed path-a, sposobnost identifikovanja choke points za freezing u real incidentu i alert fidelity za abnormal cross-chain velocity/value.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
