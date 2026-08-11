# Web3 Red Teaming usmeren na vrednost (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework kategorizuje adversarial actions i techniques usmerene na sisteme digitalne imovine.<sup>[[1]](#references)</sup> Tretirajte ga kao **osnovu za threat-modeling**: popišite svaku komponentu koja može da kreira, procenjuje, autorizuje ili usmerava imovinu, mapirajte te tačke dodira na AADAPT techniques, a zatim pokrenite red-team scenarije koji mere da li okruženje može da se odupre nepovratnom ekonomskom gubitku.

## 1. Popišite komponente koje nose vrednost
Napravite mapu svega što može da utiče na stanje vrednosti, čak i ako se nalazi off-chain.<sup>[[2]](#references)</sup>

- **Custodial signing services** (HSM/KMS klasteri, Vault/KMaaS, signing API-ji koje koriste botovi ili back-office poslovi). Zabeležite key ID-jeve, policies, automation identities i approval workflows.
- **Admin i upgrade putanje** za contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Uključite ko ili šta može da ih pozove i pod kojim quorum-om ili delay-em.
- **On-chain protocol logic** koja obrađuje lending, AMM-ove, vaults, staking, bridges ili settlement rails. Dokumentujte invariants na koje se oslanjaju (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** koja kreira transactions (market-making botovi, CI/CD pipelines, cron jobs, serverless functions). Oni često poseduju API keys ili service principals koji mogu da zahtevaju signatures.
- **Oracles i data feeds** (sastav aggregator-a, quorum, deviation thresholds, update cadence). Zabeležite svaki upstream na koji se automated risk logic oslanja.
- **Bridges i cross-chain routers** (lock/mint contracts, relayers, settlement jobs) koji povezuju chains ili custodial stacks.

Isporučivi rezultat: dijagram toka vrednosti koji prikazuje kako se assets kreću, ko autorizuje kretanje i koji external signals utiču na business logic.

## 2. Mapirajte komponente na AADAPT behaviors
Prevedite AADAPT taxonomy u konkretne attack candidates za svaku komponentu.<sup>[[2]](#references)</sup>

| Component | Primarni AADAPT fokus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Ovo mapiranje obezbeđuje da ne testirate samo contracts, već i svaki identity/automation koji može indirektno da usmerava vrednost.

## 3. Odredite prioritete prema izvodljivosti za attackera i poslovnom uticaju

1. **Operational weaknesses**: izloženi CI credentials, previše privilegovane IAM roles, pogrešno konfigurisane KMS policies, automation accounts koji mogu da zahtevaju proizvoljne signatures, public buckets sa bridge configs itd.
2. **Value-specific weaknesses**: fragilni oracle parameters, upgradable contracts bez multi-party approvals, flash-loan sensitive liquidity, governance actions koje zaobilaze timelocks.

Vodite queue kao adversary: počnite od operational footholds koji bi mogli da uspeju danas, a zatim pređite na duboke protocol/economic manipulation paths.<sup>[[2]](#references)</sup>

## 4. Izvršavajte u kontrolisanim okruženjima realističnim za production
- **Forked mainnets / isolated testnets**: replicirajte bytecode, storage i liquidity kako bi flash-loan paths, oracle drifts i bridge flows radili end-to-end bez dodirivanja stvarnih funds.<sup>[[2]](#references)</sup>
- **Blast-radius planning**: definišite circuit breakers, pausable modules, rollback runbooks i test-only admin keys pre detoniranja scenarija.
- **Stakeholder coordination**: obavestite custodians, oracle operators, bridge partners i compliance kako bi njihovi monitoring timovi očekivali saobraćaj.
- **Legal sign-off**: dokumentujte scope, authorization i stop conditions kada simulations mogu da obuhvate regulated rails.

## 5. Telemetrija usklađena sa AADAPT techniques
Instrumentišite telemetry streams tako da svaki scenario proizvodi podatke korisne za detection.<sup>[[2]](#references)</sup>

- **Chain-level traces**: kompletni call graphs, gas usage, transaction nonces, block timestamps — za rekonstrukciju flash-loan bundles, reentrancy-like structures i cross-contract hops.
- **Application/API logs**: povežite svaki on-chain tx sa human ili automation identity-jem (session ID, OAuth client, API key, CI job ID), uz IP adrese i auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address i reason codes za svaki signature. Uspostavite baseline change windows i high-risk operations.
- **Oracle/feed metadata**: composition data source-a po update-u, reported value, deviation od rolling averages, aktivirani thresholds i korišćeni failover paths.
- **Bridge/swap traces**: korelišite lock/mint/unlock events između chains pomoću correlation IDs, chain IDs, relayer identity-ja i hop timing-a.
- **Anomaly markers**: izvedene metrics kao što su slippage spikes, abnormal collateralization ratios, unusual gas density ili cross-chain velocity.

Označite sve scenario IDs ili synthetic user IDs kako bi analysts mogli da usklade observables sa AADAPT technique-om koji se testira.

## 6. Purple-team loop i metrics zrelosti
1. Pokrenite scenario u kontrolisanom okruženju i zabeležite detections (alerts, dashboards, responders koji su paged).<sup>[[2]](#references)</sup>
2. Mapirajte svaki korak na konkretne AADAPT techniques i observables proizvedene u chain/app/KMS/oracle/bridge planes.
3. Formulišite i deploy-ujte detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Ponavljajte postupak dok mean time to detect (MTTD) i mean time to contain (MTTC) ne budu u granicama poslovnih tolerancija i dok playbooks pouzdano ne zaustave gubitak vrednosti.

Pratite zrelost programa kroz tri ose:<sup>[[2]](#references)</sup>
- **Visibility**: svaki kritični value path ima telemetry u svakom plane-u.
- **Coverage**: udeo prioritizovanih AADAPT techniques testiranih end-to-end.
- **Response**: sposobnost da se contracts pauziraju, keys opozovu ili flows zamrznu pre nepovratnog gubitka.

Tipične milestones: (1) završen value inventory + AADAPT mapping, (2) prvi end-to-end scenario sa implementiranim detections, (3) kvartalni purple-team cycles koji proširuju coverage i smanjuju MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Scenario templates
Koristite ove ponovljive blueprints za dizajniranje simulations koje se direktno mapiraju na AADAPT behaviors.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: pozajmiti privremeni capital unutar jedne transaction kako bi se izmenile AMM prices/liquidity i aktivirali mispriced borrows, liquidations ili mints pre otplate.
- **Execution**:
1. Forkujte target chain i napunite pools production-like liquidity-jem.
2. Pozajmite veliki notional putem flash loan-a.
3. Izvršite kalibrisane swaps kako biste prešli price/threshold boundaries na koje se oslanjaju lending, vault ili derivative logic.
4. Pozovite victim contract odmah nakon distortion-a (borrow, liquidate, mint) i otplatite flash loan.
- **Measurement**: Da li je invariant violation uspela? Da li su slippage/price-deviation monitors, circuit breakers ili governance pause hooks aktivirani? Koliko je vremena bilo potrebno da analytics označi abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: utvrditi da li manipulated feeds mogu da pokrenu destruktivne automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. U fork/testnet okruženju deploy-ujte malicious feed ili podesite aggregator weights/quorum/update cadence izvan tolerisane deviation.
2. Dozvolite da dependent contracts konzumiraju poisoned values i izvrše svoju standardnu logic.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement i latency između početka anomaly-ja i operator response-a.

### Scenario C – Credential/signing abuse
- **Objective**: testirati da li compromise jednog signer-a ili automation identity-ja omogućava unauthorized upgrades, parameter changes ili treasury drains.
- **Execution**:
1. Popišite identities sa osetljivim signing rights (operators, CI tokens, service accounts koji pozivaju KMS/HSM, multisig participants).
2. Simulirajte compromise (ponovo koristite njihove credentials/keys u okviru lab scope-a).
3. Pokušajte privileged actions: upgrade proxies, promenite risk parameters, mint/pause assets ili pokrenite governance proposals.
- **Measurement**: Da li KMS/HSM logs generišu anomaly alerts (time-of-day, destination drift, burst high-risk operations)? Mogu li policies ili multisig thresholds da spreče unilateral abuse? Da li se primenjuju throttles/rate limits ili additional approvals?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: proceniti koliko dobro defenders mogu da prate i brzo zaustave assets koji se peru kroz bridges, DEX routers i privacy hops.
- **Execution**:
1. Povežite lock/mint operations kroz common bridges, ubacite swaps/mixers na svaki hop i održavajte per-hop correlation IDs.
2. Ubrzajte transfers da biste opteretili monitoring latency (multi-hop u roku od nekoliko minuta/blocks).
- **Measurement**: Vreme potrebno za korelaciju events-a kroz telemetry + commercial chain analytics, potpunost reconstructed path-a, sposobnost identifikovanja choke points za freeze u real incidentu i alert fidelity za abnormal cross-chain velocity/value.

## References

- [1] [AADAPT(TM) Cyber Threat Framework za Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework kao Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
