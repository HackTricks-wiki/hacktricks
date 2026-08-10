# Web3 Red Teaming usmeren na vrednost (MITRE AADAPT)

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework kategorizuje protivničke radnje i tehnike usmerene na sisteme digitalne imovine.<sup>[[1]](#references)</sup> Tretirajte ga kao **osnovu za modeliranje pretnji**: popišite svaku komponentu koja može da kreira, određuje cenu, autorizuje ili usmerava imovinu, mapirajte te tačke dodira na AADAPT tehnike, a zatim pokrenite red-team scenarije koji mere da li okruženje može da izdrži nepovratan ekonomski gubitak.

## 1. Popis komponenti koje nose vrednost
Napravite mapu svega što može da utiče na stanje vrednosti, čak i ako je off-chain.<sup>[[2]](#references)</sup>

- **Custodial signing servisi** (HSM/KMS klasteri, Vault/KMaaS, signing API-ji koje koriste botovi ili back-office poslovi). Zabeležite ID-jeve ključeva, policies, automation identitete i approval workflows.
- **Admin & upgrade putanje** za contracts (proxy admini, governance timelocks, emergency pause ključevi, registri parametara). Uključite ko/šta može da ih pozove i pod kojim quorum-om ili kašnjenjem.
- **On-chain protocol logika** koja obrađuje lending, AMM-ove, vault-ove, staking, bridges ili settlement rails. Dokumentujte invariants na koje se oslanja (oracle cene, collateral ratios, učestalost rebalansiranja…).
- **Off-chain automation** koja kreira transakcije (market-making botovi, CI/CD pipelines, cron poslovi, serverless functions). Oni često sadrže API ključeve ili service principals koji mogu da zahtevaju signatures.
- **Oracles & data feeds** (sastav agregatora, quorum, pragovi odstupanja, učestalost ažuriranja). Zabeležite svaki upstream na koji se oslanja automatizovana risk logika.
- **Bridges i cross-chain routers** (lock/mint contracts, relayers, settlement jobs) koji povezuju chains ili custodial stack-ove.

Rezultat: dijagram toka vrednosti koji prikazuje kako se imovina kreće, ko autorizuje kretanje i koji eksterni signali utiču na business logic.

## 2. Mapiranje komponenti na AADAPT ponašanja
Prevedite AADAPT taksonomiju u konkretne attack kandidate za svaku komponentu.<sup>[[2]](#references)</sup>

| Komponenta | Primarni AADAPT fokus |
| --- | --- |
| Signing/KMS estates | Krađa credentials, zaobilaženje policy-ja, zloupotreba signing-a, preuzimanje governance-a |
| Oracles/feeds | Trovanje inputa, manipulacija agregacijom, izbegavanje praga odstupanja |
| On-chain protocols | Ekonomska manipulacija flash-loan-om, kršenje invariants, rekonfiguracija parametara |
| Automation pipelines | Kompromitovani bot/CI identiteti, replay batch-a, neautorizovani deployment |
| Bridges/routers | Cross-chain izbegavanje, rapid hop laundering, desinhronizacija settlement-a |

Ovo mapiranje obezbeđuje da testirate ne samo contracts, već i svaki identitet/automation koji može indirektno da usmerava vrednost.

## 3. Prioritizacija prema izvodljivosti napadača i poslovnom uticaju

1. **Operativne slabosti**: izloženi CI credentials, IAM roles sa prevelikim privilegijama, pogrešno konfigurisani KMS policies, automation nalozi koji mogu da zahtevaju proizvoljne signatures, public buckets sa bridge konfiguracijama itd.
2. **Slabosti specifične za vrednost**: osetljivi oracle parametri, upgradable contracts bez multi-party approvals, likvidnost osetljiva na flash-loan, governance actions koje zaobilaze timelocks.

Obrađujte red kao napadač: počnite od operativnih footholds koji bi danas mogli da uspeju, a zatim pređite na duboke putanje protocol/economic manipulacije.<sup>[[2]](#references)</sup>

## 4. Izvršavanje u kontrolisanim, produkcijski realističnim okruženjima
- **Forked mainnets / isolated testnets**: replicirajte bytecode, storage i liquidity kako bi flash-loan putanje, oracle drift-ovi i bridge tokovi mogli da se izvrše end-to-end bez dodirivanja stvarnih sredstava.<sup>[[2]](#references)</sup>
- **Planiranje blast radius-a**: definišite circuit breakers, pausable modules, rollback runbooks i test-only admin ključeve pre aktiviranja scenarija.
- **Koordinacija sa stakeholder-ima**: obavestite custodians, oracle operatore, bridge partnere i compliance kako bi njihovi monitoring timovi očekivali saobraćaj.
- **Legal sign-off**: dokumentujte scope, authorization i stop conditions kada bi simulacije mogle da pređu preko regulisanih rails.

## 5. Telemetrija usklađena sa AADAPT tehnikama
Instrumentirajte telemetrijske tokove tako da svaki scenario proizvede korisne detection podatke.<sup>[[2]](#references)</sup>

- **Chain-level traces**: kompletni call graphs, potrošnja gas-a, transaction nonces, block timestamps — za rekonstrukciju flash-loan bundles, reentrancy-like struktura i cross-contract hop-ova.
- **Application/API logs**: povežite svaki on-chain tx sa ljudskim ili automation identitetom (session ID, OAuth client, API key, CI job ID), uz IP adrese i auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address i reason codes za svaki signature. Uspostavite baseline change windows i high-risk operations.
- **Oracle/feed metadata**: composition izvora podataka po ažuriranju, prijavljena vrednost, odstupanje od rolling averages, aktivirani pragovi i korišćene failover putanje.
- **Bridge/swap traces**: korelišite lock/mint/unlock events između chains pomoću correlation IDs, chain IDs, relayer identiteta i vremena hop-ova.
- **Anomaly markers**: izvedene metrike kao što su skokovi slippage-a, abnormalni collateralization ratios, neuobičajena gustina gas-a ili cross-chain velocity.

Označite sve scenario IDs ili synthetic user IDs kako bi analitičari mogli da povežu observables sa AADAPT tehnikom koja se testira.

## 6. Purple-team loop i metrike zrelosti
1. Pokrenite scenario u kontrolisanom okruženju i zabeležite detections (alerts, dashboards, responders koji su obavešteni).<sup>[[2]](#references)</sup>
2. Mapirajte svaki korak na konkretne AADAPT techniques i observables generisane u chain/app/KMS/oracle/bridge planes.
3. Formulišite i implementirajte detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Ponavljajte postupak dok mean time to detect (MTTD) i mean time to contain (MTTC) ne ispune poslovne tolerancije i dok playbooks pouzdano ne zaustave gubitak vrednosti.

Pratite zrelost programa kroz tri ose:<sup>[[2]](#references)</sup>
- **Visibility**: svaki kritični value path ima telemetriju u svakom plane-u.
- **Coverage**: udeo prioritetnih AADAPT techniques testiranih end-to-end.
- **Response**: sposobnost da se contracts pauziraju, keys opozovu ili flows zamrznu pre nepovratnog gubitka.

Tipične prekretnice: (1) završen value inventory + AADAPT mapping, (2) prvi end-to-end scenario sa implementiranim detections, (3) kvartalni purple-team ciklusi koji proširuju coverage i smanjuju MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Predlošci scenarija
Koristite ove ponovljive blueprints za dizajniranje simulacija koje se direktno mapiraju na AADAPT ponašanja.<sup>[[2]](#references)</sup>

### Scenario A – Ekonomska manipulacija flash-loan-om
- **Cilj**: pozajmiti privremeni kapital unutar jedne transakcije kako bi se izobličile AMM cene/liquidity i aktivirali pogrešno procenjeni borrow-i, liquidation-i ili mint-ovi pre otplate.
- **Izvršavanje**:
1. Forkujte target chain i napunite pools likvidnošću sličnoj produkcijskoj.
2. Pozajmite veliki notional putem flash loan-a.
3. Izvršite kalibrisane swaps kako biste prešli granice cena/pragova na koje se oslanja lending, vault ili derivative logika.
4. Pozovite victim contract odmah nakon izobličenja (borrow, liquidate, mint) i otplatite flash loan.
- **Merenje**: Da li je kršenje invariants uspelo? Da li su slippage/price-deviation monitors, circuit breakers ili governance pause hooks aktivirani? Koliko je vremena bilo potrebno da analytics označi abnormalni gas/call graph pattern?

### Scenario B – Trovanje Oracle/data feed-a
- **Cilj**: utvrditi da li manipulated feeds mogu da pokrenu destruktivne automatizovane akcije (masovne liquidation-e, pogrešne settlement-e).
- **Izvršavanje**:
1. Na fork/testnet-u postavite malicious feed ili podesite aggregator weights/quorum/update cadence iznad prihvatljivog odstupanja.
2. Dozvolite dependent contracts da preuzmu poisoned values i izvrše standardnu logiku.
- **Merenje**: Out-of-band alerts na nivou feed-a, aktiviranje fallback oracle-a, primena min/max bound-ova i kašnjenje između pojave anomalije i reakcije operatora.

### Scenario C – Zloupotreba credentials/signing-a
- **Cilj**: testirati da li kompromitovanje jednog signer-a ili automation identiteta omogućava neautorizovane upgrades, promene parametara ili pražnjenje treasury-ja.
- **Izvršavanje**:
1. Popišite identitete sa osetljivim signing pravima (operateri, CI tokens, service accounts koji pozivaju KMS/HSM, multisig učesnici).
2. Simulirajte kompromitovanje (ponovo upotrebite njihove credentials/keys u okviru lab scope-a).
3. Pokušajte privilegovane akcije: upgrade proxies, promenite risk parameters, mint/pause assets ili pokrenite governance proposals.
- **Merenje**: Da li KMS/HSM logs podižu anomaly alerts (doba dana, odstupanje destination-a, burst high-risk operations)? Da li policies ili multisig thresholds sprečavaju unilateral abuse? Da li su throttles/rate limits ili dodatna approvals primenjeni?

### Scenario D – Cross-chain izbegavanje i praznine u traceability-ju
- **Cilj**: proceniti koliko dobro defenders mogu da prate i brzo zaustave sredstva koja se peru kroz bridges, DEX routers i privacy hops.
- **Izvršavanje**:
1. Povežite lock/mint operacije kroz uobičajene bridges, ubacite swaps/mixers na svakom hop-u i održavajte correlation IDs po hop-u.
2. Ubrzajte transfere kako biste opteretili monitoring latency (multi-hop u roku od nekoliko minuta/blocks).
- **Merenje**: Vreme potrebno za korelaciju događaja kroz telemetriju + komercijalne chain analytics, potpunost rekonstruisane putanje, sposobnost identifikovanja choke points za zamrzavanje u stvarnom incidentu i alert fidelity za abnormalni cross-chain velocity/value.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
