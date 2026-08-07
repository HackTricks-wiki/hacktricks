# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix inarekodi tabia za washambuliaji wanaobadilisha thamani ya kidijitali badala ya miundombinu pekee. Ichukulie kama **msingi wa threat-modeling**: orodhesha kila sehemu inayoweza kuunda, kupanga bei, kuidhinisha, au kuelekeza assets, mapping touchpoints hizo kwa mbinu za AADAPT, kisha endesha scenarios za red-team zinazopima ikiwa mazingira yanaweza kuhimili hasara ya kiuchumi isiyoweza kurejeshwa.

## 1. Tengeneza orodha ya components zenye thamani
Tengeneza ramani ya kila kitu kinachoweza kuathiri hali ya thamani, hata kama kiko off-chain.<sup>[[1]](#references)</sup>

- **Huduma za custodial signing** (HSM/KMS clusters, Vault/KMaaS, signing APIs zinazotumiwa na bots au back-office jobs). Rekodi key IDs, policies, automation identities, na approval workflows.
- **Admin & upgrade paths** za contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Jumuisha ni nani/kitu gani kinaweza kuziita, na chini ya quorum au delay gani.
- **On-chain protocol logic** inayoshughulikia lending, AMMs, vaults, staking, bridges, au settlement rails. Andika invariants zinazoaminika (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** inayounda transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Mara nyingi hushikilia API keys au service principals zinazoweza kuomba signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Andika kila upstream inayotegemewa na automated risk logic.
- **Bridges na cross-chain routers** (lock/mint contracts, relayers, settlement jobs) zinazounganisha chains au custodial stacks.

Deliverable: value-flow diagram inayoonyesha jinsi assets zinavyosogea, nani anayeidhinisha movement, na ni signals zipi za nje zinazoathiri business logic.

## 2. Map components kwa AADAPT behaviors
Tafsiri AADAPT taxonomy kuwa attack candidates halisi kwa kila component.<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Mapping hii inahakikisha unatest si contracts pekee, bali kila identity/automation inayoweza kuelekeza value kwa njia isiyo ya moja kwa moja.

## 3. Panga kipaumbele kwa attacker feasibility dhidi ya business impact

1. **Operational weaknesses**: CI credentials zilizo exposed, IAM roles zenye privileges nyingi, KMS policies zilizosanidiwa vibaya, automation accounts zinazoweza kuomba arbitrary signatures, public buckets zenye bridge configs, n.k.
2. **Value-specific weaknesses**: oracle parameters dhaifu, upgradable contracts zisizo na multi-party approvals, liquidity iliyo sensitive kwa flash-loan, governance actions zinazopita timelocks.

Shughulikia queue kama adversary: anza na operational footholds zinazoweza kufanikiwa leo, kisha songa kwenye deep protocol/economic manipulation paths.<sup>[[1]](#references)</sup>

## 4. Tekeleza katika mazingira yaliyodhibitiwa na yanayofanana na production
- **Forked mainnets / isolated testnets**: nakili bytecode, storage, na liquidity ili flash-loan paths, oracle drifts, na bridge flows ziendesheke end-to-end bila kugusa funds halisi.<sup>[[1]](#references)</sup>
- **Blast-radius planning**: fafanua circuit breakers, pausable modules, rollback runbooks, na test-only admin keys kabla ya kuanzisha scenario.
- **Stakeholder coordination**: wajulishe custodians, oracle operators, bridge partners, na compliance ili monitoring teams zao zitayarishe traffic hiyo.
- **Legal sign-off**: andika scope, authorization, na stop conditions pale simulations zinapoweza kuvuka regulated rails.

## 5. Telemetry iliyolinganishwa na mbinu za AADAPT
Instrument telemetry streams ili kila scenario izalishe detection data inayoweza kutumika.<sup>[[1]](#references)</sup>

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps—ili kujenga upya flash-loan bundles, reentrancy-like structures, na cross-contract hops.
- **Application/API logs**: unganisha kila on-chain tx na human au automation identity (session ID, OAuth client, API key, CI job ID) pamoja na IPs na auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address, na reason codes kwa kila signature. Weka baseline ya change windows na high-risk operations.
- **Oracle/feed metadata**: per-update data source composition, reported value, deviation kutoka rolling averages, thresholds zilizochochewa, na failover paths zilizotumiwa.
- **Bridge/swap traces**: correlate lock/mint/unlock events kwenye chains mbalimbali kwa kutumia correlation IDs, chain IDs, relayer identity, na hop timing.
- **Anomaly markers**: derived metrics kama slippage spikes, collateralization ratios zisizo za kawaida, gas density isiyo ya kawaida, au cross-chain velocity.

Tag kila kitu kwa scenario IDs au synthetic user IDs ili analysts waweze kuoanisha observables na AADAPT technique inayotekelezwa.

## 6. Purple-team loop & maturity metrics
1. Endesha scenario katika mazingira yaliyodhibitiwa na capture detections (alerts, dashboards, responders waliopaged).<sup>[[1]](#references)</sup>
2. Map kila step kwa AADAPT techniques husika pamoja na observables zilizozalishwa katika chain/app/KMS/oracle/bridge planes.
3. Tengeneza na deploy detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Rudia hadi mean time to detect (MTTD) na mean time to contain (MTTC) zifikie business tolerances, na playbooks ziweze kusimamisha value loss kwa uhakika.

Fuatilia program maturity kwenye axes tatu:<sup>[[1]](#references)</sup>
- **Visibility**: kila critical value path ina telemetry katika kila plane.
- **Coverage**: proportion ya prioritized AADAPT techniques zilizotekelezwa end-to-end.
- **Response**: uwezo wa kupause contracts, kurevoke keys, au kufreeze flows kabla ya hasara isiyoweza kurejeshwa.

Milestones za kawaida: (1) value inventory + AADAPT mapping iliyokamilika, (2) scenario ya kwanza ya end-to-end yenye detections zilizotekelezwa, (3) quarterly purple-team cycles zinazopanua coverage na kupunguza MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Scenario templates
Tumia blueprints hizi zinazoweza kurudiwa ili kuunda simulations zinazomap moja kwa moja na AADAPT behaviors.<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: kukopa transient capital ndani ya transaction moja ili kubadilisha AMM prices/liquidity na kuchochea borrows, liquidations, au mints zenye bei isiyo sahihi kabla ya kulipa.
- **Execution**:
1. Fork target chain na seed pools kwa production-like liquidity.
2. Kopa large notional kupitia flash loan.
3. Fanya calibrated swaps ili kuvuka price/threshold boundaries zinazotegemewa na lending, vault, au derivative logic.
4. Iite victim contract mara moja baada ya distortion (borrow, liquidate, mint) na ulipie flash loan.
- **Measurement**: Je, invariant violation ilifanikiwa? Je, slippage/price-deviation monitors, circuit breakers, au governance pause hooks zilichochewa? Ilichukua muda gani hadi analytics zitambue abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: kubaini ikiwa manipulated feeds zinaweza kuchochea destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. Katika fork/testnet, deploy malicious feed au badilisha aggregator weights/quorum/update cadence zaidi ya tolerated deviation.
2. Ruhusu dependent contracts zitumie poisoned values na kutekeleza standard logic yao.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, na latency kati ya anomaly onset na operator response.

### Scenario C – Credential/signing abuse
- **Objective**: kutest ikiwa compromising signer mmoja au automation identity moja kunawezesha unauthorized upgrades, parameter changes, au treasury drains.
- **Execution**:
1. Orodhesha identities zenye sensitive signing rights (operators, CI tokens, service accounts zinazoita KMS/HSM, multisig participants).
2. Simulate compromise (tumia tena credentials/keys zao ndani ya lab scope).
3. Jaribu privileged actions: upgrade proxies, badilisha risk parameters, mint/pause assets, au trigger governance proposals.
- **Measurement**: Je, KMS/HSM logs zinaleta anomaly alerts (time-of-day, destination drift, burst ya high-risk operations)? Je, policies au multisig thresholds zinaweza kuzuia unilateral abuse? Je, throttles/rate limits au additional approvals zinatekelezwa?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: kutathmini jinsi defenders wanavyoweza kufuatilia na kuzuia assets zinazolaundishwa kwa kasi kupitia bridges, DEX routers, na privacy hops.
- **Execution**:
1. Unganisha lock/mint operations kwenye common bridges mbalimbali, changanya swaps/mixers kwenye kila hop, na tunza per-hop correlation IDs.
2. Harakisha transfers ili ku-stress monitoring latency (multi-hop ndani ya dakika/blocks).
- **Measurement**: Muda wa ku-correlate events kwenye telemetry + commercial chain analytics, ukamilifu wa reconstructed path, uwezo wa kutambua choke points za kufreeze katika real incident, na alert fidelity kwa abnormal cross-chain velocity/value.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
