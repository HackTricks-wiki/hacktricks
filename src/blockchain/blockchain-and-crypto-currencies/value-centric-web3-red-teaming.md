# Web3 Inayolenga Thamani Red Teaming (MITRE AADAPT)

Mfumo wa MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) huainisha vitendo na mbinu za washambuliaji zinazolenga mifumo ya digital asset.<sup>[[1]](#references)</sup> Uuchukulie kama **msingi wa threat-modeling**: orodhesha kila component inayoweza ku-mint, ku-price, ku-authorize au ku-route assets, linganisha touchpoint hizo na mbinu za AADAPT, kisha endesha scenarios za red-team zinazopima ikiwa mazingira yanaweza kuzuia hasara ya kiuchumi isiyoweza kubatilishwa.

## 1. Inventory ya components zenye thamani
Tengeneza ramani ya kila kitu kinachoweza kuathiri hali ya thamani, hata kama kiko off-chain.<sup>[[2]](#references)</sup>

- **Huduma za custodial signing** (HSM/KMS clusters, Vault/KMaaS, signing APIs zinazotumiwa na bots au back-office jobs). Rekodi key IDs, policies, automation identities na approval workflows.
- **Njia za admin na upgrade** za contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Jumuisha nani/kitu gani kinaweza kuziita, na chini ya quorum au delay gani.
- **On-chain protocol logic** inayoshughulikia lending, AMMs, vaults, staking, bridges au settlement rails. Andika invariants zinazoaminika (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** inayounda transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Mara nyingi hushikilia API keys au service principals zinazoweza kuomba signatures.
- **Oracles na data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Tambua kila upstream inayotegemewa na automated risk logic.
- **Bridges na cross-chain routers** (lock/mint contracts, relayers, settlement jobs) zinazounganisha chains au custodial stacks.

Deliverable: mchoro wa value-flow unaoonyesha jinsi assets zinavyosonga, nani ana-authorize movement, na ni signals zipi za nje zinazoathiri business logic.

## 2. Linganisha components na tabia za AADAPT
Tafsiri taxonomy ya AADAPT kuwa attack candidates halisi kwa kila component.<sup>[[2]](#references)</sup>

| Component | Mwelekeo mkuu wa AADAPT |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Mapping hii inahakikisha kuwa unatest si contracts pekee, bali pia kila identity/automation inayoweza kuelekeza thamani kwa njia isiyo ya moja kwa moja.

## 3. Panga kipaumbele kulingana na uwezekano wa attacker dhidi ya athari kwa biashara

1. **Operational weaknesses**: CI credentials zilizo wazi, IAM roles zenye privileges nyingi, KMS policies zilizosanidiwa vibaya, automation accounts zinazoweza kuomba signatures kiholela, public buckets zenye bridge configs, n.k.
2. **Value-specific weaknesses**: oracle parameters dhaifu, upgradable contracts zisizo na multi-party approvals, liquidity inayoweza kuathiriwa na flash loans, governance actions zinazopita timelocks.

Shughulikia queue kama adversary: anza na operational footholds zinazoweza kufanikiwa leo, kisha endelea kwenye deep protocol/economic manipulation paths.<sup>[[2]](#references)</sup>

## 4. Tekeleza katika mazingira yaliyodhibitiwa na yanayofanana na production
- **Forked mainnets / isolated testnets**: nakili bytecode, storage na liquidity ili flash-loan paths, oracle drifts na bridge flows ziendeshe end-to-end bila kugusa funds halisi.<sup>[[2]](#references)</sup>
- **Blast-radius planning**: fafanua circuit breakers, pausable modules, rollback runbooks na test-only admin keys kabla ya kuanzisha scenario.
- **Stakeholder coordination**: wajulishe custodians, oracle operators, bridge partners na compliance ili monitoring teams zao zitarajie traffic hiyo.
- **Legal sign-off**: andika scope, authorization na stop conditions wakati simulations zinaweza kuvuka regulated rails.

## 5. Telemetry inayolingana na mbinu za AADAPT
Sanidi telemetry streams ili kila scenario itoe detection data inayoweza kutumika.<sup>[[2]](#references)</sup>

- **Chain-level traces**: call graphs kamili, gas usage, transaction nonces na block timestamps—ili kujenga upya flash-loan bundles, miundo inayofanana na reentrancy na cross-contract hops.
- **Application/API logs**: unganisha kila on-chain tx na human au automation identity (session ID, OAuth client, API key, CI job ID), pamoja na IPs na auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address na reason codes kwa kila signature. Weka baseline ya change windows na high-risk operations.
- **Oracle/feed metadata**: kwa kila update, data source composition, reported value, deviation kutoka rolling averages, thresholds zilizo-triggeriwa na failover paths zilizotumika.
- **Bridge/swap traces**: linganisha lock/mint/unlock events katika chains kupitia correlation IDs, chain IDs, relayer identity na hop timing.
- **Anomaly markers**: derived metrics kama slippage spikes, collateralization ratios zisizo za kawaida, gas density isiyo ya kawaida au cross-chain velocity.

Tag kila kitu kwa scenario IDs au synthetic user IDs ili analysts waweze kuoanisha observables na mbinu ya AADAPT inayofanyiwa majaribio.

## 6. Purple-team loop na vipimo vya maturity
1. Endesha scenario katika mazingira yaliyodhibitiwa na ukusanye detections (alerts, dashboards, responders waliopigiwa ukurasa).<sup>[[2]](#references)</sup>
2. Linganisha kila hatua na mbinu mahususi za AADAPT pamoja na observables zilizozalishwa katika chain/app/KMS/oracle/bridge planes.
3. Tengeneza na deploy detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Rudia hadi mean time to detect (MTTD) na mean time to contain (MTTC) zifikie business tolerances, na playbooks ziweze kusimamisha value loss kwa uaminifu.

Fuatilia maturity ya program kwenye axes tatu:<sup>[[2]](#references)</sup>
- **Visibility**: kila critical value path ina telemetry katika kila plane.
- **Coverage**: uwiano wa mbinu za AADAPT zilizopewa kipaumbele na kufanyiwa majaribio end-to-end.
- **Response**: uwezo wa kupause contracts, kurevoke keys au kufreeze flows kabla ya hasara isiyoweza kubatilishwa.

Milestones za kawaida: (1) value inventory + AADAPT mapping iliyokamilika, (2) scenario ya kwanza ya end-to-end yenye detections zilizotekelezwa, (3) purple-team cycles za kila robo mwaka zinazopanua coverage na kupunguza MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Scenario templates
Tumia blueprints hizi zinazoweza kurudiwa ili kubuni simulations zinazo-map moja kwa moja kwenye tabia za AADAPT.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: kukopa capital ya muda ndani ya transaction moja ili kupotosha AMM prices/liquidity na ku-trigger mispriced borrows, liquidations au mints kabla ya kulipa tena.
- **Execution**:
1. Fanya fork ya target chain na ujaze pools kwa liquidity inayofanana na production.
2. Kopa notional kubwa kupitia flash loan.
3. Fanya swaps zilizopimwa ili kuvuka price/threshold boundaries zinazotegemewa na lending, vault au derivative logic.
4. Iite victim contract mara moja baada ya distortion (borrow, liquidate, mint) na ulipe flash loan.
- **Measurement**: Je, invariant violation ilifanikiwa? Je, slippage/price-deviation monitors, circuit breakers au governance pause hooks zili-triggeriwa? Ilichukua muda gani hadi analytics itambue abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: kubaini ikiwa feeds zilizomanipuliwa zinaweza ku-trigger destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. Katika fork/testnet, deploy malicious feed au rekebisha aggregator weights/quorum/update cadence kupita deviation inayokubalika.
2. Acha dependent contracts zitumie poisoned values na zitekeleze standard logic yao.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement na muda kati ya anomaly kuanza na operator response.

### Scenario C – Credential/signing abuse
- **Objective**: kujaribu ikiwa compromise ya signer mmoja au automation identity moja inawezesha unauthorized upgrades, parameter changes au treasury drains.
- **Execution**:
1. Orodhesha identities zenye sensitive signing rights (operators, CI tokens, service accounts zinazoita KMS/HSM, multisig participants).
2. Simulate compromise (tumia tena credentials/keys zao ndani ya lab scope).
3. Jaribu privileged actions: upgrade proxies, badilisha risk parameters, mint/pause assets au trigger governance proposals.
- **Measurement**: Je, KMS/HSM logs zina-raise anomaly alerts (time-of-day, destination drift, burst ya high-risk operations)? Je, policies au multisig thresholds zinaweza kuzuia unilateral abuse? Je, throttles/rate limits au additional approvals zinatekelezwa?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: kutathmini jinsi defenders wanavyoweza kufuatilia na kuzuia assets zinazolaundishwa kwa kasi kupitia bridges, DEX routers na privacy hops.
- **Execution**:
1. Unganisha lock/mint operations katika common bridges, changanya swaps/mixers kwenye kila hop, na dumisha per-hop correlation IDs.
2. Harakisha transfers ili kusababisha monitoring latency (multi-hop ndani ya minutes/blocks).
- **Measurement**: Muda wa kuoanisha events katika telemetry + commercial chain analytics, ukamilifu wa path iliyojengwa upya, uwezo wa kutambua choke points za kufreeze katika real incident, na alert fidelity ya cross-chain velocity/value isiyo ya kawaida.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
