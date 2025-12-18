# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Matriki ya MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) inarekodi tabia za wawanzi zinazobadilisha thamani za dijitali badala ya miundombinu pekee. Iichukulie kama mgongo wa **threat-modeling backbone**: orodhesha kila sehemu inayoweza mint, kuweka bei, kuidhinisha, au kupitisha mali, panga pointi hizo dhidi ya AADAPT techniques, kisha tengeneza sinario za red-team ambazo zinapima kama mazingira yanaweza kuhimili upotevu wa kiuchumi usioweza kurekebishwa.

## 1. Inventory value-bearing components
Jenga ramani ya kila kitu kinachoweza kuathiri hali ya thamani, hata kama kiko off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Rekodi key IDs, sera, automation identities, na approval workflows.
- **Admin & upgrade paths** kwa contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Jumuisha nani/nini kinaweza kuvitoa, na kwa chini ya quorum au delay gani.
- **On-chain protocol logic** inayoshughulikia lending, AMMs, vaults, staking, bridges, au settlement rails. Andika invariants wanazodai (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** inayojenga transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Hizi mara nyingi zina API keys au service principals zinazoweza kuomba signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Chukua kumbukumbu ya kila upstream inayotegemewa na automated risk logic.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) zinazounganisha chains au custodial stacks pamoja.

Deliverable: mchoro wa mtiririko wa thamani unaoonyesha jinsi mali zinavyosogea, nani anauthoriza kusogea, na ni ishara za nje zipi zinazoathiri business logic.

## 2. Map components to AADAPT behaviors
Tafsiri taxonomy ya AADAPT kuwa wagombea wa mashambulizi kwa kila sehemu.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Ramani hii inahakikisha unajaribu si tu contracts, bali kila identity/automation inayoweza kwa njia isiyo ya moja kwa moja kuyasimamia thamani.

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts that can request arbitrary signatures, public buckets with bridge configs, n.k.
2. **Value-specific weaknesses**: fragile oracle parameters, upgradable contracts without multi-party approvals, flash-loan sensitive liquidity, governance actions that bypass timelocks.

Fanya kazi kwa foleni kama mwanzishi: anza na footholds za operesheni ambazo zinaweza kufanikiwa leo, kisha endelea kwenye njia za kina za udanganyifu wa itifaki/uchumi.

## 4. Execute in controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: nakili bytecode, storage, na liquidity ili flash-loan paths, oracle drifts, na bridge flows zifanye end-to-end bila kugusa fedha halisi.
- **Blast-radius planning**: fafanua circuit breakers, pausable modules, rollback runbooks, na test-only admin keys kabla ya kutekeleza sinario.
- **Stakeholder coordination**: taarifa custodians, oracle operators, bridge partners, na compliance ili timu zao za ufuatiliaji zitambue trafiki.
- **Legal sign-off**: andika scope, authorization, na stop conditions wakati simulations zinaweza kuvuka rails zinazosimamiwa.

## 5. Telemetry aligned with AADAPT techniques
Sanifu telemetry streams ili kila sinario izalishwe data ya kugundua inayoweza kuchukuliwa hatua.

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps—to reconstruct flash-loan bundles, reentrancy-like structures, na cross-contract hops.
- **Application/API logs**: sambaza kila on-chain tx nyuma kwa identity ya binadamu au automation (session ID, OAuth client, API key, CI job ID) pamoja na IPs na auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address, na reason codes kwa kila signature. Tambua windows za mabadiliko na operesheni za high-risk.
- **Oracle/feed metadata**: per-update data source composition, reported value, deviation from rolling averages, thresholds triggered, na failover paths zilizoendeshwa.
- **Bridge/swap traces**: sambaza lock/mint/unlock events across chains na correlation IDs, chain IDs, relayer identity, na hop timing.
- **Anomaly markers**: metrics zilizotokana kama slippage spikes, abnormal collateralization ratios, unusual gas density, au cross-chain velocity.

Tag kila kitu na scenario IDs au synthetic user IDs ili wachambuzi waweze kulinganisha observables na AADAPT technique inayofanywa.

## 6. Purple-team loop & maturity metrics
1. Endesha sinario katika mazingira yaliyodhibitiwa na shika detections (alerts, dashboards, responders paged).
2. Ramani kila hatua kwa AADAPT techniques maalum pamoja na observables zilizoletwa katika chain/app/KMS/oracle/bridge planes.
3. Tengeneza na weka hypotheses za kugundua (threshold rules, correlation searches, invariant checks).
4. Re-run hadi mean time to detect (MTTD) na mean time to contain (MTTC) zikidhi uvumilivu wa biashara na playbooks zikizuia upotevu wa thamani kwa uhakika.

Fuatilia ukuaji wa mpango kwenye nguzo tatu:
- **Visibility**: kila njia muhimu ya thamani ina telemetry katika kila plane.
- **Coverage**: sehemu ya AADAPT techniques zawe zinazoshughulikiwa end-to-end.
- **Response**: uwezo wa kuweka pause contracts, ku-revoke keys, au ku-freeze flows kabla ya upotevu usioweza kurekebishwa.

Milestones za kawaida: (1) kukamilika kwa inventory ya thamani + AADAPT mapping, (2) sinario ya kwanza ya end-to-end na detections zilizoanzishwa, (3) mzunguko wa purple-team kila robo unaopanua coverage na kupunguza MTTD/MTTC.

## 7. Scenario templates
Tumia blueprints hizi zinazoweza kurudiwa kubuni simulations zinazolingana moja kwa moja na tabia za AADAPT.

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
