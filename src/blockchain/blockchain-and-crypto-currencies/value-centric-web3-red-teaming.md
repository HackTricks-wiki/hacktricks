# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix ऐसे attacker behaviors को कैप्चर करता है जो केवल infrastructure के बजाय digital value को manipulate करते हैं। इसे **threat-modeling backbone** मानें: ऐसे हर component की सूची बनाएं जो assets को mint, price, authorize या route कर सकता है, उन touchpoints को AADAPT techniques से map करें, और फिर ऐसे red-team scenarios चलाएं जो यह मापें कि environment irreversible economic loss का सामना कर सकता है या नहीं।

## 1. Value-bearing components की inventory बनाएं
हर उस चीज़ का map बनाएं जो value state को प्रभावित कर सकती है, भले ही वह off-chain हो।<sup>[[1]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, bots या back-office jobs द्वारा उपयोग की जाने वाली signing APIs)। Key IDs, policies, automation identities और approval workflows दर्ज करें।
- Contracts के लिए **Admin & upgrade paths** (proxy admins, governance timelocks, emergency pause keys, parameter registries)। इसमें यह भी शामिल करें कि इन्हें कौन/क्या call कर सकता है और किस quorum या delay के तहत।
- **On-chain protocol logic**, जो lending, AMMs, vaults, staking, bridges या settlement rails संभालता है। इनके द्वारा माने गए invariants को document करें (oracle prices, collateral ratios, rebalance cadence…)।
- Transactions बनाने वाला **Off-chain automation** (market-making bots, CI/CD pipelines, cron jobs, serverless functions)। इनमें अक्सर API keys या service principals होते हैं जो signatures का अनुरोध कर सकते हैं।
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence)। Automated risk logic द्वारा उपयोग किए जाने वाले हर upstream को नोट करें।
- **Bridges और cross-chain routers** (lock/mint contracts, relayers, settlement jobs), जो chains या custodial stacks को जोड़ते हैं।

Deliverable: एक value-flow diagram, जिसमें दिखाया गया हो कि assets कैसे move होते हैं, movement को कौन authorize करता है, और कौन-से external signals business logic को प्रभावित करते हैं।

## 2. Components को AADAPT behaviors से map करें
AADAPT taxonomy को प्रत्येक component के लिए concrete attack candidates में translate करें।<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

यह mapping सुनिश्चित करती है कि आप केवल contracts ही नहीं, बल्कि हर उस identity/automation को भी test करें जो अप्रत्यक्ष रूप से value को steer कर सकती है।

## 3. Attacker feasibility बनाम business impact के आधार पर प्राथमिकता तय करें

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, ऐसे automation accounts जो arbitrary signatures का अनुरोध कर सकते हैं, bridge configs वाले public buckets आदि।
2. **Value-specific weaknesses**: fragile oracle parameters, multi-party approvals के बिना upgradable contracts, flash-loan sensitive liquidity, ऐसे governance actions जो timelocks को bypass करते हैं।

Queue को adversary की तरह handle करें: उन operational footholds से शुरू करें जो आज ही सफल हो सकते हैं, फिर deep protocol/economic manipulation paths की ओर बढ़ें।<sup>[[1]](#references)</sup>

## 4. Controlled, production-realistic environments में execute करें
- **Forked mainnets / isolated testnets**: bytecode, storage और liquidity को replicate करें, ताकि flash-loan paths, oracle drifts और bridge flows real funds को छुए बिना end-to-end चल सकें।<sup>[[1]](#references)</sup>
- **Blast-radius planning**: scenario detonate करने से पहले circuit breakers, pausable modules, rollback runbooks और test-only admin keys निर्धारित करें।
- **Stakeholder coordination**: custodians, oracle operators, bridge partners और compliance को सूचित करें, ताकि उनकी monitoring teams इस traffic की अपेक्षा कर सकें।
- **Legal sign-off**: जब simulations regulated rails को cross कर सकती हों, तब scope, authorization और stop conditions document करें।

## 5. AADAPT techniques के अनुरूप telemetry
Telemetry streams को इस तरह instrument करें कि हर scenario actionable detection data उत्पन्न करे।<sup>[[1]](#references)</sup>

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps—ताकि flash-loan bundles, reentrancy-like structures और cross-contract hops को reconstruct किया जा सके।
- **Application/API logs**: प्रत्येक on-chain tx को किसी human या automation identity (session ID, OAuth client, API key, CI job ID) से IPs और auth methods सहित जोड़ें।
- **KMS/HSM logs**: हर signature के लिए key ID, caller principal, policy result, destination address और reason codes। Change windows और high-risk operations का baseline बनाएं।
- **Oracle/feed metadata**: प्रत्येक update के लिए data source composition, reported value, rolling averages से deviation, triggered thresholds और exercised failover paths।
- **Bridge/swap traces**: correlation IDs, chain IDs, relayer identity और hop timing के साथ chains के बीच lock/mint/unlock events को correlate करें।
- **Anomaly markers**: derived metrics जैसे slippage spikes, abnormal collateralization ratios, unusual gas density या cross-chain velocity।

हर चीज़ को scenario IDs या synthetic user IDs से tag करें, ताकि analysts observables को exercise की जा रही AADAPT technique के साथ align कर सकें।

## 6. Purple-team loop & maturity metrics
1. Controlled environment में scenario चलाएं और detections (alerts, dashboards, responders paged) capture करें।<sup>[[1]](#references)</sup>
2. प्रत्येक step को specific AADAPT techniques और chain/app/KMS/oracle/bridge planes में उत्पन्न observables से map करें।
3. Detection hypotheses (threshold rules, correlation searches, invariant checks) तैयार करके deploy करें।
4. तब तक re-run करें जब तक mean time to detect (MTTD) और mean time to contain (MTTC) business tolerances को पूरा न करें और playbooks value loss को विश्वसनीय रूप से रोक न दें।

Program maturity को तीन axes पर track करें:<sup>[[1]](#references)</sup>
- **Visibility**: हर critical value path में प्रत्येक plane के लिए telemetry मौजूद हो।
- **Coverage**: end-to-end exercise की गई prioritized AADAPT techniques का proportion।
- **Response**: irreversible loss से पहले contracts को pause करने, keys revoke करने या flows freeze करने की क्षमता।

Typical milestones: (1) completed value inventory + AADAPT mapping, (2) implemented detections वाला पहला end-to-end scenario, (3) coverage बढ़ाने और MTTD/MTTC घटाने वाले quarterly purple-team cycles।<sup>[[1]](#references)</sup>

## 7. Scenario templates
इन repeatable blueprints का उपयोग ऐसे simulations design करने के लिए करें जो सीधे AADAPT behaviors से map हों।<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: एक ही transaction के भीतर transient capital borrow करके AMM prices/liquidity को distort करना और repay करने से पहले mispriced borrows, liquidations या mints trigger करना।
- **Execution**:
1. Target chain को fork करें और pools में production-like liquidity seed करें।
2. Flash loan के माध्यम से बड़ा notional borrow करें।
3. Lending, vault या derivative logic द्वारा उपयोग की जाने वाली price/threshold boundaries को cross करने के लिए calibrated swaps करें।
4. Distortion के तुरंत बाद victim contract को invoke करें (borrow, liquidate, mint) और flash loan repay करें।
- **Measurement**: क्या invariant violation सफल हुआ? क्या slippage/price-deviation monitors, circuit breakers या governance pause hooks trigger हुए? Analytics द्वारा abnormal gas/call graph pattern flag किए जाने में कितना समय लगा?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: यह निर्धारित करना कि manipulated feeds destructive automated actions (mass liquidations, incorrect settlements) trigger कर सकती हैं या नहीं।
- **Execution**:
1. Fork/testnet में malicious feed deploy करें या aggregator weights/quorum/update cadence को tolerated deviation से आगे adjust करें।
2. Dependent contracts को poisoned values consume करने दें और उनका standard logic execute होने दें।
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement और anomaly onset से operator response तक की latency।

### Scenario C – Credential/signing abuse
- **Objective**: यह test करना कि किसी single signer या automation identity के compromise से unauthorized upgrades, parameter changes या treasury drains संभव होते हैं या नहीं।
- **Execution**:
1. Sensitive signing rights वाली identities की enumeration करें (operators, CI tokens, KMS/HSM invoke करने वाले service accounts, multisig participants)।
2. Compromise simulate करें (lab scope के भीतर उनके credentials/keys का re-use करें)।
3. Privileged actions का प्रयास करें: proxies upgrade करना, risk parameters बदलना, assets mint/pause करना या governance proposals trigger करना।
- **Measurement**: क्या KMS/HSM logs anomaly alerts raise करते हैं (time-of-day, destination drift, high-risk operations का burst)? क्या policies या multisig thresholds unilateral abuse को रोक सकते हैं? क्या throttles/rate limits या additional approvals enforced हैं?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: यह evaluate करना कि defenders bridges, DEX routers और privacy hops के माध्यम से तेजी से launder किए गए assets को कितनी अच्छी तरह trace और interdict कर सकते हैं।
- **Execution**:
1. Common bridges के across lock/mint operations को chain करें, प्रत्येक hop पर swaps/mixers interleave करें और per-hop correlation IDs बनाए रखें।
2. Monitoring latency को stress करने के लिए transfers को accelerate करें (minutes/blocks के भीतर multi-hop)।
- **Measurement**: telemetry + commercial chain analytics में events correlate करने का समय, reconstructed path की completeness, real incident में freezing के लिए choke points पहचानने की क्षमता, और abnormal cross-chain velocity/value के लिए alert fidelity।

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
