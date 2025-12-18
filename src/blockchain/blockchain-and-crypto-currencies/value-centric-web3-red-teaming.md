# मूल्य-केंद्रित Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

The MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix उन हमलावर व्यवहारों को कैप्चर करता है जो सिर्फ इन्फ्रास्ट्रक्चर नहीं बल्कि डिजिटल वैल्यू को प्रभावित करते हैं। इसे एक खतरा-मॉडलिंग backbone की तरह मानें: उन सभी घटकों की सूची बनाएं जो assets को mint, price, authorize, या route कर सकते हैं, उन टचपॉइंट्स को AADAPT techniques से मैप करें, और फिर ऐसे red-team परिदृश्य चलाएं जो मापें कि क्या environment अपरिवर्तनीय आर्थिक नुकसान से बच सकता है।

## 1. मूल्य-वाहक घटकों की सूची
वो सब कुछ मानचित्रित करें जो value state को प्रभावित कर सकता है, भले ही वह off-chain क्यों न हो।

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Capture key IDs, policies, automation identities, and approval workflows.
- **Admin & upgrade paths** for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). शामिल करें कि कौन/क्या उन्हें कॉल कर सकता है और किस quorum या delay के तहत।
- **On-chain protocol logic** handling lending, AMMs, vaults, staking, bridges, or settlement rails. उन invariants को डोक्युमेंट करें जिन पर ये निर्भर करते हैं (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** that builds transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). अक्सर इनमें API keys या service principals होते हैं जो signatures request कर सकते हैं।
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). हर upstream नोट करें जिस पर automated risk logic निर्भर करती है।
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) जो chains या custodial stacks को जोड़ते हैं।

Deliverable: एक value-flow diagram जो दर्शाए कि assets कैसे मूव करते हैं, किसने मूवमेंट authorize किया, और कौन से external signals business logic को प्रभावित करते हैं।

## 2. घटकों को AADAPT व्यवहारों से मैप करें
AADAPT टैक्सोनॉमी को हर घटक के लिए ठोस attack candidates में अनुवाद करें।

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

यह मैपिंग सुनिश्चित करती है कि आप सिर्फ contracts को ही नहीं बल्कि हर identity/automation का परीक्षण कर रहे हैं जो अप्रत्यक्ष रूप से value को steer कर सकता है।

## 3. attacker feasibility बनाम business impact के आधार पर प्राथमिकता तय करें

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts that can request arbitrary signatures, public buckets with bridge configs, आदि।
2. **Value-specific weaknesses**: fragile oracle parameters, upgradable contracts बिना multi-party approvals के, flash-loan sensitive liquidity, governance actions जो timelocks को bypass कर देते हैं।

क्यू को एक adversary की तरह काम करें: पहले उन operational footholds से शुरू करें जो आज सफल हो सकते हैं, फिर गहरे protocol/economic manipulation पथों की ओर बढ़ें।

## 4. Controlled, production-realistic environments में Execute करें
- **Forked mainnets / isolated testnets**: bytecode, storage, और liquidity को replicate करें ताकि flash-loan paths, oracle drifts, और bridge flows end-to-end चलें बिना असली फंड छुए।
- **Blast-radius planning**: circuit breakers, pausable modules, rollback runbooks, और test-only admin keys को परिभाषित करें पहले किसी scenario को detonate करने से पहले।
- **Stakeholder coordination**: custodians, oracle operators, bridge partners, और compliance को notify करें ताकि उनके monitoring teams उस ट्रैफ़िक की उम्मीद करें।
- **Legal sign-off**: scope, authorization, और stop conditions document करें जब simulations regulated rails को पार कर सकते हैं।

## 5. AADAPT techniques के अनुरूप Telemetry
Telemetry streams को instrument करें ताकि हर scenario actionable detection डेटा उत्पन्न करे।

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps— ताकि flash-loan bundles, reentrancy-like structures, और cross-contract hops को reconstruct किया जा सके।
- **Application/API logs**: हर on-chain tx को एक human या automation identity (session ID, OAuth client, API key, CI job ID) के साथ tie करें, IPs और auth methods सहित।
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address, और हर signature के लिए reason codes। change windows और high-risk operations के baselines रखें।
- **Oracle/feed metadata**: प्रति-update data source composition, reported value, rolling averages से deviation, triggered thresholds, और exercised failover paths।
- **Bridge/swap traces**: lock/mint/unlock events को chains के across correlate करें correlation IDs, chain IDs, relayer identity, और hop timing के साथ।
- **Anomaly markers**: derived metrics जैसे slippage spikes, abnormal collateralization ratios, unusual gas density, या cross-chain velocity।

हर चीज़ को scenario IDs या synthetic user IDs के साथ tag करें ताकि analysts observables को उस AADAPT technique के साथ align कर सकें जिसे exercise किया जा रहा है।

## 6. Purple-team loop & maturity metrics
1. Controlled environment में scenario चलाएं और detections capture करें (alerts, dashboards, responders paged)।
2. हर स्टेप को specific AADAPT techniques और chain/app/KMS/oracle/bridge planes में उत्पन्न observables के साथ मैप करें।
3. Detection hypotheses (threshold rules, correlation searches, invariant checks) तैयार करें और deploy करें।
4. तब तक re-run करें जब तक mean time to detect (MTTD) और mean time to contain (MTTC) business tolerances को पूरा न कर लें और playbooks reliably value loss को रोक दें।

प्रोग्राम परिपक्वता को तीन अक्षों पर ट्रैक करें:
- **Visibility**: हर critical value path में प्रत्येक plane के लिए telemetry मौजूद हो।
- **Coverage**: प्राथमिक AADAPT techniques में से कितने end-to-end exercise किए गए।
- **Response**: contracts को pause करने, keys revoke करने, या flows freeze करने की क्षमता इससे पहले कि irreversible loss हो।

Typical milestones: (1) पूरा किया गया value inventory + AADAPT mapping, (2) पहला end-to-end scenario जिसमें detections लागू हों, (3) तिमाही purple-team cycles जो coverage बढ़ाएँ और MTTD/MTTC घटाएँ।

## 7. Scenario templates
इन repeatable blueprints का उपयोग करें ताकि simulations सीधे AADAPT व्यवहारों से map कर सकें।

### Scenario A – Flash-loan economic manipulation
- **Objective**: एक transaction के अंदर transient capital उधार लेकर AMM prices/liquidity को distort करना और mispriced borrows, liquidations, या mints ट्रिगर करना फिर repay करने से पहले।
- **Execution**:
1. Target chain को fork करें और production-जैसी liquidity के साथ pools seed करें।
2. बड़ी notional flash loan के माध्यम से borrow करें।
3. Calibrated swaps करें ताकि lending, vault, या derivative logic पर निर्भर price/threshold boundaries cross हों।
4. distortion के तुरंत बाद victim contract को invoke करें (borrow, liquidate, mint) और flash loan repay करें।
- **Measurement**: क्या invariant violation सफल हुआ? क्या slippage/price-deviation monitors, circuit breakers, या governance pause hooks triggered हुए? analytics ने abnormal gas/call graph pattern को flag करने में कितना समय लिया?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: यह निर्धारित करना कि क्या manipulated feeds destructive automated actions (mass liquidations, incorrect settlements) ट्रिगर कर सकती हैं।
- **Execution**:
1. Fork/testnet में malicious feed deploy करें या aggregator weights/quorum/update cadence को tolerated deviation से बाहर adjust करें।
2. Dependent contracts को poisoned values consume करने दें और उनका standard logic execute होने दें।
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, और anomaly onset और operator response के बीच latency।

### Scenario C – Credential/signing abuse
- **Objective**: परीक्षण करें कि क्या एक single signer या automation identity के compromise से unauthorized upgrades, parameter changes, या treasury drains संभव हैं।
- **Execution**:
1. Sensitive signing rights वाले identities की enumeration करें (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants)।
2. Lab scope में compromise का simulation करें (उनके credentials/keys का reuse)।
3. Privileged actions की कोशिश करें: upgrade proxies, change risk parameters, mint/pause assets, या governance proposals trigger करना।
- **Measurement**: क्या KMS/HSM logs anomaly alerts उठाते हैं (time-of-day, destination drift, burst of high-risk operations)? क्या policies या multisig thresholds unilateral abuse रोक सकते हैं? क्या throttles/rate limits या अतिरिक्त approvals लागू हैं?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: आंकें कि defenders कितनी अच्छी तरह assets को rapidly bridges, DEX routers, और privacy hops के across trace और interdict कर सकते हैं।
- **Execution**:
1. सामान्य bridges के across lock/mint operations को chain together करें, हर hop पर swaps/mixers interleave करें, और per-hop correlation IDs रखें।
2. Monitoring latency को stress करने के लिए transfers accelerate करें (multi-hop within minutes/blocks)।
- **Measurement**: Telemetry + commercial chain analytics के across events को correlate करने का समय, reconstructed path की completeness, real incident में freezing के लिए choke points की पहचान करने की क्षमता, और abnormal cross-chain velocity/value के लिए alert fidelity।

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
