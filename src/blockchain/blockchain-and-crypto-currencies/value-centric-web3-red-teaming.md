# मूल्य-केंद्रित Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework, डिजिटल asset systems को निशाना बनाने वाली adversarial actions और techniques का वर्गीकरण करता है।<sup>[[1]](#references)</sup> इसे **threat-modeling backbone** की तरह इस्तेमाल करें: उन सभी components की सूची बनाएँ जो assets को mint, price, authorize या route कर सकते हैं, उन touchpoints को AADAPT techniques से map करें, और फिर ऐसे red-team scenarios चलाएँ जो मापें कि environment अपरिवर्तनीय आर्थिक नुकसान का सामना कर सकता है या नहीं।

## 1. मूल्य-युक्त components की सूची बनाएँ
उन सभी चीज़ों का map बनाएँ जो value state को प्रभावित कर सकती हैं, भले ही वे off-chain हों।<sup>[[2]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, bots या back-office jobs द्वारा उपयोग की जाने वाली signing APIs)। Key IDs, policies, automation identities और approval workflows दर्ज करें।
- Contracts के लिए **Admin और upgrade paths** (proxy admins, governance timelocks, emergency pause keys, parameter registries)। यह भी शामिल करें कि कौन/क्या उन्हें call कर सकता है और किस quorum या delay के तहत।
- **On-chain protocol logic**, जो lending, AMMs, vaults, staking, bridges या settlement rails को संभालता है। इनके मान लिए गए invariants दर्ज करें (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation**, जो transactions बनाती है (market-making bots, CI/CD pipelines, cron jobs, serverless functions)। इनके पास अक्सर API keys या service principals होते हैं, जो signatures का अनुरोध कर सकते हैं।
- **Oracles और data feeds** (aggregator composition, quorum, deviation thresholds, update cadence)। Automated risk logic जिन upstream sources पर निर्भर है, उन सभी को दर्ज करें।
- **Bridges और cross-chain routers** (lock/mint contracts, relayers, settlement jobs), जो chains या custodial stacks को जोड़ते हैं।

परिणाम: एक value-flow diagram, जो दिखाए कि assets कैसे आगे बढ़ते हैं, उनकी आवाजाही को कौन authorize करता है, और कौन-से external signals business logic को प्रभावित करते हैं।

## 2. Components को AADAPT behaviors से map करें
AADAPT taxonomy को हर component के लिए ठोस attack candidates में बदलें।<sup>[[2]](#references)</sup>

| Component | मुख्य AADAPT फोकस |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

इस mapping से यह सुनिश्चित होता है कि आप केवल contracts ही नहीं, बल्कि उन सभी identities/automation का भी परीक्षण करें जो अप्रत्यक्ष रूप से value को प्रभावित कर सकते हैं।

## 3. Attacker की व्यवहार्यता और business impact के आधार पर प्राथमिकता तय करें

1. **Operational कमजोरियाँ**: उजागर CI credentials, अत्यधिक privileges वाले IAM roles, गलत तरीके से configured KMS policies, मनमाने signatures का अनुरोध कर सकने वाले automation accounts, bridge configs वाले public buckets, आदि।
2. **Value-विशिष्ट कमजोरियाँ**: नाज़ुक oracle parameters, multi-party approvals के बिना upgradable contracts, flash-loan के प्रति संवेदनशील liquidity, timelocks को bypass करने वाली governance actions।

Queue पर adversary की तरह काम करें: पहले उन operational footholds से शुरू करें जो आज सफल हो सकते हैं, फिर protocol/economic manipulation के गहन paths पर जाएँ।<sup>[[2]](#references)</sup>

## 4. नियंत्रित और production-जैसे environments में काम करें
- **Forked mainnets / isolated testnets**: bytecode, storage और liquidity को दोहराएँ, ताकि flash-loan paths, oracle drifts और bridge flows वास्तविक funds को छुए बिना end-to-end चल सकें।<sup>[[2]](#references)</sup>
- **Blast-radius planning**: किसी scenario को सक्रिय करने से पहले circuit breakers, pausable modules, rollback runbooks और test-only admin keys तय करें।
- **Stakeholder coordination**: custodians, oracle operators, bridge partners और compliance टीम को सूचित करें, ताकि उनकी monitoring teams इस traffic की अपेक्षा करें।
- **Legal sign-off**: जब simulations regulated rails तक पहुँच सकती हों, तो scope, authorization और stop conditions दर्ज करें।

## 5. AADAPT techniques के अनुरूप telemetry
Telemetry streams को इस तरह instrument करें कि हर scenario से कार्रवाई योग्य detection data मिले।<sup>[[2]](#references)</sup>

- **Chain-level traces**: पूरे call graphs, gas usage, transaction nonces, block timestamps—flash-loan bundles, reentrancy जैसी structures और cross-contract hops को फिर से बनाने के लिए।
- **Application/API logs**: हर on-chain tx को किसी व्यक्ति या automation identity (session ID, OAuth client, API key, CI job ID) से IPs और auth methods सहित जोड़ें।
- **KMS/HSM logs**: हर signature के लिए key ID, caller principal, policy result, destination address और reason codes। Change windows और high-risk operations के baseline तय करें।
- **Oracle/feed metadata**: हर update के लिए data source composition, reported value, rolling averages से deviation, trigger हुए thresholds और इस्तेमाल किए गए failover paths।
- **Bridge/swap traces**: chains के बीच lock/mint/unlock events को correlation IDs, chain IDs, relayer identity और hop timing के साथ correlate करें।
- **Anomaly markers**: slippage spikes, असामान्य collateralization ratios, unusual gas density या cross-chain velocity जैसे derived metrics।

हर चीज़ को scenario IDs या synthetic user IDs से tag करें, ताकि analysts observables को जाँची जा रही AADAPT technique के साथ align कर सकें।

## 6. Purple-team चक्र और maturity metrics
1. नियंत्रित environment में scenario चलाएँ और detections (alerts, dashboards, responders को भेजे गए pages) दर्ज करें।<sup>[[2]](#references)</sup>
2. हर step को विशिष्ट AADAPT techniques और chain/app/KMS/oracle/bridge planes में बने observables से map करें।
3. Detection hypotheses (threshold rules, correlation searches, invariant checks) तैयार करें और लागू करें।
4. तब तक दोबारा चलाएँ, जब तक mean time to detect (MTTD) और mean time to contain (MTTC) business tolerances के अनुरूप न हों और playbooks value loss को भरोसेमंद तरीके से रोक न सकें।

तीन आयामों पर program maturity track करें:<sup>[[2]](#references)</sup>
- **Visibility**: हर critical value path में प्रत्येक plane की telemetry उपलब्ध हो।
- **Coverage**: प्राथमिकता वाली AADAPT techniques का end-to-end परीक्षण किया गया अनुपात।
- **Response**: अपरिवर्तनीय नुकसान से पहले contracts pause करने, keys revoke करने या flows freeze करने की क्षमता।

आम milestones: (1) value inventory और AADAPT mapping पूरी करना, (2) detections लागू करके पहला end-to-end scenario चलाना, (3) coverage बढ़ाने और MTTD/MTTC घटाने के लिए तिमाही purple-team cycles।<sup>[[2]](#references)</sup>

## 7. Scenario templates
इन दोहराए जा सकने वाले blueprints का उपयोग ऐसे simulations बनाने के लिए करें जो सीधे AADAPT behaviors से map हों।<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **उद्देश्य**: एक ही transaction के भीतर अस्थायी capital उधार लेकर AMM prices/liquidity को विकृत करना और चुकाने से पहले गलत मूल्य वाले borrows, liquidations या mints को trigger करना।
- **Execution**:
  1. Target chain को fork करें और pools में production-जैसी liquidity डालें।
  2. Flash loan के ज़रिए बड़ी notional राशि उधार लें।
  3. Lending, vault या derivative logic जिन पर निर्भर है, उन price/threshold boundaries को पार करने के लिए calibrated swaps करें।
  4. विकृति के तुरंत बाद victim contract को invoke करें (borrow, liquidate, mint) और flash loan चुका दें।
- **Measurement**: क्या invariant violation सफल हुआ? क्या slippage/price-deviation monitors, circuit breakers या governance pause hooks trigger हुए? Analytics को असामान्य gas/call graph pattern पहचानने में कितना समय लगा?

### Scenario B – Oracle/data-feed poisoning
- **उद्देश्य**: पता लगाना कि manipulated feeds विनाशकारी automated actions (mass liquidations, गलत settlements) trigger कर सकती हैं या नहीं।
- **Execution**:
  1. Fork/testnet में malicious feed deploy करें या aggregator weights/quorum/update cadence को tolerated deviation से आगे बदलें।
  2. Dependent contracts को poisoned values इस्तेमाल करने दें और उनका सामान्य logic चलने दें।
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, और anomaly शुरू होने से operator response तक का समय।

### Scenario C – Credential/signing abuse
- **उद्देश्य**: जाँचना कि क्या किसी एक signer या automation identity के compromise से unauthorized upgrades, parameter changes या treasury drains संभव हैं।
- **Execution**:
  1. संवेदनशील signing rights वाली identities की सूची बनाएँ (operators, CI tokens, KMS/HSM invoke करने वाले service accounts, multisig participants)।
  2. Lab scope में उनके credentials/keys का दोबारा उपयोग करके compromise का simulation करें।
  3. Privileged actions का प्रयास करें: proxies upgrade करना, risk parameters बदलना, assets mint/pause करना या governance proposals trigger करना।
- **Measurement**: क्या KMS/HSM logs anomaly alerts (दिन का समय, destination drift, high-risk operations की अचानक बढ़ी संख्या) उठाते हैं? क्या policies या multisig thresholds एकतरफा दुरुपयोग रोक सकती हैं? क्या throttles/rate limits या अतिरिक्त approvals लागू हैं?

### Scenario D – Cross-chain evasion और traceability gaps
- **उद्देश्य**: यह जाँचना कि defenders bridges, DEX routers और privacy hops के ज़रिए तेज़ी से launder किए गए assets को कितनी अच्छी तरह trace और रोक सकते हैं।
- **Execution**:
  1. आम bridges पर lock/mint operations को जोड़ें, हर hop पर swaps/mixers शामिल करें, और प्रति-hop correlation IDs बनाए रखें।
  2. Monitoring latency पर दबाव डालने के लिए transfers तेज़ करें (कुछ मिनटों/blocks के भीतर multi-hop)।
- **Measurement**: Telemetry और commercial chain analytics में events correlate करने में लगने वाला समय, reconstructed path की पूर्णता, वास्तविक incident में freezing के choke points पहचानने की क्षमता, और असामान्य cross-chain velocity/value के लिए alert की सटीकता।

## References

- [1] [डिजिटल assets के लिए AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap के रूप में MITRE AADAPT Framework (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
