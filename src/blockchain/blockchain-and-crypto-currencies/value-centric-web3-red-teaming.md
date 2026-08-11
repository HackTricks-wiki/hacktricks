# Red Teaming ya Web3 Inayozingatia Thamani (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Mfumo wa MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) huainisha vitendo na techniques za kiadui zinazolenga mifumo ya digital asset.<sup>[[1]](#references)</sup> Uchukulie kama **msingi wa threat-modeling**: orodhesha kila component inayoweza kuunda, kuweka bei, kuidhinisha, au kuelekeza assets, linganisha sehemu hizo za mawasiliano na techniques za AADAPT, kisha endesha scenarios za red-team zinazopima ikiwa mazingira yanaweza kuzuia hasara ya kiuchumi isiyoweza kurekebishwa.

## 1. Orodhesha components zenye thamani
Tengeneza ramani ya kila kitu kinachoweza kuathiri hali ya thamani, hata kama kiko off-chain.<sup>[[2]](#references)</sup>

- **Huduma za kusaini za custodial** (HSM/KMS clusters, Vault/KMaaS, signing APIs zinazotumiwa na bots au back-office jobs). Rekodi key IDs, policies, automation identities, na approval workflows.
- **Njia za admin & upgrade** za contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Jumuisha nani/kitu gani kinaweza kuziita, na chini ya quorum au delay gani.
- **Mantiki ya protocol iliyo on-chain** inayoshughulikia lending, AMMs, vaults, staking, bridges, au settlement rails. Andika invariants wanazotegemea (oracle prices, collateral ratios, rebalance cadence…).
- **Automation ya off-chain** inayounda transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Mara nyingi huwa na API keys au service principals zinazoweza kuomba signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Tambua kila upstream inayotegemewa na risk logic ya kiotomatiki.
- **Bridges na cross-chain routers** (lock/mint contracts, relayers, settlement jobs) zinazounganisha chains au custodial stacks.

Deliverable: mchoro wa value-flow unaoonyesha jinsi assets zinavyosogea, nani anayeidhinisha uhamishaji, na ni signals zipi za nje zinazoathiri business logic.

## 2. Linganisha components na mienendo ya AADAPT
Tafsiri taxonomy ya AADAPT kuwa attack candidates halisi kwa kila component.<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Ulinganishaji huu unahakikisha kuwa unatest si contracts pekee, bali pia kila identity/automation inayoweza kuelekeza thamani kwa njia isiyo ya moja kwa moja.

## 3. Panga kipaumbele kwa uwezekano wa attacker dhidi ya athari ya biashara

1. **Udhaifu wa kiutendaji**: CI credentials zilizo wazi, IAM roles zenye ruhusa kupita kiasi, KMS policies zilizosanidiwa vibaya, automation accounts zinazoweza kuomba signatures holela, public buckets zenye bridge configs, n.k.
2. **Udhaifu mahususi wa thamani**: oracle parameters dhaifu, contracts zinazoweza ku-upgrade bila approvals za pande nyingi, liquidity inayoweza kuathiriwa na flash-loan, governance actions zinazopita timelocks.

Fanya kazi kwenye queue kama adversary: anza na operational footholds zinazoweza kufanikiwa leo, kisha endelea kwenye njia za kina za protocol/economic manipulation.<sup>[[2]](#references)</sup>

## 4. Tekeleza katika mazingira yaliyodhibitiwa na yanayofanana na production
- **Forked mainnets / isolated testnets**: rudufu bytecode, storage, na liquidity ili flash-loan paths, oracle drifts, na bridge flows ziendeshwe end-to-end bila kugusa fedha halisi.<sup>[[2]](#references)</sup>
- **Mipango ya blast radius**: fafanua circuit breakers, pausable modules, rollback runbooks, na test-only admin keys kabla ya kuanzisha scenario.
- **Uratibu wa stakeholders**: wajulishe custodians, oracle operators, bridge partners, na compliance ili monitoring teams zao zitayarishe traffic hiyo.
- **Idhini ya kisheria**: andika scope, authorization, na stop conditions wakati simulations zinaweza kuvuka regulated rails.

## 5. Telemetry inayolingana na techniques za AADAPT
Sanidi telemetry streams ili kila scenario izalishe data ya detection inayoweza kuchukuliwa hatua.<sup>[[2]](#references)</sup>

- **Chain-level traces**: call graphs kamili, matumizi ya gas, transaction nonces, block timestamps—ili kujenga upya flash-loan bundles, miundo inayofanana na reentrancy, na cross-contract hops.
- **Application/API logs**: unganisha kila on-chain tx na human au automation identity (session ID, OAuth client, API key, CI job ID) pamoja na IPs na auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address, na reason codes kwa kila signature. Weka baseline ya change windows na high-risk operations.
- **Oracle/feed metadata**: muundo wa data source kwa kila update, reported value, deviation kutoka rolling averages, thresholds zilizowashwa, na failover paths zilizotumika.
- **Bridge/swap traces**: linganisha lock/mint/unlock events kati ya chains ukitumia correlation IDs, chain IDs, relayer identity, na hop timing.
- **Anomaly markers**: metrics zinazotokana kama slippage spikes, collateralization ratios zisizo za kawaida, gas density isiyo ya kawaida, au cross-chain velocity.

Tag kila kitu kwa scenario IDs au synthetic user IDs ili analysts waweze kuoanisha observables na technique ya AADAPT inayofanyiwa majaribio.

## 6. Purple-team loop & metrics za maturity
1. Endesha scenario katika mazingira yaliyodhibitiwa na rekodi detections (alerts, dashboards, responders waliopigiwa).<sup>[[2]](#references)</sup>
2. Linganisha kila hatua na techniques mahususi za AADAPT pamoja na observables zilizozalishwa katika chain/app/KMS/oracle/bridge planes.
3. Unda na deploy detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Rudia hadi mean time to detect (MTTD) na mean time to contain (MTTC) zifikie tolerances za biashara, na playbooks zizuie loss ya thamani kwa uhakika.

Fuatilia maturity ya program kwenye axes tatu:<sup>[[2]](#references)</sup>
- **Visibility**: kila value path muhimu ina telemetry katika kila plane.
- **Coverage**: asilimia ya techniques za AADAPT zilizopewa kipaumbele na kufanyiwa majaribio end-to-end.
- **Response**: uwezo wa kusitisha contracts, kubatilisha keys, au kufreeze flows kabla ya hasara isiyoweza kurekebishwa.

Milestones za kawaida: (1) value inventory + AADAPT mapping iliyokamilika, (2) scenario ya kwanza ya end-to-end yenye detections zilizotekelezwa, (3) purple-team cycles za kila robo mwaka zinazopanua coverage na kupunguza MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Scenario templates
Tumia blueprints hizi zinazoweza kurudiwa ili kubuni simulations zinazolingana moja kwa moja na mienendo ya AADAPT.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Lengo**: kukopa capital ya muda mfupi ndani ya transaction moja ili kupotosha AMM prices/liquidity na kuchochea borrows, liquidations, au mints zenye bei isiyo sahihi kabla ya kurejesha.
- **Utekelezaji**:
1. Fanya fork ya target chain na ujaze pools kwa liquidity inayofanana na production.
2. Kopa notional kubwa kupitia flash loan.
3. Fanya swaps zilizopimwa ili kuvuka price/threshold boundaries zinazotegemewa na lending, vault, au derivative logic.
4. Ita victim contract mara moja baada ya distortion (borrow, liquidate, mint) na urejeshe flash loan.
- **Upimaji**: Je, invariant violation ilifanikiwa? Je, slippage/price-deviation monitors, circuit breakers, au governance pause hooks ziliwashwa? Ilichukua muda gani hadi analytics ione gas/call graph pattern isiyo ya kawaida?

### Scenario B – Oracle/data-feed poisoning
- **Lengo**: kubaini ikiwa feeds zilizomanipuliwa zinaweza kuchochea automated actions zenye uharibifu (mass liquidations, settlements zisizo sahihi).
- **Utekelezaji**:
1. Katika fork/testnet, deploy malicious feed au rekebisha aggregator weights/quorum/update cadence ipite deviation inayokubalika.
2. Ruhusu contracts tegemezi zitumie values zilizo poisoned na kutekeleza logic yake ya kawaida.
- **Upimaji**: Alerts za nje ya kawaida kwenye feed level, activation ya fallback oracle, utekelezaji wa min/max bounds, na latency kati ya kuanza kwa anomaly na response ya operator.

### Scenario C – Credential/signing abuse
- **Lengo**: kutest ikiwa ku-compromise signer mmoja au automation identity kunawezesha upgrades, parameter changes, au treasury drains zisizoidhinishwa.
- **Utekelezaji**:
1. Orodhesha identities zenye signing rights nyeti (operators, CI tokens, service accounts zinazoita KMS/HSM, multisig participants).
2. Simulate compromise (tumia tena credentials/keys zao ndani ya scope ya lab).
3. Jaribu privileged actions: upgrade proxies, badilisha risk parameters, mint/pause assets, au anzisha governance proposals.
- **Upimaji**: Je, KMS/HSM logs zinaibua anomaly alerts (time-of-day, destination drift, burst ya high-risk operations)? Je, policies au multisig thresholds zinaweza kuzuia abuse ya mtu mmoja? Je, throttles/rate limits au approvals za ziada zinatekelezwa?

### Scenario D – Cross-chain evasion & traceability gaps
- **Lengo**: kutathmini jinsi defenders wanavyoweza kufuatilia na kuzuia assets zinazolaundishwa haraka kupitia bridges, DEX routers, na privacy hops.
- **Utekelezaji**:
1. Unganisha lock/mint operations katika bridges za kawaida, changanya swaps/mixers kwenye kila hop, na dumisha correlation IDs za kila hop.
2. Harakisha transfers ili kusisitiza monitoring latency (multi-hop ndani ya dakika/blocks).
- **Upimaji**: Muda wa kuoanisha events kati ya telemetry + commercial chain analytics, ukamilifu wa path iliyojengwa upya, uwezo wa kutambua choke points za kufreeze katika incident halisi, na alert fidelity kwa cross-chain velocity/value isiyo ya kawaida.

## References

- [1] [Mfumo wa AADAPT(TM) wa Cyber Threats kwa Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Mfumo wa MITRE AADAPT kama Roadmap ya Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
