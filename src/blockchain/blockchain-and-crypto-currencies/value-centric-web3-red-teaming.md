# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework는 digital asset system을 대상으로 하는 adversarial action과 technique을 분류합니다.<sup>[[1]](#references)</sup> 이를 **threat-modeling backbone**으로 취급하세요. asset을 mint, price, authorize 또는 route할 수 있는 모든 component를 열거하고, 해당 접점을 AADAPT technique에 매핑한 다음, environment가 되돌릴 수 없는 경제적 손실을 견딜 수 있는지 측정하는 red-team scenario를 수행합니다.

## 1. Inventory value-bearing components
off-chain인 경우에도 value state에 영향을 줄 수 있는 모든 항목을 맵으로 작성합니다.<sup>[[2]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, bot 또는 back-office job에서 사용하는 signing API). key ID, policy, automation identity 및 approval workflow를 기록합니다.
- **Admin & upgrade paths** for contracts (proxy admin, governance timelock, emergency pause key, parameter registry). 이를 호출할 수 있는 주체와 quorum 또는 delay 조건을 포함합니다.
- **On-chain protocol logic**: lending, AMM, vault, staking, bridge 또는 settlement rail을 처리하는 logic. 해당 logic이 전제로 하는 invariant(oracle price, collateral ratio, rebalance cadence…)를 문서화합니다.
- **Off-chain automation**: transaction을 생성하는 automation(market-making bot, CI/CD pipeline, cron job, serverless function). 이러한 component에는 signature를 요청할 수 있는 API key 또는 service principal이 포함되는 경우가 많습니다.
- **Oracles & data feeds** (aggregator composition, quorum, deviation threshold, update cadence). automated risk logic이 의존하는 모든 upstream을 기록합니다.
- **Bridges and cross-chain routers** (lock/mint contract, relayer, settlement job): chain 또는 custodial stack을 연결합니다.

산출물: asset의 이동 방식, 이동을 authorize하는 주체, business logic에 영향을 주는 external signal을 보여주는 value-flow diagram.

## 2. Map components to AADAPT behaviors
AADAPT taxonomy를 component별 구체적인 attack candidate로 변환합니다.<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

이 매핑을 통해 contract뿐 아니라 간접적으로 value를 조정할 수 있는 모든 identity/automation을 테스트할 수 있습니다.

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: 노출된 CI credential, 과도한 권한이 부여된 IAM role, 잘못 구성된 KMS policy, arbitrary signature를 요청할 수 있는 automation account, bridge config가 포함된 public bucket 등.
2. **Value-specific weaknesses**: 취약한 oracle parameter, multi-party approval이 없는 upgradable contract, flash-loan에 민감한 liquidity, timelock을 우회하는 governance action.

공격자처럼 queue를 처리하세요. 오늘 당장 성공할 수 있는 operational foothold부터 시작한 다음, 심층적인 protocol/economic manipulation path로 진행합니다.<sup>[[2]](#references)</sup>

## 4. Execute in controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: bytecode, storage 및 liquidity를 복제하여 실제 funds에 영향을 주지 않고 flash-loan path, oracle drift 및 bridge flow를 end-to-end로 실행합니다.<sup>[[2]](#references)</sup>
- **Blast-radius planning**: scenario를 실행하기 전에 circuit breaker, pausable module, rollback runbook 및 test-only admin key를 정의합니다.
- **Stakeholder coordination**: custodian, oracle operator, bridge partner 및 compliance team에 알려 monitoring team이 해당 traffic을 예상할 수 있도록 합니다.
- **Legal sign-off**: simulation이 regulated rail에 영향을 줄 수 있는 경우 scope, authorization 및 stop condition을 문서화합니다.

## 5. Telemetry aligned with AADAPT techniques
모든 scenario가 실행 가능한 detection data를 생성하도록 telemetry stream을 구성합니다.<sup>[[2]](#references)</sup>

- **Chain-level traces**: full call graph, gas usage, transaction nonce, block timestamp를 수집하여 flash-loan bundle, reentrancy-like structure 및 cross-contract hop을 재구성합니다.
- **Application/API logs**: 각 on-chain tx를 human 또는 automation identity(session ID, OAuth client, API key, CI job ID)에 IP 및 auth method와 함께 연결합니다.
- **KMS/HSM logs**: 모든 signature에 대해 key ID, caller principal, policy result, destination address 및 reason code를 기록합니다. 변경 window와 high-risk operation의 baseline을 설정합니다.
- **Oracle/feed metadata**: 각 update의 data source composition, reported value, rolling average와의 deviation, trigger된 threshold 및 실행된 failover path를 기록합니다.
- **Bridge/swap traces**: correlation ID, chain ID, relayer identity 및 hop timing을 사용하여 chain 간 lock/mint/unlock event를 상호 연관시킵니다.
- **Anomaly markers**: slippage spike, 비정상적인 collateralization ratio, unusual gas density 또는 cross-chain velocity와 같은 derived metric을 수집합니다.

모든 항목에 scenario ID 또는 synthetic user ID를 지정하여 analyst가 observable을 실행 중인 AADAPT technique에 맞춰 분석할 수 있도록 합니다.

## 6. Purple-team loop & maturity metrics
1. controlled environment에서 scenario를 실행하고 detection(alert, dashboard, responder 호출)을 수집합니다.<sup>[[2]](#references)</sup>
2. 각 단계를 구체적인 AADAPT technique 및 chain/app/KMS/oracle/bridge plane에서 생성된 observable에 매핑합니다.
3. detection hypothesis(threshold rule, correlation search, invariant check)를 수립하고 배포합니다.
4. mean time to detect (MTTD) 및 mean time to contain (MTTC)가 business tolerance를 충족하고 playbook이 value loss를 안정적으로 중단할 때까지 재실행합니다.

다음 세 가지 축으로 program maturity를 추적합니다.<sup>[[2]](#references)</sup>
- **Visibility**: 모든 critical value path에 각 plane의 telemetry가 존재하는지 여부.
- **Coverage**: 우선순위가 지정된 AADAPT technique 중 end-to-end로 실행된 비율.
- **Response**: irreversible loss가 발생하기 전에 contract를 pause하고, key를 revoke하거나 flow를 freeze할 수 있는 능력.

일반적인 milestone은 다음과 같습니다: (1) value inventory 및 AADAPT mapping 완료, (2) detection이 구현된 첫 end-to-end scenario, (3) coverage를 확장하고 MTTD/MTTC를 줄이는 quarterly purple-team cycle.<sup>[[2]](#references)</sup>

## 7. Scenario templates
AADAPT behavior에 직접 매핑되는 simulation을 설계할 때 다음의 반복 가능한 blueprint를 사용합니다.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: 하나의 transaction 안에서 일시적인 capital을 borrow하여 AMM price/liquidity를 왜곡하고, repay하기 전에 mispriced borrow, liquidation 또는 mint를 trigger하는지 확인합니다.
- **Execution**:
1. target chain을 fork하고 production과 유사한 liquidity로 pool을 구성합니다.
2. flash loan을 통해 큰 notional을 borrow합니다.
3. lending, vault 또는 derivative logic이 의존하는 price/threshold boundary를 넘도록 calibrated swap을 수행합니다.
4. distortion 직후 victim contract를 호출하여(borrow, liquidate, mint) flash loan을 repay합니다.
- **Measurement**: invariant violation이 성공했습니까? slippage/price-deviation monitor, circuit breaker 또는 governance pause hook이 trigger되었습니까? analytics가 비정상적인 gas/call graph pattern을 감지하기까지 얼마나 걸렸습니까?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: manipulated feed가 destructive automated action(mass liquidation, incorrect settlement)을 trigger할 수 있는지 확인합니다.
- **Execution**:
1. fork/testnet에서 malicious feed를 deploy하거나 aggregator weight/quorum/update cadence를 허용 가능한 deviation을 초과하도록 조정합니다.
2. dependent contract가 poisoned value를 사용하여 standard logic을 실행하도록 합니다.
- **Measurement**: feed-level out-of-band alert, fallback oracle activation, min/max bound enforcement 및 anomaly 발생부터 operator response까지의 latency를 측정합니다.

### Scenario C – Credential/signing abuse
- **Objective**: 단일 signer 또는 automation identity가 compromise되었을 때 unauthorized upgrade, parameter change 또는 treasury drain이 가능한지 테스트합니다.
- **Execution**:
1. sensitive signing right를 가진 identity(operator, CI token, KMS/HSM을 호출하는 service account, multisig participant)를 열거합니다.
2. compromise를 simulation합니다(lab scope 내에서 해당 credential/key를 재사용).
3. privileged action을 시도합니다: proxy upgrade, risk parameter 변경, asset mint/pause 또는 governance proposal 실행.
- **Measurement**: KMS/HSM log가 anomaly alert(time-of-day, destination drift, high-risk operation burst)을 발생시킵니까? policy 또는 multisig threshold가 unilateral abuse를 방지합니까? throttle/rate limit 또는 additional approval이 적용됩니까?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: bridge, DEX router 및 privacy hop을 통해 빠르게 launder되는 asset을 defender가 얼마나 효과적으로 추적하고 차단할 수 있는지 평가합니다.
- **Execution**:
1. common bridge에서 lock/mint operation을 연결하고, 각 hop에서 swap/mixer를 interleave하며, hop별 correlation ID를 유지합니다.
2. monitoring latency를 stress하기 위해 transfer를 가속합니다(수 분/수 block 내 multi-hop).
- **Measurement**: telemetry와 commercial chain analytics 간 event correlation에 걸리는 시간, 재구성된 path의 완전성, 실제 incident에서 freeze할 choke point를 식별하는 능력, 비정상적인 cross-chain velocity/value에 대한 alert fidelity를 측정합니다.

## References

- [1] [Digital Asset을 위한 AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap으로서의 MITRE AADAPT Framework (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
