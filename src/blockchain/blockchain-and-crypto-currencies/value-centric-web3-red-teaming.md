# 가치 중심 Web3 Red Teaming (MITRE AADAPT)

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) 프레임워크는 digital asset 시스템을 대상으로 하는 adversarial action과 technique을 분류합니다.<sup>[[1]](#references)</sup> 이를 **threat-modeling backbone**으로 활용하세요. 즉, asset을 mint, price, authorize 또는 route할 수 있는 모든 구성 요소를 열거하고, 해당 접점을 AADAPT technique에 매핑한 다음, 환경이 되돌릴 수 없는 경제적 손실을 견딜 수 있는지 측정하는 Red Team 시나리오를 실행합니다.

## 1. 가치 보유 구성 요소 인벤토리 작성
off-chain에 있더라도 value state에 영향을 줄 수 있는 모든 항목을 맵으로 작성합니다.<sup>[[2]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, bot 또는 back-office job이 사용하는 signing APIs). key ID, policy, automation identity, approval workflow를 기록합니다.
- **Contract의 Admin 및 upgrade 경로** (proxy admin, governance timelock, emergency pause key, parameter registry). 이를 호출할 수 있는 주체와 대상, 그리고 필요한 quorum 또는 delay를 포함합니다.
- **Lending, AMM, vault, staking, bridge 또는 settlement rail을 처리하는 on-chain protocol logic**. 해당 로직이 전제로 삼는 invariant(oracle price, collateral ratio, rebalance cadence…)를 문서화합니다.
- **Transaction을 생성하는 off-chain automation** (market-making bot, CI/CD pipeline, cron job, serverless function). 이러한 구성 요소에는 signature를 요청할 수 있는 API key 또는 service principal이 포함되는 경우가 많습니다.
- **Oracle 및 data feed** (aggregator composition, quorum, deviation threshold, update cadence). 자동화된 risk logic이 의존하는 모든 upstream을 기록합니다.
- **Bridge 및 cross-chain router** (lock/mint contract, relayer, settlement job). chain 또는 custodial stack을 서로 연결합니다.

산출물: asset의 이동 방식, 이동을 authorize하는 주체, business logic에 영향을 주는 external signal을 보여주는 value-flow diagram.

## 2. 구성 요소를 AADAPT behavior에 매핑
AADAPT taxonomy를 각 구성 요소별 구체적인 attack 후보로 변환합니다.<sup>[[2]](#references)</sup>

| 구성 요소 | 주요 AADAPT 초점 |
| --- | --- |
| Signing/KMS estate | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracle/feed | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocol | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipeline | Compromised bot/CI identity, batch replay, unauthorized deployment |
| Bridge/router | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

이 매핑을 통해 contract뿐 아니라 간접적으로 value의 흐름을 조정할 수 있는 모든 identity/automation을 테스트할 수 있습니다.

## 3. Attacker feasibility와 business impact를 기준으로 우선순위 지정

1. **Operational weakness**: 노출된 CI credential, 과도한 권한의 IAM role, 잘못 구성된 KMS policy, 임의의 signature를 요청할 수 있는 automation account, bridge config가 포함된 public bucket 등.
2. **Value-specific weakness**: 취약한 oracle parameter, multi-party approval이 없는 upgradable contract, flash-loan에 민감한 liquidity, timelock을 우회하는 governance action.

adversary처럼 queue를 처리합니다. 오늘 당장 성공할 수 있는 operational foothold에서 시작한 다음, 심층적인 protocol/economic manipulation 경로로 진행합니다.<sup>[[2]](#references)</sup>

## 4. 통제된 production-realistic 환경에서 실행
- **Forked mainnet / isolated testnet**: bytecode, storage 및 liquidity를 복제하여 실제 funds에 영향을 주지 않고 flash-loan 경로, oracle drift 및 bridge flow를 end-to-end로 실행합니다.<sup>[[2]](#references)</sup>
- **Blast-radius planning**: scenario를 실행하기 전에 circuit breaker, pausable module, rollback runbook 및 test-only admin key를 정의합니다.
- **Stakeholder coordination**: custodian, oracle operator, bridge partner 및 compliance 담당자에게 알려 monitoring team이 해당 traffic을 예상할 수 있도록 합니다.
- **Legal sign-off**: simulation이 regulated rail을 통과할 수 있는 경우 scope, authorization 및 stop condition을 문서화합니다.

## 5. AADAPT technique에 맞춘 telemetry
모든 scenario가 실행 가능한 detection data를 생성하도록 telemetry stream을 구성합니다.<sup>[[2]](#references)</sup>

- **Chain-level trace**: 전체 call graph, gas 사용량, transaction nonce, block timestamp를 수집하여 flash-loan bundle, reentrancy 유사 구조 및 cross-contract hop을 재구성합니다.
- **Application/API log**: 각 on-chain tx를 human 또는 automation identity(session ID, OAuth client, API key, CI job ID)에 IP 및 auth method와 함께 연결합니다.
- **KMS/HSM log**: 모든 signature에 대해 key ID, caller principal, policy result, destination address 및 reason code를 기록합니다. 변경 window와 high-risk operation의 baseline을 설정합니다.
- **Oracle/feed metadata**: update별 data source composition, reported value, rolling average와의 deviation, trigger된 threshold 및 실행된 failover 경로를 기록합니다.
- **Bridge/swap trace**: correlation ID, chain ID, relayer identity 및 hop timing을 사용하여 chain 간 lock/mint/unlock event를 상호 연관합니다.
- **Anomaly marker**: slippage spike, 비정상적인 collateralization ratio, 특이한 gas density 또는 cross-chain velocity와 같은 파생 metric을 기록합니다.

모든 항목에 scenario ID 또는 synthetic user ID를 태그하여 analyst가 observables를 실행된 AADAPT technique과 연결할 수 있도록 합니다.

## 6. Purple-team loop 및 maturity metric
1. 통제된 환경에서 scenario를 실행하고 detection(alert, dashboard, responder 호출)을 수집합니다.<sup>[[2]](#references)</sup>
2. 각 단계를 구체적인 AADAPT technique과 chain/app/KMS/oracle/bridge plane에서 생성된 observable에 매핑합니다.
3. Detection hypothesis(threshold rule, correlation search, invariant check)를 수립하고 배포합니다.
4. mean time to detect (MTTD) 및 mean time to contain (MTTC)가 business tolerance를 충족하고 playbook이 value loss를 안정적으로 중단할 때까지 다시 실행합니다.

다음 세 가지 축으로 program maturity를 추적합니다.<sup>[[2]](#references)</sup>
- **Visibility**: 모든 critical value path에 각 plane의 telemetry가 존재하는지 여부.
- **Coverage**: 우선순위가 지정된 AADAPT technique 중 end-to-end로 실행된 비율.
- **Response**: irreversible loss가 발생하기 전에 contract를 pause하고, key를 revoke하거나 flow를 freeze할 수 있는 능력.

일반적인 milestone: (1) value inventory 및 AADAPT mapping 완료, (2) detection이 구현된 첫 end-to-end scenario, (3) coverage를 확대하고 MTTD/MTTC를 줄이는 quarterly purple-team cycle.<sup>[[2]](#references)</sup>

## 7. Scenario template
AADAPT behavior에 직접 매핑되는 simulation을 설계할 때 다음과 같은 반복 가능한 blueprint를 사용합니다.<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: 한 transaction 내부에서 일시적인 capital을 borrow하여 AMM price/liquidity를 왜곡하고, 상환하기 전에 잘못 책정된 borrow, liquidation 또는 mint를 trigger합니다.
- **Execution**:
1. 대상 chain을 fork하고 production과 유사한 liquidity로 pool을 구성합니다.
2. Flash loan을 통해 큰 notional을 borrow합니다.
3. Lending, vault 또는 derivative logic이 의존하는 price/threshold 경계를 넘도록 조정된 swap을 수행합니다.
4. 왜곡 직후 victim contract를 호출하여(borrow, liquidate, mint) flash loan을 상환합니다.
- **Measurement**: invariant violation이 성공했습니까? Slippage/price-deviation monitor, circuit breaker 또는 governance pause hook이 trigger되었습니까? Analytics가 비정상적인 gas/call graph pattern을 탐지하기까지 얼마나 걸렸습니까?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: 조작된 feed가 destructive automated action(mass liquidation, incorrect settlement)을 trigger할 수 있는지 확인합니다.
- **Execution**:
1. Fork/testnet에서 malicious feed를 배포하거나 aggregator weight/quorum/update cadence를 허용된 deviation 범위를 벗어나도록 조정합니다.
2. dependent contract가 poisoned value를 소비하고 standard logic을 실행하도록 둡니다.
- **Measurement**: Feed-level out-of-band alert, fallback oracle activation, min/max bound enforcement, anomaly 발생부터 operator response까지의 latency를 측정합니다.

### Scenario C – Credential/signing abuse
- **Objective**: 단일 signer 또는 automation identity가 compromise되었을 때 unauthorized upgrade, parameter change 또는 treasury drain이 가능한지 테스트합니다.
- **Execution**:
1. 민감한 signing right를 가진 identity(operator, CI token, KMS/HSM을 호출하는 service account, multisig participant)를 열거합니다.
2. Lab scope 내에서 해당 credential/key를 재사용하여 compromise를 simulation합니다.
3. Privileged action을 시도합니다: proxy upgrade, risk parameter 변경, asset mint/pause 또는 governance proposal trigger.
- **Measurement**: KMS/HSM log가 anomaly alert(time-of-day, destination drift, high-risk operation burst)을 생성합니까? Policy 또는 multisig threshold가 unilateral abuse를 방지할 수 있습니까? Throttle/rate limit 또는 추가 approval이 적용됩니까?

### Scenario D – Cross-chain evasion 및 traceability gap
- **Objective**: Bridge, DEX router 및 privacy hop을 통해 신속하게 launder된 asset을 defender가 얼마나 효과적으로 추적하고 차단할 수 있는지 평가합니다.
- **Execution**:
1. Common bridge에서 lock/mint operation을 연결하고, 각 hop에서 swap/mixer를 interleave하며, hop별 correlation ID를 유지합니다.
2. Monitoring latency를 stress하기 위해 transfer를 가속합니다(수 분 또는 수 block 내 multi-hop).
- **Measurement**: Telemetry와 commercial chain analytics 간 event correlation 시간, 재구성된 path의 완전성, 실제 incident에서 freeze할 choke point를 식별하는 능력, 비정상적인 cross-chain velocity/value에 대한 alert fidelity를 측정합니다.

## References

- [1] [Digital Asset을 위한 AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap으로서의 MITRE AADAPT Framework (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
