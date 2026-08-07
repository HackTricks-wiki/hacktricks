# 가치 중심 Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix는 단순히 인프라만 다루는 것이 아니라 디지털 가치를 조작하는 공격자의 행동을 정리합니다. 이를 **threat-modeling의 backbone**으로 활용하세요. 자산을 발행하거나, 가격을 책정하거나, 승인하거나, 라우팅할 수 있는 모든 구성 요소를 열거하고, 해당 접점을 AADAPT techniques에 매핑한 다음, 환경이 되돌릴 수 없는 경제적 손실을 견딜 수 있는지 측정하는 red-team 시나리오를 실행합니다.

## 1. 가치가 포함된 구성 요소 인벤토리 작성
온체인 외부에 있더라도 가치 상태에 영향을 줄 수 있는 모든 요소를 매핑합니다.<sup>[[1]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, bots 또는 back-office jobs에서 사용하는 signing APIs). key IDs, policies, automation identities, approval workflows를 기록합니다.
- **Admin & upgrade paths** for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). 이를 호출할 수 있는 주체와 필요한 quorum 또는 delay도 포함합니다.
- **On-chain protocol logic**: lending, AMMs, vaults, staking, bridges 또는 settlement rails를 처리하는 로직입니다. 해당 로직이 가정하는 invariants(oracle prices, collateral ratios, rebalance cadence…)를 문서화합니다.
- **Off-chain automation**: transactions를 생성하는 구성 요소입니다(market-making bots, CI/CD pipelines, cron jobs, serverless functions). 이러한 구성 요소는 종종 signatures를 요청할 수 있는 API keys 또는 service principals를 보유합니다.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). 자동화된 risk logic이 의존하는 모든 upstream을 기록합니다.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs): chains 또는 custodial stacks를 연결합니다.

산출물: 자산의 이동 방식, 이동을 승인하는 주체, business logic에 영향을 주는 외부 신호를 보여주는 value-flow diagram.

## 2. 구성 요소를 AADAPT behaviors에 매핑
AADAPT taxonomy를 각 구성 요소별 구체적인 attack candidates로 변환합니다.<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

이 매핑을 통해 contracts뿐 아니라 간접적으로 가치를 조정할 수 있는 모든 identity/automation도 테스트할 수 있습니다.

## 3. 공격자 실행 가능성과 business impact를 기준으로 우선순위 지정

1. **Operational weaknesses**: 노출된 CI credentials, 과도한 권한이 부여된 IAM roles, 잘못 구성된 KMS policies, 임의의 signatures를 요청할 수 있는 automation accounts, bridge configs가 저장된 public buckets 등.
2. **Value-specific weaknesses**: 취약한 oracle parameters, multi-party approvals 없이 upgradable contracts, flash-loan에 민감한 liquidity, timelocks를 우회하는 governance actions.

공격자처럼 queue를 처리합니다. 오늘 당장 성공할 수 있는 operational footholds부터 시작한 뒤, 심층적인 protocol/economic manipulation paths로 진행합니다.<sup>[[1]](#references)</sup>

## 4. 통제되고 production-realistic한 환경에서 실행
- **Forked mainnets / isolated testnets**: bytecode, storage, liquidity를 복제하여 실제 funds에 영향을 주지 않고 flash-loan paths, oracle drifts, bridge flows를 end-to-end로 실행합니다.<sup>[[1]](#references)</sup>
- **Blast-radius planning**: 시나리오를 실행하기 전에 circuit breakers, pausable modules, rollback runbooks, test-only admin keys를 정의합니다.
- **Stakeholder coordination**: custodians, oracle operators, bridge partners, compliance에 통지하여 monitoring teams가 해당 traffic을 예상할 수 있도록 합니다.
- **Legal sign-off**: simulations가 regulated rails를 넘나들 수 있는 경우 scope, authorization, stop conditions를 문서화합니다.

## 5. AADAPT techniques에 맞춘 Telemetry
모든 시나리오가 실행 가능한 detection data를 생성하도록 telemetry streams를 구성합니다.<sup>[[1]](#references)</sup>

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps를 수집하여 flash-loan bundles, reentrancy-like structures, cross-contract hops를 재구성합니다.
- **Application/API logs**: 각 on-chain tx를 IPs 및 auth methods와 함께 human 또는 automation identity(session ID, OAuth client, API key, CI job ID)에 연결합니다.
- **KMS/HSM logs**: 모든 signature에 대해 key ID, caller principal, policy result, destination address, reason codes를 기록합니다. change windows와 high-risk operations의 baseline을 설정합니다.
- **Oracle/feed metadata**: 각 update의 data source composition, reported value, rolling averages와의 deviation, triggered thresholds, 실행된 failover paths를 기록합니다.
- **Bridge/swap traces**: correlation IDs, chain IDs, relayer identity, hop timing을 사용하여 chains 간 lock/mint/unlock events를 상호 연관시킵니다.
- **Anomaly markers**: slippage spikes, abnormal collateralization ratios, unusual gas density, cross-chain velocity 등의 derived metrics를 생성합니다.

분석자가 observables를 실행 중인 AADAPT technique에 맞출 수 있도록 모든 항목에 scenario IDs 또는 synthetic user IDs를 태깅합니다.

## 6. Purple-team loop & maturity metrics
1. 통제된 환경에서 시나리오를 실행하고 detections(alerts, dashboards, responders paged)을 수집합니다.<sup>[[1]](#references)</sup>
2. 각 단계를 구체적인 AADAPT techniques 및 chain/app/KMS/oracle/bridge planes에서 생성된 observables에 매핑합니다.
3. detection hypotheses(threshold rules, correlation searches, invariant checks)를 수립하고 배포합니다.
4. mean time to detect (MTTD)와 mean time to contain (MTTC)이 business tolerances를 충족하고 playbooks가 value loss를 안정적으로 중단할 때까지 다시 실행합니다.

다음 세 가지 축으로 program maturity를 추적합니다.<sup>[[1]](#references)</sup>
- **Visibility**: 모든 critical value path에 각 plane의 telemetry가 존재하는지 여부.
- **Coverage**: 우선순위가 지정된 AADAPT techniques 중 end-to-end로 실행한 비율.
- **Response**: irreversible loss가 발생하기 전에 contracts를 pause하고, keys를 revoke하거나, flows를 freeze할 수 있는 능력.

일반적인 milestones: (1) value inventory + AADAPT mapping 완료, (2) detections가 구현된 첫 end-to-end scenario, (3) coverage를 확대하고 MTTD/MTTC를 줄이는 quarterly purple-team cycles.<sup>[[1]](#references)</sup>

## 7. Scenario templates
AADAPT behaviors에 직접 매핑되는 simulations를 설계할 때 다음의 반복 가능한 blueprints를 사용합니다.<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: 하나의 transaction 내부에서 일시적인 capital을 borrow하여 AMM prices/liquidity를 왜곡하고, 상환 전에 mispriced borrows, liquidations 또는 mints를 유발합니다.
- **Execution**:
1. target chain을 fork하고 production과 유사한 liquidity로 pools를 구성합니다.
2. flash loan을 통해 큰 notional을 borrow합니다.
3. lending, vault 또는 derivative logic이 의존하는 price/threshold boundaries를 넘도록 조정된 swaps를 실행합니다.
4. 왜곡 직후 victim contract를 호출하여(borrow, liquidate, mint) flash loan을 상환합니다.
- **Measurement**: invariant violation이 성공했습니까? slippage/price-deviation monitors, circuit breakers 또는 governance pause hooks가 trigger되었습니까? analytics가 비정상적인 gas/call graph pattern을 감지하기까지 얼마나 걸렸습니까?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: manipulated feeds가 destructive automated actions(mass liquidations, incorrect settlements)를 trigger할 수 있는지 확인합니다.
- **Execution**:
1. fork/testnet에서 malicious feed를 deploy하거나 aggregator weights/quorum/update cadence를 허용되는 deviation을 초과하도록 조정합니다.
2. dependent contracts가 poisoned values를 사용하고 standard logic을 실행하도록 둡니다.
- **Measurement**: feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, anomaly 발생부터 operator response까지의 latency를 측정합니다.

### Scenario C – Credential/signing abuse
- **Objective**: 단일 signer 또는 automation identity의 compromise가 unauthorized upgrades, parameter changes 또는 treasury drains를 가능하게 하는지 테스트합니다.
- **Execution**:
1. 민감한 signing rights를 가진 identities(operators, CI tokens, KMS/HSM을 호출하는 service accounts, multisig participants)를 열거합니다.
2. compromise를 시뮬레이션합니다(lab scope 내에서 해당 credentials/keys를 재사용).
3. privileged actions를 시도합니다: proxies upgrade, risk parameters 변경, assets mint/pause 또는 governance proposals trigger.
- **Measurement**: KMS/HSM logs가 anomaly alerts(time-of-day, destination drift, high-risk operations의 burst)를 발생시킵니까? policies 또는 multisig thresholds가 unilateral abuse를 방지할 수 있습니까? throttles/rate limits 또는 additional approvals가 적용됩니까?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: bridges, DEX routers, privacy hops를 통해 신속하게 launder된 assets를 defenders가 얼마나 잘 추적하고 차단할 수 있는지 평가합니다.
- **Execution**:
1. common bridges를 통한 lock/mint operations를 연결하고, 각 hop에서 swaps/mixers를 삽입하며, hop별 correlation IDs를 유지합니다.
2. monitoring latency에 부하를 주도록 transfers를 가속합니다(multi-hop within minutes/blocks).
- **Measurement**: telemetry 및 commercial chain analytics 간 events를 correlate하는 시간, reconstructed path의 완전성, 실제 incident에서 freezing을 위한 choke points를 식별하는 능력, 비정상적인 cross-chain velocity/value에 대한 alert fidelity를 측정합니다.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
