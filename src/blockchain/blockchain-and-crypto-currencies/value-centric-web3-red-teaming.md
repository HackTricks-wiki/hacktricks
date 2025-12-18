# 가치 중심의 Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) 매트릭스는 인프라만이 아니라 디지털 가치 자체를 조작하는 공격자 행동을 포착합니다. 이를 위협 모델링의 척추(backbone)로 다루세요: 자산을 mint, 가격결정, 승인, 또는 라우팅할 수 있는 모든 구성요소를 나열하고, 해당 접점들을 AADAPT 기법에 매핑한 뒤, 환경이 되돌릴 수 없는 경제적 손실을 견딜 수 있는지 측정하는 red-team 시나리오를 설계하세요.

## 1. 가치 보유 구성요소 인벤토리 작성
오프체인이라도 가치 상태에 영향을 줄 수 있는 모든 것을 도식화하세요.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). 키 ID, 정책, 자동화 ID, 승인 워크플로우를 캡처하세요.
- **Admin & upgrade paths** for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). 누가/무엇이 호출할 수 있는지, 어떤 쿼럼이나 지연 조건인지 포함하세요.
- **On-chain protocol logic** handling lending, AMMs, vaults, staking, bridges, or settlement rails. 그들이 가정하는 불변조건(invariants)들을 문서화하세요 (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** that builds transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). 이러한 것들은 서명 요청을 할 수 있는 API 키나 서비스 주체를 보유하는 경우가 많습니다.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). 자동화된 리스크 로직이 의존하는 모든 업스트림을 기록하세요.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) 체인이나 관리 서비스 스택을 연결하는 요소들을 포함하세요.

Deliverable: 자산이 어떻게 이동하는지, 누가 이동을 승인하는지, 어떤 외부 신호가 비즈니스 로직에 영향을 주는지를 보여주는 value-flow 다이어그램.

## 2. 구성요소를 AADAPT 행동에 매핑
AADAPT 분류체계를 각 구성요소별 구체적 공격 후보로 변환하세요.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

이 매핑은 계약뿐만 아니라 가치에 간접적으로 영향을 줄 수 있는 모든 identity/automation을 테스트하게 합니다.

## 3. 공격자 실현 가능성 vs 비즈니스 영향으로 우선순위 지정

1. **Operational weaknesses**: 노출된 CI 자격증명, 권한이 과다한 IAM 역할, 잘못 구성된 KMS 정책, 임의 서명 요청이 가능한 자동화 계정, 브리지 설정이 공개된 버킷 등.
2. **Value-specific weaknesses**: 취약한 오라클 파라미터, 다자 승인 없는 업그레이드 가능한 계약, flash-loan에 민감한 유동성, timelock을 우회할 수 있는 거버넌스 액션 등.

공격자처럼 큐를 운영하세요: 오늘 성공할 수 있는 운영적 발판부터 시작해, 깊은 프로토콜/경제적 조작 경로로 진행하세요.

## 4. 통제된, 실운영과 유사한 환경에서 실행
- **Forked mainnets / isolated testnets**: 바이트코드, 스토리지, 유동성을 복제해 flash-loan 경로, 오라클 드리프트, 브리지 플로우가 실제 자금 없이 end-to-end로 실행되게 하세요.
- **Blast-radius planning**: 시나리오 실행 전 서킷브레이커, 일시정지 모듈, 롤백 런북, 테스트 전용 관리자 키를 정의하세요.
- **Stakeholder coordination**: 수탁자, 오라클 운영자, 브리지 파트너, 컴플라이언스팀에 통지해 모니터링 팀이 트래픽을 예상하게 하세요.
- **Legal sign-off**: 시뮬레이션이 규제 구간을 넘을 수 있는 경우 범위, 승인, 중단 조건을 문서화하세요.

## 5. AADAPT 기법에 맞춘 텔레메트리
모든 시나리오가 실질적 탐지 데이터를 생성하도록 텔레메트리 스트림을 계측하세요.

- **Chain-level traces**: 전체 호출 그래프, gas 사용량, 트랜잭션 논스, 블록 타임스탬프—flash-loan 번들, 재진입(reentrancy)-유사 구조, 크로스컨트랙트 홉을 재구성하기 위해 필요합니다.
- **Application/API logs**: 각 온체인 tx를 사람 또는 자동화 ID(session ID, OAuth client, API key, CI job ID)와 IP 및 인증 방법으로 연결하세요.
- **KMS/HSM logs**: 키 ID, 호출자 주체, 정책 결과, 목적지 주소, 각 서명에 대한 이유 코드. 변경 윈도우와 고위험 작업의 기준선을 확보하세요.
- **Oracle/feed metadata**: 업데이트별 데이터 소스 구성, 보고된 값, 롤링 평균 대비 편차, 트리거된 임계값, 페일오버 경로.
- **Bridge/swap traces**: 체인 간 lock/mint/unlock 이벤트를 상관 ID, 체인 ID, relayer 정체, 홉 타이밍과 함께 연관 지으세요.
- **Anomaly markers**: 슬리피지 급증, 비정상적 담보비율, 이상한 gas 밀도, 크로스체인 속도성 같은 파생 지표들.

모든 것을 시나리오 ID 또는 합성 사용자 ID로 태깅해 분석가가 관찰값을 실행한 AADAPT 기법과 정렬할 수 있게 하세요.

## 6. Purple-team 루프 & 성숙도 지표
1. 통제된 환경에서 시나리오를 실행하고 탐지(알림, 대시보드, 호출된 대응자)를 캡처하세요.
2. 각 단계를 특정 AADAPT 기법과 체인/앱/KMS/오라클/브리지 평면에서 생성된 관찰값에 매핑하세요.
3. 탐지 가설(임계값 규칙, 상관 검색, 불변성 검사)을 수립하고 배포하세요.
4. MTTD 및 MTTC가 비즈니스 허용범위에 도달하고 플레이북이 가치 손실을 신뢰성 있게 차단할 때까지 재실행하세요.

프로그램 성숙도는 세 축으로 추적하세요:
- **Visibility**: 모든 중요한 가치 경로에 각 평면의 텔레메트리가 존재.
- **Coverage**: 우선순위가 높은 AADAPT 기법 중 end-to-end로 실행된 비율.
- **Response**: 계약 일시중지, 키 폐기, 흐름 동결 등 되돌릴 수 없는 손실 이전에 조치할 수 있는 능력.

일반적인 마일스톤: (1) 가치 인벤토리 및 AADAPT 매핑 완료, (2) 탐지가 구현된 첫 번째 end-to-end 시나리오, (3) 분기별 purple-team 사이클로 커버리지 확장 및 MTTD/MTTC 단축.

## 7. 시나리오 템플릿
이 반복 가능한 청사진들을 사용해 AADAPT 행동에 직접 매핑되는 시뮬레이션을 설계하세요.

### Scenario A – Flash-loan economic manipulation
- **Objective**: 한 트랜잭션 내에서 일시적 자본을 빌려 AMM의 가격/유동성을 왜곡해 잘못 가격된 차입, 청산, 또는 mint를 트리거한 뒤 상환합니다.
- **Execution**:
1. 대상 체인을 fork하고 생산 수준의 유동성으로 풀을 시드하세요.
2. flash loan으로 큰 노티션을 빌리세요.
3. 대차로 계산된 스왑을 수행해 대출, vault, 파생 로직이 의존하는 가격/임계값을 넘기세요.
4. 왜곡 직후 피해자 계약을 호출(차입, 청산, mint)하고 flash loan을 상환하세요.
- **Measurement**: 불변성 위반이 성공했나요? 슬리피지/가격 편차 모니터, 서킷브레이커, 거버넌스 일시정지 훅이 트리거되었나요? 비정상적 gas/호출 그래프 패턴이 분석에 표시되기까지 얼마나 걸렸나요?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: 조작된 피드가 대량 청산이나 잘못된 정산 같은 파괴적 자동화 동작을 유발할 수 있는지 확인합니다.
- **Execution**:
1. fork/testnet에서 악성 피드 배포하거나 aggregator 가중치/쿼럼/업데이트 주기를 허용 편차를 넘게 조정하세요.
2. 의존하는 계약들이 오염된 값을 소비하고 표준 로직을 실행하게 하세요.
- **Measurement**: 피드 레벨의 오프-밴드(alert) 여부, fallback oracle 활성화, 최소/최대 바운드 시행, 이상 발생 시점부터 운영자 반응까지의 지연.

### Scenario C – Credential/signing abuse
- **Objective**: 단일 서명자 또는 자동화 ID를 탈취해 권한 없는 업그레이드, 파라미터 변경, 또는 금고(트레저리) 유출이 가능한지 테스트합니다.
- **Execution**:
1. 민감한 서명 권한을 가진 ID(운영자, CI 토큰, KMS/HSM를 호출하는 서비스 계정, multisig 참가자)를 열거하세요.
2. 실험 범위 내에서 해당 자격증명/키를 재사용해 탈취를 시뮬레이션하세요.
3. 권한 작업을 시도하세요: 프록시 업그레이드, 리스크 파라미터 변경, 자산 mint/pause, 또는 거버넌스 제안 트리거 등.
- **Measurement**: KMS/HSM 로그가 이상 알림(시간대, 목적지 편차, 고위험 작업 급증)을 발생시키나요? 정책이나 multisig 임계값이 단독 남용을 막을 수 있나요? 스로틀/레이트 리밋이나 추가 승인 절차가 적용되나요?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: 브리지, DEX 라우터, 프라이버시 홉을 통해 자산을 빠르게 세탁할 때 수비 측이 얼마나 신속하게 자산을 추적·차단할 수 있는지 평가합니다.
- **Execution**:
1. 일반적인 브리지들을 따라 lock/mint 작업을 연결하고 각 홉에서 스왑/믹서를 섞어가며 per-hop correlation ID를 유지하세요.
2. 전송을 가속해 모니터링 지연을 스트레스하세요(몇 분/블록 내 멀티홉).
- **Measurement**: 텔레메트리 + 상용 체인 분석을 통해 이벤트를 상관하는 시간, 재구성된 경로의 완전성, 실제 사건에서 동결 가능한 choke point 식별 능력, 비정상적 크로스체인 속도/가치에 대한 알림 정확성.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
