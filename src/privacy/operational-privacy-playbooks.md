# 운영 프라이버시 플레이북

이 플레이북은 이 섹션의 나머지 부분에 있는 통제 수단을 결합합니다. 이는 출발점일 뿐 보장이 아닙니다. 새로운 관찰자, 계정, 기기, 위치, 결제 수단, 파일 또는 상대방이 workflow에 들어올 때마다 threat model을 업데이트하십시오.

## 범용 사전 점검

1. 정당한 목적과 무엇을 **누구로부터** 비공개로 유지해야 하는지 작성합니다.
2. 해당 활동이 접촉할 신원, 기기, 네트워크, 계정, 결제 수단, 상대방, 물리적 위치 및 데이터를 기록합니다.
3. 가장 가능성이 높은 강력한 관찰자와 실패 시 결과를 식별합니다.
4. 권한, 적용 법률, provider 약관 및 조직 정책을 확인합니다.
5. 안전, incident response, 회계 및 감사를 위해 내부적으로 무엇을 귀속 가능하게 유지해야 하는지 결정합니다.
6. 작동 가능한 가장 작은 compartment를 선택하고, 사용 전에 복구 및 종료 경로를 설정합니다.
7. IP/DNS/IPv6, browser identity, 문서 metadata, 결제 명세서 및 notification leak를 포함하여 통제된 service를 대상으로 compartment를 테스트합니다.

[Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md)의 상세 모델을 사용하십시오.

## 일상적인 프라이버시 기준선

목표: 익명화를 시도하지 않고 상업적 추적, account takeover 및 불필요한 노출을 줄입니다.

- full-disk encryption, automatic updates, screen lock 및 가능한 경우 secure boot를 지원하는 유지 관리된 OS를 사용합니다.
- 먼저 password manager, recovery email 및 phishing-resistant MFA/security keys를 정비합니다.
- app permissions, location history, advertising identifiers, cloud sync 및 third-party account connections를 검토합니다.
- 확장 기능이 적고 tracking protection 및 HTTPS를 지원하는 mainstream browser를 사용하며, 업무/개인/고위험 browsing에 별도 profile을 사용합니다.
- 관계별로 private relay alias 또는 별도의 email address를 사용합니다. 단순히 선택 사항인 경우 개인 phone number를 사용하지 않습니다.
- 콘텐츠에는 end-to-end encrypted messaging을 우선 사용하되, 참여자, 시간, 그룹 및 endpoint는 여전히 metadata로 남는다는 점을 기억합니다.
- 파일에서 metadata를 의도적으로 제거하고, 게시하기 전에 원본이 아닌 export된 사본을 검사합니다.
- 결제 자격 증명을 compartmentalization하기 위해 virtual-card 또는 wallet token을 사용합니다. 이를 anonymous하다고 부르지 마십시오.
- 암호화된 recovery material을 백업하고 복원을 테스트합니다.

## Pseudonymous publication

목표: 일반 독자와 platform이 publication을 civil identity와 쉽게 연결하지 못하게 합니다. 이는 역량 있는 targeted investigation을 막지 못합니다.

1. platform, hosting provider, 독자, 연락처, local network, payment provider 또는 legal process가 threat model에 포함되는지 정의합니다.
2. clean baseline에서 전용 endpoint/account context를 생성합니다. 개인 browser sync, cloud documents, contact upload 및 notification preview를 비활성화합니다.
3. 선택한 network compartment를 통해 pseudonymous account를 생성합니다. username, avatar, recovery channel, writing boilerplate 또는 개인 identity-provider login을 재사용하지 않습니다.
4. 속도보다 destination unlinkability가 중요할 때 Tor Browser를 사용합니다. extension을 추가하거나 크기를 조정하거나 과도하게 customize하지 말고, 일반적인 desktop session에서 online 상태로 다운로드한 문서를 열지 않습니다.
5. 개인 template name, revision author, printer path, GPS/EXIF, thumbnail 또는 hidden layer가 삽입되지 않는 process로 초안을 작성합니다. 사본을 export한 뒤 적절한 metadata tool로 검사합니다.
6. 고유한 날짜, 직장 세부 정보, local weather/time zone, reflection, background audio, linguistic habit 및 이전 publication의 text reuse 등 자기 식별 정보를 content에서 확인합니다.
7. 별도의 reply channel을 사용합니다. 모든 direct contact, attachment 및 link를 잠재적인 correlation 또는 phishing 시도로 취급합니다.
8. 금전이 관련된 경우 필요한 데이터만 노출하는 합법적인 방법을 사용합니다. 독자가 알지 못하더라도 platform과 regulated intermediary는 payee를 알고 있을 수 있다고 가정합니다.
9. 게시한 후 다른 clean context에서 public result를 검사합니다. platform이 추가하거나 변환한 내용을 기록합니다.
10. 안정적인 behavioral fingerprint를 만들지 않는 경우에만 계획된 cadence를 유지합니다. compartment를 조용히 용도 변경하지 말고 폐기합니다.

중대한 journalism, activism, domestic abuse 또는 state-level risk의 경우 경험 있는 digital-security organization에서 맞춤형 도움을 받으십시오. 정적인 checklist로는 local law 또는 실제 adversary를 모델링할 수 없습니다.

## Authorized red-team engagement

목표: 권한, 통제 및 incident response를 유지하면서 operator의 개인 신원과 home network가 target telemetry에 포함되지 않게 합니다.

### 시작 시간 전

- ROE infrastructure annex, target/exclusion, source range, 날짜, emergency stop 및 third-party/provider permission을 최종 확정합니다.
- 전용 operator profile 또는 VM, engagement secret, evidence store, cloud project, domain 및 budget을 할당합니다.
- client가 제공하는 egress 또는 조직이 통제하는 fixed bastion을 우선 사용합니다. full-tunnel IPv4/IPv6/DNS 동작과 fail-closed policy를 테스트합니다.
- operator와 public infrastructure 간의 mapping을 exercise controller 또는 합의된 escrow contact와 함께 보관합니다.
- rate limit, destination allowlist 및 destructive, wireless, physical, phishing 또는 credential-collection action에 대한 별도 승인을 설정합니다.
- 조직이 통제하는 payment rail을 사용하고 승인을 내부적으로 기록합니다.

### engagement 중

- 승인된 endpoint와 tunnel에서 시작합니다. assessment traffic 전에 관찰된 egress를 확인합니다.
- 개인 account, device, phone number, repository, SSH/GPG key 및 cloud sync를 compartment에서 제외합니다.
- 불필요한 client content를 수집하지 않으면서 operator/job, 시작/종료, source, scoped destination 및 configuration change를 기록합니다.
- scope 모호성, 예상하지 못한 third-party system, provider abuse notification, safety impact, 장비 분실 또는 controller 연락 두절 시 중지합니다.
- 이웃의 Wi-Fi, 탈취한 credential, 승인되지 않은 SIM/account 또는 장소에 숨겨 둔 hardware를 절대 임의로 사용하지 않습니다.

### engagement 종료 시

- job과 C2를 중지하고, 승인된 drop device를 회수하며, token, credential 및 certificate를 revoke합니다.
- inventory를 기준으로 infrastructure, domain, source address, expense, data 및 provider case를 대조합니다.
- 계약에 따라 client data를 반환/삭제/보관하고, 필요한 최소한의 audit evidence를 보존하며, 두 번째 operator가 종료를 확인하도록 합니다.

전체 build 및 teardown guide는 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)를 참조하십시오.

## 합법적인 비공개 구매 또는 기부

목표: issuer, 회계, 세금 및 sanctions 의무를 충족하면서 merchant 또는 대중에 대한 공개를 최소화합니다.

1. 누가 무엇을 알아서는 안 되는지 나열합니다: public audience, merchant, payment intermediary, employer/family account delegate, delivery service 또는 blockchain observer.
2. local rule, recipient/counterparty, provider 약관, cash limit 및 recordkeeping 필요 사항을 확인합니다.
3. payment rail을 선택합니다:
- payment-network record 없이 허용되는 합법적인 local payment에는 cash;
- online credential separation에는 regulated virtual/merchant-specific card;
- acquisition, ledger, wallet backend, network, counterparty 및 later-spend link를 분석한 후에만 cryptocurrency.
4. 필요한 truthful detail을 사용하고 선택 사항인 loyalty/marketing 정보만 생략합니다. 다른 사람의 identity/address를 사용하거나 threshold를 피하려고 거래를 분할하지 않습니다.
5. merchant browser/account context를 분리하고 관련 없는 social login, loyalty 또는 개인 recovery channel을 피합니다.
6. statement, receipt, notification, shipping 및 public donor list에 무엇이 표시되는지 확인합니다.
7. 필요한 receipt/tax/authorization evidence를 암호화하여 보관하고, refund window 후 disposable payment credential을 revoke합니다.

[Private Digital Payments](private-digital-payments.md) 및 [Cryptocurrency Privacy](cryptocurrency-privacy.md)를 참조하십시오.

## 여행 및 신뢰할 수 없는 네트워크

목표: 사용자가 관리하지 않는 네트워크에서 data와 account를 보호하는 것이며, unauthorized activity를 숨기는 것이 아닙니다.

- 여행 전에 device를 update하고 필요한 credential/map을 다운로드합니다.
- 저장된 data를 최소화합니다. full-disk encryption, 강력한 unlock, remote-recovery planning 및 법률 자문에 적합한 powered-off border/physical-risk procedure를 사용합니다.
- venue SSID/captive portal을 확인합니다. 적절한 경우 personal hotspot을 우선 사용하되, cellular subscriber 및 location record가 남는다는 점을 기억합니다.
- 조직 data에는 full/forced approved VPN을 사용합니다. tethered device에도 VPN이 적용되는지 확인하고 IPv6/DNS 동작을 테스트합니다.
- client isolation 및 반복 가능한 policy를 위해 travel router를 사용하되, anonymity 보장으로 간주하지 않습니다.
- public USB charging, 대여한 computer, public printer 및 shared meeting-room system을 별도의 threat로 취급합니다.
- physical presence, radio identifier, portal login, camera 및 payment/location record가 방문을 correlation할 수 있다고 가정합니다.

비교 및 설정 세부 정보는 [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)에 있습니다.

## 장애 및 노출 대응

compartment가 leak되었거나 연결되었을 가능성이 있을 때:

1. 계속 진행하면 피해가 증가하는 경우 활동을 중지합니다. 해당되는 경우 engagement emergency stop을 사용합니다.
2. 민감한 data를 확산하지 않으면서 필요한 evidence를 보존합니다. 정확한 시간, 관찰된 indicator 및 영향을 받은 asset을 기록합니다.
3. 적절한 owner/controller/security contact에게 알립니다. privacy narrative를 유지하기 위해 incident를 숨기지 않습니다.
4. session, token, payment credential 및 infrastructure access를 revoke하고, known-clean endpoint에서 secret을 rotate합니다.
5. 어떤 edge가 연결을 만들었는지 확인합니다: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty 또는 physical presence.
6. 영향을 받은 전체 compartment가 burned되었다고 취급합니다. 단순히 username 또는 exit IP만 변경하지 않습니다.
7. breach, provider, client, financial 및 legal notification 의무를 이행합니다.
8. 연결을 유발한 process를 변경한 후에만 rebuild하고, 해당 control을 문서화하고 테스트합니다.

## 정기 감사

- [ ] 정해진 일정에 따라 threat model 및 legal/provider 가정을 검토했습니다.
- [ ] device, account, alias, domain, network path 및 payment credential을 inventory로 관리합니다.
- [ ] recovery path가 예기치 않게 compartment를 가로지르지 않습니다.
- [ ] full-tunnel, DNS, IPv6 및 fail-closed 동작을 테스트했습니다.
- [ ] public file 및 profile에서 metadata/content reuse를 확인했습니다.
- [ ] wallet node/backend 및 crypto protocol 가정이 최신 상태로 유지됩니다.
- [ ] log 및 receipt가 최소화되고, 암호화되며, access-controlled이고, retention 범위 내에 있습니다.
- [ ] 이전 compartment 및 engagement infrastructure를 완전히 retire했습니다.
