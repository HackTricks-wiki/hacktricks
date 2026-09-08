# 운영 개인정보 보호 플레이북

{{#include ../banners/hacktricks-training.md}}

이 플레이북은 이 섹션의 나머지 부분에서 설명한 통제 수단을 결합합니다. 이는 시작점일 뿐 보장이 아닙니다. 새로운 관찰자, 계정, 기기, 위치, 결제, 파일 또는 거래 상대방이 workflow에 들어올 때마다 threat model을 업데이트하세요.

## 범용 사전 점검

1. 정당한 목적과 무엇을 **누구로부터** 비공개로 유지해야 하는지 작성합니다.
2. 활동이 접촉할 신원, 기기, 네트워크, 계정, 결제 수단, 거래 상대방, 물리적 위치 및 데이터를 기록합니다.
3. 가장 강력할 가능성이 있는 관찰자와 실패 시 결과를 식별합니다.
4. 권한, 적용 법률, provider 약관 및 조직 정책을 확인합니다.
5. 안전, incident response, 회계 및 audit를 위해 내부적으로 무엇을 귀속 가능하게 유지해야 하는지 결정합니다.
6. 작동 가능한 가장 작은 compartment를 선택하고, 사용 전에 복구 및 shutdown 경로를 마련합니다.
7. IP/DNS/IPv6, browser identity, 문서 metadata, 결제 명세서 및 notification leak를 포함하여 통제된 service를 대상으로 compartment를 테스트합니다.

자세한 model은 [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md)을 사용하세요.

## 일상적인 개인정보 보호 기준선

목표: 익명이 되려 하지 않고 상업적 tracking, account takeover 및 불필요한 노출을 줄입니다.

- full-disk encryption, automatic updates, screen lock 및 가능한 경우 secure boot가 활성화된 유지 관리되는 OS를 사용합니다.
- password manager, recovery email 및 phishing-resistant MFA/security keys를 먼저 정리합니다.
- app permissions, location history, advertising identifiers, cloud sync 및 third-party account connections를 검토합니다.
- extension을 적게 사용하고 tracking protection 및 HTTPS가 활성화된 mainstream browser를 사용하며, 업무/개인/고위험 browsing에 별도 profile을 사용합니다.
- 관계별로 private relay alias 또는 별도의 email address를 사용합니다. 단순히 선택 사항인 경우 personal phone number를 사용하지 않습니다.
- content에는 end-to-end encrypted messaging을 우선 사용하되, 참여자, 시간, group 및 endpoint는 여전히 metadata로 남는다는 점을 기억합니다.
- 파일에서 metadata를 의도적으로 제거하고, 게시하기 전에 원본이 아닌 export한 사본을 검사합니다.
- 결제 credential compartmentalization에는 virtual-card 또는 wallet token을 사용하되, 이를 anonymous하다고 부르지 않습니다.
- 암호화된 recovery material을 backup하고 복원을 테스트합니다.

## Pseudonymous publication

목표: 일반 독자와 platform이 publication을 civil identity와 쉽게 연결하지 못하도록 합니다. 이 방법으로는 유능한 targeted investigation을 막을 수 없습니다.

1. platform, hosting provider, 독자, 연락처, local network, payment provider 또는 legal process를 threat model에 포함할지 정의합니다.
2. 깨끗한 baseline에서 전용 endpoint/account context를 생성합니다. personal browser sync, cloud documents, contact upload 및 notification preview를 비활성화합니다.
3. 선택한 network compartment를 통해 pseudonymous account를 생성합니다. username, avatar, recovery channel, writing boilerplate 또는 personal identity-provider login을 재사용하지 않습니다.
4. destination unlinkability가 속도보다 중요할 때 Tor Browser를 사용합니다. extension을 추가하거나 크기를 조정하거나 과도하게 customize하지 말고, 일반 desktop session에서 online 상태로 다운로드한 문서를 열지 않습니다.
5. 개인적인 template name, revision author, printer path, GPS/EXIF, thumbnail 또는 hidden layer를 삽입하지 않는 process로 작성합니다. 사본을 export하고 적절한 metadata tool로 검사합니다.
6. 자신을 식별할 수 있는 사실을 content에서 확인합니다. 고유한 날짜, workplace 세부 정보, local weather/time zone, reflections, background audio, linguistic habits 및 이전 publication의 text reuse가 해당합니다.
7. 별도의 reply channel을 사용합니다. 모든 direct contact, attachment 및 link를 잠재적인 correlation 또는 phishing 시도로 취급합니다.
8. money가 관련된 경우 필요한 데이터만 노출하는 lawful method를 사용합니다. 독자가 알지 못하더라도 platform과 regulated intermediary는 payee를 알고 있을 수 있다고 가정합니다.
9. publish한 후 다른 깨끗한 context에서 public result를 검사합니다. platform이 추가하거나 변환한 내용을 기록합니다.
10. 안정적인 behavioral fingerprint를 만들지 않는 경우에만 계획된 cadence를 유지합니다. compartment를 조용히 용도 변경하지 말고 폐기합니다.

중대한 journalism, activism, domestic abuse 또는 state-level risk가 있는 경우 경험이 풍부한 digital-security organization에서 맞춤형 도움을 받으세요. 정적인 checklist로는 local law나 실시간 adversary를 model할 수 없습니다.

## Authorized red-team engagement

목표: authorization, control 및 incident response를 유지하면서 operator의 personal identity와 home network가 target telemetry에 포함되지 않도록 합니다.

### 시작 window 전

- ROE infrastructure annex, target/exclusion, source range, 날짜, emergency stop 및 third-party/provider permission을 확정합니다.
- 전용 operator profile 또는 VM, engagement secret, evidence store, cloud project, domain 및 budget을 할당합니다.
- client가 제공하는 egress 또는 조직이 통제하는 fixed bastion을 우선 사용합니다. full-tunnel IPv4/IPv6/DNS 동작과 fail-closed policy를 테스트합니다.
- operator와 public infrastructure 간 mapping을 exercise controller 또는 합의된 escrow contact와 함께 보관합니다.
- rate limit, destination allowlist 및 destructive, wireless, physical, phishing 또는 credential-collection action에 대한 별도 승인을 설정합니다.
- 조직이 통제하는 payment rail을 사용하고 승인을 내부적으로 기록합니다.

### engagement 중

- 승인된 endpoint와 tunnel에서 시작하고 assessment traffic 전에 관찰된 egress를 확인합니다.
- personal account, device, phone number, repository, SSH/GPG key 및 cloud sync를 compartment에서 제외합니다.
- 불필요한 client content를 수집하지 않으면서 operator/job, start/stop, source, 범위가 지정된 destination 및 configuration change를 log합니다.
- scope 모호성, 예상하지 못한 third-party system, provider abuse notification, safety impact, 장비 분실 또는 controller contact 상실 시 중지합니다.
- 이웃의 Wi-Fi, 탈취한 credential, 승인되지 않은 SIM/account 또는 장소에 숨긴 hardware를 이용해 즉흥적으로 행동하지 않습니다.

### engagement 종료

- job과 C2를 중지하고 승인된 drop device를 회수하며 token, credential 및 certificate를 revoke합니다.
- inventory와 infrastructure, domain, source address, expense, data 및 provider case를 대조합니다.
- contract에 따라 client data를 반환/삭제/보존하고, 필요한 최소한의 audit evidence를 보존하며, 두 번째 operator가 shutdown을 확인하도록 합니다.

전체 build 및 teardown guide는 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)를 참조하세요.

## Lawful private purchase or donation

목표: issuer, 회계, 세금 및 sanctions 의무를 충족하면서 merchant 또는 public에 대한 disclosure를 최소화합니다.

1. 누가 무엇을 알아서는 안 되는지 나열합니다. public audience, merchant, payment intermediary, employer/family account delegate, delivery service 또는 blockchain observer가 해당합니다.
2. local rule, recipient/counterparty, provider term, cash limit 및 recordkeeping 요구 사항을 확인합니다.
3. rail을 선택합니다.
- payment-network record 없이 허용되는 lawful local payment에는 cash;
- online credential separation에는 regulated virtual/merchant-specific card;
- acquisition, ledger, wallet backend, network, counterparty 및 later-spend link를 분석한 후에만 cryptocurrency.
4. 필요한 truthful detail을 사용하고 optional loyalty/marketing 정보만 생략합니다. 다른 사람의 identity/address를 사용하거나 threshold를 피하려고 transaction을 분할하지 않습니다.
5. merchant browser/account context를 분리하고 관련 없는 social login, loyalty 또는 personal recovery channel을 피합니다.
6. statement, receipt, notification, shipping 및 public donor list에 무엇이 표시되는지 확인합니다.
7. 필요한 receipt/tax/authorization evidence를 암호화하여 보관하고 refund window가 지난 후 disposable payment credential을 revoke합니다.

[Private Digital Payments](private-digital-payments.md) 및 [Cryptocurrency Privacy](cryptocurrency-privacy.md)를 참조하세요.

## Travel and untrusted networks

목표: 사용자가 관리하지 않는 network에서 data와 account를 보호하는 것이며, unauthorized activity를 숨기는 것이 아닙니다.

- 여행 전에 device를 update하고 필요한 credential/map을 다운로드합니다.
- 저장된 data를 최소화하고, full-disk encryption, 강력한 unlock, remote-recovery planning 및 legal advice에 적합한 powered-off border/physical-risk procedure를 사용합니다.
- venue SSID/captive portal을 확인합니다. 적절한 경우 personal hotspot을 우선 사용하되, cellular subscriber 및 location record가 남는다는 점을 기억합니다.
- 조직 data에는 full/forced approved VPN을 사용하고 tethered device도 이를 공유하는지 확인하며 IPv6/DNS 동작을 테스트합니다.
- client isolation 및 반복 가능한 policy를 위해 travel router를 사용하되 anonymity guarantee로 간주하지 않습니다.
- public USB charging, 대여한 computer, public printer 및 공유 meeting-room system을 별도의 threat로 취급합니다.
- physical presence, radio identifier, portal login, camera 및 payment/location record가 방문을 correlate할 수 있다고 가정합니다.

비교 및 setup 세부 정보는 [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)에 있습니다.

## Failure and exposure response

compartment가 leak되었거나 연결되었을 가능성이 있을 때:

1. 계속하면 피해가 커지는 경우 activity를 중지합니다. 해당하는 경우 engagement emergency stop을 사용합니다.
2. 민감한 data를 확산하지 않으면서 필요한 evidence를 보존합니다. 정확한 시간, 관찰된 indicator 및 영향을 받은 asset을 기록합니다.
3. 적절한 owner/controller/security contact에 알립니다. privacy narrative를 유지하기 위해 incident를 은폐하지 않습니다.
4. session, token, payment credential 및 infrastructure access를 revoke하고, 알려진 clean endpoint에서 secret을 rotate합니다.
5. 어떤 edge가 연결을 만들었는지 판단합니다. endpoint, account recovery, network, payment, metadata, content, behavior, counterparty 또는 physical presence가 해당합니다.
6. 영향을 받은 전체 compartment가 burned되었다고 취급합니다. username 또는 exit IP만 변경하지 않습니다.
7. breach, provider, client, financial 및 legal notification 의무를 이행합니다.
8. link를 유발한 process를 변경한 후에만 rebuild하고, 해당 control을 문서화하고 테스트합니다.

## Periodic audit

- [ ] 정해진 일정에 따라 threat model 및 legal/provider assumption을 검토했습니다.
- [ ] device, account, alias, domain, network path 및 payment credential을 inventory화했습니다.
- [ ] recovery path가 예기치 않게 compartment를 가로지르지 않습니다.
- [ ] full-tunnel, DNS, IPv6 및 fail-closed 동작을 테스트했습니다.
- [ ] public file 및 profile에서 metadata/content reuse를 확인했습니다.
- [ ] wallet node/backend 및 crypto protocol assumption이 최신 상태로 유지됩니다.
- [ ] log와 receipt가 최소화되고, 암호화되며, access-controlled 상태이고, retention 범위 내에 있습니다.
- [ ] 이전 compartment와 engagement infrastructure를 완전히 폐기했습니다.
{{#include ../banners/hacktricks-training.md}}
