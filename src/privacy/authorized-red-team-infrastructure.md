# Authorized Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

내구성 있는 현장 장치에는 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) 설계와 의심 장치 발견 대응 runbook을 사용합니다.

전문 red team의 목표는 책임을 면하는 것이 아니라 **통제된 귀속**을 확보하는 것입니다. 대상이 운영자의 자택 IP나 개인 계정을 쉽게 확인할 수 없어야 하지만, engagement 소유자는 출처를 식별하고, 작업을 중지하며, abuse report를 처리하고, 증거를 보존하고, 승인을 입증할 수 있어야 합니다.

이 페이지는 합법적인 engagement를 위한 deployment baseline입니다. 침해된 ORB, residential relay, fronting, dead drop, 인근 wireless pivot을 포함해 이를 모방하려는 adversary tradecraft는 [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md)과 [Government and APT Case Studies](government-and-apt-case-studies.md)에서 시작한 다음, [authorized labs](authorized-adversary-emulation-labs.md)에서 필요한 telemetry를 재현합니다.

NIST는 rules of engagement (ROE)를 정의된 testing 활동에 대한 권한을 부여하는 사전 설정된 제약 조건으로 정의합니다.<sup>[[1]](#references)</sup> Privacy architecture는 해당 권한을 확대할 수 없습니다.

## egress 패턴 선택

| 패턴 | 최적의 용도 | 대상이 보는 것 | Provider/local observer가 보는 것 | 책임 추적성 |
|---|---|---|---|---|
| Client-provided VPN/jump host | 대부분의 assessment | Client address range | Client identity와 operator access | 가장 강력 |
| Red-team 조직 bastion | 반복 가능한 통제된 egress | Organization range | Hosting provider와 organization | 강력 |
| Engagement-specific VPS | Client/campaign 격리 | VPS address | Host account, billing, control-plane 및 access logs | 문서화된 경우 강력 |
| Approved commercial VPN | Provider와 ROE가 허용한 research/scanning | Shared/dedicated VPN egress | VPN account와 source connection | 중간 |
| Tor Browser | destination unlinkability가 필요한 Web research | Tor exit | Local network는 Tor/bridge를 보고, destination은 Tor를 봄 | allowlisted source attribution에는 부적합 |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network와 remote tunnel provider | inventory가 관리된 경우 강력 |
| Lawful guest Wi-Fi | 저위험 administrative/research 용도 | Venue public IP 또는 tunnel egress | Venue, ISP, VPN/Tor | 약하며 물리적으로 관찰 가능 |

대부분의 작업에서는 consumer anonymity service보다 client-provided 또는 organization-controlled fixed egress가 더 안전하고 빠릅니다. 또한 exercise 설계에 따라 defender가 알려진 source range를 allowlist하거나, 모니터링하거나, 의도적으로 **allowlist하지 않도록** 할 수 있습니다.

## ROE infrastructure annex

deployment 전에 다음을 기록합니다.

- authorization을 부여하고 수령하는 legal entity;
- 정확한 target과 명시적인 exclusion;
- 시작/종료 시각, time zone 및 허용된 technique;
- source IP, autonomous-system/provider 이름, domain, redirector, mail infrastructure 및 현장 장치 식별자;
- phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence 또는 third-party service의 허용 여부;
- client 및 provider 승인과 사전 notification reference;
- emergency stop phrase, 24/7 client 및 provider abuse contact, 최대 응답 시간;
- 수집할 수 있는 data class, encryption, access, retention 및 deletion;
- 누가 public infrastructure와 operator 간 mapping을 보유하는지를 포함한 evidence 및 logging 요구 사항;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery 및 최종 attestation.

Public IP와 domain이 실제로 authorization을 부여한 당사자가 제어하는 것인지, 또는 scope에 명시적으로 포함되어 있는지 확인합니다. NIST SP 800-115는 testing 전에 public target address가 해당 organization의 관리 범위에 속하는지 확인할 것을 권장합니다.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Engagement account/project 생성:** 정확한 billing 및 ownership 정보를 사용해 red-team organization 아래에 생성합니다. 다른 client와 role, API key, budget 및 audit log를 분리합니다.
2. **모든 provider policy 확인:** Cloud, VPS, CDN, domain, email 및 VPN provider는 서로 다른 규칙을 적용합니다. 예를 들어 AWS는 특정 assessment를 허용하지만 hosted C2/covert simulation에는 사전 승인을 요구하며, 명시된 활동을 금지합니다.<sup>[[3]](#references)</sup>
3. **고정 egress address 할당:** 이를 ROE annex에 기록합니다. 빠른 IP/resource cycling은 incident response를 복잡하게 만들고 provider policy를 위반할 수 있으므로 피합니다.
4. **Management 강화:** key-only SSH 또는 identity-aware management plane, phishing-resistant MFA, 별도의 admin network, least privilege, patch된 image, public admin port 차단 및 암호화된 secret storage를 사용합니다.
5. **Full-tunnel 경로 생성:** operator endpoint에서 bastion까지 연결합니다. DNS와 IPv6를 명시적으로 routing하고 tunnel이 중단되면 firewall deny를 적용합니다.
6. **Outbound destination 및 port 제한:** 가능한 경우 authorized scope로 제한합니다. Scanner에 rate limit을 적용하고 되돌릴 수 없거나 파괴적인 technique은 별도의 approval gate 뒤에 둡니다.
7. **감시가 아닌 accountability를 위한 logging:** operator authentication, configuration change, start/stop, source address, scoped destination 및 tool/job identifier를 기록합니다. exercise에 필요하고 data plan으로 보호되는 경우가 아니라면 payload/credential capture를 피합니다.
8. **Organization이 소유한 controlled endpoint를 통한 검증:** 관찰된 IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect 및 provider abuse contact를 확인합니다.
9. **Attribution map을 안전하게 공유:** exercise controller 또는 합의된 escrow contact와 안전하게 공유합니다. Blind detection이 test의 일부라면 target team에 이를 공개하지 않습니다.

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPS는 destination에 대해서만 pseudonymous합니다. Host에는 contact, billing, identity, source-IP, API, device, location 및 usage records가 남을 수 있으며, customer-visible AWS CloudTrail history만으로도 management activity가 노출될 수 있습니다.<sup>[[4]](#references)</sup> cryptocurrency로 hosting 비용을 지불해도 이러한 records가 삭제되지는 않습니다.

## Domains and certificates

- organization이 소유한 engagement-specific registrar account를 사용합니다.
- 지원되는 경우 registrar lock, DNSSEC, MFA/security keys를 활성화하고, 승인된 기간에만 auto-renew를 설정합니다.
- 공개 노출을 줄이기 위해 registration privacy를 사용하되, registrant information을 허위로 표시하지 않습니다. ICANN policy는 public display가 redacted 또는 proxied된 경우에도 registrar가 registration data를 수집하도록 요구합니다.<sup>[[5]](#references)</sup>
- 관련 없는 당사자를 불법적으로 사칭하는 이름을 사용하지 않습니다. Typosquatting/lookalike domains에는 client 및 provider의 명시적인 승인이 필요합니다.
- operators 또는 clients를 leak할 수 있는 DNS, certificates, CDN/redirector configuration 및 third-party analytics를 inventory에 기록합니다.
- teardown 시 records를 제거하고, certificates/tokens를 revoke하며, 합의된 evidence를 보존하고, 해당 domain을 defensive하게 유지할지 결정합니다.

## Authorized on-site drop nodes

Raspberry Pi 또는 유사한 appliance는 property/network owner와 client가 정확한 배치 위치 및 동작을 명시적으로 승인한 경우에만 허용됩니다. 안전한 plan은 다음과 같습니다.

1. device serial, MAC/private-MAC policy, photo, owner, 정확히 승인된 location, power source, retrieval deadline 및 tamper contact를 기록합니다.
2. 최소한의 signed image, encrypted secrets, read-only 또는 recoverable storage, host firewall, 가능한 경우 automatic security updates를 사용하고, default credentials를 사용하지 않습니다.
3. 이름이 지정된 engagement endpoint로 outbound-only communication을 구성합니다. 인증되지 않은 listener를 노출하지 않습니다.
4. destinations와 capabilities를 allowlist에 등록합니다. Packet capture, credential collection, wireless impersonation 및 lateral movement는 각각 명시적으로 승인되어야 합니다.
5. mutual authentication, short-lived keys, remote kill, health reporting 및 bandwidth limits를 사용합니다.
6. 분실 또는 도난이 재사용 가능한 credentials나 client data를 노출하지 않도록 합니다.
7. retrieval 및 secure wipe/decommission을 calendar에 등록하고, 서명된 recovery record를 확보합니다.

owner/operator의 서면 허가 없이 café, hotel, shared office, 이웃의 property 또는 public venue에 hardware를 숨기지 않습니다.

## Guest networks and travel routers

승인된 scenario에서 guest access가 필요한 경우:

- venue/client와 SSID 및 acceptable-use policy를 확인합니다.
- organization이 소유한 travel router 또는 low-trust bridge device를 사용하여 privileged workstation을 격리합니다.
- privileged workstation 외부에서 captive portals를 완료합니다.
- assessment traffic 전에 승인된 tunnel을 시작합니다.
- tethered devices가 실제로 해당 tunnel을 사용하는지 확인합니다.
- venue가 radio association, portal, physical presence 및 camera/payment records를 상호 연관할 수 있다고 가정합니다.
- access control을 우회하거나, 다른 device를 clone하거나, Wi-Fi를 공격하거나, equipment를 남겨두지 않습니다.

## Operational separation

- 각 client/engagement마다 endpoint compartment, cloud project, secrets set, domain group, redirector set 및 evidence store를 하나씩 분리합니다.
- 승인된 organization systems 외부에서 personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity 또는 payment reimbursement를 사용하지 않습니다.
- exercise design이 fingerprinting을 허용하지 않는 한, clients 간에 distinctive payload configuration, callback paths, certificates 또는 public repositories를 재사용하지 않습니다.
- infrastructure에 kill date와 budget alert를 설정합니다. Orphaned systems는 client와 Internet 모두에 risk가 됩니다.
- 사고를 조사할 수 있도록 충분한 internal attribution을 보존합니다. “No logs”는 일반적으로 professional evidence 및 safety obligations와 양립할 수 없습니다.

## Blind to defenders, attributable to the controller

exercise objective가 allowlist를 test하는 것이 아니라 detection을 측정하는 것이라면, operation을 accountable하지 않게 만들지 않고도 target SOC가 blind 상태를 유지할 수 있습니다.

1. exercise controller가 모든 public source, domain, certificate 및 on-site device를 승인하되, 해당 목록은 SOC에 공개하지 않습니다.
2. controller는 source-to-engagement/operator map을 별도의 encrypted vault에 저장하며, two-person emergency access를 적용합니다.
3. 각 operator job에는 scope, time window, source compartment 및 irreversible job identifier가 포함된 signed manifest를 전달합니다. target은 normal operation 중 manifest를 볼 필요가 없습니다.
4. bastion audit events를 chain하거나 controller storage로 append-only 전송하여, 사고 이후 operator가 attribution을 조용히 다시 작성하지 못하게 합니다.
5. 24/7 provider-abuse contact가 authorization을 확인할 수 있는 verification phrase/reference를 보유하되, client를 public하게 공개하지 않습니다.
6. 각 path에는 assessment C2, target network 또는 한 operator의 account에 의존하지 않는 out-of-band stop channel을 구현합니다.
7. live testing 전에 모든 source에서 benign canaries를 전송합니다. controller가 ROE response time 내에 이를 resolve하고 stop할 수 있는지 확인합니다.
8. exercise 후 SOC telemetry를 controller ledger와 비교하고, source list를 공개하며, 누락되었거나 잘못된 detections를 설명합니다.

Anti-forensics, log destruction, compromised relays 또는 false subscriber identities를 추가하지 않습니다. 이는 accountable testing을 개선하는 것이 아니라 무력화합니다.

## Teardown checklist

- [ ] Exercise controller가 stop을 확인합니다.
- [ ] C2, tunnels, redirectors, mail, VPN 및 scheduled jobs가 disabled 상태입니다.
- [ ] On-site devices를 물리적으로 회수하고 대조합니다.
- [ ] Tokens, API keys, SSH keys, certificates 및 captured credentials를 revoke/rotate합니다.
- [ ] DNS 및 cloud resources를 제거하거나 defensive retention을 위해 transfer합니다.
- [ ] Client data를 contract에 따라 반환, 보존 또는 폐기합니다.
- [ ] 필수 financial, audit 및 authorization records를 encrypted 상태와 access-controlled 상태로 유지합니다.
- [ ] Provider abuse cases를 종료하고 client에 최종 source indicators를 전달합니다.
- [ ] 두 번째 operator가 infrastructure가 active 상태로 남아 있지 않은지 확인합니다.

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Information Security Testing 및 Assessment를 위한 Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing를 위한 Customer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
