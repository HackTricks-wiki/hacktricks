# Authorized Red-Team Infrastructure

내구성이 필요한 현장 장치에는 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) 설계와 suspected-discovery runbook을 사용합니다.

Professional red team의 목표는 책임을 회피하는 것이 아니라 **통제된 귀속**입니다. 대상이 operator의 자택 IP나 개인 계정을 쉽게 확인할 수 없어야 하지만, engagement owner는 source를 식별하고, operation을 중지하며, abuse report를 처리하고, evidence를 보존하고, authorization을 입증할 수 있어야 합니다.

이 페이지는 합법적인 engagement를 위한 deployment baseline입니다. compromised ORBs, residential relays, fronting, dead drops, nearby wireless pivots를 포함해 모방하려는 adversary tradecraft에 대해서는 [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) 및 [Government and APT Case Studies](government-and-apt-case-studies.md)부터 확인한 다음, 필요한 telemetry를 [authorized labs](authorized-adversary-emulation-labs.md)에서 재현합니다.

NIST는 rules of engagement (ROE)를 정의된 testing activities에 대한 권한을 부여하는 사전 설정된 제약 조건으로 정의합니다.<sup>[[1]](#references)</sup> Privacy architecture는 해당 권한을 확대할 수 없습니다.

## egress pattern 선택

| Pattern | 적합한 용도 | Target이 확인하는 것 | Provider/local observer가 확인하는 것 | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | 대부분의 assessment | Client address range | Client identity 및 operator access | 가장 강함 |
| Red-team organization bastion | 반복 가능한 controlled egress | Organization range | Hosting provider 및 organization | 강함 |
| Engagement-specific VPS | Client/campaign 격리 | VPS address | Host account, billing, control-plane 및 access logs | 문서화된 경우 강함 |
| Approved commercial VPN | Provider 및 ROE가 허용하는 research/scanning | Shared/dedicated VPN egress | VPN account 및 source connection | 중간 |
| Tor Browser | Destination unlinkability가 필요한 Web research | Tor exit | Local network는 Tor/bridge를 확인하고, destination은 Tor를 확인 | Allowlisted source attribution에는 부적합 |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network 및 remote tunnel provider | Inventory가 관리되는 경우 강함 |
| Lawful guest Wi-Fi | 저위험 administrative/research 용도 | Venue public IP 또는 tunnel egress | Venue, ISP, VPN/Tor | 약하고 물리적으로 관찰 가능 |

대부분의 작업에서 client-provided 또는 organization-controlled fixed egress가 consumer anonymity services보다 안전하고 빠릅니다. 또한 exercise design에 따라 defenders가 알려진 source ranges를 allowlist에 추가하거나, 모니터링하거나, 의도적으로 **allowlist에 추가하지 않을** 수 있습니다.

## ROE infrastructure annex

Deployment 전에 다음을 기록합니다.

- authorization을 부여하고 수령하는 legal entities;
- 정확한 targets 및 명시적인 exclusions;
- start/end times, time zone 및 허용되는 techniques;
- source IPs, autonomous-system/provider names, domains, redirectors, mail infrastructure 및 on-site device identifiers;
- phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence 또는 third-party services의 허용 여부;
- client 및 provider approvals와 모든 pre-notification reference;
- emergency stop phrase, 24/7 client 및 provider abuse contacts, maximum response time;
- 수집 가능한 data classes, encryption, access, retention 및 deletion;
- evidence 및 logging requirements와 public infrastructure에서 operator로 연결되는 mapping을 보유하는 주체;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery 및 final attestation.

Public IPs와 domains가 실제로 authorizing party에 의해 제어되는지, 또는 scope에 명시적으로 포함되어 있는지 확인합니다. NIST SP 800-115는 testing 전에 public target addresses가 organization의 관할하에 있는지 확인할 것을 권장합니다.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Engagement account/project를 생성합니다.** 정확한 billing 및 ownership details를 사용해 red-team organization 아래에 생성합니다. 다른 clients와 roles, API keys, budgets 및 audit logs를 분리합니다.
2. **모든 provider policy를 확인합니다.** Cloud, VPS, CDN, domain, email 및 VPN providers는 서로 다른 rules를 적용합니다. 예를 들어 AWS는 명시된 assessments를 허용하지만 hosted C2/covert simulations에는 사전 승인을 요구하며, 열거된 activities를 금지합니다.<sup>[[3]](#references)</sup>
3. **Fixed egress addresses를 할당하고** ROE annex에 기록합니다. 빠른 IP/resource cycling은 incident response를 복잡하게 만들고 provider policy를 위반할 수 있으므로 피합니다.
4. **Management를 harden합니다.** key-only SSH 또는 identity-aware management plane, phishing-resistant MFA, 별도의 admin network, least privilege, patched images, public admin ports 차단 및 encrypted secret storage를 사용합니다.
5. **Operator endpoint에서 bastion까지 full-tunnel path를 생성합니다.** DNS와 IPv6를 의도적으로 route하고 tunnel이 중단되면 firewall deny를 적용합니다.
6. **가능한 경우 outbound destinations와 ports를 authorized scope로 제한합니다.** Scanners에는 rate limit을 적용하고 irreversible/destructive techniques는 별도의 approval gate 뒤에 둡니다.
7. **Surveillance가 아니라 accountability를 위해 logging합니다.** Operator authentication, configuration changes, start/stop, source address, scoped destination 및 tool/job identifiers를 기록합니다. Exercise와 data plan에서 요구하고 보호하는 경우가 아니라면 payload/credential capture를 피합니다.
8. **Organization이 소유한 controlled endpoint를 통해 검증합니다.** Observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect 및 provider abuse contact를 확인합니다.
9. **Attribution map을 exercise controller 또는 합의된 escrow contact와 안전하게 공유합니다.** Blind detection이 test의 일부인 경우 target team에 이를 공개하지 않습니다.

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
VPS는 destination에 대해서만 pseudonymous합니다. 호스트에는 contact, billing, identity, source-IP, API, device, location, usage records가 남을 수 있으며, customer-visible AWS CloudTrail history만으로도 management activity가 노출될 수 있습니다.<sup>[[4]](#references)</sup> cryptocurrency로 hosting 비용을 지불해도 이러한 records가 삭제되지는 않습니다.

## Domains and certificates

- organization이 소유한 engagement-specific registrar account를 사용합니다.
- registrar lock, 지원되는 경우 DNSSEC, MFA/security keys를 활성화하고, auto-renew는 승인된 기간에만 설정합니다.
- public exposure를 줄이기 위해 registration privacy를 사용하되, registrant information을 허위로 표시하지 않습니다. ICANN policy는 public display가 redacted 또는 proxied된 경우에도 registrars가 registration data를 수집하도록 요구합니다.<sup>[[5]](#references)</sup>
- 관련 없는 제3자를 불법으로 impersonate하는 이름을 사용하지 않습니다. Typosquatting/lookalike domains에는 client와 provider의 명시적인 승인이 필요합니다.
- operators 또는 clients를 leak할 수 있는 DNS, certificates, CDN/redirector configuration 및 third-party analytics를 inventory합니다.
- teardown 시 records를 제거하고, certificates/tokens를 revoke하며, 합의된 evidence를 보존하고, 해당 domain을 defensively retain할지 결정합니다.

## Authorized on-site drop nodes

Raspberry Pi 또는 유사한 appliance는 property/network owner와 client가 정확한 배치 위치와 동작을 명시적으로 승인한 경우에만 허용됩니다. 안전한 계획은 다음과 같습니다.

1. device serial, MAC/private-MAC policy, photo, owner, 정확히 승인된 location, power source, retrieval deadline 및 tamper contact를 기록합니다.
2. 최소한의 signed image, encrypted secrets, read-only 또는 recoverable storage, host firewall, 가능한 경우 automatic security updates를 사용하며, default credentials는 사용하지 않습니다.
3. 명명된 engagement endpoint로 outbound-only communication을 구성합니다. unauthenticated listener를 노출하지 않습니다.
4. destinations와 capabilities를 allowlist에 등록합니다. Packet capture, credential collection, wireless impersonation 및 lateral movement는 각각 명시적으로 승인되어야 합니다.
5. mutual authentication, short-lived keys, remote kill, health reporting 및 bandwidth limits를 사용합니다.
6. 분실 또는 도난 시 재사용 가능한 credentials나 client data가 노출되지 않도록 합니다.
7. retrieval 및 secure wipe/decommission을 일정에 포함하고, 서명된 recovery record를 확보합니다.

owner/operator의 서면 허가 없이 café, hotel, shared office, 이웃의 property 또는 public venue에 hardware를 숨기지 않습니다.

## Guest networks and travel routers

승인된 scenario에서 guest access가 필요한 경우:

- venue/client와 SSID 및 acceptable-use policy를 확인합니다.
- organization이 소유한 travel router 또는 low-trust bridge device를 사용하여 privileged workstation을 격리합니다.
- privileged workstation 외부에서 captive portals를 완료합니다.
- assessment traffic을 시작하기 전에 승인된 tunnel을 시작합니다.
- tethered devices가 실제로 해당 tunnel을 사용하는지 확인합니다.
- venue가 radio association, portal, physical presence 및 camera/payment records를 상호 연관할 수 있다고 가정합니다.
- access control을 우회하거나, 다른 device를 clone하거나, Wi-Fi를 공격하거나, 장비를 남겨 두지 않습니다.

## Operational separation

- 각 client/engagement마다 endpoint compartment, cloud project, secrets set, domain group, redirector set 및 evidence store를 하나씩 분리합니다.
- 승인된 organization systems 외부에서 personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity 또는 payment reimbursement를 사용하지 않습니다.
- exercise design에서 fingerprinting을 허용하지 않는 한, distinctive payload configuration, callback paths, certificates 또는 public repositories를 clients 간에 재사용하지 않습니다.
- infrastructure에 kill date와 budget alert를 설정합니다. 방치된 systems는 client와 Internet 모두에 risk가 됩니다.
- 사고를 조사할 수 있도록 충분한 internal attribution을 보존합니다. “No logs”는 일반적으로 professional evidence 및 safety obligations와 양립할 수 없습니다.

## Blind to defenders, attributable to the controller

exercise objective가 allowlist를 테스트하는 것이 아니라 detection을 측정하는 것이라면, operation의 accountability를 훼손하지 않고 target SOC가 blind 상태를 유지할 수 있습니다.

1. exercise controller가 모든 public source, domain, certificate 및 on-site device를 승인하되, 그 목록은 SOC에 공개하지 않습니다.
2. controller는 source-to-engagement/operator map을 별도의 encrypted vault에 보관하고, two-person emergency access를 적용합니다.
3. 각 operator job에는 scope, time window, source compartment 및 irreversible job identifier가 포함된 signed manifest를 제공합니다. 정상 operation 중 target이 manifest를 볼 필요는 없습니다.
4. bastion audit events를 chained 형식으로 기록하거나 controller storage에 append-only로 전송하여, incident 이후 operator가 attribution을 조용히 다시 작성할 수 없도록 합니다.
5. 24/7 provider-abuse contact가 client를 public하게 공개하지 않고도 authorization을 확인할 수 있는 verification phrase/reference를 보유합니다.
6. 모든 path에 assessment C2, target network 또는 한 operator의 account에 의존하지 않는 out-of-band stop channel을 구현합니다.
7. live testing 전에 모든 source에서 benign canaries를 전송합니다. controller가 ROE response time 내에 이를 resolve하고 stop할 수 있는지 확인합니다.
8. exercise 후 SOC telemetry를 controller ledger와 비교하고, source list를 공개하며, 누락되거나 잘못된 detections를 설명합니다.

anti-forensics, log destruction, compromised relays 또는 false subscriber identities를 추가하지 않습니다. 이는 accountable testing을 개선하는 것이 아니라 무력화합니다.

## Teardown checklist

- [ ] Exercise controller가 stop을 확인합니다.
- [ ] C2, tunnels, redirectors, mail, VPN 및 scheduled jobs를 비활성화합니다.
- [ ] On-site devices를 물리적으로 회수하고 대조합니다.
- [ ] Tokens, API keys, SSH keys, certificates 및 captured credentials를 revoke/rotate합니다.
- [ ] DNS 및 cloud resources를 제거하거나 defensive retention을 위해 transfer합니다.
- [ ] Contract에 따라 client data를 반환, 보존 또는 삭제합니다.
- [ ] Required financial, audit 및 authorization records를 encrypted 상태와 access-controlled 상태로 유지합니다.
- [ ] Provider abuse cases를 종료하고 client에 최종 source indicators를 제공합니다.
- [ ] 두 번째 operator가 infrastructure가 active 상태로 남아 있지 않은지 확인합니다.

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Information Security Testing and Assessment를 위한 Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing를 위한 Customer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
