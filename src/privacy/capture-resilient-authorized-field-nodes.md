# Capture-Resilient Authorized Field Nodes

현장에 배치된 Raspberry Pi, mini-PC, travel router 또는 cellular appliance는 authorized red team에 지속적인 vantage point를 제공할 수 있습니다. 그러나 이는 발견, 도난 및 attribution이 발생할 가능성이 높은 지점이기도 합니다. 따라서 올바른 설계 목표는 **현장 node에 권한을 거의 부여하지 않은 안정적이고 통제된 access**이지, 추적이 불가능한 implant가 아닙니다.

이 가이드는 site 소유자의 서면 승인을 받아 배치된 장비에만 적용됩니다. 네트워크에 연결할 수 있다는 이유만으로 coffee shop, 이웃, 호텔 또는 shared building이 scope에 포함되는 것은 아닙니다. 동의하지 않은 장소에 hardware를 숨기거나, captive portal을 우회하거나, 타인의 credentials를 사용하거나, monitoring을 방해하거나, 발견 후 evidence를 삭제하려고 하지 마십시오.

{% hint style="warning" %}
신뢰할 수 있는 “흔적을 남기지 않는” 설정은 없습니다. Radio association, DHCP/NAT, carrier, camera, purchase, device, provider, controller 및 destination records는 device가 제거된 후에도 남을 수 있습니다. 책임 있는 red team은 대신 node에서 **개인 정보와 관련 없는 secrets**를 제거하고, 보호된 controller-side attribution을 보존하며, capture 발생 시 쉽게 격리할 수 있도록 설계합니다.
{% endhint %}

## 장단점

**장점:** 현실적인 internal 또는 target-adjacent source; 안정적인 high-speed testing; NAC, egress, physical inventory 및 SOC coverage 검증; operator address 변경 후에도 지속 가능; bounded access를 중앙에서 revoke 가능.

**단점:** physical placement로 인해 강력한 evidence가 생성됨; 분실 시 device credentials, network profiles 및 수집된 data가 노출될 수 있음; 반복적인 control traffic은 탐지 가능함; power, portal 및 radio 변경으로 reliability가 저하됨; broad tunnel은 통제되지 않는 pivot이 될 수 있음.

## Threat model 및 설계 불변 조건

발견자가 storage를 제거하고, firmware를 검사하고, software가 보유한 모든 secret을 복사하고, 이후 network behavior를 관찰하며, device를 client 또는 law enforcement에 제공할 수 있다고 가정합니다. Full-disk encryption은 명시된 threat model하에서 전원이 꺼진 device만 보호합니다. 실행 중인 unlocked node와 memory에 release된 keys는 서로 다른 경우입니다.

| 불변 조건 | 실제 영향 |
|---|---|
| Operator-to-node 간 직접적인 identity 없음 | Operator는 organization gateway에 sign in하며, node는 별도의 device identity를 가짐 |
| 개인 workstation material 없음 | 개인 SSH key, browser profile, email, password manager, phone pairing 또는 cloud CLI cache를 사용하지 않음 |
| Controller master secret 없음 | 하나의 node가 다른 node를 enroll하거나, policy를 변경하거나, 다른 engagement를 decrypt할 수 없음 |
| Outbound-only 및 제한적 범위 | Field network는 management listener를 허용하지 않으며, node는 이름이 지정된 rendezvous/update/time services에만 연결 |
| 짧은 수명과 제한된 범위의 authority | 각 credential은 하나의 device, audience, service, expiry 및 즉시 revoke 경로를 가짐 |
| 최소한의 local data | Results는 controller로 stream하며, caches는 encrypt되고 size/TTL이 제한되며 authoritative하지 않음 |
| Capture 후에도 controller accountability 유지 | Asset-to-engagement mapping, approvals, operator access 및 commands가 중앙에 저장되고 access-controlled 상태로 유지됨 |
| 분실 시 작업 중단 | Discovery 또는 설명되지 않는 state change가 발생하면 remote destruction이 아니라 stop, revoke, notify 및 evidence preservation을 실행 |

NIST의 IoT baseline은 device identification, configuration, data protection, logical access, secure software update 및 cybersecurity-state awareness를 핵심 capability로 분류합니다. 또한 state awareness와 off-device event records가 compromise investigation을 지원한다고 명시합니다.<sup>[[1]](#references)</sup>

## Reference architecture
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
게이트웨이는 어떤 이름이 지정된 operator가 어떤 이름이 지정된 device에 접근했는지 알아야 합니다. field node에는 rendezvous를 위한 device credential만 필요합니다. field node는 operator의 source address나 authentication secret을 절대 알 수 없으며, operator도 private management key를 field node에 복사하지 않습니다. 이를 통해 exercise accountability를 훼손하지 않으면서 **field storage에서** 복구할 수 있는 개인적 연결을 줄일 수 있습니다.

더 큰 fleet의 경우 workload-identity 시스템을 사용해 단기 X.509 identity를 발급하고 key를 자동으로 rotate할 수 있습니다. SPIFFE는 가능한 경우 X.509 SVID를 권장하며, 짧은 lifetime과 빈번한 rotation이 key-compromise 노출을 제한한다고 설명합니다.<sup>[[2]](#references)</sup> 소규모 팀은 private CA와 device별 automated certificate를 사용해 동일한 속성을 적용할 수 있습니다. 단지 이 pattern을 충족하기 위해 SPIRE를 설치할 필요는 없습니다.

## Step 1: placement를 authorize하고 register하기

1. owner, site, 정확히 허용된 placement zone, 허용된 network, assessment window, 허용된 destination/action 및 emergency contact를 기록합니다.
2. model, serial, storage serial, wired/wireless MAC, modem IMEI/eSIM 또는 SIM ICCID, power supply 및 최신 사진을 기록합니다.
3. device에 비개인적인 engagement identifier를 부여합니다. 예: `E2026-014-DROP03`. broadcast hostname이나 SSID에 client name을 넣지 않습니다.
4. exercise controller와 필요한 최소한의 physical-security/SOC deconfliction group에 이 test에서 “lost”, “moved” 및 “discovered”가 무엇을 의미하는지 알립니다.
5. 누가 device를 회수할 수 있는지와 finder가 어떻게 신고할 수 있는지 사전에 합의합니다. safety label은 민감한 client detail을 생략하면서도 통제된 callback을 제공할 수 있습니다.
6. automatic authorization expiry를 설정합니다. scope 종료 후에도 connectivity가 계속된다고 해서 permission이 연장되어서는 안 됩니다.

## Step 2: 최소한으로 복구 가능한 image 구축

지원되는 OS image를 사용하고, vendor가 문서화한 channel을 통해 signature/checksum을 확인하며, security update를 설치하고 재현 가능한 build manifest를 유지합니다. software가 허용하는 경우 writable data partition을 작게 둔 read-only 또는 immutable base를 우선합니다.

1. authorized workload에 필요하지 않은 default account, demo service, compiler 및 package를 제거합니다.
2. exercise에서 명시적으로 요구하지 않는 한 local GUI, Bluetooth, discovery protocol, file sharing, Wi-Fi P2P 및 inbound administration을 비활성화합니다.
3. hardware가 실제로 지원하는 경우 secure boot와 measured boot/TPM-backed key release를 활성화합니다. 정확한 model을 검증하지 않고 Raspberry Pi configuration이 PC-class measured boot를 제공한다고 주장하지 않습니다.
4. local writable state를 encrypt하고 엄격한 maximum size와 retention time을 설정합니다. encryption은 delay/containment control이지, 실행 중인 node가 아무것도 reveal하지 않는다는 증거가 아닙니다.
5. 중요한 log를 device 외부로 전송합니다. storage exhaustion을 방지하도록 local journal의 크기를 제한하되, log wiping이나 anti-forensic deletion을 설정하지 않습니다.
6. image manifest, package version, configuration hash 및 recovery instruction을 controller에 저장합니다.
7. manifest에서 spare를 reimage하고 동일한 health test를 실행합니다. builder만 복구할 수 있는 design은 field-ready가 아닙니다.

## Step 3: one-way trust로 identity 발급

서로 다른 세 가지 identity를 생성합니다.

- 이 device의 rendezvous에서만 허용되는 **device identity**;
- organization gateway에서 허용되고 phishing-resistant MFA로 보호되는 **operator identity**; 그리고
- approved job 또는 configuration에 서명하는 데 사용되며 operator와 field node 양쪽의 외부에 보관되는 **controller/deployment identity**.

node에는 signed job을 verify하는 데 필요한 public key가 있어야 하며, signing key는 절대 있어서는 안 됩니다. 탈취된 device credential은 cloud console, source repository, payment account, 다른 node 또는 client production에 authenticate할 수 없어야 합니다.

automatic renewal이 안정적으로 작동하는 경우 짧은 certificate lifetime을 사용합니다. 운영상 long-lived WireGuard key가 필요한 경우 public key를 revocation handle로 간주하고, peer별 tunnel address, firewall policy 및 broker authorization으로 제한합니다. 해당 peer를 즉시 제거하는 테스트된 controller action을 유지합니다.

## Step 4: 안정적인 outbound rendezvous

다음의 owned-lab pattern은 inbound service를 노출하지 않고 NAT를 통한 안정적인 management를 제공합니다. 이는 covert reverse shell이 아니라 일반적인 WireGuard networking입니다. documentation address를 사용하고, 실제 사용 시 organization이 소유한 endpoint로만 교체합니다.

organization rendezvous에서 `10.77.0.1/32`를 할당하고, field node에는 `10.77.0.20/32`를 할당합니다. gateway peer entry는 node의 단일 address만 허용해야 합니다:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
노드는 rendezvous로 outbound 연결을 수립하며 필요한 경우에만 NAT 매핑을 유지합니다:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard 문서는 persistence가 필요한 경우 다양한 NAT/firewall 구현에서 25초를 합리적인 keepalive interval로 설명하며, 필요하지 않다면 이를 비활성화하는 것이 바람직하다.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32`는 의도적으로 이를 management path로 설정하며, default-route pivot으로 만들지 않는다.

그런 다음 WireGuard 외부에서 다음 controls를 적용한다.

1. 승인된 bootstrap DNS path를 통해 `vpn.redteam.example`을 resolve하고, 예상되는 organization endpoint를 deployment records에 고정한다.
2. 노드에서 outbound DHCP/RA, 필요한 DNS/NTP, rendezvous endpoint 및 최소한의 승인된 update path만 허용한다. 모든 uplink에서 unsolicited inbound traffic을 거부한다.
3. rendezvous에서 `10.77.0.20`이 exercise에 필요한 broker/health service에만 접근하도록 허용한다. 이를 일반적인 client network로 forward하지 않는다.
4. interactive operator access를 organization gateway 뒤에 둔다. signed pull-job interface가 assessment를 충족한다면 tunnel을 통해 노드에서 SSH를 노출하지 않는다.
5. service manager가 networking 이후 tunnel을 시작하고, failure 후 bounded backoff로 재시작하며, 반복적인 failure 후 alert하도록 구성한다. restart loop가 venue를 압도하거나 근본 fault를 숨겨서는 안 된다.
6. peer의 latest handshake를 확인하되, “handshake exists”를 device가 uncompromised하다는 증거로 사용하지 않는다.

TURN은 purpose-built WebRTC control plane에 relay-only reachability를 제공할 수 있고, message queue는 간헐적인 service를 견딜 수 있다. TURN은 NAT 뒤의 client에 public relay address를 명시적으로 제공하며, 그 server는 여전히 observer로 남는다.<sup>[[4]](#references)</sup> 명시된 observer 또는 reliability benefit 없이 tunnel을 겹쳐 구성하지 말고 하나의 control architecture를 선택한다.

## Step 5: personal links 없이 uplink stability 확보

승인된 venue node에는 다음 순서를 우선 적용한다.

1. client가 제공한 wired 또는 dedicated test VLAN;
2. owner가 승인한 enterprise/guest Wi-Fi profile;
3. organization이 계약한 cellular/private APN fallback.

personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account 또는 daily laptop에서 export한 Wi-Fi profile을 절대 사전에 설정하지 않는다. 이러한 artifact는 capture가 연결할 바로 그 대상이다.

각 승인된 uplink에 대해 다음을 수행한다.

- SSID/BSSID 또는 switch/VLAN과 예상되는 captive-portal behavior를 기록한다.
- deterministic priority와 owned endpoint에 대한 health check를 설정한다.
- failover는 underlay만 변경하도록 한다. device와 operator identity는 broker에 유지된다.
- transition 중 DNS, IPv6 및 application traffic이 rendezvous를 우회하지 않도록 한다.
- 알 수 없는 SSID/BSSID, SIM 변경, 새로운 default gateway, public-IP/ASN 변경 또는 simultaneous uplinks를 alert한다.
- deployment 전에 power loss, DHCP renewal, AP restart, public-IP 변경, 24시간 idle, tunnel loss 및 primary-to-secondary-to-primary recovery를 테스트한다.

Private MAC addressing은 casual cross-network tracking을 줄일 수 있지만, 승인된 NAC에는 network별 stable MAC이 필요한 경우가 많다. 선택한 OS가 실제로 수행하는 동작을 기록하고, owner의 access control을 우회하도록 rotate하지 않는다.

## Step 6: 작업과 데이터 제한

안전한 field node는 mailbox에서 임의의 shell text를 받아서는 안 된다. `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` 또는 rules of engagement에 명시된 다른 action과 같은 signed job type을 정의한다. destination, duration, rate, output size 및 scope를 노드에서 다시 검증한다.

1. 모든 job에 unique ID, device audience, issue time, expiry, scope reference 및 maximum output을 부여한다.
2. controller/deployment identity로 서명한다.
3. 알 수 없는 field, expired/replayed job 및 다른 device를 대상으로 한 job을 거부한다.
4. 결과를 owned collector로 stream하고, 불가피한 local spool은 encrypt하고 TTL을 설정한다.
5. controller에서 accepted/rejected job ID와 result hash를 log한다. 민감한 command parameter를 public monitoring channel에 포함하지 않는다.
6. authorization이 만료되거나, identity rotation이 실패하거나, controller가 device를 quarantined로 표시하면 processing을 중지한다.

## Discovery, loss 또는 compromise 모니터링

Monitoring은 observed state가 변경되었음을 controller에 알릴 수 있다. 그러나 “investigators found the device”를 신뢰성 있게 증명할 수는 없으며, responders를 surveil하거나 그들의 system을 probe하려는 시도는 authorized assessment의 범위를 벗어난다.

### off-device state 수집

randomized이지만 bounded된 operational interval로 signed, low-volume health record를 controller에 전송한다. controller에 필요한 정보만 포함한다.

- device ID, boot ID/counter 및 monotonic uptime;
- configuration/image hash 및 software version;
- device-certificate serial 및 renewal state;
- 승인된 범위 내의 uplink class, interface, BSSID 또는 switch context, default-gateway hash 및 owned service가 관찰한 public IP/ASN;
- tunnel handshake age, packet counters 및 queue depth;
- owner가 sensor를 승인한 경우 enclosure switch 또는 hardware-tamper state;
- disk pressure, temperature, clock-offset estimate 및 last successful job ID;
- replay 또는 gap을 드러내기 위한 sequence number 및 signature.

gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events 및 alerts를 중앙에 저장한다. CISA는 logs를 중앙화하고, 삭제로부터 보호하며, 정상 activity를 baseline으로 설정하고, incident-response contacts를 지정할 것을 권고한다.<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking 또는 removal | provider/site state를 corroborate한다. 승인되지 않은 path에서 reconnect하지 않는다 |
| Boot counter changed unexpectedly | power cut, crash, removal 또는 maintenance | jobs를 quarantine한다. time과 site events를 비교한다 |
| Config/image hash changed | update error, storage fault 또는 tampering | 작업을 중지한다. controller-approved release가 아니라면 revoke한다 |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device 또는 interception | approved inventory와 비교한다. 설명되지 않는 transition은 quarantine한다 |
| Repeated rejected job/signature | corruption, replay 또는 unauthorized controller | processing을 중지하고 gateway/controller logs를 조사한다 |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse 또는 network transition | 즉시 revoke한다. 두 session records를 모두 보존한다 |
| Unexpected local login, interface, process 또는 privilege event | maintenance 또는 compromise | broker policy를 통해 isolate한다. evidence를 보존한다 |
| Enclosure switch/state transition | service, movement 또는 discovery | 지정된 site contact에 알린다. destructive action을 trigger하지 않는다 |
| Provider abuse notice/account query 또는 SOC alert | detection, misconfiguration 또는 out-of-scope traffic | activity를 중지하고 deconfliction/incident process를 실행한다 |
| Sentinel credential touched | 누군가 이 노드에만 존재하는 no-privilege decoy secret을 읽었다는 의미 | 실제 device identity를 revoke하고 alert trail을 보존한다 |

sentinel credential은 **어떠한 access도 부여해서는 안 되며**, organization-owned alert service만 호출하고, rules of engagement에 공개되어야 한다. 이는 unauthorized reading을 감지하는 tripwire이지, 장비를 발견한 사람을 tracking하기 위한 beacon이 아니다.

### Alert thresholds

하나의 극적인 “caught” alarm이 아니라 stateful rule을 사용한다.

- **warning:** 한 번의 interval 누락, 정상적인 address change 또는 queue growth;
- **degraded:** 세 번의 연속 누락, renewal delay, primary-uplink loss 또는 repeated restart;
- **quarantine:** unapproved hash/boot/uplink change, duplicate credential, sentinel use 또는 unexpected privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, 계획에 없던 party에 의한 device recovery 또는 검증된 provider/SOC escalation.

field node와 독립된 channel을 통해 alert delivery를 테스트한다. 민감한 client/device detail을 personal messaging 또는 consumer push account로 보내지 않는다.

## Suspected discovery 또는 capture runbook

1. **Stop:** 새로운 jobs와 operator sessions를 중지한다. 감시 여부를 확인하는 “check if watched” probe를 보내지 않는다.
2. **Quarantine:** 기존 logs는 보존하면서 broker가 device identity와 해당 routes를 deny하도록 한다.
3. **Revoke:** device certificate/key, queue token, update credential 및 single-purpose service token을 revoke한다. physical loss 가능성이 있으면 organization SIM을 suspend한다.
4. **Preserve:** controller, gateway, provider 및 alert records를 snapshot하고, trusted time, 조치한 사람 및 last known configuration을 기록한다. 노드를 clear하거나 remotely wipe하지 않는다.
5. **Notify:** exercise controller, client incident contact 및 authorization에 정의된 legal/privacy contacts에 연락한다. third party가 이를 발견한 경우 사전에 합의한 recovery process를 사용한다.
6. **Assess:** 노드의 모든 secret과 cached result가 노출되었다고 가정한다. 각 secret이 접근할 수 있었던 대상을 정확히 열거하고, suspicious event 이후 사용되었는지 확인한다.
7. **Contain downstream:** 영향을 받은 service credential을 rotate하고, pending jobs를 invalidate하며, owned target/provider logs에서 예상하지 못한 behavior를 검사한다.
8. **Recover safely:** authorized person을 통해서만 회수한다. 사진을 촬영하고 포장하며, custody를 기록하고, client의 지시에 따라 forensic evidence를 확보한다.
9. **Resume with a new identity:** captured credential을 조용히 다시 활성화하지 않는다. known manifest에서 rebuild하고, control failure를 수정한 뒤 명시적인 승인을 받는다.

NIST의 current incident-response guidance는 preparation, detection, response 및 recovery를 organization-wide cybersecurity risk management에 통합한다. client가 무슨 일이 일어났는지 판단하고 적절한 response를 선택할 수 있도록 먼저 보존한다.<sup>[[6]](#references)</sup>

## Deployment 전 Capture drill

잠금 해제된 test unit 또는 해당 storage의 copy를 별도의 reviewer에게 전달하고 다음 항목을 열거하도록 요청한다.

1. device/site/engagement identifiers;
2. operator names, personal accounts, home/workstation networks 및 recovery contacts;
3. controller/broker destinations 및 credentials;
4. client network profiles 및 cached results;
5. 각 secret으로 접근 가능한 다른 devices/projects;
6. value 또는 payment credentials;
7. controller가 무엇을 revoke할 수 있으며 얼마나 빨리 가능한지;
8. central logs에서 어떤 activity가 계속 attributable한지.

통과 기준: personal accounts/workstation keys 없음; cross-engagement 또는 enrollment authority 없음; payment credential 없음; bounded encrypted cache; 문서화된 device-revocation action 하나; 완전한 controller-side accountability. 예상하지 못한 personal link 또는 lateral capability는 release blocker로 취급한다.

## Closeout

1. scope 종료 시 jobs를 중지하고 broker route를 disable한다.
2. 정확한 inventory를 회수하고 대조하여 누락된 항목을 보고한다.
3. engagement retention plan에 따라 logs/results 및 필요한 경우 forensic image를 보존한다.
4. hardware가 회수되었더라도 device, SIM, queue, update 및 service identities를 revoke한다.
5. preservation/acceptance 이후에만 owner가 승인한 data-disposal process로 media를 sanitize 또는 destroy하고 완료 사실을 기록한다. 이는 concealment가 아니라 lifecycle management이다.
6. venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules 및 temporary contacts를 제거한다.
7. 관찰된 detection, 누락된 telemetry, quarantine까지 걸린 시간 및 capture가 노출한 모든 artifact를 문서화한다.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
