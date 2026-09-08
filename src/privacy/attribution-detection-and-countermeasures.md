# Attribution, Detection and Countermeasures

{{#include ../banners/hacktricks-training.md}}

Attribution-evasion infrastructure는 개별 indicator를 일회용으로 만들도록 설계됩니다. Defenders는 raw evidence를 보존하고, 관계를 모델링하며, IP, domain 또는 persona가 변경되어도 지속되는 behavior를 hunt해야 합니다.

## Evidence hierarchy

| Evidence | Useful for | Main caveat |
|---|---|---|
| Source IP/ASN/geolocation | 노출된 exit와 provider의 위치 파악 | exit가 relay, NAT 또는 victim일 수 있으며 geolocation은 대략적임 |
| Passive DNS/registration | infrastructure history와 co-hosting 파악 | privacy/redaction 및 shared hosting으로 인해 공백이 발생함 |
| Certificate/TLS/HTTP fingerprint | 반복되는 deployment를 cluster화 | 일반적인 software와 mimicry로 false positive가 발생함 |
| Flow timing and byte shape | relay stage와 반복되는 beacon 연결 | CDN/NAT 및 제한된 visibility로 확실성이 낮아짐 |
| Endpoint process/identity | connection이 발생한 이유 설명 | edge/IoT에는 존재하지 않으며 attacker가 native tool을 사용할 수 있음 |
| Cloud/CDN/API audit | tenant와 infrastructure control 식별 | retention 및 provider/legal access는 서로 다름 |
| Payment/account/device | procurement을 사람/entity와 연결 | nominee, compromise 및 shared device를 고려해야 함 |
| Seized implant/configuration | key, peer, controller 및 build link 노출 | collection integrity와 seizure 시점이 중요함 |
| Human/physical evidence | digital event를 장소/operator와 연결 | intrusive하고 jurisdiction에 의존하며 엄격한 handling이 필요함 |

어떤 단일 행도 high-confidence state attribution을 뒷받침해서는 안 됩니다. competing hypotheses를 사용하고, 각 hypothesis를 falsify할 observation이 무엇인지 명시하세요.

## Minimum telemetry

1. **DNS:** client, question, type, answer, TTL, response code, resolver 및 timestamp.
2. **Network flow:** source/destination/port, start/end, packet/byte 수, TCP flag 및 sensor location.
3. **TLS/HTTP:** 확인 가능한 경우 SNI, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status 및 byte 수. 민감한 full URL은 보호하세요.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID 및 risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash 및 destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface 및 flow log.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token 및 result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP 및 posture.

Clock를 동기화하고, original time zone을 유지하며, NAT/proxy boundary를 문서화하고, 31일의 ORB node보다 오래 유지될 수 있을 만큼 충분한 history를 보존하세요.

## Build an attribution graph

Observation을 typed node와 edge로 표현합니다:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
유용한 노드에는 IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, payment instrument 및 physical device가 포함됩니다. 모든 edge에는 `first_seen`, `last_seen`, sensor/source, confidence와 함께 해당 edge가 observed인지 inferred인지 여부가 필요합니다.

Graph density만으로 판단하면 오해의 소지가 있습니다. CDN이나 certificate authority는 서로 관련 없는 많은 actor를 연결하기 때문입니다. 일반적인 hosting보다 동일한 API account, SSH key, origin allowlist, 고유한 response body 또는 control protocol처럼 operator가 제어할 가능성이 높은 희귀한 관계에 더 높은 가중치를 부여해야 합니다.

## ORB 및 compromised-router hunting

### 관찰된 exit에서

1. 해당 address가 hosting, residential, mobile, education 또는 business 중 어디에 해당하는지 확인합니다. residential source를 제외하지 마십시오.
2. 제한된 기간을 기준으로 historical DNS, services/certificates, open ports 및 관찰된 scan/exploitation behavior를 수집합니다.
3. 희귀한 service fingerprint, controller destination, certificate material 또는 rotation timing을 공유하는 peer를 검색합니다.
4. 가능한 role을 access, traversal, exit/staging 또는 administration으로 분류합니다.
5. 서로 관련 없는 여러 intrusion cluster가 동일한 pool을 사용했는지 확인합니다. multi-tenancy는 직접적인 actor attribution의 신뢰도를 낮추지만 ORB 가설은 강화합니다.
6. 기존 IP가 사라진 후 role profile과 일치하는 새 node를 추적합니다.

### network owner 측에서

- 새로 Internet-exposed된 management와 default/legacy authentication을 alert합니다.
- router/firewall/VPN configuration 변경 및 admin authentication을 device 외부로 전송합니다.
- 일반적으로 거의 session을 시작하지 않는 infrastructure에서 발생하는 outbound connection을 baseline으로 설정합니다.
- 새로운 proxy/listener process, tunnel, scheduled task, firmware 변경 및 예상치 못한 DNS를 탐지합니다.
- end-of-life device를 교체합니다. volatile malware를 제거하는 reboot만으로는 exposure가 해결되지 않습니다.
- management를 authenticated administration plane 및 알려진 source로 제한합니다.

Mandiant는 단기간의 IP blocking으로는 topology와 lifecycle을 파악할 수 없으므로 ORB infrastructure를 변화하는 entity로 추적할 것을 권장합니다.<sup>[[1]](#references)</sup>

## Fast-flux 및 dynamic-DNS analytics

registered domain과 sliding window를 기준으로 집계합니다. 실용적인 score는 다음 요소를 결합할 수 있습니다:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
여러 독립적인 특징을 사용해 도메인을 조사하고, 단일 임계값에 의존하지 마세요. CDN/anti-DDoS allow-model과 비교하고 authoritative name-server rotation을 확인해 single flux와 double flux를 구분하세요. DGA의 경우 client별 NXDOMAIN burst, 길이/문자 분포, 호스트 간 동기화된 쿼리, 그리고 이를 생성하는 process를 추가로 확인하세요. MITRE의 최신 guidance 역시 high-frequency change, low TTL, process/network correlation을 강조합니다.<sup>[[2]](#references)</sup>

## Domain-fronting 탐지

enterprise endpoint 또는 authorized inspection point에서 두 identity를 모두 확인할 수 있다면 다음을 비교하세요:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
SNI와 authority가 서로 관련 없는 tenant에 속하고, 해당 프로세스가 승인된 client가 아니며, 세션이 주기적이거나 장시간 유지되고, inner origin이 드문 경우 confidence를 높입니다. 빈 SNI는 자동으로 악성으로 판단할 것이 아니라 기록해야 하는 feature입니다. ECH는 wire 상에서 SNI를 숨길 수 있으므로 endpoint, DNS 및 provider/CDN 로그가 더욱 중요해집니다. MITRE는 불일치 SNI variant와 blank-SNI variant를 모두 문서화합니다.<sup>[[3]](#references)</sup>

## Dead-drop resolver sequence detection

high-signal behavior는 차단된 domain이 아니라 sequence입니다:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
전체 fleet에서 동일한 object path, response hash, API identifier 및 후속 destination을 탐색하십시오. actor가 가져온 content를 수정하거나 삭제할 수 있으므로 fetched content를 보존하십시오. 불필요한 service API를 제한하고 승인된 application이 enterprise proxy를 사용하도록 요구하되, developer tool과 automation은 고려하십시오. MITRE는 실제 절차에서 GitHub, forum, document 및 social/web service를 열거합니다.<sup>[[4]](#references)</sup>

## Redirector 및 재사용 가능한 deployment clustering

domain과 address가 변경되더라도 operator는 동일한 automation을 재배포하는 경우가 많습니다. 다음 조합을 기준으로 cluster를 구성하십시오.

- certificate field/key 재사용 및 발급 시점;
- TLS version/cipher/extension 순서 및 server 동작;
- 동일한 HTTP status, header 순서, cache 동작, icon/body 및 error page;
- 비정상적인 port pair 및 redirect chain;
- DNS provider/name-server pattern 및 TTL schedule;
- deployment 시점, uptime 및 maintenance window;
- back-end origin 노출 또는 동일한 allowlist.

단일한 generic Nginx page는 근거가 약합니다. 서로 독립적인 여러 희귀 일치와 시간적 연속성이 함께 나타나면 infrastructure cluster 가설을 세울 수 있습니다.

## Residential proxy 및 impossible-session 탐지

IP layer보다 상위에서 session identity를 유지하십시오. 다음과 같은 조합에 flag를 지정하십시오.

- 하나의 session/device fingerprint가 이동으로 설명할 수 있는 속도보다 빠르게 국가/ASN을 변경하는 경우;
- cookie와 TLS/browser identity는 고정된 상태에서 consumer IP가 모든 request마다 변경되는 경우;
- 주장된 local device의 latency/time zone/language가 exit와 일치하지 않는 경우;
- 하나의 address가 서로 관련 없는 account population을 번갈아 사용하거나 backconnect proxy 동작을 보이는 경우;
- privileged session이 organization의 device certificate 없이 residential access에서 나타나는 경우.

Carrier NAT, accessibility tool, corporate VPN 및 여행은 정상적인 anomaly를 발생시킬 수 있습니다. “residential proxy” label만을 근거로 되돌릴 수 없는 blocking을 수행하지 말고, step-up authentication 또는 조사를 요구하십시오.

## Wireless 및 covert-device 탐지

RADIUS/NAC를 AP 및 물리적 context와 결합하십시오.

1. 처음 관찰된 account–device–AP 조합을 찾습니다.
2. managed EAP certificate/posture 없이 사용된 credential을 식별합니다.
3. 동시 session 및 badge/building 존재 여부를 비교합니다.
4. 비정상적으로 약하거나 경계에 가까운 signal 및 AP 간 이동을 검사합니다.
5. 인근 managed endpoint에서 wireless scanning, 새로 활성화된 interface bridge/NAT, virtual adapter 또는 tunnel을 검색합니다.
6. 새로운 switchport, DHCP, USB network 및 PoE activity를 inventory합니다.
7. 근거가 이를 뒷받침하는 경우 승인된 RF/physical sweep을 수행합니다.

이는 APT28식 nearest-neighbor 경로와 exercise drop을 모두 탐지할 수 있습니다. MAC randomization을 identity 또는 guilt로 취급해서는 안 됩니다.

## Financial-attribution 탐지

- 정확한 chain, token, address, transaction 및 block identifier를 보존합니다.
- change, peel chain, fan-out/in, mixer, bridge 및 service deposit을 통한 value 흐름을 추적하되 heuristic임을 표시합니다.
- 시간, 수수료를 제외한 금액, contract event, liquidity 및 destination-chain withdrawal을 상관 분석합니다.
- 적법한 exchange, bridge, merchant, account, device 및 delivery record를 확보하거나 보존합니다.
- 적용 가능한 program에 따라 현재 제재 대상 entity/address 및 파생 대상을 screening하되, 오래된 static list에 의존하지 않습니다.
- privacy-protocol 사용은 wrongdoing의 증거가 아니라 risk-context input으로 취급합니다.

FATF의 red flag는 명시적으로 context에 따라 해석됩니다. 비정상적인 pattern, amount/frequency, geography, source of funds 및 anonymity-enhancing service는 함께 나타날 때 의미를 갖습니다.<sup>[[5]](#references)</sup>

## Deception 및 canary

Defender는 일반 사용자를 deanonymize하려 하지 않고도 높은 신뢰도의 signal을 만들 수 있습니다.

- 하나의 system 밖으로 절대 나가서는 안 되는 고유 credential 또는 document;
- 가짜 administrative endpoint 및 decoy share;
- 통제된 artifact에만 삽입된 instrumented DNS name;
- 정당한 사용처가 없는 canary cloud key;
- 어떤 managed device도 보유하지 않은 decoy Wi-Fi identity.

Deception의 범위와 운영을 신중하게 관리하십시오. canary는 defender 자신의 asset이 오용되었음을 식별해야 하며, 관련 없는 third-party traffic을 수집해서는 안 됩니다.

## Countermeasure 우선순위

1. 지원되지 않는 Internet-facing router, VPN 및 appliance를 제거합니다.
2. 내부/wireless access를 포함하여 phishing-resistant MFA 및 device-bound certificate를 요구합니다.
3. 충분히 immutable한 identity, endpoint, DNS, flow, proxy, cloud 및 network-device log를 중앙화합니다.
4. management 및 egress를 제한하고, 외부에서 도달 가능한 모든 service를 inventory합니다.
5. DNS, certificate transparency 및 cloud configuration을 모니터링하여 unauthorized asset을 탐지합니다.
6. process-to-network 및 object-level SaaS visibility를 보존합니다.
7. cross-layer investigation 및 neighboring-provider coordination을 훈련합니다.
8. IP blocklist만이 아니라 infrastructure cluster와 behavior를 추적합니다.

## Analytical discipline

다음과 같은 confidence language를 사용하십시오.

- **Observed:** sensor/provider record가 해당 관계를 직접 보여줍니다.
- **Strongly supported:** 여러 독립적인 관찰이 다른 대안보다 해당 설명을 지지합니다.
- **Assessed:** 명시된 assumption과 evidence에 기반한 inference입니다.
- **Unknown:** visibility가 부족하여 결론을 내릴 수 없습니다.

항상 최소 두 가지 가설을 유지하십시오. actor-operated infrastructure와 compromised/shared intermediary, 단일 actor와 multi-tenant service, deliberate evasion과 legitimate privacy/CDN behavior를 각각 고려해야 합니다. 불확실성을 설명할 수 있는 능력은 올바른 detection의 일부입니다.

## References

- [1] [Google Cloud/Mandiant — China-nexus espionage actor가 ORB network를 사용](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Asset Red Flag Indicator](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actor가 compromise하고 persistent access를 유지](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — communications infrastructure를 위한 향상된 visibility 및 hardening guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
