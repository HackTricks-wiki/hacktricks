# 재현 가능한 Privacy Testing

Privacy setup은 연결되었을 때 끝나는 것이 아닙니다. 주장된 경계가 일반적인 사용, 장애, 복구 및 teardown 상황에서 테스트되었을 때 비로소 완료됩니다. 직접 소유하거나 검사를 수행할 권한이 있는 infrastructure를 대상으로 테스트하세요. 공개 “leak test” 사이트는 또 다른 observer가 됩니다.

## 소규모의 권한이 부여된 테스트 환경 구축

가능하다면 별도의 provider/network에서 다음 세 가지 역할을 사용하세요:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
각 테스트 전에 다음을 기록합니다:

- 테스트 ID, UTC 시작/종료 시간, 운영자 및 승인 정보;
- endpoint/OS/client 버전 및 configuration hash;
- 예상되는 IPv4, IPv6, DNS, TLS, account, payment 및 물리적 관찰 결과;
- 검사할 로그와 해당 로그의 clock/time zone;
- 통과/실패 규칙 및 teardown 시간.

민감한 identity를 절대 먼저 테스트하지 마세요. synthetic account와 tester가 소유한 무해하고 고유한 canary 값을 사용하세요.

## Network-path test

### 1. 기준 상태 캡처

privacy path를 활성화하기 전에 로컬 route와 resolver를 기록합니다:
```bash
ip route
ip -6 route
resolvectl status
```
macOS에서는 `route -n get default`, `netstat -rn -f inet6`, `scutil --dns`를 사용합니다. 출력은 통제된 증거 저장소에만 저장합니다. 출력에는 로컬 식별자가 포함될 수 있습니다.

### 2. 연결 및 라우팅 검사

VPN/Tor/workload namespace를 활성화한 다음, 통제된 public 주소에 대해 선택된 route를 확인합니다:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
문서의 주소를 test server 주소로 교체합니다. 선택한 interface/table이 설계와 일치하는지 확인합니다.

### 3. 양쪽 끝에서 관찰

소유한 endpoint의 URL을 설정한 다음, 고유한 benign 경로를 요청합니다:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
실제 tester가 제어하는 domain, authenticated TLS 및 민감하지 않은 path token을 사용합니다. 다음 항목을 확인하려면 server log를 검사합니다.

- source address/ASN 및 예상 egress;
- IPv4와 IPv6의 차이;
- endpoint에서 확인 가능한 Host/SNI 동작;
- user agent 및 application headers;
- 정확한 시간과 request 재사용 여부.

분리된 요청이라고 간주되는 요청에 `X-Forwarded-For`, 고유한 debug headers 또는 identity-bearing cookies를 추가하지 마세요.

### 4. 소유한 canary로 DNS 테스트

query logs를 제어할 수 있는 authoritative test zone을 구성합니다. compartment를 통해 고유한 random label을 query합니다:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
authoritative log를 확인하세요. 일반적으로 client가 아니라 recursive resolver를 확인합니다. 해당 resolver를 의도한 VPN/Tor/application DNS 설계와 비교하세요. 무작위 public DNS leak 사이트는 필요하지 않습니다.

### 5. fail-closed 동작 테스트

소유한 endpoint를 대상으로 하는 무해한 요청 loop를 유지한 다음 privacy 경로를 중지하세요. workload는 physical interface로 전환하는 대신 실패해야 합니다. 두 address family와 DNS를 모두 확인하세요:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
다음 상황에서 반복합니다:

- tunnel process crash;
- Wi-Fi-to-Ethernet 또는 hotspot 전환;
- sleep/wake;
- DHCP renewal;
- captive-portal state;
- provider reconnect/key expiry.

Linux namespace/container의 tunnel을 중지하고 다른 default route 또는 resolver가 없는지 확인합니다:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
이름과 명령은 배포 환경에 따라 달라집니다. 콘솔 복구 방법 없이 원격 production host에 그대로 붙여 넣지 마세요.

### 6. 로컬 소켓 및 패킷 검사

승인을 받은 상태에서 실제로 통신하는 프로세스/인터페이스를 확인합니다:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
`TEST_SERVER_IP`를 명시적으로 소유한 주소로 교체하고, 관련 없는 사용자의 트래픽을 광범위하게 capture하지 않도록 합니다. 물리 인터페이스에서는 tunnel/bridge peer가 보여야 하며, clear destination traffic은 의도한 layer에만 존재해야 합니다.

## Tor 및 onion-service test

1. Tor Browser에서 Tor Project connection check를 방문하여 Tor 사용을 확인합니다. 이를 신원 증명으로 간주하지 마십시오.<sup>[[1]](#references)</sup>
2. 고유한 canary가 포함된 소유 HTTPS endpoint를 방문하고, 해당 endpoint가 Tor exit을 확인하며 식별 가능한 cookie가 없고 표준 browser context인지 확인합니다.
3. **New Identity**를 선택하고 다른 canary로 다시 방문하여 local state가 예상대로 삭제되었는지 확인합니다. Exit IP 변경은 보장되지 않으며 New Identity의 목적도 아닙니다.
4. onion service의 경우 Tor Browser를 통해서만 접속합니다. 권한이 부여된 external scan으로 service host에 public listener가 없는지 확인하고, application response에 public hostname/IP가 포함되지 않는지 확인합니다.
5. origin outbound DNS/HTTP, template, error page, email/webhook 및 third-party asset을 검사합니다. 직접적인 fetch는 origin 또는 operator account를 노출할 수 있습니다.
6. client authorization이 활성화된 경우, credential이 없는 clean Tor Browser는 연결할 수 없고 credential이 있는 browser는 연결할 수 있는지 확인합니다.
7. test authorization key를 rotate하고, revoke된 client가 onion identity를 변경하지 않고 access를 잃는지 확인합니다.

## Browser-compartment test

test에 필요한 field만 기록하고 retention period를 짧게 설정하는 controlled page를 생성합니다. 다음 항목에 대해 personal compartment와 privacy compartment를 비교합니다.

- cookie/local storage/service worker 및 cache;
- browser sync/login state;
- language, time zone, screen/window dimension 및 font;
- WebRTC/network candidate;
- permission 및 extension에서 확인 가능한 modification;
- server에서 확인되는 TLS/HTTP user-agent data.

Tor Browser를 “더 random하게” 만들려고 시도하지 마십시오. 통과 조건은 personal browser와 최대한 다른 것이 아니라, 표준 anonymity set과 유사하고 personal state가 없는 것입니다.

copy/paste, drag/drop, downloaded-file opening, password-manager suggestion 및 identity-provider button을 테스트합니다. 이는 compartment 간에 자주 사용되는 bridge입니다.

## Operating-system isolation test

### Tails

1. Persistent Storage가 없는 session에서 benign file/canary로 시작합니다.
2. 완전히 종료하고 reboot한 후 해당 항목이 사라졌는지 확인합니다.
3. 필요한 persistence category를 하나만 활성화하고 반복한 다음, 관련 없는 browser/application state가 보존되지 않는지 확인합니다.
4. portal login 후 Unsafe Browser를 민감한 activity에 사용할 수 없는지, Tor application이 정상적으로 reconnect되는지 확인합니다.

### Whonix/Qubes

1. Gateway/net qube를 중지하고 Workstation/app qube가 IPv4, IPv6 또는 DNS에 접근할 수 없는지 입증합니다.
2. 명시적으로 설정된 inter-qube clipboard/file path만 시도하고, 다른 shared-folder/device path가 없는지 확인합니다.
3. disposable qube에서 benign test document를 열고 닫은 다음 state가 사라지는지 확인합니다.
4. vault qube에 NetVM이 없고 template/default 변경을 통해 이를 획득할 수 없는지 확인합니다.
5. test VM을 snapshot/restore하고 identity-bearing state가 예기치 않게 돌아오는지 검사합니다.

## Communications metadata test

선택한 각 messenger에 대해 다음을 수행합니다.

1. 관리하는 device에서 test 전용 participant를 생성합니다.
2. registration에 필요한 항목인 phone, app-store account, IP, push service, username 또는 invitation을 기록합니다.
3. notification preview, linked desktop, wearable 및 backup을 검사하면서 benign message 하나를 전송합니다.
4. 독립된 경로를 통해 safety/security code를 확인합니다.
5. receipt/push를 비활성화하거나 Tor/local transport를 한 번에 하나씩 활성화하고 reliability/metadata 변경을 관찰합니다.
6. test backup을 export 또는 restore하고, 포함된 profile, contact 및 history를 정확히 문서화합니다.
7. test device를 분실/revoke하고, 나머지 participant에게 예상된 key/device 변경이 표시되는지 확인합니다.

관련 없는 사람에게 연락하거나 abusive traffic을 생성하는 방식으로 테스트하지 마십시오.

## File-sanitization test

1. 원본을 hash하고 encrypted evidence storage에 보존합니다:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md)에 설명된 형식별 process를 사용하여 정리된 사본을 생성합니다.
3. metadata inventory를 비교합니다:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. 사본을 disposable context에서 렌더링/열기합니다. 숨겨진 콘텐츠, 첨부 파일, 링크, 폼, 레이어, 썸네일 및 시각적 식별자를 확인합니다.
5. 스테이징된 사본에서만 알려진 canary 작성자/이메일/경로 문자열을 검색합니다.
6. 최종 출력의 hash를 계산하고, 두 번째 사람이 게시할 정확한 파일을 검증하도록 합니다.

ExifTool 출력에 없다고 해서 익명성이 입증되는 것은 아닙니다. 형식 내부 정보, 픽셀, 문장 및 배포 기록은 여전히 남아 있습니다.

## Payment privacy test

허용되는 가장 작은 금액 또는 공식 테스트 네트워크/샌드박스를 사용합니다.

1. payer, payee/merchant, issuer/exchange, network/node, public ledger 및 accountant/controller 각각에 대해 예상되는 view를 작성합니다.
2. 허위 신원을 사용하지 않고 고유한 테스트 invoice/merchant context를 생성합니다.
3. 한 번 결제한 다음, 해당되는 경우 **본인의** 영수증, 명세서, merchant dashboard, wallet/node log 및 public-chain view를 수집합니다.
4. 금액, timestamp, address/token, account, IP/device, 배송 및 refund 경로가 observer table과 일치하는지 확인합니다.
5. Bitcoin의 경우 wallet의 coin-control view에서 address 재사용, 선택된 inputs, change 및 이후 consolidation을 검사합니다.
6. shielded protocol의 경우 실제 pool/path와 viewing key가 공개하는 내용을 검증합니다. wallet branding만 보고 privacy를 추론하지 마십시오.
7. e-cash/Taler의 경우 소액으로 backup/recovery, refund 및 redemption을 테스트하고, mint/exchange/federation 경계 기록을 문서화합니다.
8. virtual card/test credential을 revoke하고 이후 authorization이 실패하는지 확인하는 동시에, 정상적인 refund 처리가 여전히 이해 가능한 상태인지 확인합니다.
9. 필요한 세금/authorization 증빙을 대조하고 암호화하여 보관합니다.

“privacy test”라는 이유로 circular transfer, threshold-splitting, 가짜 구매 또는 의심스러운 refund를 절대 생성하지 마십시오.

## Authorized red-team accountability drill

exercise 전에 tabletop 및 technical drill을 실행합니다.

1. operator가 승인된 각 source path에서 benign canary를 실행합니다.
2. blind testing이 의도된 경우, target SOC는 operator identity를 전달받지 않은 상태에서 탐지한 내용을 기록합니다.
3. exercise controller는 escrow된 map과 서명된 job record를 사용하여 source → engagement → operator를 확인합니다.
4. controller가 emergency stop을 전송하고, operator와 infrastructure owner는 ROE에 지정된 시간 내에 shutdown을 시연합니다.
5. provider abuse에는 올바른 24/7 연락처와 authorization reference가 전달됩니다.
6. 증거에는 불필요한 payload content를 보존하지 않고 target, time, tool/job 및 operator가 표시됩니다.
7. 두 번째 operator가 credential revocation 및 resource teardown을 검증합니다.

SOC가 개인/가정 인프라를 쉽게 확인할 수 **있거나**, controller가 source를 신속하게 귀속하고 중지할 수 없다면 readiness review를 통과시키지 마십시오.

## Test record template
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — 연결 확인](https://check.torproject.org/)
- [2] [WireGuard — Routing 및 Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ 및 metadata guidance](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — 정보 보안 Testing 및 Assessment를 위한 Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
