# 은닉형 물리 및 무선 접근

{{#include ../banners/hacktricks-training.md}}

아웃바운드 랑데부, 전원/업링크 복구, 기기에 저장되는 비밀 정보 최소화, 캡처 테스트, 발각 가능성 모니터링을 포함한 상세한 소유자 승인 구현은 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)를 참조하세요.

네트워크 경로를 바꾸면 겉으로 드러나는 물리적 출발지도 달라질 수 있습니다. 정교한 공격자는 주변의 침해된 시스템, 숨겨진 기기, 공용 액세스, 셀룰러 백홀 또는 위성 수신기를 사용해 대상 로그에 운영자가 아닌 다른 위치가 나타나게 할 수 있습니다. 하지만 이런 방법도 물리적 증거, 무선 증거 또는 제공업체 측 증거를 없애지는 않습니다. 귀속 분석에 필요한 데이터를 다른 곳으로 옮길 뿐입니다.

## 기법 비교표

| 기법 | 겉으로 드러나는 출발지 | 필요한 조건 | 가치가 높은 증거 |
|---|---|---|---|
| 주변 무선 pivot | 대상 옆의 사업장/주택 | 침해된 dual-homed 호스트와 대상 Wi-Fi 액세스 | 주변 호스트의 엔드포인트 로그, RF 연결 기록, 대상의 RADIUS/DHCP 기록 |
| 공용/게스트 네트워크 | 시설의 NAT 또는 터널 출구 | 적법한 액세스 또는 액세스 제어 우회 | captive portal, DHCP, AP 연결 기록, CCTV, 결제/위치 기록 |
| 은닉형 드롭 기기 | 대상 또는 인근의 유선, Wi-Fi 또는 셀룰러 주소 | 물리적 설치 또는 전달 | 스위치 포트/USB, RF, 자산 목록, 전원, 아웃바운드 터널 원격 측정 데이터 |
| 셀룰러 라우터/eSIM | 통신사 NAT 또는 전용 APN | 모뎀/SIM/가입 정보 | IMEI/IMSI/eSIM, 셀 섹터, 통신사 계정, 트래픽 타이밍 |
| 위성 링크 악용 | 빔 커버리지 내 가입자 주소 | 프로토콜 및 서비스별 취약점 | RF 위치, 업링크 흐름, 비정상적인 RTT/라우팅, 제공업체 기록 |

## 최근접 이웃 공격

Volexity는 2022년 APT28/GRU 작전을 기록했습니다. 공격자는 최종 대상과 원격지에 있었습니다. 유효한 자격 증명을 얻기 위해 대상의 공개 서비스를 대상으로 password-sprayed를 시도했지만, MFA 때문에 인터넷에서 직접 로그인할 수 없었습니다. 대상의 기업 Wi-Fi는 MFA 없이 해당 자격 증명을 허용했습니다. 공격자는 대상과 물리적으로 가까운 조직들을 침해하고, 무선 통신이 가능한 dual-homed 시스템을 찾아 이를 이용해 대상의 Wi-Fi에 인증했습니다. Volexity는 이를 **Nearest Neighbor Attack**이라고 명명했습니다.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

새로운 점은 이 요소들의 조합입니다. 어떤 operator도 타깃으로 이동하지 않으며, 인터넷에 노출된 서비스의 MFA도 여전히 작동합니다. 침해된 이웃 기기가 물리적 근접성을 제공하고, 탈취한 타깃 자격 증명이 논리적 접근 권한을 제공하며, 타깃 Wi-Fi가 경계를 넘는 경로가 됩니다.

### 사전 조건 및 가시성

- 근처 시스템을 원격으로 제어할 수 있어야 하며, 호환되는 무선 장치가 있거나 다른 근처 pivot에 접근할 수 있어야 합니다.
- 타깃 SSID가 해당 시스템에 도달해야 하며, Wi-Fi 접속 제어가 재사용 가능한 자격 증명/인증서/기기 상태를 허용해야 합니다.
- pivot에는 흔히 두 개의 동시 경로가 필요합니다. 하나는 operator로 돌아가는 경로이고, 다른 하나는 타깃 WLAN으로 들어가는 경로입니다.
- 타깃에서는 새 station MAC과 유효한 사용자 이름을 볼 수 있지만, 이에 대응하는 관리 기기 인증서, 보안 상태, 이력 또는 예상된 건물 출입 기록은 없을 수 있습니다.
- 이웃의 엔드포인트 로그에는 무선 검색, 새 프로필, 인터페이스 변경, 터널링 및 원격 제어 활동이 나타날 수 있습니다.

### 탐지 및 예방

1. 엔터프라이즈 Wi-Fi에 인증서 기반 EAP-TLS 및 관리 기기 보안 상태 확인을 요구하세요. 인터넷에서 MFA에 실패한 비밀번호가 무선으로 전송되었다는 이유만으로 충분한 인증 수단이 되게 해서는 안 됩니다.
2. RADIUS 인증을 MDM/NAC ID, 과거 station/기기 연결 기록, AP 위치, 물리적 출입 이벤트 및 동시 세션과 연계하세요.
3. 계정이 처음 연결되었거나, 일반적이지 않은 AP 가장자리에서 연결되었거나, 관리 기기 인증서가 없거나, 동일한 ID가 다른 곳에서 활성 상태인 경우 경고를 생성하세요.
4. 인터페이스를 브리징할 수 있는 엔드포인트를 모니터링하세요. Windows, Linux 및 네트워크 어플라이언스에서 예상치 못한 WLAN 프로필, 포워딩/NAT 구성, 가상 어댑터 및 지속적인 터널을 조사하세요.
5. AP 배치와 송신 전력을 적절히 계획해 불필요한 신호 유출을 줄이세요. 이는 보조적인 통제일 뿐, 인증 수단은 아닙니다.
6. 이웃 입주사와 사고 대응을 조율하세요. 최종 무선 신호를 내보내는 기기 자체가 피해자일 수 있습니다.

[소유한 두 조직 간의 랩](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)에서는 이웃을 공격하지 않고도 이러한 관측 항목을 재현합니다.

### Windows pivot 경로 검증

듀얼 홈 Windows 호스트는 인터페이스를 자동으로 브리징하지 않습니다. 먼저 어댑터, 라우트 및 WLAN 상태를 확인한 다음 승인된 프로필을 통해서만 연결하세요. `netsh wlan connect`의 `name` 인수는 설치된 프로필을 지정하며, 임의의 SSID와 비밀번호를 지정하는 것이 아닙니다. 연결 전후의 라우팅 테이블을 비교해 새 기본 경로가 제어 경로를 끊거나 결과를 무효화하지 않는지 확인하세요. 의도한 인터페이스와 라우트를 확인한 뒤에만 [연결 후 점검](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md)을 진행하세요.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity가 공개한 침해 아티팩트는 또 다른 유용한 차이를 보여 줍니다. 내장된 C# 코드는 WLAN API를 열고, 인터페이스를 열거하고, 디스크에서 EAP XML을 읽은 다음, 첫 번째 무선 인터페이스의 지정된 프로필에 `WlanSetProfileEapXmlUserData`를 호출합니다. 이 API는 기존 802.1X 프로필에 EAP 사용자 자격 증명을 설정하지만, 공개된 구성 요소에는 `WlanConnect`나 보고서에 설명된 검색 로직이 포함되어 있지 않습니다. 이를 완전한 연결 도구가 아니라 프로필 프로비저닝으로 간주하고, [클라이언트 및 supplicant 평가](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md)의 일부로 생성된 프로필을 검사하세요.<sup>[[5]](#references)[[7]](#references)</sup>

## 공공장소 및 제3자 Wi-Fi

카페, 호텔, 공항 또는 시립 Wi-Fi를 사용하면 대상에 표시되는 IP가 바뀝니다. 그렇다고 익명성이 보장되지는 않습니다. 장소 운영자나 서비스 제공자는 AP 연결 기록, 기기 MAC 주소, DHCP 임대 기록, 캡티브 포털 계정, SMS/이메일 인증 정보 및 트래픽 로그를 보관할 수 있습니다. 현장 출입, CCTV, 구매, 모바일 위치 및 여행 기록을 통해 디지털 활동과 개인을 연결할 수도 있습니다.

공격자는 MAC 주소 무작위화, 별도 기기, 현금 또는 터널을 사용해 단서를 줄이려 할 수 있습니다. 하지만 도착 시간, 반복되는 방문 패턴, 무선 지문, 포털 사용 방식, 트래픽 타이밍, 카메라 영상 및 터널 제공자를 통한 계층 간 상관관계 분석은 여전히 가능합니다. VPN을 사용하면 목적지에서 보던 기록이 VPN 로그로 옮겨질 뿐입니다. 기기가 그 장소에 있었다는 사실까지 장소 운영자에게서 숨기지는 못합니다.

공공 Wi-Fi 운영자는 클라이언트를 격리하고, 내부망 트래픽을 차단하고, 가능한 경우 WPA2/3-Enterprise 또는 기기별 키를 사용하고, 필요에 비례하는 DHCP/RADIUS/보안 로그를 보관하고, 캡티브 포털을 보호하며, 악용 신고 절차를 공개해야 합니다. Red teams는 해당 장소의 약관과 테스트 범위가 허용하는 경우에만 이런 장소를 사용해야 합니다. 포털 우회, 무단 액세스 탈취 또는 다른 이용자 공격은 승인된 테스트를 위한 지름길이 아닙니다.

## 은밀한 드롭 장치와 warshipping

드롭은 현장에 설치하거나 반입한 뒤, 아웃바운드 Ethernet, Wi-Fi 또는 셀룰러 연결을 통해 제어하는 소형 시스템입니다. “Warshipping”은 일반 배송 과정에서 장치가 무선 경계 안으로 들어오도록 포장합니다. 하드웨어는 단일 보드 컴퓨터부터 개조된 충전기, USB 주변 장치, 네트워크 장비 또는 배터리 구동 모뎀까지 다양할 수 있습니다.

운영 아키텍처:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

장치는 원격 foothold를 제공하거나, 무선 측정을 수행하거나, 승인된 exercise 주변 장치를 에뮬레이션하거나, 트래픽을 중계할 수 있습니다. 겉보기에는 현지에서 발생한 것처럼 보이지만, 물리적 흔적을 남깁니다. 일련번호, 포장재, 지문, 카메라 영상, 출입 로그, 전력 소비량, USB descriptor, 스위치 포트 협상, DHCP fingerprint, MAC OUI/randomization 동작, RF 방출 및 반복적인 rendezvous 연결 등이 이에 해당합니다.

### 방어 통제

- 수령 장소 및 자산 목록 관리 절차를 마련하고, 예상치 못한 전자 장비와 존재하지 않는 직원 앞으로 배송된 소포를 검사합니다.
- 유선 및 무선 액세스에 802.1X/NAC를 사용하고, 사용하지 않는 포트는 비활성화하며, 알 수 없는 장치는 제한된 remediation VLAN에 배치합니다.
- 새로운 DHCP fingerprint, 지속적으로 사용되는 locally administered MAC, 새 USB 네트워크/HID 장치, 승인되지 않은 Wi-Fi Direct/Bluetooth, 오래 유지되는 아웃바운드 터널을 탐지해 알림을 설정합니다.
- 스위치 포트, Power over Ethernet, DNS 및 TLS 동작의 기준선을 설정합니다. 주기적으로 암호화된 연결을 만들면서 자산 목록에 없는 소형 호스트는 “Raspberry Pi OUI”만으로 판단하는 것보다 더 강한 위험 신호입니다.
- exercise 중에는 장치 목록을 작성하고, 라벨을 붙이고, 범위를 정하고, 암호화하고, 원격 kill 기능을 제공하며, 회수 기한을 설정합니다. 또한 장치를 분실해도 재사용 가능한 자격 증명이 노출되지 않도록 합니다.

## 셀룰러 및 eSIM 백홀

셀룰러 모뎀은 대상의 인터넷 게이트웨이를 우회하며, 아웃바운드 rendezvous를 통해 통신 사업자 NAT 뒤에서도 drop에 계속 접근할 수 있게 합니다. 모바일 주소는 바뀌거나 여러 사용자가 공유할 수 있지만, 셀룰러 사업자에게는 가입자와 네트워크에 관한 강력한 증거가 남습니다. SIM/eSIM 식별자, IMSI, 장치 IMEI, 할당된 주소/포트, 기지국/섹터 접속 시각, 계정/결제 및 로밍 기록 등이 이에 해당합니다.

기업 관점에서는 무선/RF 조사, 엔드포인트 USB/PCI 자산 목록, MDM 제한, 불법 SSID 모니터링 및 물리적 검사를 통해 예상치 못한 모뎀과 개인용 핫스팟을 탐지합니다. 제어 통신에 셀룰러를 사용하는 drop도 로컬 Ethernet/Wi-Fi 동작과 무선 방출을 통해 탐지될 수 있습니다.

승인된 exercise의 경우, 조직이 가입 및 모뎀을 소유하고 식별 정보를 controller와 함께 기록하며, 통신 사업자/서비스 제공업체의 약관이 해당 트래픽을 허용하는지 확인해야 합니다. 선불 라벨이나 암호화폐로 구매해도 기지국, 장치 또는 소매점 기록은 없어지지 않습니다.

## MAC randomization 및 장치 fingerprinting

최신 시스템은 네트워크별로 locally administered random MAC을 사용할 수 있습니다. 이는 공장 출하 시 고정된 MAC을 이용한 장기적인 수동 추적을 줄여 주지만, 다음 항목을 숨기지는 못합니다.

- probe/association 시점 및 요청한 네트워크 기능의 집합
- 802.11 정보 요소, 지원 속도 및 vendor-specific 동작
- DHCP 옵션/호스트 이름, IPv6 식별자 및 captive-portal/브라우저 fingerprint
- 인증된 802.1X ID 또는 인증서
- 상위 계층 계정, 터널 및 트래픽 패턴
- 물리적 관찰

방어자는 MAC allowlist를 인증 수단으로 사용해서는 안 됩니다. 무선 ID를 인증서/장치 상태와 연결하고, 다른 맥락에서 이상 징후가 보이지 않는 한 MAC 변경은 정상적인 동작으로 간주해야 합니다.

## 위성 링크 hijacking

Kaspersky는 Turla가 구형 단방향 DVB-S 위성 인터넷의 취약점을 이용한 사례를 문서화했습니다. 보고된 방식에서는 정상적인 원격 가입자가 지상 링크를 통해 아웃바운드 요청을 전송했지만, 다운스트림 데이터는 암호화되지 않은 광역 위성 방송을 통해 수신했습니다. 위성 가시 범위 내의 공격자는 다운링크를 관찰하고, 활성 가입자의 IP를 선택한 뒤 C2 응답이 해당 IP로 전송되도록 할 수 있었습니다. 정상 가입자와 공격자 모두 방송을 수신했고, 공격자는 선택한 포트의 트래픽을 추출하는 반면 정상 가입자는 요청하지 않은 패킷을 폐기했습니다. 그 결과 C2 운영자는 다른 지역에 있는 위성 사업자의 주소를 사용하는 것처럼 보였습니다.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

이는 특정 프로토콜/서비스에 한정되고 대역폭 제약이 있었으며, 최신 양방향 암호화 위성 단말을 침해한 것과는 다릅니다. 또한 충분한 역량을 갖춘 관찰자로부터 행위자의 아웃바운드 요청 경로를 숨기지도 못했습니다. 탐지 기회로는 비대칭/불가능한 라우팅, 해당 흐름을 시작하지 않은 가입자로 향하는 트래픽, 비정상적인 대상 포트, provider telemetry, 수신기 위치/RF 조사 및 malware 설정이 있습니다. 이 사례를 이용해 C2 IP의 지리적 위치가 곧 컨트롤러의 위치라는 가정을 검증하되, 구축 지침으로 사용하지는 마세요.

## 물리적-디지털 상관관계 워크시트

겉보기에 로컬인 출처가 의심스러울 때는 하나의 타임라인을 작성하세요.

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch 및 물리적 출입 기록의 시간을 정규화합니다.
2. 첫 번째 경보뿐 아니라 최초의 무선 연결 또는 링크 연결 시점을 확인합니다.
3. 해당 station을 인증서, 기기 상태, DHCP 지문 및 switch/AP 위치와 연결합니다.
4. 인근 시스템에서 동시에 발생한 원격 제어/터널 활동을 찾습니다.
5. 관련 정책/법률에 따라 배송, 방문자, 재고 예외, 카메라 및 RF 조사 결과를 검토합니다.
6. 의심되는 기기와 변동 가능한 네트워크 상태를 보존합니다. 무작정 전원을 껐다 켜지 마세요.
7. 겉보기 출처가 행위자가 제어하는 인프라인지, 아니면 다른 피해자인지 판단합니다.

## References

- [1] [Volexity — 가장 가까운 이웃 공격: 러시아 APT가 인근 Wi-Fi 네트워크를 무기화한 방식](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: 하늘에서 이루어지는 APT 명령 및 제어](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — 하드웨어 추가(T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — 무선 LAN 보안 지침](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — 공개된 PowerShell/C# WLAN 프로필 코드](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData 함수](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
