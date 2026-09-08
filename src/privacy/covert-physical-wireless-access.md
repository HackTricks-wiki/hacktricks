# 은밀한 물리적 및 무선 액세스

outbound rendezvous, power/uplink recovery, minimal device-held secrets, capture testing 및 discovery 가능성 모니터링을 포함한 상세한 소유자 승인 구현은 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)를 참조하세요.

네트워크 경로를 변경하면 겉보기 물리적 출처도 변경될 수 있습니다. 정교한 공격자는 인근의 compromised system, hidden device, public access, cellular backhaul 또는 satellite receiver를 사용하여 target logs가 operator와 다른 위치를 가리키도록 할 수 있습니다. 그러나 이러한 방법 중 어느 것도 물리적, radio 또는 provider evidence를 제거하지는 않습니다. 대신 attribution을 서로 다른 datasets로 이동시킵니다.

## Technique matrix

| Technique | 겉보기 출처 | 필요한 조건 | 가치가 높은 evidence |
|---|---|---|---|
| 인근 wireless pivot | target 옆의 business/home | compromised dual-homed host 및 target Wi-Fi access | neighbor-host endpoint logs, RF association 및 target RADIUS/DHCP |
| Public/guest network | venue NAT 또는 tunnel exit | lawful access 또는 access-control bypass | captive portal, DHCP, AP association, CCTV 및 payment/location records |
| Covert drop device | target/인근의 wired, Wi-Fi 또는 cellular address | physical placement 또는 delivery | switchport/USB, RF, inventory, power 및 outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT 또는 dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account 및 traffic timing |
| Satellite-link abuse | beam footprint 내 subscriber address | protocol- 및 service-specific weakness | RF location, uplink flow, impossible RTT/routing 및 provider records |

## Nearest-neighbor attack

Volexity는 2022년 APT28/GRU operation을 문서화했습니다. 이 operation에서 actor는 ultimate target과 물리적으로 떨어진 위치에 있었습니다. actor는 target의 public service에 password-spraying을 수행하여 valid credentials를 획득했지만, MFA가 direct Internet login을 차단했습니다. target의 enterprise Wi-Fi는 MFA 없이 해당 credentials를 허용했습니다. actor는 target과 물리적으로 가까운 organizations를 compromise하고, wireless reach가 가능한 dual-homed system을 찾아 해당 system을 사용해 target Wi-Fi에 authenticate했습니다. Volexity는 이를 **Nearest Neighbor Attack**이라고 명명했습니다.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
새로운 점은 구성 방식에 있습니다. 어떤 operator도 대상 장소로 이동하지 않으며, Internet-facing service의 MFA도 여전히 작동합니다. 침해된 이웃 장치가 물리적 근접성을 제공하고, 탈취한 대상 credential이 논리적 access를 제공하며, 대상 Wi-Fi가 경계를 넘는 경로가 됩니다.

### Preconditions and visibility

- nearby system을 원격으로 제어할 수 있어야 하며, 호환되는 radio가 있거나 다른 nearby pivot에 access할 수 있어야 합니다.
- 대상 SSID가 해당 system에 도달해야 하며, Wi-Fi admission이 재사용 가능한 credential/certificate/device state를 허용해야 합니다.
- pivot에는 operator로 돌아가는 경로와 대상 WLAN으로 들어가는 경로, 두 개의 동시 경로가 필요한 경우가 많습니다.
- 대상 측에는 새로운 station MAC과 합법적인 username이 보일 수 있지만, 이에 대응하는 managed-device certificate, posture, history 또는 예상된 building entry는 보이지 않을 수 있습니다.
- neighbor endpoint logs에는 wireless scans, 새로운 profiles, interface changes, tunneling 및 remote-control activity가 나타날 수 있습니다.

### Detection and prevention

1. enterprise Wi-Fi에 certificate-backed EAP-TLS와 managed-device posture를 요구하십시오. Internet에서 MFA에 실패한 password가 단지 radio를 통해 전달되었다는 이유만으로 충분한 것으로 취급하지 마십시오.
2. RADIUS authentication을 MDM/NAC identity, historical station/device binding, AP location, physical-access events 및 concurrent sessions와 연계하십시오.
3. account가 처음으로 associate하거나, 비정상적인 AP edge에서 associate하거나, managed certificate 없이 associate하거나, 동일한 identity가 다른 곳에서 active 상태일 때 alert를 생성하십시오.
4. interfaces를 bridging할 수 있는 endpoints를 모니터링하십시오. Windows, Linux 및 network appliances에서는 예상치 못한 WLAN profiles, forwarding/NAT configuration, virtual adapters 및 persistent tunnels를 조사하십시오.
5. 합리적인 AP 배치와 power planning을 통해 불필요한 signal spill을 줄이십시오. 이는 authentication이 아니라 보조적인 control입니다.
6. neighboring tenants와 incident response를 조율하십시오. 최종 radio source 자체가 victim일 수도 있습니다.

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)는 neighbor를 공격하지 않고 이러한 observables를 재현합니다.

## Public venues and third-party Wi-Fi

café, hotel, airport 또는 municipal Wi-Fi를 사용하면 destination에 표시되는 IP가 변경됩니다. 그렇다고 anonymity가 생기는 것은 아닙니다. venue 또는 해당 provider는 AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation 및 flow logs를 보관할 수 있습니다. Physical entry, CCTV, purchase, mobile-location 및 travel records가 digital event를 특정 인물과 연결할 수 있습니다.

actor는 randomized MAC addresses, 별도의 device, cash 또는 tunnel을 사용하여 하나의 식별 단서를 줄이려 할 수 있습니다. 그러나 arrival time, 반복되는 venue pattern, radio fingerprints, portal behavior, traffic timing, camera footage 및 tunnel provider를 통한 cross-layer correlation은 여전히 가능합니다. VPN은 destination을 venue logs에서 VPN logs로 옮길 뿐이며, 해당 device가 venue에 있었다는 사실을 venue가 알고 있다는 점을 제거하지 않습니다.

Public access를 운영하는 defenders는 clients를 격리하고, lateral traffic을 차단하며, 가능한 경우 WPA2/3-Enterprise 또는 device별 keys를 사용하고, 비례적인 DHCP/RADIUS/security logs를 보관하며, captive portals를 보호하고, abuse process를 공개해야 합니다. Red teams는 venue의 terms와 engagement가 허용하는 경우에만 이러한 venue를 사용해야 합니다. portal 우회, access 탈취 또는 다른 guests를 대상으로 하는 행위는 authorized testing shortcut이 아닙니다.

## Covert drop devices and warshipping

drop은 site에 배치하거나 site로 배송한 뒤 outbound Ethernet, Wi-Fi 또는 cellular을 통해 제어하는 소형 system입니다. “Warshipping”은 일반적인 배송을 통해 device가 radio perimeter 안으로 들어가도록 device를 포장합니다. 가능한 hardware는 single-board computer부터 modified charger, USB peripheral, network appliance 또는 battery-powered modem까지 다양합니다.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
이 장치는 원격 foothold를 제공하거나, wireless measurements를 수행하거나, authorized exercise peripheral을 에뮬레이트하거나, traffic을 relay할 수 있다. 외견상 출처는 로컬이지만, serial numbers, packaging, fingerprints, cameras, access logs, power draw, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions 및 반복적인 rendezvous connections와 같은 물리적 흔적을 남긴다.

### 방어 통제

- receiving-room 및 asset-inventory 절차를 유지하고, 예상하지 못한 전자 장치와 존재하지 않는 직원 앞으로 배송된 packages를 검사한다.
- 유선 및 무선 access에 802.1X/NAC를 사용하고, 사용하지 않는 ports를 비활성화하며, 알 수 없는 devices를 제한된 remediation VLAN에 배치한다.
- 새로운 DHCP fingerprints, 지속적으로 유지되는 locally administered MACs, 새로운 USB network/HID devices, unauthorized Wi-Fi Direct/Bluetooth 및 장시간 유지되는 outbound tunnels에 alert를 설정한다.
- switchport, power-over-Ethernet, DNS 및 TLS behavior의 baseline을 수립한다. inventory record가 없는 소형 host가 주기적으로 encrypted connections를 생성하는 것은 단순히 “Raspberry Pi OUI”만 감지하는 것보다 더 높은 signal이다.
- exercise 중에는 inventory를 작성하고, label을 부착하며, scope를 지정하고, encrypt하고, remote kill을 제공하고, retrieval deadline을 설정하며, 분실 시 재사용 가능한 credentials가 노출되지 않도록 한다.

## 셀룰러 및 eSIM backhaul

cellular modem은 target의 Internet gateway를 우회하고, outbound rendezvous를 통해 carrier NAT 뒤에서도 drop에 연결 가능한 상태를 유지할 수 있다. Mobile addresses는 변경되거나 공유될 수 있지만, cellular operator는 여전히 강력한 subscriber 및 network evidence를 보유한다. 여기에는 SIM/eSIM identity, IMSI, device IMEI, assigned addresses/ports, cell/sector timing, account/payment 및 roaming records가 포함된다.

enterprise 관점에서는 wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring 및 physical inspection을 통해 예상하지 못한 modems와 personal hotspots를 탐지한다. control에 cellular을 사용하는 drop도 local Ethernet/Wi-Fi behavior와 radio emissions를 통해 포착될 수 있다.

authorized exercises의 경우 조직이 subscription과 modem을 소유하고, identifiers를 controller와 함께 기록하며, carrier/provider terms에서 해당 traffic을 허용하는지 확인해야 한다. prepaid label이나 cryptocurrency purchase를 사용해도 tower, device 또는 retail records가 삭제되지는 않는다.

## MAC randomization 및 device fingerprinting

Modern systems는 network별로 locally administered random MAC을 사용할 수 있다. 이는 안정적인 factory MAC을 통한 passive long-term tracking을 줄이지만, 다음 정보를 숨기지는 않는다.

- probe/association timing 및 요청된 network capabilities의 집합;
- 802.11 information elements, supported rates 및 vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers 및 captive-portal/browser fingerprint;
- authenticated 802.1X identity 또는 certificate;
- higher-layer account, tunnel 및 traffic pattern; 또는
- physical observation.

Defenders는 MAC allowlists를 authentication 수단으로 사용해서는 안 된다. radio identity를 certificate/device posture와 연결하고, 다른 context가 anomalous하지 않은 한 changing MACs를 정상적인 현상으로 취급해야 한다.

## Satellite-link hijacking

Kaspersky는 Turla가 과거의 one-way DVB-S satellite Internet의 weaknesses를 사용한 사례를 문서화했다. 보고된 model에서 legitimate remote subscriber는 terrestrial link를 통해 outbound requests를 전송했지만, downstream data는 unencrypted wide-area satellite broadcast를 통해 수신했다. satellite footprint 내부의 actor는 downlink를 관찰하고, active subscriber IP를 선택한 뒤, C2 replies가 해당 IP로 전송되도록 구성할 수 있었다. legitimate subscriber와 actor 모두 broadcast를 수신했으며, actor는 선택한 port의 traffic을 추출하고 legitimate subscriber는 unsolicited packets를 폐기했다. 이후 C2 operator는 다른 geography에 있는 satellite-provider address를 사용하는 것처럼 보였다.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
이는 protocol/service에 특화되고 bandwidth 제약이 있었으며, 최신 양방향 encrypted satellite terminal을 compromise하는 것과 동등하지 않았습니다. 또한 충분한 역량을 갖춘 관찰자로부터 actor의 outbound request 경로를 숨기지도 못했습니다. Detection 기회로는 비대칭적/불가능한 routing, flow를 시작하지 않은 subscriber로의 traffic, 비정상적인 destination port, provider telemetry, receiver 위치/RF investigation 및 malware configuration이 있습니다. 이 사례를 활용해 C2 IP를 geolocating하면 해당 controller의 위치도 파악된다는 가정에 이의를 제기하되, build recipe로 사용하지는 마십시오.

## Physical-to-digital correlation worksheet

겉보기에는 local source인 것이 의심스러울 때는 하나의 timeline을 작성하십시오.

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch 및 physical-access clock을 normalize합니다.
2. 첫 alert뿐 아니라 최초의 radio association 또는 link-up을 식별합니다.
3. station을 certificate, device posture, DHCP fingerprint 및 switch/AP 위치에 매핑합니다.
4. 인근 system에서 동시에 발생한 remote-control/tunnel activity를 확인합니다.
5. 적용되는 policy/law에 따라 deliveries, visitors, inventory exceptions, cameras 및 RF findings를 검토합니다.
6. 의심되는 device와 volatile network state를 보존합니다. 무작정 power-cycle하지 마십시오.
7. 겉보기 source가 actor-controlled infrastructure인지, 아니면 다른 victim인지 판단합니다.

## References

- [1] [Volexity — The Nearest Neighbor Attack: 러시아 APT가 인근 Wi-Fi network를 weaponize한 방법](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: 하늘에서의 APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wireless Local Area Network 보안을 위한 Guidelines](https://csrc.nist.gov/pubs/sp/800/153/final)
