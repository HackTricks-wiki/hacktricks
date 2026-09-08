# 정부 및 APT 사례 연구

{{#include ../banners/hacktricks-training.md}}

이러한 공개 사례는 실제 작전에서 서로 다른 privacy 기법이 어떻게 조합되는지 보여 줍니다. Attribution 라벨은 인용된 조사기관 또는 정부가 사용한 명칭이며, IP 주소, 도구 중복 또는 지정학적 적합성만으로는 결정적인 attribution이 될 수 없습니다.

## APT28: 원격 nearest-neighbor Wi-Fi access

**공개 조사 결과.** Volexity는 2022년 침해 사건을 GruesomeLarch/APT28의 소행으로 attribution했습니다. 검증된 credential을 사용한 Internet access가 MFA에 의해 차단된 후, 공격자는 target과 가까운 조직들을 침해하고 인근 dual-homed host에서 target의 enterprise Wi-Fi에 접근했습니다. Wi-Fi 경로에서는 외부 접속에 요구되던 MFA 없이 credential을 허용했습니다.<sup>[[1]](#references)</sup>

**Privacy effect.** 최종 access는 물리적 radio range에서 발생했으며, 중간 조직들은 피해자였습니다. 이 작전은 이동을 피했고, 일반적인 IP geolocation이 이웃 조직을 가리키도록 만들었습니다.

**무엇이 이를 드러냈는가.** Target alert, host/network investigation, credential activity, interface topology 및 물리적 근접성을 하나의 chain으로 분석해야 했습니다. 비정상적인 사실은 단순히 새로운 IP가 나타난 것이 아니었습니다. 주변 시스템이 침해된 상태에서, 합법적인 identity가 특이한 Wi-Fi/device context를 통해 도착했다는 점이 핵심이었습니다.

**방어 교훈.** Wi-Fi access에 certificate/device-backed access를 적용하고, RADIUS를 NAC/MDM 및 물리적 context와 correlate하며, 마지막 hop이 operator라고 가정하지 말고 인접 infrastructure를 조사해야 합니다.

## APT28: GRU가 재활용한 criminal Moobot infrastructure

**공개 조사 결과.** 2024년 2월, US Department of Justice는 수백 대의 Ubiquiti EdgeOS router로 구성된 botnet을 설명했습니다. Criminal actors는 알려진 default administrator credentials가 그대로 유지된 router에 Moobot을 설치했습니다. 이후 GRU Unit 26165가 scripts와 files를 추가하여 기존 criminal botnet을 espionage platform으로 전환했고, 이를 spearphishing 및 credential theft에 사용했습니다.<sup>[[2]](#references)</sup>

**Privacy effect.** GRU가 모든 infrastructure를 직접 구축한 것은 아니었습니다. 이미 침해된 fleet을 빌림으로써 actor와 target 사이에 무관한 가정 및 소규모 사무실의 주소를 배치하고, state activity와 criminal activity를 혼합했으며, actor별 registration artifacts를 줄였습니다.

**무엇이 이를 드러냈는가.** Router files, malware control behavior 및 non-content routing information이 investigation을 뒷받침했습니다. 이 disruption은 일시적으로 firewall rules를 변경하고 malicious files를 제거했지만, DOJ는 변경되지 않은 default credentials로 인해 reinfection이 발생할 수 있다고 경고했습니다.

**방어 교훈.** 지원이 종료된 router를 교체하고, Internet-exposed administration을 제거하며, default 값을 변경하고, patch를 적용해야 합니다. 또한 edge-device configuration/flow data를 수집하고 fleet behavior를 hunt해야 합니다. “Residential US IP”는 US operator의 증거가 아닙니다.

## Volt Typhoon: KV Botnet과 living off the land

**공개 조사 결과.** DOJ와 공동 CISA advisory는 PRC state-sponsored Volt Typhoon이 주로 침해된 수명 종료 Cisco 및 NETGEAR SOHO router로 구성된 KV Botnet을 사용하여 critical infrastructure를 대상으로 한 activity의 PRC origin을 숨겼다고 설명했습니다. Victim 내부에서 actor는 valid accounts와 built-in administration tools를 선호했으며, 기관들은 일부 environment에서 access가 최소 5년 동안 지속되었다고 보고했습니다.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Privacy effect.** ORB와 유사한 경로는 출처를 숨겼고, 접근 후에는 living-off-the-land를 사용해 새로운 바이너리와 signature 기회를 줄였다. 네트워크와 엔드포인트 은폐가 서로를 강화했다.

**What exposed it.** 단일 IOC보다 라우터/컨트롤러 구조, 법원이 승인한 기술적 수집, 반복되는 활동과 피해자 간 분석이 더 중요했다. 설명된 사례에서는 라우터를 재시작하면 휘발성 KV malware가 제거되었지만, 해당 장치의 근본적인 EOL 노출은 해결되지 않았다.

**Defensive lesson.** EOL edge device를 교체하고, 인증 및 네트워크 장치 로그를 중앙화하며, 관리자 행동의 baseline을 설정하고, 아웃바운드 연결을 제한하며, identity, endpoint 및 network 계층 전반에서 행동 시퀀스를 hunt해야 한다.

## China-nexus ORB networks: infrastructure as a service

**Public finding.** Mandiant는 여러 China-nexus espionage actor가 사용하는 ORB networks 생태계를 설명했다. Provisioned network는 임대한 VPS node를 사용했고, non-provisioned network는 침해된 IoT 및 라우터를 사용했으며, hybrid network는 이 둘을 결합했다. ORB3/SPACEHOP은 APT5/APT15와 관련된 활동을 지원했다. ORB2/FLORAHOX는 administration server, 임대한 server, customized Tor layer, 침해된 Cisco, ASUS 및 DrayTek 장치를 결합했다. Mandiant는 일부 network가 독립적으로 관리되며 여러 APT actor에게 임대되었다고 평가했다.<sup>[[5]](#references)</sup>

**Privacy effect.** Infrastructure가 service boundary가 되었다. 하나의 operator는 victim fleet를 유지하지 않고도 지리적/주거용 exit를 사용할 수 있었으며, 이를 공유하는 여러 고객 때문에 단순한 actor-to-IP 매핑이 약화되었다. 빠른 fleet 교체는 “IOC extinction”을 가속했다.

**What exposed it.** Network topography, cloned server image, port/service, controller 관계, router implant 및 lifecycle pattern은 여전히 cluster로 묶을 수 있었다. Mandiant는 일부 node IP가 ORB에 머문 기간이 31일에 불과했다고 보고했다.

**Defensive lesson.** ORB를 변화하는 entity로 추적해야 한다. node role, service fingerprint, upstream 관계, scan behavior 및 rotation rhythm을 기록한다. IP indicator가 만료되더라도 cluster를 업데이트해야 하며, 사건을 삭제해서는 안 된다.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Public finding.** 2025년 다국적 advisory는 Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 및 GhostEmperor를 포함한 상업 보고서상의 명칭과 중복되는 활동을 설명했다. 기관들은 통신 및 network provider에 접근하기 위해 임대한 VPS와 침해된 intermediate router가 사용되었다고 보고했다. Actor는 trusted provider/customer link를 통해 pivot하고, route를 변경하며, GRE/IPsec tunnel을 구축하고, device container를 사용하며, SPAN/RSPAN/ERSPAN 또는 native packet capture를 활성화해 authentication 및 customer traffic을 수집했다.<sup>[[13]](#references)</sup>

**Privacy effect.** 침해된 router는 동시에 relay, observation point 및 trusted network participant가 된다. Private interconnection은 public Internet을 기준으로 설계된 control을 우회할 수 있으며, traffic mirroring은 endpoint agent를 배포하지 않고도 credential을 수집한다.

**What exposes it.** Configuration diff, 예상하지 못한 SNMP/SSH/web administration, 새로운 static route/tunnel, mirror session, Guest Shell container, PCAP file, TACACS+/RADIUS destination 변경 및 비활성화된 logging이 단서가 된다. Advisory는 일부 intermediate router가 이전에 공개적으로 명명된 botnet에 포함되지 않았다고 강조한다. 따라서 알려진 ORB indicator가 없다고 해서 무혐의인 것은 아니다.

**Defensive lesson.** Out-of-band administration, centralized configuration/authentication log, signed-image 및 runtime integrity check, management-interface egress 제한을 사용하고, route/mirror/tunnel/AAA 변경에 alert를 설정해야 한다. 의심되는 compromise를 제거하기 전에 trusted peer 전반으로 범위를 확장해야 한다.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Public finding.** Mandiant는 EOL Juniper MX router에 설치된 custom TINYSHELL-derived backdoor를 UNC3886에 귀속했다. 이 세트에는 active 및 passive implant, legitimate daemon을 모방한 이름, log-disabling 동작, trusted process에 대한 process injection, SOCKS proxy 기능 및 ORB staging node로 평가된 infrastructure가 포함되었다. Passive variant는 `libpcap`을 통해 packet을 검사하고 magic pattern이 나타난 후에만 활성화되었다. 하나는 trigger에 제공된 active callback으로 전환할 수 있었다.<sup>[[14]](#references)</sup>

**Privacy effect.** Passive implant는 발견할 수 있는 주기적 beacon이 없다. 실제 network appliance와 port/traffic을 공유하고 짧게 활성화되며, 최종 controller에 직접 연결하는 대신 ORB를 통해 relay할 수 있다.

**What exposes it.** Memory analysis, on-disk code와 running code의 차이, 예상하지 못한 packet-capture filter/socket 동작, legitimate daemon과 일부만 유사한 process/file name, terminal server를 통한 administration, 누락된 log, staging node와 backend controller 간의 two-stage 관계가 단서가 된다.

**Defensive lesson.** Filesystem/configuration evidence뿐 아니라 memory도 수집하고, process/module을 known-good image와 비교하며, packet-capture/socket-filter 사용을 모니터링하고, management terminal server를 보호하며, EOL network hardware를 교체해야 한다. 깨끗한 outbound-beacon hunt 결과만으로 안전하다고 판단해서는 안 된다.

## APT29: Tor domain fronting

**Public finding.** MITRE는 APT29가 `meek` Tor pluggable transport를 사용해 C2 traffic을 domain-front했다고 기록한다. 외부 TLS name은 허용된 CDN-hosted domain처럼 보였지만, 내부 HTTP host가 실제 route를 선택했다.<sup>[[6]](#references)</sup>

**Privacy effect.** Filtering observer는 내부 destination 대신 일반적인 front/CDN을 볼 수 있었으며, 이를 차단하면 collateral damage가 발생할 위험이 있었다.

**What exposes it.** CDN은 routing mismatch를 관찰할 수 있고, endpoint 또는 합법적인 TLS visibility를 가진 defender는 process, authority, connection lifetime, byte pattern 및 이후 활동을 상관 분석할 수 있다. Provider policy 변경으로 technique가 비활성화될 수도 있다.

**Defensive lesson.** SNI allowlisting에만 의존하지 않아야 한다. Application-aware egress를 적용하고, 확인 가능한 경우 TLS와 HTTP identity를 비교하며, network event를 이를 시작한 process와 연결해야 한다.

## APT41 and other dead-drop resolvers

**Public finding.** MITRE는 APT41이 GitHub, Pastebin, Microsoft TechNet, Cloudflare 및 community forum을 포함한 legitimate site를 사용해 C2 정보를 게시하거나 가져온다고 기록한다. 다른 state-linked tooling도 유사한 방식으로 post, document 및 social media를 사용했다.<sup>[[7]](#references)</sup>

**Privacy effect.** Binary에는 안정적인 C2 address 대신 legitimate service/object가 포함된다. Infrastructure를 교체하기 위해 object를 수정할 수 있으며, 초기 request는 일반적인 TLS traffic에 섞인다.

**What exposes it.** Object 또는 account identifier는 안정적이고, 드문 process가 이를 반복해서 가져오며, content가 decode되고, 이후 두 번째 outbound connection이 발생한다. Provider account 및 API record는 게시와 operator를 연결할 수 있다.

**Defensive lesson.** 전체 proxy path/object ID와 endpoint process lineage를 보존해야 한다. “GitHub에 연결됨”과 같은 domain-level event만으로는 너무 거칠다.

## Turla: satellite-address C2

**Public finding.** Kaspersky는 Turla가 구형 one-way DVB-S Internet service의 암호화되지 않은 downstream broadcast를 악용했다고 보고했다. Satellite footprint 내의 operator는 legitimate subscriber address를 선택하고 해당 주소로 broadcast된 reply를 수신할 수 있었으며, 그 결과 C2가 다른 지역의 satellite provider 뒤에 hosted된 것처럼 보였다.<sup>[[8]](#references)</sup>

**Privacy effect.** 겉으로 보이는 server address는 receiver를 식별하지 못했으며, 일반적인 hosting seizure/WHOIS 절차의 유용성이 낮았다.

**What exposes it.** Actor는 여전히 outbound request path가 필요했고, routing은 asymmetric했으며, legitimate subscriber는 C2 exchange를 시작하지 않았다. 또한 RF/provider 조사를 통해 receiving footprint를 좁힐 수 있었다.

**Defensive lesson.** Geolocation을 하나의 가설로만 취급해야 한다. Path symmetry, RTT, routing ownership 및 alleged endpoint가 실제로 관찰된 service를 생성할 수 있는지를 검증해야 한다.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Public finding.** 2022년 NCSC/CISA/FBI/NSA advisory는 WatchGuard device에 설치된 Sandworm의 modular Cyclops Blink malware를 설명했다. 이 malware는 firmware update로 지속성을 확보하고 module을 추가할 수 있었다. DOJ는 별도로 APT28의 초기 VPNFilter botnet이 router 및 NAS device를 대상으로 intelligence collection, destructive activity 및 misattribution을 수행할 수 있다고 설명했다.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Privacy effect.** Edge appliance는 항상 online 상태이고 infrastructure로서 신뢰되며 EDR의 적용 범위가 부족하다. Firmware persistence는 일반적인 restart 후에도 유지될 수 있고, victim device를 relay 또는 control point로 만들 수 있다.

**What exposes it.** Firmware integrity, vendor-specific implant protocol, 예상하지 못한 management exposure, configuration 변경 및 outbound beaconing이 단서가 된다. Edge device는 투명한 배관이 아니라 forensic subject로 취급해야 한다.

## DPRK: identity, network and financial layering

**Public finding.** DOJ 사건 기록은 DPRK worker가 허위 또는 도난된 identity 자료와 VPN을 사용해 remote job을 얻고, cryptocurrency를 수령하며, transfer를 분할하고, asset/chain을 교환하고, NFT를 사용하며, proceeds를 commingle했다고 설명한다. 다른 사건은 OTC trader와 front company가 도난된 crypto를 구매 대금으로 전환했다고 설명한다. Treasury와 FBI는 Lazarus/TraderTraitor proceeds를 mixer와 공개적으로 연결했으며, 주요 theft에서 사용된 address를 식별했다.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Privacy effect.** 이는 “private coin”이 아니다. persona와 remote access가 worker의 위치를 숨기고, crypto가 가치를 이동시키며, layering이 단순한 transaction narrative를 분리하고, OTC trader/front company가 goods 및 fiat로 이어지는 다중 domain chain이다.

**What exposes it.** Employer/device anomaly, 재사용된 facilitator, blockchain timing/value continuity, exchange/bridge record, sanctioned address, account identity 및 shipment/company record가 chain을 다시 연결한다.

**Defensive lesson.** Hiring, IAM, endpoint, payroll, blockchain 및 sanctions team은 공유된 case model이 필요하다. 자세한 내용은 [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md)에 설명되어 있다.

## Cross-case patterns

| Pattern | APT examples | Defender adaptation |
|---|---|---|
| Exit은 또 다른 victim이다 | APT28/Moobot, Volt Typhoon/KV, ORBs | Exit을 조사하고 remediation하라. 이를 actor의 위치와 동일시하지 말라 |
| Boundary마다 control이 다르다 | APT28 nearest neighbor | Internal/wireless access에도 Internet access와 동일한 identity assurance를 적용하라 |
| Legitimate service가 routing layer다 | APT29, APT41 | Destination domain뿐 아니라 object/path/process context를 보존하라 |
| Edge device에는 telemetry가 부족하다 | KV, Moobot, Cyclops Blink, ORBs | Config/auth/flow log를 중앙화하고 firmware/inventory를 검증하라 |
| Infrastructure는 공유되고 수명이 짧다 | China-nexus ORBs | Behavior/topology를 cluster로 묶고 시간에 따른 role 변경을 추적하라 |
| 여러 약한 분리가 결합된다 | DPRK persona + VPN + crypto + OTC | Identity, device, network, payment 및 physical evidence를 연결하라 |

## References

- [1] [Volexity — Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — GRU-controlled Moobot router botnet의 중단](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — PRC KV Botnet의 중단](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actor의 US critical infrastructure 침해 및 지속적 access 유지](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actor의 ORB network 사용](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter 중단](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representative의 crypto-laundering conspiracy 기소](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io 제재 및 Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — 전 세계 network에 대한 Chinese state-sponsored actor의 compromise 대응](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886의 Juniper router targeting](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
