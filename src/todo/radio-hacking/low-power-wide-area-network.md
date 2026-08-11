# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN)은 낮은 bit rate로 **장거리 통신**을 수행하도록 설계된 무선 저전력 광역 네트워크 기술 그룹입니다.
무선 파라미터, 안테나, 규제 지역, 지형 및 duty cycle에 따라 LPWAN deployment는 처리량을 낮추는 대신 수 킬로미터의 커버리지와 수년의 배터리 수명을 확보할 수 있습니다. 공급업체가 제시하는 통신 거리와 배터리 수명은 보장값이 아니라 설계 목표로 간주해야 합니다.<sup>[[3]](#references)</sup>

Long Range (**LoRa**)는 현재 가장 널리 deployment된 LPWAN physical layer이며, 해당 open MAC-layer specification은 **LoRaWAN**입니다.

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Semtech가 개발한 Chirp Spread Spectrum (CSS) physical layer입니다(proprietary이지만 문서화되어 있음).
* LoRaWAN – LoRa-Alliance가 유지 관리하는 Open MAC/Network layer입니다. 현장에서는 Versions 1.0.x와 1.1이 일반적으로 사용됩니다.
* 일반적인 architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> LoRaWAN 1.1에서 **security model**은 별도의 AES-128 application 및 network root key를 사용하여 OTAA 중 역할별 session key를 도출합니다. 이전 1.0.x deployment에서는 일반적으로 하나의 AppKey를 사용해 network 및 application session key를 도출하는 반면, ABP는 session key를 직접 provision합니다. 따라서 leaked key를 통해 얻을 수 있는 capability는 LoRaWAN version과 노출된 key에 따라 달라집니다.<sup>[[3]](#references)</sup>

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Localized packet loss; 효과는 link budget, timing, bandwidth 및 regulatory constraints에 따라 달라짐 |
| MAC | nonce/counter state가 재사용되는 join 및 data-frame replay | Device desynchronization, spoofing 또는 injection; server/device가 replay protection을 위반하는 경우 |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | 게이트웨이에서의 RCE → OT/IT network로 pivot |
| Application | Hard-coded 또는 predictable AppKeys | Brute-force/decrypt traffic, 센서 사칭 |

---

## Representative implementation vulnerabilities

* **CVE-2024-29862** – 4.0.11 이전의 ChirpStack Gateway Bridge version과 4.2.1 이전의 MQTT Forwarder version은 TLS server-certificate validation이 비활성화되어 있어 attacker-controlled MQTT broker에 연결할 수 있었습니다. 이로 인해 credentials와 gateway traffic이 노출될 수 있으므로 fixed release로 upgrade해야 합니다.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227은 download 가능한 backup file이 포함된 unauthenticated `/lib/` directory listing을 설명하며, CVE-2022-45228은 logout page의 low-severity CSRF입니다. 이러한 기록만으로는 주장된 LG308 impact, configuration overwrite, population size 또는 2025 patch state를 입증할 수 없습니다.<sup>[[6]](#references)[[7]](#references)</sup>
* 이 페이지의 이전 version에서는 주장된 Semtech UDP packet-forwarder issue를 **greater-than-255-byte crafted uplink causing a stack smash and RCE on SX130x reference gateways**로 설명했으며, 이를 “LoRa Exploitation Reloaded” Black Hat Europe 2023 presentation 및 2023년 10월의 private patch와 연관 지었습니다. 해당 구체적인 내용은 research lead로서 여기에 유지하지만, 일치하는 public advisory, presentation 또는 patch는 corroborate할 수 없었습니다. 영향받는 product/version과 검증 가능한 primary source를 확보하기 전에는 이 issue를 known vulnerability로 취급하지 마십시오.

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
이 명령은 원래 workflow를 **illustrative syntax**로 보존한 것입니다. repository layout과 flags는 프로젝트/release마다 다릅니다. Passive capture만으로는 강력한 AppKey를 알아낼 수 없습니다. Offline guessing은 root key가 발견될 만큼 약하고, 캡처한 join exchange가 후보를 검증할 값을 제공하는 경우에만 유용합니다.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay protection 및 nonce state 테스트

1. authorized test network에서 정상적인 **JoinRequest**를 capture합니다.
2. 동일한 request를 replay하고, network server가 재사용된 `DevNonce`를 거부하는지 확인합니다.
3. test device를 reboot하거나 reset한 뒤 검사를 반복하여 nonce state 손실 여부를 확인합니다. compliant server는 사용된 nonce를 추적해야 합니다. JoinRequest만 replay해도 새로 파생된 session keys가 노출되거나 replayer가 session을 제어할 수 있는 것은 아닙니다.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) downgrading

network-layer MAC commands를 authenticate할 수 있는 attacker는—예를 들어 해당 network session key 또는 network server를 compromise한 후—비효율적인 data-rate parameters를 강제하고 airtime을 증가시키려 할 수 있습니다. 근처의 unauthenticated transmitter는 device address를 알고 있다는 이유만으로 ADR commands를 정당하게 발행할 수 없습니다.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

reactive jammer는 LoRa preamble을 감지한 후 transmit하여 frame을 선택적으로 방해할 수 있습니다. 이전 페이지에서는 HackRF/GNU Radio setup이 **2 km에서 200 mW 이하로** 전면적인 outage를 일으켰다고 주장했지만, 이를 뒷받침하는 측정 source가 제공되지 않았습니다. 따라서 해당 수치는 예상 결과가 아니라 reproduction target으로만 유지합니다. 필요한 transmit power, timing, bandwidth, 영향을 받는 spreading factors 및 range는 환경에 따라 다릅니다. authorized하고 RF-contained된 setup 내부에서만 테스트하며 현지 spectrum 규정을 준수합니다.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames를 craft/parse/attack하고, DB-backed analyzers 및 brute-forcer 제공 | Docker image; Semtech UDP input 지원<sup>[[1]](#references)</sup> |
| **LoRaPWN** | OTAA를 brute하고 downlinks를 생성하며 payloads를 decrypt하는 Trend Micro Python utility | Public research utility; 지원 hardware 및 protocol versions 확인 필요<sup>[[2]](#references)</sup> |
| **LoRAttack** | multi-channel LoRaWAN capture, session analysis, key derivation 및 replay testing을 위한 research framework | 2024년 master's thesis에 설명되어 있음; example flags에 의존하기 전에 정확한 implementation을 확보하고 검증해야 함<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband reception 또는 transceiver research를 위한 GNU Radio out-of-tree blocks | 프로젝트마다 GNU Radio compatibility 및 feature set이 다름<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. **OTAA**를 우선 사용하고 device와 server가 필요한 nonce state를 persist하는지 확인합니다. rejected duplicate joins를 monitor합니다.
2. 지원되는 경우 **LoRaWAN 1.1**을 우선 사용하여 network functions가 distinct session keys와 updated nonce handling을 사용하도록 합니다.<sup>[[3]](#references)</sup>
3. frame-counter를 non-volatile memory에 저장하거나(**ABP**) OTAA로 migrate합니다.
4. 적합한 **secure element**(예: 지원되는 design의 ATECC608A)을 배포하여 일반적인 firmware storage에서 root keys가 노출될 위험을 줄입니다.
5. 구성된 packet-forwarder UDP listeners(일반적으로 1700)를 untrusted networks에 노출하지 않습니다. gateway backhaul을 authenticate/encrypt하거나 VPN으로 제한합니다.
6. gateway를 vendor-supported firmware로 유지하고, 해당 advisories를 기준으로 정확한 model/version을 확인합니다.
7. **traffic anomaly detection**(예: LAF analyzer)을 구현하여 counter resets, duplicate joins 및 갑작스러운 ADR changes를 flag합니다.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN 개요](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 사양](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 regional parameters 및 join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - SDR Technology를 활용한 LPWAN Protocol Security Analysis](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
