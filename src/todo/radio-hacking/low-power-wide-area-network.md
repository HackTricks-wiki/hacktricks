# 저전력 광역 네트워크

{{#include ../../banners/hacktricks-training.md}}

## 소개

**저전력 광역 네트워크**(LPWAN)는 낮은 bit rate로 **장거리 통신**을 수행하도록 설계된 무선 저전력 광역 네트워크 기술의 그룹입니다.
6마일 이상 도달할 수 있으며 **배터리** 수명은 최대 **20년**까지 지속될 수 있습니다.

Long Range(**LoRa**)는 현재 가장 많이 배포된 LPWAN 물리 계층이며, 개방형 MAC 계층 사양은 **LoRaWAN**입니다.

---

## LPWAN, LoRa 및 LoRaWAN

* LoRa – Semtech에서 개발한 Chirp Spread Spectrum(CSS) 물리 계층(독점 기술이지만 문서화되어 있음).
* LoRaWAN – LoRa-Alliance가 유지 관리하는 Open MAC/Network 계층. 현장에서 버전 1.0.x와 1.1이 일반적으로 사용됩니다.
* 일반적인 아키텍처: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> **security model**은 두 개의 AES-128 root key(AppKey/NwkKey)에 의존하며, 이 키는 *join* 절차(OTAA) 중 session key를 파생하거나 ABP에서 하드코딩됩니다. 키가 하나라도 leak되면 공격자는 해당 traffic에 대한 완전한 read/write capability를 획득합니다.

---

## Attack surface 요약

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 단일 SDR과 1 W 미만의 출력으로 100 % packet loss 시연 가능 |
| MAC | Join-Accept 및 data-frame replay(nonce 재사용, ABP counter rollover) | Device spoofing, message injection, DoS |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | Gateway에서 RCE 발생 → OT/IT network로 pivot |
| Application | Hard-coded 또는 predictable AppKeys | Traffic brute-force/decrypt, sensor impersonation |

---

## 최근 vulnerabilities (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder*는 Kerlink gateway에서 stateful firewall rule을 우회하는 TCP packet을 허용하여 remote management interface가 노출될 수 있었습니다. 각각 4.0.11 / 4.2.1에서 수정되었습니다.
* **Dragino LG01/LG308 series** – 여러 2022-2024 CVE(예: 2022-45227 directory traversal, 2022-45228 CSRF)가 2025년에도 patch되지 않은 상태로 발견되었습니다. 수천 개의 public gateway에서 unauthenticated firmware dump 또는 config overwrite를 활성화할 수 있습니다.
* Semtech *packet-forwarder UDP* overflow(공개되지 않은 advisory, 2023-10에 patch됨): 255 B보다 큰 crafted uplink가 stack-smash를 유발하여 SX130x reference gateway에서 RCE를 실행할 수 있었습니다(Black Hat EU 2023의 “LoRa Exploitation Reloaded”에서 발견).

---

## Practical attack techniques

### 1. Traffic Sniff & Decrypt
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce reuse)

1. 합법적인 **JoinRequest**를 캡처합니다.
2. 원래 장치가 다시 전송하기 전에 즉시 재전송하거나 RSSI를 증가시킵니다.
3. network-server는 새로운 DevAddr 및 session keys를 할당하지만 대상 장치는 기존 session을 계속 사용하므로, attacker는 비어 있는 session을 소유하고 위조된 uplink를 주입할 수 있습니다.

### 3. Adaptive Data-Rate (ADR) downgrading

SF12/125 kHz를 강제하여 airtime을 증가시킵니다. 이렇게 하면 gateway의 duty-cycle을 소진시켜 denial-of-service를 일으킬 수 있으며, attacker의 배터리 영향은 낮게 유지됩니다(network-level MAC commands만 전송).

### 4. Reactive jamming

*HackRF One*에서 실행되는 GNU Radio flowgraph가 preamble을 감지할 때마다 wide-band chirp를 트리거하여 모든 spreading factor를 차단합니다. TX 출력이 ≤200 mW이며, 2 km 거리에서 완전한 outage가 측정되었습니다.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames 생성/파싱/공격, DB 기반 analyzers, brute-forcer | Docker image이며 Semtech UDP input 지원 |
| **LoRaPWN** | OTAA brute-forcing, downlinks 생성, payloads 복호화를 위한 Trend Micro Python utility | 2023년에 demo 공개, SDR-agnostic |
| **LoRAttack** | USRP를 사용한 multi-channel sniffer + replay, PCAP/LoRaTap export | 우수한 Wireshark integration |
| **gr-lora / gr-lorawan** | baseband TX/RX용 GNU Radio OOT blocks | custom attacks를 위한 기반 |

---

## Defensive recommendations (pentester checklist)

1. 진정으로 무작위인 DevNonce를 사용하는 **OTAA** devices를 우선 사용하고 중복을 모니터링합니다.
2. **LoRaWAN 1.1**을 적용합니다: 32-bit frame counters 및 서로 다른 FNwkSIntKey / SNwkSIntKey를 사용합니다.
3. frame-counter를 non-volatile memory에 저장하거나(**ABP**) OTAA로 마이그레이션합니다.
4. firmware extraction으로부터 root keys를 보호하기 위해 **secure-element**(ATECC608A/SX1262-TRX-SE)을 배포합니다.
5. 원격 UDP packet-forwarder ports(1700/1701)를 비활성화하거나 WireGuard/VPN으로 제한합니다.
6. gateways를 최신 상태로 유지합니다. Kerlink/Dragino는 2024년에 patch된 images를 제공합니다.
7. **traffic anomaly detection**(예: LAF analyzer)을 구현하여 counter resets, duplicate joins, 갑작스러운 ADR changes를 flag합니다.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
