# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network**（LPWAN）は、低いビットレートで**長距離通信**を実現するよう設計された、wireless、low-power、wide-area network technologiesの総称です。
**6マイル**以上に到達でき、**バッテリー**は最長で**20年**持続します。

Long Range（**LoRa**）は現在、最も普及しているLPWANのphysical layerであり、そのオープンなMAC-layer specificationが**LoRaWAN**です。

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Semtechが開発したChirp Spread Spectrum（CSS）physical layer（proprietaryですが仕様は文書化されています）。
* LoRaWAN – LoRa-Allianceが維持するOpen MAC/Network layer。現場ではバージョン1.0.xおよび1.1が一般的です。
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> **security model**は、2つのAES-128 root keys（AppKey/NwkKey）に依存しており、*join* procedure（OTAA）中にsession keysを派生させるか、ABPではハードコードされます。いずれかのkeyがleakすると、攻撃者は対応するtrafficに対する完全なread/write capabilityを得ます。

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 単一のSDRと1 W未満の出力で、100 % packet lossを実証 |
| MAC | Join-Accept & data-frame replay (nonce reuse, ABP counter rollover) | Device spoofing、message injection、DoS |
| Network-Server | Insecure packet-forwarder、weak MQTT/UDP filters、outdated gateway firmware | Gateways上でのRCE → OT/IT networkへのpivot |
| Application | Hard-codedまたはpredictableなAppKeys | Brute-force/decrypt traffic、sensorsのimpersonation |

---

## Recent vulnerabilities (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder*は、Kerlink gateways上のstateful firewall rulesをバイパスするTCP packetsを受け入れ、remote management interfaceのexposureを可能にしていました。それぞれ4.0.11 / 4.2.1で修正済みです。
* **Dragino LG01/LG308 series** – 複数の2022-2024年のCVEs（例：2022-45227 directory traversal、2022-45228 CSRF）が、2025年にも未修正のまま確認されています。これらにより、数千のpublic gatewaysでunauthenticated firmware dumpまたはconfig overwriteが可能になります。
* Semtech *packet-forwarder UDP* overflow（未公開のadvisory、2023-10にpatch）：255 Bを超えるcrafted uplinkによりstack-smash → SX130x reference gateways上でRCEが発生しました（Black Hat EU 2023の「LoRa Exploitation Reloaded」で発見）。

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
### 2. OTAA join-replay（DevNonce reuse）

1. 正規の **JoinRequest** をキャプチャする。
2. 元のデバイスが再送信する前に、直ちにそれを再送信する（または RSSI を増加させる）。
3. network-server は新しい DevAddr と session keys を割り当てる一方、標的デバイスは古い session を継続する → attacker は空いている session を取得し、偽造 uplinks を注入できる。

### 3. Adaptive Data-Rate（ADR）downgrading

SF12/125 kHz を強制して airtime を増加させる → gateway の duty-cycle を枯渇させ、denial-of-service を引き起こす一方、attacker 側の battery への影響は低く抑えられる（network-level MAC commands を送信するだけ）。

### 4. Reactive jamming

*HackRF One* で GNU Radio flowgraph を実行し、preamble を検出するたびに wide-band chirp をトリガーする - ≤200 mW TX ですべての spreading factors をブロックし、2 km の距離で完全な outage を測定 。

---

## Offensive tooling（2025）

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames の作成・解析・attack、DB-backed analyzers、brute-forcer | Docker image、Semtech UDP input をサポート |
| **LoRaPWN** | OTAA の brute、downlinks の生成、payloads の decrypt に対応する Trend Micro の Python utility | 2023 年に Demo をリリース、SDR-agnostic |
| **LoRAttack** | USRP による multi-channel sniffer + replay、PCAP/LoRaTap を export | Wireshark integration が良好 |
| **gr-lora / gr-lorawan** | baseband TX/RX 用 GNU Radio OOT blocks | custom attacks の基盤 |

---

## Defensive recommendations（pentester checklist）

1. 真にランダムな DevNonce を使用する **OTAA** devices を優先し、重複を監視する。
2. **LoRaWAN 1.1** を強制する：32-bit frame counters、および個別の FNwkSIntKey / SNwkSIntKey。
3. frame-counter を non-volatile memory（**ABP**）に保存するか、OTAA に migrate する。
4. firmware extraction から root keys を保護するため、**secure-element**（ATECC608A/SX1262-TRX-SE）を導入する。
5. remote UDP packet-forwarder ports（1700/1701）を無効化するか、WireGuard/VPN で制限する。
6. gateways を updated に保つ。Kerlink/Dragino は 2024-patched images を提供している。
7. **traffic anomaly detection**（例：LAF analyzer）を実装する - counter resets、duplicate joins、突然の ADR changes にフラグを付ける。<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
