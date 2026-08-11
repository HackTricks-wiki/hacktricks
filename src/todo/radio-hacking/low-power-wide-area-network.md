# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network**（LPWAN）是一组无线、低功耗、广域网络技术，旨在以较低 bit rate 实现**长距离通信**。
根据 radio 参数、天线、监管区域、地形和 duty cycle，LPWAN 部署可以牺牲 throughput，换取数公里覆盖范围和多年电池续航。应将厂商给出的 range 和 battery 数据视为设计目标，而不是保证值。<sup>[[3]](#references)</sup>

Long Range（**LoRa**）是目前部署最广泛的 LPWAN physical layer，其开放的 MAC-layer specification 是 **LoRaWAN**。

---

## LPWAN、LoRa 和 LoRaWAN

* LoRa – 由 Semtech 开发的 Chirp Spread Spectrum（CSS）physical layer（专有但有文档说明）。
* LoRaWAN – 由 LoRa-Alliance 维护的开放 MAC/Network layer。1.0.x 和 1.1 版本在实际环境中较为常见。
* 典型架构：*end-device → gateway (packet-forwarder) → network-server → application-server*。<sup>[[3]](#references)</sup>

> 在 LoRaWAN 1.1 中，**security model** 使用独立的 AES-128 application 和 network root keys，在 OTAA 期间派生出具有特定角色的 session keys。早期的 1.0.x 部署通常使用一个 AppKey 来派生 network 和 application session keys，而 ABP 则直接配置 session keys。因此，从泄露的 key 中获得的能力取决于 LoRaWAN 版本以及暴露的是哪一个 key。<sup>[[3]](#references)</sup>

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 局部 packet loss；实际效果取决于 link budget、timing、bandwidth 和监管限制 |
| MAC | 在 nonce/counter state 被重复使用时 replay join 和 data-frame | 如果 server/device 违反 replay protections，可能导致 device desynchronization、spoofing 或 injection |
| Network-Server | 不安全的 packet-forwarder、薄弱的 MQTT/UDP filters、过时的 gateway firmware | gateway 上的 RCE → pivot 进入 OT/IT network |
| Application | Hard-coded 或可预测的 AppKeys | Brute-force/decrypt traffic、冒充 sensors |

---

## Representative implementation vulnerabilities

* **CVE-2024-29862** – 受影响的 4.0.11 之前的 ChirpStack Gateway Bridge 版本和 4.2.1 之前的 MQTT Forwarder 版本，由于禁用了 TLS server-certificate validation，可能连接到攻击者控制的 MQTT broker。这可能暴露 credentials 和 gateway traffic；应升级到修复后的版本。<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 描述了一个未经 authentication 的 `/lib/` directory listing，其中包含可下载的 backup file；CVE-2022-45228 是 logout page 中的低严重性 CSRF。这些记录无法证明所声称的 LG308 impact、configuration overwrite、population size 或 2025 patch state。<sup>[[6]](#references)[[7]](#references)</sup>
* 本页面的早期版本曾描述一个据称存在的 Semtech UDP packet-forwarder issue：**大于 255 字节的 crafted uplink 导致 stack smash，并在 SX130x reference gateways 上实现 RCE**；该问题据称源自 Black Hat Europe 2023 的 “LoRa Exploitation Reloaded” presentation 以及 2023 年 10 月的 private patch。这里保留这些具体细节作为 research lead，但尚未找到相匹配的 public advisory、presentation 或 patch 加以 corroborate。在获得受影响的 product/version 和可验证的 primary source 之前，不要将该问题视为已知 vulnerability。

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
这些命令保留了原始工作流，作为**说明性语法**；不同项目或版本的仓库布局和 flags 可能有所不同。Passive capture 不会泄露强度较高的 AppKey。只有当 root key 足够弱、可以被找到，并且捕获到的 join exchange 提供了可用于验证候选值的信息时，离线猜测才有用。<sup>[[2]](#references)[[3]](#references)</sup>

### 2. 测试 OTAA replay protection 和 nonce state

1. 在经过授权的测试网络中，捕获一个合法的 **JoinRequest**。
2. Replay 同一个请求，并确认 network server 拒绝重复使用的 `DevNonce`。
3. Reboot 或 reset 测试设备，然后重复检查，以检测 nonce state 是否丢失。符合规范的 server 必须跟踪已使用的 nonce；单独 replay JoinRequest 不会泄露新派生的 session keys，也不会让 replayer 控制某个 session。<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. 自适应数据速率（ADR）降级

能够认证 network-layer MAC commands 的攻击者——例如在 compromise 适用的 network session key 或 network server 后——可能会尝试强制使用低效的数据速率参数，从而增加 airtime。附近的 unauthenticated transmitter 不能仅凭知道 device address 就合法地发出 ADR commands。<sup>[[3]](#references)</sup>

### 4. 响应式干扰

Reactive jammer 可以在检测到 LoRa preamble 后发射信号，并有选择地干扰 frames。此前页面声称 HackRF/GNU Radio setup 能够在 **2 km、功率不超过 200 mW** 的条件下造成全面中断，但没有提供支持性测量来源；保留这些数值时，应将其作为 reproduction target，而不是预期结果。所需的 transmit power、timing、bandwidth、受影响的 spreading factors 和 range 都取决于具体环境。只能在经过授权且具备 RF containment 的 setup 中进行测试，并遵守当地的 spectrum 规定。

---

## 攻击工具（2025）

| 工具 | 用途 | 备注 |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | 构造/解析/攻击 LoRaWAN frames，提供基于 DB 的 analyzers 和 brute-forcer | Docker image；支持 Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro 的 Python utility，用于 brute OTAA、生成 downlinks、解密 payloads | Public research utility；使用前确认支持的 hardware 和 protocol versions<sup>[[2]](#references)</sup> |
| **LoRAttack** | 用于多 channel LoRaWAN capture、session analysis、key derivation 和 replay testing 的 research framework | 在一篇 2024 年 master's thesis 中有所描述；在依赖示例 flags 前，应获取并验证确切的 implementation<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | 用于 LoRa baseband reception 或 transceiver research 的 GNU Radio out-of-tree blocks | 不同项目在 GNU Radio compatibility 和 feature set 方面存在差异<sup>[[9]](#references)</sup> |

---

## 防御建议（pentester checklist）

1. 优先使用 **OTAA**，并验证 devices 和 servers 是否持久化保存所需的 nonce state；监控被拒绝的 duplicate joins。
2. 在支持的情况下优先使用 **LoRaWAN 1.1**，以便 network functions 使用彼此独立的 session keys 和更新后的 nonce handling。<sup>[[3]](#references)</sup>
3. 将 frame-counter 存储在 non-volatile memory（**ABP**）中，或迁移到 OTAA。
4. 部署适用的 **secure element**（例如，在受支持的设计中使用 ATECC608A），以减少 root keys 暴露在普通 firmware storage 中的风险。
5. 不要将已配置的 packet-forwarder UDP listeners（通常为 1700）暴露给 untrusted networks；对 gateway backhaul 进行 authentication/encryption，或使用 VPN 加以限制。
6. 让 gateways 使用 vendor-supported firmware，并根据适用的 advisories 确认确切的 model/version。
7. 实施**流量异常检测**（例如 LAF analyzer）——标记 counter resets、duplicate joins 和突发的 ADR changes。<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN 审计框架（LAF）](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN 概览](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 规范](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 区域参数和 join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - 利用 SDR Technology 进行 LPWAN Protocol Security Analysis](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
