# 低功耗广域网络

{{#include ../../banners/hacktricks-training.md}}

## 简介

**低功耗广域网络**（LPWAN）是一组无线、低功耗、广域网络技术，专为以低 bit rate 进行**远距离通信**而设计。
其通信距离可超过**六英里**，并且其**电池**续航时间最长可达**20 年**。

长距离（**LoRa**）是目前部署最广泛的 LPWAN physical layer，其开放的 MAC-layer specification 是 **LoRaWAN**。

---

## LPWAN、LoRa 和 LoRaWAN

* LoRa – 由 Semtech 开发的 Chirp Spread Spectrum（CSS）physical layer（专有但有文档说明）。
* LoRaWAN – 由 LoRa-Alliance 维护的开放 MAC/Network layer。现场常见版本为 1.0.x 和 1.1。
* 典型架构：*end-device → gateway (packet-forwarder) → network-server → application-server*。

> **安全模型**依赖两个 AES-128 root keys（AppKey/NwkKey），在 *join* 过程中（OTAA）派生 session keys，或将其硬编码（ABP）。如果任何 key 发生 leak，攻击者即可完全读取和写入相应流量。

---

## 攻击面摘要

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 使用单个 SDR 和小于 1 W 的输出功率，即可实现经演示的 100 % packet loss |
| MAC | Join-Accept & data-frame replay（nonce reuse、ABP counter rollover） | Device spoofing、message injection、DoS |
| Network-Server | Insecure packet-forwarder、weak MQTT/UDP filters、outdated gateway firmware | 网关上的 RCE → pivot into OT/IT network |
| Application | Hard-coded or predictable AppKeys | Brute-force/decrypt traffic、impersonate sensors |

---

## 近期漏洞（2023-2025）

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* 接受了可绕过 Kerlink 网关 stateful firewall rules 的 TCP packets，从而导致 remote management interface exposure。分别已在 4.0.11 / 4.2.1 中修复。
* **Dragino LG01/LG308 series** – 多个 2022-2024 CVE（例如 2022-45227 directory traversal、2022-45228 CSRF）在 2025 年仍被发现未修复；这些漏洞可在数千个公开网关上启用 unauthenticated firmware dump 或 config overwrite。
* Semtech *packet-forwarder UDP* overflow（未发布的 advisory，已于 2023-10 修复）：构造大于 255 B 的 uplink 会触发 stack-smash ‑> RCE，影响 SX130x reference gateways（由 Black Hat EU 2023 的 “LoRa Exploitation Reloaded” 发现）。

---

## 实用攻击技术

### 1. 嗅探与解密流量
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce reuse)

1. 捕获一个合法的 **JoinRequest**。
2. 在原始设备再次传输之前，立即重传该请求（或增加 RSSI）。
3. network-server 分配新的 DevAddr 和会话密钥，而目标设备继续使用旧会话 → attacker 获得闲置会话，并可注入伪造的上行数据。

### 3. Adaptive Data-Rate (ADR) downgrading

强制使用 SF12/125 kHz 以增加空中时间 → 耗尽 gateway 的 duty-cycle（拒绝服务），同时将 attacker 的电池影响保持在较低水平（只需发送网络级 MAC 命令）。

### 4. Reactive jamming

*HackRF One* 运行 GNU Radio flowgraph，在检测到前导码时触发宽带 chirp – 使用 ≤200 mW TX 阻塞所有 spreading factors；在 2 km 范围内测得完全中断。

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | 构造/解析/攻击 LoRaWAN 帧，基于 DB 的分析器，brute-forcer | Docker image，支持 Semtech UDP 输入 |
| **LoRaPWN** | Trend Micro 的 Python utility，用于 brute OTAA、生成 downlinks、解密 payloads | Demo 于 2023 年发布，与 SDR 无关 |
| **LoRAttack** | 使用 USRP 的多信道 sniffer + replay；导出 PCAP/LoRaTap | 良好的 Wireshark 集成 |
| **gr-lora / gr-lorawan** | 用于 baseband TX/RX 的 GNU Radio OOT blocks | 自定义攻击的基础 |

---

## Defensive recommendations (pentester checklist)

1. 优先使用具有真正随机 DevNonce 的 **OTAA** 设备；监控重复值。
2. 强制使用 **LoRaWAN 1.1**：32 位帧计数器，以及不同的 FNwkSIntKey / SNwkSIntKey。
3. 将 frame-counter 存储在非易失性内存中（**ABP**），或迁移到 OTAA。
4. 部署 **secure-element**（ATECC608A/SX1262-TRX-SE），以保护根密钥免遭固件提取。
5. 禁用远程 UDP packet-forwarder 端口（1700/1701），或使用 WireGuard/VPN 限制访问。
6. 保持 gateways 更新；Kerlink/Dragino 提供了 2024 年修补的 images。
7. 实施 **traffic anomaly detection**（例如 LAF analyzer）– 标记计数器重置、重复 join 以及突然的 ADR 变化。<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
