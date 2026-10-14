# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## 引言

**Low-Power Wide Area Network**（LPWAN，低功耗广域网）是一类无线、低功耗、广域网技术，旨在以较低比特率实现**远距离通信**。
根据无线电参数、天线、监管区域、地形和占空比，LPWAN 部署可以牺牲吞吐量，以换取数公里的覆盖范围和数年的电池续航时间。应将厂商提供的覆盖范围和电池续航数据视为设计目标，而非保证值。<sup>[[3]](#references)</sup>

Long Range（**LoRa**）是目前部署最广泛的 LPWAN 物理层，其开放的 MAC 层规范为 **LoRaWAN**。

---

## LPWAN、LoRa 和 LoRaWAN

* LoRa – 由 Semtech 开发的 Chirp Spread Spectrum (CSS) 物理层（专有，但有文档说明）。
* LoRaWAN – 由 LoRa-Alliance 维护的开放 MAC/网络层。现场常见版本为 1.0.x 和 1.1。
* 典型架构：*终端设备 → 网关（packet-forwarder）→ network-server → application-server*。<sup>[[3]](#references)</sup>

> 在 LoRaWAN 1.1 中，**安全模型**使用独立的 AES-128 应用根密钥和网络根密钥，在 OTAA 过程中派生特定角色的会话密钥。较早的 1.0.x 部署通常使用一个 AppKey 来派生网络和应用会话密钥，而 ABP 会直接配置会话密钥。因此，泄露密钥后能够获得的能力取决于 LoRaWAN 版本以及暴露的是哪种密钥。<sup>[[3]](#references)</sup>

---

## 攻击面概述

| 层级 | 弱点 | 实际影响 |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 局部丢包；效果取决于链路预算、时序、带宽和监管限制 |
| MAC | nonce/计数器状态被重复使用时，可重放 Join 帧和数据帧 | 如果服务器/设备违反重放防护机制，可能导致设备失步、伪造或注入 |
| Network-Server | 不安全的 packet-forwarder、薄弱的 MQTT/UDP 过滤器、过时的网关固件 | 网关上的 RCE → 横向进入 OT/IT 网络 |
| Application | 硬编码或可预测的 AppKeys | 暴力破解/解密流量、冒充传感器 |

---

## 具有代表性的实现漏洞

* **CVE-2024-29862** – 受影响的 ChirpStack Gateway Bridge 4.0.11 之前版本和 MQTT Forwarder 4.2.1 之前版本，由于禁用了 TLS 服务器证书验证，可能会连接到攻击者控制的 MQTT broker。这可能导致凭据和网关流量暴露；请升级到修复版本。<sup>[[4]](#references)</sup>
* **Dragino LG01 固件 4.3.4** – CVE-2022-45227 描述了一个无需身份验证即可访问的 `/lib/` 目录列表，其中包含可下载的备份文件；CVE-2022-45228 是退出页面中一个低严重性 CSRF 漏洞。这些记录无法证实所声称的 LG308 影响、配置覆盖、受影响设备数量或 2025 年的补丁状态。<sup>[[6]](#references)[[7]](#references)</sup>
* 本页面早期版本曾描述一个所谓的 Semtech UDP packet-forwarder 问题：**精心构造的大于 255 字节的上行数据包会导致 SX130x 参考网关发生栈溢出并实现 RCE**；该说法归因于 Black Hat Europe 2023 的“LoRa Exploitation Reloaded”演讲和 2023 年 10 月的私有补丁。这里保留这些具体细节作为研究线索，但尚未找到可佐证的对应公开公告、演讲或补丁。未获得受影响的产品/版本及可验证的一手来源前，不要将此问题视为已知漏洞。

---

## 实用攻击技术

### 1. Sniff & Decrypt 流量

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

这些命令保留了原始工作流程，作为**示例语法**；不同项目/版本的仓库布局和 flags 可能有所不同。被动捕获无法揭示强 AppKey。只有在根密钥足够弱、可以被猜中，且捕获到的 join 交换过程提供了可用于验证候选值的信息时，离线猜测才有用。<sup>[[2]](#references)[[3]](#references)</sup>

### 2. 测试 OTAA 重放保护和 nonce 状态

1. 在经授权的测试网络中，捕获一个合法的 **JoinRequest**。
2. 重放相同的请求，并确认网络服务器会拒绝重用的 `DevNonce`。
3. 重启或重置测试设备，然后重复检查，以检测 nonce 状态是否丢失。符合规范的服务器必须跟踪已使用的 nonce；仅重放 JoinRequest 不会泄露新派生的会话密钥，也不会让重放者控制会话。<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. 自适应数据速率（ADR）降级

能够验证网络层 MAC 命令的攻击者——例如，在攻陷适用的网络会话密钥或网络服务器之后——可能会尝试强制使用效率低下的数据速率参数，增加空中传输时间。附近未通过身份验证的发射器不能仅凭设备地址就合法地发出 ADR 命令。<sup>[[3]](#references)</sup>

### 4. 响应式干扰

响应式干扰器可以在检测到 LoRa 前导码后发射信号，有选择性地干扰帧。前文声称 HackRF/GNU Radio 配置能在 **2 km、功率不超过 200 mW** 的条件下造成全面中断，但未提供支持该说法的测量来源；这些数字只能作为复现目标，而不能视为预期结果。所需发射功率、时序、带宽、受影响的扩频因子和范围都取决于具体环境。仅在经授权且具有 RF 屏蔽的配置中测试，并遵守当地频谱规定。

---

## 攻击工具（2025）

| 工具 | 用途 | 说明 |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | 构造/解析/攻击 LoRaWAN 帧，使用数据库的分析器，暴力破解 | Docker 镜像；支持 Semtech UDP 输入<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro 的 Python 工具，可对 OTAA 进行暴力破解、生成下行链路、解密载荷 | 公开的研究工具；请确认其支持的硬件和协议版本<sup>[[2]](#references)</sup> |
| **LoRAttack** | 用于多信道 LoRaWAN 捕获、会话分析、密钥派生和重放测试的研究框架 | 在 2024 年的一篇硕士论文中有介绍；依赖示例 flags 前，请先获取并验证确切的实现<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | 用于 LoRa 基带接收或收发器研究的 GNU Radio 外部模块 | 各项目在 GNU Radio 兼容性和功能集方面有所不同<sup>[[9]](#references)</sup> |

---

## 防御建议（pentester 检查清单）

1. 优先使用 **OTAA**，并确认设备和服务器会持久保存所需的 nonce 状态；监控被拒绝的重复 join。
2. 在支持的情况下，优先使用 **LoRaWAN 1.1**，以便网络功能使用不同的会话密钥和更新后的 nonce 处理机制。<sup>[[3]](#references)</sup>
3. 将帧计数器存储在非易失性内存中（**ABP**），或迁移到 OTAA。
4. 部署合适的 **secure element**（例如，在受支持的设计中使用 ATECC608A），以降低根密钥暴露在普通固件存储中的风险。
5. 不要将已配置的 packet-forwarder UDP 监听器（通常为 1700）暴露给不可信网络；对网关回传链路进行身份验证/加密，或使用 VPN 限制访问。
6. 让网关运行厂商支持的固件，并根据适用的安全公告确认确切的型号/版本。
7. 实施**流量异常检测**（例如，使用 LAF analyzer）——标记计数器重置、重复 join 和 ADR 突变。<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN 审计框架（LAF）](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN 概述](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 规范](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 区域参数和 join 同步](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU 论文目录 - 利用 SDR 技术分析 LPWAN 协议安全性](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio 收发器](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
