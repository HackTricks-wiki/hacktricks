# 低功耗广域网

{{#include ../../banners/hacktricks-training.md}}

## 介绍

**低功耗广域网** (LPWAN) 是一组无线、低功耗、广域网技术，旨在实现**长距离通信**，并具有低比特率。
它们的通信范围可超过**六英里**，其**电池**寿命可达**20年**。

长距离 (**LoRa**) 目前是部署最广泛的 LPWAN 物理层，其开放的 MAC 层规范是 **LoRaWAN**。

---

## LPWAN、LoRa 和 LoRaWAN

* LoRa – 由 Semtech 开发的啁啾扩频 (CSS) 物理层（专有但有文档）。
* LoRaWAN – 由 LoRa-Alliance 维护的开放 MAC/网络层。版本 1.0.x 和 1.1 在实际应用中较为常见。
* 典型架构：*终端设备 → 网关（数据包转发器） → 网络服务器 → 应用服务器*。

> **安全模型** 依赖于两个 AES-128 根密钥 (AppKey/NwkKey)，在 *加入* 过程中（OTAA）派生会话密钥，或是硬编码（ABP）。如果任何密钥泄露，攻击者将获得对相应流量的完全读/写能力。

---

## 攻击面总结

| 层级 | 弱点 | 实际影响 |
|-------|----------|------------------|
| PHY | 反应性/选择性干扰 | 使用单个 SDR 和 <1 W 输出演示 100% 数据包丢失 |
| MAC | 加入接受和数据帧重放（随机数重用，ABP 计数器回滚） | 设备欺骗、消息注入、拒绝服务 |
| 网络服务器 | 不安全的数据包转发器、弱 MQTT/UDP 过滤器、过时的网关固件 | 网关上的 RCE → 进入 OT/IT 网络 |
| 应用 | 硬编码或可预测的 AppKeys | 暴力破解/解密流量，冒充传感器 |

---

## 最近的漏洞 (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge 和 mqtt-forwarder* 接受绕过有状态防火墙规则的 TCP 数据包，导致远程管理接口暴露。分别在 4.0.11 / 4.2.1 中修复。
* **Dragino LG01/LG308 系列** – 多个 2022-2024 CVE（例如 2022-45227 目录遍历，2022-45228 CSRF）在 2025 年仍未修补；在数千个公共网关上启用未经身份验证的固件转储或配置覆盖。
* Semtech *数据包转发器 UDP* 溢出（未发布的建议，2023-10 修补）：构造的上行数据包大于 255 B 触发堆栈溢出 -> 在 SX130x 参考网关上 RCE（由 Black Hat EU 2023 “LoRa Exploitation Reloaded” 发现）。

---

## 实用攻击技术

### 1. 嗅探和解密流量
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA 加入重放 (DevNonce 重用)

1. 捕获一个合法的 **JoinRequest**。
2. 在原始设备再次传输之前立即重新传输它（或增加 RSSI）。
3. 网络服务器分配一个新的 DevAddr 和会话密钥，而目标设备继续使用旧会话 → 攻击者拥有空闲会话并可以注入伪造的上行链路。

### 3. 自适应数据速率 (ADR) 降级

强制 SF12/125 kHz 以增加空中时间 → 耗尽网关的占空比（拒绝服务），同时对攻击者的电池影响较小（仅发送网络级 MAC 命令）。

### 4. 反应性干扰

运行 GNU Radio 流图的 *HackRF One* 在检测到前导码时触发宽带啁啾 - 阻塞所有扩频因子，发射功率 ≤200 mW；在 2 公里范围内测量到完全中断。

---

## 攻击工具 (2025)

| 工具 | 目的 | 备注 |
|------|---------|-------|
| **LoRaWAN 审计框架 (LAF)** | 构造/解析/攻击 LoRaWAN 帧，基于数据库的分析器，暴力破解 | Docker 镜像，支持 Semtech UDP 输入 |
| **LoRaPWN** | Trend Micro Python 工具，用于暴力 OTAA，生成下行链路，解密有效载荷 | 2023 年发布演示，SDR 无关 |
| **LoRAttack** | 多通道嗅探器 + 重放，使用 USRP；导出 PCAP/LoRaTap | 良好的 Wireshark 集成 |
| **gr-lora / gr-lorawan** | GNU Radio OOT 块，用于基带 TX/RX | 自定义攻击的基础 |

---

## 防御建议 (渗透测试者检查清单)

1. 优先选择具有真正随机 DevNonce 的 **OTAA** 设备；监控重复项。
2. 强制执行 **LoRaWAN 1.1**：32 位帧计数器，独特的 FNwkSIntKey / SNwkSIntKey。
3. 将帧计数器存储在非易失性存储器中 (**ABP**) 或迁移到 OTAA。
4. 部署 **安全元件** (ATECC608A/SX1262-TRX-SE) 以保护根密钥免受固件提取。
5. 禁用远程 UDP 数据包转发端口 (1700/1701) 或使用 WireGuard/VPN 限制。
6. 保持网关更新；Kerlink/Dragino 提供 2024 年修补的镜像。
7. 实施 **流量异常检测**（例如，LAF 分析器） - 标记计数器重置、重复加入、突然的 ADR 变化。

## 参考文献

* LoRaWAN 审计框架 (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Trend Micro LoRaPWN 概述 – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
