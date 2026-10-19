# VSAT 前向链路信号注入

{{#include ../../banners/hacktricks-training.md}}

VSAT 终端通常会将卫星下行链路视为来自运营商枢纽的流量。在 DVB-RCS 系统中，该前向链路既可传输用户 IP 数据包，也可传输调制解调器控制消息。如果接收器在处理消息前未对其进行身份验证，本地注入的信号就可能跨越从无线电到控制平面的信任边界。这是**在终端进行下行链路注入**，不是向卫星上行，也不是被动截获下行链路。实际效果取决于调制解调器的协议实现和消息身份验证机制，而非 DVB-RCS 本身。<sup>[[1]](#references)[[2]](#references)</sup>

## 在射频隔离实验室中测试

使用自有终端及其固件，并通过适当的衰减器将 SDR 连接到调制解调器的接收输入，或使用屏蔽射频环境。不要在实际卫星信道上发射信号。首先记录终端配置的启动载波、符号率和用户群 ID；这些信息有助于前向链路捕获。<sup>[[1]](#references)[[3]](#references)</sup> DVB-RCS 捕获链使用网络信息表 (NIT) 定位 RCS 映射表 (RMT)，再通过节目关联表 (PAT) 和节目映射表 (PMT) 定位前向链路信令流。终端可能会在多个传输流载波之间重新调谐，之后才到达数据流。<sup>[[3]](#references)</sup>

1. 解码或重建目标的启动传输流，并检查其 NIT、RMT、服务 ID、数据包 ID (PID) 和时钟参考处理方式。对照标准检查目标的解析器和日志；厂商特定的排序方式或描述符可能导致原本有效的流无法被接受。
2. 在实验室发射端，将无害的 UDP 探测包封装为 `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q`，并通过 SDR sink 输入隔离的接收路径。确保传输流的节目时钟参考 (PCR) 与字节速率一致，否则调制解调器可能会在处理探测包前失去同步。
3. 确认**解调器已锁定**，并在自有的内部端点上收到探测包。仅有锁定状态只能证明物理层接受了波形。然后检查是否存在未经身份验证的管理或更新*信令*，但不要安装映像或更改服务配置。

已公开的 MDM2200 案例使用 GNU Radio 源模块处理 DVB-RCS/MPE/MPEG-TS，并使用 `gr-dtv` 进行 DVB-S2 调制。该调制解调器需要针对目标设备的初始化细节：PAT/PMT 之前要有 SDT、表 ID 为 `0x3E` 的 RCS 内容描述符，以及在其 GSE/4CPM 模式下使用私有字节 `0x01` 的 RMT。不要假设这些值适用于其他终端。<sup>[[1]](#references)</sup> 研究人员还观察到，在他们的环境中，多播 MPE 数据包能够到达接收调制解调器，因此目标选择不局限于已知的单播 MAC 地址。<sup>[[1]](#references)</sup> 另一项分析发现，所研究的系统存在未受保护的控制和软件更新信令，但必须针对每种实现分别验证这一发现。<sup>[[2]](#references)</sup>

用户流量使用 IPsec 或 VPN 隧道，并不能对更早出现的 DVB-RCS 信令或调制解调器自身的更新解析器进行身份验证。在获准的评估中，应区分**用户 IP**、**前向链路控制**和**维护/恢复**流量的加密保护，而不要把安全的用户隧道当作无线电注入已被阻止的证据。<sup>[[1]](#references)[[2]](#references)</sup>

有关初步 I/Q 检查，请参阅 [radio signal analysis](../hardware-hacking/radio.md)。有关板级固件和解析器检查，请参阅 [firmware analysis](../firmware-analysis/)。返回 [Radio Hacking overview](./) 查看其他接口。

## References

- [1] [Bisping et al. - VSAT 卫星调制解调器上的无线信号注入攻击 (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer：揭示当前 VSAT 系统实践中固有的安全问题 (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - 卫星分发系统的 DVB 交互信道](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
