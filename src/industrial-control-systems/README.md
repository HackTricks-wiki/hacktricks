# 工业控制系统 Hacking

{{#include ../banners/hacktricks-training.md}}

## 本节介绍

本节介绍工业控制系统（ICS）的组件、架构、协议和安全评估方法。ICS 属于更广泛的运营技术（OT）领域：用于监控物理流程或使其发生变化的可编程系统和设备。常见示例包括监控与数据采集（SCADA）系统、分布式控制系统（DCS）和可编程逻辑控制器（PLC）。<sup>[[1]](#references)</sup>

在这些环境中开展安全工作时，必须考虑一些不同于传统 IT 的要求，包括流程安全、可靠性、可用性、确定性运行和设备生命周期。即使某项安全控制在技术上有效，如果会干扰物理流程，也可能不适用。因此，测试和修复应与系统所有者及运维人员协调进行。<sup>[[1]](#references)</sup>

系统遭到入侵或意外中断，可能导致停产、设备损坏、危险物质泄漏、环境受损，或造成人员受伤和生命损失。由于可能产生这些物理影响，在进行主动测试前，必须先了解受控流程及其安全运行限值。<sup>[[1]](#references)</sup>

许多 OT 部署仍在使用旧版操作系统、应用程序和协议，因为设备的使用寿命很长，而且任何变更都需要经过运行和安全测试。有些协议的设计未包含现代身份验证或加密机制；由于厂商支持或维护窗口的限制，打补丁也可能受阻。在无法直接升级的情况下，可通过网络分段、访问控制和监控来降低风险。<sup>[[1]](#references)</sup>

## 评估重点

首先了解受控流程、系统边界、网络拓扑、资产、数据流、信任关系和外部连接。相同类型的设备在不同站点可能承担不同功能，因此不要假设一个部署的架构或影响模型适用于另一个部署。<sup>[[1]](#references)</sup>

尽可能优先采用被动发现方法并查阅现有工程文档。任何主动扫描或利用都应遵循经批准的测试计划，其中须明确安全限制、维护窗口、恢复程序和停止条件。评估发现的问题时，既要考虑网络安全影响，也要考虑其对物理流程的潜在影响。<sup>[[1]](#references)</sup>

同样的架构知识也有助于开展资产清点、网络分段、监控、事件响应和基于风险的漏洞管理等防御工作。<sup>[[1]](#references)</sup>

## 滥用制冷系统监控器

制冷系统管理器负责协调压缩机和冷柜控制器，但它本身不会为冷柜制冷。因此，获得其管理界面的访问权限，可能就能通过常规配置分发控制多个下级设备。这不同于更改单个恒温器或直接驱动压缩机。<sup>[[3]](#references)[[4]](#references)</sup>

### 基于日期的维护码登录

在受影响的 Danfoss 系统管理器上，另一种 XML 登录方式接受由控制器日期生成的代码，而不是账户密码。<sup>[[2]](#references)[[3]](#references)</sup> 在 SM800 和 SC255 上，Synacktiv 追踪了 `eds_only` 和 `quantum_only` 属性，发现它们经由 `xml_load_file` 和 `check_authorize` 调用 `check_code_of_day`。其公告还显示，`xml.cgi` 上的 `read_date_time` 无需身份验证即可泄露控制器日期。<sup>[[2]](#references)</sup> Claroty 在 AK-SM 800A 上发现了对应的 `getauth` 路径，但对其触发属性进行了删节；不应假设旧型号的属性名称在该平台上也有效。<sup>[[3]](#references)</sup>

Synacktiv 对无需身份验证的日期查询记录如下：<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

该代码没有设备专属密钥：从[固件](../hardware-physical-access/firmware-analysis/)中还原算法，可以为采用相同受影响实现的设备生成在日期上有效的凭据。<sup>[[2]](#references)[[3]](#references)</sup> 请先确认型号和固件版本。仅收到日期响应，并不能证明存在备用登录方式，也不能证明已获取 session。

### 批量配置与除霜加热器滥用

获得管理权限后，应确定系统管理器关联的冷柜控制器，并确认其配置分发功能能否同时更新这些控制器。通常，修改冷柜设定点只会让柜内温度升高至室温附近。若要使温度超过环境温度，相关控制项是冷柜控制器的电蒸发器除霜加热器：除霜时，制冷会停止，加热器会运行，直到传感器或定时器终止除霜周期。修改除霜方式、计划、终止温度和时间限制，可以让加热器持续运行。系统管理器可以将这些更改分发到多个冷柜，并抑制相关警报，从而将一次监控系统失陷转变为全店范围的流程变更。<sup>[[4]](#references)</sup>

这是物理过程风险，不是适合在运行中的系统上进行的安全概念验证。若设备配有热熔断器，其可能会限制加热器的运行，但持续工作仍可能导致原本就存在缺陷的电气连接过热。仅应在获批的实验室中，或依据运营方的过程安全计划，验证配置及其影响。<sup>[[4]](#references)</sup>

## 协议入口

- [Modbus 测试](../network-services-pentesting/pentesting-modbus.md)涵盖 Modbus TCP、串行变体、功能码和寄存器访问。
- [OPC UA 测试](../network-services-pentesting/4840-pentesting-opc-ua.md)涵盖工业数据交换服务。
- [BACnet 测试](../network-services-pentesting/47808-udp-bacnet.md)涵盖楼宇自动化控制网络。

## References

- [1] [NIST SP 800-82 Rev. 3 - Operational Technology (OT) Security 指南](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Danfoss System-Managers SM800 和 SC255 中的身份验证绕过](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - 冻结控制器，解冻食品：发现 Danfoss 制冷控制器中的漏洞](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - 不需要国家级攻击者也能让冰箱升温](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
