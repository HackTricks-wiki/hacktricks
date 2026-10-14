# 工业控制系统 Hacking

{{#include ../banners/hacktricks-training.md}}

## 本节介绍

本节介绍工业控制系统（ICS）的组件、架构、协议和安全评估方法。ICS 属于更广泛的运营技术（OT）领域：用于监控物理过程或使其发生变化的可编程系统和设备。常见示例包括监控控制与数据采集（SCADA）系统、分布式控制系统（DCS）和可编程逻辑控制器（PLC）。<sup>[[1]](#references)</sup>

在这些环境中开展安全工作时，必须考虑不同于传统 IT 的要求，包括过程安全、可靠性、可用性、确定性运行和设备生命周期。即使某项安全控制在技术上有效，只要它会干扰物理过程，就可能不适用；因此，测试和修复应与系统所有者及运维人员协调进行。<sup>[[1]](#references)</sup>

遭到入侵或意外中断可能导致生产停摆、设备损坏、危险物质泄漏、环境受损，或造成人员受伤和生命损失。由于可能产生这些物理影响，主动测试前必须先了解受控过程及其安全运行限值。<sup>[[1]](#references)</sup>

许多 OT 部署仍在使用旧版操作系统、应用程序和协议，因为设备使用寿命较长，且变更需要经过运行和安全测试。某些协议在设计时没有采用现代身份验证或加密机制；而供应商支持或维护窗口等限制也可能影响补丁安装。如果无法直接升级，可通过网络分段、访问控制和监控进行补偿。<sup>[[1]](#references)</sup>

## 评估重点

首先了解受控过程、系统边界、网络拓扑、资产、数据流、信任关系和外部连接。相同类型的设备在不同站点可能承担不同功能，因此不要假定某个部署的架构或影响模型适用于其他部署。<sup>[[1]](#references)</sup>

尽可能优先采用被动发现和现有工程文档。任何主动扫描或利用都应遵循经批准的测试计划，其中要明确安全限制、维护窗口、恢复流程和停止条件。评估发现的问题时，应同时考虑网络安全影响及其对物理过程的潜在影响。<sup>[[1]](#references)</sup>

同样的架构知识也有助于开展资产清单管理、网络分段、监控、事件响应和基于风险的漏洞管理等防御工作。<sup>[[1]](#references)</sup>

## 协议入口

- [Modbus 测试](../network-services-pentesting/pentesting-modbus.md)介绍 Modbus TCP、串行变体、功能码和寄存器访问。
- [OPC UA 测试](../network-services-pentesting/4840-pentesting-opc-ua.md)介绍工业数据交换服务。
- [BACnet 测试](../network-services-pentesting/47808-udp-bacnet.md)介绍楼宇自动化控制网络。

## References

- [1] [NIST SP 800-82 Rev. 3 - 运营技术（OT）安全指南](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
