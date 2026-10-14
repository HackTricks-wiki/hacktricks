# FISSURE - RF 框架

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering（基于频率无关 SDR 的信号理解与逆向工程）**

FISSURE 是一款开源 RF 和逆向工程框架，适用于各种技能水平，提供信号检测与分类、协议发现、攻击执行、IQ 操作、漏洞分析、自动化和 AI/ML 等功能。该框架旨在促进软件模块、无线电设备、协议、信号数据、脚本、flow graph、参考资料和第三方工具的快速集成。FISSURE 可帮助用户简化工作流程，将软件集中管理，并让团队轻松上手，同时共享针对特定 Linux 发行版的同一套经过验证的基线配置。<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE 中的框架和工具可用于检测 RF 能量、分析信号特征、收集和分析样本、开发发射或注入技术，以及制作自定义 payload 或消息。FISSURE 还提供协议和信号信息，便于识别、构造数据包和 fuzzing，并提供用于流量模拟和测试的归档文件与播放列表。<sup>[[1]](#references)[[2]](#references)</sup>

Python 代码库和图形界面可帮助初学者学习 RF 和逆向工程工具。教育工作者可以使用内置课程，开发者和研究人员则可以集成自己的模块和工作流程。当前版本还支持分布式传感器节点、TAK 集成、地理定位工作流程，以及针对不同角色的 Apptainer 部署。<sup>[[1]](#references)[[3]](#references)</sup>

**更多信息**

* [AIS 页面](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 幻灯片](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 论文](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 视频](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat 文字记录](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 入门

**支持的系统**

当前版本的 FISSURE 使用 **`Python3`** 分支进行活跃开发，搭配 PyQt5 和 GNU Radio 3.8 或 3.10。已弃用的 **`Python2_maint-3.7`** 分支仍可用于较旧的操作系统，以及需要 GNU Radio 3.7 的第三方工具。之前的 `Python3_maint-3.8` 和 `Python3_maint-3.10` 分支名称仅用于历史记录；现在可从 `Python3` 分支选择 GNU Radio 维护版本。<sup>[[1]](#references)[[3]](#references)</sup>

| 操作系统 | FISSURE 分支 | 默认 GNU Radio 分支 |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | 使用受支持的 Linux 版本 | 使用对应的版本 |

**开发中（beta）**

这些操作系统仍处于 beta 阶段，相关支持仍在开发中，已知有若干功能缺失。安装程序中的项目可能与现有程序冲突，或者在移除该状态前无法安装。

| 操作系统 | FISSURE 分支 | 默认 GNU Radio 分支 |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

部分第三方工具并非适用于所有操作系统。安装前请查阅当前的[已知冲突和第三方软件](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts)文档。<sup>[[3]](#references)</sup>

**安装**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

子模块步骤会下载 FISSURE 使用的 GNU Radio 外部模块，安装这些模块时必须执行此步骤。安装程序还会安装启动其安装 GUI 所需的缺失 PyQt 依赖项。<sup>[[3]](#references)</sup>

接下来，选择最符合你操作系统的选项（如果你的操作系统符合某个选项，系统应会自动检测）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

建议在干净的操作系统上安装 FISSURE，以避免现有冲突。选中所有建议的复选框（“Default”按钮），以避免在使用 FISSURE 中的各种工具时出错。安装过程中会出现多个提示，大多是请求提升权限和输入用户名。如果某个项目末尾包含“Verify”部分，安装程序将运行后续命令，并根据命令是否产生错误，将该复选框项目标为绿色或红色。没有“Verify”部分的已勾选项目在安装完成后仍会显示为黑色。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**用法**

打开终端并输入：

```
fissure
```

有关用法的更多详情，请参阅 FISSURE 的 Help 菜单。

## 详情

**组件**

* 仪表板
* 中央枢纽 (HIPRFISR)
* 目标信号识别 (TSI)
* 协议发现 (PD)
* Flow Graph 与脚本执行器 (FGE)

![组件](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**功能**

| ![信号检测器图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**信号检测器**_ | ![IQ 操作图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ 操作**_      | ![信号查找图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**信号查找**_          | ![模式识别图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**模式识别**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![攻击图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**攻击**_           | ![Fuzzing 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![信号播放列表图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**信号播放列表**_       | ![图片图库图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**图片图库**_  |
| ![数据包构造图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**数据包构造**_   | ![Scapy 集成图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy 集成**_ | ![CRC 计算器图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC 计算器**_ | ![日志图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**日志记录**_            |

**硬件**

以下硬件与 FISSURE 的集成程度各不相同：<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 适配器
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## 课程

FISSURE 提供了多份实用指南，帮助用户熟悉不同的技术和技巧。其中许多指南包含使用集成到 FISSURE 中的各类工具的步骤。

* [课程1：OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [课程2：Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [课程3：Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [课程4：ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [课程5：无线电探空仪追踪](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [课程6：RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [课程7：数据类型](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [课程8：自定义 GNU Radio 模块](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [课程9：TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [课程10：业余无线电考试](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [课程11：Wi-Fi 工具](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [课程12：创建可启动 USB](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [课程13：Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [课程14：吊扇](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## 路线图

* [ ] 增加更多硬件类型、RF 协议、信号参数和分析工具
* [ ] 支持更多操作系统
* [ ] 围绕 FISSURE 开发课程资料（RF 攻击、Wi-Fi、GNU Radio、PyQt 等）
* [ ] 创建信号调节器、特征提取器和信号分类器，并支持选择 AI/ML 技术
* [ ] 实现递归解调机制，以便从未知信号生成比特流
* [ ] 将 FISSURE 的主要组件迁移到通用传感器节点部署方案

## 贡献

我们非常欢迎提出改进 FISSURE 的建议。如果您对以下内容有任何想法，请在 [讨论](https://github.com/ainfosec/FISSURE/discussions) 页面或 Discord 服务器中留言：

* 新功能建议和设计变更
* 附有安装步骤的软件工具
* 新课程或现有课程的补充资料
* 感兴趣的 RF 协议
* 可供集成的更多硬件和 SDR 类型
* Python IQ 分析脚本
* 安装方面的修正与改进

改进 FISSURE 的贡献对加快其开发至关重要。我们非常感谢您所做的任何贡献。如果您想通过编写代码来贡献，请 fork 此 repo 并创建 pull request：

1. Fork 此项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 pull request

我们也欢迎通过创建 [Issue](https://github.com/ainfosec/FISSURE/issues) 来反馈 bug。

## 协作

请联系 Assured Information Security, Inc. (AIS) 的 Business Development 部门，提出并正式商定任何 FISSURE 协作机会——无论是投入时间集成您的软件、由 AIS 的专业人员为您的技术挑战开发解决方案，还是将 FISSURE 集成到其他平台/应用程序中。

## 许可证

GPL-3.0

许可证详情请参见 LICENSE 文件。

## 联系方式

加入 Discord 服务器：[https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

关注 Twitter：[@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## 致谢名单

我们感谢以下开发者：

[致谢名单](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 特别鸣谢

特别感谢 Samuel Mantravadi 博士和 Joseph Reith 对本项目作出的贡献。

## References

- [1] [FISSURE - RF 框架（GitHub）](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE 论文（GRCon22）](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE 文档 - 安装](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
