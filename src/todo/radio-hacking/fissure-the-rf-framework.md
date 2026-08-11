# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**基于 Frequency Independent SDR 的信号理解与 Reverse Engineering**

FISSURE 是一个开源 RF 和 reverse engineering framework，面向所有技能水平的用户，并支持信号检测与分类、协议发现、攻击执行、IQ 操作、漏洞分析、自动化以及 AI/ML。该 framework 旨在促进软件模块、radio、协议、信号数据、脚本、flow graph、参考资料和第三方工具的快速集成。FISSURE 是一个 workflow enabler，将软件集中在同一位置，使团队能够在共享同一套针对特定 Linux distributions 验证过的基线配置时，轻松快速上手。<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE 中包含的 framework 和工具用于检测 RF 能量、分析信号特征、采集与分析 samples、开发传输或注入技术，以及构造自定义 payload 或消息。FISSURE 还提供用于识别、packet crafting 和 fuzzing 的协议与信号信息，以及用于 traffic simulation 和测试的 archive 与 playlist。<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase 和 graphical interface 可帮助初学者学习 RF 与 reverse-engineering 工具。教育工作者可以使用内置 lessons，开发者和研究人员则可以集成自己的 modules 和 workflows。当前版本还支持分布式 sensor nodes、TAK integration、geolocation workflows，以及按角色划分的 Apptainer deployments。<sup>[[1]](#references)[[3]](#references)</sup>

**附加信息**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 开始使用

**已支持**

当前 FISSURE 使用 **`Python3`** branch 进行 active development，支持 PyQt5 以及 GNU Radio 3.8 或 3.10。已弃用的 **`Python2_maint-3.7`** branch 仍可用于较旧的 operating systems，以及需要 GNU Radio 3.7 的第三方工具。之前的 `Python3_maint-3.8` 和 `Python3_maint-3.10` branch 名称仅为历史名称；GNU Radio maintenance selection 现在由 `Python3` branch 处理。<sup>[[1]](#references)[[3]](#references)</sup>

| 操作系统 | FISSURE Branch | 默认 GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | 使用受支持的 Linux 版本 | 使用匹配的版本 |

**进行中（beta）**

这些 operating systems 仍处于 beta 状态，正在开发中，且已知有多个功能缺失。在移除该状态之前，installer 中的项目可能会与现有程序冲突，或无法安装。

| 操作系统 | FISSURE Branch | 默认 GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

某些第三方工具无法在所有 OS 上运行。安装前请查看当前的 [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) 文档。<sup>[[3]](#references)</sup>

**安装**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
子模块步骤会下载 FISSURE 使用的 GNU Radio out-of-tree modules，安装这些模块时必须执行此步骤。安装程序还会安装启动其安装 GUI 所需的缺失 PyQt 依赖项。<sup>[[3]](#references)</sup>

接下来，选择最符合你操作系统的选项（如果你的操作系统与某个选项匹配，系统应会自动检测）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

建议在干净的操作系统上安装 FISSURE，以避免现有冲突。选中所有建议的复选框（Default 按钮），以避免在操作 FISSURE 中的各种工具时出现错误。安装过程中会出现多个提示，其中大多数会要求提升权限和输入用户名。如果某个项目末尾包含“Verify”部分，安装程序将运行其后的命令，并根据该命令是否产生错误，将复选框项目标记为绿色或红色。没有“Verify”部分的已选项目在安装完成后将保持黑色。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用方法**

打开终端并输入：
```
fissure
```
如需了解更多用法，请参考 FISSURE Help 菜单。

## 详情

**组件**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**功能**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**硬件**

以下硬件已以不同程度集成到 FISSURE 中：<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## 课程

FISSURE 提供了多个实用指南，帮助用户熟悉不同的技术和技巧。其中许多指南包含使用已集成到 FISSURE 中的各种工具的步骤。

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lesson12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lesson13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lesson14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## 路线图

* [ ] 添加更多硬件类型、RF 协议、信号参数和分析工具
* [ ] 支持更多操作系统
* [ ] 围绕 FISSURE 开发课程材料（RF Attacks、Wi-Fi、GNU Radio、PyQt 等）
* [ ] 使用可选的 AI/ML 技术创建信号调节器、特征提取器和信号分类器
* [ ] 实现递归解调机制，从未知信号生成 bitstream
* [ ] 将主要 FISSURE 组件迁移到通用传感器节点部署方案

## 贡献

我们非常欢迎有关改进 FISSURE 的建议。如果你对以下内容有任何想法，请在 [Discussions](https://github.com/ainfosec/FISSURE/discussions) 页面或 Discord Server 中留言：

* 新功能建议和设计变更
* 包含安装步骤的软件工具
* 新课程或现有课程的补充材料
* 感兴趣的 RF 协议
* 更多用于集成的硬件和 SDR 类型
* 使用 Python 编写的 IQ 分析脚本
* 安装修正和改进

改进 FISSURE 的贡献对于加快其开发至关重要。非常感谢你所做的任何贡献。如果你希望通过代码开发参与，请 fork 此 repo 并创建 pull request：

1. Fork 此项目
2. 创建 feature branch（`git checkout -b feature/AmazingFeature`）
3. Commit 你的更改（`git commit -m 'Add some AmazingFeature'`）
4. Push 到该 branch（`git push origin feature/AmazingFeature`）
5. Open pull request

我们也欢迎通过创建 [Issues](https://github.com/ainfosec/FISSURE/issues) 来报告 bug。

## 合作

请联系 Assured Information Security, Inc. (AIS) Business Development，以提出并正式确定任何 FISSURE 合作机会——无论是投入时间集成你的软件、由 AIS 的专业人员为你的技术挑战开发解决方案，还是将 FISSURE 集成到其他平台/应用程序中。

## 许可证

GPL-3.0

有关许可证的详细信息，请参阅 LICENSE 文件。

## 联系方式

加入 Discord Server：[https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

在 Twitter 上关注：[ @FissureRF](https://twitter.com/fissurerf)、[ @AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## 致谢名单

我们向以下开发人员表示感谢：

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 鸣谢

特别感谢 Dr. Samuel Mantravadi 和 Joseph Reith 对本项目所做的贡献。

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
