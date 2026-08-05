# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**基于 Frequency Independent SDR 的信号理解与 Reverse Engineering**

FISSURE 是一个开源 RF 和 reverse engineering framework，面向所有技能水平的用户，并支持信号检测与分类、协议发现、attack execution、IQ manipulation、vulnerability analysis、automation 以及 AI/ML。该 framework 旨在促进 software modules、radios、protocols、signal data、scripts、flow graphs、reference material 和 third-party tools 的快速集成。FISSURE 是一个 workflow enabler，可将软件集中在同一位置，并让团队通过共享针对特定 Linux distributions 验证过的 baseline configuration，轻松快速上手。<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE 中包含的 framework 和 tools 可用于检测 RF energy 的存在、了解信号特征、采集和分析 samples、开发 transmit 和/或 injection techniques，以及构造 custom payloads 或 messages。FISSURE 包含不断增长的 protocol 和 signal information library，可协助进行识别、packet crafting 和 fuzzing。它还具备 online archive 功能，可下载 signal files 并构建 playlists，以模拟 traffic 和测试 systems。

友好的 Python codebase 和 user interface 使 beginners 能够快速了解 RF 和 reverse engineering 中涉及的 popular tools 和 techniques。网络安全和工程领域的 educators 可以利用内置 material，或使用该 framework 演示自己的 real-world applications。Developers 和 researchers 可以将 FISSURE 用于日常任务，或向更广泛的 audience 展示其 cutting-edge solutions。随着社区对 FISSURE 的认知和使用不断增长，其 capabilities 的范围以及所涵盖 technology 的广度也将不断扩大。

**Additional Information**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

FISSURE 中有三个 branches，可使 file navigation 更加便捷并减少 code redundancy。Python2\_maint-3.7 branch 的 codebase 基于 Python2、PyQt4 和 GNU Radio 3.7 构建；Python3\_maint-3.8 branch 基于 Python3、PyQt5 和 GNU Radio 3.8 构建；Python3\_maint-3.10 branch 基于 Python3、PyQt5 和 GNU Radio 3.10 构建。

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In-Progress (beta)**

这些 operating systems 目前仍处于 beta status。它们正在开发中，且已知有多个 features 缺失。在移除该 status 之前，installer 中的项目可能会与现有 programs 冲突，或无法完成安装。

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Note: 某些 software tools 并不适用于所有 OS。请参阅 [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
这将安装启动安装 GUI 所需的 PyQt 软件依赖（如果尚未找到这些依赖）。

接下来，选择最符合你操作系统的选项（如果你的操作系统与某个选项匹配，应会自动检测到）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

建议在干净的操作系统上安装 FISSURE，以避免现有冲突。选择所有推荐的复选框（“Default”按钮），以避免在 FISSURE 中运行各种工具时出现错误。整个安装过程中会出现多个提示，主要用于请求提升权限和用户名。如果某个项目末尾包含“Verify”部分，安装程序将运行其后的命令，并根据该命令是否产生错误，将复选框项目突出显示为绿色或红色。没有“Verify”部分但已选中的项目，在安装完成后将保持黑色。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用**

打开终端并输入：
```
fissure
```
有关使用详情，请参阅 FISSURE 的 Help 菜单。

## 详细信息

**组件**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![组件](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**功能**

| ![Signal Detector 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging 图标](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**硬件**

以下是不同集成程度的“支持”硬件列表：

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## 课程

FISSURE 提供了多份实用指南，帮助用户熟悉不同的技术和技巧。其中许多指南都包含使用 FISSURE 集成的各种工具的步骤。

* [课程 1：OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [课程 2：Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [课程 3：Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [课程 4：ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [课程 5：Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [课程 6：RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [课程 7：Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [课程 8：Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [课程 9：TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [课程 10：Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [课程 11：Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## 路线图

* [ ] 添加更多硬件类型、RF protocols、signal parameters 和 analysis tools
* [ ] 支持更多 operating systems
* [ ] 围绕 FISSURE 开发课程材料（RF Attacks、Wi-Fi、GNU Radio、PyQt 等）
* [ ] 使用可选择的 AI/ML 技术创建 signal conditioner、feature extractor 和 signal classifier
* [ ] 实现 recursive demodulation mechanisms，从未知信号生成 bitstream
* [ ] 将主要 FISSURE 组件迁移到通用 sensor node deployment scheme

## 贡献

我们非常欢迎关于改进 FISSURE 的建议。如果你对以下内容有任何想法，请在 [Discussions](https://github.com/ainfosec/FISSURE/discussions) 页面或 Discord Server 中留言：

* 新功能建议和设计变更
* 包含安装步骤的软件工具
* 新课程或现有课程的补充材料
* 感兴趣的 RF protocols
* 用于集成的更多硬件和 SDR 类型
* 使用 Python 编写的 IQ analysis scripts
* 安装更正和改进

帮助改进 FISSURE 的贡献对于加快其开发至关重要。非常感谢你做出的任何贡献。如果你希望通过代码开发参与贡献，请 fork repo 并创建 pull request：

1. Fork project
2. 创建 feature branch (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. Push 到 branch (`git push origin feature/AmazingFeature`)
5. Open pull request

我们也欢迎创建 [Issues](https://github.com/ainfosec/FISSURE/issues) 来报告 bug。

## 协作

请联系 Assured Information Security, Inc. (AIS) 的 Business Development，提出并正式确定任何 FISSURE collaboration opportunities——无论是投入时间集成你的 software、由 AIS 的专业人员为你的 technical challenges 开发解决方案，还是将 FISSURE 集成到其他 platforms/applications 中。

## 许可证

GPL-3.0

有关许可证详情，请参阅 LICENSE file。

## 联系方式

加入 Discord Server：[https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

在 Twitter 上关注：[﻿@FissureRF](https://twitter.com/fissurerf)、[﻿@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## 致谢名单

我们向以下开发者表示感谢：

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 鸣谢

特别感谢 Dr. Samuel Mantravadi 和 Joseph Reith 对本项目做出的贡献。

## 参考资料

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
