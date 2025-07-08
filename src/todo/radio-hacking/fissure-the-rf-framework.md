# FISSURE - The RF Framework

{{#include /banners/hacktricks-training.md}}

**频率独立的基于SDR的信号理解和逆向工程**

FISSURE是一个开源的RF和逆向工程框架，旨在适应所有技能水平，具有信号检测和分类、协议发现、攻击执行、IQ操控、漏洞分析、自动化和AI/ML的钩子。该框架旨在促进软件模块、无线电、协议、信号数据、脚本、流程图、参考材料和第三方工具的快速集成。FISSURE是一个工作流程启用器，将软件集中在一个位置，使团队能够轻松跟上进度，同时共享特定Linux发行版的相同经过验证的基线配置。

FISSURE包含的框架和工具旨在检测RF能量的存在，理解信号的特性，收集和分析样本，开发传输和/或注入技术，并制作自定义有效载荷或消息。FISSURE包含一个不断增长的协议和信号信息库，以协助识别、数据包制作和模糊测试。在线档案功能可以下载信号文件并构建播放列表，以模拟流量和测试系统。

友好的Python代码库和用户界面使初学者能够快速了解涉及RF和逆向工程的流行工具和技术。网络安全和工程领域的教育工作者可以利用内置材料或利用该框架展示他们自己的实际应用。开发人员和研究人员可以将FISSURE用于日常任务或向更广泛的受众展示他们的前沿解决方案。随着FISSURE在社区中的认知和使用的增长，其能力和所涵盖的技术范围也将扩大。

**附加信息**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 开始使用

**支持的**

FISSURE中有三个分支，以便于文件导航并减少代码冗余。Python2\_maint-3.7分支包含围绕Python2、PyQt4和GNU Radio 3.7构建的代码库；Python3\_maint-3.8分支围绕Python3、PyQt5和GNU Radio 3.8构建；Python3\_maint-3.10分支围绕Python3、PyQt5和GNU Radio 3.10构建。

|   操作系统   |   FISSURE分支   |
| :----------: | :------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**进行中（测试版）**

这些操作系统仍处于测试版状态。它们正在开发中，已知缺少多个功能。安装程序中的项目可能与现有程序冲突或在状态被移除之前无法安装。

|     操作系统     |    FISSURE分支   |
| :--------------: | :--------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

注意：某些软件工具并不适用于每个操作系统。请参阅 [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**安装**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
这将安装启动安装 GUI 所需的 PyQt 软件依赖项（如果未找到）。

接下来，选择最符合您操作系统的选项（如果您的操作系统与选项匹配，则应自动检测）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

建议在干净的操作系统上安装 FISSURE，以避免现有的冲突。选择所有推荐的复选框（默认按钮），以避免在操作 FISSURE 内的各种工具时出现错误。安装过程中会有多个提示，主要询问提升权限和用户名。如果某个项目在末尾包含“验证”部分，安装程序将运行后面的命令，并根据命令是否产生错误将复选框项目高亮显示为绿色或红色。没有“验证”部分的已选项目在安装后将保持黑色。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用方法**

打开终端并输入：
```
fissure
```
参考FISSURE帮助菜单以获取更多使用细节。

## 细节

**组件**

* 仪表板
* 中心枢纽 (HIPRFISR)
* 目标信号识别 (TSI)
* 协议发现 (PD)
* 流图与脚本执行器 (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**功能**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**信号检测器**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ操控**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**信号查找**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**模式识别**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**攻击**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**模糊测试**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**信号播放列表**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**图像库**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**数据包构造**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy集成**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC计算器**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**日志记录**_            |

**硬件**

以下是具有不同集成级别的“支持”硬件列表：

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11适配器
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## 课程

FISSURE附带了几本有用的指南，以帮助熟悉不同的技术和技巧。许多指南包括使用集成到FISSURE中的各种工具的步骤。

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua解码器](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: 声音交换](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP板](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde跟踪](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: 数据类型](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: 自定义GNU Radio模块](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: 无线电考试](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi工具](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## 路线图

* [ ] 添加更多硬件类型、RF协议、信号参数、分析工具
* [ ] 支持更多操作系统
* [ ] 开发围绕FISSURE的课程材料（RF攻击、Wi-Fi、GNU Radio、PyQt等）
* [ ] 创建信号调节器、特征提取器和信号分类器，支持可选择的AI/ML技术
* [ ] 实现递归解调机制，以从未知信号生成比特流
* [ ] 将主要FISSURE组件过渡到通用传感器节点部署方案

## 贡献

强烈鼓励对FISSURE的改进建议。如果您对以下内容有任何想法，请在[讨论](https://github.com/ainfosec/FISSURE/discussions)页面或Discord服务器上留言：

* 新功能建议和设计变更
* 带有安装步骤的软件工具
* 新课程或现有课程的附加材料
* 感兴趣的RF协议
* 更多硬件和SDR类型以供集成
* Python中的IQ分析脚本
* 安装修正和改进

对FISSURE的贡献对于加速其开发至关重要。您所做的任何贡献都将受到高度赞赏。如果您希望通过代码开发进行贡献，请先fork该仓库并创建一个pull请求：

1. Fork项目
2. 创建您的功能分支（`git checkout -b feature/AmazingFeature`）
3. 提交您的更改（`git commit -m 'Add some AmazingFeature'`）
4. 推送到分支（`git push origin feature/AmazingFeature`）
5. 打开一个pull请求

创建[问题](https://github.com/ainfosec/FISSURE/issues)以引起对错误的关注也是受欢迎的。

## 合作

联系Assured Information Security, Inc. (AIS)商业发展部门，提出并正式化任何FISSURE合作机会——无论是通过投入时间集成您的软件，还是让AIS的优秀人才为您的技术挑战开发解决方案，或将FISSURE集成到其他平台/应用程序中。

## 许可证

GPL-3.0

有关许可证的详细信息，请参见LICENSE文件。

## 联系

加入Discord服务器：[https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

在Twitter上关注：[ @FissureRF](https://twitter.com/fissurerf), [ @AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

商业发展 - Assured Information Security, Inc. - bd@ainfosec.com

## 贡献者

我们感谢这些开发者：

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 致谢

特别感谢Dr. Samuel Mantravadi和Joseph Reith对本项目的贡献。



{{#include /banners/hacktricks-training.md}}
