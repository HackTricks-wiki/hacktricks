# 内存转储分析

{{#include ../../../banners/hacktricks-training.md}}

## 开始

开始在 pcap 中**搜索** **malware**。使用 [**Malware Analysis**](../malware-analysis.md) 中提到的**工具**。

## [Volatility](volatility-cheatsheet.md)

**Volatility 是用于内存转储分析的主要开源框架**。这个 Python 工具会分析来自外部源或 VMware VM 的转储，并根据转储的 OS profile 识别进程和密码等数据。它支持通过 plugins 进行扩展，因此在 forensic investigations 中具有很高的通用性。

[**在此查找 cheatsheet**](volatility-cheatsheet.md)

## Mini dump crash report

当转储很小（只有几 KB，可能几 MB）时，它很可能是 mini dump crash report，而不是内存转储。

![Volatility - Mini dump crash report：当转储很小时（只有几 KB，可能几 MB），它很可能是 mini dump crash report，而不是内存转储](<../../../images/image (532).png>)

如果已安装 Visual Studio，可以打开此文件并获取一些基本信息，例如进程名称、架构、异常信息以及正在执行的模块：

![Volatility - Mini dump crash report：如果已安装 Visual Studio，可以打开此文件并获取一些基本信息，例如进程名称、架构、异常信息以及……](<../../../images/image (263).png>)

你也可以加载异常并查看反编译后的指令

![Volatility - Mini dump crash report：你也可以加载异常并查看反编译后的指令](<../../../images/image (142).png>)

![Volatility - Mini dump crash report：你也可以加载异常并查看反编译后的指令](<../../../images/image (610).png>)

不过，Visual Studio 并不是执行深度转储分析的最佳工具。

你应该使用 **IDA** 或 **Radare** **打开**它，以便对其进行**深度**检查。

{{#include ../../../banners/hacktricks-training.md}}
