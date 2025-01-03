# 内存转储分析

{{#include ../../../banners/hacktricks-training.md}}

## 开始

开始**搜索**pcap中的**恶意软件**。使用在[**恶意软件分析**](../malware-analysis.md)中提到的**工具**。

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility是内存转储分析的主要开源框架**。这个Python工具分析来自外部源或VMware虚拟机的转储，基于转储的操作系统配置文件识别数据，如进程和密码。它可以通过插件扩展，使其在取证调查中非常灵活。

**[在这里找到备忘单](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## 小型转储崩溃报告

当转储很小（只有几KB，也许几MB）时，它可能是小型转储崩溃报告，而不是内存转储。

![](<../../../images/image (216).png>)

如果您安装了Visual Studio，可以打开此文件并绑定一些基本信息，如进程名称、架构、异常信息和正在执行的模块：

![](<../../../images/image (217).png>)

您还可以加载异常并查看反编译的指令

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

无论如何，Visual Studio并不是执行转储深度分析的最佳工具。

您应该使用**IDA**或**Radare**来**深入**检查它。

​

{{#include ../../../banners/hacktricks-training.md}}
