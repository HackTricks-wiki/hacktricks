# 内存转储分析

## 开始

开始在 pcap 中**搜索** **malware**。使用 [**Malware Analysis**](../malware-analysis.md) 中提到的**工具**。

## [Volatility](volatility-cheatsheet.md)

**Volatility 是一个用于内存转储分析的开源框架**。这个 Python 工具会分析来自外部源或 VMware VM 的转储，并根据转储的操作系统配置文件识别进程、密码等数据。它支持通过插件进行扩展，因此非常适合取证调查。<sup>[[1]](#references)[[2]](#references)</sup>

[**在此处查找 cheatsheet**](volatility-cheatsheet.md)

## Mini dump 崩溃报告

当转储文件很小（只有几 KB，可能几 MB）时，它可能是 Mini dump 崩溃报告，而不是完整的内存转储。<sup>[[3]](#references)</sup>

![Volatility - Mini dump 崩溃报告：一个被识别为 Mini DuMP 崩溃报告的小型转储文件](<../../../images/image (532).png>)

如果已安装 Visual Studio，可以打开此文件以查看进程名称、架构、异常详情和已加载模块等基本信息：<sup>[[4]](#references)</sup>

![Volatility - Mini dump 崩溃报告：如果已安装 Visual Studio，可以打开此文件并获取进程名称、架构、异常信息等基本信息](<../../../images/image (263).png>)

还可以检查异常并查看模块的反汇编代码。<sup>[[4]](#references)</sup>

![Visual Studio minidump 操作面板，其中包含本机调试和设置符号路径的选项](<../../../images/image (142).png>)

![Visual Studio 对 minidump 异常中指令的反汇编](<../../../images/image (610).png>)

无论如何，Visual Studio 并不是执行深度转储分析的最佳工具。

应该使用 **IDA** 或 **Radare** 打开它，以便对其进行**深入**检查。

## References

- [1] [Volatility 框架](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility 使用方法](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump 文件](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [在 Visual Studio 调试器中使用转储文件](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
