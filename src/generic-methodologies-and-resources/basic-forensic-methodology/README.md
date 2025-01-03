# 基本取证方法论

{{#include ../../banners/hacktricks-training.md}}

## 创建和挂载镜像

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## 恶意软件分析

这**并不是在获得镜像后必须执行的第一步**。但是如果你有一个文件、文件系统镜像、内存镜像、pcap...你可以独立使用这些恶意软件分析技术，因此**记住这些操作是很好的**：

{{#ref}}
malware-analysis.md
{{#endref}}

## 检查镜像

如果你获得了设备的**取证镜像**，你可以开始**分析分区、文件系统**并**恢复**潜在的**有趣文件**（甚至是已删除的文件）。了解如何进行：

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

根据使用的操作系统甚至平台，应该搜索不同的有趣文物：

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## 深入检查特定文件类型和软件

如果你有非常**可疑的****文件**，那么**根据文件类型和创建它的软件**，可能会有几种**技巧**是有用的。\
阅读以下页面以了解一些有趣的技巧：

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

我想特别提到以下页面：

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## 内存转储检查

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap 检查

{{#ref}}
pcap-inspection/
{{#endref}}

## **反取证技术**

请记住可能使用反取证技术：

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 威胁狩猎

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
