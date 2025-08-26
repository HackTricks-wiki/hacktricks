# 基本取证方法论

{{#include ../../banners/hacktricks-training.md}}

## 创建和挂载镜像


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## 恶意软件分析

这**不一定是拿到镜像后首先要做的步骤**。但如果你有一个文件、文件系统镜像、内存镜像、pcap 等，你可以独立使用这些恶意软件分析技术，所以**记住这些操作很重要**：


{{#ref}}
malware-analysis.md
{{#endref}}

## 检查镜像

如果你被提供了设备的**取证镜像**，你可以开始**分析所使用的分区、文件系统**并**恢复**潜在的**重要文件**（甚至是已删除的）。在以下内容中了解如何：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# 基本取证方法论



## 创建和挂载镜像


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## 恶意软件分析

这**不一定是拿到镜像后首先要做的步骤**。但如果你有一个文件、文件系统镜像、内存镜像、pcap 等，你可以独立使用这些恶意软件分析技术，所以**记住这些操作很重要**：


{{#ref}}
malware-analysis.md
{{#endref}}

## 检查镜像

如果你被提供了设备的**取证镜像**，你可以开始**分析所使用的分区、文件系统**并**恢复**潜在的**重要文件**（甚至是已删除的）。在以下内容中了解如何：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

根据所用的操作系统（OSs）甚至平台，应该搜索不同的有趣痕迹：


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

## 针对特定文件类型和软件的深入检查

如果你有一个非常**可疑**的**文件**，那么**根据该文件的类型和生成它的软件**，一些**技巧**可能会很有用。\
阅读以下页面以了解一些有趣的技巧：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

我要特别提及页面：


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



## 针对特定文件类型和软件的深入检查

如果你有一个非常**可疑**的**文件**，那么**根据该文件的类型和生成它的软件**，一些**技巧**可能会很有用。\
阅读以下页面以了解一些有趣的技巧：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

我要特别提及页面：


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
