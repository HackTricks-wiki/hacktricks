# 基础取证方法论

{{#include ../../banners/hacktricks-training.md}}

## 创建和挂载镜像


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## 恶意软件分析

这**不一定是获得镜像后要执行的第一步**。但是，如果你有一个文件、文件系统镜像、内存镜像、pcap……就可以独立使用这些恶意软件分析技术，因此最好**牢记这些操作**：


{{#ref}}
malware-analysis.md
{{#endref}}

## 检查镜像

如果你获得了某个设备的**取证镜像**，就可以开始**分析所使用的分区和文件系统**，并**恢复**可能的**重要文件**（包括已删除的文件）。在以下页面中了解相关方法：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

根据所使用的操作系统甚至平台，应搜索不同的有趣工件：


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

## 深入检查特定文件类型和软件

如果你有一个非常**可疑的****文件**，那么**根据创建该文件的文件类型和软件**，一些**技巧**可能会有所帮助。\
阅读以下页面，了解一些有趣的技巧：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特别推荐以下页面：


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

请注意可能使用的反取证技术：


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 威胁狩猎


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
