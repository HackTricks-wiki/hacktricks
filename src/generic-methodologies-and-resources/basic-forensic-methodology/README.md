# 基础取证方法论

## 创建和挂载镜像


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

这**不一定是获取镜像后要执行的第一步**。但如果你有一个文件、文件系统镜像、内存镜像、pcap……则可以独立使用这些 malware analysis 技术，因此最好**牢记这些操作**：


{{#ref}}
malware-analysis.md
{{#endref}}

## 检查镜像

如果你获得了某个设备的**取证镜像**，可以开始**分析分区和所使用的文件系统**，并**恢复**可能的**有趣文件**（包括已删除的文件）。请在以下页面中了解具体方法：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

根据所使用的 OS，甚至平台的不同，应搜索不同的有趣 artifacts：


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

如果你有一个非常**可疑的****文件**，那么**根据文件类型和创建该文件的软件**，一些**技巧**可能会很有用。\
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

请牢记可能使用反取证技术的情况：


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 威胁搜寻


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
