# 基本取证方法

{{#include ../../banners/hacktricks-training.md}}

## 创建和挂载镜像


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## 恶意软件分析

**获取镜像后，这不一定是要执行的第一步**。但如果你有文件、文件系统镜像、内存镜像、pcap 等，也可以独立使用这些恶意软件分析技术，因此最好**记住这些操作**：


{{#ref}}
malware-analysis.md
{{#endref}}

## 检查镜像

如果你拿到某台设备的**取证镜像**，可以开始**分析其分区和文件系统**，并**恢复**可能**有价值的文件**（包括已删除的文件）。了解方法请参阅：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

根据使用的操作系统甚至平台，应该查找不同的有趣 artifacts：


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

有关已锁定 Android 设备、数据获取途径和内存成像，请参阅 [Android forensics](android-forensics.md)。

## 深入检查特定文件类型和软件

如果你有非常**可疑的** **文件**，那么根据**文件类型和创建该文件的软件**，一些**技巧**可能会有用。\
阅读以下页面，了解一些有趣的技巧：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特别推荐这个页面：


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

请牢记可能会使用反取证技术：


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 威胁狩猎


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
