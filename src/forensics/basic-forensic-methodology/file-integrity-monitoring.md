{{#include ../../banners/hacktricks-training.md}}

# 基线

基线是对系统某些部分进行快照，以**与未来状态进行比较以突出变化**。

例如，您可以计算并存储文件系统中每个文件的哈希值，以便找出哪些文件被修改。\
这也可以应用于创建的用户帐户、正在运行的进程、正在运行的服务以及任何其他不应有太大变化的内容。

## 文件完整性监控

文件完整性监控（FIM）是一种关键的安全技术，通过跟踪文件的变化来保护IT环境和数据。它涉及两个关键步骤：

1. **基线比较：** 使用文件属性或加密校验和（如MD5或SHA-2）建立基线，以便进行未来的比较以检测修改。
2. **实时变更通知：** 当文件被访问或更改时，立即获得警报，通常通过操作系统内核扩展实现。

## 工具

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## 参考

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
