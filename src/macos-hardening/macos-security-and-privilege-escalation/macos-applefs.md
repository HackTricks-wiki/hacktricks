# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple 专有文件系统（APFS）

**Apple File System (APFS)** 是一种现代文件系统，旨在取代 Hierarchical File System Plus (HFS+)。其开发源于对**更高性能、更强安全性和更高效率**的需求。

APFS 的一些显著特性包括：<sup>[[1]](#references)</sup>

1. **空间共享**：APFS 允许多个卷在单个物理设备上**共享底层可用存储空间**。这使空间利用更加高效，因为这些卷可以动态扩展和缩小，无需手动调整大小或重新分区。
1. 与磁盘文件中的传统分区相比，这意味着 **APFS 中的不同分区（卷）共享整个磁盘空间**，而常规分区通常具有固定大小。
2. **快照**：APFS 支持**创建快照**，这些快照是文件系统在特定时间点的**只读**实例。快照能够实现高效备份和便捷的系统回滚，因为它们只占用极少的额外存储空间，并且可以快速创建或还原。
3. **克隆**：APFS 可以**创建与原始文件或目录共享相同存储空间的文件或目录克隆**，直到克隆或原始文件被修改。此功能可以高效地创建文件或目录副本，而无需复制存储空间。
4. **加密**：APFS **原生支持全磁盘加密**以及按文件和按目录加密，从而增强不同使用场景下的数据安全性。
5. **崩溃保护**：APFS 使用**写时复制元数据机制，确保文件系统的一致性**，即使发生突然断电或系统崩溃，也能降低数据损坏的风险。

总体而言，APFS 为 Apple 设备提供了更加现代、灵活和高效的文件系统，重点提升了性能、可靠性和安全性。
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 卷挂载在 **`/System/Volumes/Data`**（可以使用 `diskutil apfs list` 检查）。

Firmlinks 列表可以在 **`/usr/share/firmlinks`** 文件中找到。
```bash

```
## References

- [1] [APFS Guide - Features - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
