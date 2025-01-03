# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## 锁定设备

要开始从 Android 设备提取数据，设备必须解锁。如果设备被锁定，您可以：

- 检查设备是否启用了 USB 调试。
- 检查是否存在可能的 [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- 尝试使用 [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## 数据获取

创建一个 [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) 并使用 [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) 提取： `java -jar abe.jar unpack file.backup file.tar`

### 如果有 root 访问或物理连接到 JTAG 接口

- `cat /proc/partitions` （搜索闪存的路径，通常第一个条目是 _mmcblk0_，对应整个闪存）。
- `df /data` （发现系统的块大小）。
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 （使用从块大小收集的信息执行）。

### 内存

使用 Linux Memory Extractor (LiME) 提取 RAM 信息。这是一个应该通过 adb 加载的内核扩展。

{{#include ../banners/hacktricks-training.md}}
