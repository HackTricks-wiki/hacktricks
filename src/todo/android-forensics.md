# Android 取证

{{#include ../banners/hacktricks-training.md}}

## 已锁定设备

要开始从 Android 设备中提取数据，必须先将其解锁。如果设备处于锁定状态，可以：

- 检查设备是否已启用 USB 调试。
- 检查是否存在可能的 [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- 尝试使用 [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## 数据获取

使用 [adb 创建 Android 备份](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup)，然后使用 [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) 提取：`java -jar abe.jar unpack file.backup file.tar`

### 如果具有 root 访问权限或已连接到 JTAG 接口

- `cat /proc/partitions`（查找 flash memory 的路径，通常第一项是 _mmcblk0_，对应整个 flash memory）。
- `df /data`（确定系统的 block size）。
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（使用从 block size 获取的信息执行）。

### 内存

使用 Linux Memory Extractor（LiME）提取 RAM 信息。这是一个应通过 adb 加载的 kernel extension。

## 参考

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
