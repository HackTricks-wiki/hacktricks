# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## 锁定的设备

优先选择能够保留设备状态的 acquisition 方法，并记录每项操作。如果设备已锁定，可用选项取决于型号、Android 版本、补丁级别，以及扣押前是否已配置访问权限。NIST 建议根据设备和检查授权选择相应的方法。<sup>[[1]](#references)</sup>

- 检查是否已启用 USB debugging，以及 acquisition 工作站是否已获得授权。ADB access 通常要求用户解锁设备并确认工作站的 RSA key。<sup>[[3]](#references)</sup>
- 根据适用的法律和程序规则，考虑 biometric access 是否仍然可用。
- **smudge attack** 可能通过屏幕上的残留痕迹揭示图形解锁 pattern，但后续触摸和清洁会降低其可靠性。<sup>[[2]](#references)</sup>
- 仅在 commercial 或 research lock-bypass tooling 明确支持确切的设备和软件 build 时使用。

## 数据获取

在较旧的设备上，legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) 可能会生成一个 `.backup` 文件，Android Backup Extractor 可以将其解包：<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
不要假设这涵盖了所有应用。ADB 将该命令标记为 deprecated，而 Android 12 不会包含目标 API level 31 或更高版本的应用数据，除非该应用是 debuggable 的。<sup>[[4]](#references)</sup>

### Root 或物理调试访问

在 live device 上拥有 root access 时，首先清点分区和挂载点；以下命令不直接适用于物理 JTAG acquisition。正确的 block device 取决于硬件，因此不要假设它总是 `mmcblk0`。仅将经过验证的 source 镜像写入独立存储设备：<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
对结果进行 hash，并记录确切的命令、设备标识符、时间以及采集期间所做的任何更改。<sup>[[1]](#references)</sup>

### 内存

LiME 可以从 Linux 和部分 Android 设备获取物理内存，但其 kernel module 必须针对目标 kernel 构建，并以足够的权限加载。Module signing、kernel lockdown 以及现代 Android hardening 可能会阻止其加载。<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - 移动设备取证指南](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - 智能手机触摸屏上的 Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
