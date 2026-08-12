# Android 取证

{{#include ../banners/hacktricks-training.md}}

## 已锁定设备

优先选择能够保留设备状态的 acquisition 方法，并记录每项操作。如果设备已锁定，可用选项取决于型号、Android 版本、补丁级别，以及扣押前是否已配置访问权限。NIST 建议根据设备和检查授权选择相应的方法。<sup>[[1]](#references)</sup>

- 检查是否启用了 USB debugging，以及 acquisition 工作站是否已经过授权。ADB access 通常要求用户解锁设备并确认工作站的 RSA key。<sup>[[3]](#references)</sup>
- 根据适用的法律和程序规则，考虑 biometric access 是否仍然可用。
- **smudge attack** 可能通过屏幕上的残留痕迹揭示图形解锁模式，但后续触摸和清洁会降低其可靠性。<sup>[[2]](#references)</sup>
- 如果获得授权的工具支持确切的设备和软件构建版本，则可以尝试 PIN、密码或模式恢复或 brute force。硬件支持的凭据验证、重试延迟和擦除策略使这一过程高度依赖具体设备，因此不要将 iPhone 技术或结果替代为 Android 设备受支持的证据。<sup>[[1]](#references)</sup>

## 数据获取

在较旧的设备上，旧版 [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) 可能会生成一个 `.backup` 文件，Android Backup Extractor 可以将其解包：<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
不要假设这涵盖了每个应用。ADB 将该命令标记为 deprecated，并且 Android 12 会排除面向 API level 31 或更高版本的应用数据，除非该应用是 debuggable 的。<sup>[[4]](#references)</sup>

### Root 或物理 debug 访问

在 live device 上拥有 root 访问权限时，首先清点分区和挂载点；以下命令不直接适用于物理 JTAG acquisition。正确的 block device 取决于硬件，因此不要假设它始终是 `mmcblk0`。仅将经过验证的源制作镜像并保存到独立存储中：<sup>[[1]](#references)</sup>

JTAG acquisition 则使用设备的硬件测试访问接口和兼容的 acquisition 设备来读取可访问的内存。引脚布局、芯片组支持、设备状态，以及 volatile 和 non-volatile 目标之间的区别都因设备而异；记录硬件路径，并针对该型号使用经过验证的流程。<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
例如，如果分区清单确认 `/dev/block/mmcblk0` 是整个闪存设备，并且目标位置有足够空间，则原始采集命令变为：<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
这里，`df /data` 有助于将 `/data` 与其挂载的文件系统关联起来；但不应将其视为证明 `mmcblk0` 是正确的整个设备源，或证明 `4096` 是唯一有效的 `dd` 块大小。

对结果进行 Hash，并记录确切的命令、设备标识符、时间以及采集期间所做的任何更改。<sup>[[1]](#references)</sup>

### Memory

LiME 可以从 Linux 和某些 Android 设备获取物理内存，但其 kernel module 必须针对目标 kernel 构建，并以足够的权限加载。Module signing、kernel lockdown 以及现代 Android hardening 可能会阻止其加载。<sup>[[5]](#references)</sup>

该项目的 Android workflow 使用 ADB 推送匹配的 module、forward 一个 TCP port、从 root shell 加载 module，并在 examination host 上捕获数据流：<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME 也可以通过 `path=/sdcard/ram.lime` 将内容写入设备存储，但这会改变设备的存储内容，并且需要足够的可用空间。记录这一副作用，并对获取的镜像计算 hash。<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - 移动设备取证指南](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - 智能手机触摸屏上的 Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB 备份限制](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
