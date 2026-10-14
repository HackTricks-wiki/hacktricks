# Android 取证

{{#include ../../banners/hacktricks-training.md}}

## 锁定的设备

优先选择能保留设备状态的采集方法，并记录每一步操作。如果设备已锁定，可用选项取决于设备型号、Android 版本、补丁级别，以及扣押前是否已配置相关访问方式。NIST 建议根据设备情况和检查授权选择方法。<sup>[[1]](#references)</sup>

- 检查是否已启用 USB debugging，以及采集工作站是否已获授权。ADB 访问通常要求用户先解锁设备，并确认工作站的 RSA 密钥。<sup>[[3]](#references)</sup>
- 根据适用的法律和程序规则，考虑是否仍可使用生物识别方式解锁。
- **smudge attack** 可能通过屏幕上的残留痕迹推断图形解锁图案，但之后的触摸和清洁操作会降低其可靠性。<sup>[[2]](#references)</sup>
- 如果经授权的工具支持确切的设备型号和软件版本，可能可以尝试恢复或暴力破解 PIN、密码或图案。硬件支持的凭据验证、重试延迟和擦除策略使此方法高度依赖具体设备，因此不要用 iPhone 技术或结果来证明某台 Android 设备受支持。<sup>[[1]](#references)</sup>

## 数据采集

在较旧的设备上，旧版 [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) 可能会生成 `.backup` 文件，可使用 Android Backup Extractor 解包：<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

不要假定这会捕获所有应用。ADB 将此命令标记为已弃用；Android 12 不会包含面向 API level 31 或更高版本的应用数据，除非该应用可调试。<sup>[[4]](#references)</sup>

### Root 或物理调试访问

在已启动的设备上拥有 root 访问权限时，先清点分区和挂载点；以下命令不能直接用于物理 JTAG 获取。正确的块设备取决于硬件，因此不要假定它总是 `mmcblk0`。仅将已验证的源映像写入独立存储设备：<sup>[[1]](#references)</sup>

JTAG 获取则使用设备的硬件测试访问接口和兼容的获取设备来读取可访问的内存。引脚布局、芯片组支持、设备状态，以及易失性目标与非易失性目标之间的区别都因设备而异；记录硬件连接路径，并针对该型号使用经过验证的流程。<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

例如，如果分区清单确认 `/dev/block/mmcblk0` 是整个闪存设备，且目标位置有足够空间，那么原始采集命令就变为：<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

这里，`df /data` 有助于确认 `/data` 所属的已挂载文件系统；不应将其视为 `mmcblk0` 是正确的整块设备源的证明，也不应认为 `4096` 是唯一有效的 `dd` 块大小。

对结果进行哈希，并记录确切命令、设备标识符、时间以及采集期间所做的任何更改。<sup>[[1]](#references)</sup>

### 内存

LiME 可以从 Linux 和部分 Android 设备获取物理内存，但其内核模块必须针对目标内核构建，并以足够的权限加载。模块签名、内核锁定以及现代 Android 加固措施可能会阻止其加载。<sup>[[5]](#references)</sup>

该项目的 Android 工作流程是通过 ADB 推送匹配的模块、转发 TCP 端口、从 root shell 加载模块，并在检查主机上捕获数据流：<sup>[[5]](#references)</sup>

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

LiME 也可以改为写入设备存储，使用 `path=/sdcard/ram.lime`，但这会更改设备存储，并且需要有足够的可用空间。记录这一副作用，并对获取的映像进行哈希。<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - 移动设备取证指南](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - 智能手机触摸屏上的 Smudge 攻击](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB 备份限制](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux 内存提取器 (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android 备份提取器](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
