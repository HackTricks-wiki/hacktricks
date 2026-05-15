# 有趣的 Windows Registry 键

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives 是从 _发生了什么？_ 快速转到 _哪个用户、何时、从哪里？_ 的最快方式之一。对于在线分析，优先使用 `CurrentControlSet`；对于离线 hive 分析，先解析实际激活的是哪个 `ControlSet00x`，不要硬编码 `ControlSet001`。

### Windows 版本和所有者信息

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build、安装时间、注册所有者、产品名称以及其他 build 元数据。
- `SYSTEM\Select`: 将 `Current`、`Default` 和 `LastKnownGood` 映射到系统实际使用的 `ControlSet00x` 值。

### 计算机名

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 当前主机名。

### 时区设置

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 配置的时区以及与 DST 相关的值。

### 访问时间跟踪

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` 表示是否正在更新 NTFS 的最后访问时间戳。
- 要启用它，使用：`fsutil behavior set disablelastaccess 0`

### 关机详情

- `SYSTEM\CurrentControlSet\Control\Windows`: 上次关机时间。
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: 较旧的系统也可能暴露关机计数器。

### 网络配置

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: 接口 IP、DHCP lease、网关和 DNS 数据。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: 网络配置文件名称/SSID 以及首次和最后一次连接时间。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 和 `...\Unmanaged\{GUID}`: 配置文件关联数据，例如网关 MAC 地址和 DNS 后缀。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: 主机发布的本地共享文件夹。

### 远程访问和网络共享历史

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: 出站 RDP MRU 列表（`MRU0`..`MRU9`）。
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: 按主机保存的出站 RDP 历史。子键通常存储 `UsernameHint`，且键的 `LastWrite` 时间很适合作为 pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 映射的网络驱动器、UNC 共享以及与特定用户关联的可移动介质挂载点。

### 自动启动程序和计划持久化

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 和 `...\Tasks\{GUID}`: 计划任务元数据。如果这里存在任务，但 `Tree\<TaskName>` 中缺少 `SD` 值，怀疑是隐藏的 Tarrask-style 任务篡改，并将其与 `C:\Windows\System32\Tasks\<TaskName>` 关联分析。

### 搜索、键入路径和 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer 搜索词。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: 手动输入的 Explorer 路径。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 最近 26 条 `Win + R` 命令。`MRUList` 保留它们的顺序。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 最近打开的文档和文件夹。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office 最近文件。

### 用户活动跟踪

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI 驱动的执行历史。值名使用 ROT13 编码，二进制数据包含运行计数和上次运行时间。
- 将 `UserAssist` 视为强辅助证据，而不是独立结论：它主要跟踪通过 Explorer 启动的应用或 `.lnk` 文件，可能漏掉命令行或服务执行。在 Windows 10+ 上，某些条目并不一定意味着进程完全运行过。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 和 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: 现代 Windows 10/11 的执行痕迹，带有 SID 归属和最后执行时间。它们对本地执行的二进制文件尤其有用，但旧条目会很快过期，来自网络共享/可移动介质的执行也不太可靠。
- 对于更广泛的执行工件，例如 Prefetch、Amcache、ShimCache 和 SRUM，参见主 [Windows forensics overview](README.md#programs-executed)。

### Shellbags

- Shellbags 存储在 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 以及 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 中。
- `NTUSER.DAT` 条目对 UNC/网络浏览尤其有用，而 `UsrClass.dat` 通常是 Windows Vista+ 存储本地/可移动文件夹 shellbags 的位置。
- 即使文件夹已被删除，它们仍可显示文件夹存在、遍历情况和文件夹视图偏好。对归档文件的类 Explorer 访问也可能留下 shellbag 痕迹。
- 并非每个 shellbag 都能证明文件夹被成功访问，因此应结合 LNK、Jump Lists、时间戳或卷映射进行交叉验证。
- 使用 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 或 **SBECmd** 进行解析。

### USB 信息

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB 大容量存储设备的主要清单（vendor、product、revision、serial/device instance）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: 更广泛的 USB 设备清单，包括非存储设备。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: 在较新的 Windows 10/11 build 上，这是一个高价值位置，可获取按设备生命周期时间戳，例如安装、首次安装、最后到达和最后移除。
- `HKLM\SYSTEM\MountedDevices`: 将卷和设备标识符映射到盘符 / volume GUID。某个盘符可能只保留最后一次映射。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: 对 volume serial number 和之前的介质元数据很有用。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 用户级的盘符和共享交互历史。
- 通过 MTP/PTP 连接的现代手机和平板可能**不会**出现在 `USBSTOR` 下。也要检查 `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` 和 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`。
- 要将设备与用户关联起来，可从设备或卷标识符 pivot 到每用户工件，例如 shellbags、LNKs、Jump Lists、`RecentDocs` 和 `MountPoints2`。



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
