# Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive 是从 _发生了什么？_ 快速追溯到 _哪个用户、何时以及从哪里？_ 的最快方式之一。对于 live analysis，优先使用 `CurrentControlSet`；对于 offline hive analysis，首先解析哪个 `ControlSet00x` 处于活动状态，而不是硬编码 `ControlSet001`。

### Windows 版本和所有者信息

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`：Windows 版本/构建版本、安装时间、注册所有者、产品名称以及其他构建元数据。
- `SYSTEM\Select`：将 `Current`、`Default` 和 `LastKnownGood` 映射到系统实际使用的 `ControlSet00x` 值。

### 计算机名称

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`：当前 hostname。

### 时区设置

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`：配置的时区和与 DST 相关的值。

### 访问时间跟踪

- `SYSTEM\CurrentControlSet\Control\FileSystem`：`NtfsDisableLastAccessUpdate` 表示是否正在更新 NTFS 的最后访问时间戳。
- 若要启用它，请使用：`fsutil behavior set disablelastaccess 0`

### 关机详情

- `SYSTEM\CurrentControlSet\Control\Windows`：上次关机时间。
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`：较旧的系统可能还会公开关机计数器。

### 网络配置

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`：接口 IP、DHCP 租约、gateway 和 DNS 数据。<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`：network profile 名称/SSID，以及首次和最后连接时间。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 和 `...\Unmanaged\{GUID}`：profile 关联数据，例如 gateway MAC 地址和 DNS 后缀。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`：主机发布的本地共享文件夹。

### 远程访问和网络共享历史

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`：出站 RDP MRU 列表（`MRU0`..`MRU9`）。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`：每个主机的出站 RDP 历史记录。子键通常存储 `UsernameHint`，而该键的 `LastWrite` 时间是一个有用的 pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`：与特定用户关联的映射网络驱动器、UNC 共享和可移动介质挂载点。

### 自动启动的程序和 Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 和 `...\Tasks\{GUID}`：scheduled task 元数据。如果此处存在任务，但 `Tree\<TaskName>` 中缺少 `SD` 值，应怀疑隐藏的 Tarrask-style task tampering，并将其与 `C:\Windows\System32\Tasks\<TaskName>` 进行关联。

### 搜索、输入的路径和 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`：File Explorer 搜索词。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`：手动输入的 Explorer 路径。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`：最近 26 条 `Win + R` 命令。`MRUList` 保留其顺序。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`：最近打开的文档和文件夹。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`：Office 最近使用的文件。

### 用户活动跟踪

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`：由 GUI 驱动的执行历史。值名称经过 ROT13 编码，二进制数据包含运行计数器和最后运行时间。<sup>[[1]](#references)</sup>
- 将 `UserAssist` 视为有力的辅助证据，而不是独立结论：它主要跟踪通过 Explorer 启动的应用或 `.lnk` 文件，可能遗漏命令行或 service 执行。在 Windows 10+ 上，某些条目不一定表示进程已完整运行。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 和 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`：具有 SID 归属和最后执行时间的现代 Windows 10/11 执行痕迹。这些条目对于本地执行的 binary 尤其有用，但较旧的条目可能会很快过期，并且从网络共享/可移动介质执行的记录可靠性较低。
- 对于 Prefetch、Amcache、ShimCache 和 SRUM 等更广泛的执行 artifacts，请参阅主 [Windows forensics overview](README.md#programs-executed)。

### Shellbags

- Shellbags 同时存储在 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 和 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 中。<sup>[[1]](#references)</sup>
- `NTUSER.DAT` 条目对于 UNC/网络浏览尤其有用，而 `UsrClass.dat` 是 Windows Vista+ 通常存储本地/可移动文件夹 shellbags 的位置。
- 即使文件夹已被删除，它们仍可显示文件夹存在、遍历以及文件夹视图偏好。类似 Explorer 的 archive 文件访问也可能留下 shellbag 痕迹。<sup>[[1]](#references)</sup>
- 并非每个 shellbag 都能证明文件夹访问成功，因此应结合 LNK、Jump Lists、时间戳或 volume mappings 进行佐证。
- 使用 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 或 **SBECmd** 解析它们。

### USB 信息

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`：USB mass-storage 设备的主要 inventory（vendor、product、revision、serial/device instance）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`：更广泛的 USB 设备 inventory，包括非存储设备。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`：在最近的 Windows 10/11 构建版本中，这是查找每个设备生命周期时间戳的高价值位置，例如安装、首次安装、最后到达和最后移除。<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`：将 volume 和 device identifier 映射到 drive letter / volume GUID。对于给定 drive letter，可能只保留最后一次映射。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`：对于 volume serial number 和以前的 media 元数据，这是一个有用的 pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`：特定于用户的 drive-letter 和 share 交互历史。<sup>[[2]](#references)</sup>
- 通过 MTP/PTP 连接的现代手机和平板电脑可能**不会**出现在 `USBSTOR` 下。还应检查 `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` 和 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`。<sup>[[2]](#references)</sup>
- 若要将设备关联到用户，可从 device 或 volume identifier pivot 到每个用户的 artifacts，例如 shellbags、LNK、Jump Lists、`RecentDocs` 和 `MountPoints2`。<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
