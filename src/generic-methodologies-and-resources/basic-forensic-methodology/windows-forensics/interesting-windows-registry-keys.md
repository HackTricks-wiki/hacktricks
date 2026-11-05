# 有趣的 Windows Registry 键

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive 是从“发生了什么？”快速追查到“哪个用户、何时、从何处？”的有效途径。进行实时分析时，优先使用 `CurrentControlSet`；分析离线 hive 时，先确认哪个 `ControlSet00x` 处于活动状态，不要直接假定是 `ControlSet001`。

### Windows 版本和所有者信息

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`：Windows 版本/内部版本、安装时间、注册所有者、产品名称及其他内部版本元数据。
- `SYSTEM\Select`：将 `Current`、`Default` 和 `LastKnownGood` 映射到系统实际使用的 `ControlSet00x` 值。

### 计算机名称

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`：当前主机名。

### 时区设置

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`：已配置的时区和与 DST 相关的值。

### 访问时间跟踪

- `SYSTEM\CurrentControlSet\Control\FileSystem`：`NtfsDisableLastAccessUpdate` 指示 NTFS 是否正在更新最后访问时间戳。
- 若要启用它，请使用：`fsutil behavior set disablelastaccess 0`

### 关机详情

- `SYSTEM\CurrentControlSet\Control\Windows`：上次关机时间。
- 较旧的系统也可能在 `SYSTEM\CurrentControlSet\Control\Watchdog\Display` 中提供关机计数器。

### 网络配置

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`：网卡 IP、DHCP 租约、网关和 DNS 数据。<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`：网络配置文件名称/SSID，以及首次和最近连接时间。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 和 `...\Unmanaged\{GUID}`：配置文件关联数据，例如网关 MAC 地址和 DNS 后缀。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`：主机发布的本地共享文件夹。

### 远程访问和网络共享历史记录

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`：出站 RDP MRU 列表（`MRU0`..`MRU9`）。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`：按主机记录的出站 RDP 历史。子项通常存储 `UsernameHint`，而该键的 `LastWrite` 时间是有用的调查切入点。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`：与特定用户关联的映射网络驱动器、UNC 共享和可移动介质挂载点。

### 自动启动程序和计划任务持久化

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 和 `...\Tasks\{GUID}`：计划任务元数据。如果此处存在任务，但 `Tree\<TaskName>` 中缺少 `SD` 值，应怀疑存在 Tarrask 风格的隐藏任务篡改，并结合 `C:\Windows\System32\Tasks\<TaskName>` 进行核查。

### 搜索、键入的路径和 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`：File Explorer 搜索词。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`：在 Explorer 中手动键入的路径。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`：最近 26 条 `Win + R` 命令。`MRUList` 保留其顺序。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`：最近打开的文档和文件夹。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`：Office 最近使用的文件。

### 用户活动跟踪

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`：由 GUI 驱动的执行历史记录。值名称使用 ROT13 编码，二进制数据包含运行计数和上次运行时间。<sup>[[1]](#references)</sup>
- 将 `UserAssist` 视为有力的佐证，而不是单独的定论：它主要跟踪通过 Explorer 启动的应用或 `.lnk` 文件，可能漏掉命令行或服务执行。在 Windows 10 及更高版本中，某些条目也不一定意味着进程已完整运行。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 和 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`：现代 Windows 10/11 执行痕迹，包含 SID 归属信息和上次执行时间。这些条目尤其适用于追查本地执行的二进制文件，但较早的条目可能很快过期，网络共享/可移动介质上的执行记录也不太可靠。
- 有关 Prefetch、Amcache、ShimCache 和 SRUM 等更广泛的执行痕迹，请参阅主 [Windows forensics overview](./#programs-executed)。

### Shellbags

- Shellbags 同时存储在 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 和 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 中。<sup>[[1]](#references)</sup>
- `NTUSER.DAT` 条目对 UNC/网络浏览尤其有用，而在 Windows Vista 及更高版本中，Windows 通常将本地/可移动文件夹的 shellbags 存储在 `UsrClass.dat` 中。
- 即使文件夹已被删除，这些条目也能显示文件夹是否存在、是否被浏览过，以及文件夹视图偏好。通过类似 Explorer 的方式访问归档文件，也可能留下 shellbag 痕迹。<sup>[[1]](#references)</sup>
- 并非每个 shellbag 都能证明文件夹访问成功，因此应通过 LNK、Jump List、时间戳或卷映射进行佐证。
- 使用 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 或 **SBECmd** 解析。

### USB 信息

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`：USB 大容量存储设备的主要清单（厂商、产品、修订版本、序列号/设备实例）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`：更广泛的 USB 设备清单，包括非存储设备。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`：在较新的 Windows 10/11 内部版本中，这里可能包含高价值的设备生命周期时间戳，例如安装、首次安装、最近接入和最近移除时间。<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`：将卷和设备标识符映射到驱动器号/卷 GUID。对于给定的驱动器号，可能只保留最近一次映射。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`：可用于追查卷序列号和先前的介质元数据。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`：特定用户的驱动器号和共享交互历史记录。<sup>[[2]](#references)</sup>
- 通过 MTP/PTP 连接的现代手机和平板电脑可能**不会**出现在 `USBSTOR` 下。也请检查 `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` 和 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`。<sup>[[2]](#references)</sup>
- 若要将设备关联到用户，可从设备或卷标识符入手，转而检查每用户痕迹，例如 shellbags、LNK、Jump List、`RecentDocs` 和 `MountPoints2`。<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry 取证速查表 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Windows 10 和 11 上的 USB 设备取证 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
