# 有趣的 Windows Registry 键

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive 是从 _发生了什么？_ 快速 pivot 到 _哪个用户、何时以及从哪里？_ 的最快方式之一。进行 live analysis 时优先使用 `CurrentControlSet`；进行 offline hive analysis 时，首先确定哪个 `ControlSet00x` 处于活动状态，不要硬编码 `ControlSet001`。

### Windows 版本和所有者信息

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`：Windows 版本/edition/build、安装时间、注册所有者、产品名称以及其他 build 元数据。
- `SYSTEM\Select`：将 `Current`、`Default` 和 `LastKnownGood` 映射到系统实际使用的 `ControlSet00x` 值。

### 计算机名称

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`：当前 hostname。

### 时区设置

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`：配置的时区和与 DST 相关的值。

### 访问时间跟踪

- `SYSTEM\CurrentControlSet\Control\FileSystem`：`NtfsDisableLastAccessUpdate` 表示是否正在更新 NTFS 的 last-access 时间戳。
- 要启用它，请使用：`fsutil behavior set disablelastaccess 0`

### 关机详情

- `SYSTEM\CurrentControlSet\Control\Windows`：上次关机时间。
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`：较旧的系统可能还会公开关机计数器。

### 网络配置

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`：接口 IP、DHCP leases、gateway 和 DNS 数据。<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`：网络 profile 名称/SSID，以及首次和最近一次连接时间。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 和 `...\Unmanaged\{GUID}`：profile 关联数据，例如 gateway MAC 地址和 DNS suffix。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`：主机发布的本地共享文件夹。

### 远程访问和网络共享历史

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`：出站 RDP MRU 列表（`MRU0`..`MRU9`）。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`：每个 host 的出站 RDP 历史。子键通常存储 `UsernameHint`，而该键的 `LastWrite` 时间是一个有用的 pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`：与特定用户关联的映射网络驱动器、UNC shares 和可移动介质挂载点。

### 自动启动的程序和 Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 和 `...\Tasks\{GUID}`：scheduled task 元数据。如果这里存在 task，但 `Tree\<TaskName>` 中缺少 `SD` 值，应怀疑隐藏的 Tarrask-style task tampering，并将其与 `C:\Windows\System32\Tasks\<TaskName>` 进行关联。

### 搜索、输入的路径和 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`：File Explorer 搜索词。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`：手动输入的 Explorer 路径。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`：最近 26 条 `Win + R` 命令。`MRUList` 保留其顺序。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`：最近打开的文档和文件夹。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`：Office 最近使用的文件。

### 用户活动跟踪

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`：由 GUI 驱动的执行历史。值名称经过 ROT13 编码，二进制数据包含运行计数器和上次运行时间。<sup>[[1]](#references)</sup>
- 将 `UserAssist` 视为有力的辅助证据，而不是单独的结论：它主要跟踪通过 Explorer 启动的 app 或 `.lnk` 文件，可能遗漏 command-line 或 service 执行。在 Windows 10+ 上，某些条目不一定表示进程已完整运行。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 和 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`：现代 Windows 10/11 的执行 trace，包含 SID attribution 和最近执行时间。这些键对于本地执行的 binary 特别有用，但较旧的条目可能很快被清除，并且来自 network shares/removable media 的执行记录可靠性较低。
- 关于 Prefetch、Amcache、ShimCache 和 SRUM 等更广泛的执行 artifact，请参阅主 [Windows forensics overview](README.md#programs-executed)。

### Shellbags

- Shellbags 同时存储在 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 和 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 中。<sup>[[1]](#references)</sup>
- `NTUSER.DAT` 条目对于 UNC/network browsing 特别有用，而 `UsrClass.dat` 是 Windows Vista+ 通常存储 local/removable-folder shellbags 的位置。
- 即使文件夹已被删除，它们仍可显示文件夹存在过、被遍历过以及 folder-view preferences。类似 Explorer 的 archive 文件访问也可能留下 shellbag trace。<sup>[[1]](#references)</sup>
- 并非每个 shellbag 都能证明成功访问过文件夹，因此应结合 LNKs、Jump Lists、时间戳或 volume mappings 进行 corroborate。
- 使用 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 或 **SBECmd** 对其进行解析。

### USB 信息

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`：USB mass-storage device 的主要 inventory（vendor、product、revision、serial/device instance）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`：更广泛的 USB device inventory，包括非存储设备。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`：在近期 Windows 10/11 build 中，这里是获取每个 device lifecycle timestamp 的高价值位置，例如安装、首次安装、最近到达和最近移除时间。<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`：将 volumes 和 device identifiers 映射到 drive letters / volume GUIDs。对于给定 drive letter，可能只有最后一次 mapping 会保留。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`：可用于 pivot 到 volume serial numbers 和之前的 media metadata。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`：特定用户的 drive-letter 和 share 交互历史。<sup>[[2]](#references)</sup>
- 通过 MTP/PTP 连接的现代 phones 和 tablets 可能**不会**出现在 `USBSTOR` 下。同时检查 `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` 和 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`。<sup>[[2]](#references)</sup>
- 要将 device 与用户关联起来，可从 device 或 volume identifiers pivot 到每个用户的 artifact，例如 shellbags、LNKs、Jump Lists、`RecentDocs` 和 `MountPoints2`。<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
