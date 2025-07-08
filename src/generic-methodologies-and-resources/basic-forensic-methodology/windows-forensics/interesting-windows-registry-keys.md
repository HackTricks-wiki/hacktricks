# 有趣的 Windows 注册表键

{{#include ../../../banners/hacktricks-training.md}}

### **Windows 版本和所有者信息**

- 位于 **`Software\Microsoft\Windows NT\CurrentVersion`**，您可以以简单的方式找到 Windows 版本、服务包、安装时间和注册所有者的名称。

### **计算机名称**

- 主机名位于 **`System\ControlSet001\Control\ComputerName\ComputerName`** 下。

### **时区设置**

- 系统的时区存储在 **`System\ControlSet001\Control\TimeZoneInformation`** 中。

### **访问时间跟踪**

- 默认情况下，最后访问时间跟踪是关闭的 (**`NtfsDisableLastAccessUpdate=1`**)。要启用它，请使用：
`fsutil behavior set disablelastaccess 0`

### Windows 版本和服务包

- **Windows 版本** 指示版本（例如，家庭版、专业版）及其发布（例如，Windows 10、Windows 11），而 **服务包** 是包含修复和有时新功能的更新。

### 启用最后访问时间

- 启用最后访问时间跟踪可以让您看到文件最后一次打开的时间，这对于取证分析或系统监控至关重要。

### 网络信息详细信息

- 注册表保存了关于网络配置的广泛数据，包括 **网络类型（无线、有线、3G）** 和 **网络类别（公共、私人/家庭、域/工作）**，这些对于理解网络安全设置和权限至关重要。

### 客户端缓存 (CSC)

- **CSC** 通过缓存共享文件的副本来增强离线文件访问。不同的 **CSCFlags** 设置控制缓存的文件类型和方式，影响性能和用户体验，特别是在连接不稳定的环境中。

### 自动启动程序

- 列在各种 `Run` 和 `RunOnce` 注册表键中的程序会在启动时自动启动，影响系统启动时间，并可能成为识别恶意软件或不需要软件的关注点。

### Shellbags

- **Shellbags** 不仅存储文件夹视图的偏好设置，还提供文件夹访问的取证证据，即使该文件夹不再存在。它们对于调查非常宝贵，揭示了通过其他方式不明显的用户活动。

### USB 信息和取证

- 注册表中存储的关于 USB 设备的详细信息可以帮助追踪哪些设备连接到计算机，可能将设备与敏感文件传输或未经授权的访问事件联系起来。

### 卷序列号

- **卷序列号** 对于跟踪文件系统的特定实例至关重要，在需要跨不同设备建立文件来源的取证场景中非常有用。

### **关机详细信息**

- 关机时间和计数（后者仅适用于 XP）保存在 **`System\ControlSet001\Control\Windows`** 和 **`System\ControlSet001\Control\Watchdog\Display`** 中。

### **网络配置**

- 有关详细的网络接口信息，请参阅 **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**。
- 首次和最后的网络连接时间，包括 VPN 连接，记录在 **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** 的各种路径下。

### **共享文件夹**

- 共享文件夹和设置位于 **`System\ControlSet001\Services\lanmanserver\Shares`** 下。客户端缓存 (CSC) 设置决定离线文件的可用性。

### **自动启动的程序**

- 像 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** 这样的路径和 `Software\Microsoft\Windows\CurrentVersion` 下的类似条目详细说明了设置为在启动时运行的程序。

### **搜索和输入的路径**

- 资源管理器搜索和输入的路径在注册表中跟踪，位于 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** 下的 WordwheelQuery 和 TypedPaths。

### **最近的文档和 Office 文件**

- 最近访问的文档和 Office 文件记录在 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` 和特定 Office 版本路径中。

### **最近使用的 (MRU) 项目**

- MRU 列表，指示最近的文件路径和命令，存储在 `NTUSER.DAT` 下的各种 `ComDlg32` 和 `Explorer` 子键中。

### **用户活动跟踪**

- 用户助手功能记录详细的应用程序使用统计信息，包括运行次数和最后运行时间，位于 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**。

### **Shellbags 分析**

- Shellbags，揭示文件夹访问详细信息，存储在 `USRCLASS.DAT` 和 `NTUSER.DAT` 下的 `Software\Microsoft\Windows\Shell` 中。使用 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 进行分析。

### **USB 设备历史**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** 和 **`HKLM\SYSTEM\ControlSet001\Enum\USB`** 包含有关连接的 USB 设备的丰富详细信息，包括制造商、产品名称和连接时间戳。
- 通过在 `NTUSER.DAT` 注册表中搜索设备的 **{GUID}**，可以确定与特定 USB 设备相关的用户。
- 最后挂载的设备及其卷序列号可以通过 `System\MountedDevices` 和 `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` 分别追踪。

本指南总结了访问 Windows 系统上详细系统、网络和用户活动信息的关键路径和方法，旨在提供清晰和可用性。

{{#include ../../../banners/hacktricks-training.md}}
