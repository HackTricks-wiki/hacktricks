# Windows 证据

## Windows 证据

{{#include ../../../banners/hacktricks-training.md}}


## 通用 Windows 证据

### Windows 10 通知

在路径 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` 中可以找到数据库 `appdb.dat`（在 Windows 周年更新之前）或 `wpndatabase.db`（在 Windows 周年更新之后）。

在这个 SQLite 数据库中，可以找到 `Notification` 表，里面包含所有的通知（以 XML 格式），可能包含有趣的数据。

### 时间线

时间线是 Windows 的一个特性，提供 **访问过的网页、编辑的文档和执行的应用程序的时间顺序历史**。

数据库位于路径 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。这个数据库可以用 SQLite 工具打开，或者用工具 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **生成的 2 个文件，这些文件可以用工具** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **打开**。

### ADS（备用数据流）

下载的文件可能包含 **ADS Zone.Identifier**，指示 **它是如何** 从内网、互联网等 **下载的**。一些软件（如浏览器）通常会提供更多 **信息**，例如 **文件下载的 URL**。

## **文件备份**

### 回收站

在 Vista/Win7/Win8/Win10 中，**回收站**可以在驱动器根目录的文件夹 **`$Recycle.bin`** 中找到（`C:\$Recycle.bin`）。\
当一个文件在这个文件夹中被删除时，会创建 2 个特定的文件：

- `$I{id}`: 文件信息（删除日期）
- `$R{id}`: 文件内容

![](<../../../images/image (486).png>)

拥有这些文件后，可以使用工具 [**Rifiuti**](https://github.com/abelcheung/rifiuti2) 获取已删除文件的原始地址和删除日期（使用 `rifiuti-vista.exe` 适用于 Vista – Win10）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### 卷影复制

卷影复制是微软Windows中包含的一项技术，可以创建计算机文件或卷的**备份副本**或快照，即使在使用时也可以。

这些备份通常位于文件系统根目录下的`\System Volume Information`中，名称由以下图像中显示的**UIDs**组成：

![](<../../../images/image (520).png>)

使用**ArsenalImageMounter**挂载取证镜像，可以使用工具[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html)检查卷影复制，甚至**提取文件**。

![](<../../../images/image (521).png>)

注册表项`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`包含**不备份**的文件和键：

![](<../../../images/image (522).png>)

注册表`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`也包含有关`卷影复制`的配置信息。

### Office自动保存文件

您可以在以下位置找到Office自动保存的文件：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell项目

Shell项目是包含有关如何访问另一个文件的信息的项目。

### 最近文档 (LNK)

Windows会在用户**打开、使用或创建文件**时**自动****创建**这些**快捷方式**：

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

当创建一个文件夹时，还会创建指向该文件夹、父文件夹和祖父文件夹的链接。

这些自动创建的链接文件**包含有关来源的信息**，例如它是一个**文件**还是一个**文件夹**、该文件的**MAC** **时间**、文件存储的**卷信息**以及**目标文件的文件夹**。这些信息在文件被删除的情况下可以用于恢复这些文件。

此外，链接文件的**创建日期**是原始文件**首次使用**的**时间**，而链接文件的**修改日期**是原始文件**最后使用**的**时间**。

要检查这些文件，您可以使用[**LinkParser**](http://4discovery.com/our-tools/)。

在此工具中，您将找到**2组**时间戳：

- **第一组：**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **第二组：**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate。

第一组时间戳引用的是**文件本身的时间戳**。第二组引用的是**链接文件的时间戳**。

您可以通过运行Windows CLI工具[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)获取相同的信息。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
在这种情况下，信息将保存在 CSV 文件中。

### Jumplists

这些是每个应用程序指示的最近文件。它是 **应用程序使用的最近文件列表**，您可以在每个应用程序上访问。它们可以 **自动创建或自定义**。

自动创建的 **jumplists** 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`。jumplists 的命名格式为 `{id}.autmaticDestinations-ms`，其中初始 ID 是应用程序的 ID。

自定义的 jumplists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`，通常是因为文件发生了某些 **重要** 事件（可能被标记为收藏）。

任何 jumplist 的 **创建时间** 表示 **文件首次访问的时间**，**修改时间为最后一次**。

您可以使用 [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) 检查 jumplists。

![](<../../../images/image (474).png>)

（_请注意，JumplistExplorer 提供的时间戳与 jumplist 文件本身相关_）

### Shellbags

[**点击此链接了解什么是 shellbags。**](interesting-windows-registry-keys.md#shellbags)

## 使用 Windows USB

可以通过以下方式识别 USB 设备的使用：

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

请注意，一些 LNK 文件不是指向原始路径，而是指向 WPDNSE 文件夹：

![](<../../../images/image (476).png>)

WPDNSE 文件夹中的文件是原始文件的副本，因此在 PC 重启后不会保留，GUID 是从 shellbag 中获取的。

### 注册表信息

[查看此页面以了解](interesting-windows-registry-keys.md#usb-information) 哪些注册表键包含有关 USB 连接设备的有趣信息。

### setupapi

检查文件 `C:\Windows\inf\setupapi.dev.log` 以获取 USB 连接发生时的时间戳（搜索 `Section start`）。

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) 可用于获取有关已连接到图像的 USB 设备的信息。

![](<../../../images/image (483).png>)

### Plug and Play Cleanup

名为“Plug and Play Cleanup”的计划任务主要用于删除过时的驱动程序版本。与其指定的保留最新驱动程序包版本的目的相反，在线来源表明它还针对过去 30 天未活动的驱动程序。因此，过去 30 天未连接的可移动设备的驱动程序可能会被删除。

该任务位于以下路径：
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

提供了任务内容的屏幕截图：
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**任务的关键组件和设置：**

- **pnpclean.dll**：此 DLL 负责实际的清理过程。
- **UseUnifiedSchedulingEngine**：设置为 `TRUE`，表示使用通用任务调度引擎。
- **MaintenanceSettings**：
- **Period ('P1M')**：指示任务调度程序在常规自动维护期间每月启动清理任务。
- **Deadline ('P2M')**：指示任务调度程序，如果任务连续两个月失败，则在紧急自动维护期间执行该任务。

此配置确保定期维护和清理驱动程序，并在连续失败的情况下重新尝试任务。

**有关更多信息，请查看：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## 电子邮件

电子邮件包含 **2 个有趣的部分：电子邮件的标题和内容**。在 **标题** 中，您可以找到以下信息：

- **谁** 发送了电子邮件（电子邮件地址、IP、重定向电子邮件的邮件服务器）
- **何时** 发送了电子邮件

此外，在 `References` 和 `In-Reply-To` 标头中，您可以找到消息的 ID：

![](<../../../images/image (484).png>)

### Windows Mail 应用

此应用程序以 HTML 或文本格式保存电子邮件。您可以在 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 的子文件夹中找到电子邮件。电子邮件以 `.dat` 扩展名保存。

电子邮件的 **元数据** 和 **联系人** 可以在 **EDB 数据库** 中找到： `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**将文件的扩展名** 从 `.vol` 更改为 `.edb`，您可以使用工具 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 打开它。在 `Message` 表中，您可以看到电子邮件。

### Microsoft Outlook

当使用 Exchange 服务器或 Outlook 客户端时，将会有一些 MAPI 标头：

- `Mapi-Client-Submit-Time`：发送电子邮件时系统的时间
- `Mapi-Conversation-Index`：线程的子消息数量和每条消息的时间戳
- `Mapi-Entry-ID`：消息标识符。
- `Mappi-Message-Flags` 和 `Pr_last_Verb-Executed`：有关 MAPI 客户端的信息（消息已读？未读？已回复？重定向？不在办公室？）

在 Microsoft Outlook 客户端中，所有发送/接收的消息、联系人数据和日历数据都存储在 PST 文件中，路径为：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

注册表路径 `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` 指示正在使用的文件。

您可以使用工具 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) 打开 PST 文件。

![](<../../../images/image (485).png>)

### Microsoft Outlook OST 文件

**OST 文件** 是 Microsoft Outlook 在配置为 **IMAP** 或 **Exchange** 服务器时生成的，存储与 PST 文件类似的信息。此文件与服务器同步，保留 **过去 12 个月** 的数据，最大大小为 50GB，并位于与 PST 文件相同的目录中。要查看 OST 文件，可以使用 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)。

### 检索附件

丢失的附件可能可以从以下位置恢复：

- 对于 **IE10**：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- 对于 **IE11 及更高版本**：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX 文件

**Thunderbird** 使用 **MBOX 文件** 存储数据，位于 `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`。

### 图像缩略图

- **Windows XP 和 8-8.1**：访问带有缩略图的文件夹会生成一个 `thumbs.db` 文件，存储图像预览，即使在删除后也会保留。
- **Windows 7/10**：通过 UNC 路径访问时会创建 `thumbs.db`。
- **Windows Vista 及更高版本**：缩略图预览集中在 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` 中，文件名为 **thumbcache_xxx.db**。 [**Thumbsviewer**](https://thumbsviewer.github.io) 和 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) 是查看这些文件的工具。

### Windows 注册表信息

Windows 注册表存储大量系统和用户活动数据，包含在以下文件中：

- `%windir%\System32\Config` 用于各种 `HKEY_LOCAL_MACHINE` 子键。
- `%UserProfile%{User}\NTUSER.DAT` 用于 `HKEY_CURRENT_USER`。
- Windows Vista 及更高版本在 `%Windir%\System32\Config\RegBack\` 中备份 `HKEY_LOCAL_MACHINE` 注册表文件。
- 此外，程序执行信息存储在 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` 中，从 Windows Vista 和 Windows 2008 Server 开始。

### 工具

一些工具对于分析注册表文件非常有用：

- **注册表编辑器**：它安装在 Windows 中。它是一个 GUI，用于浏览当前会话的 Windows 注册表。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：它允许您加载注册表文件并通过 GUI 浏览它们。它还包含书签，突出显示包含有趣信息的键。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样，它具有一个 GUI，允许浏览加载的注册表，并且还包含突出显示加载的注册表中有趣信息的插件。
- [**Windows 注册表恢复**](https://www.mitec.cz/wrr.html)：另一个 GUI 应用程序，能够从加载的注册表中提取重要信息。

### 恢复已删除元素

当一个键被删除时，它会被标记为已删除，但在占用的空间被需要之前不会被移除。因此，使用像 **Registry Explorer** 这样的工具可以恢复这些已删除的键。

### 最后写入时间

每个键值包含一个 **时间戳**，指示最后一次修改的时间。

### SAM

文件/哈希 **SAM** 包含系统的 **用户、组和用户密码** 哈希。

在 `SAM\Domains\Account\Users` 中，您可以获取用户名、RID、最后登录、最后失败的登录、登录计数器、密码策略以及帐户创建时间。要获取 **哈希**，您还 **需要** 文件/哈希 **SYSTEM**。

### Windows 注册表中的有趣条目

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## 执行的程序

### 基本 Windows 进程

在 [这篇文章](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) 中，您可以了解常见的 Windows 进程以检测可疑行为。

### Windows Recent APPs

在注册表 `NTUSER.DAT` 的路径 `Software\Microsoft\Current Version\Search\RecentApps` 中，您可以找到有关 **执行的应用程序**、**最后一次** 执行的时间和 **启动次数** 的子键。

### BAM (后台活动调节器)

您可以使用注册表编辑器打开 `SYSTEM` 文件，在路径 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 中找到有关 **每个用户执行的应用程序** 的信息（注意路径中的 `{SID}`）以及 **执行的时间**（时间在注册表的 Data 值中）。

### Windows Prefetch

预取是一种技术，允许计算机静默 **获取用户可能在不久的将来访问的内容所需的资源**，以便更快地访问资源。

Windows 预取由创建 **已执行程序的缓存** 组成，以便能够更快地加载它们。这些缓存作为 `.pf` 文件创建，路径为： `C:\Windows\Prefetch`。在 XP/VISTA/WIN7 中限制为 128 个文件，在 Win8/Win10 中限制为 1024 个文件。

文件名的格式为 `{program_name}-{hash}.pf`（哈希基于可执行文件的路径和参数）。在 W10 中，这些文件是压缩的。请注意，文件的存在仅表示 **程序在某个时刻被执行**。

文件 `C:\Windows\Prefetch\Layout.ini` 包含 **被预取文件的文件夹名称**。该文件包含 **执行次数**、**执行日期** 和 **程序打开的文件** 的信息。

要检查这些文件，您可以使用工具 [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)：
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (487).png>)

### Superprefetch

**Superprefetch** 的目标与预取相同，**通过预测将要加载的内容来更快地加载程序**。然而，它并不替代预取服务。\
该服务将在 `C:\Windows\Prefetch\Ag*.db` 中生成数据库文件。

在这些数据库中，您可以找到 **程序的名称**、**执行次数**、**打开的文件**、**访问的卷**、**完整路径**、**时间范围** 和 **时间戳**。

您可以使用工具 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 访问这些信息。

### SRUM

**系统资源使用监视器** (SRUM) **监视** **进程消耗的资源**。它出现在 W8 中，并将数据存储在位于 `C:\Windows\System32\sru\SRUDB.dat` 的 ESE 数据库中。

它提供以下信息：

- AppID 和路径
- 执行该进程的用户
- 发送的字节
- 接收的字节
- 网络接口
- 连接持续时间
- 进程持续时间

这些信息每 60 分钟更新一次。

您可以使用工具 [**srum_dump**](https://github.com/MarkBaggett/srum-dump) 从该文件中获取日期。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**，也称为 **ShimCache**，是 **Microsoft** 开发的 **应用程序兼容性数据库** 的一部分，用于解决应用程序兼容性问题。该系统组件记录了各种文件元数据，包括：

- 文件的完整路径
- 文件的大小
- 在 **$Standard_Information** (SI) 下的最后修改时间
- ShimCache 的最后更新时间
- 进程执行标志

这些数据根据操作系统的版本存储在注册表的特定位置：

- 对于 XP，数据存储在 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` 下，最多可容纳 96 条目。
- 对于 Server 2003，以及 Windows 版本 2008、2012、2016、7、8 和 10，存储路径为 `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`，分别容纳 512 和 1024 条目。

要解析存储的信息，建议使用 [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser)。

![](<../../../images/image (488).png>)

### Amcache

**Amcache.hve** 文件本质上是一个注册表蜂巢，记录了在系统上执行的应用程序的详细信息。它通常位于 `C:\Windows\AppCompat\Programas\Amcache.hve`。

该文件以存储最近执行的进程记录而著称，包括可执行文件的路径及其 SHA1 哈希。这些信息对于跟踪系统上应用程序的活动非常宝贵。

要提取和分析 **Amcache.hve** 中的数据，可以使用 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) 工具。以下命令是如何使用 AmcacheParser 解析 **Amcache.hve** 文件内容并以 CSV 格式输出结果的示例：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
在生成的 CSV 文件中，`Amcache_Unassociated file entries` 特别值得注意，因为它提供了关于未关联文件条目的丰富信息。

生成的最有趣的 CVS 文件是 `Amcache_Unassociated file entries`。

### RecentFileCache

此工件仅在 W7 中的 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` 中找到，包含有关某些二进制文件最近执行的信息。

您可以使用工具 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) 来解析该文件。

### 计划任务

您可以从 `C:\Windows\Tasks` 或 `C:\Windows\System32\Tasks` 中提取它们，并将其作为 XML 读取。

### 服务

您可以在注册表中找到它们，路径为 `SYSTEM\ControlSet001\Services`。您可以查看将要执行的内容及其时间。

### **Windows Store**

已安装的应用程序可以在 `\ProgramData\Microsoft\Windows\AppRepository\` 中找到。\
该存储库中有一个 **log**，记录了 **系统中每个已安装的应用程序**，存储在数据库 **`StateRepository-Machine.srd`** 中。

在该数据库的应用程序表中，可以找到列：“Application ID”、“PackageNumber”和“Display Name”。这些列包含有关预安装和已安装应用程序的信息，如果某些应用程序被卸载，可以找到，因为已安装应用程序的 ID 应该是连续的。

您还可以在注册表路径 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` 中 **找到已安装的应用程序**，\
在 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\` 中 **找到已卸载的应用程序**。

## Windows 事件

Windows 事件中出现的信息包括：

- 发生了什么
- 时间戳 (UTC + 0)
- 相关用户
- 相关主机 (主机名，IP)
- 访问的资产 (文件，文件夹，打印机，服务)

日志位于 `C:\Windows\System32\config`（在 Windows Vista 之前）和 `C:\Windows\System32\winevt\Logs`（在 Windows Vista 之后）。在 Windows Vista 之前，事件日志是二进制格式，之后则为 **XML 格式**，并使用 **.evtx** 扩展名。

事件文件的位置可以在 SYSTEM 注册表中找到，路径为 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**。

可以通过 Windows 事件查看器 (**`eventvwr.msc`**) 或其他工具如 [**Event Log Explorer**](https://eventlogxp.com) **或** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** 来可视化它们。

## 理解 Windows 安全事件日志

访问事件记录在位于 `C:\Windows\System32\winevt\Security.evtx` 的安全配置文件中。该文件的大小是可调的，当其容量达到时，较旧的事件会被覆盖。记录的事件包括用户登录和注销、用户操作以及安全设置的更改，以及文件、文件夹和共享资产的访问。

### 用户身份验证的关键事件 ID：

- **EventID 4624**：表示用户成功认证。
- **EventID 4625**：表示认证失败。
- **EventIDs 4634/4647**：表示用户注销事件。
- **EventID 4672**：表示以管理员权限登录。

#### EventID 4634/4647 中的子类型：

- **Interactive (2)**：直接用户登录。
- **Network (3)**：访问共享文件夹。
- **Batch (4)**：执行批处理过程。
- **Service (5)**：服务启动。
- **Proxy (6)**：代理认证。
- **Unlock (7)**：使用密码解锁屏幕。
- **Network Cleartext (8)**：明文密码传输，通常来自 IIS。
- **New Credentials (9)**：使用不同的凭据进行访问。
- **Remote Interactive (10)**：远程桌面或终端服务登录。
- **Cache Interactive (11)**：使用缓存凭据登录，无需联系域控制器。
- **Cache Remote Interactive (12)**：使用缓存凭据进行远程登录。
- **Cached Unlock (13)**：使用缓存凭据解锁。

#### EventID 4625 的状态和子状态代码：

- **0xC0000064**：用户名不存在 - 可能表示用户名枚举攻击。
- **0xC000006A**：正确的用户名但密码错误 - 可能是密码猜测或暴力破解尝试。
- **0xC0000234**：用户账户被锁定 - 可能是在暴力攻击后导致多次登录失败。
- **0xC0000072**：账户已禁用 - 未经授权尝试访问禁用账户。
- **0xC000006F**：在允许的时间之外登录 - 表示在设定的登录时间之外尝试访问，可能是未经授权的访问迹象。
- **0xC0000070**：违反工作站限制 - 可能是尝试从未经授权的位置登录。
- **0xC0000193**：账户过期 - 使用过期用户账户的访问尝试。
- **0xC0000071**：密码过期 - 使用过时密码的登录尝试。
- **0xC0000133**：时间同步问题 - 客户端和服务器之间的大时间差异可能表明更复杂的攻击，如票据传递攻击。
- **0xC0000224**：需要强制更改密码 - 频繁的强制更改可能表明试图破坏账户安全。
- **0xC0000225**：表示系统错误而非安全问题。
- **0xC000015b**：拒绝的登录类型 - 使用未经授权的登录类型进行的访问尝试，例如用户尝试执行服务登录。

#### EventID 4616：

- **时间更改**：系统时间的修改，可能会模糊事件的时间线。

#### EventID 6005 和 6006：

- **系统启动和关闭**：EventID 6005 表示系统启动，而 EventID 6006 表示系统关闭。

#### EventID 1102：

- **日志删除**：安全日志被清除，通常是掩盖非法活动的红旗。

#### USB 设备跟踪的事件 ID：

- **20001 / 20003 / 10000**：USB 设备首次连接。
- **10100**：USB 驱动程序更新。
- **EventID 112**：USB 设备插入的时间。

有关模拟这些登录类型和凭据转储机会的实际示例，请参阅 [Altered Security 的详细指南](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)。

事件详细信息，包括状态和子状态代码，提供了对事件原因的进一步洞察，特别是在事件 ID 4625 中尤为显著。

### 恢复 Windows 事件

为了提高恢复已删除 Windows 事件的机会，建议通过直接拔掉电源来关闭可疑计算机。**Bulk_extractor** 是一款指定 `.evtx` 扩展名的恢复工具，推荐用于尝试恢复此类事件。

### 通过 Windows 事件识别常见攻击

有关利用 Windows 事件 ID 识别常见网络攻击的全面指南，请访问 [Red Team Recipe](https://redteamrecipe.com/event-codes/)。

#### 暴力攻击

通过多个 EventID 4625 记录可识别，若攻击成功，则会跟随一个 EventID 4624。

#### 时间更改

通过 EventID 4616 记录，系统时间的更改可能会使取证分析变得复杂。

#### USB 设备跟踪

用于 USB 设备跟踪的有用系统事件 ID 包括 20001/20003/10000（首次使用），10100（驱动程序更新）和 EventID 112（来自 DeviceSetupManager 的插入时间戳）。

#### 系统电源事件

EventID 6005 表示系统启动，而 EventID 6006 表示关闭。

#### 日志删除

安全 EventID 1102 表示日志被删除，这是取证分析中的关键事件。

{{#include ../../../banners/hacktricks-training.md}}
