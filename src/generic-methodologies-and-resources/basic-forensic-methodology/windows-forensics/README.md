# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## 通用 Windows Artifacts

### Windows 10 通知

在路径 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` 中，可以找到数据库 `appdb.dat`（Windows anniversary 之前）或 `wpndatabase.db`（Windows Anniversary 之后）。

在这个 SQLite 数据库中，可以找到包含所有通知的 `Notification` 表，这些通知采用 XML 格式，可能包含有价值的数据。

### 时间线

Timeline 是 Windows 的一项特性，提供网页访问、文档编辑和应用程序执行的**时间顺序历史记录**。

数据库位于路径 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。可以使用 SQLite 工具打开此数据库，也可以使用工具 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 打开；该工具**会生成 2 个可使用工具** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **打开的文件**。

### ADS (Alternate Data Streams)

下载的文件可能包含 **ADS Zone.Identifier**，用于指示文件是从内联网、互联网等位置**如何下载**的。某些软件（如浏览器）通常还会写入**更多**信息，例如文件下载来源的 **URL**。

## **文件备份**

### 回收站

在 Vista/Win7/Win8/Win10 中，可以在驱动器根目录的文件夹 **`$Recycle.bin`** 中找到 **Recycle Bin**（`C:\$Recycle.bin`）。\
当文件在此文件夹中被删除时，会创建 2 个特定文件：

- `$I{id}`：文件信息（删除日期}
- `$R{id}`：文件内容

![文件备份 - 回收站：$R{id}：文件内容](<../../../images/image (1029).png>)

有了这些文件，可以使用工具 [**Rifiuti**](https://github.com/abelcheung/rifiuti2) 获取已删除文件的原始路径和删除日期（Vista – Win10 请使用 `rifiuti-vista.exe`）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy 是 Microsoft Windows 中包含的一项技术，可以创建计算机文件或卷的**备份副本**或快照，即使这些文件或卷正在使用中。

这些备份通常位于文件系统根目录下的 `\System Volume Information` 中，其名称由以下图像中显示的 **UIDs** 组成：

![Recycle Bin - Volume Shadow Copies: 这些备份通常位于文件系统根目录下的 System Volume Information 中，其名称由图中显示的 UIDs 组成](<../../../images/image (94).png>)

使用 **ArsenalImageMounter** 挂载 forensics image 后，可以使用 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) 检查 shadow copy，甚至从 shadow copy 备份中**提取文件**。

![Recycle Bin - Volume Shadow Copies: 使用 ArsenalImageMounter 挂载 forensics image 后，可以使用 ShadowCopyView 检查 shadow copy，甚至从 shadow copy 备份中提取文件](<../../../images/image (576).png>)

注册表项 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` 包含**不进行备份**的文件和键：

![Recycle Bin - Volume Shadow Copies: 注册表项 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore 包含不进行备份的文件和键](<../../../images/image (254).png>)

注册表 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` 也包含有关 `Volume Shadow Copies` 的配置信息。

### Office AutoSaved Files

可以在以下位置找到 Office 自动保存的文件：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item 是包含如何访问其他文件相关信息的项目。

### Recent Documents (LNK)

当用户在以下位置**打开、使用或创建文件**时，Windows 会**自动**创建这些**快捷方式**：

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

创建文件夹时，还会创建指向该文件夹、父文件夹和祖父文件夹的链接。

这些自动创建的链接文件**包含有关源的信息**，例如它是**文件**还是**文件夹**、该文件的 **MAC** **时间**、文件存储位置的**卷信息**以及**目标文件所在的文件夹**。如果这些文件已被删除，这些信息有助于恢复它们。

此外，链接文件的**创建日期**是原始文件**首次被使用**的**时间**，而链接文件的**修改日期**是源文件最后一次被使用的**时间**。

可以使用 [**LinkParser**](http://4discovery.com/our-tools/) 检查这些文件。

在此工具中，可以找到 **2 组**时间戳：

- **第一组：**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **第二组：**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

第一组时间戳引用**文件本身的时间戳**。第二组引用**链接文件的时间戳**。

也可以运行 Windows CLI 工具获取相同的信息：[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
在这种情况下，信息将保存到 CSV 文件中。

### Jumplists

这些是每个应用程序所记录的最近文件。它们是**应用程序最近使用的文件列表**，你可以在每个应用程序中访问这些文件。它们可以**自动创建，也可以自定义创建**。

自动创建的 **jumplists** 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` 中。jumplists 按照 `{id}.autmaticDestinations-ms` 格式命名，其中开头的 ID 是应用程序的 ID。

自定义 jumplists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` 中，通常由应用程序创建，因为文件发生了某些**重要事件**（可能被标记为收藏）。

任何 jumplist 的**创建时间**表示**文件首次被访问的时间**，而**修改时间表示最后一次访问的时间**。

你可以使用 [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) 检查 jumplists。

![Recent Documents (LNK) - Jumplists: You can inspect the jumplists using JumplistExplorer](<../../../images/image (168).png>)

（_请注意，JumplistExplorer 提供的时间戳与 jumplist 文件本身相关_）

### Shellbags

[**点击此链接了解 shellbags。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 的使用情况

通过以下内容的创建，可以确定某个 USB 设备曾被使用：

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

请注意，某些 LNK 文件并不指向原始路径，而是指向 WPDNSE 文件夹：

![Shellbags - Use of Windows USBs: Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder](<../../../images/image (218).png>)

WPDNSE 文件夹中的文件是原始文件的副本，因此在 PC 重启后不会保留，并且 GUID 取自 shellbag。

### Registry Information

[查看此页面](interesting-windows-registry-keys.md#usb-information)，了解哪些 registry keys 包含有关已连接 USB 设备的有用信息。

### setupapi

检查文件 `C:\Windows\inf\setupapi.dev.log`，获取 USB 连接建立时的时间戳（搜索 `Section start`）。

![Registry Information - setupapi: Check the file C: Windows inf setupapi.dev.log to get the timestamps about when the USB connection was produced (search for Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

可以使用 [**USBDetective**](https://usbdetective.com) 获取连接到某个 image 的 USB 设备信息。

![setupapi - USB Detective: USBDetective can be used to obtain information about the USB devices that have been connected to an image](<../../../images/image (452).png>)

### Plug and Play Cleanup

名为“Plug and Play Cleanup”的 scheduled task 主要用于删除过时的 driver 版本。与其所声明的保留最新 driver package 版本的用途相反，online sources 表明它还会针对超过 30 天未处于活动状态的 drivers。因此，过去 30 天内未连接的 removable devices 的 drivers 可能会被删除。<sup>[[1]](#references)</sup>

该 task 位于以下路径：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

以下 screenshot 展示了该 task 的内容：![USB Detective - Plug and Play Cleanup: The task is located at the following path: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**该 Task 的关键组件和设置：**

- **pnpclean.dll**：此 DLL 负责实际的 cleanup process。
- **UseUnifiedSchedulingEngine**：设置为 `TRUE`，表示使用 generic task scheduling engine。
- **MaintenanceSettings**：
- **Period ('P1M')**：指示 Task Scheduler 在定期 Automatic maintenance 期间每月启动 cleanup task。
- **Deadline ('P2M')**：如果 task 连续两个月失败，则指示 Task Scheduler 在 emergency Automatic maintenance 期间执行该 task。

此配置确保定期维护和 cleanup drivers，并在连续失败时重新尝试执行该 task。

**更多信息请查看：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Emails 包含**两个有用部分：headers 和 email content**。在 **headers** 中可以找到以下信息：

- 发送 emails 的人（email address、IP、重定向 email 的 mail servers）
- email 的发送时间

此外，在 `References` 和 `In-Reply-To` headers 中可以找到 messages 的 ID：

![Plug and Play Cleanup - Emails: When was the email sent](<../../../images/image (593).png>)

### Windows Mail App

此 application 将 emails 保存为 HTML 或 text。你可以在 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 下的子文件夹中找到 emails。emails 使用 `.dat` extension 保存。

emails 的 **metadata** 和 **contacts** 可以在 **EDB database** 中找到：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

将文件的 **extension 从 `.vol` 更改为 `.edb`**，然后可以使用工具 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 打开它。在 `Message` table 中可以查看 emails。

### Microsoft Outlook

使用 Exchange servers 或 Outlook clients 时，会存在一些 MAPI headers：

- `Mapi-Client-Submit-Time`：email 发送时系统的时间
- `Mapi-Conversation-Index`：thread 中子 messages 的数量以及 thread 中每条 message 的 timestamp
- `Mapi-Entry-ID`：Message identifier。
- `Mappi-Message-Flags` 和 `Pr_last_Verb-Executed`：有关 MAPI client 的信息（message 是否已读？未读？是否已回复？是否已重定向？是否处于 out of the office 状态？）

在 Microsoft Outlook client 中，所有已发送/已接收的 messages、contacts data 和 calendar data 都存储在以下位置的 PST file 中：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` 指示当前使用的文件。

你可以使用工具 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) 打开 PST file。

![Windows Mail App - Microsoft Outlook: You can open the PST file using the tool Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

当 Microsoft Outlook 配置为使用 **IMAP** 或 **Exchange** server 时，会生成 **OST file**，其中存储的信息与 PST file 类似。此文件会与 server 同步，保留**最近 12 个月**的数据，**最大大小为 50GB**，并且位于与 PST file 相同的 directory 中。要查看 OST file，可以使用 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)。

### Retrieving Attachments

丢失的 attachments 可能可以从以下位置恢复：

- 对于 **IE10**：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- 对于 **IE11 and above**：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** 使用 **MBOX files** 存储 data，位置为 `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`。

### Image Thumbnails

- **Windows XP and 8-8.1**：访问包含 thumbnails 的 folder 会生成 `thumbs.db` file，用于存储 image previews，即使 image 已被删除。
- **Windows 7/10**：通过 UNC path 经 network 访问时会创建 `thumbs.db`。
- **Windows Vista and newer**：Thumbnail previews 集中存储在 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` 中，文件名为 **thumbcache_xxx.db**。[**Thumbsviewer**](https://thumbsviewer.github.io) 和 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) 是用于查看这些文件的 tools。

### Windows Registry Information

Windows Registry 存储大量 system 和 user activity data，包含在以下文件中：

- `%windir%\System32\Config`：各种 `HKEY_LOCAL_MACHINE` subkeys。
- `%UserProfile%{User}\NTUSER.DAT`：`HKEY_CURRENT_USER`。
- Windows Vista 及更高版本会将 `HKEY_LOCAL_MACHINE` registry files 备份到 `%Windir%\System32\Config\RegBack\`。
- 此外，从 Windows Vista 和 Windows 2008 Server 开始，program execution information 存储在 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` 中。

### Tools

以下 tools 可用于分析 registry files：

- **Registry Editor**：Windows 自带的工具。它是一个用于浏览当前 session 的 Windows registry 的 GUI。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：允许你加载 registry file，并通过 GUI 浏览其中内容。它还包含 Bookmarks，用于突出显示包含有用信息的 keys。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样提供 GUI，可浏览已加载的 registry，还包含用于突出显示已加载 registry 中有用信息的 plugins。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：另一个能够从已加载的 registry 中提取重要信息的 GUI application。

### Recovering Deleted Element

删除 key 时，它会被标记为已删除，但在其所占用的空间被需要之前不会被移除。因此，使用 **Registry Explorer** 等 tools 可以恢复这些已删除的 keys。

### Last Write Time

每个 Key-Value 都包含一个 **timestamp**，表示其最后一次被修改的时间。

### SAM

**SAM** file/hive 包含系统的 **users、groups 和 users passwords** hashes。

在 `SAM\Domains\Account\Users` 中，可以获取 username、RID、last login、last failed logon、login counter、password policy 以及 account 的创建时间。要获取 **hashes**，还**需要** **SYSTEM** file/hive。

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

在[这篇 post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)中，你可以了解用于检测可疑行为的常见 Windows processes。

### Windows Recent APPs

在 registry `NTUSER.DAT` 的路径 `Software\Microsoft\Current Version\Search\RecentApps` 中，可以找到包含以下信息的 subkeys：**执行过的 application**、其**最后一次**执行时间，以及它被启动的**次数**。

### BAM (Background Activity Moderator)

你可以使用 registry editor 打开 `SYSTEM` file，然后在路径 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 中找到每个 user **执行过的 applications** 信息（注意路径中的 `{SID}`），以及它们的执行时间（该时间位于 registry 的 Data value 中）。

### Windows Prefetch

Prefetching 是一种技术，它允许 computer 静默地**获取显示内容所需的 resources**，这些内容是 user **可能在不久的将来访问的**，从而可以更快地访问 resources。

Windows prefetch 会创建**已执行 programs 的 caches**，以便更快地加载它们。这些 caches 会作为 `.pf` files 创建在路径 `C:\Windows\Prefetch` 中。XP/VISTA/WIN7 中限制为 128 个 files，Win8/Win10 中限制为 1024 个 files。

文件名按照 `{program_name}-{hash}.pf` 格式创建（hash 基于 executable 的 path 和 arguments）。在 W10 中，这些 files 会被压缩。请注意，仅仅存在该 file 就表示**该 program 曾在某个时间被执行过**。

文件 `C:\Windows\Prefetch\Layout.ini` 包含**被 prefetched files 所在 folder 的名称**。该 file 包含有关**执行次数**、执行的**日期**以及 program **打开的 files** 的信息。

要检查这些 files，可以使用 tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)：
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** 的目标与 prefetch 相同，即通过预测接下来要加载的内容来**更快地加载程序**。但是，它不会替代 prefetch service。\
此 service 会在 `C:\Windows\Prefetch\Ag*.db` 中生成数据库文件。

在这些数据库中，你可以找到**程序**的**名称**、**执行次数**、已**打开的文件**、已访问的**卷**、**完整路径**、**时间范围**和**时间戳**。

你可以使用工具 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 访问这些信息。

### SRUM

**System Resource Usage Monitor**（SRUM）会**监控**某个**进程**所**消耗的资源**。它出现在 W8 中，并将数据存储在位于 `C:\Windows\System32\sru\SRUDB.dat` 的 ESE 数据库中。

它提供以下信息：

- AppID 和路径
- 执行该进程的用户
- 已发送字节数
- 已接收字节数
- 网络接口
- 连接持续时间
- 进程持续时间

这些信息每 60 分钟更新一次。

你可以使用工具 [**srum_dump**](https://github.com/MarkBaggett/srum-dump) 从此文件中获取日期。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**（也称为 **ShimCache**）是由 **Microsoft** 开发的 **Application Compatibility Database** 的一部分，用于解决应用程序兼容性问题。该系统组件会记录文件的各种元数据，包括：

- 文件的完整路径
- 文件大小
- **$Standard_Information**（SI）中的上次修改时间
- ShimCache 的上次更新时间
- 进程执行标志

这些数据根据操作系统版本存储在注册表的特定位置：

- 对于 XP，数据存储在 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` 下，容量为 96 个条目。
- 对于 Server 2003，以及 Windows 2008、2012、2016、7、8 和 10，存储路径为 `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`，容量分别为 512 和 1024 个条目。

建议使用 [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) 解析存储的信息。

![SRUM - AppCompatCache (ShimCache)：建议使用 AppCompatCacheParser tool 解析存储的信息](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 文件本质上是一个 registry hive，用于记录系统上已执行应用程序的详细信息。它通常位于 `C:\Windows\AppCompat\Programas\Amcache.hve`。

该文件会存储最近执行的进程记录，包括可执行文件的路径及其 SHA1 哈希值。这些信息对于追踪系统上的应用程序活动非常有价值。

要从 **Amcache.hve** 中提取和分析数据，可以使用 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool。以下命令示例展示了如何使用 AmcacheParser 解析 **Amcache.hve** 文件的内容，并以 CSV 格式输出结果：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
在生成的 CSV 文件中，`Amcache_Unassociated file entries` 尤其值得关注，因为它提供了有关未关联文件条目的丰富信息。

生成的最有趣的 CVS 文件是 `Amcache_Unassociated file entries`。

### RecentFileCache

此 artifact 只能在 W7 的 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` 中找到，其中包含某些 binaries 最近执行的信息。

你可以使用工具 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) 解析该文件。

### Scheduled tasks

你可以从 `C:\Windows\Tasks` 或 `C:\Windows\System32\Tasks` 中提取它们，并将其作为 XML 读取。

### Services

你可以在 registry 的 `SYSTEM\ControlSet001\Services` 下找到它们。你可以查看将要执行的内容及其执行时间。

### **Windows Store**

已安装的 applications 位于 `\ProgramData\Microsoft\Windows\AppRepository\`\
该 repository 在数据库 **`StateRepository-Machine.srd`** 中包含系统内**每个已安装 application** 的 **log**。

在该数据库的 Application 表中，可以找到以下列："Application ID"、"PackageNumber" 和 "Display Name"。这些列包含预安装和已安装 applications 的信息，并且可以通过已安装 applications 的 ID 应按顺序排列这一点，判断是否有某些 applications 被卸载。

也可以在 registry 路径 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
中**找到已安装的 application**，并在以下路径中找到**已卸载**的 **applications**：`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows events 中出现的信息包括：

- 发生了什么
- Timestamp (UTC + 0)
- 涉及的 Users
- 涉及的 Hosts（hostname、IP）
- 访问的 Assets（files、folder、printer、services）

在 Windows Vista 之前，logs 位于 `C:\Windows\System32\config`；Windows Vista 之后，位于 `C:\Windows\System32\winevt\Logs`。Windows Vista 之前，event logs 使用 binary format；之后则使用 **XML format**，并采用 **.evtx** extension。

event files 的位置可以在 SYSTEM registry 的 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** 中找到。

它们可以通过 Windows Event Viewer（**`eventvwr.msc`**）查看，也可以使用 [**Event Log Explorer**](https://eventlogxp.com) **或** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** 等其他 tools 查看。**

## Understanding Windows Security Event Logging

Access events 会记录在位于 `C:\Windows\System32\winevt\Security.evtx` 的 security configuration file 中。该 file 的大小可以调整；当达到容量上限时，较早的 events 会被覆盖。记录的 events 包括 user logins 和 logoffs、user actions、security settings 的更改，以及对 files、folders 和 shared assets 的访问。

### Key Event IDs for User Authentication:

- **EventID 4624**：表示 user 成功完成 authentication。
- **EventID 4625**：表示 authentication failure。
- **EventIDs 4634/4647**：表示 user logoff events。
- **EventID 4672**：表示以 administrative privileges 登录。

#### EventID 4634/4647 中的 Sub-types：

- **Interactive (2)**：直接 user login。
- **Network (3)**：访问 shared folders。
- **Batch (4)**：执行 batch processes。
- **Service (5)**：启动 services。
- **Proxy (6)**：Proxy authentication。
- **Unlock (7)**：使用 password 解锁 screen。
- **Network Cleartext (8)**：传输 clear text password，通常来自 IIS。
- **New Credentials (9)**：使用不同的 credentials 进行访问。
- **Remote Interactive (10)**：Remote desktop 或 terminal services login。
- **Cache Interactive (11)**：在不联系 domain controller 的情况下，使用 cached credentials 登录。
- **Cache Remote Interactive (12)**：使用 cached credentials 进行 remote login。
- **Cached Unlock (13)**：使用 cached credentials 解锁。

#### EventID 4625 的 Status 和 Sub Status Codes：

- **0xC0000064**：User name 不存在 - 可能表示 username enumeration attack。
- **0xC000006A**：User name 正确但 password 错误 - 可能是 password guessing 或 brute-force attempt。
- **0xC0000234**：User account 被锁定 - 可能发生在 brute-force attack 导致多次 login failure 之后。
- **0xC0000072**：Account 已禁用 - 表示尝试未经授权访问已禁用的 accounts。
- **0xC000006F**：在允许的时间之外 logon - 表示尝试在设定的 login hours 之外访问，可能是 unauthorized access 的迹象。
- **0xC0000070**：违反 workstation restrictions - 可能表示尝试从 unauthorized location 登录。
- **0xC0000193**：Account 已过期 - 表示使用过期 user accounts 进行 access attempts。
- **0xC0000071**：Password 已过期 - 表示使用过时 passwords 进行 login attempts。
- **0xC0000133**：Time sync issues - client 与 server 之间存在较大的时间差，可能表示更复杂的 attacks，例如 pass-the-ticket。
- **0xC0000224**：必须更改 password - 频繁的 mandatory changes 可能表示试图破坏 account security。
- **0xC0000225**：表示 system bug，而不是 security issue。
- **0xC000015b**：Logon type 被拒绝 - 表示使用 unauthorized logon type 进行 access attempt，例如 user 尝试执行 service logon。

#### EventID 4616：

- **Time Change**：修改 system time，可能会掩盖 events 的 timeline。

#### EventID 6005 和 6006：

- **System Startup and Shutdown**：EventID 6005 表示 system startup，EventID 6006 表示 system shutdown。

#### EventID 1102：

- **Log Deletion**：清除 security logs，这通常是掩盖 illicit activities 的 red flag。

#### 用于 USB Device Tracking 的 EventIDs：

- **20001 / 20003 / 10000**：USB device 首次连接。
- **10100**：USB driver update。
- **EventID 112**：USB device insertion 的时间。

关于模拟这些 login types 和 credential dumping opportunities 的实际示例，请参考 [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)。

Event details（包括 status 和 sub-status codes）可以进一步揭示 events 的原因，在 Event ID 4625 中尤其值得注意。

### Recovering Windows Events

为了提高恢复已删除 Windows Events 的可能性，建议直接拔掉 suspect computer 的电源使其关机。建议使用指定 `.evtx` extension 的 recovery tool **Bulk_extractor** 尝试恢复这些 events。

### Identifying Common Attacks via Windows Events

如需全面了解如何利用 Windows Event IDs 识别常见 cyber attacks，请访问 [Red Team Recipe](https://redteamrecipe.com/event-codes/)。

#### Brute Force Attacks

其特征是存在多条 EventID 4625 records；如果 attack 成功，之后会出现 EventID 4624。

#### Time Change

由 EventID 4616 记录；system time 的更改可能使 forensic analysis 变得复杂。

#### USB Device Tracking

用于 USB device tracking 的有用 System EventIDs 包括：用于首次使用的 20001/20003/10000、用于 driver updates 的 10100，以及 DeviceSetupManager 生成的、用于记录 insertion timestamps 的 EventID 112。

#### System Power Events

EventID 6005 表示 system startup，EventID 6006 表示 system shutdown。

#### Log Deletion

Security EventID 1102 表示 logs 被删除，这是 forensic analysis 中的关键 event。

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
