# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## 通用 Windows Artifacts

### Windows 10 Notifications

在路径 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` 中，可以找到数据库 `appdb.dat`（Windows anniversary 之前）或 `wpndatabase.db`（Windows Anniversary 之后）。

在此 SQLite 数据库中，可以找到包含所有通知的 `Notification` 表，这些通知采用 XML 格式，可能包含有价值的数据。

### Timeline

Timeline 是 Windows 的一项特性，用于提供访问过的网页、编辑过的文档以及执行过的应用程序的**时间顺序历史记录**。

数据库位于路径 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。可以使用 SQLite 工具打开此数据库，也可以使用工具 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 打开。该工具**会生成 2 个可使用工具** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **打开的文件**。

### ADS (Alternate Data Streams)

下载的文件可能包含 **ADS Zone.Identifier**，用于指示该文件是从内网、互联网等位置**如何被下载**的。一些软件（例如浏览器）通常还会添加**更多**信息，例如文件下载来源的 **URL**。

## **文件备份**

### 回收站

在 Vista/Win7/Win8/Win10 中，可以在驱动器根目录的 **`$Recycle.bin`** 文件夹中找到**回收站**（`C:\$Recycle.bin`）。\
当文件在此文件夹中被删除时，会创建 2 个特定文件：

- `$I{id}`：文件信息（删除日期}
- `$R{id}`：文件内容

![文件备份 - 回收站：$R{id}：文件内容](<../../../images/image (1029).png>)

有了这些文件后，可以使用工具 [**Rifiuti**](https://github.com/abelcheung/rifiuti2) 获取已删除文件的原始路径和删除日期（Vista – Win10 请使用 `rifiuti-vista.exe`）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![文件备份 - 回收站：rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy 是 Microsoft Windows 中包含的一项技术，可以创建计算机文件或卷的**备份副本**或快照，即使这些文件或卷正在使用中。

这些备份通常位于文件系统根目录下的 `\System Volume Information` 中，其名称由下图所示的 **UIDs** 组成：

![回收站 - Volume Shadow Copies：这些备份通常位于文件系统根目录下的 System Volume Information 中，其名称由图中所示的 UIDs 组成](<../../../images/image (94).png>)

使用 **ArsenalImageMounter** 挂载 forensic image 后，可以使用 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) 检查 shadow copy，甚至从 shadow copy 备份中**提取文件**。

![回收站 - Volume Shadow Copies：使用 ArsenalImageMounter 挂载 forensic image 后，可以使用 ShadowCopyView 检查 shadow copy，甚至从 shadow copy 备份中提取文件](<../../../images/image (576).png>)

注册表项 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` 包含**不进行备份**的文件和键：

![回收站 - Volume Shadow Copies：注册表项 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore 包含不进行备份的文件和键](<../../../images/image (254).png>)

注册表 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` 也包含有关 `Volume Shadow Copies` 的配置信息。

### Office AutoSaved Files

可以在以下位置找到 Office 自动保存的文件： `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item 是包含如何访问另一个文件相关信息的项目。

### Recent Documents (LNK)

当用户在以下位置**打开、使用或创建文件**时，Windows 会**自动****创建**这些**快捷方式**：

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

创建文件夹时，也会创建指向该文件夹、父文件夹和祖父文件夹的链接。

这些自动创建的链接文件包含有关源对象的信息，例如它是**文件**还是**文件夹**、该文件的 **MAC** **时间**、文件存储位置的**卷信息**以及**目标文件所在的文件夹**。如果这些文件已被删除，这些信息有助于恢复它们。

此外，链接文件的**创建日期**是原始文件**首次****使用**的**时间**，而链接文件的**修改日期**是源文件**最后****使用**的**时间**。

可以使用 [**LinkParser**](http://4discovery.com/our-tools/) 检查这些文件。

在此工具中，可以找到 **2 组**时间戳：

- **第一组：**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **第二组：**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate。

第一组时间戳指的是**文件本身的时间戳**。第二组指的是**链接文件的时间戳**。

也可以运行 Windows CLI 工具获取相同的信息：[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
在这种情况下，信息将保存到 CSV 文件中。

### Jumplists

这些是按应用程序列出的最近文件，即你可以在每个应用程序中访问的**应用程序最近使用的文件**列表。它们可以**自动创建，也可以自定义创建**。

自动创建的 **jumplists** 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`。jumplists 按照 `{id}.autmaticDestinations-ms` 格式命名，其中开头的 ID 是应用程序的 ID。

自定义 jumplists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`，通常由应用程序创建，因为文件发生了某些**重要事件**（可能被标记为收藏）。

任何 jumplist 的**创建时间**表示**文件首次被访问的时间**，而**修改时间表示最后一次访问的时间**。

你可以使用 [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) 检查 jumplists。

![Recent Documents (LNK) - Jumplists：你可以使用 JumplistExplorer 检查 jumplists](<../../../images/image (168).png>)

(_注意，JumplistExplorer 提供的时间戳与 jumplist 文件本身相关_)

### Shellbags

[**访问此链接了解 shellbags。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 的使用情况

可以通过以下内容的创建来确认某个 USB 设备曾被使用：

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

注意，某些 LNK 文件并不指向原始路径，而是指向 WPDNSE 文件夹：

![Shellbags - Windows USB 的使用情况：注意，某些 LNK 文件并不指向原始路径，而是指向 WPDNSE 文件夹](<../../../images/image (218).png>)

WPDNSE 文件夹中的文件是原始文件的副本，因此重启 PC 后它们将不会保留，而 GUID 取自 shellbag。

### Registry Information

[访问此页面了解](interesting-windows-registry-keys.md#usb-information)哪些注册表项包含有关已连接 USB 设备的有用信息。

### setupapi

检查文件 `C:\Windows\inf\setupapi.dev.log`，获取 USB 连接建立时的时间戳（搜索 `Section start`）。

![Registry Information - setupapi：检查文件 C: Windows inf setupapi.dev.log，获取 USB 连接建立时的时间戳（搜索 Section start）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

可以使用 [**USBDetective**](https://usbdetective.com) 获取有关已连接到某个镜像的 USB 设备的信息。

![setupapi - USB Detective：USBDetective 可用于获取有关已连接到某个镜像的 USB 设备的信息](<../../../images/image (452).png>)

### Plug and Play Cleanup

名为“Plug and Play Cleanup”的计划任务主要用于删除过时的驱动程序版本。与其规定的保留最新驱动程序包版本的用途相反，在线资料表明它还会处理已 inactive 30 天的驱动程序。因此，过去 30 天内未连接的可移动设备驱动程序可能会被删除。<sup>[[1]](#references)</sup>

该任务位于以下路径：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

以下截图展示了该任务的内容：![USB Detective - Plug and Play Cleanup：该任务位于以下路径：C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**任务的主要组件和设置：**

- **pnpclean.dll**：该 DLL 负责实际的清理过程。
- **UseUnifiedSchedulingEngine**：设置为 `TRUE`，表示使用通用任务调度引擎。
- **MaintenanceSettings**：
- **Period ('P1M')**：指示 Task Scheduler 在定期 Automatic maintenance 期间每月启动清理任务。
- **Deadline ('P2M')**：如果任务连续两个月失败，则指示 Task Scheduler 在紧急 Automatic maintenance 期间执行该任务。

此配置确保定期维护和清理驱动程序，并在任务连续失败时重新尝试执行。

**如需更多信息，请查看：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Emails 包含**两个有用的部分：headers 和 email 内容**。在 **headers** 中可以找到以下信息：

- 发送 Emails 的**人员**（email address、IP、重定向该 email 的 mail servers）
- Email 的发送**时间**

此外，还可以在 `References` 和 `In-Reply-To` headers 中找到消息的 ID：

![Plug and Play Cleanup - Emails：Email 的发送时间](<../../../images/image (593).png>)

### Windows Mail App

该应用程序以 HTML 或文本格式保存 Emails。你可以在 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 下的子文件夹中找到这些 Emails。Emails 使用 `.dat` 扩展名保存。

Emails 的 **metadata** 和 **contacts** 可以在 **EDB database** 中找到：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

将文件扩展名从 `.vol` **更改**为 `.edb`，然后可以使用工具 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 打开它。在 `Message` 表中可以查看 Emails。

### Microsoft Outlook

使用 Exchange servers 或 Outlook clients 时，会存在一些 MAPI headers：

- `Mapi-Client-Submit-Time`：Email 发送时的系统时间
- `Mapi-Conversation-Index`：线程中的子消息数量，以及线程中每条消息的时间戳
- `Mapi-Entry-ID`：消息标识符。
- `Mappi-Message-Flags` 和 `Pr_last_Verb-Executed`：有关 MAPI client 的信息（消息已读？未读？已回复？已重定向？是否 out of the office？）

在 Microsoft Outlook client 中，所有已发送/已接收的消息、contacts 数据和 calendar 数据都存储在 PST 文件中，位置为：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

注册表路径 `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` 指示正在使用的文件。

你可以使用工具 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) 打开 PST 文件。

![Windows Mail App - Microsoft Outlook：你可以使用工具 Kernel PST Viewer 打开 PST 文件](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

当 Microsoft Outlook 配置为使用 **IMAP** 或 **Exchange** server 时，会生成 **OST file**，其中存储与 PST file 类似的信息。该文件与 server 同步，保留**最近 12 个月**的数据，**最大大小为 50GB**，并位于与 PST file 相同的目录中。可以使用 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) 查看 OST file。

### Retrieving Attachments

丢失的 attachments 可能可以从以下位置恢复：

- 对于 **IE10**：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- 对于 **IE11 及更高版本**：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** 使用 **MBOX files** 存储数据，位置为 `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`。

### Image Thumbnails

- **Windows XP 和 8-8.1**：访问包含 thumbnails 的文件夹会生成 `thumbs.db` 文件，用于存储图像预览，即使图像已被删除，预览仍可能存在。
- **Windows 7/10**：通过 UNC path 在 network 上访问文件夹时会创建 `thumbs.db`。
- **Windows Vista 及更高版本**：Thumbnail previews 集中存储在 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` 中，文件名为 **thumbcache_xxx.db**。[**Thumbsviewer**](https://thumbsviewer.github.io) 和 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) 可用于查看这些文件。

### Windows Registry Information

Windows Registry 存储大量 system 和 user activity 数据，包含在以下文件中：

- `%windir%\System32\Config`，用于各种 `HKEY_LOCAL_MACHINE` 子项。
- `%UserProfile%{User}\NTUSER.DAT`，用于 `HKEY_CURRENT_USER`。
- Windows Vista 及更高版本会在 `%Windir%\System32\Config\RegBack\` 中备份 `HKEY_LOCAL_MACHINE` registry files。
- 此外，从 Windows Vista 和 Windows 2008 Server 开始，program execution information 存储在 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` 中。

### Tools

一些工具可用于分析 registry files：

- **Registry Editor**：Windows 中已安装该工具。它是一个用于浏览当前 session 的 Windows registry 的 GUI。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：允许你加载 registry file，并通过 GUI 浏览其中的内容。它还包含 Bookmarks，用于突出显示包含有用信息的 keys。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样提供 GUI，可浏览已加载的 registry，并包含用于突出显示已加载 registry 中有用信息的 plugins。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：另一个能够从已加载的 registry 中提取重要信息的 GUI application。

### Recovering Deleted Element

删除 key 时，它会被标记为已删除；但在其占用的空间被需要之前，它不会被移除。因此，使用 **Registry Explorer** 等工具可以恢复这些已删除的 keys。

### Last Write Time

每个 Key-Value 都包含一个**时间戳**，表示其最后一次被修改的时间。

### SAM

**SAM** file/hive 包含系统的 **users、groups 和 users passwords** hashes。

在 `SAM\Domains\Account\Users` 中，可以获取 username、RID、last login、last failed logon、login counter、password policy 以及 account 创建时间。要获取 **hashes**，还**需要** **SYSTEM** file/hive。

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

在[这篇文章](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)中，你可以了解用于检测可疑行为的常见 Windows processes。<sup>[[2]](#references)</sup>

### Windows Recent APPs

在 registry `NTUSER.DAT` 的路径 `Software\Microsoft\Current Version\Search\RecentApps` 中，可以找到包含以下信息的 subkeys：**已执行的 application**、上次执行的**时间**以及启动该 application 的**次数**。

### BAM (Background Activity Moderator)

你可以使用 registry editor 打开 `SYSTEM` file，然后在路径 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 中找到每个 user **执行过的 applications** 信息（注意路径中的 `{SID}`），以及它们的**执行时间**（该时间位于 registry 的 Data value 中）。

### Windows Prefetch

Prefetch 是一种技术，允许计算机静默地**获取显示内容所需的资源**，这些内容是 user **可能在不久的将来访问的**，从而更快地访问资源。

Windows prefetch 会创建**已执行 programs 的 caches**，以便更快地加载它们。这些 caches 以 `.pf` 文件形式创建在路径 `C:\Windows\Prefetch` 中。XP/VISTA/WIN7 中的文件数量限制为 128 个，Win8/Win10 中的限制为 1024 个。

文件名格式为 `{program_name}-{hash}.pf`（hash 基于 executable 的路径和 arguments）。在 W10 中，这些文件经过压缩。请注意，仅文件存在这一事实就表示**该 program 曾在某个时间执行过**。

文件 `C:\Windows\Prefetch\Layout.ini` 包含**已进行 prefetched 的文件所在文件夹名称**。该文件包含有关**执行次数**、执行的**日期**以及 program **打开的** **files** 的信息。

要检查这些文件，可以使用工具 [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)：
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** 的目标与 prefetch 相同，即通过预测接下来要加载的内容来**更快地加载程序**。不过，它不会替代 prefetch service。\
此 service 会在 `C:\Windows\Prefetch\Ag*.db` 中生成数据库文件。

在这些数据库中，你可以找到 **program** 的**名称**、**执行次数**、**打开的文件**、**访问的卷**、**完整路径**、**时间范围**和**时间戳**。

你可以使用工具 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 访问这些信息。

### SRUM

**System Resource Usage Monitor**（SRUM）会**监控**进程**消耗的资源**。它在 W8 中出现，并将数据存储在位于 `C:\Windows\System32\sru\SRUDB.dat` 的 ESE 数据库中。

它提供以下信息：

- AppID 和路径
- 执行该进程的用户
- 发送的字节数
- 接收的字节数
- 网络接口
- 连接持续时间
- 进程持续时间

此信息每 60 分钟更新一次。

你可以使用工具 [**srum_dump**](https://github.com/MarkBaggett/srum-dump) 从此文件中获取日期。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**，也称为 **ShimCache**，是由 **Microsoft** 开发的 **Application Compatibility Database** 的一部分，用于解决应用程序兼容性问题。该系统组件会记录各种文件元数据，包括：

- 文件的完整路径
- 文件大小
- **$Standard_Information** (SI) 中的最后修改时间
- ShimCache 的最后更新时间
- Process Execution Flag

此类数据会根据操作系统版本存储在注册表的特定位置：

- 对于 XP，数据存储在 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` 下，最多可存储 96 条记录。
- 对于 Server 2003，以及 Windows 2008、2012、2016、7、8 和 10，存储路径为 `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`，分别可容纳 512 条和 1024 条记录。

建议使用 [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) 解析存储的信息。

![SRUM - AppCompatCache (ShimCache)：建议使用 AppCompatCacheParser tool 解析存储的信息](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 文件本质上是一个 registry hive，用于记录系统上已执行应用程序的详细信息。它通常位于 `C:\Windows\AppCompat\Programas\Amcache.hve`。

该文件会存储最近执行的进程记录，其中包括可执行文件的路径及其 SHA1 hashes。这些信息对于跟踪系统上应用程序的活动非常有价值。

要从 **Amcache.hve** 中提取并分析数据，可以使用 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool。以下命令示例展示了如何使用 AmcacheParser 解析 **Amcache.hve** 文件的内容，并以 CSV 格式输出结果：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
在生成的 CSV 文件中，`Amcache_Unassociated file entries` 尤其值得关注，因为它提供了有关未关联文件条目的丰富信息。

生成的最有趣的 CSV 文件是 `Amcache_Unassociated file entries`。

### RecentFileCache

此 artifact 只能在 W7 的 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` 中找到，其中包含某些 binaries 最近执行的信息。

你可以使用工具 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) 来解析该文件。

### Scheduled tasks

你可以从 `C:\Windows\Tasks` 或 `C:\Windows\System32\Tasks` 中提取它们，并将其作为 XML 读取。

### Services

你可以在 registry 的 `SYSTEM\ControlSet001\Services` 下找到它们。你可以查看将要执行的内容以及执行时间。

### **Windows Store**

已安装的 applications 可以在 `\ProgramData\Microsoft\Windows\AppRepository\`\
中找到。\
此 repository 在 database **`StateRepository-Machine.srd`** 中记录了系统中**每个已安装 application** 的 **log**。

在该 database 的 Application table 中，可以找到以下 columns："Application ID"、"PackageNumber" 和 "Display Name"。这些 columns 包含 pre-installed 和 installed applications 的信息，并且可以判断某些 applications 是否已被卸载，因为已安装 applications 的 IDs 应该是连续的。

还可以在 registry path `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
中**查找已安装的 application**。\
而**已卸载**的 **applications** 位于：`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows events 中出现的信息包括：

- 发生了什么
- Timestamp (UTC + 0)
- 涉及的 Users
- 涉及的 Hosts (hostname, IP)
- 访问的 Assets (files, folder, printer, services)

在 Windows Vista 之前，logs 位于 `C:\Windows\System32\config`；Windows Vista 之后，位于 `C:\Windows\System32\winevt\Logs`。在 Windows Vista 之前，event logs 使用 binary format；之后则使用 **XML format**，并采用 **.evtx** extension。

event files 的位置可以在 SYSTEM registry 中找到：**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

这些文件可以通过 Windows Event Viewer（**`eventvwr.msc`**）查看，也可以使用 [**Event Log Explorer**](https://eventlogxp.com) **或** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** 等其他 tools 查看。**

## Understanding Windows Security Event Logging

Access events 会记录在位于 `C:\Windows\System32\winevt\Security.evtx` 的 security configuration file 中。此 file 的 size 可以调整；当达到其 capacity 后，较旧的 events 会被覆盖。记录的 events 包括 user logins 和 logoffs、user actions、security settings 的 changes，以及对 files、folders 和 shared assets 的 access。

### Key Event IDs for User Authentication:

- **EventID 4624**：表示 user successfully authenticated。
- **EventID 4625**：表示 authentication failure。
- **EventIDs 4634/4647**：表示 user logoff events。
- **EventID 4672**：表示以 administrative privileges 登录。

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**：直接的 user login。
- **Network (3)**：访问 shared folders。
- **Batch (4)**：执行 batch processes。
- **Service (5)**：service launches。
- **Proxy (6)**：proxy authentication。
- **Unlock (7)**：使用 password 解锁 screen。
- **Network Cleartext (8)**：传输 clear text password，通常来自 IIS。
- **New Credentials (9)**：使用 different credentials 进行 access。
- **Remote Interactive (10)**：remote desktop 或 terminal services login。
- **Cache Interactive (11)**：使用 cached credentials 登录，且不联系 domain controller。
- **Cache Remote Interactive (12)**：使用 cached credentials 进行 remote login。
- **Cached Unlock (13)**：使用 cached credentials 解锁。

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**：User name does not exist - 可能表示 username enumeration attack。
- **0xC000006A**：Correct user name but wrong password - 可能是 password guessing 或 brute-force attempt。
- **0xC0000234**：User account locked out - 可能发生在 brute-force attack 之后，此时通常已有多次 failed logins。
- **0xC0000072**：Account disabled - 表示有人未经授权尝试访问 disabled accounts。
- **0xC000006F**：Logon outside allowed time - 表示尝试在规定 login hours 之外进行 access，可能是 unauthorized access 的迹象。
- **0xC0000070**：Violation of workstation restrictions - 可能是尝试从 unauthorized location 登录。
- **0xC0000193**：Account expiration - 使用 expired user accounts 进行 access attempts。
- **0xC0000071**：Expired password - 使用 outdated passwords 进行 login attempts。
- **0xC0000133**：Time sync issues - client 和 server 之间较大的 time discrepancies 可能表明更复杂的 attacks，例如 pass-the-ticket。
- **0xC0000224**：Mandatory password change required - 频繁的 mandatory changes 可能表明有人试图 destabilize account security。
- **0xC0000225**：表示 system bug，而非 security issue。
- **0xC000015b**：Denied logon type - 使用 unauthorized logon type 进行 access attempt，例如 user 尝试执行 service logon。

#### EventID 4616:

- **Time Change**：修改 system time，可能会掩盖 event timeline。

#### EventID 6005 and 6006:

- **System Startup and Shutdown**：EventID 6005 表示 system starting up，而 EventID 6006 表示 system shutting down。

#### EventID 1102:

- **Log Deletion**：security logs 被清除，这通常是掩盖 illicit activities 的 red flag。

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**：USB device first connection。
- **10100**：USB driver update。
- **EventID 112**：USB device insertion 的 time。

如需实际示例来模拟这些 login types 和 credential dumping opportunities，请参考 [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)。

Event details，包括 status 和 sub-status codes，可以进一步揭示 event causes，在 Event ID 4625 中尤其值得注意。

### Recovering Windows Events

为了提高恢复 deleted Windows Events 的可能性，建议通过直接拔掉电源来关闭 suspect computer。推荐使用指定 `.evtx` extension 的 recovery tool **Bulk_extractor** 尝试恢复此类 events。

### Identifying Common Attacks via Windows Events

如需了解如何使用 Windows Event IDs 识别常见 cyber attacks 的 comprehensive guide，请访问 [Red Team Recipe](https://redteamrecipe.com/event-codes/)。

#### Brute Force Attacks

其特征是存在多条 EventID 4625 records；如果 attack succeeds，随后会出现 EventID 4624。

#### Time Change

由 EventID 4616 记录；system time 的 changes 可能使 forensic analysis 变得复杂。

#### USB Device Tracking

可用于 USB device tracking 的 System EventIDs 包括：用于 initial use 的 20001/20003/10000、用于 driver updates 的 10100，以及来自 DeviceSetupManager、用于记录 insertion timestamps 的 EventID 112。

#### System Power Events

EventID 6005 表示 system startup，而 EventID 6006 表示 shutdown。

#### Log Deletion

Security EventID 1102 表示 logs 被删除，这是 forensic analysis 中的 critical event。

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
