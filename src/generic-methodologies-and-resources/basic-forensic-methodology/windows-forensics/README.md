# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## 通用 Windows Artifacts

### Windows 10 通知

每个用户的通知数据库位于 `%LOCALAPPDATA%\Microsoft\Windows\Notifications` 下（例如，`C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`）。早期的 Windows 10 版本使用 `appdb.dat`；Anniversary Update (1607) 引入了 `wpndatabase.db`。该 SQLite 数据库包含 `Notification` 表，其中有通知 payload 和时间字段，但数据保留情况及可用数据会因版本和清理策略而异。<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline 是一项活动历史记录功能，可包含受支持的应用程序、文档及其他用户活动的记录；其覆盖范围取决于应用程序和 Windows 版本。<sup>[[4]](#references)</sup>

数据库位于 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。可以使用 SQLite 打开，或使用 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 进行解析，其输出可使用 [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) 查看。<sup>[[4]](#references)[[5]](#references)</sup>

### ADS（Alternate Data Streams）

从本地信任边界外下载的文件可能包含 **`Zone.Identifier` alternate data stream**，它会记录 zone 信息，并可能包含 URL 等来源元数据。其存在及字段取决于生成者和系统策略。<sup>[[6]](#references)</sup>

## **文件备份**

### 回收站

在 Vista 及更高版本中，**Recycle Bin** 位于驱动器根目录下的 **`$Recycle.bin`** 文件夹中（例如，`C:\$Recycle.bin`）。\
当文件在此文件夹中被删除时，会创建两个特定文件：

- `$I{id}`：文件信息，包括删除时间和原始路径
- `$R{id}`：文件内容

![文件备份 - 回收站：$R{id}：文件内容](<../../../images/image (1029).png>)

获得这些文件后，可以使用 [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) 提取原始路径和删除时间（请使用适用于目标 Windows 版本的版本）。<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![文件备份 - 回收站：rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) 可以在文件正在使用时创建卷的时间点快照；shadow copy 不能替代 forensic image。<sup>[[8]](#references)</sup>

副本元数据通常与卷根目录中的 `\System Volume Information` 关联，其标识符因系统而异：

![回收站 - Volume Shadow Copies：这些备份通常位于文件系统根目录的 System Volume Information 中，名称由图中显示的 UID 组成](<../../../images/image (94).png>)

使用合适的 forensic mounter 挂载 image 后，[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) 可以枚举可用的 VSS snapshots，并浏览或复制其中的文件。<sup>[[9]](#references)</sup>

![回收站 - Volume Shadow Copies：使用 ArsenalImageMounter 挂载 forensic image 后，可以使用 ShadowCopyView 检查 shadow copy，甚至提取文件](<../../../images/image (576).png>)

VSS registry writer 配置包括 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`，其中可以指定从 backup 中排除的文件和 keys：<sup>[[10]](#references)[[11]](#references)</sup>

![回收站 - Volume Shadow Copies：registry 项 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore 包含不进行 backup 的文件和 keys](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key 也包含 VSS service 配置。<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover 位置因 Office application、版本和配置而异。对于 Word，Microsoft 将 `%APPDATA%\Microsoft\Word` 记录为默认位置；请检查 application settings 以确定当前路径。<sup>[[12]](#references)</sup>

## Shell Items

Shell item 是包含如何访问另一个文件相关信息的 item。

### Recent Documents (LNK)

当用户打开或以其他方式访问某个 item 时，Windows 通常会创建 recent-item shortcuts：

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

访问文件夹也可能为该文件夹及其相关父文件夹创建 links。

这些 link files 可以包含 target type、target MAC times、volume information 和 target path。这些 metadata 可能有助于识别已删除的 target，但该 artifact 本身不能证明 target 曾由特定用户打开。<sup>[[13]](#references)[[14]](#references)</sup>

LNK 自身的 filesystem timestamps 与其嵌入的 target timestamps 是不同的。除非有其他 artifacts 佐证，否则不要将 link creation 解释为首次使用，也不要将 link modification 解释为最后使用；该格式会将 target timestamps 与 link file 的 timestamps 分开存储。<sup>[[13]](#references)[[14]](#references)</sup>

现有的 [**LinkParser**](http://4discovery.com/our-tools/) link 作为历史选项保留，但在审查期间无法获取其 documentation。对于有 documentation 的 command-line parser，请使用 [**LECmd**](https://github.com/EricZimmerman/LECmd)。<sup>[[15]](#references)</sup>

这些 tools 通常会显示两组 timestamps：

- **Target timestamps:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-file timestamps:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

第一组指向 target；第二组指向 LNK file 本身。请结合 parser 的 documentation 和 filesystem context 解读这两组 timestamps。<sup>[[14]](#references)[[15]](#references)</sup>

你可以运行 Windows CLI tool：[**LECmd.exe**](https://github.com/EricZimmerman/LECmd) 来获取相同的信息。<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
在此情况下，信息将保存在 CSV 文件中。

### Jumplists

Jump Lists 是按应用程序划分的最近项目或特定任务项目列表，可以是自动创建的，也可以是自定义的。<sup>[[13]](#references)</sup>

Automatic Jump Lists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` 中，并使用类似 `{id}.automaticDestinations-ms` 的名称，其中 ID 用于标识应用程序。

Custom Jump Lists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` 中；由应用程序控制其创建的任务或项目条目。

文件系统创建时间和修改时间描述的是 Jump List 文件，而不是每个列出目标的首次和最后访问时间。应将解析出的条目与文件时间戳及其他 artifacts 进行关联。<sup>[[13]](#references)</sup>

你可以使用 [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) 检查 Jump Lists。<sup>[[5]](#references)</sup>

![最近文档 (LNK) - Jumplists：你可以使用 JumplistExplorer 检查 jumplists](<../../../images/image (168).png>)

(_请注意，JumplistExplorer 提供的时间戳与 jumplist 文件本身相关_)

### Shellbags

[**点击此链接了解 shellbags。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 的使用

USB 的使用有时可以通过访问可移动介质上的文件时创建的 artifacts 得到佐证，包括：

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) 等工具可以将这些 artifacts 与 USB 设备记录进行关联，但 artifact 是否可用取决于 Windows 版本和应用程序。<sup>[[18]](#references)</sup>

在针对 Windows XP 和 Windows 7 MTP 工作流记录的测试中，一些 LNK 指向的是 `WPDNSE` 文件夹，而不是原始路径。<sup>[[16]](#references)</sup>

![Shellbags - Windows USB 的使用：请注意，某些 LNK 文件并未指向原始路径，而是指向 WPDNSE 文件夹](<../../../images/image (218).png>)

该研究观察到 `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` 下存在副本；在其测试中，临时内容在重启后不会保留，并且 GUID 可以与 shellbag 数据进行关联。应将其视为依赖操作系统、设备和应用程序的行为，而非普遍规则。<sup>[[16]](#references)</sup>

### Registry Information

[查看此页面以了解](interesting-windows-registry-keys.md#usb-information)哪些 registry keys 包含有关已连接 USB 设备的有用信息。

### setupapi

在 Vista 及更高版本中，检查 `C:\Windows\inf\setupapi.dev.log` 以了解设备安装活动。Section headers 包含 `Section start` 时间戳；它们记录 setup 处理过程，应与其他连接证据进行关联，而不应被视为精确的物理插入时间。<sup>[[17]](#references)</sup>

![Registry Information - setupapi：检查文件 C: Windows inf setupapi.dev.log 以获取 USB 连接发生时间的时间戳（搜索 Section start）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

可以使用 [**USBDetective**](https://usbdetective.com) 获取已连接到 image 的 USB 设备信息。<sup>[[18]](#references)</sup>

![setupapi - USB Detective：USBDetective 可用于获取已连接到 image 的 USB 设备信息](<../../../images/image (452).png>)

### Plug and Play Cleanup

名为 `Plug and Play Cleanup` 的 scheduled task 会删除过时的 driver 版本。Adam Harrison 记录的一个 Windows 10 task definition 还会针对 30 天未活动的 drivers，因此可移动设备的 driver 证据可能会被清理；在概括此行为之前，应确认本地 task definition 和 Windows build。<sup>[[1]](#references)</sup>

该 task 位于以下路径：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

**该 Task 的关键组件和设置：**

- **pnpclean.dll**：此 DLL 负责实际的清理过程。
- **UseUnifiedSchedulingEngine**：设置为 `TRUE`，表示使用通用 task scheduling engine。
- **MaintenanceSettings**：
- **Period ('P1M')**：指示 Task Scheduler 在常规 Automatic maintenance 期间每月启动清理 task。
- **Deadline ('P2M')**：如果 task 连续两个月失败，则指示 Task Scheduler 在 emergency Automatic maintenance 期间执行该 task。

此配置安排定期维护，并在连续失败后重试；具体 XML 和行为取决于版本。<sup>[[1]](#references)</sup>

**更多信息请查看：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)。<sup>[[1]](#references)</sup>

## Emails

Emails 包含 **2 个有用部分：email 的 headers 和 content**。在 **headers** 中可以找到以下信息：

- **谁**发送了 emails（email address、IP、重定向 email 的 mail servers）
- **何时**发送了 email

此外，`References` 和 `In-Reply-To` headers 可以携带用于将回复与会话关联的 message IDs。<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails：email 是何时发送的](<../../../images/image (593).png>)

### Windows Mail App

此应用程序将 email content 保存为 auxiliary text 或 HTML 文件，路径类似于 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`；具体的编号文件夹和文件布局可能因 artifact 而异。<sup>[[75]](#references)</sup>

Emails 的 **metadata** 和 **contacts** 可以在 **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 中找到。<sup>[[75]](#references)</sup>

`store.vol` 使用 Extensible Storage Engine (ESE) 格式。应在副本上进行操作，并使用 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 等 ESE parser；如果某个 tool 要求使用 `.edb` 后缀，只重命名副本，并在依赖 `Message` table 之前验证 table schema。<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

检查 Outlook MAPI properties 时，canonical properties 包括：

- `PidTagClientSubmitTime`：client 提交 message 的 UTC 时间。
- `PidTagConversationIndex`：message 在 conversation thread 中的相对位置。
- `PidTagEntryId`：message object 的 identifier。
- `PidTagMessageFlags`：表示已提交、已读、未读或包含 attachments 等状态的 flags。
- `PidTagLastVerbExecuted`：为 message 记录的最后一个操作，例如 open、reply 或 forward。<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file 的位置因版本和 account type 而异。Microsoft 记录了以下 PST/OST 文件的常见位置：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` 可能标识 Outlook profile 及关联的 data-file 配置。

PST 文件可以包含 messages、contacts、calendar data 以及其他 Outlook items。你可以使用 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) 检查副本。<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook：你可以使用 Kernel PST Viewer tool 打开 PST 文件](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** 是 Exchange 或 Microsoft 365 accounts 的本地 cache；Cached Exchange Mode 不适用于 POP 或 IMAP accounts。offline period 可配置，默认通常为 12 个月，而 PST/OST size limits 是独立的可配置设置。要查看 OST file，可以使用 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

丢失的 attachments 可能可以从以下位置恢复：

- 对于 legacy Outlook/IE configurations：`%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- 对于较新的 Outlook/IE11 configurations：`%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`。<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** 将 profile data 存储在 `%APPDATA%\Thunderbird\Profiles` 下；mail folders 通常使用无扩展名的 mbox files，并位于特定 account 的 `Mail` 或 `ImapMail` directories 下。<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**：缩略图预览通常存储在每个 folder 的 `thumbs.db` files 中。
- **Network folders**：当启用相关 thumbnail behavior 时，UNC folder 仍可能创建 `thumbs.db` file；不要假设每个 Windows 版本或 policy 都会创建该文件。
- **Windows Vista 及更高版本**：system thumbnail cache 集中存储在 `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` 下，文件名如 **thumbcache_xxx.db**。[**Thumbsviewer**](https://thumbsviewer.github.io) 可以解析 legacy `Thumbs.db`，而 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) 可以解析 modern thumbnail-cache databases。<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Windows Registry 存储 system 和 user configuration data，并包含在以下位置的 hive files 中：

- `%WINDIR%\System32\Config`：用于存储支持各种 `HKEY_LOCAL_MACHINE` subkeys 的 machine hives。
- `%USERPROFILE%\NTUSER.DAT`：用户的 `HKEY_CURRENT_USER` hive。
- 一些较旧的 Windows installations 在 `%WINDIR%\System32\Config\RegBack\` 中包含副本；Windows 10 version 1803 及更高版本不会自动填充此 directory，除非启用了 periodic backup。<sup>[[34]](#references)[[35]](#references)</sup>
- 在 modern Windows 中，每个用户的 shell 和 class-registration data 通常也存储在 `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` 中。<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

一些 tools 可用于分析 registry hives；在依赖输出之前，应确认每个 tool 支持的 hive formats 和 version：

- **Registry Editor**：Windows 中已安装。它是一个 GUI，用于浏览当前 session 的 Windows registry。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：允许你加载 registry file，并通过 GUI 浏览其中内容。它还包含 Bookmarks，用于突出显示包含有用信息的 keys。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样提供 GUI，允许浏览已加载的 registry，并包含用于突出显示已加载 registry 中有用信息的 plugins。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：另一个能够从已加载 registry hive 中提取信息的 GUI application。<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

已删除的 hive cells 可能会一直保留到其空间被重新使用，但恢复结果取决于 hive 状态和 parser；应将恢复的 deleted keys 视为需要验证的 evidence，而不是保证准确的 records。

### Last Write Time

Registry keys 带有 last-write timestamp；Windows 会为 key 或其 value entries 中的任意一个公开该时间，因此某个 value 不一定具有独立的 modification timestamp。<sup>[[69]](#references)</sup>

### SAM

**SAM** hive 包含本地 user 和 group account data，包括由 system 的 boot-key material 保护的 password hashes。<sup>[[38]](#references)[[39]](#references)</sup>

在 `SAM\Domains\Account\Users` 中可以获取 account identifiers 以及部分 logon 和 policy fields。离线 hash extraction 还需要 `SYSTEM` hive，以恢复相关的 boot-key material。<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry 中的有用条目


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

现有的[关于常见 Windows processes 的文章](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)作为补充阅读内容保留；任何 process behavior 声明都应通过最新的 Windows documentation 和本地 evidence 进行佐证。<sup>[[2]](#references)</sup>

### Windows Recent APPs

在提供该功能的 Windows 10 versions 中，`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` 包含按 application 划分的 subkeys，其中有 last-used time 和 launch count 等 fields；该 artifact 已从后续 releases 中移除，因此应验证目标 build。<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

在提供 Background Activity Moderator 的 systems 中，检查 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 或较新的 `...\bam\State\UserSettings\{SID}` path。Values 以 user SID 为 key，并可能包含被跟踪的 executable paths 和类似 FILETIME 的 execution data；该 artifact 取决于 version，应与其他 evidence 进行佐证。<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch 会缓存 resources 和 launch metadata，使 programs 能够更快启动。

Prefetch files 以 `.pf` files 的形式存储在 `C:\Windows\Prefetch` 中；其 format、retention 和 file-count limits 因 Windows version 而异。Microsoft 记录了 Windows 8 及更高版本会保留最近八次 execution times 以及最多 1024 个 files，因此不应将较早的固定 limit summaries 泛化。<sup>[[13]](#references)</sup>

文件名通常使用 `{program_name}-{hash}.pf` 格式，其中 hash 根据 path 和 arguments 等 execution context 生成；Windows 10 及更高版本可能会压缩该文件。文件存在可以作为 execution evidence，但其本身不能证明是用户执行的，应与其他 artifacts 进行关联。<sup>[[13]](#references)</sup>

要检查这些 files，可以使用 [**PECmd.exe**](https://github.com/EricZimmerman/PECmd)；该 tool 记录了 directory parsing、CSV/HTML output，以及对适用的 Windows 10 Prefetch files 的 decompression support。<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** 通过使用历史使用模式来改善加载，从而补充 Prefetch。在会生成这些文件的系统上，其数据库文件通常位于 `C:\Windows\Prefetch\Ag*.db`；其格式和是否存在取决于系统版本。<sup>[[41]](#references)</sup>

这些数据库可能包含应用程序名称、使用次数、访问过的文件或卷、路径以及时间范围，但不应将其视为精确的执行日志。<sup>[[41]](#references)</sup>

现有的 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 链接作为可能的解析器保留；使用前请根据该工具的文档确认其当前可用性和支持的输出格式。

### SRUM

**System Resource Usage Monitor**（SRUM）记录应用程序和用户的资源使用情况。它在 Windows 8 中引入，并将数据存储在 ESE 数据库 `C:\Windows\System32\sru\SRUDB.dat` 中。<sup>[[13]](#references)</sup>

它提供以下信息：

- AppID 和路径
- 与记录关联的用户/SID
- 发送字节数
- 接收字节数
- 网络接口
- 连接持续时间
- 进程持续时间

数据收集频率和保留期限取决于具体实现；不要假设每条记录都代表一个精确的 60 分钟执行时间间隔。<sup>[[13]](#references)</sup>

你可以使用 [**srum_dump**](https://github.com/MarkBaggett/srum-dump) 提取和查看数据，具体选项请以当前工具版本记录的文档为准。<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**（也称为 **ShimCache**）是 Windows 应用程序兼容性基础设施的一部分，用于记录文件元数据以支持兼容性决策。hive 路径、记录格式、保留容量和字段会因 Windows 版本而异；在现代 Windows 中，单凭 ShimCache 无法证明用户执行过某个文件。请使用 [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) 解析相关的 `SYSTEM` hive，并结合其他执行痕迹对其输出进行佐证。<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache)：建议使用 AppCompatCacheParser tool 解析存储的信息](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 文件是一个注册表 hive，用于记录 Windows 观察到的应用程序和文件。它通常位于 `C:\Windows\AppCompat\Programs\Amcache.hve`。

其中可能包含有关联和无关联的文件条目、路径以及 SHA1 值，但它的存在只能作为清单证据，本身不能证明某个进程曾执行过。<sup>[[13]](#references)[[44]](#references)</sup>

要提取和分析 **Amcache.hve**，请使用 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool。此命令会解析该 hive 并写入 CSV 输出。<sup>[[44]](#references)</sup>

例如：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
在生成的 CSV 文件中，`Amcache_Unassociated file entries` 在调查与已识别程序不关联的文件时可能很有用。<sup>[[44]](#references)</sup>

### RecentFileCache

在 Windows 7 系统上，`C:\Windows\AppCompat\Programs\RecentFileCache.bcf` 可能包含近期观测到的 binaries 信息；其可用性和含义取决于版本。

你可以使用 [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) 解析该文件。<sup>[[45]](#references)</sup>

### 计划任务

现代任务的计划任务证据可能位于 `C:\Windows\System32\Tasks`，旧版任务则可能位于包含 `.job` 文件的 `C:\Windows\Tasks`；应根据操作系统检查相应的任务定义格式。<sup>[[73]](#references)[[74]](#references)</sup>

### 服务

Service Control Manager 数据库位于 `SYSTEM\CurrentControlSet\Services`（对于离线 SYSTEM hive，应检查对应的 control-set key）；其中包含服务和驱动程序配置，例如可执行文件路径和启动类型。<sup>[[72]](#references)</sup>

### **Windows Store**

已安装的 Windows Store 应用可能记录在 `\ProgramData\Microsoft\Windows\AppRepository\` 下，其中包括数据库 **`StateRepository-Machine.srd`**。其 schema 和路径会因 Windows 版本而异。<sup>[[71]](#references)</sup>

该数据库可能包含应用标识符、package numbers 和显示名称。标识符中的间隔本身并不能证明应用已被卸载；应结合 package 和 registry 状态进行佐证。

Package registrations 也可能出现在 `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` 下。Microsoft 记录了针对已移除 provisioned apps 的特定版本 `Deprovisioned` subkey；不要假设每个 build 都存在 `Deleted` subkey。<sup>[[70]](#references)</sup>

## Windows Events

根据 provider 的不同，Windows events 可能包含：

- 发生了什么
- `TimeCreated` timestamp，必须结合 event schema 和主机时间上下文进行解释
- 涉及的用户
- 涉及的主机（hostname、IP）
- 被访问的 assets（files、folders、printers 或 services）。<sup>[[49]](#references)</sup>

在 Windows Vista 之前，event logs 通常使用位于 `C:\Windows\System32\config` 下的旧版 binary format；Vista 及更高版本使用 Windows Event Log format，通常位于 `C:\Windows\System32\winevt\Logs` 下，其中 `.evtx` 文件包含以 XML 呈现的 event data。<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry 在 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** 下存储 channel configuration，包括配置的文件路径和 retention settings。<sup>[[47]](#references)</sup>

可以使用 Windows Event Viewer（**`eventvwr.msc`**）或 [**Event Log Explorer**](https://eventlogxp.com)、[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) 等工具查看这些内容。<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

在 Vista 及更高版本中，Security channel 通常存储于 `C:\Windows\System32\winevt\Logs\Security.evtx`。其最大大小和 retention policy 可配置；在 circular logging 下，当文件达到限制时，较旧的 records 可能被覆盖。当启用相关 auditing 时，该 channel 可以记录 authentication、logoff、privilege、audit-policy 和 object-access events。<sup>[[46]](#references)[[47]](#references)</sup>

### 用户身份验证的关键 Event IDs：

- **Event ID 4624**：账户成功 logon。<sup>[[50]](#references)</sup>
- **Event ID 4625**：账户 logon 失败。<sup>[[51]](#references)</sup>
- **Event ID 4634**：logon session 已终止。<sup>[[52]](#references)</sup>
- **Event ID 4647**：用户发起了 logoff。<sup>[[53]](#references)</sup>
- **Event ID 4672**：为新的 logon 分配了特殊权限；system 和 administrator accounts 经常出现此事件，因此该事件本身不能证明存在恶意活动。<sup>[[54]](#references)</sup>

#### 4624、4625、4634 和 4647 中常记录的 logon types：

- **Interactive (2)**：交互式本地 logon。
- **Network (3)**：访问 shared resource。
- **Batch (4)**：batch-process logon。
- **Service (5)**：service logon。
- **Unlock (7)**：workstation unlock。
- **NetworkCleartext (8)**：向 authentication package 以 cleartext 提供 credentials 的 network logon。
- **NewCredentials (9)**：使用提供的 alternate credentials 进行 outbound connections 的 logon。
- **RemoteInteractive (10)**：Remote Desktop 或 Terminal Services logon。
- **CachedInteractive (11)**：使用 cached domain credentials 的交互式 logon。
- **CachedRemoteInteractive (12)**：cached remote-interactive logon。
- **CachedUnlock (13)**：使用 cached credentials 的 unlock。<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625 的 Status 和 Sub Status Codes：

- **0xC0000064**：不存在此用户。
- **0xC000006A**：用户名正确，但 password 错误。
- **0xC0000234**：账户已被锁定。
- **0xC0000072**：账户已禁用。
- **0xC000006F**：在允许的时间之外进行 logon。
- **0xC0000070**：违反 workstation restriction。
- **0xC0000193**：账户已过期。
- **0xC0000071**：password 已过期。
- **0xC0000133**：client 和 server 的时间差过大。
- **0xC0000224**：账户必须更改其 password。
- **0xC0000225**：`STATUS_NOT_FOUND`；单凭此 code 无法确定是 system bug 还是 attack。
- **0xC000015B**：账户未被授予请求的 logon type。<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616：

- **Time Change**：system time 发生了更改。许多 events 反映的是常规的 time-service correction，因此在将其视为 tampering 之前，应关联 actor 和 time source。<sup>[[56]](#references)</sup>

#### Event IDs 12、13、1074、6005、6006、6008 和 6009：

- **Power and service context**：Event 12 记录 OS start，13 记录 OS shutdown，1074 记录计划中的 shutdown 或 restart，6008 表示 unexpected shutdown，6009 记录启动时的 Windows version。Events 6005 和 6006 分别表示 Event Log service started 和 stopped；它们本身不能证明 OS startup 和 shutdown。<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102：

- **Log Deletion**：Event 1102 记录 Security audit log 已被清除；应调查 actor 和周边 events，而不是仅根据此 event 假定其意图。<sup>[[62]](#references)</sup>

#### 用于 USB Device Tracking 的 EventIDs：

- **20001 / 20003**：`UserPnp` device-installation events，可帮助确定首次使用或安装活动。
- **10000 / 10100**：`DriverFrameworks-UserMode` events，可能伴随 device activity 出现。
- **Event ID 112**：`DeviceSetupManager/Admin` activity，可提供与插入相关的 timestamps。
- Provider、channel 和 event semantics 会因 Windows 版本而异；在赋予其含义之前，应检查 provider name 和 event payload。<sup>[[59]](#references)</sup>

有关 logon types 及其关联 credential material 的实际示例，请参阅 [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)。<sup>[[60]](#references)</sup>

Event details，包括 logon type、status、substatus、source address 和 process fields，可为 Event ID 4625 提供上下文；status code 或 repeated failure pattern 是调查线索，而不是结论。<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

由于 event logs 通常采用 circular 方式，已被 logger 覆盖的 records 可能无法恢复。在与 live system 交互之前，应保留 forensic image 或 working copy；仅在确认工具版本支持目标 `.evtx` data 后，才使用经过验证的 parser 或 carver，例如 **Bulk_extractor**，并且不要仅为尝试恢复 events 而拔掉正在运行的 system。<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

有关实用的 event-ID reference，请参阅现有的 [Red Team Recipe](https://redteamrecipe.com/event-codes/) link，并根据上文的 provider documentation 验证其中的示例。

#### Brute Force Attacks

将重复的 Event ID 4625 failures 与之后的 4624 success、logon type、status、source 和 account context 进行关联；该 sequence 是用于调查的 indicator，而不是 attack 的证据。<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 记录 system-time changes，可能使 timeline analysis 变得复杂；应将其与 time-service 和 host evidence 进行比较。<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs 特定于 provider；应将 `UserPnp` 20001/20003、`DriverFrameworks-UserMode` 10000/10100 和 `DeviceSetupManager/Admin` 112 与 SetupAPI 和 registry artifacts 进行关联。<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

使用 12/13/1074/6008/6009 获取 OS start、shutdown、restart 和 unexpected-power context；6005/6006 标记 Event Log service start/stop。<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 记录 Security audit log 已被清除，应与 responsible account 和 process 进行关联。<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 调查常见 Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Notifications 的 Digital Forensic View](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier 和 Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS 下的 Registry backup and restore operations](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [用于 backup and restore 的 Registry keys](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover location 上的 Word performance issue](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: 识别 Data Exfiltration Artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID and Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [查找和 transfer Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Turn on Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Only a subset of items is synchronized](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configure size limits for Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird 存储用户数据的位置](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings and mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry not backed up to RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Remotely edit the registry](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [使用 system event logs 排查 unexpected reboots](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Troubleshoot shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print stops printing PDF attachments in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Keep removed apps from returning during an update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK and Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigating the Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
