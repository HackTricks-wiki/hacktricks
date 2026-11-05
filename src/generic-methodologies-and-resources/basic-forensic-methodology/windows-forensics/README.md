# Windows 取证痕迹

{{#include ../../../banners/hacktricks-training.md}}

## 通用 Windows 取证痕迹

### Windows 10 通知

每个用户的通知数据库位于 `%LOCALAPPDATA%\Microsoft\Windows\Notifications`（例如，`C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`）。早期 Windows 10 版本使用 `appdb.dat`；Anniversary Update（1607）引入了 `wpndatabase.db`。SQLite 数据库包含 `Notification` 表，其中有通知负载和时间字段，但保留期限和可用数据因版本和清理策略而异。<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline 是一项活动历史记录功能，可包含受支持的应用程序、文档和其他用户活动的记录；其覆盖范围取决于应用程序和 Windows 版本。<sup>[[4]](#references)</sup>

数据库位于 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。可以使用 SQLite 打开，或使用 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 解析，再通过 [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) 查看其输出。<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall 快照（Copilot+ PCs）

在受支持的 Windows 11 Copilot+ PCs 上，Recall 需要用户选择启用。当前版本会使用与 Windows Hello 和 VBS enclave 关联的密钥加密快照及其索引。不要将该存储的离线副本视为明文 SQLite 数据库；2024 年预览版和正式发布版的访问属性有所不同。<sup>[[77]](#references)</sup>

对于**正在运行且已启用 Recall 的会话**，同一用户的 `AIXHost.exe` 渲染进程是另一种访问途径。TotalRecall Reloaded 概念验证会向该进程注入 DLL，并调用其 Recall COM 接口。提取完整历史记录仍需用户通过 Windows Hello 进行身份验证；这不是离线解密，也不是绕过 Hello。研究人员记录了该工具在 Windows 11 ARM64 上的情况，因此在依赖它之前，请先确认其与目标版本兼容。<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` 使用 `GetRecentCaptureThumbnail`，在无需 Windows Hello 的情况下请求最新捕获内容的大尺寸版本。授权后，`--wait` 可以提取屏幕截图、OCR 文本和每次捕获的元数据，包括应用程序和窗口上下文。输出会写入带时间戳的 `extraction_*` 目录中。这些是基于 PoC 的、依赖具体构建版本的发现，并不保证 Recall 已启用，也不保证捕获了每个屏幕。<sup>[[78]](#references)</sup>

### ADS（备用数据流）

从本地信任边界之外下载的文件可能包含 **`Zone.Identifier` 备用数据流**，其中会记录区域信息，也可能包含 URL 等来源元数据。它是否存在及包含哪些字段，取决于生成文件的程序和系统策略。<sup>[[6]](#references)</sup>

## **文件备份**

### 回收站

在 Vista 及更高版本中，**回收站**位于驱动器根目录下的 **`$Recycle.bin`** 文件夹中（例如 `C:\$Recycle.bin`）。\
删除文件时，此文件夹中会创建 2 个特定文件：

- `$I{id}`：文件信息，包括删除时间和原始路径
- `$R{id}`：文件内容

![文件备份 - 回收站：$R{id}：文件内容](<../../../images/image (1029).png>)

有了这些文件，你可以使用 [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) 提取原始路径和删除时间（使用适用于目标 Windows 版本的版本）。<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![文件备份 - 回收站：rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### 卷影副本

卷影复制服务 (VSS) 可以在文件正在使用时创建卷的时间点卷影副本；卷影副本不能替代取证镜像。<sup>[[8]](#references)</sup>

副本元数据通常与卷根目录下的 `\System Volume Information` 相关联，其标识符因系统而异：

![回收站 - 卷影副本：这些备份通常位于文件系统根目录下的 System Volume Information 中，名称由图中所示的 UID 组成……](<../../../images/image (94).png>)

使用合适的取证挂载工具挂载镜像后，可以使用 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) 枚举可用的 VSS 快照，并浏览或复制其中的文件。<sup>[[9]](#references)</sup>

![回收站 - 卷影副本：使用 ArsenalImageMounter 挂载取证镜像后，可以使用 ShadowCopyView 工具检查卷影副本，甚至提取其中的文件……](<../../../images/image (576).png>)

VSS 注册表写入器配置包括 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`，其中可以指定备份时排除的文件和注册表项：<sup>[[10]](#references)[[11]](#references)</sup>

![回收站 - 卷影副本：注册表项 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore 包含备份时不应包含的文件和注册表项](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` 项也包含 VSS 服务配置。<sup>[[8]](#references)</sup>

### Office 自动保存文件

AutoRecover 的位置因 Office 应用程序、版本和配置而异。对于 Word，Microsoft 文档指出默认位置为 `%APPDATA%\Microsoft\Word`；请在应用程序设置中检查当前使用的路径。<sup>[[12]](#references)</sup>

## Shell 项

Shell 项包含有关如何访问其他文件的信息。

### 最近使用的文档 (LNK)

用户打开或以其他方式访问某个项目时，Windows 通常会创建最近使用项目的快捷方式：

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

访问文件夹时，也可能会为该文件夹及相关的父文件夹创建链接。

这些链接文件可能包含目标类型、目标 MAC 时间、卷信息和目标路径。这些元数据可能有助于识别已删除的目标，但该工件本身不能证明特定用户曾打开过目标。<sup>[[13]](#references)[[14]](#references)</sup>

LNK 文件自身的文件系统时间戳与其嵌入的目标时间戳是不同的。若没有其他工件佐证，不要将链接创建时间解读为首次使用时间，也不要将链接修改时间解读为最后使用时间；该格式会将目标时间戳与链接文件的时间戳分别存储。<sup>[[13]](#references)[[14]](#references)</sup>

这里保留现有的 [**LinkParser**](http://4discovery.com/our-tools/) 链接作为历史选项，但审核时无法找到其文档。若要使用有文档说明的命令行解析器，请使用 [**LECmd**](https://github.com/EricZimmerman/LECmd)。<sup>[[15]](#references)</sup>

这些工具通常会显示两组时间戳：

- **目标时间戳：**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **链接文件时间戳：**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate。

第一组指目标；第二组指 LNK 文件本身。请结合解析器文档和文件系统上下文解读两组时间戳。<sup>[[14]](#references)[[15]](#references)</sup>

你也可以运行 Windows CLI 工具 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) 获取相同信息。<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

在这种情况下，信息将保存到 CSV 文件中。

### Jumplists

Jump Lists 是按应用程序划分的最近项目或特定任务项目列表，可以是自动列表，也可以是自定义列表。<sup>[[13]](#references)</sup>

自动 Jump Lists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` 中，文件名类似 `{id}.automaticDestinations-ms`，其中 ID 用于标识应用程序。

自定义 Jump Lists 存储在 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` 中；应用程序决定创建哪些任务或项目条目。

文件系统记录的创建和修改时间描述的是 Jump List 文件本身，并不自动代表其中每个目标的首次和最近访问时间。请将解析出的条目与文件时间戳及其他 artifacts 进行关联分析。<sup>[[13]](#references)</sup>

你可以使用 [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) 检查 Jump Lists。<sup>[[5]](#references)</sup>

![最近文档 (LNK) - Jumplists：你可以使用 JumplistExplorer 检查 Jump Lists](<../../../images/image (168).png>)

(_请注意，JumplistExplorer 提供的时间戳与 Jump List 文件本身相关_)

### Shellbags

[**点击此链接了解什么是 shellbags。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 的使用情况

有时可以通过访问可移动介质上的文件时创建的 artifacts 来佐证 USB 使用情况，包括：

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) 等工具可以将这些 artifacts 与 USB 设备记录相关联，但 artifacts 是否可用取决于 Windows 版本和应用程序。<sup>[[18]](#references)</sup>

在针对 Windows XP 和 Windows 7 MTP 工作流程的测试记录中，有些 LNK 指向的是 `WPDNSE` 文件夹，而不是原始路径。<sup>[[16]](#references)</sup>

![Shellbags - Windows USB 的使用情况：请注意，有些 LNK 文件指向的不是原始路径，而是 WPDNSE 文件夹](<../../../images/image (218).png>)

该研究观察到文件副本位于 `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` 下；在其测试中，临时内容在重启后不会保留，并且 GUID 可以与 shellbag 数据关联。应将此视为取决于 OS、设备和应用程序的行为，而非普遍适用的规则。<sup>[[16]](#references)</sup>

### Registry 信息

[查看此页面，了解](interesting-windows-registry-keys.md#usb-information)哪些 registry keys 包含有关已连接 USB 设备的有用信息。

### setupapi

在 Vista 及更高版本中，检查 `C:\Windows\inf\setupapi.dev.log` 中的设备安装活动。节标题包含 `Section start` 时间戳；这些记录描述的是安装处理过程，应与其他连接证据关联分析，而不应视为设备实际插入时间的精确记录。<sup>[[17]](#references)</sup>

![Registry 信息 - setupapi：检查文件 C: Windows inf setupapi.dev.log，获取 USB 连接发生时间的时间戳（搜索 Section start）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

可以使用 [**USBDetective**](https://usbdetective.com) 获取有关已连接到映像的 USB 设备的信息。<sup>[[18]](#references)</sup>

![setupapi - USB Detective：可以使用 USBDetective 获取有关已连接到映像的 USB 设备的信息](<../../../images/image (452).png>)

### 即插即用清理

名为 `Plug and Play Cleanup` 的计划任务会删除过时的驱动程序版本。Adam Harrison 记录的 Windows 10 任务定义还会处理 30 天未活动的驱动程序，因此可移动设备驱动程序的证据可能会被清理；在将此行为推广到其他环境前，请确认本地任务定义和 Windows 版本。<sup>[[1]](#references)</sup>

该任务位于以下路径：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

![Windows Plug and Play Cleanup 计划任务的 XML 定义](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**任务的关键组件和设置：**

- **pnpclean.dll**：此 DLL 负责实际的清理过程。
- **UseUnifiedSchedulingEngine**：设为 `TRUE`，表示使用通用任务计划引擎。
- **MaintenanceSettings**：
  - **Period ('P1M')**：指示 Task Scheduler 在常规 Automatic maintenance 期间每月启动清理任务。
  - **Deadline ('P2M')**：指示 Task Scheduler 在任务连续两个月失败时，于紧急 Automatic maintenance 期间执行该任务。

此配置会安排定期维护，并在连续失败后重试；具体 XML 和行为因版本而异。<sup>[[1]](#references)</sup>

**更多信息请查看：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)。<sup>[[1]](#references)</sup>

## Emails

Emails 包含 **2 个值得关注的部分：邮件头和邮件内容**。在**邮件头**中可以找到以下信息：

- **谁**发送了邮件（电子邮件地址、IP、转发邮件的 mail servers）
- 邮件的发送**时间**

此外，`References` 和 `In-Reply-To` 邮件头可以包含用于将回复与对话关联起来的 message IDs。<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails：邮件的发送时间](<../../../images/image (593).png>)

### Windows Mail App

此应用程序会将邮件内容保存到辅助文本或 HTML 文件中，路径示例为 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`；具体的编号文件夹和文件布局可能因 artifact 而异。<sup>[[75]](#references)</sup>

邮件的**元数据**和**联系人**可以在 **ESE 数据库** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 中找到。<sup>[[75]](#references)</sup>

`store.vol` 使用 Extensible Storage Engine (ESE) 格式。请在副本上操作，并使用 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 等 ESE parser；如果工具要求文件扩展名为 `.edb`，只重命名副本，并在依赖 `Message` 表之前验证表结构。<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

检查 Outlook MAPI 属性时，常见属性包括：

- `PidTagClientSubmitTime`：客户端提交邮件时的 UTC 时间。
- `PidTagConversationIndex`：邮件在对话线程中的相对位置。
- `PidTagEntryId`：邮件对象的标识符。
- `PidTagMessageFlags`：状态标志，例如已提交、已读、未读或包含附件。
- `PidTagLastVerbExecuted`：邮件最近记录的操作，例如打开、回复或转发。<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook 数据文件的位置因版本和账户类型而异。Microsoft 列出了以下常见 PST/OST 文件位置：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

registry 路径 `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` 可能会标识 Outlook 配置文件及相关数据文件配置。

PST 文件可以包含邮件、联系人、日历数据及其他 Outlook 项目。你可以使用 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) 检查副本。<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook：你可以使用 Kernel PST Viewer 工具打开 PST 文件](<../../../images/image (498).png>)

### Microsoft Outlook OST 文件

**OST 文件**是 Exchange 或 Microsoft 365 账户的本地缓存；Cached Exchange Mode 不适用于 POP 或 IMAP 账户。离线时间段可以配置，默认值通常为 12 个月；PST/OST 大小限制则是单独的可配置设置。可以使用 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) 查看 OST 文件。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### 检索附件

丢失的附件可能可以从以下位置恢复：

- 对于旧版 Outlook/IE 配置：`%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- 对于较新的 Outlook/IE11 配置：`%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`。<sup>[[65]](#references)</sup>

### Thunderbird MBOX 文件

**Thunderbird** 将配置文件数据存储在 `%APPDATA%\Thunderbird\Profiles` 下；邮件文件夹通常是无扩展名的 mbox 文件，位于特定账户的 `Mail` 或 `ImapMail` 目录中。<sup>[[29]](#references)[[30]](#references)</sup>

### 图像缩略图

- **Windows XP**：缩略图预览通常存储在每个文件夹的 `thumbs.db` 文件中。
- **网络文件夹**：启用相关缩略图行为时，UNC 文件夹仍可能创建 `thumbs.db` 文件；不要假设每个 Windows 版本或策略都会创建此文件。
- **Windows Vista 及更新版本**：系统缩略图缓存集中存储在 `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` 下，文件名类似 **thumbcache_xxx.db**。[**Thumbsviewer**](https://thumbsviewer.github.io) 可以解析旧版 `Thumbs.db`，而 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) 可以解析现代缩略图缓存数据库。<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry 信息

用于存储系统和用户配置数据的 Windows Registry 位于以下 hive 文件中：

- `%WINDIR%\System32\Config`：存放支撑多个 `HKEY_LOCAL_MACHINE` 子键的计算机 hive。
- `%USERPROFILE%\NTUSER.DAT`：存放用户的 `HKEY_CURRENT_USER` hive。
- 一些较旧的 Windows 安装会在 `%WINDIR%\System32\Config\RegBack\` 中保存副本；除非启用了定期备份，否则 Windows 10 version 1803 及更高版本不会自动填充此目录。<sup>[[34]](#references)[[35]](#references)</sup>
- 在现代 Windows 中，每个用户的 shell 和类注册数据通常也存储在 `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` 中。<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

以下工具有助于分析 registry hives；在依赖其输出之前，请确认每个工具支持的 hive 格式和版本：

- **Registry Editor**：Windows 自带的工具。它提供 GUI，可浏览当前会话的 Windows registry。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：允许你加载 registry 文件并通过 GUI 浏览内容。它还包含用于突出显示含有有用信息的 keys 的书签。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样提供 GUI，可浏览已加载的 registry，并包含用于突出显示已加载 registry 中有用信息的 plugins。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：另一款 GUI 应用程序，可以从已加载的 registry hive 中提取信息。<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### 恢复已删除的元素

已删除的 hive cells 可能会保留，直到其空间被重新使用；但能否恢复取决于 hive 状态和 parser。恢复出的已删除 keys 应视为需要验证的证据，而非必然可靠的记录。

### Last Write Time

Registry keys 带有最后写入时间戳；Windows 会为 key 及其任意 value entries 提供此时间戳，因此 value 不一定有独立的修改时间戳。<sup>[[69]](#references)</sup>

### SAM

**SAM** hive 包含本地用户和组账户数据，其中包括由系统 boot-key 材料保护的密码哈希。<sup>[[38]](#references)[[39]](#references)</sup>

在 `SAM\Domains\Account\Users` 中可以获取账户标识符以及部分登录和策略字段。离线提取哈希还需要 `SYSTEM` hive，以恢复相关的 boot-key 材料。<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry 中的有用条目


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## 执行过的程序

### Windows 基本进程

有关常见 Windows 进程的[一篇文章](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)可供进一步阅读；请使用最新的 Windows 文档和本地证据佐证任何有关进程行为的说法。<sup>[[2]](#references)</sup>

### Windows 最近使用的 APPs

在提供此功能的 Windows 10 版本中，`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` 包含按应用程序划分的子键，其中有最后使用时间和启动次数等字段；此 artifact 已从后续版本中移除，因此请验证目标系统的 build。<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

在提供 Background Activity Moderator 的系统中，检查 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 或较新的 `...\bam\State\UserSettings\{SID}` 路径。值以用户 SID 为键，可能包含被跟踪的可执行文件路径和类似 FILETIME 的执行数据；此 artifact 因版本而异，应通过其他证据进行佐证。<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching 会缓存资源和启动元数据，以便程序更快启动。

Prefetch 文件以 `.pf` 文件的形式存储在 `C:\Windows\Prefetch` 中；格式、保留期限和文件数量限制因 Windows 版本而异。Microsoft 文档指出，Windows 8 及更高版本会保留最近 8 次执行时间，最多保留 1024 个文件，因此不应将较早的固定限制概述推广到所有版本。<sup>[[13]](#references)</sup>

文件名通常采用 `{program_name}-{hash}.pf` 格式，hash 根据路径和参数等执行环境信息生成；Windows 10 及更高版本可能会压缩文件。文件存在可作为程序执行的证据，但本身并不能证明是用户执行的，应结合其他 artifacts 进行分析。<sup>[[13]](#references)</sup>

你可以使用 [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) 检查这些文件；该工具支持目录解析、CSV/HTML 输出，并支持解压适用的 Windows 10 Prefetch 文件。<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** 通过利用历史使用模式来改进加载，是 Prefetch 的补充。在会生成这些文件的系统上，其数据库文件通常位于 `C:\Windows\Prefetch\Ag*.db`；格式和文件是否存在取决于 Windows 版本。<sup>[[41]](#references)</sup>

这些数据库可能包含应用程序名称、使用次数、访问过的文件或卷、路径和时间范围，但不应将其视为精确的执行日志。<sup>[[41]](#references)</sup>

保留现有的 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 链接作为可能的解析工具；使用前请根据该工具的文档确认其当前是否可用以及支持的输出格式。

### SRUM

**System Resource Usage Monitor** (SRUM) 记录应用程序和用户的资源使用情况。它于 Windows 8 中引入，并将数据存储在 ESE 数据库 `C:\Windows\System32\sru\SRUDB.dat` 中。<sup>[[13]](#references)</sup>

它提供以下信息：

- AppID 和路径
- 与记录关联的用户/SID
- 发送字节数
- 接收字节数
- 网络接口
- 连接持续时间
- 进程持续时间

数据收集频率和保留期限取决于具体实现；不要假设每条记录都代表精确的 60 分钟执行间隔。<sup>[[13]](#references)</sup>

你可以使用 [**srum_dump**](https://github.com/MarkBaggett/srum-dump) 提取和查看数据，并按照当前工具版本文档中说明的选项进行操作。<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**（也称为 **ShimCache**）是 Windows 应用程序兼容性基础架构的一部分，会记录文件元数据以供兼容性决策使用。注册表配置单元路径、记录格式、保留容量和字段因 Windows 版本而异；在现代 Windows 系统上，仅凭 ShimCache 无法证明用户执行过某个文件。使用 [**AppCompatCacheParser** 工具](https://github.com/EricZimmerman/AppCompatCacheParser)解析相关的 `SYSTEM` 配置单元，并结合其他执行痕迹佐证其输出。<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache)：建议使用 AppCompatCacheParser 工具解析存储的信息](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 文件是一个注册表配置单元，用于清点 Windows 发现的应用程序和文件。它通常位于 `C:\Windows\AppCompat\Programs\Amcache.hve`。

其中可能包含关联和未关联的文件条目、路径及 SHA1 值，但它的存在仅能作为清点证据，不能单独证明某个进程曾经执行。<sup>[[13]](#references)[[44]](#references)</sup>

要提取和分析 **Amcache.hve**，请使用 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) 工具。此命令会解析配置单元并生成 CSV 输出。<sup>[[44]](#references)</sup>

例如：

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

在生成的 CSV 文件中，`Amcache_Unassociated file entries` 可用于调查未关联到已识别程序的文件。<sup>[[44]](#references)</sup>

### RecentFileCache

在 Windows 7 系统上，`C:\Windows\AppCompat\Programs\RecentFileCache.bcf` 可能包含近期观察到的二进制文件信息；具体是否存在及其含义取决于版本。

可以使用 [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) 解析此文件。<sup>[[45]](#references)</sup>

### Scheduled tasks

现代任务的计划任务证据可能位于 `C:\Windows\System32\Tasks`；旧版任务的证据可能位于 `C:\Windows\Tasks` 下的 `.job` 文件中。请根据操作系统检查相应格式的任务定义。<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Manager 数据库位于 `SYSTEM\CurrentControlSet\Services`（对于离线 SYSTEM hive，请检查对应的 control-set 键）；其中包含服务和驱动程序配置，例如可执行文件路径和启动类型。<sup>[[72]](#references)</sup>

### **Windows Store**

已安装的 Windows Store 应用可能记录在 `\ProgramData\Microsoft\Windows\AppRepository\` 下，其中包括数据库 **`StateRepository-Machine.srd`**。数据库架构和路径会因 Windows 版本而异。<sup>[[71]](#references)</sup>

数据库可能包含应用标识符、包编号和显示名称。标识符存在间隔本身并不能证明某个应用已卸载；请结合包和注册表状态进行佐证。

包注册信息也可能出现在 `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` 下。Microsoft 文档记载了一个特定版本中用于已移除预配应用的 `Deprovisioned` 子键；不要假定每个版本都存在 `Deleted` 子键。<sup>[[70]](#references)</sup>

## Windows Events

根据事件提供程序的不同，Windows 事件可能包含：

- 发生了什么
- `TimeCreated` 时间戳；必须结合事件架构和主机时间环境解读
- 涉及的用户
- 涉及的主机（主机名、IP）
- 访问的资产（文件、文件夹、打印机或服务）。<sup>[[49]](#references)</sup>

在 Windows Vista 之前，事件日志通常使用旧版二进制格式，存储在 `C:\Windows\System32\config` 下；Vista 及更高版本使用 Windows Event Log 格式，通常存储在 `C:\Windows\System32\winevt\Logs` 下，`.evtx` 文件中包含以 XML 呈现的事件数据。<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM 注册表在 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** 下存储通道配置，包括配置的文件路径和保留设置。<sup>[[47]](#references)</sup>

可以使用 Windows Event Viewer（**`eventvwr.msc`**）或 [**Event Log Explorer**](https://eventlogxp.com)、[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) 等工具查看这些日志。<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

在 Vista 及更高版本中，Security 通道通常存储在 `C:\Windows\System32\winevt\Logs\Security.evtx`。其最大大小和保留策略均可配置；采用循环日志记录时，文件达到上限后，较旧记录可能被覆盖。启用相关审核后，该通道可记录身份验证、注销、权限、审核策略和对象访问事件。<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**：帐户成功登录。<sup>[[50]](#references)</sup>
- **Event ID 4625**：帐户登录失败。<sup>[[51]](#references)</sup>
- **Event ID 4634**：登录会话已终止。<sup>[[52]](#references)</sup>
- **Event ID 4647**：用户发起了注销。<sup>[[53]](#references)</sup>
- **Event ID 4672**：新登录被分配了特殊权限；系统和管理员帐户经常出现此事件，因此单凭此事件不能证明存在恶意活动。<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**：本地交互式登录。
- **Network (3)**：访问共享资源。
- **Batch (4)**：批处理进程登录。
- **Service (5)**：服务登录。
- **Unlock (7)**：解锁工作站。
- **NetworkCleartext (8)**：网络登录时向身份验证包提供明文凭据。
- **NewCredentials (9)**：使用提供的备用凭据进行出站连接的登录。
- **RemoteInteractive (10)**：Remote Desktop 或 Terminal Services 登录。
- **CachedInteractive (11)**：使用缓存域凭据进行的交互式登录。
- **CachedRemoteInteractive (12)**：缓存的远程交互式登录。
- **CachedUnlock (13)**：使用缓存凭据解锁。<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**：用户不存在。
- **0xC000006A**：用户名正确，但密码错误。
- **0xC0000234**：帐户已锁定。
- **0xC0000072**：帐户已禁用。
- **0xC000006F**：在允许的时间段之外登录。
- **0xC0000070**：违反工作站限制。
- **0xC0000193**：帐户已过期。
- **0xC0000071**：密码已过期。
- **0xC0000133**：客户端与服务器的时间差过大。
- **0xC0000224**：帐户必须更改密码。
- **0xC0000225**：`STATUS_NOT_FOUND`；仅凭此代码无法判定是系统错误还是攻击。
- **0xC000015B**：帐户未被授予所请求的登录类型。<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616：

- **Time Change**：系统时间已更改。许多事件反映的是常规时间服务校正；在将其视为篡改之前，应先核对操作者和时间源。<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009：

- **电源和服务上下文**：事件 12 记录操作系统启动，13 记录操作系统关机，1074 记录计划内关机或重启，6008 表示意外关机，6009 记录启动时的 Windows 版本。事件 6005 和 6006 分别表示 Event Log 服务已启动和已停止；它们本身不能证明操作系统已启动或关闭。<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102：

- **日志删除**：事件 1102 记录 Security 审核日志已清除；应调查操作者及前后相关事件，不要仅凭此事件推断意图。<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**：`UserPnp` 设备安装事件，可帮助确认首次使用或安装活动。
- **10000 / 10100**：可能伴随设备活动出现的 `DriverFrameworks-UserMode` 事件。
- **Event ID 112**：`DeviceSetupManager/Admin` 活动，可提供与设备插入相关的时间戳。
- 提供程序、通道和事件含义会因 Windows 版本而异；解释事件前，请检查提供程序名称和事件内容。<sup>[[59]](#references)</sup>

有关登录类型及其关联凭据材料的实际示例，请参阅 [Altered Security 的详细指南](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)。<sup>[[60]](#references)</sup>

事件详细信息（包括登录类型、状态、子状态、源地址和进程字段）可为 Event ID 4625 提供上下文；状态代码或重复失败模式只是调查线索，并非结论。<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

由于事件日志通常采用循环记录方式，被日志记录器覆盖的记录可能无法恢复。与在线系统交互前，请先保留取证镜像或工作副本；只有在确认工具版本支持目标 `.evtx` 数据后，才使用经过验证的解析器或 carving 工具（例如 **Bulk_extractor**），并且不要仅为尝试恢复事件而拔掉正在运行的系统电源。<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

如需查阅实用的事件 ID 参考资料，请参阅现有的 [Red Team Recipe](https://redteamrecipe.com/event-codes/) 链接，并根据上文的提供程序文档验证其中的示例。

#### Brute Force Attacks

将重复出现的 Event ID 4625 登录失败与后续的 4624 登录成功、登录类型、状态、来源和帐户上下文进行关联；此序列是需要调查的指标，并不能证明发生了攻击。<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 记录系统时间更改，可能会影响时间线分析；请将其与时间服务和主机证据进行比对。<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB 事件 ID 因提供程序而异；请将 `UserPnp` 20001/20003、`DriverFrameworks-UserMode` 10000/10100 和 `DeviceSetupManager/Admin` 112 与 SetupAPI 和注册表 artifacts 进行关联。<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

使用 12/13/1074/6008/6009 了解操作系统启动、关机、重启和意外断电情况；6005/6006 标记 Event Log 服务的启动/停止。<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 记录 Security 审核日志已清除；应将其与相关帐户和进程进行关联。<sup>[[62]](#references)</sup>



## References

- [1] [Windows 即插即用清理](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 调查常见 Windows 进程](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 通知的数字取证视角](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman 取证工具](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier 和备用数据流](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [卷影复制服务](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS 下的注册表备份和还原操作](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [用于备份和还原的注册表项](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word 在 AutoRecover 位置上的性能问题](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [事件响应指南](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK：Shell Link 二进制文件格式](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP 取证：识别数据外泄 artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI 设备安装日志条目](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID 和相关类型](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [查找并传输 Outlook 数据文件](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [启用缓存 Exchange 模式](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [仅同步了部分项目](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [配置 Outlook 数据文件的大小限制](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [配置文件 - Thunderbird 存储用户数据的位置](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird 帐户设置和 mbox 目录](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache 接口](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [注册表 hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [系统注册表未备份到 RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows 注册表恢复](https://www.mitec.cz/wrr.html)
- [38] [远程编辑注册表](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [密码技术概述](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch 证据](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [事件日志文件格式](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog 注册表项](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated 事件属性](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [事件 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [事件 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [事件 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [事件 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [事件 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF：NTSTATUS 值](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [事件 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [使用系统事件日志排查意外重启](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [排查正在进行的关机问题](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 USB 存储设备取证](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [精彩的 Windows 登录类型](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [事件 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [后台活动调节器](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [注册表 - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop 中的快速打印无法打印 PDF 附件](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows 注册表文件](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [防止已移除的应用在更新期间重新出现](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT：FTK 和 Registry Viewer 测试结果](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [已安装服务数据库](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [任务](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [计划任务因 Task Scheduler 服务不可用而失败](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [浏览 Windows Mail 数据库](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322：Internet 消息格式](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [管理 Windows 客户端的 Recall](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
