{{#include ../../banners/hacktricks-training.md}}

# 时间戳

攻击者可能会对**更改文件的时间戳**感兴趣，以避免被检测。\
可以在MFT中的属性`$STANDARD_INFORMATION`和`$FILE_NAME`中找到时间戳。

这两个属性都有4个时间戳：**修改**、**访问**、**创建**和**MFT注册修改**（MACE或MACB）。

**Windows资源管理器**和其他工具显示来自**`$STANDARD_INFORMATION`**的信息。

## TimeStomp - 反取证工具

该工具**修改**`$STANDARD_INFORMATION`中的时间戳信息**但**不修改`$FILE_NAME`中的信息。因此，可以**识别****可疑****活动**。

## Usnjrnl

**USN日志**（更新序列号日志）是NTFS（Windows NT文件系统）的一个特性，用于跟踪卷更改。 [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)工具允许检查这些更改。

![](<../../images/image (449).png>)

上图是**工具**显示的**输出**，可以观察到对文件进行了一些**更改**。

## $LogFile

**对文件系统的所有元数据更改都被记录**在一个称为[写前日志](https://en.wikipedia.org/wiki/Write-ahead_logging)的过程中。记录的元数据保存在名为`**$LogFile**`的文件中，该文件位于NTFS文件系统的根目录。可以使用[LogFileParser](https://github.com/jschicht/LogFileParser)等工具解析此文件并识别更改。

![](<../../images/image (450).png>)

同样，在工具的输出中可以看到**进行了一些更改**。

使用同一工具可以识别**时间戳被修改到哪个时间**：

![](<../../images/image (451).png>)

- CTIME: 文件创建时间
- ATIME: 文件修改时间
- MTIME: 文件的MFT注册修改
- RTIME: 文件的访问时间

## `$STANDARD_INFORMATION`和`$FILE_NAME`比较

识别可疑修改文件的另一种方法是比较两个属性上的时间，寻找**不匹配**。

## 纳秒

**NTFS**时间戳的**精度**为**100纳秒**。因此，找到时间戳如2010-10-10 10:10:**00.000:0000的文件是非常可疑的**。

## SetMace - 反取证工具

该工具可以修改两个属性`$STARNDAR_INFORMATION`和`$FILE_NAME`。然而，从Windows Vista开始，必须在活动操作系统中修改此信息。

# 数据隐藏

NFTS使用集群和最小信息大小。这意味着如果一个文件占用一个半集群，**剩下的半个集群将永远不会被使用**，直到文件被删除。因此，可以在这个松弛空间中**隐藏数据**。

有像slacker这样的工具可以在这个“隐藏”空间中隐藏数据。然而，对`$logfile`和`$usnjrnl`的分析可以显示一些数据被添加：

![](<../../images/image (452).png>)

然后，可以使用FTK Imager等工具检索松弛空间。请注意，这种工具可以保存内容为模糊或甚至加密的形式。

# UsbKill

这是一个工具，如果检测到USB端口的任何更改，将**关闭计算机**。\
发现这一点的一种方法是检查正在运行的进程并**审查每个正在运行的python脚本**。

# 实时Linux发行版

这些发行版在**RAM**内存中**执行**。检测它们的唯一方法是**在NTFS文件系统以写入权限挂载的情况下**。如果仅以读取权限挂载，则无法检测到入侵。

# 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows配置

可以禁用多个Windows日志记录方法，以使取证调查变得更加困难。

## 禁用时间戳 - UserAssist

这是一个注册表项，维护用户运行每个可执行文件的日期和时间。

禁用UserAssist需要两个步骤：

1. 设置两个注册表项，`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`和`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`，都设置为零，以表示我们希望禁用UserAssist。
2. 清除看起来像`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`的注册表子树。

## 禁用时间戳 - Prefetch

这将保存有关执行的应用程序的信息，目的是提高Windows系统的性能。然而，这对于取证实践也可能有用。

- 执行`regedit`
- 选择文件路径`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- 右键单击`EnablePrefetcher`和`EnableSuperfetch`
- 选择修改，将每个值从1（或3）更改为0
- 重启

## 禁用时间戳 - 最后访问时间

每当从Windows NT服务器上的NTFS卷打开文件夹时，系统会花时间**更新每个列出文件夹的时间戳字段**，称为最后访问时间。在一个使用频繁的NTFS卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找`NtfsDisableLastAccessUpdate`。如果不存在，请添加此DWORD并将其值设置为1，这将禁用该过程。
4. 关闭注册表编辑器，并重启服务器。

## 删除USB历史

所有**USB设备条目**都存储在Windows注册表下的**USBSTOR**注册表项中，该项包含在您将USB设备插入PC或笔记本电脑时创建的子项。您可以在这里找到此项`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除此项**将删除USB历史。\
您还可以使用工具[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)确保您已删除它们（并删除它们）。

另一个保存USB信息的文件是`C:\Windows\INF`中的`setupapi.dev.log`。这也应该被删除。

## 禁用影子副本

**列出**影子副本使用`vssadmin list shadowstorage`\
**删除**它们运行`vssadmin delete shadow`

您还可以通过GUI删除它们，按照[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)中提出的步骤进行操作。

要禁用影子副本，请参见[此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 通过在点击Windows开始按钮后在文本搜索框中输入“services”打开服务程序。
2. 从列表中找到“卷影副本”，选择它，然后右键单击访问属性。
3. 从“启动类型”下拉菜单中选择禁用，然后通过单击应用和确定确认更改。

还可以在注册表`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`中修改将要在影子副本中复制的文件的配置。

## 覆盖已删除文件

- 您可以使用**Windows工具**：`cipher /w:C`这将指示cipher从C驱动器的可用未使用磁盘空间中删除任何数据。
- 您还可以使用像[**Eraser**](https://eraser.heidi.ie)这样的工具。

## 删除Windows事件日志

- Windows + R --> eventvwr.msc --> 展开“Windows日志” --> 右键单击每个类别并选择“清除日志”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## 禁用Windows事件日志

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- 在服务部分禁用“Windows事件日志”服务
- `WEvtUtil.exec clear-log`或`WEvtUtil.exe cl`

## 禁用$UsnJrnl

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
