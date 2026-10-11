# 使用 Autoruns 进行权限提升

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** 可用于在**启动时**运行程序。使用以下命令查看哪些二进制文件被设置为在启动时运行：

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## 计划任务

**任务**可以安排以**特定频率**运行。使用以下命令查看计划运行的二进制文件：

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

即使任务定义和操作文件受到保护，以 SYSTEM 身份运行的已启用任务也值得检查。[Task Scheduler 需要任务具有执行权限，才能按需运行该任务](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)。如果低权限用户拥有该权限，请检查具体操作，尤其是会修改 Active Directory ACL 或重置账户保护设置的 PowerShell 脚本。检查任务的 `AllowDemandStart` 设置，并验证脚本的输入和效果；仅拥有启动固定任务的权限，并不意味着可以执行任意代码。

## 文件夹

**Startup folders 中的所有二进制文件都会在启动时执行**。常见的启动文件夹如下所列，但启动文件夹的位置由注册表指定。[阅读此文了解具体位置。](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

更高权限用户的 Startup 条目可能会启动一个受保护的脚本，而该脚本会反复打开另一个用户可写目录中的文件。在将该目录视为提权路径之前，请检查条目的**实际登录身份**、脚本的输入目录及其 ACL，以及具体执行的操作。尤其是，[`hh.exe` 会打开已编译的 HTML Help（`.chm`）文件](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program)；即使脚本检查了文件名或开头几个字节，只要它将调用者提供的文件传给 `hh.exe`，就跨越了内容信任边界。[HTML Help 策略可以限制可执行快捷方式](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands)，因此请确认已安装的策略以及可访问内容的实际行为。仅凭 `.chm` 扩展名或 magic bytes，无法证明能以更高权限执行代码。枚举时检查 autorun、进程命令行和路径权限，但不要打开不受信任的文件。

当更高权限用户**手动打开**另一个用户可替换的文档目录中的 `.chm` 文件时，也存在相同的内容边界。请确认具体文件及其父目录的写入权限、实际查看器身份和打开事件，以及生效的 HTML Help 策略。目录可写，或有人要求审阅文档，并不能证明更高权限用户打开了攻击者控制的内容。

> **提示**：归档解压 *path traversal* 漏洞（例如 WinRAR 7.13 之前版本中被利用的漏洞——CVE-2025-8088）可在解压时将 **payloads 直接放入这些 Startup 文件夹**，从而在下次用户登录时实现代码执行。关于此技术的深入介绍，请参阅：

{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [此处的说明](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f)：**Wow6432Node** 注册表项表示你运行的是 64 位 Windows 版本。操作系统使用此项为在 64 位 Windows 版本上运行的 32 位应用程序提供 HKEY_LOCAL_MACHINE\SOFTWARE 的单独视图。

### 运行项

**常见的** AutoRun 注册表项：

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

名为 **Run** 和 **RunOnce** 的注册表项用于在用户每次登录系统时自动执行程序。分配给注册表项数据值的命令行长度不能超过 260 个字符。<sup>[[2]](#references)</sup>

**服务运行项**（可控制服务在启动期间是否自动启动）：

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx：**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

在 Windows Vista 及更高版本中，**Run** 和 **RunOnce** 注册表项不会自动创建。这些项中的条目可以直接启动程序，也可以将程序指定为依赖项。例如，要在登录时加载 DLL 文件，可以使用 **RunOnceEx** 注册表项以及一个 “Depend” 项。以下示例通过添加注册表项，在系统启动期间执行 “C:\temp\evil.dll”：<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**：如果你可以写入 **HKLM** 中提到的任何注册表项，那么当其他用户登录时，你就可以提升权限。

> [!TIP]
> **Exploit 2**：如果你可以覆盖 **HKLM** 中任何注册表项所指向的二进制文件，那么当其他用户登录时，你就可以将该文件修改为带有后门的版本，从而提升权限。

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

放置在 **Startup** 文件夹中的快捷方式会在用户登录或系统重启时自动触发服务或应用程序启动。**Startup** 文件夹的位置由注册表中 **Local Machine** 和 **Current User** 范围的设置定义。这意味着，添加到指定 **Startup** 位置的任何快捷方式都会确保关联的服务或程序在登录或重启后启动，因此这是安排程序自动运行的一种简单方法。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> 如果你可以覆盖 **HKLM** 下的任何 \[User] Shell Folder，就能将其指向你控制的文件夹，并放置一个 backdoor，使其在用户每次登录系统时执行，从而提升权限。

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

此每用户注册表值可以指向用户登录时执行的脚本或命令。它主要是一种 **persistence** 原语，因为它只会在受影响用户的上下文中运行，但在 post-exploitation 和 autoruns 检查期间仍值得查看。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 如果你能为当前用户写入此值，就可以在下次交互式登录时重新触发执行，无需管理员权限。如果你能为其他用户的注册表配置单元写入此值，则可能在该用户登录时获得代码执行。

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

注释：

- 优先使用目标用户已可读取的 `.bat`、`.cmd`、`.ps1` 或其他启动器文件的完整路径。
- 在删除该值之前，注销或重启后它都会继续生效。
- 与 `HKLM\...\Run` 不同，此项本身不会授予提升权限；它属于用户范围的持久化。

### Winlogon 键

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常，**Userinit** 键设置为 **userinit.exe**。但是，如果修改了此键，用户登录时，指定的可执行文件也会由 **Winlogon** 启动。同样，**Shell** 键应指向 **explorer.exe**，这是 Windows 的默认 shell。<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> 如果你可以覆盖注册表值或二进制文件，就能够提升权限。

### 策略设置

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

检查 **Run** 键。

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### 更改安全模式命令提示符

在 Windows 注册表的 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 下，默认设置为 `cmd.exe` 的 **`AlternateShell`** 值决定了启动时（按 F8）选择“带命令提示符的安全模式”后使用 `cmd.exe`。不过，也可以将计算机设置为自动以此模式启动，而无需按 F8 手动选择。

创建一个自动以“带命令提示符的安全模式”启动的启动选项：<sup>[[5]](#references)</sup>

1. 更改 `boot.ini` 文件的属性，移除只读、系统和隐藏标记：`attrib c:\boot.ini -r -s -h`
2. 打开 `boot.ini` 进行编辑。
3. 插入类似以下内容的一行：`multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. 保存对 `boot.ini` 的更改。
5. 恢复文件的原始属性：`attrib c:\boot.ini +r +s +h`

- **Exploit 1：**更改 **AlternateShell** 注册表项可以设置自定义命令 shell，可能导致未授权访问。
- **Exploit 2（PATH 写入权限）：**如果对系统 **PATH** 变量的任意部分具有写入权限，尤其是 `C:\Windows\system32` 之前的部分，就可以执行自定义的 `cmd.exe`；如果系统以安全模式启动，这可能成为后门。
- **Exploit 3（PATH 和 boot.ini 写入权限）：**对 `boot.ini` 具有写入权限，就可以启用自动安全模式启动，从而在下次重启时实现未授权访问。

要检查当前的 **AlternateShell** 设置，请使用以下命令：

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Installed Component

Active Setup 是 Windows 中的一项功能，会在**桌面环境完全加载之前启动**。它会优先执行某些命令，并且这些命令必须完成后，用户登录流程才会继续。此过程甚至会在触发 Run 或 RunOnce 注册表项等其他启动项之前发生。

Active Setup 通过以下注册表项进行管理：

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

这些注册表项下包含多个子项，每个子项对应一个特定组件。特别值得关注的键值包括：

- **IsInstalled:**
  - `0` 表示该组件的命令不会执行。
  - `1` 表示该命令会为每个用户执行一次；如果缺少 `IsInstalled` 值，这是默认行为。
- **StubPath:** 定义由 Active Setup 执行的命令。它可以是任何有效的命令行，例如启动 `notepad`。

**安全提示：**

- 修改或写入 **`IsInstalled`** 设置为 `"1"` 且包含指定 **`StubPath`** 的注册表项，可能导致未经授权的命令执行，并可能用于 privilege escalation。
- 如果权限足够，修改任何 **`StubPath`** 值所引用的二进制文件，也可能实现 privilege escalation。

可以使用以下命令检查 Active Setup 组件中的 **`StubPath`** 配置：

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### 浏览器辅助对象

### 浏览器辅助对象 (BHO) 概述

浏览器辅助对象 (BHO) 是为 Microsoft Internet Explorer 添加额外功能的 DLL 模块。它们会在每次启动时加载到 Internet Explorer 和 Windows Explorer 中。不过，将 **NoExplorer** 键设为 1 可以阻止它们执行，使其无法随 Windows Explorer 实例加载。<sup>[[1]](#references)</sup>

BHO 可通过 Internet Explorer 11 兼容 Windows 10，但 Microsoft Edge（较新版本 Windows 中的默认浏览器）不支持 BHO。

要查看系统上注册的 BHO，可以检查以下注册表项：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

每个 BHO 在注册表中都由其 **CLSID** 表示，作为唯一标识符。可在 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 下找到每个 CLSID 的详细信息。

可以使用以下命令查询注册表中的 BHO：

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer 扩展

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

请注意，注册表中每个 dll 都会有一个新的注册表项，并以 **CLSID** 表示。你可以在 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 中找到 CLSID 信息。

### 字体驱动程序

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### 打开命令

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### 上下文菜单 COM 处理程序

Explorer 上下文菜单处理程序是注册在 `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` 和 `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` 等项下的 shell 扩展。处理程序的默认值（有时是其项名称）是一个 CLSID。根据该 CLSID 查找 `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`；其默认值指定调用处理程序时加载的 DLL。

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

同时检查 32 位和 64 位注册表视图。`HKCR` 会合并每用户和全计算机范围的类注册，因此请确认进程实际会解析到哪个底层键。低权限身份如果能修改全计算机范围的 `InprocServer32` 值，就可能将权限更高的进程重定向到另一个 DLL；但要实现提权，该进程必须调用相应的处理程序。即使注册表值本身受保护，可写的 DLL 路径也可能带来类似风险。

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

请注意，所有可以找到 autoruns 的位置都已由[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)搜索过。不过，如果想获得更全面的自动执行文件列表，可以使用 systinternals 提供的 [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)：

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## 更多

**查找更多类似注册表的 Autoruns，见** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [常见恶意软件持久化机制](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – 启动或登录自动启动执行：注册表 Run 键 / 启动文件夹](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – 启动或登录初始化脚本：登录脚本（Windows）](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – 自动启动类别（使用 Windows Sysinternals 工具进行故障排除，第 2 版）](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [如何添加一个启动备用 shell 的启动选项？](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit 周报 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
