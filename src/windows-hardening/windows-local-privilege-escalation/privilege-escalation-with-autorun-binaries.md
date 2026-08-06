# 使用 Autoruns 进行 Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** 可用于在 **startup** 时运行程序。使用以下命令查看哪些 binaries 被设置为在 startup 时运行：
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## 计划任务

**任务**可以按**特定频率**运行。使用以下命令查看计划运行的二进制文件：
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## 文件夹

**启动文件夹**中的所有 binary 都会在启动时执行。常见的启动文件夹如下所列，但启动文件夹的位置由 registry 指定。[阅读此处了解其位置。](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**：Archive extraction *path traversal* 漏洞（例如 WinRAR 7.13 之前版本中被利用的漏洞 – CVE-2025-8088）可在解压过程中将 **payloads 直接写入这些 Startup 文件夹**，从而在下一次用户登录时实现代码执行。有关此技术的深入介绍，请参阅：


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [此处的说明](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f)：**Wow6432Node** registry entry 表示你运行的是 64 位 Windows 版本。操作系统使用此 key 为在 64 位 Windows 版本上运行的 32 位 applications 显示 HKEY_LOCAL_MACHINE\SOFTWARE 的独立视图。

### Runs

**常见的** AutoRun registry：

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

名为 **Run** 和 **RunOnce** 的 Registry keys 用于在用户每次登录系统时自动执行 programs。作为 key 数据值分配的 command line 长度限制为 260 个字符或更少。<sup>[[2]](#references)</sup>

**Service runs**（可控制系统启动期间 services 的 automatic startup）：

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

在 Windows Vista 及更高版本中，**Run** 和 **RunOnce** registry keys 不会自动生成。这些 keys 中的 entries 可以直接启动 programs，也可以将其指定为 dependencies。例如，要在登录时加载 DLL file，可以使用 **RunOnceEx** registry key 以及一个 "Depend" key。下面演示了如何添加一个 registry entry，使其在系统启动期间执行 "C:\temp\evil.dll"：<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**：如果你可以写入 **HKLM** 中提到的任何注册表项，那么当其他用户登录时，你就可以提升权限。

> [!TIP]
> **Exploit 2**：如果你可以覆盖 **HKLM** 中任何注册表项所指示的二进制文件，那么当其他用户登录时，你就可以用后门修改该二进制文件并提升权限。
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

放置在 **Startup** 文件夹中的快捷方式会在用户 logon 或系统 reboot 期间自动触发 services 或 applications 启动。**Startup** 文件夹的位置会在 registry 中为 **Local Machine** 和 **Current User** 范围分别定义。这意味着，添加到这些指定 **Startup** 位置的任何快捷方式都会确保关联的 service 或 program 在 logon 或 reboot 过程后启动，因此这是一种让 programs 自动运行的简单方法。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> 如果你可以覆盖 **HKLM** 下的任何 \[User] Shell Folder，就能够将其指向由你控制的文件夹，并放置一个 backdoor；每当用户登录系统时，该 backdoor 都会被执行，从而提升 privileges。
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

此 per-user registry value 可以指向一个 script 或 command，并在该用户登录时执行。它主要是一种 **persistence** primitive，因为它只会在受影响用户的上下文中运行，但在 post-exploitation 和 autoruns review 期间仍然值得检查。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 如果你可以为当前用户写入此 value，则无需 admin rights，即可在下一次 interactive logon 时重新触发执行。如果你可以为其他用户的 hive 写入此 value，则可能在该用户登录时获得 code execution。
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
注意：

- 优先使用目标用户已经可以读取的 `.bat`、`.cmd`、`.ps1` 或其他 launcher 文件的完整路径。
- 在删除该值之前，这种方式会一直持续，即使用户注销或系统重启也不会失效。
- 与 `HKLM\...\Run` 不同，这种方式本身不会授予提升权限；它属于用户范围的持久化。

### Winlogon 键

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常，**Userinit** 键被设置为 **userinit.exe**。但是，如果修改了此键，指定的可执行文件也会在用户登录时由 **Winlogon** 启动。同样，**Shell** 键应指向 **explorer.exe**，后者是 Windows 的默认 shell。<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> 如果你可以覆盖 registry value 或 binary，就能够提升权限。

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

检查 **Run** key。
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### 更改安全模式命令提示符

在 Windows 注册表的 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 下，有一个默认设置为 `cmd.exe` 的 **`AlternateShell`** 值。这意味着在启动时选择“带命令提示符的安全模式”（按 F8）后，系统会使用 `cmd.exe`。不过，也可以将计算机配置为自动以此模式启动，而无需按 F8 并手动选择。

创建自动以“带命令提示符的安全模式”启动的启动选项的步骤：<sup>[[5]](#references)</sup>

1. 更改 `boot.ini` 文件的属性，移除只读、系统和隐藏标志：`attrib c:\boot.ini -r -s -h`
2. 打开 `boot.ini` 进行编辑。
3. 插入类似以下内容的行：`multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. 将更改保存到 `boot.ini`。
5. 重新应用原始文件属性：`attrib c:\boot.ini +r +s +h`

- **Exploit 1：**更改 **AlternateShell** 注册表键可以设置自定义命令 shell，从而可能用于未授权访问。
- **Exploit 2（PATH 写入权限）：**如果对系统 **PATH** 变量的任意部分具有写入权限，尤其是在 `C:\Windows\system32` 之前的部分，就可以执行自定义的 `cmd.exe`；如果系统以安全模式启动，这可能成为后门。
- **Exploit 3（PATH 和 boot.ini 写入权限）：**对 `boot.ini` 具有写入权限，可以启用自动启动安全模式，从而在下一次重启时促成未授权访问。

要检查当前的 **AlternateShell** 设置，请使用以下命令：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### 已安装组件

Active Setup 是 Windows 中的一项功能，**会在桌面环境完全加载之前启动**。它会优先执行某些命令，这些命令必须完成后，用户登录过程才会继续。该过程甚至会早于 Run 或 RunOnce 注册表部分中的其他启动项触发。

Active Setup 通过以下注册表项进行管理：

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

这些注册表项中包含各种子项，每个子项对应一个特定组件。尤其值得关注的键值包括：

- **IsInstalled：**
- `0` 表示不会执行该组件的命令。
- `1` 表示每个用户执行一次该命令；如果缺少 `IsInstalled` 值，这是默认行为。
- **StubPath：** 定义由 Active Setup 执行的命令。它可以是任何有效的命令行，例如启动 `notepad`。

**安全洞察：**

- 修改或写入 **`IsInstalled`** 设置为 `"1"` 且具有特定 **`StubPath`** 的注册表项，可能导致未经授权的命令执行，并可能用于 privilege escalation。
- 如果拥有足够权限，修改任意 **`StubPath`** 值所引用的二进制文件，也可能实现 privilege escalation。

可以使用以下命令检查 Active Setup 组件中的 **`StubPath`** 配置：
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) 概述

Browser Helper Objects (BHOs) 是为 Microsoft Internet Explorer 添加额外功能的 DLL 模块。它们会在 Internet Explorer 和 Windows Explorer 每次启动时加载。不过，通过将 **NoExplorer** 键设置为 1，可以阻止其随 Windows Explorer 实例加载，从而禁止其执行。<sup>[[1]](#references)</sup>

BHOs 可通过 Internet Explorer 11 兼容 Windows 10，但 Microsoft Edge（较新版本 Windows 中的默认浏览器）不支持它们。

要查看系统中注册的 BHOs，可以检查以下注册表项：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

每个 BHO 在注册表中都由其 **CLSID** 表示，作为唯一标识符。每个 CLSID 的详细信息可以在 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 下找到。

要查询注册表中的 BHOs，可以使用以下命令：
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

请注意，注册表中每个 dll 都会对应一个新的注册表项，并通过 **CLSID** 表示。可以在 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 中查找 CLSID 信息。

### Font Drivers

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
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

请注意，所有可以找到 autoruns 的位置都已被[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)搜索。但是，如果你需要一个**更全面的自动执行**文件列表，可以使用 systinternals 提供的 [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)：
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## 更多

**在** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup> **中查找更多类似注册表的 Autoruns**

## 参考资料

- [1] [常见的 malware 持久化机制](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – 自动启动类别（Troubleshooting with the Windows Sysinternals Tools, 2nd Edition）](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [如何添加启动 alternate shell 的启动选项？](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit 综述 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
