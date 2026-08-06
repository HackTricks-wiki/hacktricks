# Windows Kimlik Bilgisi Korumaları

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Windows XP ile birlikte sunulan [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protokolü, HTTP Protocol üzerinden authentication için tasarlanmıştır ve **Windows XP'den Windows 8.0'a ve Windows Server 2003'ten Windows Server 2012'ye kadar varsayılan olarak enabled durumdadır**. Bu varsayılan ayar, **parolaların LSASS'te** (Local Security Authority Subsystem Service) **açık metin olarak depolanmasına** neden olur. Bir attacker, aşağıdakini çalıştırarak Mimikatz ile **bu kimlik bilgilerini extract edebilir**:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Bu özelliği **kapatmak veya açmak** için _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ içindeki _**UseLogonCredential**_ ve _**Negotiate**_ registry key'leri "1" olarak ayarlanmalıdır. Bu key'ler **mevcut değilse veya "0" olarak ayarlanmışsa**, WDigest **devre dışıdır**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP ve PPL protected processes)

**Protected Process (PP)** ve **Protected Process Light (PPL)**, **LSASS** gibi hassas process'lere yetkisiz erişimi engellemek için tasarlanmış **Windows kernel-level protection** mekanizmalarıdır. **Windows Vista** ile tanıtılan **PP model**, başlangıçta **DRM** enforcement için oluşturulmuş ve yalnızca **special media certificate** ile imzalanmış binary'lerin korunmasına izin vermiştir. **PP** olarak işaretlenmiş bir process'e yalnızca **aynı zamanda PP olan** ve **eşit veya daha yüksek bir protection level** değerine sahip diğer process'ler erişebilir; bu durumda bile, özellikle izin verilmedikçe **yalnızca sınırlı access rights** kullanılabilir.

**Windows 8.1** ile tanıtılan **PPL**, PP'nin daha esnek bir sürümüdür. **Digital signature** içindeki EKU (Enhanced Key Usage) alanına dayalı **"protection levels"** sunarak **daha geniş kullanım alanlarına** (ör. LSASS, Defender) izin verir. Protection level, `EPROCESS.Protection` alanında tutulur; bu alan aşağıdakileri içeren bir `PS_PROTECTION` structure'ıdır:
- **Type** (`Protected` veya `ProtectedLight`)
- **Signer** (ör. `WinTcb`, `Lsa`, `Antimalware` vb.)

Bu structure tek bir byte içine paketlenir ve **kimlerin kimlere erişebileceğini** belirler:
- **Daha yüksek signer değerleri**, daha düşük değerlere erişebilir
- **PPL'ler PP'lere erişemez**
- **Unprotected process'ler** hiçbir PPL/PP'ye erişemez

### Offensive perspective açısından bilmeniz gerekenler

- **LSASS bir PPL olarak çalıştığında**, normal bir admin context'inden `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` kullanılarak yapılan erişim girişimleri, `SeDebugPrivilege` etkin olsa bile **`0x5 (Access Denied)`** ile başarısız olur.
- **LSASS protection level** değerini Process Hacker gibi araçları kullanarak veya programatik olarak `EPROCESS.Protection` değerini okuyarak **kontrol edebilirsiniz**.
- LSASS genellikle `PsProtectedSignerLsa-Light` (`0x41`) değerine sahip olur; buna yalnızca `WinTcb` (`0x61` veya `0x62`) gibi daha yüksek seviyeli signer ile imzalanmış process'ler erişebilir.
- PPL, **yalnızca Userland restriction**'dır; **kernel-level code** bunu tamamen bypass edebilir.
- LSASS'in PPL olması, **kernel shellcode execute edebiliyorsanız** veya **uygun access'e sahip yüksek ayrıcalıklı bir process'i leverage edebiliyorsanız**, credential dumping yapılmasını engellemez.
- **PPL'yi ayarlamak veya kaldırmak**, reboot ya da **Secure Boot/UEFI settings** gerektirir; bu ayar, registry değişiklikleri geri alınsa bile PPL ayarını kalıcı olarak koruyabilir.

### Launch sırasında bir PPL process oluşturma (documented API)

Windows, extended startup attribute list kullanarak child process oluşturma sırasında Protected Process Light level istemek için documented bir yöntem sunar. Bu yöntem signing requirements'ı bypass etmez — target image, istenen signer class için imzalanmış olmalıdır.

C/C++ ile minimal flow:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Notlar ve kısıtlamalar:
- `STARTUPINFOEX` ile `InitializeProcThreadAttributeList` ve `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)` kullanın, ardından `CreateProcess*` işlevine `EXTENDED_STARTUPINFO_PRESENT` parametresini geçirin.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Koruma `DWORD` değeri, `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` veya `PROTECTION_LEVEL_LSA_LIGHT` gibi sabitlere ayarlanabilir.
- Alt işlem yalnızca imzası ilgili signer sınıfı için geçerliyse PPL olarak başlar; aksi takdirde işlem oluşturma başarısız olur ve genellikle `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)` hatası alınır.
- Bu bir bypass değildir — uygun şekilde imzalanmış image'lar için tasarlanmış desteklenen bir API'dir. Araçları harden etmek veya PPL-korumalı yapılandırmaları doğrulamak için kullanışlıdır.

Minimal bir loader kullanan örnek CLI:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**PPL korumalarını bypass etme seçenekleri:**

PPL'ye rağmen LSASS dump'lamak istiyorsanız, 3 ana seçeneğiniz vardır:
1. **İmzalı bir kernel driver (ör. Mimikatz + mimidrv.sys) kullanarak** **LSASS'in protection flag'ini kaldırmak**:

![Kimlik bilgileri koruması etkileşimini gösteren Mimikatz mimidrv driver çıktısı](../../images/mimidrv.png)

2. **Kendi Savunmasız Driver'ınızı Getirin (BYOVD)**; özel kernel kodu çalıştırarak korumayı devre dışı bırakın. **PPLKiller**, **gdrv-loader** veya **kdmapper** gibi araçlar bunu mümkün kılar.
3. Açık bir LSASS handle'ına sahip başka bir işlemden (ör. bir AV işlemi) **mevcut bir LSASS handle'ını çalın**, ardından bunu **duplicate ederek** kendi işleminize aktarın. Bu, `pypykatz live lsa --method handledup` tekniğinin temelidir.
4. Adres alanınıza veya başka bir privileged process içine rastgele kod yüklemenize izin verecek bazı privileged process'leri **abuse edin**; bu, PPL kısıtlamalarını etkili bir şekilde bypass eder. Bunun bir örneğini [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) veya [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) adreslerinde inceleyebilirsiniz.

**LSASS için LSA protection (PPL/PP) mevcut durumunu kontrol et:**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`** çalıştırdığınızda muhtemelen `0x00000005` hata koduyla başarısız olur; bunun nedeni budur.

- Bu check hakkında daha fazla bilgi için [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, yalnızca **Windows 10 (Enterprise ve Education sürümleri)** için sunulan bir özellik olup **Virtual Secure Mode (VSM)** ve **Virtualization Based Security (VBS)** kullanarak makine kimlik bilgilerinin güvenliğini artırır. CPU virtualization extensions kullanarak ana işletim sisteminin erişiminden uzak, korumalı bir bellek alanı içinde temel işlemleri izole eder. Bu izolasyon, kernel'in bile VSM içindeki belleğe erişememesini sağlayarak kimlik bilgilerini **pass-the-hash** gibi saldırılara karşı etkili bir şekilde korur. **Local Security Authority (LSA)** bu güvenli ortamda bir trustlet olarak çalışırken, ana işletim sistemindeki **LSASS** işlemi yalnızca VSM'nin LSA'sı ile iletişim kurar.

Varsayılan olarak **Credential Guard** etkin değildir ve bir kuruluş içinde manuel olarak etkinleştirilmesi gerekir. Kimlik bilgilerini çıkarma yetenekleri kısıtlanan **Mimikatz** gibi araçlara karşı güvenliği artırmak açısından kritik öneme sahiptir. Ancak, login attempts sırasında kimlik bilgilerini clear text olarak yakalamak için özel **Security Support Providers (SSP)** eklenerek güvenlik açıklarından hâlâ yararlanılabilir.

**Credential Guard**'ın etkinleştirilme durumunu doğrulamak için _**LsaCfgFlags**_ registry key'i _**HKLM\System\CurrentControlSet\Control\LSA**_ altında incelenebilir. "**1**" değeri **UEFI lock** ile etkinleştirildiğini, "**2**" kilit olmadan etkinleştirildiğini, "**0**" ise etkin olmadığını gösterir. Bu registry check güçlü bir gösterge olsa da **Credential Guard**'ı etkinleştirmek için gereken tek adım değildir. Bu özelliği etkinleştirmek için ayrıntılı yönergeler ve bir PowerShell script'i online olarak bulunabilir.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10'da **Credential Guard**'ı etkinleştirme ve **Windows 11 Enterprise ve Education (sürüm 22H2)** uyumlu sistemlerinde otomatik olarak etkinleştirilmesi hakkında kapsamlı bilgi ve talimatlar için [Microsoft'un belgelerini](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) ziyaret edin.<sup>[[9]](#references)</sup>

Credential capture için özel SSP'leri uygulama hakkında daha fazla ayrıntı [bu kılavuzda](../active-directory-methodology/custom-ssp.md) sağlanmaktadır.

## RDP RestrictedAdmin Mode

**Windows 8.1 ve Windows Server 2012 R2**, _**RDP için Restricted Admin mode**_ dahil olmak üzere çeşitli yeni güvenlik özellikleri sunmuştur. Bu mode, [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) saldırılarıyla ilişkili riskleri azaltarak güvenliği artırmak üzere tasarlanmıştır.

Geleneksel olarak, RDP aracılığıyla uzak bir bilgisayara bağlanırken kimlik bilgileriniz hedef makinede depolanır. Bu durum, özellikle yükseltilmiş ayrıcalıklara sahip hesaplar kullanıldığında önemli bir güvenlik riski oluşturur. Ancak _**Restricted Admin mode**_'un kullanıma sunulmasıyla bu risk önemli ölçüde azaltılmıştır.

**mstsc.exe /RestrictedAdmin** komutunu kullanarak bir RDP bağlantısı başlatıldığında, uzak bilgisayarda kimlik bilgileriniz depolanmadan kimlik doğrulaması gerçekleştirilir. Bu yaklaşım, bir malware bulaşması veya kötü amaçlı bir kullanıcının uzak sunucuya erişim sağlaması durumunda kimlik bilgileriniz sunucuda depolanmadığından bunların ele geçirilmemesini sağlar.

**Restricted Admin mode**'da, RDP oturumundan network kaynaklarına erişme girişimlerinin kişisel kimlik bilgilerinizi kullanmayacağını; bunun yerine **makinenin kimliğinin** kullanılacağını belirtmek önemlidir.

Bu özellik, uzak masaüstü bağlantılarının güvenliğini sağlama ve bir güvenlik ihlali durumunda hassas bilgilerin açığa çıkmasını önleme konusunda önemli bir adım teşkil eder.

![Credential extraction bağlamı için Windows RAM bellek diyagramı](../../images/RAM.png)

Daha ayrıntılı bilgi için [bu kaynağı](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) ziyaret edin.<sup>[[6]](#references)</sup>

## Önbelleğe Alınmış Kimlik Bilgileri

Windows, **domain credentials**'ı **Local Security Authority (LSA)** aracılığıyla güvence altına alır ve **Kerberos** ile **NTLM** gibi güvenlik protokolleriyle logon işlemlerini destekler. Windows'un önemli bir özelliği, kullanıcıların **domain controller çevrimdışı** olsa bile bilgisayarlarına erişmeye devam edebilmesini sağlamak için **son on domain login** bilgisini önbelleğe alabilmesidir. Bu özellik, şirketlerinin network'ünden sıklıkla uzakta olan laptop kullanıcıları için büyük bir avantajdır.

Önbelleğe alınan login sayısı, belirli bir **registry key veya group policy** aracılığıyla ayarlanabilir. Bu ayarı görüntülemek veya değiştirmek için aşağıdaki komut kullanılır:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Bu önbelleğe alınmış kimlik bilgilerine erişim sıkı bir şekilde denetlenir; bunları görüntülemek için gerekli izinlere yalnızca **SYSTEM** hesabı sahiptir. Bu bilgilere erişmesi gereken yöneticiler işlemi SYSTEM kullanıcı ayrıcalıklarıyla gerçekleştirmelidir. Kimlik bilgileri şu konumda depolanır: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**, `lsadump::cache` komutu kullanılarak bu önbelleğe alınmış kimlik bilgilerini çıkarmak için kullanılabilir.

Daha fazla ayrıntı için orijinal [kaynak](http://juggernaut.wikidot.com/cached-credentials) kapsamlı bilgiler sunar.<sup>[[7]](#references)</sup>

## Protected Users

**Protected Users grubu** üyeliği, kullanıcılar için çeşitli güvenlik geliştirmeleri sağlar ve kimlik bilgilerinin çalınması ile kötüye kullanılmasına karşı daha yüksek düzeyde koruma sunar:

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials** Group Policy ayarı etkin olsa bile Protected Users kullanıcılarının düz metin kimlik bilgileri önbelleğe alınmaz.
- **Windows Digest**: **Windows 8.1 ve Windows Server 2012 R2** sürümlerinden itibaren, Windows Digest durumu ne olursa olsun Protected Users kullanıcılarının düz metin kimlik bilgileri önbelleğe alınmaz.
- **NTLM**: Sistem, Protected Users kullanıcılarının düz metin kimlik bilgilerini veya NT one-way function'larını (NTOWF) önbelleğe almaz.
- **Kerberos**: Protected Users için Kerberos authentication, **DES** veya **RC4 key** oluşturmaz; ayrıca ilk Ticket-Granting Ticket (TGT) ediniminin ötesinde düz metin kimlik bilgilerini veya long-term key'leri önbelleğe almaz.
- **Offline Sign-In**: Protected Users kullanıcıları için oturum açma ya da kilit açma sırasında cached verifier oluşturulmaz; bu nedenle bu hesaplarda offline sign-in desteklenmez.

Bu korumalar, **Protected Users grubunun** üyesi olan bir kullanıcı cihazda oturum açtığı anda etkinleştirilir. Böylece çeşitli kimlik bilgisi ele geçirme yöntemlerine karşı kritik güvenlik önlemlerinin uygulanması sağlanır.

Daha ayrıntılı bilgi için resmi [belgelere](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) başvurun.<sup>[[10]](#references)</sup>

**[belgelerdeki](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) tablo**.<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}
