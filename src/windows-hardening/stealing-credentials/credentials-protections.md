# Windows Kimlik Bilgileri Korumaları

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Windows XP ile birlikte kullanıma sunulan [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protokolü, HTTP Protokolü üzerinden kimlik doğrulama için tasarlanmıştır ve **Windows XP'den Windows 8.0'a ve Windows Server 2003'ten Windows Server 2012'ye kadar varsayılan olarak etkindir**. Bu varsayılan ayar, **LSASS'te** (Local Security Authority Subsystem Service) düz metin parola depolanmasına neden olur. Bir saldırgan, aşağıdaki komutu çalıştırarak bu **kimlik bilgilerini çıkarmak** için Mimikatz kullanabilir:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Bu özelliği **devre dışı bırakmak veya etkinleştirmek** için _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ içindeki _**UseLogonCredential**_ ve _**Negotiate**_ registry key'leri "1" olarak ayarlanmalıdır. Bu key'ler **yoksa veya "0" olarak ayarlanmışsa**, WDigest **devre dışıdır**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP ve PPL protected processes)

**Protected Process (PP)** ve **Protected Process Light (PPL)**, **LSASS** gibi hassas süreçlere yetkisiz erişimi engellemek için tasarlanmış **Windows kernel-level protections**'dır. **Windows Vista**'da tanıtılan **PP modeli**, başlangıçta **DRM** uygulaması için oluşturulmuş ve yalnızca **özel bir media certificate** ile imzalanmış binary'lerin korunmasına izin vermiştir. **PP** olarak işaretlenmiş bir sürece yalnızca **aynı zamanda PP** olan ve **eşit veya daha yüksek protection level**'a sahip diğer süreçler erişebilir; o durumda bile, özel olarak izin verilmediği sürece **yalnızca sınırlı access rights** kullanılabilir.

**Windows 8.1**'de tanıtılan **PPL**, PP'nin daha esnek bir sürümüdür. **Digital signature**'ın EKU (Enhanced Key Usage) alanına dayalı **"protection levels"** sunarak **daha geniş kullanım alanlarına** (ör. LSASS, Defender) izin verir. Protection level, `PS_PROTECTION` yapısı olan `EPROCESS.Protection` alanında saklanır ve şunları içerir:
- **Type** (`Protected` veya `ProtectedLight`)
- **Signer** (ör. `WinTcb`, `Lsa`, `Antimalware` vb.)

Bu yapı tek bir byte içine paketlenir ve **kimin kime erişebileceğini** belirler:
- **Daha yüksek signer değerleri**, daha düşük değerlere erişebilir
- **PPL'ler PP'lere erişemez**
- **Unprotected processes**, hiçbir PPL/PP'ye erişemez

### Offensive perspective açısından bilmeniz gerekenler

- **LSASS bir PPL olarak çalıştığında**, normal bir admin context'ten `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` kullanılarak açılma girişimleri, `SeDebugPrivilege` etkin olsa bile **`0x5 (Access Denied)`** ile başarısız olur.
- **LSASS protection level**'ı Process Hacker gibi araçlarla veya programatik olarak `EPROCESS.Protection` değeri okunarak **kontrol edebilirsiniz**.
- LSASS genellikle `PsProtectedSignerLsa-Light` (`0x41`) değerine sahip olur ve bu değere yalnızca `WinTcb` (`0x61` veya `0x62`) gibi daha yüksek seviyeli bir signer ile imzalanmış süreçler erişebilir.
- PPL yalnızca **Userland-level bir kısıtlamadır**; **kernel-level code** bunu tamamen bypass edebilir.
- LSASS'ın PPL olması, **kernel shellcode çalıştırabiliyor** veya uygun access'e sahip yüksek ayrıcalıklı bir süreçten **yararlanabiliyorsanız**, credential dumping yapılmasını engellemez.
- **PPL'yi ayarlamak veya kaldırmak**, reboot ya da **Secure Boot/UEFI settings** gerektirir; bu ayarlar, registry değişiklikleri geri alınsa bile PPL ayarını kalıcı olarak koruyabilir.

### Launch sırasında bir PPL process oluşturma (documented API)

Windows, extended startup attribute list kullanarak oluşturma sırasında bir child process için Protected Process Light level istemenin documented bir yolunu sunar. Bu, signing gereksinimlerini bypass etmez — hedef image, istenen signer class için imzalanmış olmalıdır.

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
- `STARTUPINFOEX` ile `InitializeProcThreadAttributeList` ve `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)` kullanın, ardından `CreateProcess*` işlevine `EXTENDED_STARTUPINFO_PRESENT` geçirin.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Protection `DWORD`, `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` veya `PROTECTION_LEVEL_LSA_LIGHT` gibi sabitlere ayarlanabilir.
- Child process yalnızca image ilgili signer class için imzalanmışsa PPL olarak başlar; aksi durumda process creation başarısız olur. Bu genellikle `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)` hatasıyla sonuçlanır.
- Bu bir bypass değildir — uygun şekilde imzalanmış image'lar için tasarlanmış desteklenen bir API'dir. Tool'ları harden etmek veya PPL-korumalı yapılandırmaları doğrulamak için kullanışlıdır.

Minimal loader kullanan örnek CLI:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**PPL protections bypass seçenekleri:**

PPL'e rağmen LSASS dump etmek istiyorsanız, 3 ana seçeneğiniz vardır:
1. **İmzalı bir kernel driver (ör. Mimikatz + mimidrv.sys) kullanarak** **LSASS'in protection flag'ini kaldırmak**:

![Credential protection etkileşimini gösteren Mimikatz mimidrv driver çıktısı](../../images/mimidrv.png)

2. **Kendi Vulnerable Driver'ınızı Getirin (BYOVD)**; custom kernel code çalıştırarak protection'ı devre dışı bırakın. **PPLKiller**, **gdrv-loader** veya **kdmapper** gibi tool'lar bunu mümkün kılar.
3. Açık bir LSASS handle'ına sahip başka bir process'ten (ör. bir AV process'i) **mevcut LSASS handle'ını çalın**, ardından bunu process'inize **duplicate edin**. `pypykatz live lsa --method handledup` tekniği bunun temelidir.
4. Address space'ine veya başka bir privileged process'in içine arbitrary code yüklemenize izin veren bazı privileged process'leri **abuse edin**; bu, PPL restrictions'ı etkili şekilde bypass eder. Bunun bir örneğini [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) veya [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) adreslerinde görebilirsiniz.

**LSA protection'ın (PPL/PP) LSASS için mevcut durumunu kontrol etme:**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`** çalıştırıldığında, bu koruma nedeniyle muhtemelen `0x00000005` hata koduyla başarısız olur.

- Bu kontrol hakkında daha fazla bilgi için [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, yalnızca **Windows 10 (Enterprise ve Education sürümleri)** için sunulan ve **Virtual Secure Mode (VSM)** ile **Virtualization Based Security (VBS)** kullanarak makine kimlik bilgilerinin güvenliğini artıran bir özelliktir. CPU virtualization extensions özelliklerinden yararlanarak temel işlemleri, ana işletim sisteminin erişim alanından uzakta, korumalı bir bellek alanı içinde izole eder. Bu izolasyon, kernel'in bile VSM içindeki belleğe erişememesini sağlayarak kimlik bilgilerini **pass-the-hash** gibi saldırılara karşı etkili şekilde korur. **Local Security Authority (LSA)** bu güvenli ortam içinde bir trustlet olarak çalışırken, ana işletim sistemindeki **LSASS** işlemi yalnızca VSM'nin LSA'sı ile iletişim kurar.

Varsayılan olarak **Credential Guard** etkin değildir ve bir kuruluş içinde manuel olarak etkinleştirilmesi gerekir. Kimlik bilgilerini ayıklama yetenekleri kısıtlanan **Mimikatz** gibi araçlara karşı güvenliği artırmak açısından kritik öneme sahiptir. Ancak oturum açma girişimleri sırasında kimlik bilgilerini clear text olarak yakalamak için özel **Security Support Providers (SSP)** eklenmesi yoluyla güvenlik açıklarından hâlâ yararlanılabilir.

**Credential Guard**'ın etkinleştirilme durumunu doğrulamak için _**HKLM\System\CurrentControlSet\Control\LSA**_ altındaki _**LsaCfgFlags**_ registry key incelenebilir. "**1**" değeri **UEFI lock** ile etkinleştirildiğini, "**2**" kilit olmadan etkinleştirildiğini, "**0**" ise etkin olmadığını belirtir. Bu registry kontrolü güçlü bir gösterge olsa da Credential Guard'ı etkinleştirmek için gereken tek adım değildir. Bu özelliği etkinleştirmeye yönelik ayrıntılı yönergeler ve bir PowerShell script'i çevrimiçi olarak mevcuttur.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10'da **Credential Guard**'ı etkinleştirme ve **Windows 11 Enterprise and Education (version 22H2)** ile uyumlu sistemlerde otomatik olarak etkinleştirilmesi hakkında kapsamlı bilgi ve talimatlar için [Microsoft'un belgelerini](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) inceleyin.<sup>[[9]](#references)</sup>

Kimlik bilgilerini yakalamak için özel SSP'lerin uygulanmasına ilişkin daha fazla ayrıntı [bu kılavuzda](../active-directory-methodology/custom-ssp.md) sunulmaktadır.

## RDP RestrictedAdmin Mode

**Windows 8.1 ve Windows Server 2012 R2**, _**Restricted Admin mode for RDP**_ dahil olmak üzere çeşitli yeni güvenlik özelliklerini kullanıma sundu. Bu mod, [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) saldırılarıyla ilişkili riskleri azaltarak güvenliği artırmak amacıyla tasarlanmıştır.

Geleneksel olarak, RDP aracılığıyla uzak bir bilgisayara bağlanırken kimlik bilgileriniz hedef makinede depolanır. Bu durum, özellikle yükseltilmiş ayrıcalıklara sahip hesaplar kullanıldığında önemli bir güvenlik riski oluşturur. Ancak _**Restricted Admin mode**_'un kullanıma sunulmasıyla bu risk önemli ölçüde azaltılmıştır.

**mstsc.exe /RestrictedAdmin** komutu kullanılarak bir RDP bağlantısı başlatıldığında, uzak bilgisayarda kimlik bilgileriniz depolanmadan kimlik doğrulaması gerçekleştirilir. Bu yaklaşım, bir malware bulaşması veya kötü amaçlı bir kullanıcının uzak sunucuya erişim sağlaması durumunda kimlik bilgilerinizin sunucuda depolanmadığı için ele geçirilmemesini sağlar.

**Restricted Admin mode**'da RDP oturumundan ağ kaynaklarına erişme girişimlerinin kişisel kimlik bilgilerinizi kullanmayacağını; bunun yerine **makinenin kimliğinin** kullanılacağını belirtmek önemlidir.

Bu özellik, uzak masaüstü bağlantılarının güvenliğini sağlama ve bir güvenlik ihlali durumunda hassas bilgilerin açığa çıkmasını önleme açısından önemli bir ilerleme teşkil eder.

![Kimlik bilgisi çıkarma bağlamında Windows RAM bellek şeması](../../images/RAM.png)

Daha ayrıntılı bilgi için [bu kaynağı](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) inceleyin.<sup>[[6]](#references)</sup>

## Önbelleğe Alınmış Kimlik Bilgileri

Windows, **domain credentials**'ı **Local Security Authority (LSA)** aracılığıyla güvence altına alır ve **Kerberos** ile **NTLM** gibi güvenlik protokolleriyle logon süreçlerini destekler. Windows'un önemli bir özelliği, kullanıcıların **domain controller** çevrimdışı olsa bile bilgisayarlarına erişmeye devam edebilmesini sağlamak için **son on domain login** bilgisini önbelleğe alabilmesidir. Bu, şirketlerinin ağından sık sık uzakta bulunan laptop kullanıcıları için büyük bir avantajdır.

Önbelleğe alınan login sayısı, belirli bir **registry key veya group policy** aracılığıyla ayarlanabilir. Bu ayarı görüntülemek veya değiştirmek için aşağıdaki komut kullanılır:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Bu önbelleğe alınmış kimlik bilgilerine erişim sıkı bir şekilde kontrol edilir ve bunları görüntülemek için gerekli izinlere yalnızca **SYSTEM** hesabı sahiptir. Bu bilgilere erişmesi gereken yöneticiler, işlemi SYSTEM kullanıcı ayrıcalıklarıyla gerçekleştirmelidir. Kimlik bilgileri şu konumda depolanır: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**, `lsadump::cache` komutu kullanılarak bu önbelleğe alınmış kimlik bilgilerini çıkarmak için kullanılabilir.

Daha fazla ayrıntı için orijinal [kaynak](http://juggernaut.wikidot.com/cached-credentials) kapsamlı bilgiler sunmaktadır.<sup>[[7]](#references)</sup>

## Protected Users

**Protected Users group** üyeliği, kullanıcılar için çeşitli güvenlik geliştirmeleri sağlayarak kimlik bilgisi hırsızlığına ve kötüye kullanımına karşı daha yüksek düzeyde koruma sunar:

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials** Group Policy ayarı etkin olsa bile Protected Users kullanıcılarının düz metin kimlik bilgileri önbelleğe alınmaz.
- **Windows Digest**: **Windows 8.1 and Windows Server 2012 R2** sürümlerinden itibaren, Windows Digest durumu ne olursa olsun Protected Users kullanıcılarının düz metin kimlik bilgileri önbelleğe alınmaz.
- **NTLM**: Sistem, Protected Users kullanıcılarının düz metin kimlik bilgilerini veya NT one-way functions (NTOWF) değerlerini önbelleğe almaz.
- **Kerberos**: Protected Users için Kerberos authentication, **DES** veya **RC4 keys** oluşturmaz; ayrıca ilk Ticket-Granting Ticket (TGT) ediniminin ötesinde düz metin kimlik bilgilerini veya long-term keys değerlerini önbelleğe almaz.
- **Offline Sign-In**: Protected Users için oturum açma veya kilit açma sırasında önbelleğe alınmış bir verifier oluşturulmaz; bu nedenle bu hesaplar için çevrimdışı oturum açma desteklenmez.

Bu korumalar, **Protected Users group** üyesi olan bir kullanıcı cihazda oturum açtığı anda etkinleştirilir. Böylece kimlik bilgilerinin ele geçirilmesine yönelik çeşitli yöntemlere karşı koruma sağlamak için kritik güvenlik önlemleri devreye alınır.

Daha ayrıntılı bilgi için resmi [belgelere](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) başvurun.<sup>[[10]](#references)</sup>

**[belgelerden](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) tablo.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators            | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators              |
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
