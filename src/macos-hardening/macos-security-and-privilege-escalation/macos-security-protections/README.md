# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper genellikle, **Karantina + Gatekeeper + XProtect** birleşimini ifade etmek için kullanılır; bunlar, **kullanıcıların indirdiği potansiyel olarak kötü amaçlı yazılımları çalıştırmasını önlemeye** çalışan 3 macOS güvenlik modülüdür.

Daha fazla bilgi:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Süreç Kısıtlamaları

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox, sandbox içinde çalışan **uygulamaları**, uygulamanın birlikte çalıştığı **Sandbox profilinde belirtilen izin verilen eylemlerle** sınırlar. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** bir güvenlik framework'üdür. Uygulamaların **izinlerini yönetmek**, özellikle de hassas özelliklere erişimlerini düzenlemek için tasarlanmıştır. Buna **konum servisleri, kişiler, fotoğraflar, mikrofon, kamera, accessibility ve full disk access** gibi unsurlar dahildir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebilmesini sağlayarak gizliliği ve kişisel veriler üzerindeki kontrolü güçlendirir.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS'taki launch constraints, **bir süreci kimin**, **nasıl** ve **nereden** başlatabileceğini tanımlayarak **süreç başlatmayı düzenleyen** bir güvenlik özelliğidir. macOS Ventura'da kullanıma sunulan bu özellik, sistem binary'lerini bir **trust cache** içindeki constraint kategorilerine ayırır. Her executable binary, **self**, **parent** ve **responsible** constraints dahil olmak üzere **launch** işlemi için belirlenmiş **kurallara** sahiptir. macOS Sonoma'da üçüncü taraf uygulamalara **Environment Constraints** olarak genişletilen bu özellikler, süreç başlatma koşullarını yöneterek olası sistem exploit'lerini azaltmaya yardımcı olur.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT), macOS'un güvenlik altyapısının başka bir parçasıdır. Adından da anlaşılacağı gibi MRT'nin temel işlevi, **bulaşmış sistemlerden bilinen malware'i kaldırmaktır**.

Bir Mac'te malware tespit edildiğinde (XProtect tarafından veya başka bir yolla), MRT **malware'i otomatik olarak kaldırmak** için kullanılabilir. MRT arka planda sessizce çalışır ve genellikle sistem güncellendiğinde veya yeni bir malware tanımı indirildiğinde çalışır (MRT'nin malware tespit etmek için kullandığı kuralların binary'nin içinde bulunduğu görülmektedir).

Hem XProtect hem de MRT macOS'un güvenlik önlemlerinin parçası olsa da farklı işlevler gerçekleştirir:

- **XProtect** önleyici bir araçtır. **Dosyaları indirilirken** (belirli uygulamalar aracılığıyla) **kontrol eder** ve bilinen herhangi bir malware türü tespit ederse **dosyanın açılmasını engeller**; böylece malware'in ilk etapta sisteminize bulaşmasını önler.
- **MRT** ise **tepkisel bir araçtır**. Bir sistemde malware tespit edildikten sonra çalışır ve sistemi temizlemek için zararlı yazılımı kaldırmayı amaçlar.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumunda bulunur.

## Background Tasks Management

**macOS**, bir araç kod çalıştırmayı kalıcı hale getirmek için bilinen bir **tekniği** (Login Items, Daemons...) her kullandığında artık **uyarı verir**; böylece kullanıcı **hangi yazılımın persistence sağladığını** daha iyi bilir.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu işlem, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumunda bulunan bir **daemon** ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumundaki **agent** ile gerçekleştirilir.<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`**, bir şeyin persistence için kullanılan bir klasöre yüklendiğini, **FSEvents'leri alarak** ve bunlar için bazı **handler'lar** oluşturarak anlar.<sup>[[1]](#references)</sup>

Buna ek olarak Apple tarafından sürdürülen ve sık sık persistence sağlayan **bilinen uygulamaları** içeren bir plist dosyası bulunur. Dosya şu konumdadır: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>.
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Apple CLI tool'u çalıştırarak **yapılandırılmış tüm** arka plan öğelerini enumerate etmek mümkündür:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ayrıca, bu bilgileri [**DumpBTM**](https://github.com/objective-see/DumpBTM) ile listelemek de mümkündür.<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Bu bilgiler **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** içinde saklanır ve Terminal'in FDA'ya ihtiyacı vardır.<sup>[[2]](#references)</sup>

### BTM ile Oynama

Yeni bir persistence bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir event oluşturulur. Bu nedenle, bu **event**'in gönderilmesini **engellemenin** veya **agent'ın uyarı vermesini** önlemenin herhangi bir yolu, saldırganın BTM'yi _**bypass**_ etmesine yardımcı olur.<sup>[[1]](#references)</sup>

- **Veritabanını sıfırlama**: Aşağıdaki komutun çalıştırılması veritabanını sıfırlar (veritabanını baştan oluşturması gerekir); ancak herhangi bir nedenle, bu işlemden sonra sistem yeniden başlatılana kadar **yeni persistence'lar hakkında uyarı verilmez**.<sup>[[1]](#references)</sup>
- **root** gereklidir.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent'i Durdur**: Yeni tespitler bulunduğunda **kullanıcıyı uyarmaması** için Agent'e bir durdurma sinyali göndermek mümkündür.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: **persistence'ı oluşturan process hemen ardından hızlıca kapanırsa**, daemon onun hakkında **bilgi almaya** çalışır, **başarısız olur** ve yeni bir şeyin persistence yaptığını belirten **event'i gönderemez**.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
