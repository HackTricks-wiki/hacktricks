# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper genellikle **Quarantine + Gatekeeper + XProtect** kombinasyonunu ifade etmek için kullanılır; bunlar, **kullanıcıların indirdiği potansiyel olarak kötü amaçlı yazılımları çalıştırmasını önlemeye** çalışan 3 macOS güvenlik modülüdür.

Daha fazla bilgi:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Process Limitations

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox, Sandbox içinde çalışan **uygulamaları**, uygulamanın çalıştığı **Sandbox profile** içinde belirtilen **izin verilen eylemlerle** sınırlar. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** bir güvenlik framework'üdür. Özellikle hassas özelliklere erişimi düzenleyerek uygulamaların **izinlerini yönetmek** için tasarlanmıştır. Buna **konum servisleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi unsurlar dahildir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebilmesini sağlayarak gizliliği ve kişisel veriler üzerindeki kontrolü güçlendirir.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS'taki launch constraints, **bir süreci kimin**, **nasıl** ve **nereden** başlatabileceğini tanımlayarak **süreç başlatmayı düzenleyen** bir güvenlik özelliğidir. macOS Ventura'da tanıtılan bu özellik, sistem binary'lerini bir **trust cache** içindeki constraint kategorilerine ayırır. Her executable binary'nin **launch** işlemi için **self**, **parent** ve **responsible** constraints dahil olmak üzere belirlenmiş **kuralları** vardır. macOS Sonoma'da üçüncü taraf uygulamalara **Environment** Constraints olarak genişletilen bu özellikler, süreç başlatma koşullarını yöneterek olası sistem exploitation'larını azaltmaya yardımcı olur.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT), macOS'un güvenlik altyapısının bir başka parçasıdır. Adından da anlaşılacağı gibi MRT'nin temel işlevi, **bilinen malware'leri bulaşmış sistemlerden kaldırmaktır**.

Bir Mac'te malware tespit edildiğinde (XProtect tarafından veya başka bir şekilde), MRT **malware'i otomatik olarak kaldırmak** için kullanılabilir. MRT arka planda sessizce çalışır ve genellikle sistem güncellendiğinde veya yeni bir malware definition indirildiğinde çalışır (MRT'nin malware tespit etmek için kullandığı kurallar binary'nin içinde gibi görünmektedir).

Hem XProtect hem de MRT macOS'un güvenlik önlemlerinin parçası olsa da farklı işlevler gerçekleştirirler:

- **XProtect** önleyici bir araçtır. **Dosyaları indirildikleri sırada kontrol eder** (belirli uygulamalar aracılığıyla) ve bilinen herhangi bir malware türü tespit ederse **dosyanın açılmasını engeller**; böylece malware'in ilk etapta sisteminize bulaşmasını önler.
- **MRT** ise **reaktif bir araçtır**. Bir sistemde malware tespit edildikten sonra çalışır ve sistemi temizlemek için zararlı yazılımı kaldırmayı amaçlar.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumunda bulunur.

## Background Tasks Management

**macOS**, bir araç iyi bilinen bir **code execution persistence tekniği** (Login Items, Daemons gibi) kullandığında artık **her seferinde uyarı verir**; böylece kullanıcı **hangi yazılımın persistence sağladığını** daha iyi bilir.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu işlem, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumunda bulunan bir **daemon** ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumundaki **agent** ile gerçekleştirilir.<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`**, bir şeyin persistent bir klasöre kurulduğunu **FSEvents'ları alarak** ve bunlar için bazı **handler'lar** oluşturarak anlar.<sup>[[1]](#references)</sup>

Ayrıca Apple tarafından sürdürülen ve sık sık persistence sağlayan **iyi bilinen uygulamaları** içeren bir plist dosyası şu konumda bulunur: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Apple cli tool kullanılarak çalışan **tüm** yapılandırılmış background item'ları enumerate etmek mümkündür:<sup>[[3]](#references)</sup>
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
Bu bilgiler **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** dosyasında saklanır ve Terminal'in FDA'ya ihtiyacı vardır.<sup>[[2]](#references)</sup>

### BTM ile oynama

Yeni bir persistence bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir event oluşur. Bu nedenle, bu **event**'in gönderilmesini **engellemenin** veya **agent**'ın kullanıcıyı **uyarmasını** önlemenin herhangi bir yolu, bir saldırganın BTM'yi _**bypass**_ etmesine yardımcı olur.<sup>[[1]](#references)</sup>

- **Veritabanını sıfırlama**: Aşağıdaki komutun çalıştırılması veritabanını sıfırlar (bu işlem veritabanını sıfırdan yeniden oluşturmalıdır). Ancak bunu yaptıktan sonra, sistem yeniden başlatılana kadar **yeni persistence uyarıları görünmez**.<sup>[[1]](#references)</sup>
- **root** gerekir.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent'i Durdur**: Yeni tespitler bulunduğunda **kullanıcıyı uyarmaması** için agent'a bir durdurma sinyali göndermek mümkündür.<sup>[[1]](#references)</sup>
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
- **Hata**: **persistence'ı oluşturan process hemen ardından çıkarsa**, daemon bu process hakkında **bilgi almaya** çalışır, **başarısız olur** ve yeni bir öğenin persistence gerçekleştirdiğini belirten **event'i gönderemez**.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "macOS'un Background Task Management'ını Gizemden Arındırma (& Bypass Etme)" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Yeni (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Mac'te login item'ları ve background task'ları yönetme - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
