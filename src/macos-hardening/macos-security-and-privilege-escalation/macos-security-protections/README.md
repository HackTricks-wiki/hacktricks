# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper genellikle **Quarantine + Gatekeeper + XProtect** birleşimini ifade etmek için kullanılır; bunlar, **indirilmiş potansiyel olarak kötü amaçlı yazılımların kullanıcılar tarafından çalıştırılmasını engellemeye** çalışan 3 macOS güvenlik modülüdür.

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

MacOS Sandbox, sandbox içinde çalışan **uygulamaları**, uygulamanın çalıştığı **Sandbox profilinde belirtilen izin verilen eylemlerle sınırlar**. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** bir güvenlik framework'üdür. Uygulamaların izinlerini **yönetmek**, özellikle de hassas özelliklere erişimlerini düzenlemek için tasarlanmıştır. Buna **konum servisleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi unsurlar dahildir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebilmesini sağlayarak gizliliği ve kişisel veriler üzerindeki kontrolü güçlendirir.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS'taki Launch constraints, bir süreci **kimlerin**, **nasıl** ve **nereden** başlatabileceğini tanımlayarak **süreç başlatmayı düzenleyen** bir güvenlik özelliğidir. macOS Ventura'da tanıtılan bu özellik, sistem binary'lerini bir **trust cache** içindeki constraint kategorilerine ayırır. Her executable binary, **self**, **parent** ve **responsible** constraints dahil olmak üzere **başlatılmasına** yönelik belirli **kurallara** sahiptir. macOS Sonoma'da üçüncü taraf uygulamalara **Environment Constraints** olarak genişletilen bu özellikler, süreç başlatma koşullarını yöneterek olası sistem exploit'lerini azaltmaya yardımcı olur.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT), macOS güvenlik altyapısının bir başka parçasıdır. Adından da anlaşılacağı gibi MRT'nin temel işlevi **bilinen malware'leri infected sistemlerden kaldırmaktır**.

Bir Mac'te malware tespit edildiğinde (XProtect tarafından veya başka bir yöntemle), MRT **malware'i otomatik olarak kaldırmak** için kullanılabilir. MRT arka planda sessizce çalışır ve genellikle sistem güncellendiğinde veya yeni bir malware tanımı indirildiğinde çalışır (MRT'nin malware tespit etmek için kullandığı kuralların binary'nin içinde bulunduğu görülüyor).

Hem XProtect hem de MRT macOS güvenlik önlemlerinin parçası olsa da farklı işlevleri yerine getirir:

- **XProtect** önleyici bir araçtır. **Dosyaları indirildikleri sırada** (belirli uygulamalar aracılığıyla) **kontrol eder** ve bilinen malware türlerinden herhangi birini tespit ederse **dosyanın açılmasını engeller**; böylece malware'in ilk etapta sisteminize bulaşmasını önler.
- Buna karşılık **MRT**, **reaktif bir araçtır**. Bir sistemde malware tespit edildikten sonra çalışır ve sistemi temizlemek için sorun oluşturan yazılımı kaldırmayı amaçlar.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumunda bulunur.

## Background Tasks Management

**macOS**, bir araç **code execution'ı kalıcı hale getirmek için iyi bilinen bir technique** (Login Items, Daemons gibi) kullandığında artık **her seferinde uyarı verir**; böylece kullanıcı **hangi yazılımın persistence sağladığını** daha iyi bilir.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu işlem, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumundaki bir **daemon** ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumundaki **agent** ile gerçekleştirilir.<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`**'nin bir şeyin persistence sağlanan bir klasöre kurulduğunu anlamasının yolu, **FSEvents'leri alması** ve bunlar için bazı **handler'lar** oluşturmasıdır.<sup>[[1]](#references)</sup>

Ayrıca Apple tarafından sürdürülen ve sıklıkla persistence sağlayan **iyi bilinen uygulamaları** içeren bir plist dosyası şu konumda bulunur: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>.
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

Apple CLI tool'u çalıştırarak yapılandırılmış **tüm** arka plan öğelerini enumerate etmek mümkündür:<sup>[[3]](#references)</sup>
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
Bu bilgiler **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** konumunda depolanır ve Terminal için FDA gerekir.<sup>[[2]](#references)</sup>

### BTM ile Oynama

Yeni bir persistence bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir event oluşturulur. Bu nedenle, bu **event**'in gönderilmesini **engellemenin** veya **agent'ın kullanıcıyı uyarmasını** önlemenin herhangi bir yolu, saldırganın BTM'yi _**bypass**_ etmesine yardımcı olur.<sup>[[1]](#references)</sup>

- **Veritabanını sıfırlama**: Aşağıdaki komutu çalıştırmak veritabanını sıfırlar (veritabanının baştan oluşturulması gerekir); ancak bazı nedenlerden dolayı, bu işlemden sonra sistem yeniden başlatılana kadar **hiçbir yeni persistence için uyarı verilmez**.<sup>[[1]](#references)</sup>
- **root** gereklidir.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent'i Durdur**: Agent'a bir durdurma sinyali gönderilerek yeni tespitler bulunduğunda **kullanıcıyı uyarmaması** sağlanabilir.<sup>[[1]](#references)</sup>
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
- **Bug**: **persistence'ı oluşturan process**, oluşturduktan hemen sonra **hızla sona ererse**, daemon onun hakkında **bilgi almaya** çalışacak, **başarısız olacak** ve yeni bir şeyin persistence oluşturduğunu belirten **event'i gönderemeyecek**.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "macOS'un Background Task Management'ını Gizeminden Arındırma (& Bypass Etme)" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Yeni (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Mac'te login item'ları ve background task'leri yönetme - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
