# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper genellikle **Quarantine + Gatekeeper + XProtect** birleşimini ifade etmek için kullanılır; bunlar, **potansiyel olarak kötü amaçlı indirilen yazılımların kullanıcılar tarafından çalıştırılmasını engellemeye** çalışan 3 macOS security module'üdür.

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

MacOS Sandbox, sandbox içinde çalışan **uygulamaları**, uygulamanın çalıştığı **Sandbox profile'ında belirtilen izin verilen eylemlerle sınırlar**. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** bir security framework'üdür. Uygulamaların **izinlerini yönetmek** ve özellikle hassas özelliklere erişimlerini düzenlemek için tasarlanmıştır. Buna **konum servisleri, kişiler, fotoğraflar, microphone, camera, accessibility ve full disk access** gibi unsurlar dahildir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebilmesini sağlayarak gizliliği ve kişisel veriler üzerindeki kontrolü güçlendirir.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS'taki Launch constraints, **bir süreci kimin**, **nasıl** ve **nereden** başlatabileceğini tanımlayarak **süreç başlatılmasını düzenleyen** bir security feature'dır. macOS Ventura'da tanıtılan bu özellik, system binary'lerini bir **trust cache** içindeki constraint kategorilerine ayırır. Her executable binary'nin **başlatılması** için **self**, **parent** ve **responsible** constraints dahil olmak üzere belirlenmiş **kuralları** vardır. macOS Sonoma'da üçüncü taraf uygulamalara **Environment Constraints** olarak genişletilen bu özellikler, süreç başlatma koşullarını yöneterek olası system exploitation'larını azaltmaya yardımcı olur.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT), macOS'un security infrastructure'ının başka bir parçasıdır. Adından da anlaşılacağı üzere MRT'nin temel işlevi **bilinen malware'leri infected system'lerden kaldırmaktır**.

Bir Mac'te malware tespit edildiğinde (XProtect tarafından veya başka bir yolla), MRT **malware'i otomatik olarak kaldırmak** için kullanılabilir. MRT arka planda sessizce çalışır ve genellikle system güncellendiğinde veya yeni bir malware definition indirildiğinde çalışır (MRT'nin malware tespit etmek için kullandığı kuralların binary içinde bulunduğu görülüyor).

Hem XProtect hem de MRT macOS'un security measures'ının parçası olsa da farklı işlevler gerçekleştirir:

- **XProtect** bir preventative tool'dur. **Dosyaları indirildikleri sırada** (belirli applications aracılığıyla) **kontrol eder** ve bilinen herhangi bir malware türü tespit ederse **dosyanın açılmasını engeller**; böylece malware'in ilk etapta system'e bulaşmasını önler.
- Buna karşılık **MRT**, **reactive tool**'dur. Bir system'de malware tespit edildikten sonra çalışır ve system'i temizlemek için offending software'i kaldırmayı amaçlar.

MRT application'ı **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumunda bulunur.

## Background Tasks Management

**macOS**, bir tool code execution'ı persist etmek için iyi bilinen bir **technique** kullandığında (Login Items, Daemons gibi) artık **her seferinde alert verir**; böylece kullanıcı **hangi software'in persistence sağladığını** daha iyi bilir.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu işlem, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumunda bulunan bir **daemon** ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumundaki **agent** ile gerçekleştirilir.<sup>[1]</sup>

**`backgroundtaskmanagementd`**'nin bir şeyin persistent folder'a yüklendiğini anlamasının yolu, **FSEvents'leri alması** ve bunlar için bazı **handler'lar** oluşturmasıdır.<sup>[1]</sup>

Ayrıca Apple tarafından sürdürülen ve sık sık persistence sağlayan **well known applications**'ları içeren bir plist file şu konumda bulunur: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

Apple CLI aracını çalıştırarak yapılandırılmış **tüm** arka plan öğelerini **enumerate** etmek mümkündür:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ayrıca, bu bilgileri [**DumpBTM**](https://github.com/objective-see/DumpBTM) ile listelemek de mümkündür.<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Bu bilgiler **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** içinde depolanır ve Terminal için FDA gerekir.<sup>[2]</sup>

### BTM ile Oynamak

Yeni bir persistence bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir event oluşturulur. Bu nedenle, bu **event**'in gönderilmesini **engellemenin** veya **agent**'ın kullanıcıyı **uyarmasını engellemenin** herhangi bir yolu, saldırganın BTM'yi _**bypass**_ etmesine yardımcı olur.<sup>[1]</sup>

- **Veritabanını sıfırlama**: Aşağıdaki komutu çalıştırmak veritabanını sıfırlar (veritabanının baştan oluşturulması gerekir); ancak herhangi bir nedenle, bu işlemden sonra sistem yeniden başlatılana kadar **yeni bir persistence için uyarı verilmez**.<sup>[1]</sup>
- **root** gerekir.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent'i Durdurma**: Agent'e bir durdurma sinyali gönderilerek yeni tespitler bulunduğunda **kullanıcıyı uyarmaması** sağlanabilir.<sup>[1]</sup>
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
- **Hata**: **persistence'ı oluşturan process hemen ardından hızlıca kapanırsa**, daemon onun hakkında **bilgi almaya** çalışacak, **başarısız olacak** ve yeni bir şeyin persistence yaptığını belirten **event'i gönderemeyecek**.<sup>[1]</sup>

## Referanslar

- [1] [OBTS v6.0: "macOS'un Background Task Management Sisteminin Gizemini Çözmek (& Bypass Etmek)" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Yeni (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Mac'te login items ve background tasks'ı yönetme - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
