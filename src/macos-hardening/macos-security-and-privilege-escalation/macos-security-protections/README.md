# macOS Güvenlik Koruma Önlemleri

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper genellikle **Quarantine + Gatekeeper + XProtect** kombinasyonunu ifade etmek için kullanılır; bu, kullanıcıların **potansiyel olarak zararlı yazılımları çalıştırmalarını engellemeye** çalışan 3 macOS güvenlik modülüdür.

Daha fazla bilgi için:

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Süreç Sınırlamaları

### MACF

### SIP - Sistem Bütünlüğü Koruması

{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox, sandbox içinde çalışan uygulamaları, uygulamanın çalıştığı Sandbox profilinde belirtilen **izin verilen eylemlerle** sınırlamaktadır. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Şeffaflık, Onay ve Kontrol**

**TCC (Şeffaflık, Onay ve Kontrol)** bir güvenlik çerçevesidir. Uygulamaların **izinlerini yönetmek** için tasarlanmıştır, özellikle de hassas özelliklere erişimlerini düzenleyerek. Bu, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi unsurları içerir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebileceğini garanti ederek, kişisel veriler üzerindeki gizlilik ve kontrolü artırır.

{{#ref}}
macos-tcc/
{{#endref}}

### Başlatma/Ortam Kısıtlamaları ve Güven Cache'i

macOS'taki başlatma kısıtlamaları, bir sürecin **başlatılmasını düzenlemek** için bir güvenlik özelliğidir; **kimin** bir süreci başlatabileceğini, **nasıl** ve **nereden** tanımlayarak. macOS Ventura ile tanıtılan bu özellikler, sistem ikili dosyalarını bir **güven cache'i** içinde kısıtlama kategorilerine ayırır. Her yürütülebilir ikili dosya, **başlatma** için belirli **kurallara** sahiptir; bunlar arasında **kendisi**, **ebeveyn** ve **sorumlu** kısıtlamaları bulunur. macOS Sonoma'da üçüncü taraf uygulamalara **Ortam** Kısıtlamaları olarak genişletilen bu özellikler, süreç başlatma koşullarını yöneterek potansiyel sistem istismarlarını azaltmaya yardımcı olur.

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Kötü Amaçlı Yazılım Kaldırma Aracı

Kötü Amaçlı Yazılım Kaldırma Aracı (MRT), macOS'un güvenlik altyapısının bir parçasıdır. Adından da anlaşılacağı gibi, MRT'nin ana işlevi **bilinen kötü amaçlı yazılımları enfekte olmuş sistemlerden kaldırmaktır**.

Bir Mac'te kötü amaçlı yazılım tespit edildiğinde (ya XProtect ya da başka bir yöntemle), MRT otomatik olarak **kötü amaçlı yazılımı kaldırmak için** kullanılabilir. MRT, arka planda sessizce çalışır ve genellikle sistem güncellendiğinde veya yeni bir kötü amaçlı yazılım tanımı indirildiğinde çalışır (MRT'nin kötü amaçlı yazılımı tespit etmek için kurallarının ikilinin içinde olduğu görünmektedir).

Hem XProtect hem de MRT, macOS'un güvenlik önlemlerinin bir parçası olmasına rağmen, farklı işlevler yerine getirir:

- **XProtect**, önleyici bir araçtır. **İndirilen dosyaları kontrol eder** (belirli uygulamalar aracılığıyla) ve bilinen kötü amaçlı yazılım türlerini tespit ederse, dosyanın **açılmasını engeller**, böylece kötü amaçlı yazılımın sisteminizi enfekte etmesini önler.
- **MRT** ise **reaktif bir araçtır**. Kötü amaçlı yazılım bir sistemde tespit edildikten sonra çalışır ve amacı, sistemin temizlenmesi için zararlı yazılımı kaldırmaktır.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumundadır.

## Arka Plan Görevleri Yönetimi

**macOS**, artık her seferinde bir aracın **kod yürütmesini sürdürmek için bilinen bir tekniği** (Login Items, Daemons gibi) kullandığında kullanıcıyı **uyarıyor**, böylece kullanıcı **hangi yazılımın sürdüğünü** daha iyi biliyor.

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumundaki bir **daemon** ile çalışır ve **ajan** `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumundadır.

**`backgroundtaskmanagementd`**'nin bir şeyin kalıcı bir klasörde yüklü olduğunu bilmesinin yolu, **FSEvents** alarak ve bunlar için bazı **işleyiciler** oluşturarak gerçekleşir.

Ayrıca, sıkça kalıcı olan **bilinen uygulamaları** içeren bir plist dosyası vardır; bu dosya Apple tarafından yönetilmektedir ve konumu: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Apple cli aracını kullanarak **tüm** yapılandırılmış arka plan öğelerini listelemek mümkündür:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ayrıca, bu bilgileri [**DumpBTM**](https://github.com/objective-see/DumpBTM) ile listelemek de mümkündür.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Bu bilgi **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** içinde saklanmaktadır ve Terminal FDA gerektirir.

### BTM ile Oynama

Yeni bir kalıcılık bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir olay meydana gelir. Bu nedenle, bu **olayın** gönderilmesini **önlemenin** veya **ajanın** kullanıcıyı uyarmasını engellemenin herhangi bir yolu, bir saldırgana BTM'yi _**bypass**_ etmesine yardımcı olacaktır.

- **Veritabanını sıfırlama**: Aşağıdaki komut veritabanını sıfırlayacaktır (temelden yeniden inşa edilmesi gerekir), ancak bir nedenle, bunu çalıştırdıktan sonra **sistem yeniden başlatılana kadar yeni bir kalıcılık uyarısı yapılmayacaktır**.
- **root** gereklidir.
```bash
# Reset the database
sfltool resettbtm
```
- **Ajanı Durdur**: Ajanı durdurmak için bir durdurma sinyali göndermek mümkündür, böylece **yeni tespitler bulunduğunda kullanıcıyı uyarmayacaktır**.
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
- **Hata**: Eğer **kalıcılığı oluşturan süreç hemen ardından hızlı bir şekilde mevcutsa**, daemon **hakkında bilgi almaya** çalışacak, **başarısız olacak** ve **yeni bir şeyin kalıcı olduğunu belirten olayı gönderemeyecek**.

Referanslar ve **BTM hakkında daha fazla bilgi**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
