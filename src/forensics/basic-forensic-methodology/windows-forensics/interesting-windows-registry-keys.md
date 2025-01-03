# İlginç Windows Kayıt Defteri Anahtarları

### İlginç Windows Kayıt Defteri Anahtarları

{{#include ../../../banners/hacktricks-training.md}}

### **Windows Sürümü ve Sahibi Bilgileri**

- **`Software\Microsoft\Windows NT\CurrentVersion`** altında, Windows sürümünü, Servis Paketini, kurulum zamanını ve kayıtlı sahibin adını basit bir şekilde bulabilirsiniz.

### **Bilgisayar Adı**

- Ana bilgisayar adı **`System\ControlSet001\Control\ComputerName\ComputerName`** altında bulunur.

### **Saat Dilimi Ayarı**

- Sistem saat dilimi **`System\ControlSet001\Control\TimeZoneInformation`** içinde saklanır.

### **Erişim Zamanı Takibi**

- Varsayılan olarak, son erişim zamanı takibi kapalıdır (**`NtfsDisableLastAccessUpdate=1`**). Bunu etkinleştirmek için:
`fsutil behavior set disablelastaccess 0` kullanın.

### Windows Sürümleri ve Servis Paketleri

- **Windows sürümü**, sürümü (örneğin, Home, Pro) ve sürümünü (örneğin, Windows 10, Windows 11) belirtirken, **Servis Paketleri** düzeltmeler ve bazen yeni özellikler içeren güncellemelerdir.

### Son Erişim Zamanını Etkinleştirme

- Son erişim zamanı takibini etkinleştirmek, dosyaların en son ne zaman açıldığını görmenizi sağlar; bu, adli analiz veya sistem izleme için kritik olabilir.

### Ağ Bilgileri Detayları

- Kayıt defteri, **ağ türleri (kablosuz, kablolu, 3G)** ve **ağ kategorileri (Genel, Özel/Ev, Alan/İş)** dahil olmak üzere ağ yapılandırmaları hakkında kapsamlı veriler tutar; bu, ağ güvenlik ayarlarını ve izinlerini anlamak için hayati öneme sahiptir.

### İstemci Tarafı Önbellekleme (CSC)

- **CSC**, paylaşılan dosyaların kopyalarını önbelleğe alarak çevrimdışı dosya erişimini artırır. Farklı **CSCFlags** ayarları, hangi dosyaların ve nasıl önbelleğe alınacağını kontrol eder, bu da performansı ve kullanıcı deneyimini etkiler, özellikle kesintili bağlantıların olduğu ortamlarda.

### Otomatik Başlatılan Programlar

- Çeşitli `Run` ve `RunOnce` kayıt defteri anahtarlarında listelenen programlar, başlangıçta otomatik olarak başlatılır, bu da sistemin önyükleme süresini etkiler ve kötü amaçlı yazılım veya istenmeyen yazılımları tanımlamak için ilgi noktaları olabilir.

### Shellbags

- **Shellbags**, yalnızca klasör görünüm tercihlerini saklamakla kalmaz, aynı zamanda klasör artık mevcut olmasa bile klasör erişiminin adli kanıtını sağlar. Diğer yollarla belirgin olmayan kullanıcı etkinliğini ortaya çıkardığı için soruşturmalar için değerlidir.

### USB Bilgileri ve Adli Analiz

- Kayıt defterinde saklanan USB cihazlarıyla ilgili detaylar, bir bilgisayara hangi cihazların bağlandığını izlemeye yardımcı olabilir ve potansiyel olarak bir cihazı hassas dosya transferleri veya yetkisiz erişim olaylarıyla ilişkilendirebilir.

### Hacim Seri Numarası

- **Hacim Seri Numarası**, dosya sisteminin belirli bir örneğini izlemek için kritik olabilir; bu, dosya kökeninin farklı cihazlar arasında belirlenmesi gereken adli senaryolar için yararlıdır.

### **Kapatma Detayları**

- Kapatma zamanı ve sayısı (ikincisi yalnızca XP için) **`System\ControlSet001\Control\Windows`** ve **`System\ControlSet001\Control\Watchdog\Display`** içinde saklanır.

### **Ağ Yapılandırması**

- Ayrıntılı ağ arayüzü bilgileri için **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**'e bakın.
- İlk ve son ağ bağlantı zamanları, VPN bağlantıları dahil olmak üzere, **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** altında çeşitli yollarla kaydedilir.

### **Paylaşılan Klasörler**

- Paylaşılan klasörler ve ayarlar **`System\ControlSet001\Services\lanmanserver\Shares`** altında bulunur. İstemci Tarafı Önbellekleme (CSC) ayarları çevrimdışı dosya erişilebilirliğini belirler.

### **Otomatik Başlatılan Programlar**

- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** gibi yollar ve `Software\Microsoft\Windows\CurrentVersion` altında benzer girişler, başlangıçta çalışacak şekilde ayarlanmış programları detaylandırır.

### **Aramalar ve Yazılan Yollar**

- Gezginde yapılan aramalar ve yazılan yollar, **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** altında WordwheelQuery ve TypedPaths için sırasıyla izlenir.

### **Son Belgeler ve Ofis Dosyaları**

- Erişilen son belgeler ve Ofis dosyaları, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` ve belirli Ofis sürüm yollarında not edilir.

### **En Son Kullanılan (MRU) Öğeler**

- Son dosya yolları ve komutları gösteren MRU listeleri, `NTUSER.DAT` altında çeşitli `ComDlg32` ve `Explorer` alt anahtarlarında saklanır.

### **Kullanıcı Etkinliği Takibi**

- Kullanıcı Yardımcı özelliği, **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`** altında çalıştırma sayısı ve son çalıştırma zamanı dahil olmak üzere ayrıntılı uygulama kullanım istatistiklerini kaydeder.

### **Shellbags Analizi**

- Klasör erişim detaylarını ortaya çıkaran Shellbags, `USRCLASS.DAT` ve `NTUSER.DAT` altında `Software\Microsoft\Windows\Shell` içinde saklanır. Analiz için **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** kullanın.

### **USB Cihaz Geçmişi**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** ve **`HKLM\SYSTEM\ControlSet001\Enum\USB`** bağlı USB cihazları hakkında zengin detaylar içerir; bunlar arasında üretici, ürün adı ve bağlantı zaman damgaları bulunur.
- Belirli bir USB cihazıyla ilişkili kullanıcı, cihazın **{GUID}**'sini arayarak `NTUSER.DAT` hives'inde tespit edilebilir.
- Son takılı cihaz ve hacim seri numarası, sırasıyla `System\MountedDevices` ve `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` üzerinden izlenebilir.

Bu kılavuz, Windows sistemlerinde ayrıntılı sistem, ağ ve kullanıcı etkinliği bilgilerine erişim için kritik yolları ve yöntemleri özetlemektedir; açıklık ve kullanılabilirlik hedeflenmiştir.

{{#include ../../../banners/hacktricks-training.md}}
