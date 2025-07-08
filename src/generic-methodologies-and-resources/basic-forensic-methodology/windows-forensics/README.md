# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Yolda `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` veritabanı `appdb.dat` (Windows yıldönümünden önce) veya `wpndatabase.db` (Windows Yıldönümünden sonra) bulunabilir.

Bu SQLite veritabanının içinde, ilginç veriler içerebilecek tüm bildirimlerin (XML formatında) bulunduğu `Notification` tablosunu bulabilirsiniz.

### Timeline

Timeline, ziyaret edilen web sayfalarının, düzenlenen belgelerin ve çalıştırılan uygulamaların **kronolojik geçmişini** sağlayan bir Windows özelliğidir.

Veritabanı, yolda `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` bulunur. Bu veritabanı bir SQLite aracıyla veya [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) aracıyla açılabilir **ve bu araç 2 dosya oluşturur** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) aracıyla açılabilir.

### ADS (Alternate Data Streams)

İndirilen dosyalar, intranet, internet vb. üzerinden **nasıl** **indirildiğini** gösteren **ADS Zone.Identifier** içerebilir. Bazı yazılımlar (tarayıcılar gibi) genellikle dosyanın indirildiği **URL** gibi **daha fazla** **bilgi** de ekler.

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10'da **Recycle Bin** kök dizinde **`$Recycle.bin`** klasöründe bulunabilir (`C:\$Recycle.bin`).\
Bu klasörde bir dosya silindiğinde 2 özel dosya oluşturulur:

- `$I{id}`: Dosya bilgileri (silindiği tarih)
- `$R{id}`: Dosyanın içeriği

![](<../../../images/image (1029).png>)

Bu dosyalara sahip olduğunuzda, silinen dosyaların orijinal adresini ve silindiği tarihi almak için [**Rifiuti**](https://github.com/abelcheung/rifiuti2) aracını kullanabilirsiniz (Vista – Win10 için `rifiuti-vista.exe` kullanın).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Hacim Gölgesi Kopyaları

Gölge Kopyası, Microsoft Windows'a dahil olan ve bilgisayar dosyalarının veya hacimlerinin **yedek kopyalarını** veya anlık görüntülerini oluşturabilen bir teknolojidir; bu, dosyalar kullanılırken bile mümkündür.

Bu yedekler genellikle dosya sisteminin kökünden `\System Volume Information` içinde bulunur ve isimleri aşağıdaki resimde gösterilen **UID'lerden** oluşur:

![](<../../../images/image (94).png>)

**ArsenalImageMounter** ile adli görüntüyü monte ederek, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) aracı bir gölge kopyasını incelemek ve hatta gölge kopyası yedeklerinden **dosyaları çıkarmak** için kullanılabilir.

![](<../../../images/image (576).png>)

Kayıt defteri girişi `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, **yedeklenmeyecek** dosyaları ve anahtarları içerir:

![](<../../../images/image (254).png>)

Kayıt defteri `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` ayrıca `Hacim Gölgesi Kopyaları` hakkında yapılandırma bilgilerini içerir.

### Ofis Otomatik Kaydedilen Dosyaları

Ofis otomatik kaydedilen dosyalarını şurada bulabilirsiniz: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Öğeleri

Bir shell öğesi, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir öğedir.

### Son Belgeler (LNK)

Windows, kullanıcı bir dosyayı **açtığında, kullandığında veya oluşturduğunda** bu **kısayolları** **otomatik olarak** **oluşturur**:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Ofis: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Bir klasör oluşturulduğunda, klasöre, üst klasöre ve büyük üst klasöre bir bağlantı da oluşturulur.

Bu otomatik olarak oluşturulan bağlantı dosyaları, **bir dosya** **veya** **bir klasör** olup olmadığı, o dosyanın **MAC** **zamanları**, dosyanın saklandığı yerin **hacim bilgisi** ve **hedef dosyanın klasörü** gibi **kaynak hakkında bilgi** **içerir**. Bu bilgi, dosyalar silinirse kurtarmak için yararlı olabilir.

Ayrıca, bağlantı dosyasının **oluşturulma tarihi**, orijinal dosyanın **ilk** **kullanıldığı** **zaman** ve bağlantı dosyasının **değiştirilme tarihi**, kaynak dosyanın en son **kullanıldığı** **zamandır**.

Bu dosyaları incelemek için [**LinkParser**](http://4discovery.com/our-tools/) kullanabilirsiniz.

Bu araçta **2 set** zaman damgası bulacaksınız:

- **İlk Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **İkinci Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

İlk zaman damgası seti, **dosyanın kendisine ait zaman damgalarını** referans alır. İkinci set, **bağlantılı dosyanın zaman damgalarını** referans alır.

Aynı bilgiyi Windows CLI aracı olan [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) ile çalıştırarak da alabilirsiniz.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Bu durumda, bilgiler bir CSV dosyası içinde kaydedilecektir.

### Jumplists

Bunlar, her uygulama için belirtilen son dosyalardır. Her uygulamada erişebileceğiniz **bir uygulama tarafından kullanılan son dosyaların listesi**dir. **Otomatik olarak veya özel olarak** oluşturulabilirler.

Otomatik olarak oluşturulan **jumplists**, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` içinde saklanır. Jumplists, `{id}.autmaticDestinations-ms` formatına göre adlandırılır; burada başlangıç ID'si uygulamanın ID'sidir.

Özel jumplists, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` içinde saklanır ve genellikle dosya ile ilgili **önemli** bir şey olduğunda uygulama tarafından oluşturulur (belki favori olarak işaretlenmiştir).

Her jumplist'in **oluşturulma zamanı**, dosyanın **ilk kez erişildiği zamanı** ve **değiştirilme zamanı** son erişim zamanını gösterir.

Jumplists'i [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.

![](<../../../images/image (168).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasının kendisiyle ilgili olduğunu unutmayın_)

### Shellbags

[**Shellbags nedir öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB'lerinin Kullanımı

Bir USB cihazının kullanıldığını belirlemek mümkündür, bunun için:

- Windows Recent Klasörü
- Microsoft Office Recent Klasörü
- Jumplists

Bazı LNK dosyalarının orijinal yolu işaret etmek yerine WPDNSE klasörüne işaret ettiğini unutmayın:

![](<../../../images/image (218).png>)

WPDNSE klasöründeki dosyalar, orijinal dosyaların bir kopyasıdır, bu nedenle PC'nin yeniden başlatılmasında hayatta kalmazlar ve GUID bir shellbag'den alınır.

### Kayıt Bilgileri

[USB bağlı cihazlar hakkında ilginç bilgileri içeren kayıt anahtarlarını öğrenmek için bu sayfayı kontrol edin](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB bağlantısının ne zaman gerçekleştiğine dair zaman damgalarını almak için `C:\Windows\inf\setupapi.dev.log` dosyasını kontrol edin ( `Section start` için arama yapın).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Dedektifi

[**USBDetective**](https://usbdetective.com) bağlı USB cihazları hakkında bilgi almak için kullanılabilir.

![](<../../../images/image (452).png>)

### Tak ve Çalıştır Temizleme

'Tak ve Çalıştır Temizleme' olarak bilinen planlı görev, esasen eski sürücü sürümlerinin kaldırılması için tasarlanmıştır. En son sürücü paket sürümünü koruma amacıyla belirtilmiş olmasına rağmen, çevrimiçi kaynaklar, 30 gündür etkin olmayan sürücüleri de hedef aldığını önermektedir. Bu nedenle, son 30 günde bağlanmamış çıkarılabilir cihazların sürücüleri silinme riski taşımaktadır.

Görev aşağıdaki yolda bulunmaktadır: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Görevin içeriğini gösteren bir ekran görüntüsü sağlanmıştır: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Görevin Ana Bileşenleri ve Ayarları:**

- **pnpclean.dll**: Bu DLL, gerçek temizleme işlemini gerçekleştirir.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanmıştır, genel görev zamanlama motorunun kullanıldığını gösterir.
- **MaintenanceSettings**:
- **Period ('P1M')**: Görev Zamanlayıcı'nın, düzenli Otomatik bakım sırasında temizleme görevini aylık olarak başlatmasını yönlendirir.
- **Deadline ('P2M')**: Görev Zamanlayıcı'ya, görev iki ardışık ay boyunca başarısız olursa, acil Otomatik bakım sırasında görevi yürütmesini talimat verir.

Bu yapılandırma, sürücülerin düzenli bakımını ve temizliğini sağlar ve ardışık hatalar durumunda görevi yeniden denemek için önlemler içerir.

**Daha fazla bilgi için kontrol edin:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-postalar

E-postalar **2 ilginç kısım içerir: Başlıklar ve e-postanın içeriği**. **Başlıklarda** aşağıdaki bilgileri bulabilirsiniz:

- **Kim** e-postaları gönderdi (e-posta adresi, IP, e-postayı yönlendiren sunucular)
- **Ne zaman** e-posta gönderildi

Ayrıca, `References` ve `In-Reply-To` başlıkları içinde mesajların ID'sini bulabilirsiniz:

![](<../../../images/image (593).png>)

### Windows Mail Uygulaması

Bu uygulama, e-postaları HTML veya metin olarak kaydeder. E-postaları `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` içindeki alt klasörlerde bulabilirsiniz. E-postalar `.dat` uzantısıyla kaydedilir.

E-postaların **meta verileri** ve **kişiler** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` içindeki **EDB veritabanında** bulunabilir.

Dosyanın uzantısını `.vol`'dan `.edb`'ye değiştirin ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracını kullanarak açabilirsiniz. `Message` tablosunda e-postaları görebilirsiniz.

### Microsoft Outlook

Exchange sunucuları veya Outlook istemcileri kullanıldığında bazı MAPI başlıkları olacaktır:

- `Mapi-Client-Submit-Time`: E-postanın gönderildiği zaman sistemin zamanı
- `Mapi-Conversation-Index`: İletinin çocuk mesajlarının sayısı ve her mesajın zaman damgası
- `Mapi-Entry-ID`: Mesaj tanımlayıcısı.
- `Mappi-Message-Flags` ve `Pr_last_Verb-Executed`: MAPI istemcisi hakkında bilgi (mesaj okundu mu? okunmadı mı? yanıtlandı mı? yönlendirildi mi? ofis dışında mı?)

Microsoft Outlook istemcisinde, gönderilen/alınan tüm mesajlar, kişiler verileri ve takvim verileri, aşağıdaki konumda bir PST dosyasında saklanır:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Kayıt yolu `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`, kullanılan dosyayı gösterir.

PST dosyasını [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) aracıyla açabilirsiniz.

![](<../../../images/image (498).png>)

### Microsoft Outlook OST Dosyaları

Bir **OST dosyası**, Microsoft Outlook tarafından **IMAP** veya bir **Exchange** sunucusu ile yapılandırıldığında oluşturulur ve PST dosyasına benzer bilgileri saklar. Bu dosya, sunucu ile senkronize edilir, **son 12 ay** için verileri saklar ve **maksimum boyutu 50GB**'dır ve PST dosyası ile aynı dizinde bulunur. Bir OST dosyasını görüntülemek için [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.

### Ekleri Kurtarma

Kaybolan ekler şunlardan kurtarılabilir:

- **IE10 için**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 ve üzeri için**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Dosyaları

**Thunderbird**, verileri saklamak için **MBOX dosyaları** kullanır ve bu dosyalar `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` konumundadır.

### Görüntü Küçültmeleri

- **Windows XP ve 8-8.1**: Küçültme içeren bir klasöre erişmek, silinmiş olsa bile görüntü önizlemelerini saklayan bir `thumbs.db` dosyası oluşturur.
- **Windows 7/10**: `thumbs.db`, UNC yolu üzerinden erişildiğinde oluşturulur.
- **Windows Vista ve daha yeni**: Küçültme önizlemeleri, `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` içinde **thumbcache_xxx.db** adında dosyalarla merkezi olarak saklanır. Bu dosyaları görüntülemek için [**Thumbsviewer**](https://thumbsviewer.github.io) ve [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) araçları kullanılabilir.

### Windows Kayıt Bilgileri

Windows Kayıt Defteri, kapsamlı sistem ve kullanıcı etkinlik verilerini saklar ve aşağıdaki dosyalarda bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` alt anahtarları için `%windir%\System32\Config`.
- `HKEY_CURRENT_USER` için `%UserProfile%{User}\NTUSER.DAT`.
- Windows Vista ve sonraki sürümler, `HKEY_LOCAL_MACHINE` kayıt dosyalarını `%Windir%\System32\Config\RegBack\` içinde yedekler.
- Ayrıca, program yürütme bilgileri, Windows Vista ve Windows 2008 Server'dan itibaren `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` içinde saklanır.

### Araçlar

Kayıt dosyalarını analiz etmek için bazı araçlar faydalıdır:

- **Kayıt Defteri Düzenleyici**: Windows'ta yüklüdür. Mevcut oturumun Windows kayıt defterinde gezinmek için bir GUI'dir.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Kayıt dosyasını yüklemenizi ve GUI ile gezinmenizi sağlar. Ayrıca ilginç bilgiler içeren anahtarları vurgulayan Yer İmleri içerir.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen kayıt defterinde gezinmenizi sağlayan bir GUI'ye sahiptir ve ayrıca yüklenen kayıt defterinde ilginç bilgileri vurgulayan eklentiler içerir.
- [**Windows Kayıt Kurtarma**](https://www.mitec.cz/wrr.html): Yüklenen kayıt defterinden önemli bilgileri çıkarmak için başka bir GUI uygulamasıdır.

### Silinen Elemanı Kurtarma

Bir anahtar silindiğinde, böyle işaretlenir, ancak kapladığı alan gerekli olana kadar kaldırılmaz. Bu nedenle, **Registry Explorer** gibi araçlar kullanarak bu silinmiş anahtarları kurtarmak mümkündür.

### Son Yazma Zamanı

Her Anahtar-Değer, en son ne zaman değiştirildiğini gösteren bir **zaman damgası** içerir.

### SAM

**SAM** dosyası/hive, sistemin **kullanıcılar, gruplar ve kullanıcı parolaları** hash'lerini içerir.

`SAM\Domains\Account\Users` içinde kullanıcı adını, RID'yi, son giriş zamanını, son başarısız oturumu, giriş sayacını, parola politikasını ve hesabın ne zaman oluşturulduğunu elde edebilirsiniz. **Hash'leri** almak için ayrıca **SYSTEM** dosyasına/hive'ye de **ihtiyacınız vardır**.

### Windows Kayıt Defterindeki İlginç Girişler

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Çalıştırılan Programlar

### Temel Windows Süreçleri

[Bu yazıda](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) şüpheli davranışları tespit etmek için yaygın Windows süreçleri hakkında bilgi edinebilirsiniz.

### Windows Son Uygulamalar

Kayıt defteri `NTUSER.DAT` içinde `Software\Microsoft\Current Version\Search\RecentApps` yolunda, **çalıştırılan uygulama**, **son çalıştırma zamanı** ve **kaç kez** başlatıldığına dair bilgiler içeren alt anahtarlar bulabilirsiniz.

### BAM (Arka Plan Etkinlik Modaratörü)

`SYSTEM` dosyasını bir kayıt defteri düzenleyici ile açabilir ve `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` yolunda **her kullanıcı tarafından çalıştırılan uygulamalar** hakkında bilgileri bulabilirsiniz (yoldaki `{SID}`'yi not edin) ve **ne zaman** çalıştırıldıklarını (zaman, kayıt defterinin Veri değerinin içinde) görebilirsiniz.

### Windows Prefetch

Önceden alma, bir bilgisayarın, bir kullanıcının **yakın gelecekte erişebileceği içerikleri görüntülemek için gerekli kaynakları sessizce almasına** olanak tanıyan bir tekniktir, böylece kaynaklara daha hızlı erişilebilir.

Windows önceden alma, **çalıştırılan programların önbelleklerini** oluşturarak daha hızlı yüklenmelerini sağlar. Bu önbellekler, `C:\Windows\Prefetch` yolunda `.pf` dosyaları olarak oluşturulur. XP/VISTA/WIN7'de 128 dosya ve Win8/Win10'da 1024 dosya sınırı vardır.

Dosya adı `{program_name}-{hash}.pf` olarak oluşturulur (hash, yürütülebilir dosyanın yolu ve argümanlarına dayanır). W10'da bu dosyalar sıkıştırılmıştır. Dosyanın varlığı, **programın bir noktada çalıştırıldığını** gösterir.

`C:\Windows\Prefetch\Layout.ini` dosyası, **önceden alınan dosyaların klasörlerinin adlarını** içerir. Bu dosya, **çalıştırma sayısı**, **çalıştırma tarihleri** ve program tarafından **açılan dosyalar** hakkında **bilgi** içerir.

Bu dosyaları incelemek için [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) aracını kullanabilirsiniz:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch**, önceden yükleme ile aynı amaca sahiptir, **programları daha hızlı yüklemek** için neyin yükleneceğini tahmin eder. Ancak, önceden yükleme hizmetinin yerini almaz.\
Bu hizmet, `C:\Windows\Prefetch\Ag*.db` konumunda veritabanı dosyaları oluşturur.

Bu veritabanlarında **programın adı**, **çalıştırma sayısı**, **açılan dosyalar**, **erişilen hacim**, **tam yol**, **zaman dilimleri** ve **zaman damgaları** bulunabilir.

Bu bilgilere [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) aracı kullanarak erişebilirsiniz.

### SRUM

**Sistem Kaynak Kullanım İzleyici** (SRUM), **bir süreç tarafından tüketilen kaynakları** **izler**. W8'de ortaya çıkmış ve verileri `C:\Windows\System32\sru\SRUDB.dat` konumunda bir ESE veritabanında saklar.

Aşağıdaki bilgileri sağlar:

- AppID ve Yol
- Süreci çalıştıran kullanıcı
- Gönderilen Bayt
- Alınan Bayt
- Ağ Arayüzü
- Bağlantı süresi
- Süreç süresi

Bu bilgiler her 60 dakikada bir güncellenir.

Bu dosyadan tarihi [**srum_dump**](https://github.com/MarkBaggett/srum-dump) aracı kullanarak elde edebilirsiniz.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, ayrıca **ShimCache** olarak da bilinir, **Microsoft** tarafından uygulama uyumluluğu sorunlarını ele almak için geliştirilen **Uygulama Uyumluluk Veritabanı**nın bir parçasını oluşturur. Bu sistem bileşeni, aşağıdakiler de dahil olmak üzere çeşitli dosya meta verilerini kaydeder:

- Dosyanın tam yolu
- Dosyanın boyutu
- **$Standard_Information** (SI) altında Son Değiştirilme zamanı
- ShimCache'in Son Güncellenme zamanı
- İşlem Çalıştırma Bayrağı

Bu tür veriler, işletim sisteminin sürümüne bağlı olarak kayıt defterinde belirli konumlarda saklanır:

- XP için, veriler `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` altında 96 giriş kapasitesi ile saklanır.
- Server 2003 için, ayrıca Windows sürümleri 2008, 2012, 2016, 7, 8 ve 10 için, depolama yolu `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` olup, sırasıyla 512 ve 1024 giriş kapasitesine sahiptir.

Saklanan bilgileri ayrıştırmak için, [**AppCompatCacheParser** aracı](https://github.com/EricZimmerman/AppCompatCacheParser) kullanılması önerilir.

![](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** dosyası, bir sistemde yürütülen uygulamalar hakkında ayrıntıları kaydeden temel bir kayıt defteri hivesidir. Genellikle `C:\Windows\AppCompat\Programas\Amcache.hve` konumunda bulunur.

Bu dosya, yürütülen süreçlerin kayıtlarını, yürütülebilir dosyaların yollarını ve SHA1 hash'lerini saklamasıyla dikkat çekmektedir. Bu bilgi, bir sistemdeki uygulamaların etkinliğini izlemek için değerlidir.

**Amcache.hve** dosyasından veri çıkarmak ve analiz etmek için, [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) aracı kullanılabilir. Aşağıdaki komut, AmcacheParser'ı **Amcache.hve** dosyasının içeriğini ayrıştırmak ve sonuçları CSV formatında çıkarmak için nasıl kullanacağınıza dair bir örnektir:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Üretilen CSV dosyaları arasında, `Amcache_Unassociated file entries` özellikle dikkat çekicidir çünkü ilişkilendirilmemiş dosya girişleri hakkında zengin bilgiler sunar.

Üretilen en ilginç CVS dosyası `Amcache_Unassociated file entries`dir.

### RecentFileCache

Bu artefakt yalnızca W7'de `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` konumunda bulunabilir ve bazı ikili dosyaların son çalıştırılması hakkında bilgi içerir.

Dosyayı ayrıştırmak için [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) aracını kullanabilirsiniz.

### Planlı görevler

Bunları `C:\Windows\Tasks` veya `C:\Windows\System32\Tasks` konumundan çıkarabilir ve XML olarak okuyabilirsiniz.

### Hizmetler

Bunları `SYSTEM\ControlSet001\Services` kayıt defterinde bulabilirsiniz. Ne zaman ve neyin çalıştırılacağını görebilirsiniz.

### **Windows Store**

Yüklenen uygulamalar `\ProgramData\Microsoft\Windows\AppRepository\` konumunda bulunabilir. Bu depo, sistemdeki **her yüklü uygulama** ile ilgili bir **log** içerir ve bu log **`StateRepository-Machine.srd`** veritabanındadır.

Bu veritabanının Uygulama tablosunda "Application ID", "PackageNumber" ve "Display Name" sütunlarını bulmak mümkündür. Bu sütunlar, önceden yüklenmiş ve yüklenmiş uygulamalar hakkında bilgi içerir ve bazı uygulamaların kaldırılıp kaldırılmadığını bulmak mümkündür çünkü yüklü uygulamaların kimlikleri sıralı olmalıdır.

Ayrıca, kayıt defteri yolunda yüklü uygulamaları bulmak da mümkündür: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Ve **kaldırılmış** **uygulamaları**: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Olayları

Windows olayları içinde görünen bilgiler şunlardır:

- Ne oldu
- Zaman damgası (UTC + 0)
- İlgili kullanıcılar
- İlgili ana bilgisayarlar (hostname, IP)
- Erişilen varlıklar (dosyalar, klasör, yazıcı, hizmetler)

Loglar, Windows Vista'dan önce `C:\Windows\System32\config` konumunda ve Windows Vista'dan sonra `C:\Windows\System32\winevt\Logs` konumunda bulunmaktadır. Windows Vista'dan önce, olay logları ikili formatta, sonrasında ise **XML formatında** ve **.evtx** uzantısını kullanarak kaydedilmiştir.

Olay dosyalarının konumu, **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** kayıt defterinde bulunabilir.

Windows Olay Görüntüleyici (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) **veya** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** gibi diğer araçlarla görselleştirilebilir.

## Windows Güvenlik Olay Kaydı Anlama

Erişim olayları, `C:\Windows\System32\winevt\Security.evtx` konumundaki güvenlik yapılandırma dosyasında kaydedilir. Bu dosyanın boyutu ayarlanabilir ve kapasitesi dolduğunda, daha eski olaylar üzerine yazılır. Kaydedilen olaylar, kullanıcı girişleri ve çıkışları, kullanıcı eylemleri ve güvenlik ayarlarındaki değişiklikler ile dosya, klasör ve paylaşılan varlık erişimlerini içerir.

### Kullanıcı Kimlik Doğrulaması için Ana Olay Kimlikleri:

- **EventID 4624**: Kullanıcının başarıyla kimlik doğruladığını gösterir.
- **EventID 4625**: Kimlik doğrulama hatasını belirtir.
- **EventIDs 4634/4647**: Kullanıcı çıkış olaylarını temsil eder.
- **EventID 4672**: Yönetici ayrıcalıklarıyla giriş yapıldığını belirtir.

#### EventID 4634/4647 içindeki alt türler:

- **Interactive (2)**: Doğrudan kullanıcı girişi.
- **Network (3)**: Paylaşılan klasörlere erişim.
- **Batch (4)**: Toplu işlemlerin yürütülmesi.
- **Service (5)**: Hizmet başlatmaları.
- **Proxy (6)**: Proxy kimlik doğrulaması.
- **Unlock (7)**: Şifre ile ekranın kilidinin açılması.
- **Network Cleartext (8)**: Genellikle IIS'den gelen düz metin şifre iletimi.
- **New Credentials (9)**: Erişim için farklı kimlik bilgileri kullanımı.
- **Remote Interactive (10)**: Uzak masaüstü veya terminal hizmetleri girişi.
- **Cache Interactive (11)**: Alan denetleyicisi ile iletişim olmadan önbellekli kimlik bilgileri ile giriş.
- **Cache Remote Interactive (12)**: Önbellekli kimlik bilgileri ile uzak giriş.
- **Cached Unlock (13)**: Önbellekli kimlik bilgileri ile kilidin açılması.

#### EventID 4625 için Durum ve Alt Durum Kodları:

- **0xC0000064**: Kullanıcı adı mevcut değil - Bir kullanıcı adı tahsis etme saldırısını gösterebilir.
- **0xC000006A**: Doğru kullanıcı adı ama yanlış şifre - Olası şifre tahmin etme veya kaba kuvvet denemesi.
- **0xC0000234**: Kullanıcı hesabı kilitlendi - Birden fazla başarısız girişle sonuçlanan bir kaba kuvvet saldırısını takip edebilir.
- **0xC0000072**: Hesap devre dışı bırakıldı - Devre dışı bırakılmış hesaplara yetkisiz erişim girişimleri.
- **0xC000006F**: İzin verilen zaman dışında oturum açma - Belirlenen giriş saatleri dışında erişim girişimlerini gösterir, yetkisiz erişim belirtisi olabilir.
- **0xC0000070**: İş istasyonu kısıtlamalarının ihlali - Yetkisiz bir yerden giriş yapma girişimi olabilir.
- **0xC0000193**: Hesap süresi doldu - Süresi dolmuş kullanıcı hesapları ile erişim girişimleri.
- **0xC0000071**: Süresi dolmuş şifre - Eski şifrelerle giriş girişimleri.
- **0xC0000133**: Zaman senkronizasyon sorunları - İstemci ve sunucu arasında büyük zaman farklılıkları, daha karmaşık saldırıların (pass-the-ticket gibi) belirtisi olabilir.
- **0xC0000224**: Zorunlu şifre değişikliği gereklidir - Sık sık zorunlu değişiklikler, hesap güvenliğini bozma girişimini gösterebilir.
- **0xC0000225**: Bir sistem hatasını belirtir, güvenlik sorunu değil.
- **0xC000015b**: Reddedilen oturum açma türü - Yetkisiz oturum açma türü ile erişim girişimi, örneğin bir kullanıcının bir hizmet oturumu başlatmaya çalışması.

#### EventID 4616:

- **Zaman Değişikliği**: Sistem zamanının değiştirilmesi, olayların zaman çizelgesini belirsizleştirebilir.

#### EventID 6005 ve 6006:

- **Sistem Başlangıcı ve Kapatılması**: EventID 6005 sistemin başlatıldığını, EventID 6006 ise kapatıldığını belirtir.

#### EventID 1102:

- **Log Silme**: Güvenlik loglarının temizlenmesi, genellikle yasadışı faaliyetleri örtbas etme için bir kırmızı bayraktır.

#### USB Cihaz Takibi için Olay Kimlikleri:

- **20001 / 20003 / 10000**: USB cihazının ilk bağlantısı.
- **10100**: USB sürücü güncellemesi.
- **EventID 112**: USB cihazının takılma zamanı.

Bu oturum açma türlerini simüle etme ve kimlik bilgisi dökme fırsatları hakkında pratik örnekler için [Altered Security'nin detaylı kılavuzuna](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) başvurun.

Olay detayları, durum ve alt durum kodları, özellikle Event ID 4625'te olay nedenleri hakkında daha fazla bilgi sağlar.

### Windows Olaylarını Kurtarma

Silinmiş Windows Olaylarını kurtarma şansını artırmak için, şüpheli bilgisayarı doğrudan fişini çekerek kapatmak önerilir. **Bulk_extractor**, `.evtx` uzantısını belirten bir kurtarma aracı olarak, bu tür olayları kurtarmak için önerilir.

### Windows Olayları Aracılığıyla Yaygın Saldırıları Tanımlama

Yaygın siber saldırıları tanımlamak için Windows Olay Kimliklerini kullanma konusunda kapsamlı bir kılavuz için [Red Team Recipe](https://redteamrecipe.com/event-codes/) adresini ziyaret edin.

#### Kaba Kuvvet Saldırıları

Birden fazla EventID 4625 kaydı ile tanımlanabilir, saldırı başarılı olursa ardından bir EventID 4624 kaydı gelir.

#### Zaman Değişikliği

EventID 4616 ile kaydedilen sistem zamanındaki değişiklikler, adli analizleri karmaşıklaştırabilir.

#### USB Cihaz Takibi

USB cihaz takibi için yararlı Sistem Olay Kimlikleri, ilk kullanım için 20001/20003/10000, sürücü güncellemeleri için 10100 ve takılma zaman damgaları için DeviceSetupManager'dan EventID 112'dir.

#### Sistem Güç Olayları

EventID 6005 sistem başlangıcını, EventID 6006 ise kapanmayı belirtir.

#### Log Silme

Güvenlik EventID 1102, logların silindiğini belirtir, bu adli analiz için kritik bir olaydır.

{{#include ../../../banners/hacktricks-training.md}}
