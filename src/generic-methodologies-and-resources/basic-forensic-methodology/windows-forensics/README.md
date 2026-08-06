# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

`...` yolunda `appdb.dat` (Windows anniversary sürümünden önce) veya `wpndatabase.db` (Windows Anniversary sonrasında) veritabanını bulabilirsiniz.

Bu SQLite veritabanının içinde, ilginç veriler içerebilecek tüm bildirimleri (XML formatında) barındıran `Notification` tablosunu bulabilirsiniz.

### Timeline

Timeline, ziyaret edilen web sayfalarının, düzenlenen belgelerin ve çalıştırılan uygulamaların **kronolojik geçmişini** sağlayan bir Windows özelliğidir.

Veritabanı `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` yolunda bulunur. Bu veritabanı bir SQLite aracıyla veya [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) aracıyla açılabilir; bu araç, [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) aracıyla açılabilen **2 dosya oluşturur**.

### ADS (Alternate Data Streams)

İndirilen dosyalar, intranet, internet vb. üzerinden **nasıl** **indirildiğini** belirten **ADS Zone.Identifier** bilgisini içerebilir. Bazı yazılımlar (tarayıcılar gibi), genellikle dosyanın indirildiği **URL** gibi daha da fazla **bilgi** ekler.

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10 sürümlerinde **Recycle Bin**, sürücünün kök dizinindeki **`$Recycle.bin`** klasöründe (`C:\$Recycle.bin`) bulunabilir.\
Bu klasörde bir dosya silindiğinde 2 özel dosya oluşturulur:

- `$I{id}`: Dosya bilgileri (silindiği tarih}
- `$R{id}`: Dosyanın içeriği

![File Backups - Recycle Bin: $R{id}: Dosyanın içeriği](<../../../images/image (1029).png>)

Bu dosyalara sahip olduğunuzda, silinen dosyaların özgün konumunu ve silinme tarihini öğrenmek için [**Rifiuti**](https://github.com/abelcheung/rifiuti2) aracını kullanabilirsiniz (Vista – Win10 için `rifiuti-vista.exe` kullanın).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Dosya Yedekleri - Geri Dönüşüm Kutusu: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy, Microsoft Windows'a dahil olan ve kullanımda olsalar bile bilgisayar dosyalarının veya birimlerinin **yedek kopyalarını** ya da anlık görüntülerini oluşturabilen bir teknolojidir.

Bu yedekler genellikle dosya sisteminin kök dizinindeki `\System Volume Information` konumunda bulunur ve adları aşağıdaki görselde gösterilen **UID'lerden** oluşur:

![Geri Dönüşüm Kutusu - Volume Shadow Copies: Bu yedekler genellikle dosya sisteminin kök dizinindeki System Volume Information konumunda bulunur ve adları görselde gösterilen UID'lerden oluşur](<../../../images/image (94).png>)

Forensics imajı **ArsenalImageMounter** ile mount ederek, bir shadow copy'yi incelemek ve hatta shadow copy yedeklerindeki **dosyaları çıkarmak** için [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) aracı kullanılabilir.

![Geri Dönüşüm Kutusu - Volume Shadow Copies: Forensics imajı ArsenalImageMounter ile mount edildiğinde ShadowCopyView aracı bir shadow copy'yi incelemek ve hatta shadow copy yedeklerindeki dosyaları çıkarmak için kullanılabilir](<../../../images/image (576).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` registry girdisi **yedeklenmemesi gereken** dosyaları ve anahtarları içerir:

![Geri Dönüşüm Kutusu - Volume Shadow Copies: HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore registry girdisi yedeklenmemesi gereken dosyaları ve anahtarları içerir](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` registry girdisi de `Volume Shadow Copies` hakkında yapılandırma bilgileri içerir.

### Office AutoSaved Files

Office otomatik kaydedilen dosyalarını şu konumda bulabilirsiniz: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Bir shell item, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir öğedir.

### Recent Documents (LNK)

Windows, kullanıcı bir dosyayı **açtığında, kullandığında veya oluşturduğunda** bu **kısayolları** aşağıdaki konumlarda **otomatik olarak** **oluşturur**:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Bir klasör oluşturulduğunda, klasöre, üst klasöre ve üst klasörün üst klasörüne bir bağlantı da oluşturulur.

Otomatik olarak oluşturulan bu bağlantı dosyaları, **kaynak hakkında**, bunun bir **dosya** mı yoksa **klasör** mü olduğu, dosyanın **MAC** **zamanları**, dosyanın depolandığı **birim bilgileri** ve **hedef dosyanın klasörü** gibi bilgiler içerir. Bu bilgiler, dosyaların kaldırılması durumunda kurtarılmasına yardımcı olabilir.

Ayrıca bağlantı dosyasının **oluşturulma tarihi**, orijinal dosyanın **ilk kez kullanıldığı** ilk **zamandır**; bağlantı dosyasının **değiştirilme tarihi** ise kaynak dosyanın kullanıldığı **son zamandır**.

Bu dosyaları incelemek için [**LinkParser**](http://4discovery.com/our-tools/) kullanabilirsiniz.

Bu tool'da **2 timestamp kümesi** bulacaksınız:

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

İlk timestamp kümesi, **dosyanın kendisine ait timestamp'leri** ifade eder. İkinci küme ise **bağlantı verilen dosyanın timestamp'lerini** ifade eder.

Aynı bilgileri Windows CLI aracını çalıştırarak da alabilirsiniz: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Bu durumda bilgiler bir CSV dosyasının içine kaydedilecektir.

### Jumplists

Bunlar uygulama başına belirtilen son dosyalardır. Her uygulamada erişebileceğiniz **bir uygulama tarafından kullanılan son dosyaların listesidir**. **Otomatik olarak veya özel olarak** oluşturulabilirler.

Otomatik olarak oluşturulan **jumplists** `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` içinde saklanır. Jumplists, `{id}.autmaticDestinations-ms` biçimini izleyen adlarla adlandırılır; başlangıçtaki ID, uygulamanın ID'sidir.

Özel jumplists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` içinde saklanır ve genellikle dosyayla ilgili **önemli** bir durum meydana geldiği için uygulama tarafından oluşturulurlar (dosya favori olarak işaretlenmiş olabilir).

Herhangi bir jumplist'in **oluşturulma zamanı**, **dosyaya ilk kez erişildiği zamanı**; **değiştirilme zamanı** ise son erişim zamanını gösterir.

Jumplist'leri [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.

![Recent Documents (LNK) - Jumplists: Jumplist'leri JumplistExplorer kullanarak inceleyebilirsiniz](<../../../images/image (168).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasının kendisiyle ilişkili olduğunu unutmayın_)

### Shellbags

[**Shellbag'lerin ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB'lerinin Kullanımı

Bir USB cihazının kullanıldığını aşağıdakilerin oluşturulması sayesinde tespit etmek mümkündür:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Bazı LNK dosyalarının, orijinal yolu göstermek yerine WPDNSE klasörünü gösterdiğini unutmayın:

![Shellbags - Windows USB'lerinin Kullanımı: Bazı LNK dosyalarının orijinal yolu göstermek yerine WPDNSE klasörünü gösterdiğini unutmayın](<../../../images/image (218).png>)

WPDNSE klasöründeki dosyalar orijinal dosyaların kopyalarıdır; bu nedenle bilgisayar yeniden başlatıldığında varlıklarını koruyamazlar ve GUID bir shellbag'den alınır.

### Registry Bilgileri

USB'ye bağlı cihazlar hakkında ilgi çekici bilgiler içeren registry anahtarlarını öğrenmek için [bu sayfayı inceleyin](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB bağlantısının ne zaman gerçekleştirildiğine ilişkin zaman damgalarını almak için `C:\Windows\inf\setupapi.dev.log` dosyasını kontrol edin (`Section start` ifadesini arayın).

![Registry Information - setupapi: USB bağlantısının ne zaman gerçekleştirildiğine ilişkin zaman damgalarını almak için C: Windows inf setupapi.dev.log dosyasını kontrol edin (Section start ifadesini arayın)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com), bir imaja bağlı olan USB cihazları hakkında bilgi almak için kullanılabilir.

![setupapi - USB Detective: USBDetective, bir imaja bağlanmış USB cihazları hakkında bilgi almak için kullanılabilir](<../../../images/image (452).png>)

### Plug and Play Cleanup

'Plug and Play Cleanup' olarak bilinen zamanlanmış görev, öncelikle güncel olmayan driver sürümlerini kaldırmak için tasarlanmıştır. Belirtilen amacı en son driver paketi sürümünü korumak olmasına rağmen, çevrimiçi kaynaklar bu görevin 30 gündür etkin olmayan driver'ları da hedeflediğini belirtmektedir. Sonuç olarak, son 30 gün içinde bağlanmamış çıkarılabilir cihazlara ait driver'lar silinebilir.<sup>[[1]](#references)</sup>

Görev şu yolda bulunur: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Görevin içeriğini gösteren bir ekran görüntüsü aşağıda verilmiştir: ![USB Detective - Plug and Play Cleanup: Görev şu yolda bulunur: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Görevin Temel Bileşenleri ve Ayarları:**

- **pnpclean.dll**: Bu DLL, gerçek temizleme işleminden sorumludur.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanmıştır ve genel görev zamanlama motorunun kullanıldığını belirtir.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler'ın normal Automatic maintenance sırasında temizleme görevini aylık olarak başlatmasını sağlar.
- **Deadline ('P2M')**: Görev art arda iki ay boyunca başarısız olursa Task Scheduler'a görevi acil Automatic maintenance sırasında yürütmesini bildirir.

Bu yapılandırma, driver'ların düzenli olarak bakımının yapılmasını ve temizlenmesini sağlar; ayrıca art arda gerçekleşen hatalar durumunda görevin yeniden denenmesine olanak tanır.

**Daha fazla bilgi için bkz.:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-postalar

E-postalar **2 ilgi çekici bölüm içerir: E-postanın headers ve içeriği**. **Headers** içinde şu tür bilgileri bulabilirsiniz:

- E-postaları **kimin** gönderdiği (e-posta adresi, IP, e-postayı yönlendiren mail sunucuları)
- E-postanın **ne zaman** gönderildiği

Ayrıca `References` ve `In-Reply-To` headers içinde mesajların ID'sini bulabilirsiniz:

![Plug and Play Cleanup - E-postalar: E-posta ne zaman gönderildi](<../../../images/image (593).png>)

### Windows Mail App

Bu uygulama e-postaları HTML veya text olarak kaydeder. E-postaları `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` içindeki alt klasörlerde bulabilirsiniz. E-postalar `.dat` uzantısıyla kaydedilir.

E-postaların **metadata** bilgileri ve **contacts** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` içindeki **EDB database** içinde bulunabilir.

Dosyanın **uzantısını `.vol` yerine `.edb` olarak değiştirin**; ardından dosyayı açmak için [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracını kullanabilirsiniz. `Message` tablosunun içinde e-postaları görebilirsiniz.

### Microsoft Outlook

Exchange sunucuları veya Outlook clients kullanıldığında bazı MAPI headers bulunur:

- `Mapi-Client-Submit-Time`: E-postanın gönderildiği sistem zamanı
- `Mapi-Conversation-Index`: Thread'in child message sayısı ve thread'deki her mesajın zaman damgası
- `Mapi-Entry-ID`: Mesaj identifier'ı.
- `Mappi-Message-Flags` ve `Pr_last_Verb-Executed`: MAPI client hakkında bilgiler (mesaj okundu mu? okunmadı mı? yanıtlandı mı? yönlendirildi mi? out of the office?)

Microsoft Outlook client'ında gönderilen/alınan tüm mesajlar, contacts verileri ve calendar verileri şu konumlardaki bir PST dosyasında saklanır:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` registry yolu, kullanılan dosyayı belirtir.

PST dosyasını [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) aracını kullanarak açabilirsiniz.

![Windows Mail App - Microsoft Outlook: PST dosyasını Kernel PST Viewer aracını kullanarak açabilirsiniz](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Bir **OST file**, Microsoft Outlook **IMAP** veya bir **Exchange** sunucusuyla yapılandırıldığında oluşturulur ve PST file'a benzer bilgiler depolar. Bu dosya sunucuyla senkronize edilir; **son 12 aya** ait verileri, **maksimum 50GB boyutuna** kadar saklar ve PST file ile aynı dizinde bulunur. Bir OST file'ı görüntülemek için [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.

### Ekleri Alma

Kayıp ekler şu konumlardan kurtarılabilir:

- **IE10** için: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 ve üzeri** için: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird**, verileri depolamak için `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` konumunda bulunan **MBOX files**'ı kullanır.

### Image Thumbnails

- **Windows XP ve 8-8.1**: Thumbnail'lerin bulunduğu bir klasöre erişildiğinde, silinmiş olsalar bile image preview'larını depolayan bir `thumbs.db` dosyası oluşturulur.
- **Windows 7/10**: `thumbs.db`, UNC path üzerinden bir klasöre erişildiğinde oluşturulur.
- **Windows Vista ve daha yeni sürümler**: Thumbnail preview'ları `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` içinde merkezi olarak saklanır ve dosya adları **thumbcache_xxx.db** biçimindedir. [**Thumbsviewer**](https://thumbsviewer.github.io) ve [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) bu dosyaları görüntülemek için kullanılan araçlardır.

### Windows Registry Information

Kapsamlı system ve user activity verilerini depolayan Windows Registry, şu konumlardaki dosyaların içinde bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` alt anahtarları için `%windir%\System32\Config`.
- `HKEY_CURRENT_USER` için `%UserProfile%{User}\NTUSER.DAT`.
- Windows Vista ve sonraki sürümler, `HKEY_LOCAL_MACHINE` registry dosyalarını `%Windir%\System32\Config\RegBack\` konumunda yedekler.
- Ayrıca program execution bilgileri, Windows Vista ve Windows 2008 Server'dan itibaren `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` içinde depolanır.

### Tools

Registry dosyalarını analiz etmek için bazı araçlar yararlıdır:

- **Registry Editor**: Windows ile birlikte kurulur. Mevcut session'ın Windows registry'sinde gezinmek için kullanılan bir GUI'dir.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Registry dosyasını yüklemenize ve GUI üzerinden bunlar arasında gezinmenize olanak tanır. Ayrıca ilgi çekici bilgiler içeren anahtarları vurgulayan Bookmarks da içerir.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen registry'de gezinmenize olanak tanıyan bir GUI içerir ve ayrıca yüklenen registry içindeki ilgi çekici bilgileri vurgulayan plugin'ler barındırır.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Yüklenen registry'den önemli bilgileri çıkarabilen başka bir GUI uygulamasıdır.

### Silinen Element'leri Kurtarma

Bir key silindiğinde bu şekilde işaretlenir; ancak kapladığı alana ihtiyaç duyulana kadar kaldırılmaz. Bu nedenle **Registry Explorer** gibi araçları kullanarak silinen key'leri kurtarmak mümkündür.

### Last Write Time

Her Key-Value, son değiştirilme zamanını belirten bir **timestamp** içerir.

### SAM

**SAM** file/hive, system'in **users, groups ve users passwords** hash'lerini içerir.

`SAM\Domains\Account\Users` içinde username, RID, son login, son failed logon, login counter, password policy ve account'un ne zaman oluşturulduğu bilgilerini alabilirsiniz. **Hash'leri** elde etmek için **SYSTEM** file/hive'ına da **ihtiyacınız vardır**.

### Windows Registry'deki İlgi Çekici Entry'ler


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Çalıştırılan Programs

### Basic Windows Processes

[bu post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) içinde şüpheli davranışları tespit etmek için kullanılan yaygın Windows processes hakkında bilgi edinebilirsiniz.

### Windows Recent APPs

`NTUSER.DAT` registry'si içinde `Software\Microsoft\Current Version\Search\RecentApps` path'inde **çalıştırılan application**, en **son ne zaman** çalıştırıldığı ve **kaç kez** başlatıldığı hakkında bilgiler içeren subkey'ler bulunur.

### BAM (Background Activity Moderator)

`SYSTEM` file'ını bir registry editor ile açabilir ve `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` path'inin içinde **her user tarafından çalıştırılan applications** hakkında bilgileri (path'teki `{SID}` ifadesine dikkat edin) ve bunların **hangi zamanda** çalıştırıldığını (zaman registry'nin Data value'sunun içindedir) bulabilirsiniz.

### Windows Prefetch

Prefetching, bir user'ın **yakın gelecekte erişebileceği** içeriği görüntülemek için gereken **gerekli kaynakları sessizce almasını** sağlayan ve kaynaklara daha hızlı erişilmesine olanak tanıyan bir tekniktir.

Windows prefetch, programların daha hızlı yüklenebilmesi için **çalıştırılan programların cache'lerini** oluşturur. Bu cache'ler `C:\Windows\Prefetch` path'inin içinde `.pf` dosyaları olarak oluşturulur. XP/VISTA/WIN7'de 128 dosya, Win8/Win10'da ise 1024 dosya sınırı vardır.

Dosya adı `{program_name}-{hash}.pf` biçiminde oluşturulur (hash, executable'ın path'i ve arguments'larına dayanır). W10'da bu dosyalar compressed durumdadır. Dosyanın yalnızca mevcut olması bile **programın bir noktada çalıştırıldığını** gösterir.

`C:\Windows\Prefetch\Layout.ini` dosyası, prefetch edilen dosyaların **klasör adlarını** içerir. Bu dosya **çalıştırma sayısı**, çalıştırma **tarihleri** ve program tarafından **açılan dosyalar** hakkında bilgiler içerir.

Bu dosyaları incelemek için [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) aracını kullanabilirsiniz:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch**, sırada neyin yükleneceğini tahmin ederek **programları daha hızlı yüklemek** amacıyla prefetch ile aynı hedefe sahiptir. Ancak prefetch servisini değiştirmez.\
Bu servis `C:\Windows\Prefetch\Ag*.db` konumunda veritabanı dosyaları oluşturur.

Bu veritabanlarında **programın** **adını**, **çalıştırılma sayısını**, **açılan** **dosyaları**, **erişilen** **birimi**, **tam** **yolu**, **zaman aralıklarını** ve **zaman damgalarını** bulabilirsiniz.

Bu bilgilere [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) aracıyla erişebilirsiniz.

### SRUM

**System Resource Usage Monitor** (SRUM), **bir işlem tarafından** **tüketilen** **kaynakları** **izler**. W8'de ortaya çıkmıştır ve verileri `C:\Windows\System32\sru\SRUDB.dat` konumunda bulunan bir ESE veritabanında saklar.

Aşağıdaki bilgileri sağlar:

- AppID ve Path
- İşlemi çalıştıran kullanıcı
- Gönderilen baytlar
- Alınan baytlar
- Ağ arayüzü
- Bağlantı süresi
- İşlem süresi

Bu bilgiler her 60 dakikada bir güncellenir.

Bu dosyadaki tarihi [**srum_dump**](https://github.com/MarkBaggett/srum-dump) aracıyla elde edebilirsiniz.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, diğer adıyla **ShimCache**, uygulama uyumluluğu sorunlarını çözmek amacıyla **Microsoft** tarafından geliştirilen **Application Compatibility Database**'in bir parçasıdır. Bu sistem bileşeni, aşağıdakiler dahil olmak üzere çeşitli dosya meta verilerini kaydeder:

- Dosyanın tam yolu
- Dosyanın boyutu
- **$Standard_Information** (SI) altındaki Son Değiştirilme zamanı
- ShimCache'in Son Güncellenme zamanı
- Process Execution Flag

Bu veriler, işletim sistemi sürümüne bağlı olarak kayıt defterindeki belirli konumlarda saklanır:

- XP için veriler, 96 kayıt kapasitesine sahip `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` altında saklanır.
- Server 2003 ile Windows 2008, 2012, 2016, 7, 8 ve 10 sürümleri için depolama yolu `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache` şeklindedir ve sırasıyla 512 ve 1024 kayıt barındırır.

Saklanan bilgileri ayrıştırmak için [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) kullanılması önerilir.

![SRUM - AppCompatCache (ShimCache): Saklanan bilgileri ayrıştırmak için AppCompatCacheParser tool kullanılması önerilir](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** dosyası, bir sistemde çalıştırılmış uygulamalarla ilgili ayrıntıları kaydeden bir kayıt defteri hive'ıdır. Genellikle `C:\Windows\AppCompat\Programas\Amcache.hve` konumunda bulunur.

Bu dosya, çalıştırılan işlemlere ait kayıtları, çalıştırılabilir dosyaların yolları ve SHA1 hash'leri dahil olmak üzere saklamasıyla dikkat çeker. Bu bilgiler, bir sistemdeki uygulama etkinliklerini takip etmek için son derece değerlidir.

**Amcache.hve** dosyasındaki verileri çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) aracı kullanılabilir. Aşağıdaki komut, **Amcache.hve** dosyasının içeriğini ayrıştırmak ve sonuçları CSV formatında dışa aktarmak için AmcacheParser'ın nasıl kullanılacağına dair bir örnektir:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Oluşturulan CSV dosyaları arasında `Amcache_Unassociated file entries`, ilişkilendirilmemiş dosya girdileri hakkında sağladığı zengin bilgiler nedeniyle özellikle dikkat çekicidir.

Oluşturulan en ilginç CSV dosyası `Amcache_Unassociated file entries` dosyasıdır.

### RecentFileCache

Bu artifact yalnızca W7'de `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` konumunda bulunabilir ve bazı binary'lerin yakın zamanda çalıştırılması hakkında bilgi içerir.

Dosyayı parse etmek için [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) aracını kullanabilirsiniz.

### Scheduled tasks

Bunları `C:\Windows\Tasks` veya `C:\Windows\System32\Tasks` konumlarından çıkarabilir ve XML olarak okuyabilirsiniz.

### Services

Bunları registry'de `SYSTEM\ControlSet001\Services` altında bulabilirsiniz. Ne çalıştırılacağını ve ne zaman çalıştırılacağını görebilirsiniz.

### **Windows Store**

Yüklü uygulamalar `\ProgramData\Microsoft\Windows\AppRepository\`\
konumunda bulunabilir.
Bu repository, sistemde **yüklü olan her uygulamayı** **`StateRepository-Machine.srd`** database'i içinde bir **log** ile kaydeder.

Bu database'in Application tablosunda "Application ID", "PackageNumber" ve "Display Name" sütunlarını bulmak mümkündür. Bu sütunlar önceden yüklü ve sonradan yüklenmiş uygulamalar hakkında bilgi içerir ve yüklü uygulamaların ID'leri sıralı olması gerektiğinden bazı uygulamaların uninstall edilip edilmediği belirlenebilir.

**Yüklü uygulamalar** registry'deki şu path içinde de bulunabilir: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
**Uninstall edilmiş** **uygulamalar** ise şu konumdadır: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows events içinde görünen bilgiler şunlardır:

- Ne olduğu
- Timestamp (UTC + 0)
- İlgili kullanıcılar
- İlgili host'lar (hostname, IP)
- Erişilen asset'ler (dosyalar, klasörler, printer'lar, servisler)

Log'lar Windows Vista'dan önce `C:\Windows\System32\config` konumunda, Windows Vista'dan sonra ise `C:\Windows\System32\winevt\Logs` konumunda bulunur. Windows Vista'dan önce event log'ları binary formatındaydı; sonrasında ise **XML formatındadır** ve **.evtx** uzantısını kullanır.

Event dosyalarının konumu SYSTEM registry'sinde **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** altında bulunabilir.

Bunlar Windows Event Viewer (**`eventvwr.msc`**) üzerinden veya [**Event Log Explorer**](https://eventlogxp.com) **ya da** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** gibi diğer araçlarla görüntülenebilir.**

## Windows Security Event Logging'i Anlama

Access event'leri `C:\Windows\System32\winevt\Security.evtx` konumunda bulunan security configuration file içine kaydedilir. Bu dosyanın boyutu ayarlanabilir ve kapasitesine ulaşıldığında eski event'lerin üzerine yazılır. Kaydedilen event'ler arasında kullanıcı login ve logoff işlemleri, kullanıcı eylemleri ve security setting değişikliklerinin yanı sıra dosya, klasör ve paylaşılan asset erişimleri bulunur.

### User Authentication için Önemli Event ID'leri:

- **EventID 4624**: Bir kullanıcının başarıyla authenticate olduğunu belirtir.
- **EventID 4625**: Bir authentication failure olduğunu gösterir.
- **EventIDs 4634/4647**: Kullanıcı logoff event'lerini temsil eder.
- **EventID 4672**: Administrative privilege'larla login yapıldığını belirtir.

#### EventID 4634/4647 içindeki Sub-type'lar:

- **Interactive (2)**: Doğrudan kullanıcı login'i.
- **Network (3)**: Paylaşılan klasörlere erişim.
- **Batch (4)**: Batch process'lerin çalıştırılması.
- **Service (5)**: Service launch'ları.
- **Proxy (6)**: Proxy authentication.
- **Unlock (7)**: Ekranın password ile unlock edilmesi.
- **Network Cleartext (8)**: Genellikle IIS'ten gelen clear text password transmission.
- **New Credentials (9)**: Erişim için farklı credential'ların kullanılması.
- **Remote Interactive (10)**: Remote desktop veya terminal services login'i.
- **Cache Interactive (11)**: Domain controller ile iletişim kurulmadan cached credential'larla login.
- **Cache Remote Interactive (12)**: Cached credential'larla remote login.
- **Cached Unlock (13)**: Cached credential'larla unlock işlemi.

#### EventID 4625 için Status ve Sub Status Code'ları:

- **0xC0000064**: Kullanıcı adı mevcut değil - Bir username enumeration attack'ine işaret edebilir.
- **0xC000006A**: Kullanıcı adı doğru ancak password yanlış - Olası password guessing veya brute-force attempt.
- **0xC0000234**: Kullanıcı account'u lock out edilmiş - Birden fazla başarısız login sonucunda gerçekleşen bir brute-force attack'i takip edebilir.
- **0xC0000072**: Account disabled - Disabled account'lara erişim için yetkisiz attempt'ler.
- **0xC000006F**: İzin verilen saatler dışında logon - Belirlenen login saatleri dışında erişim attempt'lerini gösterir ve yetkisiz erişim belirtisi olabilir.
- **0xC0000070**: Workstation restriction ihlali - Yetkisiz bir location'dan login attempt'i olabilir.
- **0xC0000193**: Account expiration - Süresi dolmuş kullanıcı account'larıyla erişim attempt'leri.
- **0xC0000071**: Expired password - Güncel olmayan password'larla login attempt'leri.
- **0xC0000133**: Time sync sorunları - Client ve server arasındaki büyük zaman farkları, pass-the-ticket gibi daha gelişmiş attack'lerin göstergesi olabilir.
- **0xC0000224**: Zorunlu password değişikliği gerekli - Sık gerçekleşen zorunlu değişiklikler, account security'sini destabilize etme attempt'ine işaret edebilir.
- **0xC0000225**: Bir security issue'dan ziyade system bug'ına işaret eder.
- **0xC000015b**: Reddedilen logon type - Bir kullanıcının service logon çalıştırmaya çalışması gibi yetkisiz logon type ile erişim attempt'i.

#### EventID 4616:

- **Time Change**: System time'ın değiştirilmesi; event timeline'ını gizleyebilir.

#### EventID 6005 ve 6006:

- **System Startup and Shutdown**: EventID 6005 system startup'ını, EventID 6006 ise system shutdown'ını belirtir.

#### EventID 1102:

- **Log Deletion**: Security log'larının temizlenmesi; genellikle yasa dışı faaliyetlerin izlerini kapatmaya yönelik bir red flag'dir.

#### USB Device Tracking için EventID'ler:

- **20001 / 20003 / 10000**: USB device'ın ilk bağlantısı.
- **10100**: USB driver update'i.
- **EventID 112**: USB device insertion zamanı.

Bu login type'larını ve credential dumping fırsatlarını simüle etmeye yönelik pratik örnekler için [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) kaynağına başvurabilirsiniz.

Status ve sub-status code'ları dahil event detayları, event'lerin nedenleri hakkında daha fazla bilgi sağlar; bu durum özellikle Event ID 4625 için dikkat çekicidir.

### Windows Events'leri Recover Etme

Silinmiş Windows Events'leri recover etme olasılığını artırmak için şüpheli bilgisayarın fişini doğrudan çekerek power down edilmesi önerilir. `.evtx` uzantısını belirterek kullanılan bir recovery tool olan **Bulk_extractor**, bu event'leri recover etmeyi denemek için önerilir.

### Windows Events ile Yaygın Attack'leri Belirleme

Yaygın cyber attack'leri belirlemek için Windows Event ID'lerinin nasıl kullanılacağına dair kapsamlı bir guide için [Red Team Recipe](https://redteamrecipe.com/event-codes/) kaynağını ziyaret edin.

#### Brute Force Attack'leri

Birden fazla EventID 4625 kaydıyla ve attack başarılı olursa bunun ardından gelen bir EventID 4624 ile belirlenebilir.

#### Time Change

EventID 4616 tarafından kaydedilir; system time değişiklikleri forensic analysis'i zorlaştırabilir.

#### USB Device Tracking

USB device tracking için faydalı System EventID'leri arasında ilk kullanım için 20001/20003/10000, driver update'leri için 10100 ve insertion timestamp'leri için DeviceSetupManager kaynaklı EventID 112 bulunur.

#### System Power Events

EventID 6005 system startup'ını, EventID 6006 ise shutdown'ı belirtir.

#### Log Deletion

Security EventID 1102, forensic analysis açısından kritik bir event olan log'ların silinmesini gösterir.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
