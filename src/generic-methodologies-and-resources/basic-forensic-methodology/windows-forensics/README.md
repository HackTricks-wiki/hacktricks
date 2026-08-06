# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

` \Users\<username>\AppData\Local\Microsoft\Windows\Notifications` yolunda `appdb.dat` (Windows Anniversary öncesi) veya `wpndatabase.db` (Windows Anniversary sonrası) veritabanını bulabilirsiniz.

Bu SQLite veritabanının içinde, ilginç veriler içerebilen tüm bildirimleri (XML formatında) barındıran `Notification` tablosunu bulabilirsiniz.

### Timeline

Timeline, ziyaret edilen web sayfalarının, düzenlenen belgelerin ve çalıştırılan uygulamaların **kronolojik geçmişini** sağlayan bir Windows özelliğidir.

Veritabanı `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` yolunda bulunur. Bu veritabanı bir SQLite aracıyla veya [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) aracıyla açılabilir; bu araç, [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) aracıyla açılabilen **2 dosya oluşturur**.

### ADS (Alternate Data Streams)

İndirilen dosyalar, intranet, internet vb. kaynaklardan **nasıl indirildiğini** belirten **ADS Zone.Identifier** içerebilir. Bazı yazılımlar (tarayıcılar gibi), dosyanın indirildiği **URL** gibi **daha fazla bilgi** de ekler.

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10'da **Recycle Bin**, sürücünün kök dizinindeki **`$Recycle.bin`** klasöründe (`C:\$Recycle.bin`) bulunabilir.\
Bu klasörde bir dosya silindiğinde 2 özel dosya oluşturulur:

- `$I{id}`: Dosya bilgileri (silindiği tarih}
- `$R{id}`: Dosyanın içeriği

![File Backups - Recycle Bin: $R{id}: Dosyanın içeriği](<../../../images/image (1029).png>)

Bu dosyalara sahip olduğunuzda, silinen dosyaların özgün konumunu ve silinme tarihini almak için [**Rifiuti**](https://github.com/abelcheung/rifiuti2) aracını kullanabilirsiniz (Vista – Win10 için `rifiuti-vista.exe` kullanın).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy, Microsoft Windows'a dahil olan ve bilgisayar dosyalarının veya birimlerinin kullanımda olsalar bile **yedek kopyalarını** veya anlık görüntülerini oluşturabilen bir teknolojidir.

Bu yedekler genellikle dosya sisteminin kök dizinindeki `\System Volume Information` içinde bulunur ve adları aşağıdaki görüntüde gösterilen **UIDs** değerlerinden oluşur:

![Recycle Bin - Volume Shadow Copies: Bu yedekler genellikle dosya sisteminin kök dizinindeki System Volume Information içinde bulunur ve adları görüntüde gösterilen UIDs değerlerinden oluşur:](<../../../images/image (94).png>)

Forensics imajı **ArsenalImageMounter** ile bağlandığında, bir shadow copy'yi incelemek ve hatta shadow copy yedeklerindeki **dosyaları çıkarmak** için [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) aracı kullanılabilir.

![Recycle Bin - Volume Shadow Copies: Forensics imajı ArsenalImageMounter ile bağlandığında ShadowCopyView aracı bir shadow copy'yi incelemek ve hatta shadow copy yedeklerindeki dosyaları çıkarmak için kullanılabilir:](<../../../images/image (576).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` registry girdisi, **yedeklenmeyecek dosyaları ve anahtarları** içerir:

![Recycle Bin - Volume Shadow Copies: HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore registry girdisi, yedeklenmeyecek dosyaları ve anahtarları içerir:](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` registry'si de `Volume Shadow Copies` hakkında yapılandırma bilgileri içerir.

### Office AutoSaved Files

Office otomatik kaydedilen dosyalarını şu konumda bulabilirsiniz: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Bir shell item, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir öğedir.

### Recent Documents (LNK)

Windows, kullanıcı bir dosyayı **açtığında, kullandığında veya oluşturduğunda** bu **kısayolları** **otomatik olarak** şu konumlarda **oluşturur**:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Bir klasör oluşturulduğunda, klasöre, üst klasöre ve üst klasörün üst klasörüne bir bağlantı da oluşturulur.

Otomatik olarak oluşturulan bu bağlantı dosyaları, öğenin kaynağı hakkında, bunun bir **dosya** mı yoksa **klasör** mü olduğu, dosyanın **MAC** **zamanları**, dosyanın depolandığı **birim bilgileri** ve **hedef dosyanın klasörü** gibi bilgiler **içerir**. Bu bilgiler, dosyaların silinmiş olması durumunda kurtarılmaları için yararlı olabilir.

Ayrıca, bağlantı dosyasının **oluşturulma tarihi**, orijinal dosyanın **ilk kez kullanıldığı** ilk **zaman**; bağlantı dosyasının **değiştirilme tarihi** ise kaynak dosyanın kullanıldığı son **zaman**dır.

Bu dosyaları incelemek için [**LinkParser**](http://4discovery.com/our-tools/) kullanabilirsiniz.

Bu araçta **2 zaman damgası kümesi** bulacaksınız:

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

İlk zaman damgası kümesi **dosyanın kendisine ait zaman damgalarına** işaret eder. İkinci küme ise **bağlantılı dosyanın zaman damgalarına** işaret eder.

Aynı bilgileri Windows CLI aracını çalıştırarak da alabilirsiniz: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Bu durumda bilgiler bir CSV dosyası içine kaydedilecektir.

### Jumplists

Bunlar, uygulama başına belirtilen son dosyalardır. Her uygulamada erişebileceğiniz **bir uygulama tarafından kullanılan son dosyaların listesidir**. **Otomatik olarak veya özel** şekilde oluşturulabilirler.

**Otomatik olarak** oluşturulan **jumplists**, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` konumunda saklanır. Jumplists, `{id}.autmaticDestinations-ms` formatına göre adlandırılır; başlangıçtaki ID, uygulamanın ID'sidir.

Özel jumplists, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` konumunda saklanır ve genellikle dosyayla ilgili **önemli** bir durum gerçekleştiği için (belki favori olarak işaretlendiğinde) uygulama tarafından oluşturulur.

Herhangi bir jumplist'in **oluşturulma zamanı**, **dosyaya ilk kez erişildiği zamanı**; **değiştirilme zamanı** ise son erişim zamanını belirtir.

Jumplist'leri [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.

![Recent Documents (LNK) - Jumplists: Jumplist'leri JumplistExplorer kullanarak inceleyebilirsiniz](<../../../images/image (168).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasının kendisiyle ilişkili olduğunu unutmayın_)

### Shellbags

[**Shellbags'in ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB'lerinin Kullanımı

Bir USB cihazının kullanıldığını aşağıdakilerin oluşturulması sayesinde belirlemek mümkündür:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Bazı LNK dosyalarının özgün yolu göstermek yerine WPDNSE klasörünü gösterdiğini unutmayın:

![Shellbags - Windows USB'lerinin Kullanımı: Bazı LNK dosyalarının özgün yolu göstermek yerine WPDNSE klasörünü gösterdiğini unutmayın](<../../../images/image (218).png>)

WPDNSE klasöründeki dosyalar özgün dosyaların kopyasıdır; bu nedenle bilgisayarın yeniden başlatılmasından sonra varlıklarını korumazlar ve GUID bir shellbag'den alınır.

### Registry Bilgileri

USB'ye bağlı cihazlar hakkında ilginç bilgiler içeren registry anahtarlarını öğrenmek için [bu sayfaya bakın](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB bağlantısının ne zaman gerçekleştirildiğine ilişkin zaman damgalarını almak için `C:\Windows\inf\setupapi.dev.log` dosyasını kontrol edin (`Section start` ifadesini arayın).

![Registry Bilgileri - setupapi: USB bağlantısının ne zaman gerçekleştirildiğine ilişkin zaman damgalarını almak için C: Windows inf setupapi.dev.log dosyasını kontrol edin (Section start ifadesini arayın)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com), bir imaja bağlanmış USB cihazları hakkında bilgi edinmek için kullanılabilir.

![setupapi - USB Detective: USBDetective, bir imaja bağlanmış USB cihazları hakkında bilgi edinmek için kullanılabilir](<../../../images/image (452).png>)

### Plug and Play Cleanup

'Plug and Play Cleanup' olarak bilinen zamanlanmış görev, öncelikle eski driver sürümlerinin kaldırılması için tasarlanmıştır. Belirtilen amacının en yeni driver paketi sürümünü korumak olmasına karşın, çevrimiçi kaynaklar bunun 30 gündür etkin olmayan driver'ları da hedeflediğini belirtmektedir. Sonuç olarak, son 30 gün içinde bağlanmamış çıkarılabilir cihazlara ait driver'lar silinebilir.<sup>[[1]](#references)</sup>

Görev şu konumda bulunur: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Görevin içeriğini gösteren bir ekran görüntüsü aşağıda verilmiştir: ![USB Detective - Plug and Play Cleanup: Görev şu konumda bulunur: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Görevin Temel Bileşenleri ve Ayarları:**

- **pnpclean.dll**: Bu DLL, gerçek temizleme işleminden sorumludur.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanmıştır ve genel görev zamanlama motorunun kullanıldığını belirtir.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler'ın normal Automatic maintenance sırasında temizleme görevini aylık olarak başlatmasını sağlar.
- **Deadline ('P2M')**: Görev art arda iki ay başarısız olursa Task Scheduler'a görevi acil Automatic maintenance sırasında yürütmesini bildirir.

Bu yapılandırma, driver'ların düzenli bakımını ve temizlenmesini sağlar; ayrıca art arda gerçekleşen hatalar durumunda görevin yeniden denenmesine olanak tanır.

**Daha fazla bilgi için kontrol edin:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## E-postalar

E-postalar **2 ilginç bölüm içerir: Üst bilgiler ve e-postanın içeriği**. **Üst bilgilerde** şu tür bilgileri bulabilirsiniz:

- E-postaları **kimin** gönderdiği (e-posta adresi, IP, e-postayı yeniden yönlendiren mail sunucuları)
- E-postanın **ne zaman** gönderildiği

Ayrıca `References` ve `In-Reply-To` üst bilgilerinde mesajların ID'lerini bulabilirsiniz:

![Plug and Play Cleanup - E-postalar: E-postanın ne zaman gönderildiği](<../../../images/image (593).png>)

### Windows Mail App

Bu uygulama e-postaları HTML veya metin olarak kaydeder. E-postaları `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` içindeki alt klasörlerde bulabilirsiniz. E-postalar `.dat` uzantısıyla kaydedilir.

E-postaların **metadata** bilgileri ve **contacts** bilgileri **EDB database** içinde bulunabilir: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

Dosyanın uzantısını `.vol` yerine `.edb` olarak **değiştirin**; ardından dosyayı açmak için [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracını kullanabilirsiniz. `Message` tablosunda e-postaları görebilirsiniz.

### Microsoft Outlook

Exchange sunucuları veya Outlook istemcileri kullanıldığında bazı MAPI üst bilgileri bulunur:

- `Mapi-Client-Submit-Time`: E-postanın gönderildiği sistem zamanı
- `Mapi-Conversation-Index`: Thread'deki alt mesajların sayısı ve thread'deki her mesajın zaman damgası
- `Mapi-Entry-ID`: Mesaj tanımlayıcısı.
- `Mappi-Message-Flags` ve `Pr_last_Verb-Executed`: MAPI client hakkında bilgiler (mesaj okundu mu? okunmadı mı? yanıtlandı mı? yönlendirildi mi? out of the office?)

Microsoft Outlook istemcisinde gönderilen/alınan tüm mesajlar, contacts verileri ve calendar verileri şu konumlardaki bir PST dosyasında saklanır:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` registry yolu, kullanılan dosyayı belirtir.

PST dosyasını [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) aracını kullanarak açabilirsiniz.

![Windows Mail App - Microsoft Outlook: PST dosyasını Kernel PST Viewer aracını kullanarak açabilirsiniz](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Bir **OST file**, Microsoft Outlook **IMAP** veya bir **Exchange** sunucusuyla yapılandırıldığında oluşturulur ve PST dosyasına benzer bilgiler depolar. Bu dosya sunucuyla senkronize edilir; **son 12 aya** ait verileri, **en fazla 50 GB** boyutla saklar ve PST dosyasıyla aynı dizinde bulunur. Bir OST dosyasını görüntülemek için [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.

### Ekleri Alma

Kayıp ekler şu konumlardan kurtarılabilir:

- **IE10** için: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 ve üzeri** için: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird**, verileri `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` konumunda bulunan **MBOX files** kullanarak depolar.

### Görüntü Küçük Resimleri

- **Windows XP ve 8-8.1**: Küçük resimlerin bulunduğu bir klasöre erişildiğinde, silinmiş olsalar bile görüntü önizlemelerini depolayan bir `thumbs.db` dosyası oluşturulur.
- **Windows 7/10**: `thumbs.db`, UNC path üzerinden bir klasöre ağ üzerinden erişildiğinde oluşturulur.
- **Windows Vista ve sonrası**: Küçük resim önizlemeleri `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` konumunda merkezileştirilir ve **thumbcache_xxx.db** adlı dosyalarda saklanır. Bu dosyaları görüntülemek için [**Thumbsviewer**](https://thumbsviewer.github.io) ve [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) araçları kullanılabilir.

### Windows Registry Bilgileri

Kapsamlı sistem ve kullanıcı etkinliği verilerini depolayan Windows Registry, şu konumlardaki dosyalarda bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` alt anahtarları için `%windir%\System32\Config`.
- `HKEY_CURRENT_USER` için `%UserProfile%{User}\NTUSER.DAT`.
- Windows Vista ve sonraki sürümler, `HKEY_LOCAL_MACHINE` registry dosyalarını `%Windir%\System32\Config\RegBack\` konumunda yedekler.
- Ayrıca program çalıştırma bilgileri, Windows Vista ve Windows 2008 Server'dan itibaren `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` konumunda saklanır.

### Araçlar

Registry dosyalarını analiz etmek için bazı araçlar kullanışlıdır:

- **Registry Editor**: Windows ile birlikte kurulur. Mevcut oturumun Windows registry'sinde gezinmek için kullanılan bir GUI'dir.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Registry dosyasını yüklemenize ve bir GUI üzerinden dosyada gezinmenize olanak tanır. Ayrıca ilginç bilgiler içeren anahtarları vurgulayan Bookmarks içerir.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen registry'de gezinmenizi sağlayan bir GUI'ye sahiptir ve ayrıca yüklenen registry içindeki ilginç bilgileri vurgulayan plugin'ler içerir.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Yüklenen registry'den önemli bilgileri çıkarabilen başka bir GUI uygulamasıdır.

### Silinmiş Element'i Kurtarma

Bir anahtar silindiğinde bu şekilde işaretlenir; ancak kapladığı alana ihtiyaç duyulana kadar kaldırılmaz. Bu nedenle **Registry Explorer** gibi araçları kullanarak silinmiş anahtarları kurtarmak mümkündür.

### Last Write Time

Her Key-Value, en son değiştirildiği zamanı belirten bir **timestamp** içerir.

### SAM

**SAM** file/hive, sistemin **users, groups ve users passwords** hash'lerini içerir.

`SAM\Domains\Account\Users` konumunda username, RID, son login, son başarısız logon, login counter, password policy ve hesabın oluşturulma zamanını elde edebilirsiniz. **Hash**'leri elde etmek için ayrıca **SYSTEM** file/hive dosyasına da **ihtiyacınız vardır**.

### Windows Registry'deki İlginç Girdiler


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Çalıştırılan Programlar

### Temel Windows Process'leri

[Bu yazıda](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), şüpheli davranışları tespit etmek için kullanılan yaygın Windows process'leri hakkında bilgi edinebilirsiniz.<sup>[[2]](#references)</sup>

### Windows Recent APPs

`NTUSER.DAT` registry'si içinde `Software\Microsoft\Current Version\Search\RecentApps` path'inde **çalıştırılan uygulama**, uygulamanın **son çalıştırıldığı zaman** ve uygulamanın **kaç kez** başlatıldığı hakkında bilgiler içeren subkey'ler bulunur.

### BAM (Background Activity Moderator)

`SYSTEM` file'ını bir registry editor ile açın. `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` path'i içinde **her kullanıcı tarafından çalıştırılan uygulamalar** ve bunların **hangi zamanda** çalıştırıldığı hakkında bilgileri bulabilirsiniz (path içindeki `{SID}` değerine dikkat edin); zaman, registry'nin Data value'su içindedir.

### Windows Prefetch

Prefetching, bir kullanıcının **yakın gelecekte erişebileceği** içerikleri görüntülemek için gereken **gerekli kaynakları sessizce alma** ve böylece kaynaklara daha hızlı erişilmesini sağlama tekniğidir.

Windows prefetch, çalıştırılan programların daha hızlı yüklenebilmesi için **cache'lerinin oluşturulmasını** içerir. Bu cache'ler `C:\Windows\Prefetch` path'i içinde `.pf` dosyaları olarak oluşturulur. XP/VISTA/WIN7'de 128, Win8/Win10'da ise 1024 dosya sınırı vardır.

Dosya adı `{program_name}-{hash}.pf` şeklinde oluşturulur (hash, executable'ın path'i ve argümanlarına dayanır). W10'da bu dosyalar sıkıştırılır. Dosyanın tek başına mevcut olması, **programın bir noktada çalıştırıldığını** gösterir.

`C:\Windows\Prefetch\Layout.ini` dosyası, prefetch edilen dosyaların **bulunduğu klasörlerin adlarını** içerir. Bu dosya, **çalıştırma sayısı**, çalıştırma **tarihleri** ve program tarafından **açılan dosyalar** hakkında **bilgi** içerir.

Bu dosyaları incelemek için [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) aracını kullanabilirsiniz:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch**, sırada neyin yükleneceğini tahmin ederek **programları daha hızlı yüklemek** amacıyla prefetch ile aynı hedefe sahiptir. Ancak prefetch hizmetinin yerini almaz.\
Bu hizmet, `C:\Windows\Prefetch\Ag*.db` konumunda veritabanı dosyaları oluşturur.

Bu veritabanlarında **programın** **adı**, **çalıştırılma sayısı**, **açılan** **dosyalar**, **erişilen** **birim**, **tam** **yol**, **zaman aralıkları** ve **zaman damgaları** bulunabilir.

Bu bilgilere [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) aracını kullanarak erişebilirsiniz.

### SRUM

**System Resource Usage Monitor** (SRUM), **bir işlem tarafından** **tüketilen** **kaynakları** **izler**. W8'de ortaya çıkmıştır ve verileri `C:\Windows\System32\sru\SRUDB.dat` konumunda bulunan bir ESE veritabanında saklar.

Aşağıdaki bilgileri sağlar:

- AppID ve yol
- İşlemi çalıştıran kullanıcı
- Gönderilen baytlar
- Alınan baytlar
- Ağ arayüzü
- Bağlantı süresi
- İşlem süresi

Bu bilgiler her 60 dakikada bir güncellenir.

Bu dosyadaki verileri [**srum_dump**](https://github.com/MarkBaggett/srum-dump) aracını kullanarak elde edebilirsiniz.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**ShimCache** olarak da bilinen **AppCompatCache**, uygulama uyumluluğu sorunlarını çözmek amacıyla **Microsoft** tarafından geliştirilen **Application Compatibility Database** sisteminin bir parçasıdır. Bu sistem bileşeni, aşağıdakiler dahil olmak üzere çeşitli dosya meta verilerini kaydeder:

- Dosyanın tam yolu
- Dosyanın boyutu
- **$Standard_Information** (SI) altındaki Son Değiştirilme zamanı
- ShimCache'in Son Güncellenme zamanı
- Process Execution Flag

Bu veriler, işletim sisteminin sürümüne bağlı olarak kayıt defterinde belirli konumlarda depolanır:

- XP için veriler, 96 giriş kapasitesine sahip olan `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` altında depolanır.
- Server 2003 ile Windows 2008, 2012, 2016, 7, 8 ve 10 sürümleri için depolama yolu `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` şeklindedir ve sırasıyla 512 ve 1024 giriş kapasitesine sahiptir.

Depolanan bilgileri ayrıştırmak için [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) kullanılması önerilir.

![SRUM - AppCompatCache (ShimCache): Depolanan bilgileri ayrıştırmak için AppCompatCacheParser tool kullanılması önerilir](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** dosyası, bir sistemde çalıştırılmış uygulamalarla ilgili ayrıntıları kaydeden bir registry hive'dır. Genellikle `C:\Windows\AppCompat\Programas\Amcache.hve` konumunda bulunur.

Bu dosya, yürütülebilir dosyaların yolları ve SHA1 hash'leri de dahil olmak üzere yakın zamanda çalıştırılan process'lere ait kayıtları depolamasıyla dikkat çeker. Bu bilgiler, bir sistemdeki uygulama etkinliğini izlemek için son derece değerlidir.

**Amcache.hve** dosyasındaki verileri çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool'u kullanılabilir. Aşağıdaki komut, **Amcache.hve** dosyasının içeriğini ayrıştırmak ve sonuçları CSV formatında dışa aktarmak için AmcacheParser'ın nasıl kullanılacağına ilişkin bir örnektir:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Oluşturulan CSV dosyaları arasında `Amcache_Unassociated file entries`, ilişkilendirilmemiş dosya girdileri hakkında sağladığı zengin bilgiler nedeniyle özellikle dikkat çekicidir.

Oluşturulan en ilgi çekici CVS dosyası `Amcache_Unassociated file entries` dosyasıdır.

### RecentFileCache

Bu artifact yalnızca W7'de `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` konumunda bulunabilir ve bazı binary dosyaların yakın zamanda çalıştırılması hakkında bilgiler içerir.

Dosyayı ayrıştırmak için [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) aracını kullanabilirsiniz.

### Scheduled tasks

Bunları `C:\Windows\Tasks` veya `C:\Windows\System32\Tasks` konumlarından çıkarabilir ve XML olarak okuyabilirsiniz.

### Services

Bunları registry'de `SYSTEM\ControlSet001\Services` altında bulabilirsiniz. Neyin ve ne zaman çalıştırılacağını görebilirsiniz.

### **Windows Store**

Yüklü uygulamalar `\ProgramData\Microsoft\Windows\AppRepository\`\
konumunda bulunabilir.
Bu repository, sistemde **yüklenmiş her uygulama** için **`StateRepository-Machine.srd`** database'i içinde bir **log** barındırır.

Bu database'in Application tablosunda "Application ID", "PackageNumber" ve "Display Name" sütunlarını bulmak mümkündür. Bu sütunlar, önceden yüklenmiş ve yüklenmiş uygulamalar hakkında bilgiler içerir ve yüklü uygulamaların ID'lerinin sıralı olması gerektiğinden bazı uygulamaların kaldırılıp kaldırılmadığı tespit edilebilir.

Ayrıca **yüklü uygulamalar** registry'de şu path içinde bulunabilir: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Ve **kaldırılmış** **uygulamalar** şu konumda bulunabilir: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows events içinde görünen bilgiler şunlardır:

- Ne oldu
- Timestamp (UTC + 0)
- İlgili kullanıcılar
- İlgili host'lar (hostname, IP)
- Erişilen asset'ler (dosyalar, klasör, printer, services)

Log'lar Windows Vista'dan önce `C:\Windows\System32\config` konumunda, Windows Vista'dan sonra ise `C:\Windows\System32\winevt\Logs` konumunda bulunur. Windows Vista'dan önce event log'ları binary formatındaydı; daha sonra **XML formatını** kullanmaya başladılar ve **.evtx** uzantısına sahip oldular.

Event dosyalarının konumu SYSTEM registry'sinde **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** altında bulunabilir.

Bunlar Windows Event Viewer (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) **ya da** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** gibi diğer araçlarla görüntülenebilir.**

## Windows Security Event Logging'i Anlama

Access event'leri `C:\Windows\System32\winevt\Security.evtx` konumunda bulunan security configuration file'a kaydedilir. Bu dosyanın boyutu ayarlanabilir ve kapasitesine ulaşıldığında eski event'lerin üzerine yazılır. Kaydedilen event'ler arasında kullanıcı login ve logout'ları, kullanıcı işlemleri ve security settings değişikliklerinin yanı sıra dosya, klasör ve paylaşılan asset erişimleri bulunur.

### User Authentication için Önemli Event ID'leri:

- **EventID 4624**: Bir kullanıcının başarıyla authenticate olduğunu gösterir.
- **EventID 4625**: Bir authentication failure olduğunu belirtir.
- **EventIDs 4634/4647**: Kullanıcının logout event'lerini temsil eder.
- **EventID 4672**: Administrative privileges ile login yapıldığını belirtir.

#### EventID 4634/4647 İçindeki Sub-type'lar:

- **Interactive (2)**: Doğrudan kullanıcı login'i.
- **Network (3)**: Paylaşılan klasörlere erişim.
- **Batch (4)**: Batch process'lerin çalıştırılması.
- **Service (5)**: Service'lerin başlatılması.
- **Proxy (6)**: Proxy authentication.
- **Unlock (7)**: Ekranın password ile kilidinin açılması.
- **Network Cleartext (8)**: Genellikle IIS'ten gönderilen clear text password transmission.
- **New Credentials (9)**: Erişim için farklı credential'ların kullanılması.
- **Remote Interactive (10)**: Remote desktop veya terminal services login'i.
- **Cache Interactive (11)**: Domain controller ile iletişim kurmadan cached credential'lar ile login.
- **Cache Remote Interactive (12)**: Cached credential'lar ile remote login.
- **Cached Unlock (13)**: Cached credential'lar ile kilidin açılması.

#### EventID 4625 için Status ve Sub Status Code'ları:

- **0xC0000064**: Kullanıcı adı mevcut değil - Bir username enumeration attack'ine işaret edebilir.
- **0xC000006A**: Kullanıcı adı doğru ancak password yanlış - Olası password guessing veya brute-force attempt.
- **0xC0000234**: Kullanıcı hesabı lockout oldu - Birden fazla başarısız login ile sonuçlanan bir brute-force attack'in ardından gerçekleşebilir.
- **0xC0000072**: Account disabled - Disabled account'lara erişmek için yapılan unauthorized attempt'ler.
- **0xC000006F**: Allowed time dışında logon - Belirlenen login saatleri dışında erişim girişimlerini gösterir ve unauthorized access işareti olabilir.
- **0xC0000070**: Workstation restrictions ihlali - Unauthorized bir konumdan login yapılmaya çalışıldığını gösterebilir.
- **0xC0000193**: Account expiration - Süresi dolmuş user account'lar ile yapılan access attempt'leri.
- **0xC0000071**: Expired password - Güncel olmayan password'ler ile login attempt'leri.
- **0xC0000133**: Time sync sorunları - Client ve server arasındaki büyük zaman farklılıkları, pass-the-ticket gibi daha gelişmiş attack'lerin göstergesi olabilir.
- **0xC0000224**: Mandatory password change gerekli - Sık gerçekleşen zorunlu değişiklikler, account security'yi istikrarsızlaştırma girişimine işaret edebilir.
- **0xC0000225**: Bir security issue yerine system bug'ını gösterir.
- **0xC000015b**: Denied logon type - Bir kullanıcının service logon çalıştırmaya çalışması gibi unauthorized logon type ile access attempt.

#### EventID 4616:

- **Time Change**: System time'ın değiştirilmesi; event timeline'ını gizleyebilir.

#### EventID 6005 ve 6006:

- **System Startup and Shutdown**: EventID 6005 system'in başlatıldığını, EventID 6006 ise kapatıldığını gösterir.

#### EventID 1102:

- **Log Deletion**: Security log'larının temizlenmesi; bu durum çoğunlukla illicit activity'leri gizlemeye yönelik bir red flag'dir.

#### USB Device Tracking için EventID'ler:

- **20001 / 20003 / 10000**: USB device'ın ilk bağlantısı.
- **10100**: USB driver update.
- **EventID 112**: USB device insertion zamanı.

Bu login type'larını ve credential dumping fırsatlarını simüle etmeye yönelik pratik örnekler için [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) kaynağına başvurabilirsiniz.

Status ve sub-status code'ları da dahil olmak üzere event ayrıntıları, event'in nedenleri hakkında daha fazla bilgi sağlar; bu durum özellikle Event ID 4625'te dikkat çekicidir.

### Windows Events'leri Kurtarma

Silinmiş Windows Events'leri kurtarma şansını artırmak için şüpheli bilgisayarın power'ını doğrudan fişini çekerek kapatmanız önerilir. `.evtx` uzantısını belirterek kullanılan bir recovery tool olan **Bulk_extractor**, bu tür event'leri kurtarmaya çalışmak için önerilir.

### Windows Events Aracılığıyla Yaygın Attack'leri Tespit Etme

Yaygın cyber attack'leri tespit etmek için Windows Event ID'lerinin nasıl kullanılacağına dair kapsamlı bir guide için [Red Team Recipe](https://redteamrecipe.com/event-codes/) adresini ziyaret edin.

#### Brute Force Attacks

Birden fazla EventID 4625 kaydıyla tespit edilebilir; attack başarılı olursa bunları bir EventID 4624 takip eder.

#### Time Change

EventID 4616 tarafından kaydedilir; system time'daki değişiklikler forensic analysis'i karmaşıklaştırabilir.

#### USB Device Tracking

USB device tracking için faydalı System EventID'leri arasında ilk kullanım için 20001/20003/10000, driver update'leri için 10100 ve insertion timestamp'leri için DeviceSetupManager'dan EventID 112 bulunur.

#### System Power Events

EventID 6005 system startup'ını, EventID 6006 ise shutdown'ı gösterir.

#### Log Deletion

Security EventID 1102, forensic analysis açısından kritik bir event olan log'ların silindiğini belirtir.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
