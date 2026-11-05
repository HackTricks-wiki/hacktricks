# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Genel Windows Artifacts

### Windows 10 Bildirimleri

Kullanıcı başına bildirim veritabanı `%LOCALAPPDATA%\Microsoft\Windows\Notifications` konumundadır (örneğin, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). İlk Windows 10 sürümlerinde `appdb.dat` kullanılıyordu; Anniversary Update (1607) ile `wpndatabase.db` kullanıma sunuldu. SQLite veritabanında bildirim içeriklerini ve zamanlama alanlarını içeren bir `Notification` tablosu bulunur; ancak saklama süresi ve mevcut veriler sürüme ve temizleme politikasına göre değişir.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline, desteklenen uygulamalar, belgeler ve diğer kullanıcı etkinliklerine ilişkin kayıtlar içerebilen bir etkinlik geçmişi özelliğidir; kapsama alanı uygulamaya ve Windows sürümüne bağlıdır.<sup>[[4]](#references)</sup>

Veritabanı `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` konumunda bulunur. SQLite ile açılabilir veya çıktısı [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) ile incelenebilen [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) kullanılarak ayrıştırılabilir.<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall anlık görüntüleri (Copilot+ PC'ler)

Recall, desteklenen Windows 11 Copilot+ PC'lerde isteğe bağlıdır. Güncel derlemeler, anlık görüntüleri ve dizinlerini Windows Hello'ya ve bir VBS enclave'e bağlı anahtarlarla şifreler. Çevrimdışı bir mağaza kopyasını düz metin bir SQLite veritabanı olarak değerlendirmeyin; 2024 önizlemesinin ve yayımlanan tasarımın erişim özellikleri farklıdır.<sup>[[77]](#references)</sup>

**Canlı ve etkin bir Recall oturumunda**, aynı kullanıcıya ait `AIXHost.exe` işleme süreci farklı bir erişim yüzeyidir. TotalRecall Reloaded kavram kanıtı, bu sürece bir DLL enjekte eder ve Recall COM arayüzlerini çağırır. Tüm geçmişin çıkarılması için kullanıcının Windows Hello ile kimlik doğrulaması yapması gerekir; bu, çevrimdışı şifre çözme veya Hello atlatma yöntemi değildir. Araştırmacı aracı Windows 11 ARM64 üzerinde belgelediğinden, araca güvenmeden önce hedef derlemeyle uyumluluğunu doğrulayın.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth`, Hello olmadan en son yakalamanın büyük boyutlu bir sürümünü istemek için `GetRecentCaptureThumbnail` kullanır. Yetkilendirmeden sonra `--wait`, ekran görüntülerini, OCR metnini ve uygulama ile pencere bağlamı dahil her yakalamaya ait meta verileri çıkarabilir. Çıktı, zaman damgalı bir `extraction_*` dizinine yazılır. Bunlar kavram kanıtından elde edilen, derlemeye bağlı bulgulardır; Recall'ın etkin olduğunu veya tüm ekranların yakalandığını garanti etmez.<sup>[[78]](#references)</sup>

### ADS (Alternatif Veri Akışları)

Yerel güven sınırının dışından indirilen dosyalarda, bölge bilgilerini kaydeden ve URL gibi kaynak meta verileri içerebilen **`Zone.Identifier` alternatif veri akışı** bulunabilir. Bu akışın bulunması ve alanları, dosyayı oluşturan programa ve sistem ilkesine bağlıdır.<sup>[[6]](#references)</sup>

## **Dosya Yedekleri**

### Geri Dönüşüm Kutusu

Vista ve sonraki sürümlerde **Geri Dönüşüm Kutusu**, sürücünün kök dizinindeki **`$Recycle.bin`** klasöründe bulunur (örneğin, `C:\$Recycle.bin`).\
Bu klasörde bir dosya silindiğinde 2 özel dosya oluşturulur:

- `$I{id}`: Silinme zamanı ve özgün yol dahil dosya bilgileri
- `$R{id}`: Dosyanın içeriği

![Dosya Yedekleri - Geri Dönüşüm Kutusu: $R{id}: Dosyanın içeriği](<../../../images/image (1029).png>)

Bu dosyaları kullanarak özgün yolu ve silinme zamanını çıkarmak için [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) kullanabilirsiniz (hedef Windows sürümüne uygun sürümü kullanın).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Dosya Yedekleri - Geri Dönüşüm Kutusu: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Birim Gölge Kopyaları

Volume Shadow Copy Service (VSS), dosyalar kullanımdayken birimlerin belirli bir andaki gölge kopyalarını oluşturabilir; gölge kopya, adli bilişim imajının yerini tutmaz.<sup>[[8]](#references)</sup>

Kopya meta verileri normalde birimin kök dizinindeki `\System Volume Information` ile ilişkilidir; tanımlayıcılar sisteme göre değişir:

![Geri Dönüşüm Kutusu - Birim Gölge Kopyaları: Bu yedekler genellikle dosya sisteminin kökündeki System Volume Information konumunda bulunur ve adları, ... bölümünde gösterilen UID'lerden oluşur](<../../../images/image (94).png>)

Uygun bir adli bilişim bağlayıcısıyla imajı bağladıktan sonra, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) kullanılabilir VSS anlık görüntülerini listeleyebilir ve bunlardaki dosyalara göz atabilir veya dosyaları kopyalayabilir.<sup>[[9]](#references)</sup>

![Geri Dönüşüm Kutusu - Birim Gölge Kopyaları: Adli bilişim imajı ArsenalImageMounter ile bağlandıktan sonra, ShadowCopyView aracı bir gölge kopyayı incelemek ve hatta dosyaları çıkarmak için kullanılabilir...](<../../../images/image (576).png>)

VSS kayıt defteri yazıcısının yapılandırması, yedeklemenin dışında tutulacak dosya ve anahtarları belirtebilen `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` anahtarını içerir:<sup>[[10]](#references)[[11]](#references)</sup>

![Geri Dönüşüm Kutusu - Birim Gölge Kopyaları: HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore kayıt defteri girdisi, yedeklenmeyecek dosya ve anahtarları içerir](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` anahtarı da VSS hizmeti yapılandırmasını içerir.<sup>[[8]](#references)</sup>

### Office Otomatik Kaydedilen Dosyaları

AutoRecover konumları Office uygulamasına, sürüme ve yapılandırmaya göre değişir. Word için Microsoft, varsayılan konum olarak `%APPDATA%\Microsoft\Word` yolunu belirtir; etkin yolu uygulama ayarlarından kontrol edin.<sup>[[12]](#references)</sup>

## Shell Öğeleri

Shell öğesi, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir öğedir.

### Son Kullanılan Belgeler (LNK)

Windows, kullanıcı bir öğeyi açtığında veya başka bir şekilde ona eriştiğinde genellikle son kullanılan öğeler için kısayollar oluşturur:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Klasöre erişilmesi, klasör ve ilişkili üst klasörler için de bağlantılar oluşturabilir.

Bu bağlantı dosyaları hedef türünü, hedefin MAC zamanlarını, birim bilgilerini ve hedef yolunu içerebilir. Bu meta veriler, kaldırılmış bir hedefi belirlemeye yardımcı olabilir; ancak bu bulgu tek başına hedefin belirli bir kullanıcı tarafından açıldığının kanıtı değildir.<sup>[[13]](#references)[[14]](#references)</sup>

LNK dosyasının kendi dosya sistemi zaman damgaları ile içine gömülü hedef zaman damgaları birbirinden farklıdır. Doğrulayıcı başka bulgular olmadan bağlantının oluşturulmasını ilk kullanım, bağlantının değiştirilmesini de son kullanım olarak yorumlamayın; biçim, hedef zaman damgalarını bağlantı dosyasının zaman damgalarından ayrı saklar.<sup>[[13]](#references)[[14]](#references)</sup>

Mevcut [**LinkParser**](http://4discovery.com/our-tools/) bağlantısı, geçmişten kalan bir seçenek olarak korunmuştur; ancak inceleme sırasında belgelere erişilememiştir. Belgeleri bulunan bir komut satırı ayrıştırıcısı için [**LECmd**](https://github.com/EricZimmerman/LECmd) kullanın.<sup>[[15]](#references)</sup>

Bu araçlar genellikle iki zaman damgası kümesini gösterir:

- **Hedef zaman damgaları:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Bağlantı dosyasının zaman damgaları:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

İlk küme hedefi, ikinci küme ise LNK dosyasının kendisini ifade eder. Her ikisini de ayrıştırıcının belgeleri ve dosya sistemi bağlamıyla birlikte değerlendirin.<sup>[[14]](#references)[[15]](#references)</sup>

Aynı bilgileri Windows CLI aracı [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) ile çalıştırarak da alabilirsiniz.<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

Bu durumda bilgiler bir CSV dosyasına kaydedilir.

### Jumplists

Jump List'ler, uygulama başına tutulan son kullanılan veya göreve özgü öğe listeleridir ve otomatik ya da özel olabilir.<sup>[[13]](#references)</sup>

Otomatik Jump List'ler `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` konumunda saklanır ve uygulamayı tanımlayan ID'yi içeren `{id}.automaticDestinations-ms` gibi adlar kullanır.

Özel Jump List'ler `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` konumunda saklanır; hangi görev veya öğe girişlerini oluşturacağını uygulama belirler.

Dosya sisteminin oluşturulma ve değiştirilme zamanları, Jump List dosyasını tanımlar; listelenen her hedefe ilk ve son erişim zamanını otomatik olarak göstermez. Ayrıştırılan girişleri dosyanın zaman damgaları ve diğer artefaktlarla ilişkilendirin.<sup>[[13]](#references)</sup>

Jump List'leri [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.<sup>[[5]](#references)</sup>

![Son Belgeler (LNK) - Jumplists: JumplistExplorer kullanarak jumplist'leri inceleyebilirsiniz](<../../../images/image (168).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasının kendisiyle ilgili olduğunu unutmayın_)

### Shellbags

[**Shellbag'lerin ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB Kullanımı

USB kullanımını bazen çıkarılabilir medyadaki dosyalara erişildiğinde oluşturulan şu artefaktlarla doğrulamak mümkündür:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) gibi araçlar bu artefaktları USB cihaz kayıtlarıyla ilişkilendirir; ancak artefaktların bulunabilirliği Windows sürümüne ve uygulamaya bağlıdır.<sup>[[18]](#references)</sup>

Windows XP ve Windows 7 MTP iş akışları için belgelenen testlerde, bazı LNK dosyaları özgün yol yerine `WPDNSE` klasörünü gösteriyordu.<sup>[[16]](#references)</sup>

![Shellbags - Windows USB Kullanımı: Bazı LNK dosyalarının özgün yol yerine WPDNSE klasörünü gösterdiğini unutmayın](<../../../images/image (218).png>)

Bu çalışmada `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` altında kopyalar gözlemlendi; testlerde geçici içerikler yeniden başlatma sonrasında kalmadı ve GUID, shellbag verileriyle ilişkilendirilebildi. Bunu evrensel bir kural olarak değil, işletim sistemine, cihaza ve uygulamaya bağlı bir davranış olarak değerlendirin.<sup>[[16]](#references)</sup>

### Registry Bilgileri

USB ile bağlanan cihazlar hakkında ilgi çekici bilgiler içeren registry anahtarlarını öğrenmek için [bu sayfaya göz atın](interesting-windows-registry-keys.md#usb-information).

### setupapi

Vista ve sonraki sürümlerde, cihaz yükleme etkinliğini incelemek için `C:\Windows\inf\setupapi.dev.log` dosyasına bakın. Bölüm başlıklarında `Section start` zaman damgaları bulunur; bunlar kurulum işlemlerini belgeler. Kesin fiziksel takılma zamanı olarak değerlendirilmemeli, diğer bağlantı kanıtlarıyla ilişkilendirilmelidir.<sup>[[17]](#references)</sup>

![Registry Bilgileri - setupapi: USB bağlantısının ne zaman gerçekleştiğine ilişkin zaman damgalarını görmek için C: Windows inf setupapi.dev.log dosyasını inceleyin (Section start ifadesini arayın)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Bir imaja bağlanmış USB cihazları hakkında bilgi edinmek için [**USBDetective**](https://usbdetective.com) kullanılabilir.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: Bir imaja bağlanmış USB cihazları hakkında bilgi edinmek için USBDetective kullanılabilir](<../../../images/image (452).png>)

### Tak ve Kullan Temizleme

`Plug and Play Cleanup` olarak bilinen zamanlanmış görev, eski sürücü sürümlerini kaldırır. Adam Harrison tarafından belgelenen bir Windows 10 görev tanımı, 30 gündür etkin olmayan sürücüleri de hedefler; bu nedenle çıkarılabilir cihaz sürücülerine ilişkin kanıtlar temizlenebilir. Bu davranışı genellemeden önce yerel görev tanımını ve Windows derlemesini doğrulayın.<sup>[[1]](#references)</sup>

Görev şu yolda bulunur: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Windows Plug and Play Cleanup zamanlanmış görevinin XML tanımı](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Görevin Temel Bileşenleri ve Ayarları:**

- **pnpclean.dll**: Bu DLL, gerçek temizleme işleminden sorumludur.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanmıştır; bu, genel görev zamanlama altyapısının kullanıldığını gösterir.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Task Scheduler'a, düzenli Automatic bakım sırasında temizleme görevini aylık olarak başlatmasını söyler.
  - **Deadline ('P2M')**: Görev art arda iki ay boyunca başarısız olursa, Task Scheduler'a görevi acil Automatic bakım sırasında çalıştırmasını söyler.

Bu yapılandırma düzenli bakım planlar ve art arda gelen başarısızlıklardan sonra yeniden dener; XML'in ve davranışın tam biçimi sürüme bağlıdır.<sup>[[1]](#references)</sup>

**Daha fazla bilgi için göz atın:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-postalar

E-postalar **2 ilgi çekici bölüm içerir: Başlıklar ve e-posta içeriği**. **Başlıklarda** şu tür bilgiler bulunabilir:

- E-postayı **kimin** gönderdiği (e-posta adresi, IP, e-postayı yönlendiren posta sunucuları)
- E-postanın **ne zaman** gönderildiği

Ayrıca `References` ve `In-Reply-To` başlıkları, yanıtları bir konuşmayla ilişkilendirmek için kullanılan mesaj ID'lerini içerebilir.<sup>[[76]](#references)</sup>

![Tak ve Kullan Temizleme - E-postalar: E-postanın ne zaman gönderildiği](<../../../images/image (593).png>)

### Windows Mail Uygulaması

Bu uygulama e-posta içeriğini `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` gibi yollar altında yardımcı metin veya HTML dosyalarına kaydeder; numaralı klasörlerin ve dosyaların tam düzeni artefakta göre değişebilir.<sup>[[75]](#references)</sup>

E-postaların **metadata**'sı ve **kişiler**, **ESE veritabanı** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` içinde bulunabilir.<sup>[[75]](#references)</sup>

`store.vol`, Extensible Storage Engine (ESE) biçimini kullanır. Bir kopya üzerinde çalışın ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi bir ESE ayrıştırıcısı kullanın; bir araç `.edb` uzantısı gerektiriyorsa yalnızca kopyanın adını değiştirin ve `Message` tablosuna güvenmeden önce tablo şemasını doğrulayın.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI özelliklerini incelerken şu standart özellikler önemlidir:

- `PidTagClientSubmitTime`: İstemcinin mesajı gönderdiği UTC zamanı.
- `PidTagConversationIndex`: Mesajın konuşma dizisindeki göreli konumu.
- `PidTagEntryId`: Mesaj nesnesinin tanımlayıcısı.
- `PidTagMessageFlags`: Gönderildi, okundu, okunmadı veya ek içeriyor gibi durum bayrakları.
- `PidTagLastVerbExecuted`: Mesaj için kaydedilen son işlem; örneğin açma, yanıtlama veya iletme.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook veri dosyalarının konumları sürüme ve hesap türüne göre değişir. Microsoft, PST/OST dosyaları için şu yaygın konumları belgeliyor:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

`HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` registry yolu, Outlook profilini ve ilişkili veri dosyası yapılandırmasını gösterebilir.

PST dosyaları mesajlar, kişiler, takvim verileri ve diğer Outlook öğelerini içerebilir. Bir kopyayı [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) ile inceleyebilirsiniz.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail Uygulaması - Microsoft Outlook: PST dosyasını Kernel PST Viewer aracıyla açabilirsiniz](<../../../images/image (498).png>)

### Microsoft Outlook OST Dosyaları

Bir **OST dosyası**, Exchange veya Microsoft 365 hesapları için yerel önbellektir; Cached Exchange Mode, POP veya IMAP hesapları için geçerli değildir. Çevrimdışı dönem yapılandırılabilir ve varsayılan olarak genellikle 12 aydır; PST/OST boyut sınırları ise ayrı yapılandırılabilir ayarlardır. Bir OST dosyasını görüntülemek için [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Ekleri Alma

Kaybolan ekler şu konumlardan kurtarılabilir:

- Eski Outlook/IE yapılandırmaları için: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Daha yeni Outlook/IE11 yapılandırmaları için: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Dosyaları

**Thunderbird**, profil verilerini `%APPDATA%\Thunderbird\Profiles` altında saklar; posta klasörleri genellikle hesaba özgü `Mail` veya `ImapMail` dizinlerinde uzantısız mbox dosyaları kullanır.<sup>[[29]](#references)[[30]](#references)</sup>

### Görüntü Küçük Resimleri

- **Windows XP**: Küçük resim önizlemeleri genellikle klasör başına `thumbs.db` dosyalarında saklanırdı.
- **Ağ klasörleri**: İlgili küçük resim davranışı etkinleştirildiğinde UNC klasörü için de `thumbs.db` dosyası oluşturulabilir; her Windows sürümünün veya ilkenin böyle bir dosya oluşturduğunu varsaymayın.
- **Windows Vista ve sonrası**: Sistem küçük resim önbelleği, **thumbcache_xxx.db** gibi dosyalarla `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` altında merkezi olarak saklanır. [**Thumbsviewer**](https://thumbsviewer.github.io) eski `Thumbs.db` dosyalarını, [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) ise modern küçük resim önbelleği veritabanlarını ayrıştırabilir.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Bilgileri

Sistem ve kullanıcı yapılandırma verilerini saklayan Windows Registry, şu konumlardaki hive dosyalarında bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` alt anahtarlarını destekleyen makine hive'ları için `%WINDIR%\System32\Config`.
- Kullanıcının `HKEY_CURRENT_USER` hive'ı için `%USERPROFILE%\NTUSER.DAT`.
- Bazı eski Windows kurulumlarında `%WINDIR%\System32\Config\RegBack\` içinde kopyalar bulunur; Windows 10 sürüm 1803 ve sonrasında, periyodik yedekleme etkin değilse bu dizin otomatik olarak doldurulmaz.<sup>[[34]](#references)[[35]](#references)</sup>
- Kullanıcı başına shell ve sınıf kayıt verileri de modern Windows'ta genellikle `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` içinde saklanır.<sup>[[34]](#references)[[66]](#references)</sup>

### Araçlar

Registry hive'larını analiz etmek için bazı araçlar yararlıdır; çıktılara güvenmeden önce her aracın desteklediği hive biçimlerini ve sürümleri doğrulayın:

- **Registry Editor**: Windows ile birlikte yüklenir. Geçerli oturumun Windows registry'sinde gezinmek için kullanılan bir GUI'dir.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Registry dosyasını yüklemenize ve GUI üzerinden içinde gezinmenize olanak tanır. Ayrıca ilgi çekici bilgiler içeren anahtarları vurgulayan yer işaretleri de bulunur.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yüklenen registry'de gezinmeyi sağlayan bir GUI'ye ve registry içindeki ilgi çekici bilgileri vurgulayan eklentilere sahiptir.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Yüklenen bir registry hive'ından bilgi çıkarabilen başka bir GUI uygulamasıdır.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Silinen Öğeleri Kurtarma

Silinen hive hücreleri, alanları yeniden kullanılana kadar kalabilir; ancak kurtarma işlemi hive'ın durumuna ve ayrıştırıcıya bağlıdır. Kurtarılan silinmiş anahtarları doğrulanması gereken kanıtlar olarak değerlendirin, kesin kayıtlar olarak değil.

### Son Yazma Zamanı

Registry anahtarlarında son yazma zaman damgası bulunur; Windows bunu anahtar veya anahtarın değer girişlerinden herhangi biri için gösterir. Dolayısıyla bir değerin kendine ait bağımsız bir değiştirilme zaman damgası olması gerekmez.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive'ı, sistemin boot-key materyaliyle korunan parola hash'leri de dahil olmak üzere yerel kullanıcı ve grup hesap verilerini içerir.<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` içinde hesap tanımlayıcılarını ve bazı oturum açma ve ilke alanlarını bulabilirsiniz. Çevrimdışı hash çıkarma işlemi, ilgili boot-key materyalini kurtarmak için `SYSTEM` hive'ını da gerektirir.<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry'deki İlgi Çekici Girdiler


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Çalıştırılan Programlar

### Temel Windows İşlemleri

[Yaygın Windows işlemleriyle ilgili mevcut bir gönderi](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) ek okuma kaynağı olarak sunulmuştur; süreç davranışıyla ilgili iddiaları güncel Windows belgeleri ve yerel kanıtlarla doğrulayın.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Bu özelliği sunan Windows 10 sürümlerinde, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` son kullanım zamanı ve başlatma sayısı gibi alanlar içeren, uygulama başına alt anahtarlar barındırır; bu artefakt sonraki sürümlerden kaldırılmıştır, bu nedenle hedef derlemeyi doğrulayın.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator özelliğini sunan sistemlerde `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` veya daha yeni olan `...\bam\State\UserSettings\{SID}` yolunu inceleyin. Değerler kullanıcı SID'sine göre düzenlenir ve izlenen çalıştırılabilir dosya yolları ile FILETIME benzeri çalıştırma verileri içerebilir; bu artefakt sürüme bağlıdır ve diğer kanıtlarla doğrulanmalıdır.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch, programların daha hızlı başlatılabilmesi için kaynakları ve başlatma metadata'sını önbelleğe alır.

Prefetch dosyaları `C:\Windows\Prefetch` konumunda `.pf` dosyaları olarak saklanır; biçim, saklama süresi ve dosya sayısı sınırları Windows sürümüne göre değişir. Microsoft, Windows 8 ve sonrasında son sekiz çalıştırma zamanının ve en fazla 1024 dosyanın saklandığını belgeliyor; bu nedenle eski sabit sınır özetleri genellenmemelidir.<sup>[[13]](#references)</sup>

Dosya adı genellikle `{program_name}-{hash}.pf` biçimindedir; hash, yol ve argümanlar gibi çalıştırma bağlamından türetilir. Windows 10 ve sonraki sürümler dosyayı sıkıştırabilir. Dosyanın bulunması çalıştırma açısından yararlı bir kanıttır; ancak tek başına kullanıcının programı çalıştırdığını kanıtlamaz ve diğer artefaktlarla ilişkilendirilmelidir.<sup>[[13]](#references)</sup>

Bu dosyaları incelemek için dizin ayrıştırma, CSV/HTML çıktısı ve ilgili Windows 10 Prefetch dosyaları için açma desteğini belgeleyen [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) aracını kullanabilirsiniz.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain**, yüklemeyi iyileştirmek için geçmiş kullanım kalıplarından yararlanarak Prefetch'i tamamlar. Bu dosyaları oluşturan sistemlerde veritabanı dosyaları genellikle `C:\Windows\Prefetch\Ag*.db` konumunda bulunur; biçimleri ve bulunup bulunmamaları Windows sürümüne bağlıdır.<sup>[[41]](#references)</sup>

Bu veritabanları uygulama adlarını, kullanım sayılarını, erişilen dosya veya birimleri, yolları ve zaman aralıklarını içerebilir; ancak bunlar kesin bir yürütme günlüğü olarak değerlendirilmemelidir.<sup>[[41]](#references)</sup>

Mevcut [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) bağlantısı olası bir parser olarak korunmuştur; kullanmadan önce aracın güncel kullanılabilirliğini ve desteklediği çıktıları belgelerinden doğrulayın.

### SRUM

**System Resource Usage Monitor** (SRUM), uygulamaların ve kullanıcıların kaynak kullanımını kaydeder. Windows 8'de kullanıma sunulmuştur ve verileri ESE veritabanı olan `C:\Windows\System32\sru\SRUDB.dat` dosyasında saklar.<sup>[[13]](#references)</sup>

Aşağıdaki bilgileri sağlar:

- AppID ve Path
- Kayıtla ilişkili kullanıcı/SID
- Gönderilen bayt sayısı
- Alınan bayt sayısı
- Ağ arayüzü
- Bağlantı süresi
- İşlem süresi

Veri toplama sıklığı ve saklama süresi uygulamaya bağlıdır; her kaydın tam 60 dakikalık bir yürütme aralığını temsil ettiğini varsaymayın.<sup>[[13]](#references)</sup>

Verileri, [**srum_dump**](https://github.com/MarkBaggett/srum-dump) aracının güncel sürümünde belgelenen seçenekleri kullanarak dışa aktarabilir ve inceleyebilirsiniz.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, **ShimCache** olarak da bilinir; Windows uygulama uyumluluğu altyapısının bir parçasıdır ve uyumluluk kararlarında kullanılmak üzere dosya meta verilerini kaydeder. Kovanın yolu, kayıt biçimi, saklama kapasitesi ve alanları Windows sürümüne göre değişir; modern Windows'ta ShimCache tek başına kullanıcının bir dosyayı çalıştırdığını kanıtlayamaz. İlgili `SYSTEM` kovanını [**AppCompatCacheParser** aracıyla](https://github.com/EricZimmerman/AppCompatCacheParser) ayrıştırın ve çıktısını çalıştırma artefaktlarıyla doğrulayın.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Kaydedilmiş bilgileri ayrıştırmak için AppCompatCacheParser aracının kullanılması önerilir](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** dosyası, Windows tarafından gözlemlenen uygulama ve dosyaların envanterini tutan bir kayıt defteri kovanıdır. Genellikle `C:\Windows\AppCompat\Programs\Amcache.hve` konumunda bulunur.

İlişkili ve ilişkisiz dosya girdileri, yollar ve SHA1 değerleri içerebilir; ancak bu dosyanın bulunması envanter kanıtıdır ve tek başına bir işlemin çalıştırıldığını kanıtlamaz.<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** dosyasını çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) aracını kullanın. Bu komut, kovanı ayrıştırır ve CSV çıktısı yazar.<sup>[[44]](#references)</sup>

Örneğin:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Oluşturulan CSV dosyaları arasında `Amcache_Unassociated file entries`, tanınan bir programla ilişkili olmayan dosyaları incelerken faydalı olabilir.<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 sistemlerinde `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, yakın zamanda gözlemlenen ikili dosyalar hakkında bilgi içerebilir; dosyanın kullanılabilirliği ve anlamı sürüme bağlıdır.

Dosyayı ayrıştırmak için [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) kullanabilirsiniz.<sup>[[45]](#references)</sup>

### Zamanlanmış görevler

Modern görevlerin kanıtları `C:\Windows\System32\Tasks` altında, eski görevlerin kanıtları ise `.job` dosyalarıyla birlikte `C:\Windows\Tasks` altında bulunabilir; işletim sistemine uygun görev tanımı biçimini inceleyin.<sup>[[73]](#references)[[74]](#references)</sup>

### Hizmetler

Service Control Manager veritabanı `SYSTEM\CurrentControlSet\Services` altında bulunur (çevrimdışı bir SYSTEM hive için ilgili control-set anahtarını inceleyin); yürütülebilir dosya yolları ve başlatma türleri gibi hizmet ve sürücü yapılandırmalarını içerir.<sup>[[72]](#references)</sup>

### **Windows Store**

Yüklü Windows Store uygulamaları, **`StateRepository-Machine.srd`** veritabanı da dahil olmak üzere `\ProgramData\Microsoft\Windows\AppRepository\` altında temsil edilebilir. Şema ve yollar Windows sürümüne göre değişir.<sup>[[71]](#references)</sup>

Veritabanı uygulama tanımlayıcıları, paket numaraları ve görünen adlar içerebilir. Tanımlayıcılardaki boşluklar tek başına bir uygulamanın kaldırıldığının kanıtı değildir; paket ve kayıt defteri durumuyla doğrulayın.

Paket kayıtları `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` altında da bulunabilir. Microsoft, kaldırılan önceden sağlanmış uygulamalar için sürüme özgü bir `Deprovisioned` alt anahtarı belgeler; her derlemede `Deleted` alt anahtarı bulunduğunu varsaymayın.<sup>[[70]](#references)</sup>

## Windows Events

Sağlayıcıya bağlı olarak Windows olayları şunları içerebilir:

- Ne olduğu
- Olay şeması ve ana makinenin zaman bağlamı dikkate alınarak yorumlanması gereken bir `TimeCreated` zaman damgası
- Olaylara dahil olan kullanıcılar
- Olaylara dahil olan ana makineler (ana makine adı, IP)
- Erişilen varlıklar (dosyalar, klasörler, yazıcılar veya hizmetler).<sup>[[49]](#references)</sup>

Windows Vista'dan önce olay günlükleri genellikle `C:\Windows\System32\config` altında eski ikili biçimi kullanıyordu; Vista ve sonraki sürümler, XML olarak işlenmiş olay verilerini içeren `.evtx` dosyalarıyla, normalde `C:\Windows\System32\winevt\Logs` altında bulunan Windows Event Log biçimini kullanır.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM kayıt defteri; yapılandırılmış dosya yolu ve saklama ayarları dahil olmak üzere kanal yapılandırmasını **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** altında depolar.<sup>[[47]](#references)</sup>

Bu günlükler Windows Event Viewer (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) ve [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) gibi araçlarla görüntülenebilir.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows Security Event Logging'i Anlama

Vista ve sonraki sürümlerde Security kanalı genellikle `C:\Windows\System32\winevt\Logs\Security.evtx` konumunda saklanır. Maksimum boyutu ve saklama ilkesi yapılandırılabilir; dairesel günlükleme kullanıldığında dosya sınırına ulaştığında eski kayıtların üzerine yazılabilir. İlgili denetim etkinleştirilmişse kanal kimlik doğrulama, oturum kapatma, ayrıcalık, denetim ilkesi ve nesne erişimi olaylarını kaydedebilir.<sup>[[46]](#references)[[47]](#references)</sup>

### Kullanıcı Kimlik Doğrulaması için Önemli Olay Kimlikleri:

- **Event ID 4624**: Hesap oturumu başarıyla açıldı.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Hesap oturumu açılamadı.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Oturum açma oturumu sonlandırıldı.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Kullanıcı oturumu kapatmayı başlattı.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Yeni bir oturum açmaya özel ayrıcalıklar atandı; bu, sistem ve yönetici hesaplarında yaygındır, dolayısıyla tek başına kötü amaçlı etkinliğin kanıtı değildir.<sup>[[54]](#references)</sup>

#### 4624, 4625, 4634 ve 4647'de yaygın olarak kaydedilen oturum açma türleri:

- **Interactive (2)**: Yerel olarak etkileşimli oturum açma.
- **Network (3)**: Paylaşılan bir kaynağa erişim.
- **Batch (4)**: Toplu işlem oturumu açma.
- **Service (5)**: Hizmet oturumu açma.
- **Unlock (7)**: İş istasyonunun kilidini açma.
- **NetworkCleartext (8)**: Kimlik bilgilerini kimlik doğrulama paketine açık metin olarak sağlayan ağ oturumu açma.
- **NewCredentials (9)**: Giden bağlantılarda sağlanan alternatif kimlik bilgilerini kullanan oturum açma.
- **RemoteInteractive (10)**: Remote Desktop veya Terminal Services oturumu açma.
- **CachedInteractive (11)**: Önbelleğe alınmış etki alanı kimlik bilgilerini kullanan etkileşimli oturum açma.
- **CachedRemoteInteractive (12)**: Önbelleğe alınmış uzak etkileşimli oturum açma.
- **CachedUnlock (13)**: Önbelleğe alınmış kimlik bilgileriyle kilit açma.<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625 için Status ve Sub Status Kodları:

- **0xC0000064**: Böyle bir kullanıcı yok.
- **0xC000006A**: Kullanıcı adı doğru, parola yanlış.
- **0xC0000234**: Hesap kilitlendi.
- **0xC0000072**: Hesap devre dışı.
- **0xC000006F**: İzin verilen saatlerin dışında oturum açma.
- **0xC0000070**: İş istasyonu kısıtlaması ihlali.
- **0xC0000193**: Hesabın süresi doldu.
- **0xC0000071**: Parolanın süresi doldu.
- **0xC0000133**: İstemci ve sunucu arasındaki zaman farkı çok büyük.
- **0xC0000224**: Hesabın parolasını değiştirmesi gerekiyor.
- **0xC0000225**: `STATUS_NOT_FOUND`; bu kod tek başına bir sistem hatasını veya saldırıyı göstermez.
- **0xC000015B**: İstenen oturum açma türü için hesaba izin verilmemiş.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Zaman Değişikliği**: Sistem saati değiştirildi. Birçok olay, zaman hizmetinin rutin düzeltmelerini yansıtır; bu nedenle olayı kurcalama olarak değerlendirmeden önce işlemi yapanı ve zaman kaynağını ilişkilendirin.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 ve 6009:

- **Güç ve hizmet bağlamı**: Olay 12 işletim sisteminin başlatıldığını, 13 işletim sisteminin kapatıldığını, 1074 planlı kapatma veya yeniden başlatmayı, 6008 beklenmeyen kapatmayı, 6009 ise açılışta Windows sürümünü kaydeder. Olay 6005 ve 6006, sırasıyla Event Log hizmetinin başlatıldığını ve durdurulduğunu gösterir; bunlar tek başına işletim sisteminin başlatıldığının veya kapatıldığının kanıtı değildir.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Günlük Silme**: Olay 1102, Security denetim günlüğünün temizlendiğini kaydeder; yalnızca bu olaydan niyet çıkarmak yerine işlemi yapanı ve çevresindeki olayları araştırın.<sup>[[62]](#references)</sup>

#### USB Aygıtı Takibi için EventIDs:

- **20001 / 20003**: İlk kullanım veya yükleme etkinliğini belirlemeye yardımcı olabilecek `UserPnp` aygıt yükleme olayları.
- **10000 / 10100**: Aygıt etkinliğiyle ilişkili olabilecek `DriverFrameworks-UserMode` olayları.
- **Event ID 112**: Ekleme zaman damgaları sağlayabilecek `DeviceSetupManager/Admin` etkinliği.
- Sağlayıcı, kanal ve olay anlamları Windows sürümüne göre değişir; anlam atfetmeden önce sağlayıcı adını ve olay yükünü inceleyin.<sup>[[59]](#references)</sup>

Oturum açma türleri ve bunlarla ilişkili kimlik bilgisi materyalleriyle ilgili uygulamalı örnekler için [Altered Security'nin ayrıntılı kılavuzuna](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) bakın.<sup>[[60]](#references)</sup>

Oturum açma türü, durum, alt durum, kaynak adresi ve işlem alanları dahil olmak üzere olay ayrıntıları, Event ID 4625 için bağlam sağlar; bir durum kodu veya tekrarlanan başarısızlık örüntüsü, araştırmaya yönelik bir ipucudur, kesin sonuç değildir.<sup>[[51]](#references)[[55]](#references)</sup>

### Windows Events'i Kurtarma

Olay günlükleri genellikle dairesel olduğundan, günlükçü tarafından üzerine yazılan kayıtlar kurtarılamayabilir. Canlı bir sistemle etkileşime geçmeden önce adli imajı veya çalışma kopyasını koruyun; **Bulk_extractor** gibi doğrulanmış bir ayrıştırıcıyı veya carving aracını yalnızca aracın sürümünün hedef `.evtx` verilerini desteklediğini doğruladıktan sonra kullanın ve olayları kurtarmayı denemek için çalışan bir sistemin fişini çekmeyin.<sup>[[46]](#references)</sup>

### Windows Events ile Yaygın Saldırıları Belirleme

Uygulamalı bir olay kimliği başvuru kaynağı için mevcut [Red Team Recipe](https://redteamrecipe.com/event-codes/) bağlantısına bakın ve örneklerini yukarıdaki sağlayıcı belgeleriyle doğrulayın.

#### Brute Force Saldırıları

Tekrarlanan Event ID 4625 başarısızlıklarını; daha sonraki bir 4624 başarısı, oturum açma türü, durum, kaynak ve hesap bağlamıyla ilişkilendirin. Bu sıralama, bir saldırının kanıtı değil, araştırma göstergesidir.<sup>[[50]](#references)[[51]](#references)</sup>

#### Zaman Değişikliği

Event ID 4616 sistem saati değişikliklerini kaydeder ve zaman çizelgesi analizini zorlaştırabilir; bunu zaman hizmeti ve ana makine kanıtlarıyla karşılaştırın.<sup>[[56]](#references)</sup>

#### USB Aygıtı Takibi

USB olay kimlikleri sağlayıcıya özgüdür; `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 ve `DeviceSetupManager/Admin` 112 olaylarını SetupAPI ve kayıt defteri kalıntılarıyla ilişkilendirin.<sup>[[17]](#references)[[59]](#references)</sup>

#### Sistem Güç Olayları

İşletim sisteminin başlatılması, kapatılması, yeniden başlatılması ve beklenmedik güç kesintisi bağlamı için 12/13/1074/6008/6009 olaylarını kullanın; 6005/6006, Event Log hizmetinin başlatılmasını/durdurulmasını gösterir.<sup>[[57]](#references)[[58]](#references)</sup>

#### Günlük Silme

Security Event ID 1102, Security denetim günlüğünün temizlendiğini kaydeder ve sorumlu hesap ile işlemle ilişkilendirilerek incelenmelidir.<sup>[[62]](#references)</sup>



## References

- [1] [Windows Tak ve Kullan Temizliği](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Yaygın Windows İşlemlerini İnceleme](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Bildirimlerine Dijital Adli Bilişim Bakışı](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman adli bilişim araçları](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier ve Alternatif Veri Akışları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS altında kayıt defteri yedekleme ve geri yükleme işlemleri](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Yedekleme ve geri yükleme için kayıt defteri anahtarları](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover konumunda Word performans sorunu](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Olay Müdahale Rehberi](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link İkili Dosya Biçimi](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Adli Bilişimi: Veri Sızdırma Kalıntılarını Belirleme](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI aygıt yükleme günlük girdileri](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID ve İlgili Türler](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook veri dosyalarını bulma ve aktarma](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Önbelleğe Alınmış Exchange Modu'nu etkinleştirme](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Öğelerin yalnızca bir alt kümesi eşitleniyor](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook veri dosyaları için boyut sınırlarını yapılandırma](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiller - Thunderbird'ün kullanıcı verilerini depoladığı konum](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird hesap ayarları ve mbox dizinleri](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache arabirimi](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Kayıt Defteri Hive'ları](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Sistem kayıt defteri RegBack'e yedeklenmiyor](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Kayıt Defteri Kurtarma](https://www.mitec.cz/wrr.html)
- [38] [Kayıt defterini uzaktan düzenleme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Parolalara teknik genel bakış](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch kanıtları](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Olay Günlüğü Dosya Biçimi](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog kayıt defteri anahtarı](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated olay özelliği](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS değerleri](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Sistem olay günlüklerini kullanarak beklenmeyen yeniden başlatmaları giderme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [İşlem sürerken kapanma sorununu giderme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 için USB Depolama Aygıtı Adli Bilişimi](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Harika Windows Oturum Açma Türleri](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Arka plan etkinliği moderatörü](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Kayıt Defteri - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop'ta Hızlı Yazdırma, PDF eklerini yazdırmayı durduruyor](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Kayıt Defteri dosyaları](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Kaldırılan uygulamaların güncelleme sırasında geri gelmesini önleme](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK ve Registry Viewer Test Sonuçları](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Yüklü Hizmetler Veritabanı](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Görevler](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler Hizmeti Kullanılamıyor Hatasıyla Zamanlanmış Görevler Başarısız Oluyor](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail veritabanında gezinme](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: İnternet İleti Biçimi](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Windows istemcileri için Recall'ı yönetme](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
