# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Genel Windows Artifacts

### Windows 10 Notifications

Kullanıcı başına notification database `%LOCALAPPDATA%\Microsoft\Windows\Notifications` altında bulunur (örneğin, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Windows 10'un ilk sürümlerinde `appdb.dat` kullanılırken Anniversary Update (1607) ile `wpndatabase.db` kullanıma sunulmuştur. SQLite database, notification payload'larını ve zamanlama alanlarını içeren bir `Notification` tablosuna sahiptir; ancak saklama süresi ve kullanılabilir veriler sürüme ve cleanup policy'ye göre değişir.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline, desteklenen uygulamalar, belgeler ve diğer kullanıcı etkinlikleri için kayıtlar içerebilen bir activity-history özelliğidir; kapsamı uygulamaya ve Windows sürümüne bağlıdır.<sup>[[4]](#references)</sup>

Database, `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` konumunda bulunur. SQLite ile açılabilir veya çıktısı [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) ile incelenebilen [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) kullanılarak parse edilebilir.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Yerel trust boundary dışından indirilen dosyalar, zone bilgilerini kaydeden ve URL gibi origin metadata içerebilen **`Zone.Identifier` alternate data stream**'ini içerebilir. Bu stream'in varlığı ve alanları producer'a ve system policy'ye bağlıdır.<sup>[[6]](#references)</sup>

## **Dosya Yedekleri**

### Recycle Bin

Vista ve sonraki sürümlerde **Recycle Bin**, sürücünün kök dizinindeki **`$Recycle.bin`** klasöründe bulunabilir (örneğin, `C:\$Recycle.bin`).\
Bu klasörde bir dosya silindiğinde 2 özel dosya oluşturulur:

- `$I{id}`: Silinme zamanı ve orijinal path dahil olmak üzere dosya bilgileri
- `$R{id}`: Dosyanın içeriği

![Dosya Yedekleri - Recycle Bin: $R{id}: Dosyanın içeriği](<../../../images/image (1029).png>)

Bu dosyalara sahip olduğunuzda, orijinal path'i ve silinme zamanını çıkarmak için [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) kullanabilirsiniz (hedef Windows sürümüne uygun version'ı kullanın).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Dosya Yedekleri - Geri Dönüşüm Kutusu: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Birim Gölge Kopyaları

Volume Shadow Copy Service (VSS), dosyalar kullanımdayken birimlerin belirli bir zamandaki gölge kopyalarını oluşturabilir; ancak gölge kopya, adli imajın yerine geçmez.<sup>[[8]](#references)</sup>

Kopya meta verileri normalde birim kökündeki `\System Volume Information` ile ilişkilidir ve sistemden sisteme değişen tanımlayıcılar içerir:

![Geri Dönüşüm Kutusu - Birim Gölge Kopyaları: Bu yedekler genellikle dosya sisteminin kökündeki System Volume Information içinde bulunur ve adları, ... bölümünde gösterilen UID'lerden oluşur](<../../../images/image (94).png>)

Bir imaj uygun bir adli mounter ile mount edildikten sonra, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) kullanılabilir VSS snapshot'larını listeleyebilir ve bunlardaki dosyalara göz atabilir veya dosyaları kopyalayabilir.<sup>[[9]](#references)</sup>

![Geri Dönüşüm Kutusu - Birim Gölge Kopyaları: Adli imaj ArsenalImageMounter ile mount edildiğinde ShadowCopyView aracı bir gölge kopyayı incelemek ve hatta dosyaları çıkarmak için kullanılabilir...](<../../../images/image (576).png>)

VSS registry writer yapılandırması, yedeklemeden hariç tutulan dosya ve anahtarları belirtebilen `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` konumunu içerir:<sup>[[10]](#references)[[11]](#references)</sup>

![Geri Dönüşüm Kutusu - Birim Gölge Kopyaları: HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore registry girdisi, yedeklenmemesi gereken dosya ve anahtarları içerir](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` anahtarı da VSS service yapılandırmasını içerir.<sup>[[8]](#references)</sup>

### Office Otomatik Kaydedilen Dosyaları

AutoRecover konumları Office application'ına, sürümüne ve yapılandırmasına göre değişir. Word için Microsoft, varsayılan konum olarak `%APPDATA%\Microsoft\Word` yolunu belgeler; etkin yolu application settings üzerinden kontrol edin.<sup>[[12]](#references)</sup>

## Shell Öğeleri

Bir shell öğesi, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir öğedir.

### Son Kullanılan Belgeler (LNK)

Windows, bir kullanıcı bir öğeyi açtığında veya başka şekilde eriştiğinde genellikle son kullanılan öğe shortcut'ları oluşturur:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Klasöre erişilmesi, klasör ve ilişkili üst klasörler için de link'ler oluşturabilir.

Bu link dosyaları hedef türünü, hedef MAC zamanlarını, volume bilgilerini ve hedef yolunu içerebilir. Bu meta veriler silinmiş bir hedefin belirlenmesine yardımcı olabilir; ancak artifact, hedefin belirli bir kullanıcı tarafından açıldığının tek başına kanıtı değildir.<sup>[[13]](#references)[[14]](#references)</sup>

LNK'nin kendi filesystem timestamp'leri ile içerdiği hedef timestamp'leri birbirinden farklıdır. Destekleyici artifact'ler olmadan link oluşturulmasını ilk kullanım veya link değiştirilmesini son kullanım olarak yorumlamayın; format, hedef timestamp'lerini link dosyasının timestamp'lerinden ayrı olarak saklar.<sup>[[13]](#references)[[14]](#references)</sup>

Mevcut [**LinkParser**](http://4discovery.com/our-tools/) link'i tarihsel bir seçenek olarak korunmuştur; ancak inceleme sırasında dokümantasyonuna erişilememiştir. Belgelenmiş bir command-line parser için [**LECmd**](https://github.com/EricZimmerman/LECmd) kullanın.<sup>[[15]](#references)</sup>

Bu araçlar genellikle iki timestamp kümesini gösterir:

- **Hedef timestamp'leri:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link dosyası timestamp'leri:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

İlk küme hedefi; ikinci küme ise LNK dosyasının kendisini ifade eder. Her ikisini de parser'ın dokümantasyonu ve filesystem bağlamıyla birlikte yorumlayın.<sup>[[14]](#references)[[15]](#references)</sup>

Aynı bilgileri Windows CLI aracını çalıştırarak alabilirsiniz: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Bu durumda bilgiler bir CSV dosyasına kaydedilecektir.

### Jumplists

Jump Lists, uygulama başına son kullanılan veya göreve özgü öğelerin listeleridir ve otomatik ya da özel olabilir.<sup>[[13]](#references)</sup>

Automatic Jump Lists, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` konumunda saklanır ve `{id}.automaticDestinations-ms` gibi adlar kullanır; ID, uygulamayı tanımlar.

Custom Jump Lists, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` konumunda saklanır; hangi görev veya öğe girdilerini oluşturacağını uygulama belirler.

Dosya sisteminin oluşturulma ve değiştirilme zamanları Jump List dosyasını açıklar; listelenen her hedefe ilk ve son erişimi otomatik olarak göstermez. Ayrıştırılan girdileri dosyanın zaman damgaları ve diğer artifact'lerle ilişkilendirin.<sup>[[13]](#references)</sup>

Jump Lists'i [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Jumplist'leri JumplistExplorer kullanarak inceleyebilirsiniz](<../../../images/image (168).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasının kendisiyle ilişkili olduğunu unutmayın_)

### Shellbags

[**Shellbag'lerin ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB Kullanımı

USB kullanımı, dosyalara çıkarılabilir medyadan erişildiğinde oluşturulan artifact'ler kullanılarak bazen doğrulanabilir. Bunlar arasında:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) gibi araçlar bu artifact'leri USB cihaz kayıtlarıyla ilişkilendirir; ancak artifact'lerin kullanılabilirliği Windows sürümüne ve uygulamaya bağlıdır.<sup>[[18]](#references)</sup>

Windows XP ve Windows 7 MTP iş akışları için belgelenen testlerde bazı LNK'ler, özgün yol yerine bir `WPDNSE` klasörünü gösteriyordu.<sup>[[16]](#references)</sup>

![Shellbags - Windows USB Kullanımı: Bazı LNK dosyalarının özgün yolu göstermek yerine WPDNSE klasörünü gösterdiğine dikkat edin](<../../../images/image (218).png>)

Bu çalışma, `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` altında kopyalar bulunduğunu gözlemledi; testlerde geçici içerikler yeniden başlatma sonrasında korunmadı ve GUID, shellbag verileriyle ilişkilendirilebildi. Bunu evrensel bir kural olarak değil, işletim sistemine, cihaza ve uygulamaya bağlı bir davranış olarak değerlendirin.<sup>[[16]](#references)</sup>

### Registry Bilgileri

USB'ye bağlı cihazlar hakkında ilginç bilgiler içeren registry anahtarlarını öğrenmek için [bu sayfayı inceleyin](interesting-windows-registry-keys.md#usb-information).

### setupapi

Vista ve sonraki sürümlerde, cihaz yükleme etkinlikleri için `C:\Windows\inf\setupapi.dev.log` dosyasını inceleyin. Bölüm başlıkları `Section start` zaman damgalarını içerir; bunlar kurulum işlemlerini belgeler ve kesin fiziksel takılma zamanı olarak değerlendirilmek yerine diğer bağlantı kanıtlarıyla ilişkilendirilmelidir.<sup>[[17]](#references)</sup>

![Registry Bilgileri - setupapi: USB bağlantısının ne zaman gerçekleştirildiğine ilişkin zaman damgalarını almak için C: Windows inf setupapi.dev.log dosyasını inceleyin (Section start ifadesini arayın)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com), bir image'a bağlanmış USB cihazları hakkında bilgi almak için kullanılabilir.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective, bir image'a bağlanmış USB cihazları hakkında bilgi almak için kullanılabilir](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup` olarak bilinen scheduled task, güncel olmayan driver sürümlerini kaldırır. Adam Harrison tarafından belgelenen bir Windows 10 task tanımı, 30 gündür etkin olmayan driver'ları da hedefler; bu nedenle çıkarılabilir cihaz driver'larına ilişkin kanıtlar temizlenebilir. Bu davranışı genelleştirmeden önce yerel task tanımını ve Windows build'ini doğrulayın.<sup>[[1]](#references)</sup>

Task şu path'te bulunur: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Windows Plug and Play Cleanup scheduled task'ının XML tanımı](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Task'ın Temel Bileşenleri ve Ayarları:**

- **pnpclean.dll**: Bu DLL, gerçek cleanup işleminden sorumludur.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanmıştır ve generic task scheduling engine kullanımını belirtir.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler'ın cleanup task'ını normal Automatic maintenance sırasında aylık olarak başlatmasını sağlar.
- **Deadline ('P2M')**: Task'ın art arda iki ay boyunca başarısız olması durumunda Task Scheduler'a task'ı emergency Automatic maintenance sırasında çalıştırmasını bildirir.

Bu yapılandırma düzenli maintenance işlemlerini ve art arda gerçekleşen başarısızlıklardan sonra yeniden denemeleri planlar; kesin XML ve davranış sürüme bağlıdır.<sup>[[1]](#references)</sup>

**Daha fazla bilgi için:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-postalar

E-postalar **2 ilginç bölüm içerir: E-postanın headers ve content bölümleri**. **Headers** içinde şu tür bilgileri bulabilirsiniz:

- E-postaları **kimin** gönderdiği (e-posta adresi, IP, e-postayı yönlendiren mail server'lar)
- E-postanın **ne zaman** gönderildiği

Ayrıca `References` ve `In-Reply-To` header'ları, yanıtları bir konuşmayla ilişkilendirmek için kullanılan message ID'lerini taşıyabilir.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-postalar: E-posta ne zaman gönderildi](<../../../images/image (593).png>)

### Windows Mail App

Bu uygulama e-posta içeriğini `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` gibi path'lerdeki yardımcı text veya HTML dosyalarında saklar; kesin numaralı klasör ve dosya düzeni artifact'e göre değişebilir.<sup>[[75]](#references)</sup>

E-postaların **metadata** bilgileri ve **contacts**, **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` içinde bulunabilir.<sup>[[75]](#references)</sup>

`store.vol`, Extensible Storage Engine (ESE) formatını kullanır. Bir kopya üzerinde çalışın ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi bir ESE parser kullanın; bir tool `.edb` suffix'i gerektiriyorsa yalnızca kopyanın adını değiştirin ve bir `Message` table'ına güvenmeden önce table schema'sını doğrulayın.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties incelenirken canonical properties şunları içerir:

- `PidTagClientSubmitTime`: client'ın message'ı gönderdiği UTC zamanı.
- `PidTagConversationIndex`: message'ın bir conversation thread içindeki göreli konumu.
- `PidTagEntryId`: message object için bir identifier.
- `PidTagMessageFlags`: gönderilmiş, okunmuş, okunmamış veya attachment içeren durumlar gibi status flag'leri.
- `PidTagLastVerbExecuted`: open, reply veya forward gibi message için kaydedilen son operation.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file konumları sürüme ve account type'a göre değişir. Microsoft, PST/OST dosyaları için şu yaygın konumları belgeler:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

`HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` registry path'i, Outlook profile'ını ve ilişkili data-file configuration'ını belirleyebilir.

PST dosyaları message'lar, contacts, calendar data ve diğer Outlook item'larını içerebilir. Bir kopyayı [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) ile inceleyebilirsiniz.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST dosyasını Kernel PST Viewer tool'u ile açabilirsiniz](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Bir **OST file**, Exchange veya Microsoft 365 account'ları için yerel bir cache'tir; Cached Exchange Mode, POP veya IMAP account'ları için geçerli değildir. Offline period yapılandırılabilir ve varsayılan olarak genellikle 12 aydır; PST/OST size limit'leri ise ayrı ve yapılandırılabilir ayarlardır. Bir OST file'ı görüntülemek için [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Attachment'ları Alma

Kayıp attachment'lar şu konumlardan kurtarılabilir:

- Legacy Outlook/IE configuration'ları için: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Daha yeni Outlook/IE11 configuration'ları için: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird**, profile data'sını `%APPDATA%\Thunderbird\Profiles` altında saklar; mail folder'ları, account'a özel `Mail` veya `ImapMail` directory'leri altında genellikle uzantısız mbox dosyalarını kullanır.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail preview'ları genellikle folder başına `thumbs.db` dosyalarında saklanırdı.
- **Network folder'ları**: İlgili thumbnail behavior etkinleştirildiğinde bir UNC folder için yine de `thumbs.db` dosyası oluşturulabilir; her Windows sürümünün veya policy'nin bunu oluşturduğunu varsaymayın.
- **Windows Vista ve daha yeni sürümler**: System thumbnail cache, **thumbcache_xxx.db** gibi dosyalarla `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` altında merkezi olarak saklanır. [**Thumbsviewer**](https://thumbsviewer.github.io), legacy `Thumbs.db` dosyalarını; [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) ise modern thumbnail-cache database'lerini ayrıştırabilir.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Bilgileri

System ve user configuration data'sını saklayan Windows Registry, şu konumlardaki hive file'ları içinde bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` subkey'lerini destekleyen machine hive'ları için `%WINDIR%\System32\Config`.
- Bir kullanıcının `HKEY_CURRENT_USER` hive'ı için `%USERPROFILE%\NTUSER.DAT`.
- Bazı eski Windows kurulumları `%WINDIR%\System32\Config\RegBack\` içinde kopyalar bulundurur; Windows 10 version 1803 ve sonraki sürümler, periodic backup etkinleştirilmediği sürece bu directory'yi otomatik olarak doldurmaz.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-user shell ve class-registration data'sı, modern Windows'ta genellikle `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` içinde de saklanır.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Bazı tools registry hive'larını analiz etmek için kullanışlıdır; bir output'a güvenmeden önce her tool'un desteklediği hive format'larını ve version'ını doğrulayın:

- **Registry Editor**: Windows'ta yüklü olarak gelir. Mevcut session'ın Windows registry'sinde gezinmek için kullanılan bir GUI'dir.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Registry file'ını yüklemenize ve bir GUI üzerinden içinde gezinmenize olanak tanır. Ayrıca ilginç bilgiler içeren key'leri vurgulayan Bookmarks özelliğine sahiptir.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen registry içinde gezinmenizi sağlayan bir GUI'ye ve yüklenen registry'deki ilginç bilgileri vurgulayan plugin'lere sahiptir.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Yüklenen bir registry hive'ından bilgi çıkarabilen başka bir GUI application'dır.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Deleted Element'ları Kurtarma

Silinmiş hive cell'leri, alanları yeniden kullanılana kadar kalabilir; ancak kurtarma hive state'ine ve parser'a bağlıdır. Kurtarılan silinmiş key'leri garanti edilmiş records olarak değil, validation gerektiren evidence olarak değerlendirin.

### Last Write Time

Registry key'leri bir last-write timestamp taşır; Windows bunu key veya value entry'lerinden herhangi biri için sunar. Bu nedenle bir value'nun kendisine ait bağımsız bir modification timestamp'ı olması gerekmez.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive'ı, system'in boot-key material'ı tarafından korunan password hash'leri de dahil olmak üzere local user ve group account data'sını içerir.<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` içinde account identifier'larını ve bazı logon ve policy field'larını elde edebilirsiniz. Offline hash extraction işlemi, ilgili boot-key material'ını kurtarmak için ayrıca `SYSTEM` hive'ını gerektirir.<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry'deki İlginç Girdiler


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Çalıştırılan Programs

### Temel Windows Processes

[Common Windows processes hakkında mevcut bir post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), ek okuma olarak korunmuştur; process behavior iddialarını güncel Windows documentation'ı ve yerel evidence ile doğrulayın.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Windows 10'un bu özelliği sunan sürümlerinde `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`, last-used time ve launch count gibi field'lara sahip application başına subkey'ler içerir; artifact sonraki release'lerden kaldırılmıştır, bu nedenle hedef build'i doğrulayın.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator'ı sunan sistemlerde `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` veya daha yeni `...\bam\State\UserSettings\{SID}` path'ini inceleyin. Value'lar user SID'lerine göre key'lenir ve izlenen executable path'lerini ve FILETIME benzeri execution data'sını içerebilir; artifact version'a bağlıdır ve diğer evidence'larla doğrulanmalıdır.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching, programların daha hızlı başlatılabilmesi için resource'ları ve launch metadata'sını cache'ler.

Prefetch file'ları `C:\Windows\Prefetch` konumunda `.pf` dosyaları olarak saklanır; format, retention ve file-count limit'leri Windows version'ına göre değişir. Microsoft, Windows 8 ve sonraki sürümlerde son sekiz execution time'ın ve 1024'e kadar file'ın tutulduğunu belgeler; bu nedenle eski fixed-limit özetleri genelleştirilmemelidir.<sup>[[13]](#references)</sup>

Dosya adı genellikle `{program_name}-{hash}.pf` formatını kullanır; hash, path ve argument'lar gibi execution context'ten türetilir. Windows 10 ve sonraki sürümler dosyayı compress edebilir. Varlığı execution evidence olarak kullanışlıdır, ancak tek başına bir kullanıcının execution gerçekleştirdiğini kanıtlamaz ve diğer artifact'lerle ilişkilendirilmelidir.<sup>[[13]](#references)</sup>

Bu file'ları incelemek için, directory parsing, CSV/HTML output ve uygulanabilir Windows 10 Prefetch file'ları için decompression desteğini belgeleyen [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) kullanılabilir.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain**, yükleme işlemini iyileştirmek için geçmiş kullanım modellerini kullanarak Prefetch'i tamamlar. Bunları oluşturan sistemlerde veritabanı dosyaları genellikle `C:\Windows\Prefetch\Ag*.db` konumunda bulunur; biçim ve mevcut olma durumu sürüme bağlıdır.<sup>[[41]](#references)</sup>

Bu veritabanları uygulama adlarını, kullanım sayılarını, erişilen dosyaları veya birimleri, yolları ve zaman aralıklarını içerebilir; ancak kesin bir çalıştırma günlüğü olarak değerlendirilmemelidir.<sup>[[41]](#references)</sup>

Mevcut [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) bağlantısı olası bir ayrıştırıcı olarak korunmuştur; kullanmadan önce güncel erişilebilirliğini ve desteklenen çıktı biçimini aracın belgelerine göre doğrulayın.

### SRUM

**System Resource Usage Monitor** (SRUM), uygulamalar ve kullanıcılar tarafından gerçekleştirilen kaynak kullanımını kaydeder. Windows 8'de kullanıma sunulmuş ve verileri `C:\Windows\System32\sru\SRUDB.dat` ESE veritabanında depolar.<sup>[[13]](#references)</sup>

Aşağıdaki bilgileri sağlar:

- AppID ve Path
- Kayıtla ilişkilendirilmiş User/SID
- Gönderilen Baytlar
- Alınan Baytlar
- Ağ Arayüzü
- Bağlantı süresi
- İşlem süresi

Toplama sıklığı ve saklama süresi uygulamaya bağlıdır; her kaydın tam olarak 60 dakikalık bir çalıştırma aralığını temsil ettiğini varsaymayın.<sup>[[13]](#references)</sup>

Verileri, mevcut araç sürümünde belgelenen seçenekleri kullanarak [**srum_dump**](https://github.com/MarkBaggett/srum-dump) ile çıkarabilir ve inceleyebilirsiniz.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, **ShimCache** olarak da bilinir ve uyumluluk kararları için dosya metadata'sını kaydeden Windows uygulama uyumluluğu altyapısının bir parçasıdır. Hive yolu, kayıt biçimi, saklanan kapasite ve alanlar Windows sürümüne göre değişir; modern Windows sürümlerinde yalnızca ShimCache, bir kullanıcının dosyayı çalıştırdığını kanıtlayamaz. İlgili `SYSTEM` hive'ını [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) ile ayrıştırın ve çıktısını execution artifact'larıyla doğrulayın.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Saklanan bilgileri ayrıştırmak için AppCompatCacheParser tool kullanılması önerilir](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** dosyası, Windows tarafından gözlemlenen uygulamaları ve dosyaları envantere alan bir registry hive'ıdır. Genellikle `C:\Windows\AppCompat\Programs\Amcache.hve` konumunda bulunur.

İlişkili ve ilişkisiz dosya girdileri, yollar ve SHA1 değerleri içerebilir; ancak bu dosyanın mevcut olması envanter kanıtıdır ve tek başına bir process'in çalıştırıldığını kanıtlamaz.<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** dosyasını çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool'unu kullanın. Bu komut hive'ı ayrıştırır ve CSV çıktısı yazar.<sup>[[44]](#references)</sup>

Örneğin:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Oluşturulan CSV dosyaları arasında `Amcache_Unassociated file entries`, tanınan bir programla ilişkilendirilmemiş dosyaları incelerken yararlı olabilir.<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 sistemlerinde, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` yakın zamanda gözlemlenen binary dosyalar hakkında bilgi içerebilir; kullanılabilirlik ve anlam sürüme bağlıdır.

Dosyayı ayrıştırmak için [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) kullanabilirsiniz.<sup>[[45]](#references)</sup>

### Zamanlanmış görevler

Zamanlanmış görev kanıtları, modern görevler için `C:\Windows\System32\Tasks` altında ve eski görevler için `.job` dosyalarıyla birlikte `C:\Windows\Tasks` altında bulunabilir; işletim sistemine uygun görev tanımı biçimini inceleyin.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Manager veritabanı `SYSTEM\CurrentControlSet\Services` altında bulunur (çevrimdışı bir SYSTEM hive için ilgili control-set anahtarını inceleyin); çalıştırılabilir dosya yolları ve başlangıç türleri gibi service ve driver yapılandırmalarını içerir.<sup>[[72]](#references)</sup>

### **Windows Store**

Yüklü Windows Store uygulamaları, **`StateRepository-Machine.srd`** veritabanı da dahil olmak üzere `\ProgramData\Microsoft\Windows\AppRepository\` altında temsil edilebilir. Şema ve yollar Windows sürümüne göre değişir.<sup>[[71]](#references)</sup>

Veritabanı application identifier'ları, package numaralarını ve görünen adları içerebilir. Identifier'lar arasındaki boşluklar tek başına bir application'ın kaldırıldığını kanıtlamaz; package ve registry durumuyla doğrulayın.

Package kayıtları `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` altında da görünebilir. Microsoft, kaldırılan provisioned app'ler için sürüme özgü bir `Deprovisioned` alt anahtarını belgeler; her build'de bir `Deleted` alt anahtarının bulunduğunu varsaymayın.<sup>[[70]](#references)</sup>

## Windows Events

Provider'a bağlı olarak Windows event'leri şunları içerebilir:

- Ne olduğu
- Event şeması ve host zaman bağlamıyla yorumlanması gereken bir `TimeCreated` timestamp'i
- İlgili kullanıcılar
- İlgili host'lar (hostname, IP)
- Erişilen varlıklar (dosyalar, klasörler, printer'lar veya service'ler).<sup>[[49]](#references)</sup>

Windows Vista'dan önce event log'ları genellikle `C:\Windows\System32\config` altında legacy binary formatını kullanıyordu; Vista ve sonraki sürümler, normalde `C:\Windows\System32\winevt\Logs` altında bulunan Windows Event Log formatını kullanır ve `.evtx` dosyaları XML olarak işlenmiş event verilerini içerir.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry, kanal yapılandırmasını **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** altında depolar; buna yapılandırılmış dosya yolu ve retention ayarları dahildir.<sup>[[47]](#references)</sup>

Bunlar Windows Event Viewer (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) ve [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) gibi araçlarla görüntülenebilir.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Vista ve sonraki sürümlerde Security kanalı genellikle `C:\Windows\System32\winevt\Logs\Security.evtx` konumunda depolanır. Maksimum boyutu ve retention policy yapılandırılabilir; circular logging kullanıldığında dosya sınırına ulaştığında eski kayıtların üzerine yazılabilir. İlgili auditing etkinleştirildiğinde kanal authentication, logoff, privilege, audit-policy ve object-access event'lerini kaydedebilir.<sup>[[46]](#references)[[47]](#references)</sup>

### User Authentication için önemli Event ID'leri:

- **Event ID 4624**: Başarılı bir account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Başarısız bir account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Bir logon session sonlandırıldı.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Bir kullanıcı logoff işlemi başlattı.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Yeni bir logon'a özel privilege'lar atandı; bu system ve administrator account'ları için yaygındır, dolayısıyla tek başına malicious activity kanıtı değildir.<sup>[[54]](#references)</sup>

#### 4624, 4625, 4634 ve 4647'de yaygın olarak kaydedilen Logon türleri:

- **Interactive (2)**: Etkileşimli bir local logon.
- **Network (3)**: Paylaşılan bir kaynağa erişim.
- **Batch (4)**: Bir batch-process logon'ı.
- **Service (5)**: Bir service logon'ı.
- **Unlock (7)**: Bir workstation kilidinin açılması.
- **NetworkCleartext (8)**: Authentication package'a credential'ları cleartext olarak sağlayan bir network logon'ı.
- **NewCredentials (9)**: Outbound bağlantılar için sağlanan alternatif credential'ların kullanıldığı bir logon.
- **RemoteInteractive (10)**: Remote Desktop veya Terminal Services logon'ı.
- **CachedInteractive (11)**: Cached domain credential'ları kullanılarak gerçekleştirilen etkileşimli bir logon.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Cached credential'lar kullanılarak gerçekleştirilen bir unlock.<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625 için Status ve Sub Status Code'ları:

- **0xC0000064**: Böyle bir kullanıcı yok.
- **0xC000006A**: Kullanıcı adı doğru, ancak parola yanlış.
- **0xC0000234**: Account kilitlendi.
- **0xC0000072**: Account devre dışı bırakıldı.
- **0xC000006F**: İzin verilen saatler dışında logon.
- **0xC0000070**: Workstation kısıtlaması ihlali.
- **0xC0000193**: Account'un süresi doldu.
- **0xC0000071**: Parolanın süresi doldu.
- **0xC0000133**: Client ve server arasındaki zaman farkı çok büyük.
- **0xC0000224**: Account parolasını değiştirmeli.
- **0xC0000225**: `STATUS_NOT_FOUND`; code tek başına bir system bug'ını veya attack'i tanımlamaz.
- **0xC000015B**: İstenen logon türü account'a verilmemiş.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: System zamanı değiştirildi. Birçok event rutin time-service düzeltmesini yansıtır; bunu tampering olarak değerlendirmeden önce aktör ve time source ile ilişkilendirin.<sup>[[56]](#references)</sup>

#### Event ID'leri 12, 13, 1074, 6005, 6006, 6008 ve 6009:

- **Power and service context**: Event 12 OS başlangıcını, 13 OS kapanışını, 1074 planlanmış kapanma veya yeniden başlatmayı, 6008 beklenmeyen kapanmayı ve 6009 boot sırasında Windows sürümünü kaydeder. Event 6005 ve 6006, sırasıyla Event Log service'in başlatıldığını ve durdurulduğunu gösterir; bunlar tek başlarına OS başlangıcı ve kapanışı kanıtı değildir.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102, Security audit log'un temizlendiğini kaydeder; yalnızca bu event'ten niyet çıkarmak yerine aktörü ve çevredeki event'leri inceleyin.<sup>[[62]](#references)</sup>

#### USB Device Tracking için Event ID'leri:

- **20001 / 20003**: İlk kullanım veya installation activity'sini belirlemeye yardımcı olabilecek `UserPnp` device-installation event'leri.
- **10000 / 10100**: Device activity'ye eşlik edebilecek `DriverFrameworks-UserMode` event'leri.
- **Event ID 112**: Insertion ile ilişkili timestamp'ler sağlayabilen `DeviceSetupManager/Admin` activity'si.
- Provider, channel ve event semantiği Windows sürümüne göre değişir; anlam atamadan önce provider adını ve event payload'ını inceleyin.<sup>[[59]](#references)</sup>

Logon türleri ve bunlarla ilişkili credential material hakkında pratik örnekler için [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) kaynağına bakın.<sup>[[60]](#references)</sup>

Logon türü, status, substatus, source address ve process alanları dahil event ayrıntıları, Event ID 4625 için bağlam sağlar; bir status code veya tekrarlanan failure pattern'i bir investigation lead'idir, sonuç değildir.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Event log'ları genellikle circular olduğundan logger tarafından üzerine yazılan kayıtlar kurtarılamayabilir. Canlı bir system ile etkileşime geçmeden önce forensic image veya working copy oluşturun; yalnızca tool sürümünün hedef `.evtx` verisini desteklediğini doğruladıktan sonra **Bulk_extractor** gibi doğrulanmış bir parser veya carver kullanın ve yalnızca event'leri kurtarmayı denemek için çalışan bir system'in fişini çekmeyin.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Pratik bir event-ID referansı için mevcut [Red Team Recipe](https://redteamrecipe.com/event-codes/) link'ine bakın ve örneklerini yukarıdaki provider documentation ile doğrulayın.

#### Brute Force Attacks

Tekrarlanan Event ID 4625 failure'larını daha sonraki bir 4624 success, logon type, status, source ve account context ile ilişkilendirin; bu sequence bir attack investigation indicator'ıdır, attack kanıtı değildir.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 system-time değişikliklerini kaydeder; bu değişiklikler timeline analysis'i karmaşıklaştırabilir. Event'i time-service ve host evidence ile karşılaştırın.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event ID'leri provider'a özgüdür; `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 ve `DeviceSetupManager/Admin` 112 event'lerini SetupAPI ve registry artifact'larıyla ilişkilendirin.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS başlangıcı, kapanışı, yeniden başlatma ve beklenmeyen güç durumları için 12/13/1074/6008/6009'u kullanın; 6005/6006, Event Log service başlangıcını/durdurulmasını gösterir.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102, Security audit log'un temizlendiğini kaydeder ve sorumlu account ile process ile ilişkilendirilmelidir.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Yaygın Windows Process'lerini İnceleme](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Notifications için Digital Forensic Görünümü](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier ve Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS altında Registry backup ve restore işlemleri](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Backup ve restore için Registry anahtarları](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover konumunda Word performance sorunu](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Data Exfiltration Artifact'larını Belirleme](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID ve Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook data files'ı bulma ve aktarma](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode'u etkinleştirme](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Yalnızca öğelerin bir alt kümesi synchronize edilir](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data files için size limit'lerini yapılandırma](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird'in user data'sını depoladığı yer](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings ve mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry RegBack'e yedeklenmiyor](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Registry'yi uzaktan düzenleme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [System event log'larını kullanarak beklenmeyen reboot'ları giderme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [İşlem sırasında shutdown sorunlarını giderme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 için USB Storage Device Forensics](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop'ta Quick Print'in PDF attachments yazdırmayı durdurması](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Bir update sırasında kaldırılan app'lerin geri dönmesini önleme](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK ve Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Yüklü Services veritabanı](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler Service Is Not Available Hatasıyla Scheduled Tasks Başarısız Oluyor](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail veritabanında gezinme](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
