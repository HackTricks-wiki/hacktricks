# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Kullanıcı başına ait notification veritabanı `%LOCALAPPDATA%\Microsoft\Windows\Notifications` altında bulunur (örneğin, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Windows 10'un ilk sürümlerinde `appdb.dat` kullanılırken Anniversary Update (1607) ile `wpndatabase.db` kullanıma sunulmuştur. SQLite veritabanı, notification payload'larını ve zamanlama alanlarını içeren bir `Notification` tablosuna sahiptir; ancak saklama süresi ve kullanılabilir veriler, sürüme ve cleanup policy'ye göre değişir.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline; desteklenen uygulamalar, belgeler ve diğer kullanıcı etkinlikleri için kayıtlar içerebilen bir etkinlik geçmişi özelliğidir. Kapsamı uygulamaya ve Windows sürümüne bağlıdır.<sup>[[4]](#references)</sup>

Veritabanı `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` konumunda bulunur. SQLite ile açılabilir veya çıktısı [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) ile incelenebilen [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) kullanılarak parse edilebilir.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Yerel trust boundary dışından indirilen dosyalar, bölge bilgilerini kaydeden ve URL gibi origin metadata içerebilen **`Zone.Identifier` alternate data stream**'ini barındırabilir. Bu stream'in varlığı ve alanları, producer'a ve system policy'ye bağlıdır.<sup>[[6]](#references)</sup>

## **File Backups**

### Recycle Bin

Vista ve sonraki sürümlerde **Recycle Bin**, sürücünün kök dizinindeki **`$Recycle.bin`** klasöründe bulunabilir (örneğin, `C:\$Recycle.bin`).\
Bu klasörde bir dosya silindiğinde 2 özel dosya oluşturulur:

- `$I{id}`: Silinme zamanı ve özgün path dahil olmak üzere dosya bilgileri
- `$R{id}`: Dosyanın içeriği

![File Backups - Recycle Bin: $R{id}: Dosyanın içeriği](<../../../images/image (1029).png>)

Bu dosyalara sahip olduğunuzda, özgün path'i ve silinme zamanını çıkarmak için [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) kullanabilirsiniz (hedef Windows sürümüne uygun version'ı kullanın).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS), dosyalar kullanımdayken volume'ların belirli bir andaki shadow copy'lerini oluşturabilir; bir shadow copy, forensic image yerine geçmez.<sup>[[8]](#references)</sup>

Copy metadata'sı normalde volume kökündeki `\System Volume Information` ile ilişkilidir ve sistemden sisteme değişen identifier'lar içerir:

![Recycle Bin - Volume Shadow Copies: Bu yedekler genellikle file system kökündeki System Volume Information içinde bulunur ve adları görüntüde gösterilen UID'lerden oluşur...](<../../../images/image (94).png>)

Bir image'i uygun bir forensic mounter ile mount ettikten sonra, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) mevcut VSS snapshot'larını listeleyebilir ve bunlardaki dosyalara göz atabilir veya dosyaları kopyalayabilir.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Forensics image'i ArsenalImageMounter ile mount ettikten sonra ShadowCopyView aracı bir shadow copy'yi incelemek ve hatta dosyaları çıkarmak için kullanılabilir...](<../../../images/image (576).png>)

VSS registry writer yapılandırması, yedekleme dışında bırakılan dosya ve key'leri belirtebilen `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` konumunu içerir:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore registry girdisi, yedeklenmemesi gereken dosya ve key'leri içerir](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key'i ayrıca VSS service yapılandırmasını da içerir.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover konumları Office uygulamasına, sürümüne ve yapılandırmasına göre değişir. Word için Microsoft, varsayılan konum olarak `%APPDATA%\Microsoft\Word` yolunu belirtir; etkin path'i uygulama ayarlarından kontrol edin.<sup>[[12]](#references)</sup>

## Shell Items

Bir shell item, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir item'dır.

### Recent Documents (LNK)

Windows, bir kullanıcı bir item'ı açtığında veya başka şekilde eriştiğinde genellikle recent-item shortcut'ları oluşturur:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Folder erişimi, folder ve ilişkili parent folder'lar için de link'ler oluşturabilir.

Bu link dosyaları target type, target MAC times, volume bilgileri ve target path içerebilir. Bu metadata, kaldırılmış bir target'ın belirlenmesine yardımcı olabilir; ancak artifact tek başına target'ın belirli bir kullanıcı tarafından açıldığının kanıtı değildir.<sup>[[13]](#references)[[14]](#references)</sup>

LNK'nın kendi filesystem timestamp'leri ile içine gömülü target timestamp'leri birbirinden farklıdır. Doğrulayıcı başka artifact'ler olmadan link oluşturulmasını ilk kullanım veya link değiştirilmesini son kullanım olarak yorumlamayın; format, target timestamp'lerini link dosyasının timestamp'lerinden ayrı olarak depolar.<sup>[[13]](#references)[[14]](#references)</sup>

Mevcut [**LinkParser**](http://4discovery.com/our-tools/) link'i historical bir seçenek olarak korunmuştur, ancak inceleme sırasında documentation mevcut değildi. Documentation'ı bulunan bir command-line parser için [**LECmd**](https://github.com/EricZimmerman/LECmd) kullanın.<sup>[[15]](#references)</sup>

Bu araçlar genellikle iki timestamp kümesini gösterir:

- **Target timestamp'leri:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-file timestamp'leri:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

İlk küme target'ı; ikinci küme ise LNK dosyasının kendisini ifade eder. Her ikisini de parser documentation'ı ve filesystem bağlamıyla birlikte yorumlayın.<sup>[[14]](#references)[[15]](#references)</sup>

Aynı bilgileri Windows CLI tool'u [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) çalıştırarak da alabilirsiniz.<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Bu durumda bilgiler bir CSV dosyasının içine kaydedilecektir.

### Jumplists

Jump Lists, uygulama başına son kullanılan veya göreve özgü öğelerin listeleridir ve otomatik ya da özel olabilir.<sup>[[13]](#references)</sup>

Automatic Jump Lists, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` konumunda saklanır ve `{id}.automaticDestinations-ms` gibi adlar kullanır; ID, uygulamayı tanımlar.

Custom Jump Lists, `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` konumunda saklanır; hangi görev veya öğe girdilerini oluşturacağını uygulama belirler.

Dosya sisteminin oluşturulma ve değiştirilme zamanları Jump List dosyasını belirtir; listelenen her hedefe ilk ve son erişimi otomatik olarak belirtmez. Ayrıştırılmış girdileri dosyanın zaman damgaları ve diğer artifact'lerle ilişkilendirin.<sup>[[13]](#references)</sup>

Jump Lists'i [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: JumplistExplorer kullanılarak jumplist'leri inceleyebilirsiniz](<../../../images/image (168).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasının kendisiyle ilişkili olduğunu unutmayın_)

### Shellbags

[**Shellbag'lerin ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB'lerinin Kullanımı

USB kullanımı bazen dosyalara çıkarılabilir medyadan erişildiğinde oluşturulan artifact'lerle doğrulanabilir. Bunlar arasında şunlar bulunur:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) gibi araçlar bu artifact'leri USB cihaz kayıtlarıyla ilişkilendirir; ancak artifact'lerin kullanılabilirliği Windows sürümüne ve uygulamaya bağlıdır.<sup>[[18]](#references)</sup>

Windows XP ve Windows 7 MTP iş akışları için belgelenen testlerde bazı LNK'ler, özgün yol yerine bir `WPDNSE` klasörünü gösteriyordu.<sup>[[16]](#references)</sup>

![Shellbags - Windows USB'lerinin Kullanımı: Bazı LNK dosyalarının özgün yolu göstermek yerine WPDNSE klasörünü gösterdiğine dikkat edin](<../../../images/image (218).png>)

Bu çalışma `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` altında kopyalar gözlemledi; testlerde geçici içerikler yeniden başlatmadan sonra korunmadı ve GUID, shellbag verileriyle ilişkilendirilebildi. Bu davranışı evrensel bir kural olarak değil, işletim sistemi, cihaz ve uygulamaya bağlı bir davranış olarak değerlendirin.<sup>[[16]](#references)</sup>

### Registry Bilgileri

USB'ye bağlı cihazlar hakkında ilginç bilgiler içeren registry anahtarlarını öğrenmek için [bu sayfayı kontrol edin](interesting-windows-registry-keys.md#usb-information).

### setupapi

Vista ve sonraki sürümlerde cihaz yükleme etkinlikleri için `C:\Windows\inf\setupapi.dev.log` dosyasını inceleyin. Bölüm başlıkları `Section start` zaman damgalarını içerir; bunlar kurulum işlemlerini belgeler ve kesin fiziksel takılma zamanı olarak değerlendirilmek yerine diğer bağlantı kanıtlarıyla ilişkilendirilmelidir.<sup>[[17]](#references)</sup>

![Registry Bilgileri - setupapi: USB bağlantısının ne zaman oluşturulduğuna ilişkin zaman damgalarını almak için C: Windows inf setupapi.dev.log dosyasını kontrol edin (Section start ifadesini arayın)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com), bir image'a bağlanmış USB cihazları hakkında bilgi edinmek için kullanılabilir.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective, bir image'a bağlanmış USB cihazları hakkında bilgi edinmek için kullanılabilir](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup` olarak bilinen zamanlanmış görev, güncel olmayan driver sürümlerini kaldırır. Adam Harrison tarafından belgelenen bir Windows 10 görev tanımı, 30 gün boyunca etkin olmayan driver'ları da hedefler; bu nedenle çıkarılabilir cihaz driver'larına ilişkin kanıtlar temizlenebilir. Bu davranışı genellemeden önce yerel görev tanımını ve Windows build'ini doğrulayın.<sup>[[1]](#references)</sup>

Görev şu yolda bulunur: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Görevin Temel Bileşenleri ve Ayarları:**

- **pnpclean.dll**: Bu DLL, gerçek cleanup işleminden sorumludur.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanır ve generic task scheduling engine kullanımını belirtir.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler'ı regular Automatic maintenance sırasında cleanup görevini aylık olarak başlatmaya yönlendirir.
- **Deadline ('P2M')**: Görev arka arkaya iki ay boyunca başarısız olursa Task Scheduler'a görevi emergency Automatic maintenance sırasında çalıştırmasını bildirir.

Bu yapılandırma düzenli maintenance işlemlerini ve art arda gerçekleşen başarısızlıklardan sonra yeniden denemeleri planlar; kesin XML ve davranış sürüme bağlıdır.<sup>[[1]](#references)</sup>

**Daha fazla bilgi için kontrol edin:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-postalar

E-postalar **2 ilginç bölüm içerir: E-postanın headers'ları ve içeriği**. **Headers** içinde şu tür bilgileri bulabilirsiniz:

- E-postaları **kimin** gönderdiği (e-posta adresi, IP, e-postayı yönlendiren mail servers)
- E-postanın **ne zaman** gönderildiği

Ayrıca `References` ve `In-Reply-To` headers'ları, yanıtları bir conversation ile ilişkilendirmek için kullanılan message ID'lerini taşıyabilir.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-postalar: E-posta ne zaman gönderildi](<../../../images/image (593).png>)

### Windows Mail App

Bu uygulama e-posta içeriğini `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` gibi yollarda auxiliary text veya HTML dosyaları olarak kaydeder; kesin numaralandırılmış klasör ve dosya düzeni artifact'e göre değişebilir.<sup>[[75]](#references)</sup>

E-postaların **metadata** bilgileri ve **contacts**, **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` içinde bulunabilir.<sup>[[75]](#references)</sup>

`store.vol`, Extensible Storage Engine (ESE) formatını kullanır. Bir kopya üzerinde çalışın ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi bir ESE parser kullanın; bir araç `.edb` suffix'i gerektiriyorsa yalnızca kopyanın adını değiştirin ve bir `Message` tablosuna güvenmeden önce table schema'yı doğrulayın.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties incelenirken canonical properties şunları içerir:

- `PidTagClientSubmitTime`: client'ın message'ı gönderdiği UTC zamanı.
- `PidTagConversationIndex`: message'ın conversation thread içindeki göreli konumu.
- `PidTagEntryId`: message object için bir identifier.
- `PidTagMessageFlags`: gönderilmiş, okunmuş, okunmamış veya attachment içeren gibi status flags.
- `PidTagLastVerbExecuted`: message için kaydedilen son operation; örneğin open, reply veya forward.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file konumları sürüme ve account type'a göre değişir. Microsoft, PST/OST files için şu yaygın konumları belgeler:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

`HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` registry path'i, Outlook profile'ını ve ilişkili data-file configuration'ını tanımlayabilir.

PST files; messages, contacts, calendar data ve diğer Outlook items'larını içerebilir. Bir kopyayı [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) ile inceleyebilirsiniz.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST dosyasını Kernel PST Viewer aracıyla açabilirsiniz](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Bir **OST file**, Exchange veya Microsoft 365 accounts için local cache'tir; Cached Exchange Mode, POP veya IMAP accounts için geçerli değildir. Offline period yapılandırılabilir ve varsayılan olarak genellikle 12 aydır; PST/OST size limits ise ayrı yapılandırılabilir ayarlardır. Bir OST file'ı görüntülemek için [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Attachments'ları Alma

Kayıp attachments şu konumlardan kurtarılabilir:

- Eski Outlook/IE configurations için: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Daha yeni Outlook/IE11 configurations için: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird**, profile data'sını `%APPDATA%\Thunderbird\Profiles` altında saklar; mail folders, account-specific `Mail` veya `ImapMail` directories altında genellikle extensionsız mbox files kullanır.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews genellikle klasör başına `thumbs.db` files içinde saklanır.
- **Network folders**: İlgili thumbnail davranışı etkinleştirildiğinde bir UNC folder için `thumbs.db` file oluşturulmaya devam edebilir; her Windows sürümünün veya policy'nin bir tane oluşturduğunu varsaymayın.
- **Windows Vista and newer**: System thumbnail cache, `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` altında **thumbcache_xxx.db** gibi files ile merkezi olarak saklanır. [**Thumbsviewer**](https://thumbsviewer.github.io), legacy `Thumbs.db` dosyalarını parse edebilir; [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) ise modern thumbnail-cache databases'lerini parse edebilir.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Bilgileri

System ve user configuration data'sını saklayan Windows Registry, şu konumlardaki hive files içinde bulunur:

- `%WINDIR%\System32\Config`, çeşitli `HKEY_LOCAL_MACHINE` subkeys'lerini destekleyen machine hives için.
- `%USERPROFILE%\NTUSER.DAT`, bir kullanıcının `HKEY_CURRENT_USER` hive'ı için.
- Bazı eski Windows installations, `%WINDIR%\System32\Config\RegBack\` içinde kopyalar barındırır; Windows 10 version 1803 ve sonraki sürümler, periodic backup etkinleştirilmediği sürece bu directory'yi otomatik olarak doldurmaz.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-user shell ve class-registration data'sı, modern Windows'ta genellikle `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` içinde de saklanır.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Bazı tools registry hives'larını analiz etmek için kullanışlıdır; bir output'a güvenmeden önce her tool'un desteklediği hive formats ve version'ı doğrulayın:

- **Registry Editor**: Windows'a kurulu olarak gelir. Mevcut session'ın Windows registry'sinde gezinmek için kullanılan bir GUI'dir.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Registry file'ı yüklemenize ve bir GUI aracılığıyla içinde gezinmenize olanak tanır. Ayrıca ilginç bilgiler içeren keys'leri vurgulayan Bookmarks içerir.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen registry içinde gezinmenize olanak tanıyan bir GUI'ye sahiptir ve ayrıca yüklenen registry içindeki ilginç bilgileri vurgulayan plugins içerir.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Yüklenen bir registry hive'ından bilgi çıkarabilen başka bir GUI application.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Silinen Element'leri Kurtarma

Silinen hive cells, alanları yeniden kullanılana kadar kalabilir; ancak recovery, hive state ve parser'a bağlıdır. Kurtarılan deleted keys'leri garanti edilmiş records olarak değil, doğrulama gerektiren evidence olarak değerlendirin.

### Last Write Time

Registry keys bir last-write timestamp taşır; Windows bunu key veya value entries'lerinden herhangi biri için sunar. Bu nedenle bir value'nun bağımsız bir modification timestamp'ine sahip olması gerekmez.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive'ı, system'in boot-key material'ı tarafından korunan password hashes dahil olmak üzere local user ve group account data'sını içerir.<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` içinde account identifiers ve bazı logon ve policy fields'larını elde edebilirsiniz. Offline hash extraction işlemi, ilgili boot-key material'ını kurtarmak için `SYSTEM` hive'ını da gerektirir.<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry'deki İlginç Girdiler


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Çalıştırılan Programs

### Basic Windows Processes

Mevcut [common Windows processes hakkındaki post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) ek okuma olarak korunmuştur; process behavior ile ilgili iddiaları güncel Windows documentation ve local evidence ile doğrulayın.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Windows 10'un bunu sunduğu sürümlerde `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`, last-used time ve launch count gibi fields içeren application başına subkeys barındırır; artifact sonraki releases'lerde kaldırılmıştır, bu nedenle hedef build'i doğrulayın.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator'ı sunan systems üzerinde `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` veya daha yeni `...\bam\State\UserSettings\{SID}` path'ini inceleyin. Values, user SID ile anahtarlanır ve takip edilen executable paths ile FILETIME-like execution data içerebilir; artifact version-dependent'tır ve diğer evidence'larla doğrulanmalıdır.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching, programların daha hızlı başlatılabilmesi için resources ve launch metadata'yı cache'ler.

Prefetch files, `C:\Windows\Prefetch` içinde `.pf` files olarak saklanır; format, retention ve file-count limits Windows sürümüne göre değişir. Microsoft, Windows 8 ve sonraki sürümlerde son sekiz execution time'ın ve en fazla 1024 file'ın tutulduğunu belgeler; bu nedenle eski fixed-limit summaries genelleştirilmemelidir.<sup>[[13]](#references)</sup>

Filename genellikle `{program_name}-{hash}.pf` formatını kullanır; hash, path ve arguments gibi execution context'ten türetilir. Windows 10 ve sonraki sürümler file'ı compress edebilir. Varlığı execution evidence olarak kullanışlıdır; ancak tek başına bir kullanıcının execution gerçekleştirdiğinin kanıtı değildir ve diğer artifacts'lerle ilişkilendirilmelidir.<sup>[[13]](#references)</sup>

Bu files'ları incelemek için, ilgili Windows 10 Prefetch files için directory parsing, CSV/HTML output ve decompression desteğini belgeleyen [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) kullanılabilir.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Süperprefetch

**Superfetch/SysMain**, yüklemeyi iyileştirmek için geçmiş kullanım kalıplarını kullanarak Prefetch'i tamamlar. Bunları oluşturan sistemlerde veritabanı dosyaları genellikle `C:\Windows\Prefetch\Ag*.db` konumunda bulunur; biçim ve mevcut olma durumu sürüme bağlıdır.<sup>[[41]](#references)</sup>

Bu veritabanları uygulama adlarını, kullanım sayılarını, erişilen dosyaları veya birimleri, yolları ve zaman aralıklarını içerebilir; ancak kesin bir yürütme günlüğü olarak değerlendirilmemelidir.<sup>[[41]](#references)</sup>

Mevcut [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) bağlantısı olası bir parser olarak korunmuştur; kullanmadan önce güncel kullanılabilirliğini ve desteklenen çıktısını aracın belgelerine göre doğrulayın.

### SRUM

**System Resource Usage Monitor** (SRUM), uygulamalar ve kullanıcılar tarafından gerçekleştirilen kaynak kullanımını kaydeder. Windows 8'de kullanıma sunulmuştur ve verileri ESE veritabanı olan `C:\Windows\System32\sru\SRUDB.dat` içinde depolar.<sup>[[13]](#references)</sup>

Aşağıdaki bilgileri sağlar:

- AppID ve Path
- Kayıtla ilişkili kullanıcı/SID
- Gönderilen Baytlar
- Alınan Baytlar
- Ağ Arayüzü
- Bağlantı süresi
- İşlem süresi

Toplama sıklığı ve saklama süresi uygulamaya bağlıdır; her kaydın tam olarak 60 dakikalık bir yürütme aralığını temsil ettiğini varsaymayın.<sup>[[13]](#references)</sup>

Verileri, geçerli araç sürümünde belgelenen seçenekleri kullanarak [**srum_dump**](https://github.com/MarkBaggett/srum-dump) ile çıkarabilir ve inceleyebilirsiniz.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, diğer adıyla **ShimCache**, Windows uygulama uyumluluğu altyapısının bir parçasıdır ve uyumluluk kararları için dosya meta verilerini kaydeder. Hive yolu, kayıt biçimi, saklanan kapasite ve alanlar Windows sürümüne göre değişir; modern Windows sürümlerinde yalnızca ShimCache, bir kullanıcının dosyayı çalıştırdığını kanıtlayamaz. İlgili `SYSTEM` hive dosyasını [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) ile ayrıştırın ve çıktısını execution artifact'leriyle doğrulayın.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Saklanan bilgileri ayrıştırmak için AppCompatCacheParser tool kullanılması önerilir](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** dosyası, Windows tarafından gözlemlenen uygulamaların ve dosyaların envanterini tutan bir registry hive dosyasıdır. Genellikle `C:\Windows\AppCompat\Programs\Amcache.hve` konumunda bulunur.

İlişkili ve ilişkilendirilmemiş dosya girdilerini, yolları ve SHA1 değerlerini içerebilir; ancak varlığı envanter kanıtıdır ve tek başına bir process'in çalıştırıldığını kanıtlamaz.<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** dosyasını çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) aracını kullanın. Bu komut hive dosyasını ayrıştırır ve CSV çıktısı yazar.<sup>[[44]](#references)</sup>

Örneğin:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Oluşturulan CSV dosyaları arasında `Amcache_Unassociated file entries`, tanınan bir programla ilişkilendirilemeyen dosyaları araştırırken yararlı olabilir.<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 sistemlerinde `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, yakın zamanda gözlemlenen binary dosyalar hakkında bilgi içerebilir; kullanılabilirliği ve anlamı sürüme bağlıdır.

Dosyayı ayrıştırmak için [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) kullanabilirsiniz.<sup>[[45]](#references)</sup>

### Zamanlanmış görevler

Zamanlanmış görev kanıtları, modern görevler için `C:\Windows\System32\Tasks` altında ve eski görevler için `.job` dosyalarıyla birlikte `C:\Windows\Tasks` altında bulunabilir; işletim sistemine uygun görev tanımı formatını inceleyin.<sup>[[73]](#references)[[74]](#references)</sup>

### Hizmetler

Service Control Manager veritabanı `SYSTEM\CurrentControlSet\Services` altında bulunur (çevrimdışı bir SYSTEM hive için ilgili control-set anahtarını inceleyin); çalıştırılabilir dosya yolları ve başlatma türleri gibi service ve driver yapılandırmalarını içerir.<sup>[[72]](#references)</sup>

### **Windows Store**

Yüklü Windows Store uygulamaları, **`StateRepository-Machine.srd`** veritabanı da dahil olmak üzere `\ProgramData\Microsoft\Windows\AppRepository\` altında temsil edilebilir. Şema ve yollar Windows sürümüne göre değişir.<sup>[[71]](#references)</sup>

Veritabanı application identifier'ları, package numaralarını ve display name'leri içerebilir. Identifier'lar arasındaki boşluklar tek başına bir application'ın kaldırıldığını kanıtlamaz; package ve registry durumuyla doğrulayın.

Package registration'ları `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` altında da görünebilir. Microsoft, kaldırılmış provisioned app'ler için sürüme özgü bir `Deprovisioned` subkey'i belgeler; her build'de bir `Deleted` subkey'inin bulunduğunu varsaymayın.<sup>[[70]](#references)</sup>

## Windows Events

Provider'a bağlı olarak Windows events şunları içerebilir:

- Ne olduğu
- Event schema'sı ve host time context ile yorumlanması gereken bir `TimeCreated` timestamp'i
- İlgili kullanıcılar
- İlgili host'lar (hostname, IP)
- Erişilen asset'ler (dosyalar, klasörler, printer'lar veya service'ler).<sup>[[49]](#references)</sup>

Windows Vista'dan önce event log'ları genellikle `C:\Windows\System32\config` altında legacy binary format'ını kullanıyordu; Vista ve sonraki sürümler, normalde `C:\Windows\System32\winevt\Logs` altında bulunan ve XML olarak oluşturulmuş event data içeren `.evtx` dosyalarıyla Windows Event Log format'ını kullanır.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry, kanal yapılandırmasını **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** altında saklar; buna yapılandırılmış dosya yolu ve retention ayarları dahildir.<sup>[[47]](#references)</sup>

Bunlar Windows Event Viewer (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) ve [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) gibi araçlarla görüntülenebilir.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows Security Event Logging'i Anlama

Vista ve sonraki sürümlerde Security channel genellikle `C:\Windows\System32\winevt\Logs\Security.evtx` konumunda saklanır. Maksimum boyutu ve retention policy yapılandırılabilir; circular logging kullanıldığında dosya sınırına ulaştığında eski kayıtların üzerine yazılabilir. İlgili auditing etkinleştirildiğinde channel; authentication, logoff, privilege, audit-policy ve object-access event'lerini kaydedebilir.<sup>[[46]](#references)[[47]](#references)</sup>

### Kullanıcı Authentication'ı için Önemli Event ID'leri:

- **Event ID 4624**: Başarılı bir account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Başarısız bir account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Bir logon session sonlandırıldı.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Bir kullanıcı tarafından başlatılan logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Yeni bir logon'a özel privilege'lar atandı; bu system ve administrator account'ları için yaygındır, dolayısıyla tek başına malicious activity kanıtı değildir.<sup>[[54]](#references)</sup>

#### 4624, 4625, 4634 ve 4647'de yaygın olarak kaydedilen Logon type'ları:

- **Interactive (2)**: Etkileşimli bir local logon.
- **Network (3)**: Paylaşılan bir resource'a erişim.
- **Batch (4)**: Bir batch-process logon.
- **Service (5)**: Bir service logon.
- **Unlock (7)**: Bir workstation'ın kilidinin açılması.
- **NetworkCleartext (8)**: Authentication package'a credential'ları cleartext olarak sağlayan bir network logon.
- **NewCredentials (9)**: Outbound connection'lar için sağlanan alternatif credential'lar kullanılarak yapılan bir logon.
- **RemoteInteractive (10)**: Remote Desktop veya Terminal Services logon'ı.
- **CachedInteractive (11)**: Cached domain credential'ları kullanılarak yapılan etkileşimli bir logon.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Cached credential'lar kullanılarak kilit açma.<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625 için Status ve Sub Status Code'ları:

- **0xC0000064**: Böyle bir kullanıcı yok.
- **0xC000006A**: Kullanıcı adı doğru ancak password yanlış.
- **0xC0000234**: Account lockout durumunda.
- **0xC0000072**: Account devre dışı.
- **0xC000006F**: İzin verilen saatlerin dışında logon.
- **0xC0000070**: Workstation restriction ihlali.
- **0xC0000193**: Account'un süresi dolmuş.
- **0xC0000071**: Password'un süresi dolmuş.
- **0xC0000133**: Client ve server arasındaki time difference çok büyük.
- **0xC0000224**: Account password'unu değiştirmeli.
- **0xC0000225**: `STATUS_NOT_FOUND`; code tek başına bir system bug'ını veya attack'i tanımlamaz.
- **0xC000015B**: İstenen logon type account'a verilmemiş.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: System time değiştirildi. Birçok event rutin time-service düzeltmesini yansıtır; bu nedenle bunu tampering olarak değerlendirmeden önce actor ve time source ile ilişkilendirin.<sup>[[56]](#references)</sup>

#### Event ID'leri 12, 13, 1074, 6005, 6006, 6008 ve 6009:

- **Power and service context**: Event 12 OS start'ını, 13 OS shutdown'ını, 1074 planlı bir shutdown veya restart'ı, 6008 beklenmeyen bir shutdown'ı ve 6009 boot sırasında Windows version'ını kaydeder. Event 6005 ve 6006, sırasıyla Event Log service'in başladığını ve durduğunu gösterir; bunlar tek başına OS start ve shutdown kanıtı değildir.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102, Security audit log'un temizlendiğini kaydeder; yalnızca bu event'ten intent varsaymak yerine actor'ı ve çevresindeki event'leri araştırın.<sup>[[62]](#references)</sup>

#### USB Device Tracking için Event ID'leri:

- **20001 / 20003**: İlk kullanım veya installation activity'sini belirlemeye yardımcı olabilecek `UserPnp` device-installation event'leri.
- **10000 / 10100**: Device activity'ye eşlik edebilecek `DriverFrameworks-UserMode` event'leri.
- **Event ID 112**: Insertion ile ilgili timestamp'ler sağlayabilen `DeviceSetupManager/Admin` activity'si.
- Provider, channel ve event semantics Windows version'ına göre değişir; anlam atamadan önce provider name'ini ve event payload'ını inceleyin.<sup>[[59]](#references)</sup>

Logon type'ları ve bunlarla ilişkili credential material hakkında pratik örnekler için [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) sayfasına bakın.<sup>[[60]](#references)</sup>

Logon type, status, substatus, source address ve process field'ları dahil event ayrıntıları, Event ID 4625 için context sağlar; bir status code veya tekrarlanan failure pattern'i bir investigative lead'dir, conclusion değildir.<sup>[[51]](#references)[[55]](#references)</sup>

### Windows Events'i Kurtarma

Event log'ları genellikle circular olduğundan, logger tarafından üzerine yazılan kayıtlar kurtarılamayabilir. Live system ile etkileşime geçmeden önce forensic image veya working copy koruyun; yalnızca tool version'ının hedef `.evtx` data'sını desteklediğini doğruladıktan sonra **Bulk_extractor** gibi doğrulanmış bir parser veya carver kullanın ve yalnızca event'leri kurtarmayı denemek için çalışan bir system'ın bağlantısını kesmeyin.<sup>[[46]](#references)</sup>

### Windows Events Kullanarak Yaygın Attack'leri Belirleme

Pratik bir event-ID reference için mevcut [Red Team Recipe](https://redteamrecipe.com/event-codes/) link'ine bakın ve örneklerini yukarıdaki provider documentation'a göre doğrulayın.

#### Brute Force Attack'leri

Tekrarlanan Event ID 4625 failure'larını daha sonraki bir 4624 success'i, logon type, status, source ve account context ile ilişkilendirin; sequence bir attack indicator'ıdır, attack kanıtı değildir.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 system-time change'lerini kaydeder; bu değişiklikler timeline analysis'i zorlaştırabilir. Bunları time-service ve host evidence ile karşılaştırın.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event ID'leri provider-specific'tir; `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 ve `DeviceSetupManager/Admin` 112 event'lerini SetupAPI ve registry artifact'larıyla ilişkilendirin.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS start, shutdown, restart ve unexpected-power context için 12/13/1074/6008/6009'u kullanın; 6005/6006 Event Log service start/stop işlemlerini belirtir.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102, Security audit log'un temizlendiğini kaydeder ve sorumlu account ile process ile ilişkilendirilmelidir.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Yaygın Windows Process'lerini Araştırma](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Notifications'a Digital Forensic Bakış](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier ve Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS altında Registry backup ve restore işlemleri](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Backup ve restore için Registry key'leri](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover konumunda Word performans sorunu](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
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
- [25] [Outlook data file'larını bulma ve transfer etme](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode'u açma](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Yalnızca öğelerin bir alt kümesi synchronize ediliyor](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data file'ları için size limit'lerini yapılandırma](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird'in user data'sını depoladığı konum](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings ve mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry'nin RegBack'e backup'lanmaması](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Registry'yi remotely edit etme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
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
- [57] [System event log'larını kullanarak beklenmeyen reboot'ları troubleshoot etme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Shutdown in process sorununu troubleshoot etme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 için USB Storage Device Forensics](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop'ta PDF attachment'larını Quick Print'in yazdırmayı durdurması](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Kaldırılan app'lerin update sırasında geri dönmesini önleme](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK ve Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Installed Services Database](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks'in Task Scheduler Service Is Not Available Hatasıyla Başarısız Olması](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail database'inde gezinme](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
